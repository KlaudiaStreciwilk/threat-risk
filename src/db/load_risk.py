"""Zapis wyników oceny ryzyka (CVE) i reputacji (IoC) do grafowej bazy Neo4j."""
import os

import pandas as pd
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

PROC_DIR = "data/processed"
PACZKA = 2000

Q_CVE = """
UNWIND $rows AS r
MATCH (c:CVE {id: r.id})
SET c.ryzyko = r.ryzyko, c.poziom = r.poziom, c.ryzyko_bez_kev = r.ryzyko_bez_kev,
    c.s_powaga = r.s_powaga, c.zrodlo_powagi = r.zrodlo_powagi, c.s_atak = r.s_atak,
    c.s_rynek = r.s_rynek, c.s_graf = r.s_graf, c.swiezosc = r.swiezosc,
    c.n_raportow = r.n_raportow
RETURN count(c) AS n
"""

Q_IOC = """
UNWIND $rows AS r
MATCH (i:IoC {value: r.value})
SET i.reputacja = r.reputacja, i.poziom = r.poziom,
    i.n_zgloszen = r.n_zgloszen, i.n_zrodel = r.n_zrodel, i.zrodla = r.zrodla,
    i.s_pewnosc = r.s_pewnosc, i.s_powiazania = r.s_powiazania,
    i.s_czestosc = r.s_czestosc, i.swiezosc = r.swiezosc,
    i.popularna_domena = r.popularna_domena, i.malware_nazwa = r.malware_nazwa
RETURN count(i) AS n
"""

Q_MALWARE = """
MATCH (m:Malware)<-[:ASSOCIATED_WITH]-(i:IoC)
WITH m, max(i.reputacja) AS mx, count(i) AS n,
     sum(CASE WHEN i.reputacja >= 60 THEN 1 ELSE 0 END) AS wysokie
SET m.max_reputacja_ioc = mx, m.liczba_ioc = n, m.liczba_ioc_wysokich = wysokie
"""

Q_AKTOR = """
MATCH (a:Actor)<-[:ATTRIBUTED_TO]-(:Report)-[:MENTIONS]->(c:CVE)
WHERE c.ryzyko IS NOT NULL
WITH a, max(c.ryzyko) AS mx, count(DISTINCT c) AS n
SET a.max_ryzyko_cve = mx, a.liczba_cve = n
"""


def oczysc(df):
    return df.astype(object).where(pd.notna(df), None)


def wyslij(session, zapytanie, rekordy):
    razem = 0
    for i in range(0, len(rekordy), PACZKA):
        razem += session.run(zapytanie, rows=rekordy[i:i + PACZKA]).single()["n"]
    return razem


if __name__ == "__main__":
    cve = pd.read_csv(f"{PROC_DIR}/cve_risk.csv")
    cve = cve[["id", "ryzyko", "poziom", "ryzyko_bez_kev", "s_powaga", "zrodlo_powagi",
               "s_atak", "s_rynek", "s_graf", "swiezosc", "n_raportow"]]
    ioc = pd.read_csv(f"{PROC_DIR}/ioc_reputation.csv")
    ioc = ioc[["value", "reputacja", "poziom", "n_zgloszen", "n_zrodel", "zrodla",
               "s_pewnosc", "s_powiazania", "s_czestosc", "swiezosc",
               "popularna_domena", "malware_nazwa"]]

    driver = GraphDatabase.driver(
        os.getenv("NEO4J_URI"),
        auth=(os.getenv("NEO4J_USER"), os.getenv("NEO4J_PASSWORD")),
    )
    with driver.session() as s:
        n_cve = wyslij(s, Q_CVE, oczysc(cve).to_dict("records"))
        print(f"CVE z oceną ryzyka: {n_cve} z {len(cve)}")
        n_ioc = wyslij(s, Q_IOC, oczysc(ioc).to_dict("records"))
        print(f"IoC z oceną reputacji: {n_ioc} z {len(ioc)}")

        s.run(Q_MALWARE)
        s.run(Q_AKTOR)

        print("\nSprawdzenie – 5 najbardziej ryzykownych CVE w bazie:")
        for r in s.run("MATCH (c:CVE) WHERE c.ryzyko IS NOT NULL "
                       "RETURN c.id AS id, c.ryzyko AS ryzyko, c.poziom AS poziom "
                       "ORDER BY ryzyko DESC LIMIT 5"):
            print(f"  {r['id']:<17} {r['ryzyko']:>5}  {r['poziom']}")

        print("\nMalware z największą liczbą IoC o wysokiej reputacji:")
        for r in s.run("MATCH (m:Malware) WHERE m.liczba_ioc_wysokich > 0 "
                       "RETURN m.name AS nazwa, m.liczba_ioc_wysokich AS wysokie, m.liczba_ioc AS wszystkie "
                       "ORDER BY wysokie DESC LIMIT 5"):
            print(f"  {r['nazwa']:<20} {r['wysokie']:>4} z {r['wszystkie']}")

        print("\nGrupy APT powiązane z najgroźniejszymi podatnościami:")
        for r in s.run("MATCH (a:Actor) WHERE a.max_ryzyko_cve IS NOT NULL "
                       "RETURN a.name AS nazwa, a.max_ryzyko_cve AS mx, a.liczba_cve AS n "
                       "ORDER BY mx DESC LIMIT 5"):
            print(f"  {r['nazwa']:<20} max ryzyko {r['mx']:>5}  ({r['n']} CVE)")
    driver.close()