"""Dodanie do grafu raportów OTX i encji wyciągniętych z tekstów (etap 3)."""
import os

import pandas as pd
from dotenv import load_dotenv
from neo4j import GraphDatabase

from src.extract.build_dictionary import oczysc_nazwe

load_dotenv()

PROC_DIR = "data/processed"
PACZKA = 1000
IOC_TYPY = {"IP", "DOMAIN", "URL", "HASH"}

OGRANICZENIA = [
    "CREATE CONSTRAINT actor_name IF NOT EXISTS FOR (n:Actor) REQUIRE n.name IS UNIQUE",
]

Q_RAPORTY = """
UNWIND $rows AS r
MERGE (rep:Report {id: r.id})
SET rep.source = 'OTX', rep.title = r.title, rep.text = r.text,
    rep.published = r.published, rep.author = r.author,
    rep.tags = r.tags, rep.industries = r.industries
"""

Q_IOC = """
UNWIND $rows AS r
MATCH (rep:Report {id: r.report_id})
MERGE (i:IoC {value: r.value})
ON CREATE SET i.type = r.type
MERGE (rep)-[m:MENTIONS]->(i)
SET m.via = r.via
"""

Q_CVE = """
UNWIND $rows AS r
MATCH (rep:Report {id: r.report_id})
MERGE (c:CVE {id: r.value})
ON CREATE SET c.from_report_only = true
MERGE (rep)-[m:MENTIONS]->(c)
SET m.via = r.via
"""

Q_MALWARE = """
UNWIND $rows AS r
MATCH (rep:Report {id: r.report_id})
MERGE (m:Malware {name: r.value})
MERGE (rep)-[x:MENTIONS]->(m)
SET x.via = r.via
"""

Q_ACTOR = """
UNWIND $rows AS r
MATCH (rep:Report {id: r.report_id})
MERGE (a:Actor {name: r.value})
MERGE (rep)-[x:ATTRIBUTED_TO]->(a)
SET x.via = r.via
"""

# Malware użyte przez aktora: tylko gdy autor raportu sam wskazał grupę
Q_USED_BY = """
MATCH (rep:Report {source: 'OTX'})-[at:ATTRIBUTED_TO]->(a:Actor)
WHERE at.via CONTAINS 'list'
MATCH (rep)-[:MENTIONS]->(m:Malware)
MERGE (m)-[:USED_BY]->(a)
"""

Q_NVD_SOFT = """
UNWIND $rows AS r
MATCH (c:CVE {id: r.cve_id})
MERGE (p:Product {name: r.value})
MERGE (c)-[x:AFFECTS]->(p)
ON CREATE SET x.via = 'text'
"""

Q_NVD_VENDOR = """
UNWIND $rows AS r
MATCH (c:CVE {id: r.cve_id})
MERGE (v:Vendor {name: r.value})
MERGE (c)-[x:AFFECTS_VENDOR]->(v)
ON CREATE SET x.via = 'text'
"""

Q_CZESTOSC = """
MATCH (i:IoC)
SET i.mentions = COUNT { (i)<-[:MENTIONS]-(:Report) }
"""


def oczysc(df):
    return df.astype(object).where(pd.notna(df), None)


def wyslij(session, zapytanie, rekordy, nazwa):
    for i in range(0, len(rekordy), PACZKA):
        session.run(zapytanie, rows=rekordy[i:i + PACZKA])
    print(f"{nazwa}: {len(rekordy)}")


def normalizuj(typ, wartosc):
    wartosc = str(wartosc).strip()
    if typ == "CVE":
        return wartosc.upper()
    if typ in ("DOMAIN", "HASH"):
        return wartosc.lower()
    return wartosc


def encje_raportow(kanon):
    """Łączy encje z list autorów ('list') i wyciągnięte z tekstu ('text')."""
    raporty = pd.read_csv(f"{PROC_DIR}/otx_reports.csv", dtype=str).fillna("")
    lista = pd.read_csv(f"{PROC_DIR}/otx_indicators.csv", dtype=str).fillna("")
    tekst = pd.read_csv(f"{PROC_DIR}/otx_extracted.csv", dtype=str).fillna("")

    wiersze = []
    for w in lista.itertuples():
        wiersze.append((w.report_id, w.type, w.value, "list"))
    for r in raporty.itertuples():
        for m in r.malware.split(";"):
            if m:
                m = oczysc_nazwe(m)
                wiersze.append((r.id, "MALWARE", kanon.get(m.lower(), m), "list"))
        if r.adversary:
            wiersze.append((r.id, "ACTOR", kanon.get(r.adversary.lower(), r.adversary), "list"))
    for w in tekst.itertuples():
        if w.type in IOC_TYPY | {"CVE", "MALWARE", "ACTOR"}:
            wiersze.append((w.report_id, w.type, w.value, "text"))

    df = pd.DataFrame(wiersze, columns=["report_id", "type", "value", "via"])
    df["value"] = [normalizuj(t, v) for t, v in zip(df["type"], df["value"])]
    # ta sama encja z listy i z tekstu -> via = "list,text"
    df = (df.groupby(["report_id", "type", "value"])["via"]
            .apply(lambda s: ",".join(sorted(set(s)))).reset_index())
    return raporty, df


if __name__ == "__main__":
    slownik = pd.read_csv(f"{PROC_DIR}/entity_dictionary.csv")
    kanon = dict(zip(slownik["key"], slownik["canonical"]))

    raporty, encje = encje_raportow(kanon)

    nvd = pd.read_csv(f"{PROC_DIR}/nvd_extracted.csv", dtype=str).fillna("")
    nvd["value"] = nvd["value"].str.replace(" ", "_")  # zgodnie z nazwami z CPE (windows_server_2025)

    driver = GraphDatabase.driver(
        os.getenv("NEO4J_URI"),
        auth=(os.getenv("NEO4J_USER"), os.getenv("NEO4J_PASSWORD")),
    )
    with driver.session() as s:
        for q in OGRANICZENIA:
            s.run(q)

        wyslij(s, Q_RAPORTY, oczysc(raporty).to_dict("records"), "Raporty OTX")
        wyslij(s, Q_IOC, encje[encje["type"].isin(IOC_TYPY)].to_dict("records"), "Powiązania raport-IoC")
        wyslij(s, Q_CVE, encje[encje["type"] == "CVE"].to_dict("records"), "Powiązania raport-CVE")
        wyslij(s, Q_MALWARE, encje[encje["type"] == "MALWARE"].to_dict("records"), "Powiązania raport-malware")
        wyslij(s, Q_ACTOR, encje[encje["type"] == "ACTOR"].to_dict("records"), "Powiązania raport-aktor")
        s.run(Q_USED_BY)
        wyslij(s, Q_NVD_SOFT, nvd[nvd["type"] == "SOFTWARE"].to_dict("records"), "CVE-produkt (z opisów)")
        wyslij(s, Q_NVD_VENDOR, nvd[nvd["type"] == "VENDOR"].to_dict("records"), "CVE-producent (z opisów)")
        s.run(Q_CZESTOSC)

        print("\nCzy części grafu się połączyły?")
        zapytania = {
            "Raporty łączące IoC z CVE":
                "MATCH (i:IoC)<-[:MENTIONS]-(r:Report)-[:MENTIONS]->(c:CVE) RETURN count(DISTINCT r) AS n",
            "IoC z ThreatFox potwierdzone w raportach OTX":
                "MATCH (:Report {source:'ThreatFox'})-[:MENTIONS]->(i:IoC)<-[:MENTIONS]-(:Report {source:'OTX'}) "
                "RETURN count(DISTINCT i) AS n",
            "Malware występujące w ThreatFox i OTX":
                "MATCH (:IoC)-[:ASSOCIATED_WITH]->(m:Malware)<-[:MENTIONS]-(:Report {source:'OTX'}) "
                "RETURN count(DISTINCT m) AS n",
            "Aktorzy w grafie":
                "MATCH (a:Actor) RETURN count(a) AS n",
            "Powiązania malware -> aktor":
                "MATCH ()-[x:USED_BY]->() RETURN count(x) AS n",
        }
        for opis, q in zapytania.items():
            print(f"  {opis}: {s.run(q).single()['n']}")
    driver.close()