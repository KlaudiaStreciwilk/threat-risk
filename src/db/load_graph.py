"""Ładowanie danych (CVE z NVD/EPSS/KEV oraz IoC z ThreatFox) do grafowej bazy Neo4j."""
import os

import pandas as pd
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

PROC_DIR = "data/processed"
PACZKA = 1000  # ile rekordów wysyłamy do bazy naraz

# Ograniczenia unikalności – każdy obiekt istnieje w bazie tylko raz
# (przy okazji Neo4j tworzy indeksy, co bardzo przyspiesza ładowanie)
OGRANICZENIA = [
    "CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (n:CVE) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT vendor_name IF NOT EXISTS FOR (n:Vendor) REQUIRE n.name IS UNIQUE",
    "CREATE CONSTRAINT product_name IF NOT EXISTS FOR (n:Product) REQUIRE n.name IS UNIQUE",
    "CREATE CONSTRAINT cwe_id IF NOT EXISTS FOR (n:CWE) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT ioc_value IF NOT EXISTS FOR (n:IoC) REQUIRE n.value IS UNIQUE",
    "CREATE CONSTRAINT malware_name IF NOT EXISTS FOR (n:Malware) REQUIRE n.name IS UNIQUE",
    "CREATE CONSTRAINT report_id IF NOT EXISTS FOR (n:Report) REQUIRE n.id IS UNIQUE",
]

ZAPYTANIE_CVE = """
UNWIND $rows AS r
MERGE (c:CVE {id: r.id})
SET c.description     = r.text,
    c.published       = r.published,
    c.status          = r.status,
    c.cvss_score      = r.cvss_score,
    c.cvss_severity   = r.cvss_severity,
    c.cvss_version    = r.cvss_version,
    c.epss            = r.epss,
    c.epss_percentile = r.epss_percentile,
    c.in_kev          = r.in_kev,
    c.kev_ransomware  = r.kev_ransomware,
    c.n_references    = r.n_references
FOREACH (v IN r.vendors  | MERGE (x:Vendor  {name: v}) MERGE (c)-[:AFFECTS_VENDOR]->(x))
FOREACH (p IN r.products | MERGE (x:Product {name: p}) MERGE (c)-[:AFFECTS]->(x))
FOREACH (w IN r.cwe      | MERGE (x:CWE     {id: w})   MERGE (c)-[:HAS_WEAKNESS]->(x))
"""

ZAPYTANIE_IOC = """
UNWIND $rows AS r
MERGE (rep:Report {id: r.id})
SET rep.source      = r.source,
    rep.reference   = r.reference,
    rep.threat_type = r.threat_type,
    rep.confidence  = r.confidence,
    rep.published   = r.first_seen,
    rep.tags        = r.tags,
    rep.text        = r.text
MERGE (i:IoC {value: r.value})
ON CREATE SET i.type = r.type, i.first_seen = r.first_seen
SET i.last_seen = coalesce(r.last_seen, r.first_seen)
MERGE (rep)-[:MENTIONS]->(i)
FOREACH (_ IN CASE WHEN r.malware IS NULL THEN [] ELSE [1] END |
    MERGE (m:Malware {name: r.malware})
    MERGE (i)-[:ASSOCIATED_WITH]->(m)
)
"""

# Wskaźnik reputacji: w ilu raportach pojawił się dany IoC
ZAPYTANIE_CZESTOSC = """
MATCH (i:IoC)
SET i.mentions = COUNT { (i)<-[:MENTIONS]-(:Report) }
"""


def na_liste(tekst):
    """'a;b;c' -> ['a', 'b', 'c'], puste pole -> []"""
    if tekst is None or tekst == "":
        return []
    return [x for x in str(tekst).split(";") if x]


def oczysc(df):
    """Zamienia NaN na None (Neo4j nie rozumie NaN) i typy numpy na zwykłe typy Pythona."""
    return df.astype(object).where(pd.notna(df), None)


def wyslij(session, zapytanie, rekordy, nazwa):
    for i in range(0, len(rekordy), PACZKA):
        session.run(zapytanie, rows=rekordy[i:i + PACZKA])
        print(f"{nazwa}: {min(i + PACZKA, len(rekordy))} / {len(rekordy)}")


def zaladuj_cve(session):
    df = oczysc(pd.read_csv(f"{PROC_DIR}/cves_enriched.csv"))
    rekordy = df.to_dict("records")
    for r in rekordy:
        r["vendors"] = na_liste(r["vendors"])
        r["products"] = na_liste(r["products"])
        r["cwe"] = na_liste(r["cwe"])
    wyslij(session, ZAPYTANIE_CVE, rekordy, "CVE")


def zaladuj_ioc(session):
    df = pd.read_csv(f"{PROC_DIR}/threatfox_iocs.csv")
    # Nieznane malware nie tworzy węzła – inaczej tysiące niezwiązanych IoC
    # byłyby połączone przez wspólny węzeł "Unknown"
    df.loc[df["malware"].fillna("").str.startswith("Unknown"), "malware"] = None
    df = oczysc(df)
    wyslij(session, ZAPYTANIE_IOC, df.to_dict("records"), "IoC")


def podsumowanie(session):
    print("\nWęzły w bazie:")
    for rec in session.run(
        "MATCH (n) RETURN labels(n)[0] AS typ, count(*) AS liczba ORDER BY liczba DESC"
    ):
        print(f"  {rec['typ']:<10} {rec['liczba']}")

    print("\nRelacje w bazie:")
    for rec in session.run(
        "MATCH ()-[r]->() RETURN type(r) AS typ, count(*) AS liczba ORDER BY liczba DESC"
    ):
        print(f"  {rec['typ']:<16} {rec['liczba']}")


if __name__ == "__main__":
    driver = GraphDatabase.driver(
        os.getenv("NEO4J_URI"),
        auth=(os.getenv("NEO4J_USER"), os.getenv("NEO4J_PASSWORD")),
    )
    with driver.session() as session:
        for q in OGRANICZENIA:
            session.run(q)
        print("Ograniczenia utworzone\n")

        zaladuj_cve(session)
        zaladuj_ioc(session)
        session.run(ZAPYTANIE_CZESTOSC)

        podsumowanie(session)
    driver.close()