"""Pobieranie podatności (CVE) z NVD API 2.0 i zapis w ujednoliconym formacie."""
import os
import json
import time
from datetime import datetime, timedelta, timezone

import requests
import pandas as pd
from dotenv import load_dotenv

load_dotenv()

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.getenv("NVD_API_KEY")
RAW_DIR = "data/raw"
PROC_DIR = "data/processed"


def pobierz_nvd(dni=30):
    """Pobiera wszystkie CVE opublikowane w ostatnich `dni` dniach (strona po stronie)."""
    koniec = datetime.now(timezone.utc)
    start = koniec - timedelta(days=dni)
    fmt = "%Y-%m-%dT%H:%M:%S.000"

    params = {
        "pubStartDate": start.strftime(fmt),
        "pubEndDate": koniec.strftime(fmt),
        "resultsPerPage": 2000,
        "startIndex": 0,
    }
    headers = {"apiKey": API_KEY} if API_KEY else {}
    przerwa = 1 if API_KEY else 6  # bez klucza NVD pozwala na mniej zapytań

    wszystkie = []
    while True:
        r = requests.get(NVD_URL, params=params, headers=headers, timeout=60)
        r.raise_for_status()
        dane = r.json()

        wszystkie.extend(dane["vulnerabilities"])
        total = dane["totalResults"]
        print(f"Pobrano {len(wszystkie)} / {total}")

        params["startIndex"] += dane["resultsPerPage"]
        if params["startIndex"] >= total or dane["resultsPerPage"] == 0:
            break
        time.sleep(przerwa)

    return wszystkie


def wyciagnij_cvss(metrics):
    """Zwraca (wynik, poziom, wersja) – bierze najnowszą dostępną wersję CVSS."""
    for klucz in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        lista = metrics.get(klucz, [])
        if lista:
            m = next((x for x in lista if x.get("type") == "Primary"), lista[0])
            d = m["cvssData"]
            poziom = d.get("baseSeverity") or m.get("baseSeverity")
            return d.get("baseScore"), poziom, d.get("version")
    return None, None, None


def wyciagnij_produkty(configurations):
    """Z wpisów CPE wyciąga producentów i produkty (np. microsoft / outlook)."""
    producenci, produkty = set(), set()
    for conf in configurations:
        for node in conf.get("nodes", []):
            for match in node.get("cpeMatch", []):
                czesci = match.get("criteria", "").split(":")
                if len(czesci) > 4:
                    producenci.add(czesci[3])
                    produkty.add(czesci[4])
    return ";".join(sorted(producenci)), ";".join(sorted(produkty))


def ujednolic(vulnerabilities):
    """Zamienia surowe dane NVD na wspólny format rekordów."""
    rekordy = []
    for v in vulnerabilities:
        cve = v["cve"]
        opis = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
        wynik, poziom, wersja = wyciagnij_cvss(cve.get("metrics", {}))
        cwe = {
            d["value"]
            for w in cve.get("weaknesses", [])
            for d in w.get("description", [])
            if d["value"].startswith("CWE-")
        }
        producenci, produkty = wyciagnij_produkty(cve.get("configurations", []))

        rekordy.append({
            "id": cve["id"],
            "source": "NVD",
            "type": "CVE",
            "text": opis,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "status": cve.get("vulnStatus"),
            "cvss_score": wynik,
            "cvss_severity": poziom,
            "cvss_version": wersja,
            "cwe": ";".join(sorted(cwe)),
            "vendors": producenci,
            "products": produkty,
            "n_references": len(cve.get("references", [])),
        })
    return pd.DataFrame(rekordy)


if __name__ == "__main__":
    os.makedirs(RAW_DIR, exist_ok=True)
    os.makedirs(PROC_DIR, exist_ok=True)

    surowe = pobierz_nvd(dni=30)

    with open(f"{RAW_DIR}/nvd_raw.json", "w", encoding="utf-8") as f:
        json.dump(surowe, f)

    df = ujednolic(surowe)
    df.to_csv(f"{PROC_DIR}/nvd_cves.csv", index=False, encoding="utf-8")

    print(f"\nZapisano {len(df)} podatności do {PROC_DIR}/nvd_cves.csv")
    print("\nRozkład poziomów CVSS:")
    print(df["cvss_severity"].value_counts(dropna=False))