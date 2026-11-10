"""Pobieranie raportów o zagrożeniach (tzw. pulsów) z AlienVault OTX."""
import os
import json
import time
from datetime import datetime, timedelta, timezone

import requests
import pandas as pd
from dotenv import load_dotenv

load_dotenv()

URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
API_KEY = os.getenv("OTX_API_KEY")
RAW_DIR = "data/raw"
PROC_DIR = "data/processed"

# Ujednolicenie typów wskaźników z OTX do naszych kategorii
TYPY = {
    "IPv4": "IP",
    "IPv6": "IP",
    "domain": "DOMAIN",
    "hostname": "DOMAIN",
    "URL": "URL",
    "FileHash-MD5": "HASH",
    "FileHash-SHA1": "HASH",
    "FileHash-SHA256": "HASH",
    "CVE": "CVE",
}


def pobierz_pulsy(dni=30, max_stron=30):
    """Pobiera raporty zmienione w ostatnich `dni` dniach (po 20 na stronę)."""
    if not API_KEY:
        raise SystemExit("Brak OTX_API_KEY w pliku .env")

    od = (datetime.now(timezone.utc) - timedelta(days=dni)).strftime("%Y-%m-%dT%H:%M:%S")
    params = {"limit": 20, "page": 1, "modified_since": od}
    headers = {"X-OTX-API-KEY": API_KEY}

    pulsy = []
    while params["page"] <= max_stron:
        r = requests.get(URL, params=params, headers=headers, timeout=120)
        r.raise_for_status()
        dane = r.json()
        wyniki = dane.get("results", [])
        pulsy.extend(wyniki)
        print(f"Strona {params['page']}: mamy {len(pulsy)} raportów "
              f"(dostępnych łącznie: {dane.get('count', '?')})")

        if not dane.get("next") or not wyniki:
            break
        params["page"] += 1
        time.sleep(1)
    return pulsy


def nazwy(lista):
    """OTX zapisuje nazwy malware raz jako tekst, raz jako słownik – obsługujemy oba."""
    wynik = []
    for x in lista or []:
        if isinstance(x, dict):
            wynik.append(x.get("display_name") or x.get("name") or "")
        else:
            wynik.append(str(x))
    return [w for w in wynik if w]


def ujednolic(pulsy):
    """Zwraca dwie tabele: raporty (teksty) i wskaźniki wymienione w raportach."""
    raporty, wskazniki = [], []
    for p in pulsy:
        rid = f"OTX-{p['id']}"
        ind = p.get("indicators") or []
        cves = sorted({i["indicator"] for i in ind if i.get("type") == "CVE"})
        opis = p.get("description") or ""

        raporty.append({
            "id": rid,
            "source": "OTX",
            "title": p.get("name", ""),
            "text": f"{p.get('name', '')}. {opis}".strip(),
            "published": p.get("created"),
            "modified": p.get("modified"),
            "author": p.get("author_name"),
            "adversary": p.get("adversary") or "",
            "malware": ";".join(nazwy(p.get("malware_families"))),
            "tags": ";".join(p.get("tags") or []),
            "industries": ";".join(p.get("industries") or []),
            "references": ";".join(p.get("references") or []),
            "cves": ";".join(cves),
            "n_indicators": len(ind),
        })

        for i in ind:
            typ = TYPY.get(i.get("type"))
            if typ:
                wskazniki.append({
                    "report_id": rid,
                    "type": typ,
                    "value": i["indicator"],
                    "otx_type": i.get("type"),
                })
    return pd.DataFrame(raporty), pd.DataFrame(wskazniki)


if __name__ == "__main__":
    os.makedirs(RAW_DIR, exist_ok=True)
    os.makedirs(PROC_DIR, exist_ok=True)

    pulsy = pobierz_pulsy(dni=30)

    with open(f"{RAW_DIR}/otx_raw.json", "w", encoding="utf-8") as f:
        json.dump(pulsy, f)

    raporty, wskazniki = ujednolic(pulsy)
    raporty.to_csv(f"{PROC_DIR}/otx_reports.csv", index=False, encoding="utf-8")
    wskazniki.to_csv(f"{PROC_DIR}/otx_indicators.csv", index=False, encoding="utf-8")

    print(f"\nZapisano {len(raporty)} raportów i {len(wskazniki)} wskaźników")
    print(f"Średnia długość tekstu raportu: {raporty['text'].str.len().mean():.0f} znaków")
    print(f"Raporty z podanym aktorem (APT): {(raporty['adversary'] != '').sum()}")
    print(f"Raporty wymieniające CVE: {(raporty['cves'] != '').sum()}")

    print("\nTypy wskaźników:")
    print(wskazniki["type"].value_counts())

    print("\nNajczęstsi aktorzy:")
    print(raporty.loc[raporty["adversary"] != "", "adversary"].value_counts().head(10))

    print("\nNajczęstsze malware:")
    print(
        raporty["malware"].str.split(";").explode()
        .loc[lambda s: s != ""].value_counts().head(10)
    )