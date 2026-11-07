"""Pobieranie wskaźników kompromitacji (IoC) z ThreatFox (abuse.ch)."""
import os
import json

import requests
import pandas as pd
from dotenv import load_dotenv

load_dotenv()

URL = "https://threatfox-api.abuse.ch/api/v1/"
AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY")
RAW_DIR = "data/raw"
PROC_DIR = "data/processed"

# Ujednolicone nazwy typów IoC
TYPY = {
    "ip:port": "IP",
    "domain": "DOMAIN",
    "url": "URL",
    "md5_hash": "HASH",
    "sha1_hash": "HASH",
    "sha256_hash": "HASH",
}


def pobierz_threatfox(dni=7):
    """Pobiera IoC dodane do ThreatFox w ostatnich `dni` dniach (maksymalnie 7)."""
    if not AUTH_KEY:
        raise SystemExit("Brak ABUSECH_AUTH_KEY w pliku .env")

    r = requests.post(
        URL,
        json={"query": "get_iocs", "days": dni},
        headers={"Auth-Key": AUTH_KEY},
        timeout=120,
    )
    r.raise_for_status()
    dane = r.json()

    if dane.get("query_status") != "ok":
        raise SystemExit(f"ThreatFox zwrócił: {dane.get('query_status')}")
    return dane["data"]


def ujednolic(iocs):
    """Zamienia surowe dane ThreatFox na wspólny format rekordów."""
    rekordy = []
    for x in iocs:
        typ_oryg = x.get("ioc_type") or ""
        wartosc = x["ioc"]
        if typ_oryg == "ip:port":
            wartosc = wartosc.rsplit(":", 1)[0]  # 1.2.3.4:443 -> 1.2.3.4

        tagi = x.get("tags") or []
        malware = x.get("malware_printable") or ""
        opis_zagrozenia = x.get("threat_type_desc") or ""

        rekordy.append({
            "id": f"TF-{x['id']}",
            "source": "ThreatFox",
            "type": TYPY.get(typ_oryg, typ_oryg.upper()),
            "value": wartosc,
            "ioc_type_detail": typ_oryg,
            "malware": malware,
            "malware_alias": x.get("malware_alias"),
            "threat_type": x.get("threat_type"),
            "confidence": x.get("confidence_level"),
            "first_seen": x.get("first_seen"),
            "last_seen": x.get("last_seen"),
            "tags": ";".join(tagi),
            "reference": x.get("reference"),
            "text": f"{opis_zagrozenia}. Malware: {malware}. Tags: {', '.join(tagi)}",
        })
    return pd.DataFrame(rekordy)


if __name__ == "__main__":
    os.makedirs(RAW_DIR, exist_ok=True)
    os.makedirs(PROC_DIR, exist_ok=True)

    surowe = pobierz_threatfox(dni=7)

    with open(f"{RAW_DIR}/threatfox_raw.json", "w", encoding="utf-8") as f:
        json.dump(surowe, f)

    df = ujednolic(surowe)
    df.to_csv(f"{PROC_DIR}/threatfox_iocs.csv", index=False, encoding="utf-8")

    print(f"Zapisano {len(df)} IoC do {PROC_DIR}/threatfox_iocs.csv")
    print("\nTypy IoC:")
    print(df["type"].value_counts())
    print("\nTop 10 rodzin malware:")
    print(df["malware"].value_counts().head(10))
    print("\nŚredni poziom pewności (confidence):", round(df["confidence"].mean(), 1))