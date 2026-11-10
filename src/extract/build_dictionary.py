"""Budowa słownika nazw: aktorzy (APT), malware, oprogramowanie i producenci."""
import os
import re
import json

import requests
import pandas as pd
from wordfreq import zipf_frequency

RAW_DIR = "data/raw"
PROC_DIR = "data/processed"
MITRE_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
             "master/enterprise-attack/enterprise-attack.json")
MITRE_PLIK = f"{RAW_DIR}/mitre_attack.json"

# Gdy ta sama nazwa trafi do kilku kategorii, wygrywa ta z niższą liczbą
PRIORYTET = {"ACTOR": 0, "MALWARE": 1, "VENDOR": 2, "SOFTWARE": 3}

# Słowa zbyt ogólne (w tym branżowe), które dawałyby fałszywe trafienia
ZBYT_OGOLNE = {
    "unknown", "none", "other", "generic", "malware", "trojan", "backdoor",
    "loader", "stealer", "ransomware", "botnet", "update", "agent", "client",
    "server", "service", "system", "edge", "exchange", "teams", "office",
    "word", "access", "project", "visual", "core", "data", "network",
    "payload", "endpoint", "beacon", "implant", "dropper", "shell", "exploit",
    "shellcode", "webshell", "miner", "worm", "spyware", "wiper", "keylogger",
    "downloader", "injector", "crypter", "proxy", "tunnel", "scanner", "nexus",
}




def oczysc_nazwe(nazwa):
    """'Cobalt Strike - S0154' -> 'Cobalt Strike'"""
    return re.sub(r"\s+-\s+S\d{4}$", "", str(nazwa)).strip()

def zwykle_slowo(alias, zrodlo):
    """True, jeśli alias to jedno popularne angielskie słowo (np. 'Play', 'Elise')."""
    if not alias.isalpha():
        return False  # nazwy z cyframi lub myślnikami (APT-C-23, Aria-body) to nie zwykłe słowa
    # Skala Zipfa: 3 = słowo występujące średnio raz na milion słów.
    # Nazwom z aktualnych feedów (ThreatFox, OTX) ufamy bardziej niż archiwum MITRE.
    prog = 3.0 if zrodlo == "MITRE" else 4.0
    return zipf_frequency(alias.lower(), "en") >= prog


def pobierz_mitre():
    if not os.path.exists(MITRE_PLIK):
        print("Pobieram MITRE ATT&CK (ok. 40 MB, tylko za pierwszym razem)...")
        r = requests.get(MITRE_URL, timeout=300)
        r.raise_for_status()
        with open(MITRE_PLIK, "wb") as f:
            f.write(r.content)
    with open(MITRE_PLIK, encoding="utf-8") as f:
        return json.load(f)["objects"]


def z_mitre():
    wiersze = []
    for o in pobierz_mitre():
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        if o["type"] == "intrusion-set":
            etykieta, aliasy = "ACTOR", o.get("aliases", [])
        elif o["type"] == "malware":
            etykieta, aliasy = "MALWARE", o.get("x_mitre_aliases", [])
        else:
            continue
        nazwa = o["name"]
        for a in {nazwa, *aliasy}:
            wiersze.append((a, etykieta, nazwa, "MITRE"))
    return wiersze


def z_threatfox():
    df = pd.read_csv(f"{PROC_DIR}/threatfox_iocs.csv")
    wiersze = []
    for nazwa, aliasy in df[["malware", "malware_alias"]].drop_duplicates().itertuples(index=False):
        if pd.isna(nazwa) or str(nazwa).startswith("Unknown"):
            continue
        nazwa = oczysc_nazwe(nazwa)
        wiersze.append((nazwa, "MALWARE", nazwa, "ThreatFox"))
        if pd.notna(aliasy):
            for a in str(aliasy).split(","):
                wiersze.append((a.strip(), "MALWARE", nazwa, "ThreatFox"))
    return wiersze


def z_otx():
    df = pd.read_csv(f"{PROC_DIR}/otx_reports.csv", dtype=str).fillna("")
    wiersze = []
    for pole in df["malware"]:
        for m in str(pole).split(";"):
            if m:
                m = oczysc_nazwe(m)
                wiersze.append((m, "MALWARE", m, "OTX"))
    for a in df["adversary"]:
        if a:
            wiersze.append((a, "ACTOR", a, "OTX"))
    return wiersze


def z_nvd():
    df = pd.read_csv(f"{PROC_DIR}/cves_enriched.csv", usecols=["products", "vendors"], dtype=str).fillna("")
    wiersze = []
    for pole in df["products"]:
        for p in str(pole).split(";"):
            if not p:
                continue
            pelna = p.replace("_", " ")
            # windows_11_24h2 -> windows ; windows_server_2025 -> windows server
            baza = re.sub(r"(_\d[\w.]*)+$", "", p).replace("_", " ")
            wiersze.append((pelna, "SOFTWARE", pelna, "NVD"))
            wiersze.append((baza, "SOFTWARE", baza, "NVD"))
    for pole in df["vendors"]:
        for v in str(pole).split(";"):
            if v:
                v = v.replace("_", " ")
                wiersze.append((v, "VENDOR", v, "NVD"))
    return wiersze


if __name__ == "__main__":
    wiersze = z_mitre() + z_threatfox() + z_otx() + z_nvd()
    df = pd.DataFrame(wiersze, columns=["alias", "label", "canonical", "source"])

    df["alias"] = df["alias"].astype(str).str.strip()
    df["key"] = df["alias"].str.lower()
    df = df[
        (df["alias"].str.len() >= 4)
        & (~df["key"].isin(ZBYT_OGOLNE))
        & (~df["alias"].str.isdigit())
    ]

    # Odrzucenie zwykłych angielskich słów – tylko dla malware i aktorów
    do_sprawdzenia = df["label"].isin(["MALWARE", "ACTOR"])
    czy_slowo = df.apply(lambda r: zwykle_slowo(r["alias"], r["source"]), axis=1)
    odrzucone = df[do_sprawdzenia & czy_slowo]
    df = df.drop(odrzucone.index)

    # Jedna nazwa = jedna kategoria (według priorytetu)
    df["prio"] = df["label"].map(PRIORYTET)
    df = df.sort_values(["prio", "source"]).drop_duplicates("key")
    df = df.drop(columns=["prio"])

    df.to_csv(f"{PROC_DIR}/entity_dictionary.csv", index=False, encoding="utf-8")

    utracone = sorted(set(odrzucone["key"]) - set(df["key"]))
    print(f"Odrzucono {len(utracone)} nazw będących zwykłymi słowami:")
    print("  " + ", ".join(utracone[:40]))
    print(f"\nSłownik zawiera {len(df)} nazw\n")
    print("Według kategorii:")
    print(df["label"].value_counts())
    for nazwa in ["amos", "akira", "apt-c-23", "play", "elise"]:
        print(f"  {nazwa:<10} w słowniku: {nazwa in set(df['key'])}")