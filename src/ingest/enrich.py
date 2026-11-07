"""Wzbogacenie CVE z NVD o ocenę EPSS (FIRST.org) i listę CISA KEV."""
import time

import requests
import pandas as pd

PROC_DIR = "data/processed"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HEADERS = {"User-Agent": "threat-risk-student-project/1.0"}


def pobierz_epss(cve_ids, paczka=100):
    """Pobiera EPSS dla listy CVE, po 100 identyfikatorów w jednym zapytaniu."""
    wyniki = []
    for i in range(0, len(cve_ids), paczka):
        fragment = cve_ids[i:i + paczka]
        r = requests.get(
            EPSS_URL,
            params={"cve": ",".join(fragment), "limit": paczka},
            headers=HEADERS,
            timeout=60,
        )
        r.raise_for_status()
        wyniki.extend(r.json().get("data", []))
        print(f"EPSS: {min(i + paczka, len(cve_ids))} / {len(cve_ids)}")
        time.sleep(0.5)

    df = pd.DataFrame(wyniki)
    if df.empty:
        return pd.DataFrame(columns=["id", "epss", "epss_percentile"])

    df = df.rename(columns={"cve": "id", "percentile": "epss_percentile"})
    df["epss"] = df["epss"].astype(float)
    df["epss_percentile"] = df["epss_percentile"].astype(float)
    return df[["id", "epss", "epss_percentile"]]


def pobierz_kev():
    """Pobiera katalog CISA KEV (podatności wykorzystywane w realnych atakach)."""
    r = requests.get(KEV_URL, headers=HEADERS, timeout=60)
    r.raise_for_status()
    df = pd.DataFrame(r.json()["vulnerabilities"])
    df = df.rename(columns={
        "cveID": "id",
        "dateAdded": "kev_date_added",
        "knownRansomwareCampaignUse": "kev_ransomware",
    })
    return df[["id", "kev_date_added", "kev_ransomware"]]


if __name__ == "__main__":
    cves = pd.read_csv(f"{PROC_DIR}/nvd_cves.csv")
    print(f"Wczytano {len(cves)} CVE z NVD\n")

    epss = pobierz_epss(cves["id"].tolist())
    kev = pobierz_kev()
    print(f"\nKatalog KEV zawiera {len(kev)} podatności")

    df = cves.merge(epss, on="id", how="left").merge(kev, on="id", how="left")
    df["in_kev"] = df["kev_date_added"].notna()

    df.to_csv(f"{PROC_DIR}/cves_enriched.csv", index=False, encoding="utf-8")

    print(f"\nZapisano {len(df)} rekordów do {PROC_DIR}/cves_enriched.csv")
    print(f"CVE z oceną EPSS: {df['epss'].notna().sum()}")
    print(f"CVE obecne w KEV: {df['in_kev'].sum()}")
    print("\nStatystyki EPSS:")
    print(df["epss"].describe())
    print("\nTop 10 CVE wg EPSS:")
    print(
        df.sort_values("epss", ascending=False)
        [["id", "cvss_score", "cvss_severity", "epss", "in_kev"]]
        .head(10)
        .to_string(index=False)
    )