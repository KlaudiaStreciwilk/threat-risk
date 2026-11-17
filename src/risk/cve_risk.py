"""Dynamiczna ocena ryzyka podatności (CVE) w skali 0-100."""
import numpy as np
import pandas as pd

PROC_DIR = "data/processed"

# ===== Parametry algorytmu (wszystko w jednym miejscu) =====
WAGI_RDZENIA = {"powaga": 0.45, "atak": 0.55}   # dobrane na podstawie analizy wrażliwości (krok 5c)  # podstawa: jak groźna jest dziura i czy zaatakują
WZMOCNIENIE = {"rynek": 0.30, "graf": 0.30}     # kontekst podnosi ryzyko, a jego brak go nie obniża
WAGI_RYNKU = {"popularnosc": 0.5, "wzmianki": 0.3, "ransomware": 0.2}
POLOWICZNY_ZANIK_DNI = 30     # co tyle dni czynnik świeżości maleje o połowę
MIN_RYZYKO_KEV = 70           # podatność faktycznie atakowana ma co najmniej tyle
NASYCENIE_WZMIANEK = 5        # od tylu raportów wzmianki dają maksimum
GRAF_AKTOR, GRAF_MALWARE = 1.0, 0.6


def data(kolumna):
    return pd.to_datetime(kolumna, utc=True, errors="coerce", format="mixed")


def raporty_o_cve():
    """Które raporty OTX wspominają które CVE, kiedy, i czy wskazują aktora lub malware."""
    rap = pd.read_csv(f"{PROC_DIR}/otx_reports.csv", dtype=str).fillna("")
    ext = pd.read_csv(f"{PROC_DIR}/otx_extracted.csv", dtype=str).fillna("")

    pary = [(r.id, c) for r in rap.itertuples() for c in r.cves.split(";") if c]
    pary += [(w.report_id, w.value) for w in ext[ext["type"] == "CVE"].itertuples()]
    pary = pd.DataFrame(pary, columns=["report_id", "cve"]).drop_duplicates()

    z_aktorem = set(rap.loc[rap["adversary"] != "", "id"]) | set(ext.loc[ext["type"] == "ACTOR", "report_id"])
    z_malware = set(rap.loc[rap["malware"] != "", "id"]) | set(ext.loc[ext["type"] == "MALWARE", "report_id"])
    daty = dict(zip(rap["id"], data(rap["published"])))

    pary["z_aktorem"] = pary["report_id"].isin(z_aktorem)
    pary["z_malware"] = pary["report_id"].isin(z_malware)
    pary["data"] = pary["report_id"].map(daty)

    return pary.groupby("cve").agg(
        n_raportow=("report_id", "nunique"),
        z_aktorem=("z_aktorem", "any"),
        z_malware=("z_malware", "any"),
        ostatnia_wzmianka=("data", "max"),
    )


def popularnosc_producentow(cves):
    """Popularność producenta = (logarytm) liczby jego podatności; dla CVE bierzemy najpopularniejszego."""
    nvd_ext = pd.read_csv(f"{PROC_DIR}/nvd_extracted.csv", dtype=str).fillna("")

    pary = [(r.id, v) for r in cves.itertuples() for v in str(r.vendors).split(";") if v and v != "nan"]
    pary += [(r.cve_id, r.value.replace(" ", "_").lower())
             for r in nvd_ext[nvd_ext["type"] == "VENDOR"].itertuples()]
    pary = pd.DataFrame(pary, columns=["cve", "vendor"]).drop_duplicates()

    liczba = pary.groupby("vendor")["cve"].nunique()
    pary["pop"] = np.log1p(pary["vendor"].map(liczba)) / np.log1p(liczba.max())
    return pary.sort_values("pop").groupby("cve").last()[["vendor", "pop"]]


def oblicz_ryzyko():
    cves = pd.read_csv(f"{PROC_DIR}/cves_enriched.csv", dtype={"vendors": str, "kev_ransomware": str})
    cves = cves[cves["status"] != "Rejected"].copy()
    cves = cves.merge(pd.read_csv(f"{PROC_DIR}/cve_text_scores.csv"), on="id", how="left")

    df = (cves
          .merge(raporty_o_cve(), left_on="id", right_index=True, how="left")
          .merge(popularnosc_producentow(cves), left_on="id", right_index=True, how="left"))
    kev = df["in_kev"].astype(str).str.lower() == "true"

    # 1. Powaga
    df["s_powaga"] = (df["cvss_score"] / 10).fillna(df["text_score"]).fillna(0.5)
    df["zrodlo_powagi"] = np.select(
        [df["cvss_score"].notna(), df["text_score"].notna()], ["CVSS", "klasyfikator"], "brak")

    # 2. Prawdopodobieństwo ataku
    epss_p = df["epss_percentile"].fillna(0.5)
    df["s_atak"] = np.where(kev, 1.0, epss_p)
    df["s_atak_bez_kev"] = epss_p

    # 3. Kontekst rynkowy
    n = df["n_raportow"].fillna(0)
    df["n_raportow"] = n
    df["r_popularnosc"] = df["pop"].fillna(0)
    df["r_wzmianki"] = np.minimum(1, np.log1p(n) / np.log1p(NASYCENIE_WZMIANEK))
    df["r_ransomware"] = (df["kev_ransomware"].astype(str).str.lower() == "known").astype(float)
    df["s_rynek"] = (WAGI_RYNKU["popularnosc"] * df["r_popularnosc"]
                     + WAGI_RYNKU["wzmianki"] * df["r_wzmianki"]
                     + WAGI_RYNKU["ransomware"] * df["r_ransomware"])
    df["s_rynek_bez_kev"] = (WAGI_RYNKU["popularnosc"] * df["r_popularnosc"]
                             + WAGI_RYNKU["wzmianki"] * df["r_wzmianki"]) / (1 - WAGI_RYNKU["ransomware"])

    # 4. Reputacja w grafie
    aktor = df["z_aktorem"].fillna(False).astype(bool)
    malware = df["z_malware"].fillna(False).astype(bool)
    df["s_graf"] = np.select([aktor, malware], [GRAF_AKTOR, GRAF_MALWARE], 0.0)

    # 5. Świeżość
    teraz = pd.Timestamp.now(tz="UTC")
    ostatnia = pd.concat(
        [data(df["published"]), data(df["kev_date_added"]), df["ostatnia_wzmianka"]], axis=1
    ).max(axis=1)
    df["dni_od_aktywnosci"] = (teraz - ostatnia).dt.days.clip(lower=0).fillna(365)
    df["swiezosc"] = 0.5 + 0.5 * 0.5 ** (df["dni_od_aktywnosci"] / POLOWICZNY_ZANIK_DNI)

    # Wynik końcowy: rdzeń wzmocniony kontekstem
    rdzen = WAGI_RDZENIA["powaga"] * df["s_powaga"] + WAGI_RDZENIA["atak"] * df["s_atak"]
    wzmocnienie = 1 + WZMOCNIENIE["rynek"] * df["s_rynek"] + WZMOCNIENIE["graf"] * df["s_graf"]
    df["ryzyko"] = (100 * np.minimum(1, rdzen * wzmocnienie) * df["swiezosc"]).round(1)
    df.loc[kev, "ryzyko"] = df.loc[kev, "ryzyko"].clip(lower=MIN_RYZYKO_KEV)

    # Wersja bez informacji z KEV – do uczciwej oceny w kroku 5c
    rdzen_bk = WAGI_RDZENIA["powaga"] * df["s_powaga"] + WAGI_RDZENIA["atak"] * df["s_atak_bez_kev"]
    wzm_bk = 1 + WZMOCNIENIE["rynek"] * df["s_rynek_bez_kev"] + WZMOCNIENIE["graf"] * df["s_graf"]
    df["ryzyko_bez_kev"] = (100 * np.minimum(1, rdzen_bk * wzm_bk) * df["swiezosc"]).round(1)

    df["poziom"] = pd.cut(df["ryzyko"], bins=[0, 30, 60, 80, 100.1],
                          labels=["niskie", "średnie", "wysokie", "krytyczne"], right=False)
    df["in_kev"] = kev
    return df


if __name__ == "__main__":
    df = oblicz_ryzyko()

    kolumny = ["id", "ryzyko", "poziom", "ryzyko_bez_kev",
               "s_powaga", "zrodlo_powagi", "s_atak", "s_rynek", "s_graf", "swiezosc",
               "r_popularnosc", "r_wzmianki", "r_ransomware",
               "cvss_score", "epss", "epss_percentile", "in_kev", "vendor",
               "n_raportow", "dni_od_aktywnosci", "text"]
    df[kolumny].sort_values("ryzyko", ascending=False).to_csv(
        f"{PROC_DIR}/cve_risk.csv", index=False, encoding="utf-8")

    pd.set_option("display.width", 200)
    print(f"Oceniono {len(df)} podatności\n")
    print("Poziomy ryzyka:")
    print(df["poziom"].value_counts().sort_index())
    print("\nŹródło oceny powagi:")
    print(df["zrodlo_powagi"].value_counts())

    print("\nTop 15 najbardziej ryzykownych:")
    print(df.nlargest(15, "ryzyko")[
        ["id", "ryzyko", "cvss_score", "epss_percentile", "in_kev", "vendor", "n_raportow", "s_graf"]
    ].to_string(index=False))

    najwyzsza = df.nlargest(1, "ryzyko").iloc[0]
    print(f"\nRozbicie wyniku dla {najwyzsza['id']}:")
    for skladnik in ["s_powaga", "s_atak", "s_rynek", "s_graf", "swiezosc"]:
        print(f"  {skladnik:<10} {najwyzsza[skladnik]:.3f}")