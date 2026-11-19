"""Ocena reputacji wskaźników kompromitacji (IoC) w skali 0-100."""
import os
import io
import re
import zipfile

import numpy as np
import pandas as pd
import requests
import tldextract

from src.extract.build_dictionary import oczysc_nazwe

RAW_DIR = "data/raw"
PROC_DIR = "data/processed"

# ===== Parametry algorytmu =====
WAGI_RDZENIA = {"pewnosc": 0.5, "powiazania": 0.5}
WZMOCNIENIE = {"czestosc": 0.4, "zrodla": 0.3}
NORMALIZACJA = 1.3             # wynik wiarygodnego IoC zgłoszonego średnio często – zapobiega obcinaniu do maksimum
NASYCENIE_ZGLOSZEN = 10        # od tylu zgłoszeń częstotliwość daje maksimum
POLOWICZNY_ZANIK_DNI = 14      # IoC starzeją się szybciej niż podatności
PEWNOSC_OTX = 0.7              # raporty OTX nie podają pewności – przyjmujemy stałą
POW_AKTOR, POW_MALWARE = 1.0, 0.7
KARA_POPULARNA_DOMENA = 0.2
TOP_POPULARNYCH = 100_000
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_PLIK = f"{RAW_DIR}/tranco_top1m.csv"
IOC_TYPY = {"IP", "DOMAIN", "URL", "HASH"}

_tld = tldextract.TLDExtract(suffix_list_urls=())


def data(kolumna):
    return pd.to_datetime(kolumna, utc=True, errors="coerce", format="mixed")


def norm(typ, wartosc):
    wartosc = str(wartosc).strip()
    return wartosc.lower() if typ in ("DOMAIN", "HASH") else wartosc


def popularne_domeny():
    """Lista najpopularniejszych domen świata (Tranco) – do odróżnienia stron legalnych."""
    if not os.path.exists(TRANCO_PLIK):
        try:
            print("Pobieram listę najpopularniejszych domen (Tranco)...")
            r = requests.get(TRANCO_URL, timeout=180)
            r.raise_for_status()
            with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                with z.open(z.namelist()[0]) as f, open(TRANCO_PLIK, "wb") as wyj:
                    wyj.write(f.read())
        except Exception as e:
            print(f"Nie udało się pobrać listy Tranco ({e}) – pomijam karę za popularne domeny")
            return set()
    lista = pd.read_csv(TRANCO_PLIK, header=None, names=["pozycja", "domena"], nrows=TOP_POPULARNYCH)
    return set(lista["domena"].str.lower())


def host(typ, wartosc):
    """Nazwa serwera: dla domeny ona sama, dla URL część między :// a pierwszym /."""
    if typ == "DOMAIN":
        return wartosc.lower()
    if typ == "URL":
        return re.sub(r"^[a-z]+://", "", wartosc, flags=re.IGNORECASE).split("/")[0].split(":")[0].lower()
    return None


def domena_glowna(nazwa_hosta):
    """'sub.evil.com' -> 'evil.com'"""
    if not nazwa_hosta:
        return None
    czesci = _tld(nazwa_hosta)
    return f"{czesci.domain}.{czesci.suffix}" if czesci.domain and czesci.suffix else None


def strona_glowna(typ, wartosc):
    """True dla samej domeny lub URL bez ścieżki; False dla konkretnego pliku, profilu itp."""
    if typ == "DOMAIN":
        return True
    sciezka = re.sub(r"^[a-z]+://[^/]+", "", wartosc, flags=re.IGNORECASE)
    return sciezka in ("", "/")

def czy_ukarac(typ, wartosc, popularne):
    """Kara tylko dla SAMEJ popularnej domeny lub jej strony głównej (booking.com, https://booking.com/),
    a nie dla subdomen na darmowych serwisach (evil.mooo.com) ani konkretnych linków (github.com/.../malware.zip)."""
    h = host(typ, wartosc)
    d = domena_glowna(h)
    return bool(h) and bool(d) and d in popularne and h in (d, f"www.{d}") and strona_glowna(typ, wartosc)

def zgloszenia():
    """Wszystkie zgłoszenia IoC z ThreatFox i OTX w jednej tabeli."""
    wiersze = []

    tf = pd.read_csv(f"{PROC_DIR}/threatfox_iocs.csv")
    tf_data = pd.concat([data(tf["last_seen"]), data(tf["first_seen"])], axis=1).max(axis=1)
    for r, d in zip(tf.itertuples(), tf_data):
        znane = isinstance(r.malware, str) and not r.malware.startswith("Unknown")
        wiersze.append({
            "value": norm(r.type, r.value), "type": r.type, "zrodlo": "ThreatFox",
            "report_id": r.id, "pewnosc": (r.confidence or 0) / 100,
            "aktor": False, "malware": znane,
            "malware_nazwa": r.malware if znane else "", "data": d,
        })

    rap = pd.read_csv(f"{PROC_DIR}/otx_reports.csv", dtype=str).fillna("")
    ext = pd.read_csv(f"{PROC_DIR}/otx_extracted.csv", dtype=str).fillna("")
    ind = pd.read_csv(f"{PROC_DIR}/otx_indicators.csv", dtype=str).fillna("")

    z_aktorem = set(rap.loc[rap["adversary"] != "", "id"]) | set(ext.loc[ext["type"] == "ACTOR", "report_id"])
    z_malware = set(rap.loc[rap["malware"] != "", "id"]) | set(ext.loc[ext["type"] == "MALWARE", "report_id"])
    nazwy = dict(zip(rap["id"], rap["malware"].str.split(";").str[0]))
    daty = dict(zip(rap["id"], pd.concat([data(rap["published"]), data(rap["modified"])], axis=1).max(axis=1)))

    otx = pd.concat([ind[["report_id", "type", "value"]], ext[["report_id", "type", "value"]]])
    otx = otx[otx["type"].isin(IOC_TYPY)]
    for r in otx.itertuples():
        wiersze.append({
            "value": norm(r.type, r.value), "type": r.type, "zrodlo": "OTX",
            "report_id": r.report_id, "pewnosc": PEWNOSC_OTX,
            "aktor": r.report_id in z_aktorem, "malware": r.report_id in z_malware,
            "malware_nazwa": oczysc_nazwe(nazwy.get(r.report_id, "")), "data": daty.get(r.report_id),
        })

    return pd.DataFrame(wiersze)


def oblicz_reputacje():
    z = zgloszenia()
    z["data"] = pd.to_datetime(z["data"], utc=True)

    df = z.groupby("value").agg(
        type=("type", "first"),
        n_zgloszen=("report_id", "nunique"),
        n_zrodel=("zrodlo", "nunique"),
        zrodla=("zrodlo", lambda s: ",".join(sorted(set(s)))),
        pewnosc=("pewnosc", "max"),
        aktor=("aktor", "any"),
        malware=("malware", "any"),
        malware_nazwa=("malware_nazwa", lambda s: ", ".join(sorted({x for x in s if x}))[:80]),
        ostatnio=("data", "max"),
    ).reset_index()

    # Rdzeń
    df["s_pewnosc"] = df["pewnosc"]
    df["s_powiazania"] = np.select([df["aktor"], df["malware"]], [POW_AKTOR, POW_MALWARE], 0.0)
    rdzen = WAGI_RDZENIA["pewnosc"] * df["s_pewnosc"] + WAGI_RDZENIA["powiazania"] * df["s_powiazania"]

    # Wzmocnienie
    df["s_czestosc"] = np.minimum(1, np.log1p(df["n_zgloszen"]) / np.log1p(NASYCENIE_ZGLOSZEN))
    df["s_zrodla"] = (df["n_zrodel"] >= 2).astype(float)
    wzmocnienie = 1 + WZMOCNIENIE["czestosc"] * df["s_czestosc"] + WZMOCNIENIE["zrodla"] * df["s_zrodla"]

    # Świeżość
    teraz = pd.Timestamp.now(tz="UTC")
    df["dni_od_zgloszenia"] = (teraz - df["ostatnio"]).dt.days.clip(lower=0).fillna(60)
    df["swiezosc"] = 0.5 + 0.5 * 0.5 ** (df["dni_od_zgloszenia"] / POLOWICZNY_ZANIK_DNI)

    # Kara tylko dla SAMEJ popularnej domeny lub jej strony głównej (booking.com, https://booking.com/),
    # a nie dla subdomen na darmowych serwisach (evil.mooo.com) ani konkretnych linków (github.com/.../malware.zip)
    popularne = popularne_domeny()
    df["domena_glowna"] = [domena_glowna(host(t, v)) for t, v in zip(df["type"], df["value"])]
    df["popularna_domena"] = [czy_ukarac(t, v, popularne) for t, v in zip(df["type"], df["value"])]
    kara = np.where(df["popularna_domena"], KARA_POPULARNA_DOMENA, 1.0)

    wynik = np.minimum(1, rdzen * wzmocnienie / NORMALIZACJA)
    df["reputacja"] = (100 * wynik * df["swiezosc"] * kara).round(1)
    df["poziom"] = pd.cut(df["reputacja"], bins=[0, 30, 60, 80, 100.1],
                          labels=["niskie", "średnie", "wysokie", "krytyczne"], right=False)
    return df


if __name__ == "__main__":
    df = oblicz_reputacje()
    df = df.sort_values(["reputacja", "n_zgloszen"], ascending=False)
    df.to_csv(f"{PROC_DIR}/ioc_reputation.csv", index=False, encoding="utf-8")

    pd.set_option("display.width", 200)
    print(f"\nOceniono {len(df)} unikalnych IoC")
    print(f"Potwierdzone przez dwa źródła: {(df['n_zrodel'] >= 2).sum()}")
    print(f"Popularne (legalne) domeny ukarane: {df['popularna_domena'].sum()}\n")

    print("Poziomy według typu:")
    print(pd.crosstab(df["type"], df["poziom"]))

    print("\nTop 15 IoC o najgorszej reputacji:")
    print(df.head(15)[
        ["value", "type", "reputacja", "n_zgloszen", "zrodla", "malware_nazwa", "dni_od_zgloszenia"]
    ].to_string(index=False))

    print("\nPrzykłady ukaranych popularnych domen:")
    print(df[df["popularna_domena"]].nlargest(10, "n_zgloszen")[
        ["value", "type", "reputacja", "zrodla"]
    ].to_string(index=False))