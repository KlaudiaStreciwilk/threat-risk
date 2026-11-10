"""Ocena skuteczności ekstrakcji encji – porównanie z polami wypełnionymi przez autorów raportów OTX."""
import pandas as pd

from src.extract.regex_extractor import napraw_tekst
from src.extract.ner_extractor import wyciagnij_wszystko
from src.extract.build_dictionary import oczysc_nazwe

PROC_DIR = "data/processed"
TYPY = ["CVE", "IP", "DOMAIN", "URL", "HASH", "MALWARE", "ACTOR"]


def norm(typ, wartosc):
    wartosc = str(wartosc).strip()
    return wartosc.upper() if typ == "CVE" else wartosc.lower()


def wczytaj_referencje(raporty, wskazniki, kanon):
    """Referencja = to, co autor raportu wpisał do ustrukturyzowanych pól."""
    ref = {rid: {t: set() for t in TYPY} for rid in raporty["id"]}

    for w in wskazniki.itertuples():
        if w.report_id in ref and w.type in TYPY:
            ref[w.report_id][w.type].add(norm(w.type, w.value))

    for r in raporty.itertuples():
        for m in str(r.malware).split(";"):
            if m:
                m = oczysc_nazwe(m)
                ref[r.id]["MALWARE"].add(norm("MALWARE", kanon.get(m.lower(), m)))
        if r.adversary:
            a = r.adversary
            ref[r.id]["ACTOR"].add(norm("ACTOR", kanon.get(a.lower(), a)))
    return ref


def dziel(a, b):
    return round(a / b, 3) if b else None


if __name__ == "__main__":
    raporty = pd.read_csv(f"{PROC_DIR}/otx_reports.csv", dtype=str).fillna("")
    wskazniki = pd.read_csv(f"{PROC_DIR}/otx_indicators.csv", dtype=str).fillna("")
    slownik = pd.read_csv(f"{PROC_DIR}/entity_dictionary.csv")
    kanon = dict(zip(slownik["key"], slownik["canonical"]))

    ref = wczytaj_referencje(raporty, wskazniki, kanon)

    liczniki = {t: {"tp": 0, "fp": 0, "ref": 0, "ref_w_tekscie": 0, "tp_w_tekscie": 0} for t in TYPY}
    bledne = {t: [] for t in TYPY}

    for r in raporty.itertuples():
        tekst = napraw_tekst(r.text).lower()
        znalezione = wyciagnij_wszystko(r.text)

        for t in TYPY:
            ext = {norm(t, x) for x in znalezione.get(t, set())}
            wz = ref[r.id][t]
            wz_w_tekscie = {x for x in wz if x.lower() in tekst}

            liczniki[t]["tp"] += len(ext & wz)
            liczniki[t]["fp"] += len(ext - wz)
            liczniki[t]["ref"] += len(wz)
            liczniki[t]["ref_w_tekscie"] += len(wz_w_tekscie)
            liczniki[t]["tp_w_tekscie"] += len(ext & wz_w_tekscie)
            bledne[t].extend(ext - wz)

    wiersze = []
    for t, c in liczniki.items():
        wiersze.append({
            "typ": t,
            "znalezione": c["tp"] + c["fp"],
            "poprawne": c["tp"],
            "w_liscie_autora": c["ref"],
            "z_listy_w_tekscie": c["ref_w_tekscie"],
            "precyzja": dziel(c["tp"], c["tp"] + c["fp"]),
            "czulosc": dziel(c["tp_w_tekscie"], c["ref_w_tekscie"]),
            "pokrycie": dziel(c["tp"], c["ref"]),
        })
    wynik = pd.DataFrame(wiersze)
    wynik.to_csv(f"{PROC_DIR}/eval_extraction.csv", index=False, encoding="utf-8")

    pd.set_option("display.width", 200)
    print(wynik.to_string(index=False))

    print("\nPrzykłady 'błędów' do ręcznej oceny (znalezione, ale nie ma ich w liście autora):")
    for t in ["MALWARE", "ACTOR", "DOMAIN", "CVE"]:
        przyklady = pd.Series(bledne[t]).value_counts().head(8).index.tolist()
        print(f"  {t:<8} {przyklady}")