"""Uruchamia ekstrakcję regex na wszystkich raportach OTX i zapisuje wyniki."""
import pandas as pd

from src.extract.regex_extractor import wyciagnij

PROC_DIR = "data/processed"

if __name__ == "__main__":
    raporty = pd.read_csv(f"{PROC_DIR}/otx_reports.csv")

    wiersze = []
    for _, r in raporty.iterrows():
        for typ, wartosci in wyciagnij(r["text"]).items():
            for w in wartosci:
                wiersze.append({"report_id": r["id"], "type": typ, "value": w})

    wynik = pd.DataFrame(wiersze, columns=["report_id", "type", "value"])
    wynik.to_csv(f"{PROC_DIR}/otx_extracted_regex.csv", index=False, encoding="utf-8")

    print(f"Znaleziono {len(wynik)} encji w {wynik['report_id'].nunique()} raportach\n")
    print(wynik["type"].value_counts())
    print("\nPrzykłady:")
    for typ in ["CVE", "IP", "DOMAIN", "URL", "HASH"]:
        przyklady = wynik.loc[wynik["type"] == typ, "value"].head(3).tolist()
        print(f"  {typ:<7} {przyklady}")