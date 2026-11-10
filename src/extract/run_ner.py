"""Uruchamia pełną ekstrakcję encji na raportach OTX i opisach podatności NVD."""
import pandas as pd

from src.extract.ner_extractor import wyciagnij_wszystko, pobierz_nlp

PROC_DIR = "data/processed"


def demo():
    zdanie = "APT28 exploited CVE-2023-23397 in Microsoft Outlook."
    print("Demo:", zdanie)
    for typ, wartosci in wyciagnij_wszystko(zdanie).items():
        if wartosci:
            print(f"  {typ:<9} {sorted(wartosci)}")


def otx():
    raporty = pd.read_csv(f"{PROC_DIR}/otx_reports.csv")
    wiersze = []
    for r in raporty.itertuples():
        for typ, wartosci in wyciagnij_wszystko(r.text).items():
            for w in wartosci:
                wiersze.append({"report_id": r.id, "type": typ, "value": w})

    df = pd.DataFrame(wiersze, columns=["report_id", "type", "value"])
    df.to_csv(f"{PROC_DIR}/otx_extracted.csv", index=False, encoding="utf-8")

    print(f"\nOTX: {len(df)} encji w {df['report_id'].nunique()} z {len(raporty)} raportów")
    print(df["type"].value_counts())
    for typ in ("ACTOR", "MALWARE", "SOFTWARE"):
        print(f"\nNajczęstsze {typ}:")
        print(df.loc[df["type"] == typ, "value"].value_counts().head(8))


def nvd():
    cves = pd.read_csv(
        f"{PROC_DIR}/cves_enriched.csv", usecols=["id", "text", "products"], dtype=str
    ).fillna("")
    nlp = pobierz_nlp()

    wiersze = []
    for cve_id, doc in zip(cves["id"], nlp.pipe(cves["text"], batch_size=500)):
        for ent in doc.ents:
            wiersze.append({"cve_id": cve_id, "type": ent.label_, "value": ent.ent_id_ or ent.text})

    df = pd.DataFrame(wiersze, columns=["cve_id", "type", "value"]).drop_duplicates()
    df.to_csv(f"{PROC_DIR}/nvd_extracted.csv", index=False, encoding="utf-8")

    bez_cpe = set(cves.loc[cves["products"] == "", "id"])
    uzupelnione = df.loc[
        df["type"].isin(["SOFTWARE", "VENDOR"]) & df["cve_id"].isin(bez_cpe), "cve_id"
    ].nunique()

    print(f"\nNVD: {len(df)} nazw w opisach {df['cve_id'].nunique()} podatności")
    print(df["type"].value_counts())
    print(f"\nCVE bez danych o produkcie w NVD: {len(bez_cpe)}")
    print(f"  z tego rozpoznano oprogramowanie/producenta w opisie: {uzupelnione}")


if __name__ == "__main__":
    demo()
    otx()
    nvd()