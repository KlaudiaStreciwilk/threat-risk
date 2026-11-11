"""Porównanie modeli i zastosowanie klasyfikatora do CVE bez CVSS oraz raportów OTX."""
import json

import joblib
import pandas as pd
from sklearn.metrics import roc_auc_score, average_precision_score, f1_score

PROC_DIR = "data/processed"
MODEL_DIR = "models"
pd.set_option("display.width", 200)
pd.set_option("display.max_colwidth", 90)


def porownaj_modele():
    print("=== 1. Porównanie modeli ===\n")
    metryki = [
        json.load(open(f"{MODEL_DIR}/baseline_metrics.json", encoding="utf-8")),
        json.load(open(f"{MODEL_DIR}/distilbert_metrics.json", encoding="utf-8")),
    ]
    print(pd.DataFrame(metryki).set_index("model").T)

    b = pd.read_csv(f"{PROC_DIR}/pred_baseline.csv")
    d = pd.read_csv(f"{PROC_DIR}/pred_distilbert.csv")
    z = b.merge(d, on=["id", "label"], suffixes=("_tfidf", "_bert"))

    zgodnosc = (z["pred_tfidf"] == z["pred_bert"]).mean()
    oba_przeoczyly = ((z["label"] == 1) & (z["pred_tfidf"] == 0) & (z["pred_bert"] == 0)).sum()
    srednia = (z["proba_tfidf"] + z["proba_bert"]) / 2

    print(f"\nModele zgadzają się w {zgodnosc:.1%} przypadków")
    print(f"Krytyczne przeoczone przez OBA modele: {oba_przeoczyly} z {(z['label'] == 1).sum()}")
    print("Połączenie obu modeli (średnia prawdopodobieństw):")
    print(f"  F1 = {f1_score(z['label'], (srednia >= 0.5).astype(int)):.3f}, "
          f"ROC-AUC = {roc_auc_score(z['label'], srednia):.3f}, "
          f"PR-AUC = {average_precision_score(z['label'], srednia):.3f}")


if __name__ == "__main__":
    porownaj_modele()
    model = joblib.load(f"{MODEL_DIR}/baseline_tfidf_lr.joblib")

    # Ocena z tekstu dla wszystkich CVE (składnik algorytmu ryzyka w etapie 5)
    cves = pd.read_csv(f"{PROC_DIR}/cves_enriched.csv")
    cves = cves[(cves["status"] != "Rejected") & (cves["text"].fillna("").str.len() > 20)].copy()
    cves["text_score"] = model.predict_proba(cves["text"])[:, 1]
    cves[["id", "text_score"]].to_csv(f"{PROC_DIR}/cve_text_scores.csv", index=False)

    print("\n=== 2. Podatności bez oceny CVSS ===\n")
    bez = cves[cves["cvss_score"].isna()]
    print(f"Liczba: {len(bez)}, z tego model uznał za krytyczne: {(bez['text_score'] >= 0.5).sum()}")
    print("\nNajbardziej krytyczne wg modelu:")
    print(bez.nlargest(5, "text_score")[["id", "text_score", "text"]].to_string(index=False))

    print("\n=== 3. Podatności z KEV (faktycznie atakowane) ===\n")
    kev = cves[cves["in_kev"].astype(str).str.lower() == "true"]
    print(f"Średnia ocena modelu: {kev['text_score'].mean():.3f}, "
          f"uznane za krytyczne: {(kev['text_score'] >= 0.5).sum()} z {len(kev)}")
    print(kev[["id", "cvss_score", "text_score"]].sort_values("text_score").to_string(index=False))

    print("\n=== 4. Raporty OTX ===\n")
    otx = pd.read_csv(f"{PROC_DIR}/otx_reports.csv")
    otx["text_score"] = model.predict_proba(otx["text"].fillna(""))[:, 1]
    otx[["id", "title", "text_score"]].to_csv(f"{PROC_DIR}/otx_text_scores.csv", index=False)
    print(f"Uznane za krytyczne: {(otx['text_score'] >= 0.5).sum()} z {len(otx)}")
    print("\nNajbardziej krytyczne:")
    print(otx.nlargest(8, "text_score")[["text_score", "title"]].to_string(index=False))
    print("\nNajmniej krytyczne:")
    print(otx.nsmallest(5, "text_score")[["text_score", "title"]].to_string(index=False))