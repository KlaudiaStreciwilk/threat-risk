"""Model bazowy: TF-IDF + regresja logistyczna (krytyczne zagrożenie vs szum)."""
import os
import json

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    average_precision_score, f1_score, precision_score, recall_score,
)

PROC_DIR = "data/processed"
MODEL_DIR = "models"


if __name__ == "__main__":
    os.makedirs(MODEL_DIR, exist_ok=True)
    train = pd.read_csv(f"{PROC_DIR}/clf_train.csv")
    test = pd.read_csv(f"{PROC_DIR}/clf_test.csv")

    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),     # pojedyncze słowa i pary słów
            min_df=2,               # pomijamy słowa występujące tylko raz
            max_df=0.9,             # pomijamy słowa obecne prawie wszędzie
            sublinear_tf=True,
            stop_words="english",
        )),
        ("clf", LogisticRegression(class_weight="balanced", max_iter=2000)),
    ])
    model.fit(train["text"], train["label"])

    proba = model.predict_proba(test["text"])[:, 1]
    pred = (proba >= 0.5).astype(int)

    print("Wyniki na zbiorze testowym:\n")
    print(classification_report(test["label"], pred, target_names=["szum", "krytyczne"], digits=3))

    macierz = pd.DataFrame(
        confusion_matrix(test["label"], pred),
        index=["prawda: szum", "prawda: krytyczne"],
        columns=["model: szum", "model: krytyczne"],
    )
    print("Macierz pomyłek:")
    print(macierz)

    metryki = {
        "model": "TF-IDF + regresja logistyczna",
        "precyzja": round(precision_score(test["label"], pred), 3),
        "czulosc": round(recall_score(test["label"], pred), 3),
        "f1": round(f1_score(test["label"], pred), 3),
        "f1_macro": round(f1_score(test["label"], pred, average="macro"), 3),
        "roc_auc": round(roc_auc_score(test["label"], proba), 3),
        "pr_auc": round(average_precision_score(test["label"], proba), 3),
    }
    print("\nPodsumowanie:", metryki)

    with open(f"{MODEL_DIR}/baseline_metrics.json", "w", encoding="utf-8") as f:
        json.dump(metryki, f, ensure_ascii=False, indent=2)
    joblib.dump(model, f"{MODEL_DIR}/baseline_tfidf_lr.joblib")
    test.assign(proba=proba, pred=pred)[["id", "label", "proba", "pred"]].to_csv(
        f"{PROC_DIR}/pred_baseline.csv", index=False
    )

    # Które słowa najbardziej wpływają na decyzję
    slowa = model["tfidf"].get_feature_names_out()
    wagi = pd.Series(model["clf"].coef_[0], index=slowa).sort_values()
    print("\nSłowa najmocniej wskazujące na KRYTYCZNE:")
    print(", ".join(wagi.tail(15).index[::-1]))
    print("\nSłowa najmocniej wskazujące na SZUM:")
    print(", ".join(wagi.head(15).index))