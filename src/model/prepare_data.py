"""Przygotowanie zbioru do klasyfikacji: krytyczne zagrożenie (1) vs szum informacyjny (0)."""
import pandas as pd
from sklearn.model_selection import train_test_split

PROC_DIR = "data/processed"


def oznacz(df):
    cvss = df["cvss_score"]
    epss_p = df["epss_percentile"].fillna(0)
    kev = df["in_kev"].astype(str).str.lower() == "true"

    krytyczne = kev | (cvss >= 9.0) | (epss_p >= 0.95)
    szum = (cvss < 7.0) & (epss_p < 0.90) & ~kev

    df["label"] = None
    df.loc[szum, "label"] = 0
    df.loc[krytyczne, "label"] = 1  # gdyby oba warunki były spełnione, wygrywa "krytyczne"
    df["powod"] = ""
    df.loc[kev, "powod"] += "KEV;"
    df.loc[cvss >= 9.0, "powod"] += "CVSS>=9;"
    df.loc[epss_p >= 0.95, "powod"] += "EPSS top 5%;"
    return df


if __name__ == "__main__":
    df = pd.read_csv(f"{PROC_DIR}/cves_enriched.csv")
    print(f"Wszystkie CVE: {len(df)}")

    df = df[df["status"] != "Rejected"]
    df = df[df["text"].fillna("").str.len() > 20]
    print(f"Po usunięciu odrzuconych i pustych: {len(df)}")

    df = oznacz(df)
    pominiete = df["label"].isna().sum()
    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int)
    print(f"Pominięte przypadki pośrednie: {pominiete}")

    przed = len(df)
    df = df.drop_duplicates(subset="text")
    print(f"Usunięte powtarzające się opisy: {przed - len(df)}")

    kolumny = ["id", "text", "label", "powod", "cvss_score", "epss", "epss_percentile", "in_kev"]
    df = df[kolumny]

    train, test = train_test_split(df, test_size=0.2, stratify=df["label"], random_state=42)
    train.to_csv(f"{PROC_DIR}/clf_train.csv", index=False, encoding="utf-8")
    test.to_csv(f"{PROC_DIR}/clf_test.csv", index=False, encoding="utf-8")

    print(f"\nZbiór końcowy: {len(df)} opisów")
    print(df["label"].value_counts().rename({1: "krytyczne (1)", 0: "szum (0)"}))
    print(f"\nUczący: {len(train)}   Testowy: {len(test)}")

    print("\nDlaczego opisy uznano za krytyczne:")
    print(df.loc[df["label"] == 1, "powod"].str.split(";").explode()
          .loc[lambda s: s != ""].value_counts())

    pd.set_option("display.max_colwidth", 150)
    print("\nPrzykład krytyczny:")
    print(df.loc[df["label"] == 1, "text"].sample(2, random_state=1).to_string(index=False))
    print("\nPrzykład szumu:")
    print(df.loc[df["label"] == 0, "text"].sample(2, random_state=1).to_string(index=False))