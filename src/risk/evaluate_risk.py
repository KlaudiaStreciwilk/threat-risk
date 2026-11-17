"""Ocena algorytmu ryzyka: czy podatności faktycznie atakowane (KEV) trafiają na szczyt rankingu."""
import os

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy.stats import spearmanr
from sklearn.metrics import average_precision_score

PROC_DIR = "data/processed"
FIG_DIR = "figures"


def ryzyko_bez_kev(df, wp=0.45, wr=0.30, wg=0.30, swiezosc=True):
    """Odtworzenie wyniku algorytmu (bez informacji z KEV) dla dowolnych wag."""
    atak = df["epss_percentile"].fillna(0.5)
    rynek = (0.5 * df["r_popularnosc"] + 0.3 * df["r_wzmianki"]) / 0.8
    rdzen = wp * df["s_powaga"] + (1 - wp) * atak
    wzmocnienie = 1 + wr * rynek + wg * df["s_graf"]
    s = df["swiezosc"] if swiezosc else 1
    return 100 * np.minimum(1, rdzen * wzmocnienie) * s


def ocen(wynik, kev):
    rangi = (-wynik).rank(method="average")   # 1 = najwyższe ryzyko; remisy dostają średnią pozycję
    rk = rangi[kev]
    return {
        "AP": round(average_precision_score(kev, wynik), 4),
        "KEV w top 50": int((rk <= 50).sum()),
        "KEV w top 100": int((rk <= 100).sum()),
        "KEV w top 500": int((rk <= 500).sum()),
        "mediana pozycji KEV": round(rk.median()),
        "pozycja ostatniego KEV": round(rk.max()),
    }, np.sort(rk.values)


if __name__ == "__main__":
    os.makedirs(FIG_DIR, exist_ok=True)
    df = pd.read_csv(f"{PROC_DIR}/cve_risk.csv")
    kev = df["in_kev"].astype(str).str.lower() == "true"
    print(f"Podatności: {len(df)}, w tym KEV: {kev.sum()} "
          f"(losowy ranking dałby AP ≈ {kev.mean():.4f})\n")

    rankingi = {
        "Tylko CVSS": df["cvss_score"].fillna(df["s_powaga"] * 10),
        "Tylko EPSS": df["epss_percentile"].fillna(0.5),
        "CVSS + EPSS": ryzyko_bez_kev(df, wr=0, wg=0, swiezosc=False),
        "Nasz algorytm": ryzyko_bez_kev(df),
    }

    wyniki, krzywe = {}, {}
    for nazwa, wynik in rankingi.items():
        wyniki[nazwa], krzywe[nazwa] = ocen(wynik, kev)

    pd.set_option("display.width", 200)
    print("=== Porównanie rankingów ===")
    print(pd.DataFrame(wyniki).T.to_string())

    # Wykres: ile atakowanych podatności "wyłapiemy", łatając po kolei z listy
    plt.figure(figsize=(8, 5))
    for nazwa, pozycje in krzywe.items():
        x = np.concatenate([[0], pozycje])
        y = np.arange(len(x))
        plt.step(x, y, where="post", label=nazwa, linewidth=2)
    plt.xscale("symlog", linthresh=10)
    plt.xlabel("Liczba podatności przejrzanych od góry rankingu (skala logarytmiczna)")
    plt.ylabel("Liczba wychwyconych podatności z KEV")
    plt.title("Jak szybko poszczególne rankingi wskazują podatności faktycznie atakowane")
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{FIG_DIR}/ranking_kev.png", dpi=150)
    print(f"\nWykres zapisany: {FIG_DIR}/ranking_kev.png")

    # Analiza wrażliwości na wagi
    print("\n=== Analiza wrażliwości na wagi ===")
    bazowy = ryzyko_bez_kev(df)
    wiersze = []
    for wp in [0.30, 0.45, 0.55, 0.70, 0.85]:
        for wr in [0.0, 0.3, 0.6]:
            for wg in [0.0, 0.3, 0.6]:
                w = ryzyko_bez_kev(df, wp=wp, wr=wr, wg=wg)
                m, _ = ocen(w, kev)
                wiersze.append({
                    "waga powagi": wp, "waga ataku": round(1 - wp, 2),
                    "wzm. rynek": wr, "wzm. graf": wg,
                    "AP": m["AP"], "KEV w top 100": m["KEV w top 100"],
                    "zgodność z bazowym (Spearman)": round(spearmanr(bazowy, w).correlation, 3),
                })
    wr_df = pd.DataFrame(wiersze)
    print(f"Sprawdzono {len(wr_df)} zestawów wag")
    print(f"AP: od {wr_df['AP'].min()} do {wr_df['AP'].max()}")
    print(f"Najniższa zgodność rankingu z wersją bazową: {wr_df['zgodność z bazowym (Spearman)'].min()}")
    print("\n5 najlepszych zestawów wag (wg AP):")
    print(wr_df.nlargest(5, "AP").to_string(index=False))
    
    print("\nNasze wagi (0,45 / 0,55 / 0,3 / 0,3):")
    print(wr_df[(wr_df["waga powagi"] == 0.45) & (wr_df["wzm. rynek"] == 0.3) & (wr_df["wzm. graf"] == 0.3)]
          .to_string(index=False))

    print("\nWpływ świeżości:")
    print(f"  z czynnikiem świeżości:  AP = {ocen(bazowy, kev)[0]['AP']}")
    print(f"  bez czynnika świeżości:  AP = {ocen(ryzyko_bez_kev(df, swiezosc=False), kev)[0]['AP']}")