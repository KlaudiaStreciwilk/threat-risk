"""Dostrojenie modelu DistilBERT do klasyfikacji: krytyczne zagrożenie vs szum."""
import os
import json
import time
import argparse

import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader, Dataset
from tqdm import tqdm
from transformers import (
    AutoTokenizer, AutoModelForSequenceClassification,
    DataCollatorWithPadding, get_linear_schedule_with_warmup,
)
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    average_precision_score, f1_score, precision_score, recall_score,
)

PROC_DIR = "data/processed"
MODEL_DIR = "models"
NAZWA_MODELU = "distilbert-base-uncased"
MAX_DLUGOSC = 128
PACZKA = 16
WSP_UCZENIA = 5e-5
ZAMROZONE_WARSTWY = 4   # z 6 warstw douczamy tylko 2 górne


class ZbiorTekstow(Dataset):
    """Teksty zamienione na tokeny, bez sztucznego wydłużania."""
    def __init__(self, tokenizer, teksty, etykiety):
        self.enc = tokenizer(list(teksty), truncation=True, max_length=MAX_DLUGOSC)
        self.y = list(etykiety)

    def __len__(self):
        return len(self.y)

    def __getitem__(self, i):
        return {
            "input_ids": self.enc["input_ids"][i],
            "attention_mask": self.enc["attention_mask"][i],
            "labels": self.y[i],
        }


def zamroz_dolne_warstwy(model, ile):
    for p in model.distilbert.embeddings.parameters():
        p.requires_grad = False
    for warstwa in model.distilbert.transformer.layer[:ile]:
        for p in warstwa.parameters():
            p.requires_grad = False
    uczone = sum(p.numel() for p in model.parameters() if p.requires_grad)
    wszystkie = sum(p.numel() for p in model.parameters())
    print(f"Douczane parametry: {uczone:,} z {wszystkie:,} ({100 * uczone / wszystkie:.0f}%)")


def przewiduj(model, loader, urzadzenie):
    model.eval()
    wyniki = []
    with torch.no_grad():
        for paczka in tqdm(loader, desc="Ocena"):
            paczka = {k: v.to(urzadzenie) for k, v in paczka.items()}
            paczka.pop("labels")
            logity = model(**paczka).logits
            wyniki.append(torch.softmax(logity, dim=-1)[:, 1].cpu().numpy())
    return np.concatenate(wyniki)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--probny", action="store_true", help="szybki test na małej części danych")
    args = parser.parse_args()

    torch.manual_seed(42)
    urzadzenie = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"Urządzenie: {urzadzenie}, wątki procesora: {torch.get_num_threads()}")

    train = pd.read_csv(f"{PROC_DIR}/clf_train.csv")
    test = pd.read_csv(f"{PROC_DIR}/clf_test.csv")
    if args.probny:
        train = train.sample(500, random_state=42)
        test = test.sample(300, random_state=42)
        epoki = 1
        print("TRYB PRÓBNY: 500 przykładów uczących, 300 testowych, 1 epoka")
    else:
        epoki = 2

    tokenizer = AutoTokenizer.from_pretrained(NAZWA_MODELU)
    model = AutoModelForSequenceClassification.from_pretrained(NAZWA_MODELU, num_labels=2).to(urzadzenie)
    zamroz_dolne_warstwy(model, ZAMROZONE_WARSTWY)

    dopelnianie = DataCollatorWithPadding(tokenizer, return_tensors="pt")
    dl_train = DataLoader(ZbiorTekstow(tokenizer, train["text"], train["label"]),
                          batch_size=PACZKA, shuffle=True, collate_fn=dopelnianie)
    dl_test = DataLoader(ZbiorTekstow(tokenizer, test["text"], test["label"]),
                         batch_size=32, collate_fn=dopelnianie)

    # Wagi klas – rzadsza klasa "krytyczne" liczy się mocniej
    licznosci = train["label"].value_counts().sort_index()
    wagi = torch.tensor((len(train) / (2 * licznosci)).values, dtype=torch.float).to(urzadzenie)
    funkcja_straty = torch.nn.CrossEntropyLoss(weight=wagi)

    optymalizator = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=WSP_UCZENIA)
    wszystkie_kroki = len(dl_train) * epoki
    harmonogram = get_linear_schedule_with_warmup(optymalizator, int(0.1 * wszystkie_kroki), wszystkie_kroki)

    start = time.time()
    for epoka in range(epoki):
        model.train()
        suma_straty = 0.0
        pasek = tqdm(dl_train, desc=f"Epoka {epoka + 1}/{epoki}")
        for paczka in pasek:
            paczka = {k: v.to(urzadzenie) for k, v in paczka.items()}
            y = paczka.pop("labels")
            optymalizator.zero_grad()
            logity = model(**paczka).logits
            strata = funkcja_straty(logity, y)
            strata.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optymalizator.step()
            harmonogram.step()
            suma_straty += strata.item()
            pasek.set_postfix(strata=f"{strata.item():.3f}")
        print(f"Epoka {epoka + 1}: średnia strata {suma_straty / len(dl_train):.4f}")

    czas_min = (time.time() - start) / 60
    print(f"Czas treningu: {czas_min:.1f} min ({czas_min * 60 / wszystkie_kroki:.1f} s na krok)")

    proba = przewiduj(model, dl_test, urzadzenie)
    pred = (proba >= 0.5).astype(int)

    print("\nWyniki na zbiorze testowym:\n")
    print(classification_report(test["label"], pred, target_names=["szum", "krytyczne"], digits=3))
    print("Macierz pomyłek:")
    print(pd.DataFrame(
        confusion_matrix(test["label"], pred),
        index=["prawda: szum", "prawda: krytyczne"],
        columns=["model: szum", "model: krytyczne"],
    ))

    metryki = {
        "model": "DistilBERT (dostrojony, 2 górne warstwy)",
        "precyzja": round(precision_score(test["label"], pred), 3),
        "czulosc": round(recall_score(test["label"], pred), 3),
        "f1": round(f1_score(test["label"], pred), 3),
        "f1_macro": round(f1_score(test["label"], pred, average="macro"), 3),
        "roc_auc": round(roc_auc_score(test["label"], proba), 3),
        "pr_auc": round(average_precision_score(test["label"], proba), 3),
        "czas_treningu_min": round(czas_min, 1),
    }
    print("\nPodsumowanie:", metryki)

    if not args.probny:
        os.makedirs(MODEL_DIR, exist_ok=True)
        with open(f"{MODEL_DIR}/distilbert_metrics.json", "w", encoding="utf-8") as f:
            json.dump(metryki, f, ensure_ascii=False, indent=2)
        model.save_pretrained(f"{MODEL_DIR}/distilbert_clf")
        tokenizer.save_pretrained(f"{MODEL_DIR}/distilbert_clf")
        test.assign(proba=proba, pred=pred)[["id", "label", "proba", "pred"]].to_csv(
            f"{PROC_DIR}/pred_distilbert.csv", index=False
        )
        print(f"Model zapisany w {MODEL_DIR}/distilbert_clf")