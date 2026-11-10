"""Pełna ekstrakcja encji: regex (CVE, IP, URL, domeny, hashe) + słownik spaCy (aktorzy, malware, oprogramowanie)."""
import pandas as pd
import spacy

from src.extract.regex_extractor import wyciagnij as wyciagnij_regex

SLOWNIK = "data/processed/entity_dictionary.csv"
ETYKIETY_NAZW = ("ACTOR", "MALWARE", "SOFTWARE", "VENDOR")

_nlp = None


def pobierz_nlp():
    """Buduje (raz) potok spaCy rozpoznający nazwy ze słownika."""
    global _nlp
    if _nlp is None:
        nlp = spacy.blank("en")
        ruler = nlp.add_pipe("entity_ruler", config={"phrase_matcher_attr": "LOWER"})
        slownik = pd.read_csv(SLOWNIK)
        ruler.add_patterns([
            {"label": r.label, "pattern": r.alias, "id": r.canonical}
            for r in slownik.itertuples()
        ])
        _nlp = nlp
    return _nlp


def wyciagnij_wszystko(tekst):
    """Zwraca słownik: typ encji -> zbiór wartości (nazwy sprowadzone do nazwy głównej)."""
    wynik = wyciagnij_regex(tekst)
    for etykieta in ETYKIETY_NAZW:
        wynik[etykieta] = set()

    if isinstance(tekst, str) and tekst:
        for ent in pobierz_nlp()(tekst).ents:
            wynik[ent.label_].add(ent.ent_id_ or ent.text)
    return wynik