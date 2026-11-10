"""Ekstrakcja 'twardych' encji (CVE, IP, URL, domeny, hashe) z tekstu za pomocą wyrażeń regularnych."""
import re
import ipaddress

import tldextract

_tld = tldextract.TLDExtract(suffix_list_urls=())  # lista wbudowana, bez pobierania z internetu

# Naprawa celowo "zepsutych" zapisów, np. evil[.]com, hxxp://
NAPRAWY = [
    (r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", "."),
    (r"hxxp", "http"),
    (r"\[:\]", ":"),
    (r"\[/\]", "/"),
]

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`]+", re.IGNORECASE)
SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
SHA1_RE = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
MD5_RE = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)
DOMENA_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23}\b",
    re.IGNORECASE,
)

# Końcówki, które są prawdziwymi domenami najwyższego poziomu,
# ale w raportach prawie zawsze oznaczają nazwy plików (np. script.py, README.md)
KONCOWKI_PLIKOW = {"zip", "mov", "py", "sh", "md", "so", "pm", "ps"}


def napraw_tekst(tekst):
    for wzorzec, zamiana in NAPRAWY:
        tekst = re.sub(wzorzec, zamiana, tekst, flags=re.IGNORECASE)
    return tekst


def poprawny_ip(ip):
    """Zostawia tylko publiczne adresy (odrzuca prywatne, lokalne, zarezerwowane)."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def poprawna_domena(domena):
    czesci = _tld(domena)
    if not czesci.domain or not czesci.suffix:
        return False  # np. update.exe – "exe" nie jest domeną najwyższego poziomu
    return domena.rsplit(".", 1)[-1].lower() not in KONCOWKI_PLIKOW


def wyciagnij(tekst):
    """Zwraca słownik: typ encji -> zbiór znalezionych wartości."""
    wynik = {"CVE": set(), "IP": set(), "URL": set(), "DOMAIN": set(), "HASH": set()}
    if not isinstance(tekst, str) or not tekst:
        return wynik

    tekst = napraw_tekst(tekst)

    wynik["CVE"] = {m.upper() for m in CVE_RE.findall(tekst)}
    wynik["IP"] = {m for m in IP_RE.findall(tekst) if poprawny_ip(m)}
    wynik["URL"] = {m.rstrip(".,;:)]}'\"") for m in URL_RE.findall(tekst)}
    wynik["DOMAIN"] = {
        m.lower() for m in DOMENA_RE.findall(tekst)
        if not IP_RE.fullmatch(m) and poprawna_domena(m)
    }
    wynik["HASH"] = {
        m.lower()
        for wzorzec in (SHA256_RE, SHA1_RE, MD5_RE)
        for m in wzorzec.findall(tekst)
    }
    return wynik