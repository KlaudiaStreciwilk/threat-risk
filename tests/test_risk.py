"""Testy algorytmów oceny ryzyka (CVE) i reputacji (IoC)."""
from pathlib import Path

import pandas as pd
import pytest

from src.risk.evaluate_risk import ryzyko_bez_kev
from src.risk.ioc_reputation import czy_ukarac, domena_glowna, host
from src.extract.build_dictionary import oczysc_nazwe, zwykle_slowo

CVE_RISK = Path("data/processed/cve_risk.csv")
IOC_REP = Path("data/processed/ioc_reputation.csv")


# ==================== 1. Zasady algorytmu ryzyka (sztuczne przykłady) ====================
def ryzyko(**zmiany):
    """Ryzyko pojedynczej, sztucznej podatności. Domyślnie: wszystko po środku, bez kontekstu."""
    wiersz = {"s_powaga": 0.5, "epss_percentile": 0.5, "r_popularnosc": 0.0,
              "r_wzmianki": 0.0, "s_graf": 0.0, "swiezosc": 1.0}
    wiersz.update(zmiany)
    return float(ryzyko_bez_kev(pd.DataFrame([wiersz])).iloc[0])


def test_brak_kontekstu_nie_obniza_wyniku():
    # bez raportów i powiązań wynik to sam rdzeń: 100 * (0,45 * 0,5 + 0,55 * 0,5) = 50
    assert ryzyko() == pytest.approx(50.0)


def test_kontekst_i_graf_podnosza_wynik():
    assert ryzyko(s_graf=1.0) > ryzyko()
    assert ryzyko(r_popularnosc=1.0) > ryzyko()
    assert ryzyko(r_wzmianki=1.0) > ryzyko()


def test_wyzszy_epss_daje_wyzsze_ryzyko():
    assert ryzyko(epss_percentile=0.9) > ryzyko(epss_percentile=0.1)


def test_wyzsza_powaga_daje_wyzsze_ryzyko():
    assert ryzyko(s_powaga=0.9) > ryzyko(s_powaga=0.1)


def test_swiezosc_zmniejsza_wynik_proporcjonalnie():
    assert ryzyko(swiezosc=0.5) == pytest.approx(ryzyko() * 0.5)


def test_wynik_nie_przekracza_100():
    maks = ryzyko(s_powaga=1.0, epss_percentile=1.0, r_popularnosc=1.0, r_wzmianki=1.0, s_graf=1.0)
    assert maks == pytest.approx(100.0)


def test_brak_epss_traktowany_jak_srodek_skali():
    assert ryzyko(epss_percentile=float("nan")) == pytest.approx(ryzyko(epss_percentile=0.5))


# ==================== 2. Funkcje pomocnicze ====================
POPULARNE = {"booking.com", "mooo.com", "github.com"}


@pytest.mark.parametrize("typ, wartosc, oczekiwane", [
    ("DOMAIN", "booking.com", True),                                  # sama popularna domena
    ("DOMAIN", "www.booking.com", True),
    ("URL", "https://booking.com/", True),                            # strona główna
    ("DOMAIN", "flow505.mooo.com", False),                            # subdomena na darmowym serwisie
    ("URL", "https://github.com/x/y/releases/download/Setup.zip", False),  # konkretny złośliwy plik
    ("DOMAIN", "magento.ink", False),                                 # domena spoza listy
    ("IP", "45.87.53.10", False),                                     # adres IP nigdy nie jest karany
])
def test_kara_za_popularna_domene(typ, wartosc, oczekiwane):
    assert czy_ukarac(typ, wartosc, POPULARNE) == oczekiwane


def test_domena_glowna_z_adresu_url():
    assert domena_glowna(host("URL", "https://sub.evil.com:8080/path/x.php")) == "evil.com"


def test_czyszczenie_nazwy_malware():
    assert oczysc_nazwe("Cobalt Strike - S0154") == "Cobalt Strike"
    assert oczysc_nazwe("AsyncRAT") == "AsyncRAT"


def test_filtr_zwyklych_slow():
    assert zwykle_slowo("Play", "MITRE")           # popularne słowo – odrzucone
    assert not zwykle_slowo("AMOS", "ThreatFox")   # imię, ale nazwa z aktualnego feedu – zostaje
    assert not zwykle_slowo("APT-C-23", "MITRE")   # nazwa z cyframi i myślnikami – zostaje


# ==================== 3. Wyniki na rzeczywistych danych ====================
wymaga_cve = pytest.mark.skipif(not CVE_RISK.exists(), reason="brak wyników – uruchom python -m src.risk.cve_risk")
wymaga_ioc = pytest.mark.skipif(not IOC_REP.exists(), reason="brak wyników – uruchom python -m src.risk.ioc_reputation")


@wymaga_cve
def test_podatnosci_z_kev_maja_co_najmniej_70():
    df = pd.read_csv(CVE_RISK)
    kev = df["in_kev"].astype(str).str.lower() == "true"
    assert kev.sum() > 0
    assert (df.loc[kev, "ryzyko"] >= 70).all()


@wymaga_cve
def test_skladniki_ryzyka_w_dozwolonych_zakresach():
    df = pd.read_csv(CVE_RISK)
    assert df["ryzyko"].between(0, 100).all()
    assert df["swiezosc"].between(0.5, 1.0).all()
    for kolumna in ["s_powaga", "s_atak", "s_rynek", "s_graf"]:
        assert df[kolumna].between(0, 1).all(), kolumna


@wymaga_ioc
def test_reputacja_ioc_w_zakresie_i_kara_dziala():
    df = pd.read_csv(IOC_REP)
    assert df["reputacja"].between(0, 100).all()
    # ukarana popularna domena nie może mieć więcej niż 20% maksymalnego wyniku
    assert (df.loc[df["popularna_domena"], "reputacja"] <= 20).all()