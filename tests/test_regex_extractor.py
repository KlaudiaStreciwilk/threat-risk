from src.extract.regex_extractor import wyciagnij


def test_cve_wielkosc_liter():
    assert wyciagnij("Exploited cve-2024-3400 in PAN-OS")["CVE"] == {"CVE-2024-3400"}


def test_ip_zepsuty_zapis():
    assert wyciagnij("C2 server at 45[.]33[.]32[.]156")["IP"] == {"45.33.32.156"}


def test_ip_prywatny_odrzucony():
    assert wyciagnij("internal host 192.168.1.10")["IP"] == set()


def test_url_i_domena_z_hxxp():
    w = wyciagnij("Payload downloaded from hxxps://evil-update[.]com/load.php.")
    assert w["URL"] == {"https://evil-update.com/load.php"}
    assert "evil-update.com" in w["DOMAIN"]


def test_nazwy_plikow_to_nie_domeny():
    w = wyciagnij("The dropper update.exe opens invoice.pdf and README.md")
    assert w["DOMAIN"] == set()


def test_hashe():
    sha256 = "a" * 64
    md5 = "b" * 32
    w = wyciagnij(f"Sample {sha256} and {md5}")
    assert w["HASH"] == {sha256, md5}