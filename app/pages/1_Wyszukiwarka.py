"""Wyszukiwarka reputacji: wskaźnik kompromitacji (IP, domena, URL, hash) lub podatność CVE."""
import re

import pandas as pd
import streamlit as st

from baza import zapytanie, sprawdz_polaczenie, etykieta_poziomu

st.set_page_config(page_title="Wyszukiwarka reputacji", page_icon="🔎", layout="wide")
sprawdz_polaczenie()

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
PRZYKLADY = ["CVE-2026-109618", "193.161.193.99", "magento.ink", "booking.com"]

# Link do oryginalnego raportu w ThreatFox lub OTX
LINK = """CASE r.source
    WHEN 'OTX' THEN 'https://otx.alienvault.com/pulse/' + substring(r.id, 4)
    WHEN 'ThreatFox' THEN 'https://threatfox.abuse.ch/ioc/' + substring(r.id, 3) + '/'
END"""

KOLUMNY_RAPORTOW = {
    "Link": st.column_config.LinkColumn(display_text="otwórz"),
}


def normalizuj(tekst):
    """Poprawia celowo zepsute zapisy: evil[.]com -> evil.com, hxxp -> http."""
    t = tekst.strip()
    t = re.sub(r"\[\.\]|\(\.\)|\{\.\}", ".", t)
    return re.sub(r"hxxp", "http", t, flags=re.IGNORECASE)


def liczba(x, wzor="{:.1f}"):
    return "–" if x is None or pd.isna(x) else wzor.format(x)


def ustaw(wartosc):
    st.session_state["szukaj"] = wartosc


def tabela_skladnikow(wiersze):
    st.dataframe(
        pd.DataFrame(wiersze, columns=["Składnik", "Wartość", "Co oznacza"]),
        hide_index=True, width="stretch",
        column_config={"Wartość": st.column_config.ProgressColumn(min_value=0, max_value=1, format="%.2f")},
    )


# ======================= WSKAŹNIK KOMPROMITACJI (IoC) =======================
def pokaz_ioc(wartosc):
    warianty = sorted({wartosc, wartosc.lower()})
    wynik = zapytanie("""
        MATCH (i:IoC) WHERE i.value IN $warianty
        OPTIONAL MATCH (i)-[:ASSOCIATED_WITH]->(m:Malware)
        RETURN i {.*} AS ioc, collect(DISTINCT m.name) AS malware
        LIMIT 1
    """, warianty=warianty)
    if wynik.empty:
        return False

    ioc, malware = wynik.iloc[0]["ioc"], wynik.iloc[0]["malware"]
    st.subheader(f"{ioc.get('type', 'IoC')}: `{ioc['value']}`")

    k = st.columns(4)
    k[0].metric("Reputacja zagrożenia", f"{liczba(ioc.get('reputacja'))} / 100")
    k[1].metric("Poziom", etykieta_poziomu(ioc.get("poziom")))
    k[2].metric("Liczba zgłoszeń", liczba(ioc.get("n_zgloszen"), "{:.0f}"))
    k[3].metric("Źródła", ioc.get("zrodla") or "–")

    if ioc.get("popularna_domena"):
        st.info("Ta domena należy do 100 000 najpopularniejszych stron świata (lista Tranco), "
                "więc najpewniej jest legalna, np. wspomniana w raporcie jako podszywana marka. "
                "Jej wynik został obniżony.")
    if malware:
        st.write("**Powiązane malware:** " + ", ".join(malware))

    st.markdown("#### Dlaczego taki wynik?")
    tabela_skladnikow([
        ("Pewność zgłoszenia", ioc.get("s_pewnosc"),
         "poziom pewności podany przez ThreatFox (dla raportów OTX przyjęto 0,7)"),
        ("Powiązania", ioc.get("s_powiazania"), "1 = grupa APT, 0,7 = znane malware, 0 = brak"),
        ("Częstotliwość zgłoszeń", ioc.get("s_czestosc"), "rośnie z liczbą raportów, maksimum przy 10"),
        ("Potwierdzenie przez 2 źródła", 1.0 if (ioc.get("n_zrodel") or 0) >= 2 else 0.0,
         "wskaźnik zgłoszony niezależnie przez ThreatFox i OTX"),
        ("Świeżość", ioc.get("swiezosc"), "maleje z czasem od ostatniego zgłoszenia (o połowę co 14 dni)"),
    ])

    st.markdown("#### Raporty, w których się pojawia")
    raporty = zapytanie(f"""
        MATCH (r:Report)-[:MENTIONS]->(i:IoC) WHERE i.value IN $warianty
        OPTIONAL MATCH (r)-[:ATTRIBUTED_TO]->(a:Actor)
        RETURN r.source AS `Źródło`, left(r.published, 10) AS `Data`,
               coalesce(r.title, r.threat_type) AS `Opis`,
               collect(DISTINCT a.name) AS `Grupy APT`, {LINK} AS `Link`
        ORDER BY `Data` DESC
    """, warianty=warianty)
    st.dataframe(raporty, hide_index=True, width="stretch", column_config=KOLUMNY_RAPORTOW)
    return True


# ============================== PODATNOŚĆ (CVE) ==============================
def pokaz_cve(cve_id):
    wynik = zapytanie("""
        MATCH (c:CVE {id: $id})
        OPTIONAL MATCH (c)-[:AFFECTS_VENDOR]->(v:Vendor)
        OPTIONAL MATCH (c)-[:AFFECTS]->(p:Product)
        OPTIONAL MATCH (c)-[:HAS_WEAKNESS]->(w:CWE)
        RETURN c {.*} AS cve, collect(DISTINCT v.name) AS producenci,
               collect(DISTINCT p.name) AS produkty, collect(DISTINCT w.id) AS cwe
    """, id=cve_id)
    if wynik.empty:
        return False

    w = wynik.iloc[0]
    cve = w["cve"]
    st.subheader(cve_id)
    st.markdown(f"[Otwórz w NVD](https://nvd.nist.gov/vuln/detail/{cve_id})")

    if cve.get("ryzyko") is None:
        st.info("To CVE pojawia się tylko w raportach o zagrożeniach. Nie ma go w pobranych danych NVD "
                "(podatności z ostatnich 30 dni), dlatego nie ma oceny ryzyka.")
    else:
        k = st.columns(5)
        k[0].metric("Ryzyko", f"{liczba(cve.get('ryzyko'))} / 100")
        k[1].metric("Poziom", etykieta_poziomu(cve.get("poziom")))
        k[2].metric(f"CVSS ({cve.get('cvss_severity') or 'brak oceny'})", liczba(cve.get("cvss_score")))
        k[3].metric("EPSS (percentyl)", liczba(cve.get("epss_percentile"), "{:.3f}"),
                    help=f"Prawdopodobieństwo wykorzystania w ciągu 30 dni: {liczba(cve.get('epss'), '{:.4f}')}")
        k[4].metric("W katalogu KEV", "TAK" if cve.get("in_kev") else "nie")

        if cve.get("in_kev"):
            st.error("Ta podatność jest wykorzystywana w prawdziwych atakach (katalog CISA KEV).")
        if str(cve.get("kev_ransomware", "")).lower() == "known":
            st.error("Podatność była wykorzystywana w kampaniach ransomware.")

        st.markdown("**Opis:**")
        st.write(cve.get("description") or "–")

        if w["producenci"]:
            st.write("**Producenci:** " + ", ".join(w["producenci"]))
        if w["produkty"]:
            produkty = w["produkty"]
            reszta = f" (i {len(produkty) - 15} innych)" if len(produkty) > 15 else ""
            st.write("**Produkty:** " + ", ".join(produkty[:15]) + reszta)
        if w["cwe"]:
            st.write("**Typ błędu (CWE):** " + ", ".join(w["cwe"]))

        st.markdown("#### Dlaczego taki wynik?")
        tabela_skladnikow([
            (f"Powaga (źródło: {cve.get('zrodlo_powagi', '–')})", cve.get("s_powaga"),
             "CVSS / 10; gdy brak CVSS, ocena klasyfikatora z tekstu opisu"),
            ("Prawdopodobieństwo ataku", cve.get("s_atak"), "percentyl EPSS; podatność z KEV = 1"),
            ("Kontekst rynkowy", cve.get("s_rynek"),
             "popularność producenta, wzmianki w raportach, wykorzystanie przez ransomware"),
            ("Powiązania w grafie", cve.get("s_graf"), "1 = raport o grupie APT, 0,6 = raport o malware, 0 = brak"),
            ("Świeżość", cve.get("swiezosc"), "maleje z czasem od ostatniej aktywności (o połowę co 30 dni)"),
        ])
        st.caption("Ryzyko = 100 × min(1, (0,45·powaga + 0,55·atak) × (1 + 0,3·rynek + 0,3·graf)) × świeżość. "
                   "Podatność z KEV ma ryzyko co najmniej 70.")

    st.markdown("#### Raporty, w których się pojawia")
    raporty = zapytanie(f"""
        MATCH (r:Report)-[:MENTIONS]->(c:CVE {{id: $id}})
        OPTIONAL MATCH (r)-[:ATTRIBUTED_TO]->(a:Actor)
        OPTIONAL MATCH (r)-[:MENTIONS]->(m:Malware)
        RETURN r.source AS `Źródło`, left(r.published, 10) AS `Data`, r.title AS `Tytuł`,
               collect(DISTINCT a.name) AS `Grupy APT`, collect(DISTINCT m.name) AS `Malware`,
               {LINK} AS `Link`
        ORDER BY `Data` DESC
    """, id=cve_id)
    if raporty.empty:
        st.caption("Żaden z pobranych raportów nie wspomina tej podatności.")
    else:
        st.dataframe(raporty, hide_index=True, width="stretch", column_config=KOLUMNY_RAPORTOW)
    return True


# ================================ STRONA ================================
st.title("🔎 Wyszukiwarka reputacji")
st.write("Wpisz adres IP, domenę, URL, hash pliku albo identyfikator CVE. "
         "Zapisy typu `evil[.]com` i `hxxp://` są poprawiane automatycznie.")

st.text_input("Czego szukasz?", key="szukaj", placeholder="np. CVE-2024-3400, 45.87.53.10, evil.com")
# CVE przekazane z rankingu (przycisk "Pokaż szczegóły w wyszukiwarce")
if "do_wyszukania" in st.session_state:
    st.session_state["szukaj"] = st.session_state.pop("do_wyszukania")

przyciski = st.columns([1, 2, 2, 2, 2])
przyciski[0].caption("Przykłady:")
for kolumna, przyklad in zip(przyciski[1:], PRZYKLADY):
    kolumna.button(przyklad, on_click=ustaw, args=(przyklad,))

szukane = normalizuj(st.session_state.get("szukaj", ""))
if szukane:
    st.divider()
    if CVE_RE.match(szukane):
        znaleziono = pokaz_cve(szukane.upper())
    else:
        znaleziono = pokaz_ioc(szukane)

    if not znaleziono:
        st.warning(f"Nie znaleziono „{szukane}” w bazie.")
        st.caption("Brak w bazie nie oznacza, że obiekt jest bezpieczny. Oznacza tylko, "
                   "że nie pojawił się w pobranych źródłach.")
        if len(szukane) >= 4:
            podobne = zapytanie("""
                CALL {
                    MATCH (i:IoC) WHERE toLower(i.value) CONTAINS toLower($q)
                    RETURN i.value AS wartosc, i.type AS typ, i.reputacja AS wynik
                    UNION
                    MATCH (c:CVE) WHERE c.id CONTAINS toUpper($q)
                    RETURN c.id AS wartosc, 'CVE' AS typ, c.ryzyko AS wynik
                }
                RETURN wartosc AS `Wartość`, typ AS `Typ`, wynik AS `Wynik`
                ORDER BY `Wynik` DESC LIMIT 20
            """, q=szukane)
            if not podobne.empty:
                st.write("**Podobne wyniki w bazie** (skopiuj wartość do wyszukiwarki):")
                st.dataframe(podobne, hide_index=True, width="stretch")