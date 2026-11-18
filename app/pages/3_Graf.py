"""Interaktywny graf powiązań wokół wybranego obiektu (pyvis)."""
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from pyvis.network import Network

from baza import zapytanie, polaczenie, sprawdz_polaczenie, KOLORY_POZIOMOW

st.set_page_config(page_title="Graf powiązań", page_icon="🕸️", layout="wide")
sprawdz_polaczenie()

# Jak znaleźć obiekt startowy dla każdego typu
WARUNEK = {
    "CVE": "s:CVE AND s.id = toUpper($q)",
    "IoC": "s:IoC AND (s.value = $q OR s.value = toLower($q))",
    "Malware": "s:Malware AND toLower(s.name) = toLower($q)",
    "Grupa APT": "s:Actor AND toLower(s.name) = toLower($q)",
}

# Podpowiedzi: obiekty z największą liczbą powiązań lub najwyższym wynikiem
PODPOWIEDZI = {
    "CVE": "MATCH (c:CVE) WHERE c.n_raportow > 0 RETURN c.id AS v ORDER BY c.ryzyko DESC LIMIT 100",
    "IoC": "MATCH (i:IoC) WHERE i.reputacja IS NOT NULL RETURN i.value AS v "
           "ORDER BY i.reputacja DESC, i.n_zgloszen DESC LIMIT 100",
    "Malware": "MATCH (m:Malware) RETURN m.name AS v ORDER BY COUNT { (m)--() } DESC LIMIT 100",
    "Grupa APT": "MATCH (a:Actor) RETURN a.name AS v ORDER BY COUNT { (a)--() } DESC LIMIT 100",
}

# Kształt = typ obiektu; kolory typów są neutralne, żeby nie myliły się z poziomami ryzyka
KSZTALTY = {"CVE": "diamond", "IoC": "dot", "Malware": "triangle", "Actor": "star",
            "Report": "square", "Vendor": "hexagon", "Product": "hexagon", "CWE": "hexagon"}
KOLORY_TYPOW = {"Malware": "#e87ba4", "Actor": "#6250d6", "Report": "#8a8a85",
                "Vendor": "#c3c2b7", "Product": "#c3c2b7", "CWE": "#c3c2b7"}
BRAK_OCENY = "#a5a49c"


def fmt(x, wzor="{:.1f}"):
    return "–" if x is None else wzor.format(x)


def skroc(tekst, n=28):
    tekst = str(tekst)
    return tekst if len(tekst) <= n else tekst[:n - 1] + "…"


def opisz(etykieta, p):
    """Zwraca (napis na węźle, dymek po najechaniu, wynik 0-100 lub None)."""
    if etykieta == "CVE":
        dymek = (f"Podatność {p.get('id')}\nRyzyko: {fmt(p.get('ryzyko'))} ({p.get('poziom') or 'brak oceny'})\n"
                 f"CVSS: {fmt(p.get('cvss_score'))}   EPSS (percentyl): {fmt(p.get('epss_percentile'), '{:.3f}')}\n"
                 f"W katalogu KEV: {'tak' if p.get('in_kev') else 'nie'}")
        return p.get("id"), dymek, p.get("ryzyko")
    if etykieta == "IoC":
        dymek = (f"{p.get('type', 'IoC')}: {p.get('value')}\n"
                 f"Reputacja: {fmt(p.get('reputacja'))} ({p.get('poziom') or 'brak oceny'})\n"
                 f"Zgłoszenia: {fmt(p.get('n_zgloszen'), '{:.0f}')}   Źródła: {p.get('zrodla') or '–'}")
        return skroc(p.get("value"), 22), dymek, p.get("reputacja")
    if etykieta == "Malware":
        return p.get("name"), f"Malware: {p.get('name')}\nIoC o złej reputacji: {p.get('liczba_ioc_wysokich') or 0}", None
    if etykieta == "Actor":
        return p.get("name"), f"Grupa APT: {p.get('name')}\nNajwyższe ryzyko powiązanych CVE: {fmt(p.get('max_ryzyko_cve'))}", None
    if etykieta == "Report":
        tytul = p.get("title") or p.get("threat_type") or ""
        dymek = f"Raport {p.get('source')} ({str(p.get('published') or '')[:10]})\n{skroc(tytul, 90)}"
        return skroc(tytul or p.get("id"), 24), dymek, None
    nazwa = p.get("name") or p.get("id")
    return skroc(nazwa, 24), f"{etykieta}: {nazwa}", None


@st.cache_data(ttl=600, show_spinner="Buduję graf...")
def pobierz_graf(typ, q, glebokosc, limit, z_produktami):
    filtr = "true" if z_produktami else \
        "all(n IN nodes(p)[1..] WHERE NOT (n:Vendor OR n:Product OR n:CWE))"
    cypher = f"""
        MATCH (s) WHERE {WARUNEK[typ]}
        WITH s LIMIT 1
        MATCH p = (s)-[*1..{int(glebokosc)}]-(x)
        WHERE {filtr}
        WITH s, p, x ORDER BY CASE WHEN x:Actor OR x:Malware THEN 0 ELSE 1 END,
                              coalesce(x.ryzyko, x.reputacja, 0) DESC
        LIMIT $limit
        RETURN elementId(s) AS start,
               [n IN nodes(p) | {{id: elementId(n), etykieta: labels(n)[0], p: properties(n)}}] AS wezly,
               [r IN relationships(p) | {{od: elementId(startNode(r)), do: elementId(endNode(r)), typ: type(r)}}] AS relacje
    """
    with polaczenie().session() as s:
        rekordy = list(s.run(cypher, q=q, limit=limit))

    wezly, krawedzie, start = {}, set(), None
    for r in rekordy:
        start = r["start"]
        for w in r["wezly"]:
            wezly[w["id"]] = w
        for k in r["relacje"]:
            krawedzie.add((k["od"], k["do"], k["typ"]))
    return start, wezly, sorted(krawedzie)


def narysuj(start, wezly, krawedzie):
    try:
        ciemny = st.context.theme.type == "dark"
    except Exception:
        ciemny = False
    tlo, tekst = ("#1a1a19", "#f0efec") if ciemny else ("#fcfcfb", "#0b0b0b")

    net = Network(height="650px", width="100%", bgcolor=tlo, font_color=tekst,
                  directed=True, cdn_resources="remote")
    net.barnes_hut(gravity=-3000, spring_length=80)

    for wid, w in wezly.items():
        etykieta = w["etykieta"]
        napis, dymek, wynik = opisz(etykieta, w["p"])
        if etykieta in ("CVE", "IoC"):
            kolor = KOLORY_POZIOMOW.get(w["p"].get("poziom"), BRAK_OCENY)
            rozmiar = 10 + (wynik or 0) / 5
        else:
            kolor = KOLORY_TYPOW.get(etykieta, BRAK_OCENY)
            rozmiar = 16 if etykieta in ("Malware", "Actor") else 12
        if wid == start:
            rozmiar += 12
        net.add_node(wid, label=napis, title=dymek, color=kolor, size=rozmiar,
                     shape=KSZTALTY.get(etykieta, "dot"), borderWidth=4 if wid == start else 1,
                     font={"size": 18})

    for od, do, typ in krawedzie:
        net.add_edge(od, do, title=typ, color="#b5b3aa", width=1, arrowStrikethrough=False)

    components.html(net.generate_html(), height=670, scrolling=False)


# ================================ STRONA ================================
st.title("🕸️ Graf powiązań")
st.write("Wybierz obiekt, a zobaczysz, z czym jest powiązany: raporty, wskaźniki, podatności, "
         "malware i grupy APT. Węzły można przeciągać, a kółkiem myszy przybliżać.")

c1, c2, c3 = st.columns([1, 2, 2])
typ = c1.radio("Typ obiektu", list(WARUNEK))
podpowiedzi = zapytanie(PODPOWIEDZI[typ])["v"].tolist()
wybrany = c2.selectbox("Wybierz z listy", podpowiedzi,
                       help="Obiekty z największą liczbą powiązań lub najwyższym wynikiem")
wlasny = c3.text_input("…albo wpisz własną wartość", placeholder="np. CVE-2026-109618, Cobalt Strike")
q = (wlasny or "").strip() or wybrany

o1, o2, o3 = st.columns(3, vertical_alignment="bottom")
glebokosc = o1.radio("Zasięg", [1, 2], horizontal=True,
                     format_func=lambda d: "bezpośrednie powiązania" if d == 1 else "także powiązania powiązań")
limit = o2.slider("Maksymalna liczba ścieżek", 20, 300, 80, step=20,
                  help="Przy dużych węzłach pokazywane są ścieżki do najgroźniejszych obiektów")
z_produktami = o3.checkbox("Pokaż producentów, produkty i CWE", value=False)

if not q:
    st.stop()

start, wezly, krawedzie = pobierz_graf(typ, q, glebokosc, limit, z_produktami)
if not wezly:
    st.warning(f"Nie znaleziono „{q}” albo ten obiekt nie ma powiązań przy wybranych ustawieniach.")
    st.stop()

st.caption(f"Na grafie: {len(wezly)} obiektów i {len(krawedzie)} powiązań. "
           "Obiekt startowy jest powiększony i ma grubszą obwódkę.")
narysuj(start, wezly, krawedzie)

st.markdown(
    "**Legenda.** Kształt: ◆ podatność (CVE) · ● wskaźnik IoC · ▲ malware · ★ grupa APT · ■ raport · "
    "⬢ producent, produkt lub CWE.  \n"
    "Kolor podatności i IoC to poziom ryzyka: 🟢 niskie · 🟡 średnie · 🟠 wysokie · 🔴 krytyczne "
    "(szary = brak oceny). Im wyższy wynik, tym większy węzeł."
)

with st.expander("Lista obiektów na grafie"):
    lista = []
    for w in wezly.values():
        napis, dymek, wynik = opisz(w["etykieta"], w["p"])
        lista.append({"Typ": w["etykieta"], "Obiekt": dymek.split("\n")[0], "Wynik": wynik,
                      "Poziom": w["p"].get("poziom")})
    st.dataframe(pd.DataFrame(lista).sort_values("Wynik", ascending=False, na_position="last"),
                 hide_index=True, width="stretch")