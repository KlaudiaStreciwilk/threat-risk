"""Ranking podatności według wyliczonego ryzyka, z filtrami."""
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from baza import zapytanie, sprawdz_polaczenie, etykieta_poziomu, KOLEJNOSC_POZIOMOW

st.set_page_config(page_title="Ranking podatności", page_icon="📊", layout="wide")
sprawdz_polaczenie()

NIEBIESKI = "#4a7fd4"


@st.cache_data(ttl=600, show_spinner="Wczytuję podatności...")
def wczytaj_podatnosci():
    df = zapytanie("""
        MATCH (c:CVE) WHERE c.ryzyko IS NOT NULL
        OPTIONAL MATCH (c)-[:AFFECTS_VENDOR]->(v:Vendor)
        WITH c, collect(DISTINCT v.name) AS producenci
        RETURN c.id AS CVE, c.ryzyko AS Ryzyko, c.poziom AS poziom, c.cvss_score AS CVSS,
               c.epss_percentile AS EPSS, c.in_kev AS KEV, c.n_raportow AS Raporty,
               c.s_graf AS graf, c.zrodlo_powagi AS zrodlo_powagi,
               left(c.published, 10) AS Opublikowano, producenci, c.description AS Opis
    """)
    df["Opublikowano"] = pd.to_datetime(df["Opublikowano"], errors="coerce").dt.date
    df["KEV"] = df["KEV"].fillna(False).astype(bool)
    df["Raporty"] = df["Raporty"].fillna(0).astype(int)
    df["Poziom"] = df["poziom"].apply(etykieta_poziomu)
    df["Producent"] = df["producenci"].apply(", ".join)
    df["NVD"] = "https://nvd.nist.gov/vuln/detail/" + df["CVE"]
    return df.sort_values("Ryzyko", ascending=False).reset_index(drop=True)


df = wczytaj_podatnosci()

st.title("📊 Ranking podatności")
st.write("Podatności posortowane według wyliczonego ryzyka. Zawęź listę filtrami poniżej.")

# ---------------------------- Filtry ----------------------------
licznosc_producentow = df["producenci"].explode().dropna().value_counts()

f1, f2, f3, f4 = st.columns(4)
poziomy = f1.multiselect("Poziom ryzyka", KOLEJNOSC_POZIOMOW, default=["wysokie", "krytyczne"],
                         format_func=etykieta_poziomu)
producenci = f2.multiselect("Producent", licznosc_producentow.index.tolist(),
                            format_func=lambda p: f"{p} ({licznosc_producentow[p]})",
                            placeholder="wszyscy")
najstarsza, najnowsza = df["Opublikowano"].min(), df["Opublikowano"].max()
daty = f3.date_input("Data publikacji", value=(najstarsza, najnowsza),
                     min_value=najstarsza, max_value=najnowsza, format="DD.MM.YYYY")
min_ryzyko = f4.slider("Minimalne ryzyko", 0, 100, 0)

g1, g2, g3, g4 = st.columns(4, vertical_alignment="bottom")
fraza = g1.text_input("Fraza w opisie", placeholder="np. remote code execution")
tylko_kev = g2.checkbox("Tylko wykorzystywane w atakach (KEV)")
tylko_graf = g3.checkbox("Tylko powiązane z APT lub malware")
tylko_bez_cvss = g4.checkbox("Tylko bez oceny CVSS (ocena klasyfikatora)")

# ---------------------------- Filtrowanie ----------------------------
maska = df["Ryzyko"] >= min_ryzyko
if poziomy:
    maska &= df["poziom"].isin(poziomy)
if producenci:
    wybrani = set(producenci)
    maska &= df["producenci"].apply(lambda lista: bool(wybrani & set(lista)))
if isinstance(daty, tuple) and len(daty) == 2:
    maska &= df["Opublikowano"].between(daty[0], daty[1])
if fraza:
    maska &= df["Opis"].fillna("").str.contains(fraza, case=False, regex=False)
if tylko_kev:
    maska &= df["KEV"]
if tylko_graf:
    maska &= df["graf"].fillna(0) > 0
if tylko_bez_cvss:
    maska &= df["zrodlo_powagi"] == "klasyfikator"

wynik = df[maska].reset_index(drop=True)

st.divider()

# ---------------------------- Wyniki ----------------------------
m1, m2, m3 = st.columns(3)
m1.metric("Podatności spełniające kryteria", f"{len(wynik):,}".replace(",", " "))
m2.metric("W tym wykorzystywane w atakach (KEV)", int(wynik["KEV"].sum()))
m3.metric("Średnie ryzyko", f"{wynik['Ryzyko'].mean():.1f}" if len(wynik) else "–")

if wynik.empty:
    st.info("Żadna podatność nie spełnia wybranych kryteriów. Poluzuj filtry.")
    st.stop()

st.caption("Zaznacz pole po lewej stronie wiersza, aby zobaczyć opis podatności.")
zdarzenie = st.dataframe(
    wynik, key="tabela_ryzyka", on_select="rerun", selection_mode="single-row",
    hide_index=True, width="stretch", height=420,
    column_order=["CVE", "Ryzyko", "Poziom", "CVSS", "EPSS", "KEV", "Raporty",
                  "Producent", "Opublikowano", "NVD"],
    column_config={
        "Ryzyko": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%.1f"),
        "CVSS": st.column_config.NumberColumn(format="%.1f"),
        "EPSS": st.column_config.NumberColumn("EPSS (percentyl)", format="%.3f"),
        "KEV": st.column_config.CheckboxColumn(),
        "Opublikowano": st.column_config.DateColumn(format="DD.MM.YYYY"),
        "NVD": st.column_config.LinkColumn(display_text="otwórz"),
    },
)

if zdarzenie.selection.rows:
    wiersz = wynik.iloc[zdarzenie.selection.rows[0]]
    with st.container(border=True):
        st.markdown(f"#### {wiersz['CVE']}  ·  ryzyko {wiersz['Ryzyko']:.1f}  ·  {wiersz['Poziom']}")
        st.write(wiersz["Opis"] or "–")
        if st.button("🔎 Pokaż szczegóły w wyszukiwarce"):
            st.session_state["do_wyszukania"] = wiersz["CVE"]
            st.switch_page("pages/1_Wyszukiwarka.py")

st.download_button(
    "⬇️ Pobierz wyniki (CSV)",
    wynik.drop(columns=["producenci", "poziom", "graf"]).to_csv(index=False).encode("utf-8-sig"),
    file_name="ranking_podatnosci.csv", mime="text/csv",
)

# ---------------------------- Wykres producentów ----------------------------
top = wynik["producenci"].explode().dropna().value_counts().head(10).sort_values()
if not top.empty:
    fig = go.Figure(go.Bar(
        x=top.values, y=top.index, orientation="h",
        marker=dict(color=NIEBIESKI, cornerradius=4),
        hovertemplate="%{y}: %{x} podatności<extra></extra>",
    ))
    fig.update_layout(title="Producenci z największą liczbą podatności w wynikach",
                      height=380, bargap=0.3, showlegend=False,
                      margin=dict(t=50, b=10, l=10, r=10))
    fig.update_xaxes(gridcolor="rgba(128,128,128,0.15)", title="liczba podatności")
    st.plotly_chart(fig, width="stretch")