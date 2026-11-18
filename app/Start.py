"""Strona startowa panelu: podsumowanie danych i najgroźniejsze zagrożenia."""
import plotly.graph_objects as go
import streamlit as st

from baza import zapytanie, sprawdz_polaczenie, KOLEJNOSC_POZIOMOW, KOLORY_POZIOMOW

st.set_page_config(page_title="Threat Risk", page_icon="🛡️", layout="wide")
sprawdz_polaczenie()

st.title("🛡️ Analiza reputacji i ryzyka zagrożeń")
st.caption("Źródła danych: NVD, EPSS (FIRST.org), CISA KEV, ThreatFox (abuse.ch), AlienVault OTX")

# ---------- Liczby ----------
liczby = zapytanie("""
RETURN
  COUNT { (c:CVE) WHERE c.ryzyko IS NOT NULL } AS cve,
  COUNT { (c:CVE) WHERE c.in_kev = true } AS kev,
  COUNT { (c:CVE) WHERE c.poziom IN ['wysokie', 'krytyczne'] } AS cve_wysokie,
  COUNT { (i:IoC) } AS ioc,
  COUNT { (i:IoC) WHERE i.poziom IN ['wysokie', 'krytyczne'] } AS ioc_wysokie,
  COUNT { (r:Report) } AS raporty,
  COUNT { (m:Malware) } AS malware,
  COUNT { (a:Actor) } AS aktorzy
""").iloc[0]

k1, k2, k3, k4 = st.columns(4)
k1.metric("Podatności (CVE)", f"{liczby['cve']:,}".replace(",", " "))
k2.metric("CVE o ryzyku wysokim lub krytycznym", f"{liczby['cve_wysokie']:,}".replace(",", " "))
k3.metric("CVE wykorzystywane w atakach (KEV)", liczby["kev"])
k4.metric("Raporty o zagrożeniach", f"{liczby['raporty']:,}".replace(",", " "))

k5, k6, k7, k8 = st.columns(4)
k5.metric("Wskaźniki kompromitacji (IoC)", f"{liczby['ioc']:,}".replace(",", " "))
k6.metric("IoC o złej reputacji (wysoka/krytyczna)", liczby["ioc_wysokie"])
k7.metric("Rodziny malware", liczby["malware"])
k8.metric("Grupy APT", liczby["aktorzy"])

st.divider()


# ---------- Wykresy poziomów ----------
def wykres_poziomow(df, tytul):
    df = df.set_index("poziom").reindex(KOLEJNOSC_POZIOMOW, fill_value=0).reset_index()
    fig = go.Figure(go.Bar(
        x=df["poziom"],
        y=df["liczba"],
        marker=dict(color=[KOLORY_POZIOMOW[p] for p in df["poziom"]], cornerradius=4),
        text=df["liczba"],
        textposition="outside",
        cliponaxis=False,
        hovertemplate="Poziom %{x}: %{y}<extra></extra>",
    ))
    fig.update_layout(title=tytul, height=330, bargap=0.35, showlegend=False,
                      margin=dict(t=50, b=10, l=10, r=10))
    fig.update_yaxes(range=[0, df["liczba"].max() * 1.15], gridcolor="rgba(128,128,128,0.15)")
    return fig


lewa, prawa = st.columns(2)
with lewa:
    df = zapytanie("MATCH (c:CVE) WHERE c.poziom IS NOT NULL "
                   "RETURN c.poziom AS poziom, count(*) AS liczba")
    st.plotly_chart(wykres_poziomow(df, "Podatności według poziomu ryzyka"), width="stretch")
with prawa:
    df = zapytanie("MATCH (i:IoC) WHERE i.poziom IS NOT NULL "
                   "RETURN i.poziom AS poziom, count(*) AS liczba")
    st.plotly_chart(wykres_poziomow(df, "Wskaźniki IoC według reputacji"), width="stretch")

st.divider()

# ---------- Najgroźniejsze podatności ----------
st.subheader("10 podatności o najwyższym ryzyku")
top_cve = zapytanie("""
MATCH (c:CVE) WHERE c.ryzyko IS NOT NULL
WITH c ORDER BY c.ryzyko DESC LIMIT 10
OPTIONAL MATCH (c)-[:AFFECTS_VENDOR]->(v:Vendor)
RETURN c.id AS CVE, c.ryzyko AS Ryzyko, c.poziom AS Poziom, c.cvss_score AS CVSS,
       c.epss_percentile AS `EPSS (percentyl)`, c.in_kev AS KEV,
       c.n_raportow AS Raporty, head(collect(v.name)) AS Producent
ORDER BY Ryzyko DESC
""")
st.dataframe(
    top_cve, hide_index=True, width="stretch",
    column_config={
        "Ryzyko": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%.1f"),
        "EPSS (percentyl)": st.column_config.NumberColumn(format="%.3f"),
        "KEV": st.column_config.CheckboxColumn(),
        "Raporty": st.column_config.NumberColumn(format="%d"),
    },
)

# ---------- Malware i grupy APT ----------
lewa, prawa = st.columns(2)
with lewa:
    st.subheader("Malware z najwięcej groźnymi IoC")
    st.dataframe(zapytanie("""
        MATCH (m:Malware) WHERE m.liczba_ioc_wysokich > 0
        RETURN m.name AS Malware, m.liczba_ioc_wysokich AS `IoC o złej reputacji`,
               m.liczba_ioc AS `Wszystkie IoC`
        ORDER BY `IoC o złej reputacji` DESC LIMIT 10
    """), hide_index=True, width="stretch")
with prawa:
    st.subheader("Grupy APT powiązane z groźnymi CVE")
    st.dataframe(zapytanie("""
        MATCH (a:Actor) WHERE a.max_ryzyko_cve IS NOT NULL
        RETURN a.name AS Grupa, a.max_ryzyko_cve AS `Najwyższe ryzyko CVE`,
               a.liczba_cve AS `Liczba CVE`
        ORDER BY `Najwyższe ryzyko CVE` DESC, `Liczba CVE` DESC LIMIT 10
    """), hide_index=True, width="stretch")