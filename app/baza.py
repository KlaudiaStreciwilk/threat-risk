"""Wspólne połączenie z bazą Neo4j i ustawienia używane przez wszystkie strony panelu."""
import os

import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

KOLEJNOSC_POZIOMOW = ["niskie", "średnie", "wysokie", "krytyczne"]
KOLORY_POZIOMOW = {
    "niskie": "#0ca30c",
    "średnie": "#fab219",
    "wysokie": "#ec835a",
    "krytyczne": "#d03b3b",
}


@st.cache_resource
def polaczenie():
    return GraphDatabase.driver(
        os.getenv("NEO4J_URI"),
        auth=(os.getenv("NEO4J_USER"), os.getenv("NEO4J_PASSWORD")),
    )


def sprawdz_polaczenie():
    """Zatrzymuje stronę z czytelnym komunikatem, jeśli baza nie działa."""
    try:
        polaczenie().verify_connectivity()
    except Exception:
        st.error("Brak połączenia z bazą Neo4j. Uruchom Docker Desktop i wpisz w terminalu: docker start neo4j")
        st.stop()


@st.cache_data(ttl=600, show_spinner=False)
def zapytanie(cypher, **parametry):
    """Wykonuje zapytanie Cypher i zwraca wynik jako tabelę pandas (zapamiętaną na 10 minut)."""
    with polaczenie().session() as s:
        return pd.DataFrame([r.data() for r in s.run(cypher, **parametry)])