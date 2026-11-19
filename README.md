# Analiza reputacji i estymacja ryzyka zagrożeń cybernetycznych

Prototyp systemu do automatycznego zbierania danych o zagrożeniach (OSINT / Threat Intelligence),
oceny ich reputacji oraz dynamicznej estymacji ryzyka.

System:
- pobiera i ujednolica dane z otwartych źródeł,
- wyciąga z tekstów raportów encje (CVE, IP, domeny, URL, hashe, nazwy malware, grup APT i oprogramowania),
- klasyfikuje opisy jako krytyczne zagrożenie lub szum informacyjny,
- zapisuje zagrożenia i powiązania między nimi w grafowej bazie Neo4j,
- wylicza dynamiczne ryzyko podatności i reputację wskaźników kompromitacji (0–100),
- prezentuje wyniki w interaktywnym panelu (Streamlit).

## Źródła danych

| Źródło | Co dostarcza |
|---|---|
| NVD API 2.0 | podatności (CVE): opis, CVSS, CWE, producenci i produkty |
| EPSS (FIRST.org) | prawdopodobieństwo wykorzystania podatności w ciągu 30 dni |
| CISA KEV | podatności wykorzystywane w atakach (w tym przez ransomware) |
| ThreatFox (abuse.ch) | wskaźniki kompromitacji (IoC) powiązane z malware |
| AlienVault OTX | raporty o zagrożeniach (teksty, IoC, malware, grupy APT) |
| MITRE ATT&CK | nazwy i aliasy grup APT oraz rodzin malware (słownik) |
| Tranco | lista najpopularniejszych domen (odróżnianie stron legalnych) |

## Wymagania

- Python 3.13
- Docker (baza Neo4j 5 Community)
- darmowe klucze API: NVD (opcjonalny), abuse.ch, AlienVault OTX

## Instalacja

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

Skopiuj `.env.example` jako `.env` i uzupełnij klucze:
```
NVD_API_KEY=
ABUSECH_AUTH_KEY=
OTX_API_KEY=
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=
```

Uruchom bazę Neo4j (hasło takie jak w `.env`):
```powershell
docker run -d --name neo4j -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/<haslo> -v neo4j_data:/data neo4j:5-community
```
Przy kolejnych uruchomieniach wystarczy `docker start neo4j`.

## Uruchomienie całego przetwarzania

Kroki trzeba wykonać w tej kolejności (każdy korzysta z wyników poprzednich):

```powershell
# 1. Pobieranie danych
python src\ingest\nvd.py
python src\ingest\enrich.py
python src\ingest\threatfox.py
python src\ingest\otx.py

# 2. Baza grafowa
python src\db\load_graph.py

# 3. Ekstrakcja encji
python -m src.extract.build_dictionary
python -m src.extract.run_ner
python -m src.extract.evaluate
python -m src.db.load_reports

# 4. Klasyfikator
python -m src.model.prepare_data
python -m src.model.baseline
python -m src.model.transformer      # opcjonalnie: ok. 1,5 h na procesorze
python -m src.model.apply            # wymaga wcześniejszego uruchomienia transformer.py

# 5. Ocena ryzyka i reputacji
python -m src.risk.cve_risk
python -m src.risk.ioc_reputation
python -m src.risk.evaluate_risk
python -m src.db.load_risk
```

## Panel

```powershell
streamlit run app/Start.py
```
Panel otwiera się pod adresem http://localhost:8501 i zawiera cztery strony:
- **Start** – podsumowanie danych i najgroźniejsze zagrożenia,
- **Wyszukiwarka** – reputacja IP, domeny, URL, hasha lub CVE wraz z wyjaśnieniem wyniku,
- **Ranking** – podatności według ryzyka z filtrami i eksportem do CSV,
- **Graf** – interaktywny graf powiązań wokół wybranego obiektu.

## Testy

```powershell
pytest -v
```

## Struktura projektu

```
threat-risk/
├── app/                  panel Streamlit
│   ├── Start.py          strona startowa
│   ├── baza.py           wspólne połączenie z Neo4j
│   └── pages/            wyszukiwarka, ranking, graf
├── src/
│   ├── ingest/           pobieranie danych (NVD, EPSS/KEV, ThreatFox, OTX)
│   ├── extract/          ekstrakcja encji (regex, słownik, spaCy) i jej ocena
│   ├── model/            klasyfikator: TF-IDF, DistilBERT, porównanie
│   ├── risk/             ryzyko CVE, reputacja IoC, ocena algorytmu
│   └── db/               ładowanie danych i wyników do Neo4j
├── tests/                testy jednostkowe (pytest)
├── figures/              wykresy do sprawozdania
├── data/                 dane (nie są przechowywane w repozytorium)
└── models/               wytrenowane modele (nie są przechowywane w repozytorium)
```