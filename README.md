# Analiza reputacji i estymacja ryzyka zagrożeń cybernetycznych

Prototyp systemu do automatycznego zbierania danych o zagrożeniach (OSINT / Threat Intelligence),
oceny ich reputacji oraz dynamicznej estymacji ryzyka.

## Źródła danych
- NVD API 2.0 – podatności (CVE, CVSS)
- EPSS (FIRST.org) – prawdopodobieństwo wykorzystania podatności
- CISA KEV – podatności wykorzystywane w atakach
- ThreatFox (abuse.ch) – wskaźniki kompromitacji (IoC)

## Uruchomienie
```
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```
Skopiuj `.env.example` jako `.env` i uzupełnij klucze API.

Baza Neo4j:
```
docker run -d --name neo4j -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/<haslo> -v neo4j_data:/data neo4j:5-community
```

Pobieranie danych:
```
python src\ingest\nvd.py
python src\ingest\enrich.py
python src\ingest\threatfox.py
```