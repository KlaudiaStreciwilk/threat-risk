import pandas, sklearn, spacy, networkx, streamlit, torch, transformers
from dotenv import load_dotenv
import os

load_dotenv()
nlp = spacy.load("en_core_web_sm")
doc = nlp("APT28 exploited CVE-2023-23397 in Microsoft Outlook.")
print([(e.text, e.label_) for e in doc.ents])
print("NEO4J_URI z .env:", os.getenv("NEO4J_URI"))
print("Wszystko działa!")