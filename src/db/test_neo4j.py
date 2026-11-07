import os
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

driver = GraphDatabase.driver(
    os.getenv("NEO4J_URI"),
    auth=(os.getenv("NEO4J_USER"), os.getenv("NEO4J_PASSWORD")),
)

with driver.session() as session:
    wynik = session.run("RETURN 'Połączenie z Neo4j działa!' AS msg").single()
    print(wynik["msg"])

driver.close()