import requests
import time
from neo4j import GraphDatabase
from dotenv import load_dotenv
import os

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USER = os.getenv("NEO4J_USER")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")


# ==== CONFIG ====
OTX_API_KEY = "57280c9d6b4d7a25648133716a1c4f2b5c1ad76fd135c74e0ee5349340299feb"
MAX_PAGES = 50
# ================

headers = {"X-OTX-API-KEY": OTX_API_KEY}
all_pulses = []

for page in range(1, MAX_PAGES + 1):
    url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?page={page}"
    print(f" Fetching page {page}...")

    for attempt in range(3):
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            results = data.get("results", [])
            
            if not results:
                print("No more results, stopping.")
                break

            all_pulses.extend(results)
            break
        else:
            print(f"Attempt {attempt + 1} failed. Retrying in 5 seconds...")
            time.sleep(5)

    if response.status_code != 200:
        print(f"Stopped at page {page}: HTTP {response.status_code}")
        break

print(f"\n Total pulses fetched: {len(all_pulses)}")

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

def import_pulse(tx, pulse):
    pulse_id = pulse["id"]
    tx.run("""
        MERGE (p:Pulse {id: $id})
        SET p.name = $name, p.description = $desc, p.created = $created
    """, id=pulse_id, name=pulse["name"], desc=pulse.get("description", ""), created=pulse["created"])

    for i in pulse.get("indicators", []):
        ioc_type = i.get("type", "").lower()
        value = i.get("indicator")
        rel_query = ""

        if ioc_type == "ipv4":
            rel_query = "MERGE (n:IP {address: $val})"
        elif ioc_type == "domain":
            rel_query = "MERGE (n:Domain {name: $val})"
        elif ioc_type == "url":
            rel_query = "MERGE (n:URL {url: $val})"
        elif ioc_type == "hostname":
            rel_query = "MERGE (n:Hostname {name: $val})"
        elif ioc_type == "bitcoinaddress":
            rel_query = "MERGE (n:BitcoinAddress {addr: $val})"
        elif ioc_type.startswith("filehash"):
            rel_query = "MERGE (n:FileHash {hash: $val})"
        elif ioc_type == "cve":
            rel_query = "MERGE (n:CVE {id: $val})"
        elif ioc_type == "yara":
            rel_query = "MERGE (n:YARARule {rule: $val})"

        if rel_query:
            full_query = f"""
            {rel_query}
            WITH n
            MATCH (p:Pulse {{id: $pid}})
            MERGE (n)-[:ASSOCIATED_WITH]->(p)
            """
            tx.run(full_query, val=value, pid=pulse_id)

# Write to Neo4j
with driver.session() as session:
    for pulse in all_pulses:
        session.execute_write(import_pulse, pulse)

driver.close()
print("\n OTX indicators successfully imported into Neo4j.")
