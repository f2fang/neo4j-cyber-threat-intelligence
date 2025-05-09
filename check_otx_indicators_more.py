import requests
from collections import Counter
from dotenv import load_dotenv
import os

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USER = os.getenv("NEO4J_USER")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")


# Replace with your OTX API key, this is my API key connect with my account(Fang)
OTX_API_KEY = "57280c9d6b4d7a25648133716a1c4f2b5c1ad76fd135c74e0ee5349340299feb"
headers = {
    "X-OTX-API-KEY": OTX_API_KEY
}

all_pulses = []
max_pages = 50

for page in range(1, max_pages + 1):
    url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?page={page}"
    print(f" Fetching page {page}...")
    
    response = requests.get(url, headers=headers)
    
    if response.status_code != 200:
        print(f" Stopped at page {page}: HTTP {response.status_code}")
        break
    
    data = response.json()
    results = data.get("results", [])
    
    if not results:
        print(" No more results, stopping.")
        break
    
    all_pulses.extend(results)

print(f"\n Total pulses fetched: {len(all_pulses)}")

#  Process all pulses
indicator_types = []
total_indicators = 0

print("\n Subscribed Pulse Details:")

for pulse in all_pulses:
    name = pulse.get("name", "Untitled Pulse")
    indicators = pulse.get("indicators", [])
    print(f" - {name} ({len(indicators)} indicators)")
    total_indicators += len(indicators)
    for i in indicators:
        indicator_types.append(i.get("type"))

# Count each type of indicator
type_counts = Counter(indicator_types)

print(f"\n Total Indicators: {total_indicators}")
print("\n Indicator Type Breakdown:")
for ioc_type, count in type_counts.items():
    print(f" - {ioc_type}: {count}")
