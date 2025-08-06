## Python-Script
---
import pandas as pd
import re

# Load IOCs
def load_iocs(ioc_file):
    with open(ioc_file, 'r') as file:
        return [line.strip() for line in file.readlines()]

# Search for IOCs in log fields
def search_logs(log_df, iocs):
    matches = []
    for idx, row in log_df.iterrows():
        for field in row:
            for ioc in iocs:
                if ioc.lower() in str(field).lower():
                    matches.append((row['TimeCreated'], ioc, row.to_dict()))
                    break
    return matches

# Load logs
logs = pd.read_csv("logs.csv")
iocs = load_iocs("iocs.txt")
alerts = search_logs(logs, iocs)

# Output alerts
if alerts:
    print(f"\n🚨 Detected {len(alerts)} suspicious events:")
    for alert in alerts:
        print(f"\n🕒 Time: {alert[0]}\n🎯 IOC: {alert[1]}\n📝 Event: {alert[2]}")
else:
    print("✅ No IOCs found in logs.")
    ---
