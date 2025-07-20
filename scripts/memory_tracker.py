import json
import os
from datetime import datetime
from collections import defaultdict

TRIVY_RESULTS_PATH = "trivy-results.json"  # make sure this matches your actual file
MEMORY_DB_PATH = "memory_db.json"
OUTPUT_DATA_PATH = "data.json"

def load_json(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            data = json.load(f)
            # Fix if memory_db.json contains a list instead of dict
            if path == MEMORY_DB_PATH and isinstance(data, list):
                print(f"WARNING: {MEMORY_DB_PATH} contains a list, resetting to empty dict")
                return {}
            return data
    if path == MEMORY_DB_PATH:
        return {}  # memory_db must be dict
    else:
        return []  # other files default to list

def extract_repeated_secrets(trivy_data, memory_db):
    repeated = defaultdict(lambda: {"count": 0, "file": "", "type": "", "contributors": set()})

    # Debug memory_db type and keys
    if isinstance(memory_db, dict):
        print(f"DEBUG: Keys in memory_db: {list(memory_db.keys())}")
    else:
        print(f"DEBUG: memory_db is not a dict but a {type(memory_db)}")

    # Extract results safely
    if isinstance(trivy_data, dict):
        results = trivy_data.get("Results", [])
    elif isinstance(trivy_data, list):
        results = trivy_data
    else:
        results = []

    print(f"DEBUG: Found {len(results)} results in trivy data")

    for result in results:
        print(f"DEBUG: Processing target: {result.get('Target')}, Class: {result.get('Class')}")
        if result.get("Class") != "secret":
            continue

        for secret in result.get("Secrets", []):
            fingerprint = f"{secret['RuleID']}_{result['Target']}"
            print(f"DEBUG: Found secret: {secret['RuleID']} in {result['Target']}")
            contributor = "SimulatedUser"  # replace with git blame or API if you want

            if fingerprint in memory_db:
                repeated[fingerprint]["count"] += 1
                repeated[fingerprint]["file"] = result["Target"]
                repeated[fingerprint]["type"] = secret["Category"]
                repeated[fingerprint]["contributors"].add(contributor)
                print(f"DEBUG: Secret {fingerprint} is repeated, count={repeated[fingerprint]['count']}")
            else:
                memory_db[fingerprint] = {
                    "first_seen": datetime.utcnow().isoformat()
                }
                print(f"DEBUG: Secret {fingerprint} first seen, adding to memory")

    return repeated, memory_db

def build_dashboard_data(repeated_dict):
    timestamp = datetime.utcnow().isoformat()
    dashboard_entries = []

    for fingerprint, details in repeated_dict.items():
        entry = {
            "timestamp": timestamp,
            "count": details["count"],
            "file": details["file"],
            "type": details["type"],
            "contributor": ", ".join(details["contributors"])
        }
        dashboard_entries.append(entry)

    return dashboard_entries

def main():
    print("Current working directory:", os.getcwd())

    # Print raw JSON content for debug
    with open(TRIVY_RESULTS_PATH, "r") as f:
        raw_content = f.read()
    print("Raw trivyresults.json content (first 1000 chars):")
    print(raw_content[:1000])

    trivy_data = json.loads(raw_content)
    memory_db = load_json(MEMORY_DB_PATH)

    repeated_dict, updated_memory = extract_repeated_secrets(trivy_data, memory_db)
    dashboard_data = build_dashboard_data(repeated_dict)

    with open(OUTPUT_DATA_PATH, "w") as outf:
        json.dump(dashboard_data, outf, indent=2)

    with open(MEMORY_DB_PATH, "w") as memf:
        json.dump(updated_memory, memf, indent=2)

if __name__ == "__main__":
    main()
