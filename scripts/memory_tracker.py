import json
import os
from datetime import datetime
from collections import defaultdict

TRIVY_RESULTS_PATH = "trivyresult.json"
MEMORY_DB_PATH = "memory_db.json"
OUTPUT_DATA_PATH = "data.json"

def load_json(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return []  # default empty list

def extract_repeated_secrets(trivy_data, memory_db):
    repeated = defaultdict(lambda: {"count": 0, "file": "", "type": "", "contributors": set()})

    # Check if trivy_data is a list or dict
    if isinstance(trivy_data, dict):
        results = trivy_data.get("Results", [])
    elif isinstance(trivy_data, list):
        results = trivy_data
    else:
        results = []

    for result in results:
        if result.get("Class") != "secret":
            continue

        for secret in result.get("Secrets", []):
            fingerprint = f"{secret['RuleID']}_{result['Target']}"
            contributor = "SimulatedUser"  # Replace with git blame or GitHub API if needed

            if fingerprint in memory_db:
                repeated[fingerprint]["count"] += 1
                repeated[fingerprint]["file"] = result["Target"]
                repeated[fingerprint]["type"] = secret["Category"]
                repeated[fingerprint]["contributors"].add(contributor)
            else:
                # First-time discovery - store in memory
                memory_db[fingerprint] = {
                    "first_seen": datetime.utcnow().isoformat()
                }

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
    trivy_data = load_json(TRIVY_RESULTS_PATH)
    memory_db = load_json(MEMORY_DB_PATH)

    repeated_dict, updated_memory = extract_repeated_secrets(trivy_data, memory_db)
    dashboard_data = build_dashboard_data(repeated_dict)

    # Append to existing data.json entries (time series)
    existing_data = load_json(OUTPUT_DATA_PATH)
    if isinstance(existing_data, dict):  # Backward compatibility fix
        existing_data = []

    all_data = existing_data + dashboard_data

    with open(MEMORY_DB_PATH, "w") as memf:
        json.dump(updated_memory, memf, indent=2)

    with open(OUTPUT_DATA_PATH, "w") as outf:
        json.dump(all_data, outf, indent=2)

if __name__ == "__main__":
    main()
