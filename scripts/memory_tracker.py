import json
import os
from datetime import datetime
from collections import defaultdict

TRIVY_RESULTS_PATH = "trivy-results.json"
MEMORY_DB_PATH = "memory_db.json"
OUTPUT_DATA_PATH = "data.json"

def load_json(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            data = json.load(f)
            if path == MEMORY_DB_PATH and isinstance(data, list):
                print(f"WARNING: {MEMORY_DB_PATH} contains a list, resetting to empty dict")
                return {}
            return data
    return {} if path == MEMORY_DB_PATH else []

def extract_repeated_secrets(trivy_data, memory_db):
    repeated = defaultdict(lambda: {"count": 0, "file": "", "type": "", "contributors": set()})

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
            contributor = "SimulatedUser"

            if fingerprint in memory_db:
                repeated[fingerprint]["count"] = memory_db[fingerprint].get("repeat_count", 0) + 1
                repeated[fingerprint]["file"] = result["Target"]
                repeated[fingerprint]["type"] = secret["Category"]
                repeated[fingerprint]["contributors"].add(contributor)
                memory_db[fingerprint]["repeat_count"] = repeated[fingerprint]["count"]
                memory_db[fingerprint]["last_seen"] = datetime.utcnow().isoformat()
            else:
                memory_db[fingerprint] = {
                    "first_seen": datetime.utcnow().isoformat(),
                    "repeat_count": 0,
                    "last_seen": datetime.utcnow().isoformat()
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
    with open(TRIVY_RESULTS_PATH, "r") as f:
        raw_content = f.read()
    trivy_data = json.loads(raw_content)
    memory_db = load_json(MEMORY_DB_PATH)

    repeated_dict, updated_memory = extract_repeated_secrets(trivy_data, memory_db)
    dashboard_data = build_dashboard_data(repeated_dict)

    #alert metadata
    REPEAT_THRESHOLD = 1
    repeats_to_alert = {k: v for k, v in repeated_dict.items() if v["count"] >= REPEAT_THRESHOLD}

    output = {
        "entries": dashboard_data,
        "alert": {
            "active": len(repeats_to_alert) > 0,
            "count": len(repeats_to_alert),
            "threshold": REPEAT_THRESHOLD
        }
    }

    with open(OUTPUT_DATA_PATH, "w") as outf:
        json.dump(output, outf, indent=2)

    with open(MEMORY_DB_PATH, "w") as memf:
        json.dump(updated_memory, memf, indent=2)

if __name__ == "__main__":
    main()
