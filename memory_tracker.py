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
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {} if path == MEMORY_DB_PATH else []
    return {} if path == MEMORY_DB_PATH else []

def extract_repeated_secrets(trivy_data, memory_db):
    repeated = defaultdict(lambda: {
        "count": 0, "file": "", "type": "", "contributors": set(), "severity": ""
    })

    results = trivy_data.get("Results", [])

    for result in results:
        if result.get("Class") != "secret":
            continue

        for secret in result.get("Secrets", []):
            fingerprint = f"{secret['RuleID']}_{result['Target']}"
            contributor = secret.get("Contributor", "UnknownUser")
            severity = secret.get("Severity", "UNKNOWN")
            rule_id = secret.get("RuleID", "UNKNOWN")

            if fingerprint in memory_db:
                new_count = memory_db[fingerprint].get("repeat_count", 1) + 1
                memory_db[fingerprint]["repeat_count"] = new_count
                memory_db[fingerprint]["last_seen"] = datetime.utcnow().isoformat()
            else:
                memory_db[fingerprint] = {
                    "first_seen": datetime.utcnow().isoformat(),
                    "repeat_count": 1,
                    "last_seen": datetime.utcnow().isoformat()
                }
                new_count = 1

            repeated[fingerprint]["count"] = new_count
            repeated[fingerprint]["file"] = result["Target"]
            repeated[fingerprint]["type"] = rule_id  # <--- CHANGED HERE
            repeated[fingerprint]["contributors"].add(contributor)
            repeated[fingerprint]["severity"] = severity

    return repeated, memory_db

def build_dashboard_data(repeated_dict):
    dashboard_entries = []
    timestamp = datetime.utcnow().isoformat()

    for _, details in repeated_dict.items():
        entry = {
            "timestamp": timestamp,
            "count": details["count"],
            "file": details["file"],
            "type": details["type"],  # rule_id now shown in dashboard
            "contributor": ", ".join(details["contributors"]),
            "severity": details.get("severity", "UNKNOWN")
        }
        dashboard_entries.append(entry)

    return dashboard_entries

def main():
    trivy_data = load_json(TRIVY_RESULTS_PATH)
    memory_db = load_json(MEMORY_DB_PATH)

    repeated_dict, updated_memory = extract_repeated_secrets(trivy_data, memory_db)
    dashboard_data = build_dashboard_data(repeated_dict)

    REPEAT_THRESHOLD = 2
    alert_entries = [v for v in repeated_dict.values() if v["count"] >= REPEAT_THRESHOLD]

    output = {
        "entries": dashboard_data,
        "alert": {
            "active": len(alert_entries) > 0,
            "count": len(alert_entries),
            "threshold": REPEAT_THRESHOLD
        }
    }

    with open(OUTPUT_DATA_PATH, "w") as outf:
        json.dump(output, outf, indent=2)

    with open(MEMORY_DB_PATH, "w") as memf:
        json.dump(updated_memory, memf, indent=2)

    print(f"[memory_tracker.py] Dashboard data written to {OUTPUT_DATA_PATH}")

if __name__ == "__main__":
    main()
