import json
import os
from datetime import datetime

TRIVY_REPORT_PATH = "reports/trivy-results.json"
MEMORY_PATH = "memory.json"
DATA_PATH = "data.json"

def load_json(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {}

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def extract_secrets(trivy_data):
    secrets = []
    results = trivy_data.get("Results", [])
    for result in results:
        if result.get("Class") == "secret":
            for secret in result.get("Secrets", []):
                secrets.append({
                    "file": result.get("Target", ""),
                    "rule": secret.get("RuleID", ""),
                    "severity": secret.get("Severity", ""),
                    "title": secret.get("Title", ""),
                    "line": secret.get("StartLine", ""),
                    "match": secret.get("Match", ""),
                    "timestamp": datetime.now().isoformat()
                })
    return secrets

def main():
    trivy_report = load_json(TRIVY_REPORT_PATH)
    memory = load_json(MEMORY_PATH)
    current_secrets = extract_secrets(trivy_report)

    # Count repeat occurrences
    history_keys = set((v["file"], v["rule"]) for v in memory.get("secrets", []))
    repeated = [
        s for s in current_secrets if (s["file"], s["rule"]) in history_keys
    ]

    memory.setdefault("secrets", []).extend(current_secrets)
    save_json(MEMORY_PATH, memory)

    dashboard_data = {
        "timestamp": datetime.now().isoformat(),
        "new_vulnerabilities": current_secrets,
        "repeated_vulnerabilities": repeated
    }
    save_json(DATA_PATH, dashboard_data)

if __name__ == "__main__":
    main()
