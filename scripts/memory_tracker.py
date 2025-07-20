import json
from datetime import datetime
import os

TRIVY_RESULTS = "trivy-results.json"
MEMORY_FILE = "memory.json"
OUTPUT_DIR = "dashboard"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "data.json")

def load_trivy_data():
    with open(TRIVY_RESULTS, 'r') as f:
        return json.load(f)

def load_memory():
    if os.path.exists(MEMORY_FILE):
        with open(MEMORY_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_memory(memory):
    with open(MEMORY_FILE, 'w') as f:
        json.dump(memory, f, indent=2)

def save_dashboard(data):
    # Ensure the 'dashboard' directory exists
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def main():
    trivy = load_trivy_data()
    memory = load_memory()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    current_findings = {}
    dashboard_rows = []

    for result in trivy.get("Results", []):
        target = result.get("Target")
        secrets = result.get("Secrets", [])

        for secret in secrets:
            rule_id = secret.get("RuleID")
            severity = secret.get("Severity", "UNKNOWN")
            title = secret.get("Title", "")
            unique_id = f"{target}::{rule_id}"

            current_findings[unique_id] = {
                "timestamp": timestamp,
                "severity": severity,
                "rule": rule_id,
                "target": target,
                "title": title
            }

            memory.setdefault(unique_id, {"count": 0, "history": []})
            memory[unique_id]["count"] += 1
            memory[unique_id]["history"].append(timestamp)

    for vuln_id, data in memory.items():
        dashboard_rows.append({
            "id": vuln_id,
            "severity": current_findings.get(vuln_id, {}).get("severity", "UNKNOWN"),
            "title": current_findings.get(vuln_id, {}).get("title", ""),
            "target": current_findings.get(vuln_id, {}).get("target", ""),
            "rule": current_findings.get(vuln_id, {}).get("rule", ""),
            "occurrences": data["count"],
            "last_seen": data["history"][-1] if data["history"] else "N/A"
        })

    save_memory(memory)
    save_dashboard({"vulnerabilities": dashboard_rows})
    print(f"[+] Dashboard data written to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
