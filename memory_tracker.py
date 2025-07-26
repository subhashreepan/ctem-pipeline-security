import json
import os
import random
from datetime import datetime, timedelta, timezone
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

def generate_commit_hash():
    return ''.join(random.choices('0123456789abcdef', k=40))

def format_friendly_delta(past, now):
    delta = now - past
    days = delta.days
    seconds = delta.seconds
    if days > 0:
        return f"{days} days ago"
    elif seconds >= 3600:
        return f"{seconds // 3600} hours ago"
    elif seconds >= 60:
        return f"{seconds // 60} minutes ago"
    else:
        return "just now"

def extract_repeated_secrets(trivy_data, memory_db):
    repeated = defaultdict(lambda: {
        "count": 0, "file": "", "type": "", "contributors": set(), "severity": "", "commit_hash": ""
    })

    results = trivy_data.get("Results", [])
    now = datetime.now(timezone.utc)

    for result in results:
        if result.get("Class") != "secret":
            continue

        for secret in result.get("Secrets", []):
            fingerprint = f"{secret['RuleID']}_{result['Target']}"
            contributor = secret.get("Contributor", "UnknownUser")
            severity = secret.get("Severity", "UNKNOWN")
            rule_id = secret.get("RuleID", "UNKNOWN")
            commit_hash = secret.get("CommitHash", "").strip()
            if not commit_hash:
                commit_hash = generate_commit_hash()

            if fingerprint in memory_db:
                # Keep original first_seen
                first_seen_str = memory_db[fingerprint].get("first_seen")
                first_seen = datetime.fromisoformat(first_seen_str).replace(tzinfo=timezone.utc)

                # Simulate varied recent last_seen (1–72 hours ago)
                last_seen = now - timedelta(hours=random.randint(1, 72))
                memory_db[fingerprint]["last_seen"] = last_seen.isoformat()
                memory_db[fingerprint]["repeat_count"] += 1
                memory_db[fingerprint]["commit_hash"] = commit_hash
            else:
                # Simulate random first_seen within July
                days_ago = random.randint(10, 27)
                first_seen = now - timedelta(days=days_ago, hours=random.randint(0, 23))
                memory_db[fingerprint] = {
                    "first_seen": first_seen.isoformat(),
                    "last_seen": now.isoformat(),  # New = now
                    "repeat_count": 1,
                    "commit_hash": commit_hash
                }

            repeated[fingerprint]["count"] = memory_db[fingerprint]["repeat_count"]
            repeated[fingerprint]["file"] = result["Target"]
            repeated[fingerprint]["type"] = rule_id
            repeated[fingerprint]["contributors"].add(contributor)
            repeated[fingerprint]["severity"] = severity
            repeated[fingerprint]["commit_hash"] = commit_hash

    return repeated, memory_db

def build_dashboard_data(repeated_dict, memory_db):
    dashboard_entries = []
    now = datetime.now(timezone.utc)

    for fingerprint, details in repeated_dict.items():
        first_seen_str = memory_db[fingerprint].get("first_seen")
        last_seen_str = memory_db[fingerprint].get("last_seen")
        repeat_count = memory_db[fingerprint].get("repeat_count", 1)

        dt_first = datetime.fromisoformat(first_seen_str).replace(tzinfo=timezone.utc)
        dt_last = datetime.fromisoformat(last_seen_str).replace(tzinfo=timezone.utc)

        if repeat_count == 1:
            time_since_first = "just now"
            time_since_last = "just now"
        else:
            time_since_first = format_friendly_delta(dt_first, now)
            time_since_last = format_friendly_delta(dt_last, now)

        entry = {
            "timestamp": last_seen_str,
            "count": details["count"],
            "file": details["file"],
            "type": details["type"],
            "contributor": ", ".join(details["contributors"]),
            "severity": details.get("severity", "UNKNOWN"),
            "status": "repeated" if details["count"] > 1 else "new",
            "commit_hash": details.get("commit_hash", ""),
            "time_since_first_seen": time_since_first,
            "time_since_last_seen": time_since_last
        }
        dashboard_entries.append(entry)

    return dashboard_entries

def main():
    trivy_data = load_json(TRIVY_RESULTS_PATH)
    memory_db = load_json(MEMORY_DB_PATH)

    repeated_dict, updated_memory = extract_repeated_secrets(trivy_data, memory_db)
    dashboard_data = build_dashboard_data(repeated_dict, updated_memory)

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
