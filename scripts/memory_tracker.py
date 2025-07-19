import sqlite3
import json
import os
from datetime import datetime

# Ensure paths exist
os.makedirs("memory", exist_ok=True)
os.makedirs("dashboard", exist_ok=True)

TRIVY_RESULTS_PATH = "trivy-results.json"  # Fix: correct path as per GitHub Action output
DATA_OUTPUT_PATH = "dashboard/data.json"

# Load new scan results from Trivy
if not os.path.exists(TRIVY_RESULTS_PATH):
    print(f"⚠️ {TRIVY_RESULTS_PATH} not found.")
    exit(1)

with open(TRIVY_RESULTS_PATH, "r") as f:
    new_data = json.load(f)

# Connect to SQLite
conn = sqlite3.connect("memory/memory.db")
c = conn.cursor()

# Create table if not exists
c.execute('''
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vuln_id TEXT,
        pkg_name TEXT,
        severity TEXT,
        detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

# Insert scan results & build memory data
repeated = []
new_entries = []
seen = set()

for result in new_data.get("Results", []):
    for vuln in result.get("Vulnerabilities", []):
        vuln_id = vuln.get("VulnerabilityID", "UNKNOWN")
        pkg_name = vuln.get("PkgName", "UNKNOWN")
        severity = vuln.get("Severity", "UNKNOWN")
        seen_key = f"{vuln_id}|{pkg_name}"

        # Check for repeats
        c.execute('''
            SELECT COUNT(*) FROM vulnerabilities
            WHERE vuln_id = ? AND pkg_name = ?
        ''', (vuln_id, pkg_name))
        count = c.fetchone()[0]

        if count > 0:
            repeated.append({
                "vuln_id": vuln_id,
                "pkg_name": pkg_name,
                "severity": severity,
                "count": count + 1
            })
        else:
            new_entries.append({
                "vuln_id": vuln_id,
                "pkg_name": pkg_name,
                "severity": severity,
                "count": 1
            })

        if seen_key not in seen:
            seen.add(seen_key)
            c.execute('''
                INSERT INTO vulnerabilities (vuln_id, pkg_name, severity)
                VALUES (?, ?, ?)
            ''', (vuln_id, pkg_name, severity))

# Commit to DB
conn.commit()
conn.close()

# Build data.json structure
summary_data = {
    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "new_vulnerabilities": new_entries,
    "repeated_vulnerabilities": repeated,
    "total_found": len(new_entries) + len(repeated)
}

# Write to dashboard/data.json
with open(DATA_OUTPUT_PATH, "w") as f:
    json.dump(summary_data, f, indent=2)

print(f"Memory updated and data.json written to {DATA_OUTPUT_PATH}")
