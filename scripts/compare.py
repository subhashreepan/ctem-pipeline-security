import json
import sqlite3
import os
from datetime import datetime, timezone

DB_PATH = "memory/exposure.db"
TRIVY_RESULTS = "trivy-results.json"

os.makedirs("memory", exist_ok=True)

# Connect to SQLite
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

# Create table 
cur.execute("""
CREATE TABLE IF NOT EXISTS vulnerabilities (
    vuln_id TEXT,
    description TEXT,
    file_path TEXT,
    severity TEXT,
    first_seen TEXT,
    last_seen TEXT,
    repeat_count INTEGER,
    PRIMARY KEY (vuln_id, file_path)
)
""")

# Load current scan results
with open(TRIVY_RESULTS, "r") as f:
    trivy_data = json.load(f)

current_vulns = []
for result in trivy_data.get("Results", []):
    for vuln in result.get("Vulnerabilities", []):
        vuln_id = vuln.get("VulnerabilityID")
        desc = vuln.get("Title") or vuln.get("Description", "")
        path = result.get("Target", "")
        severity = vuln.get("Severity", "")
        current_vulns.append((vuln_id, desc, path, severity))

now = datetime.now(timezone.utc).isoformat()

for vuln_id, desc, path, severity in current_vulns:
    cur.execute("""
    SELECT repeat_count FROM vulnerabilities
    WHERE vuln_id=? AND file_path=?
    """, (vuln_id, path))
    row = cur.fetchone()

    if row:
        repeat_count = row[0] + 1
        cur.execute("""
        UPDATE vulnerabilities
        SET last_seen=?, repeat_count=?
        WHERE vuln_id=? AND file_path=?
        """, (now, repeat_count, vuln_id, path))
    else:
        cur.execute("""
        INSERT INTO vulnerabilities (
            vuln_id, description, file_path, severity,
            first_seen, last_seen, repeat_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (vuln_id, desc, path, severity, now, now, 0))

conn.commit()
conn.close()

print("compare.py executed and updated exposure.db")
