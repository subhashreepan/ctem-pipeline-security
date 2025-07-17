import sqlite3
import json
import os

# Create memory directory if it doesn't exist
os.makedirs("memory", exist_ok=True)

# Load new scan results (mockup for now)
with open("trivy-results.json", "r") as f:
    new_data = json.load(f)

# Connect to SQLite database
conn = sqlite3.connect("memory/memory.db")
c = conn.cursor()

# Create table if it doesn't exist
c.execute('''
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vuln_id TEXT,
        pkg_name TEXT,
        severity TEXT,
        detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

# Insert new scan results
for result in new_data.get("Results", []):
    for vuln in result.get("Vulnerabilities", []):
        c.execute('''
            INSERT INTO vulnerabilities (vuln_id, pkg_name, severity)
            VALUES (?, ?, ?)
        ''', (
            vuln.get("VulnerabilityID", "UNKNOWN"),
            vuln.get("PkgName", "UNKNOWN"),
            vuln.get("Severity", "UNKNOWN")
        ))

conn.commit()
conn.close()
print("Memory updated successfully.")
