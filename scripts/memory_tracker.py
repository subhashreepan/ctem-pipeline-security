import os
import json
import sqlite3
from datetime import datetime

TRIVY_REPORT = "trivy-results.json"
DB_PATH = "memory/memory.db"

def init_db():
    os.makedirs("memory", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_id TEXT,
            pkg_name TEXT,
            version TEXT,
            severity TEXT,
            description TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    return conn

def parse_trivy_report():
    if not os.path.exists(TRIVY_REPORT):
        print("Trivy report not found.")
        return []
    with open(TRIVY_REPORT) as f:
        data = json.load(f)
    vulns = []
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            vulns.append({
                "vuln_id": vuln["VulnerabilityID"],
                "pkg_name": vuln["PkgName"],
                "version": vuln["InstalledVersion"],
                "severity": vuln["Severity"],
                "description": vuln.get("Title", "N/A"),
            })
    return vulns

def record_vulns(conn, vulns):
    c = conn.cursor()
    for v in vulns:
        c.execute("""
            INSERT INTO vulnerabilities (vuln_id, pkg_name, version, severity, description, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            v["vuln_id"],
            v["pkg_name"],
            v["version"],
            v["severity"],
            v["description"],
            datetime.utcnow().isoformat()
        ))
    conn.commit()

if __name__ == "__main__":
    conn = init_db()
    vulns = parse_trivy_report()
    if vulns:
        record_vulns(conn, vulns)
        print(f"{len(vulns)} vulnerabilities recorded.")
    else:
        print("No new vulnerabilities to record.")
    conn.close()
