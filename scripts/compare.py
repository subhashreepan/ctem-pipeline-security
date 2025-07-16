import sqlite3
import json
import hashlib
import os
from datetime import datetime

DB_PATH = "memory/exposure.db"
GITLEAKS_PATH = "scans/gitleaks.json"
TRIVY_PATH = "scans/trivy.json"

def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        hash TEXT PRIMARY KEY,
        vuln_id TEXT,
        type TEXT,
        description TEXT,
        file_path TEXT,
        line INT,
        severity TEXT,
        commit_hash TEXT,
        first_seen TEXT,
        last_seen TEXT,
        repeat_count INT
    )
    ''')
    con.commit()
    con.close()

def load_gitleaks():
    if not os.path.exists(GITLEAKS_PATH):
        return []
    with open(GITLEAKS_PATH, 'r') as f:
        data = json.load(f)
    findings = []
    for item in data:
        findings.append({
            "vuln_id": item.get("rule", "gitleaks-secret"),
            "type": "secret",
            "description": item.get("description", ""),
            "file_path": item.get("file", ""),
            "line": item.get("start_line", 0),
            "severity": "medium",
            "commit_hash": item.get("commit", ""),
        })
    return findings

def load_trivy():
    if not os.path.exists(TRIVY_PATH):
        return []
    with open(TRIVY_PATH, 'r') as f:
        data = json.load(f)
    findings = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []):
            findings.append({
                "vuln_id": vuln.get("VulnerabilityID", ""),
                "type": "vulnerability",
                "description": vuln.get("Description", ""),
                "file_path": target,
                "line": 0,
                "severity": vuln.get("Severity", "unknown"),
                "commit_hash": "",  # Commit hash unavailable from Trivy
            })
    return findings

def hash_finding(finding):
    concat_str = f"{finding['vuln_id']}|{finding['file_path']}|{finding['line']}|{finding['type']}"
    return hashlib.sha256(concat_str.encode()).hexdigest()

def update_memory(findings):
    now = datetime.utcnow().isoformat()
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    for f in findings:
        h = hash_finding(f)
        cur.execute("SELECT hash, repeat_count FROM vulnerabilities WHERE hash = ?", (h,))
        row = cur.fetchone()
        if row:
            # Existing vulnerability, update last_seen and increment repeat_count
            repeat_count = row[1] + 1
            cur.execute(
                "UPDATE vulnerabilities SET last_seen = ?, repeat_count = ? WHERE hash = ?",
                (now, repeat_count, h)
            )
        else:
            # New vulnerability, insert record
            cur.execute(
                "INSERT INTO vulnerabilities VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (h, f["vuln_id"], f["type"], f["description"], f["file_path"], f["line"], f["severity"],
                 f["commit_hash"], now, now, 0)
            )
    con.commit()
    con.close()

if __name__ == "__main__":
    init_db()
    findings = load_gitleaks() + load_trivy()
    update_memory(findings)
