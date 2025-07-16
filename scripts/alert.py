import sqlite3

DB_PATH = "memory/exposure.db"

def alert_repeats():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
    SELECT vuln_id, description, file_path, severity, repeat_count, first_seen, last_seen
    FROM vulnerabilities WHERE repeat_count > 0 ORDER BY last_seen DESC
    """)
    repeats = cur.fetchall()
    con.close()

    if repeats:
        print("Repeated Vulnerabilities Detected:")
        for r in repeats:
            print(f"- ID: {r[0]} | Severity: {r[3]} | File: {r[2]} | Count: {r[4]}")
            print(f"  Desc: {r[1]}")
            print(f"  First seen: {r[5]} | Last seen: {r[6]}")
    else:
        print("No repeated vulnerabilities found.")

if __name__ == "__main__":
    alert_repeats()
