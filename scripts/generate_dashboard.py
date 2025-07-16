import sqlite3
import json
from collections import defaultdict

DB_PATH = "memory/exposure.db"
DASHBOARD_JSON = "dashboard/data.json"

def generate_dashboard_data():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
    SELECT first_seen, last_seen, repeat_count FROM vulnerabilities ORDER BY first_seen ASC
    """)
    rows = cur.fetchall()
    con.close()

    # Aggregate counts by day
    timeline = defaultdict(lambda: {"new": 0, "repeat": 0})
    for first, last, repeat in rows:
        day = first.split("T")[0]
        if repeat > 0:
            timeline[day]["repeat"] += 1
        else:
            timeline[day]["new"] += 1

    dates = sorted(timeline.keys())
    new_counts = [timeline[d]["new"] for d in dates]
    repeat_counts = [timeline[d]["repeat"] for d in dates]

    data = {
        "dates": dates,
        "new_findings": new_counts,
        "repeated_findings": repeat_counts,
    }

    with open(DASHBOARD_JSON, "w") as f:
        json.dump(data, f, indent=2)

if __name__ == "__main__":
    generate_dashboard_data()
