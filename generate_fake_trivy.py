import json
import random
from datetime import datetime, timedelta

OUTPUT_FILE = "trivy-results.json"

CONTRIBUTORS = ["Subhashree", "Lana", "John", "George", "Sara"]
SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
CATEGORY = "Hardcoded Secret"
FILES = [
    "src/app/auth.py",
    "src/utils/secrets.py",
    "config/credentials.yml",
    "Dockerfile",
    "README.md",
    "scripts/deploy.sh",
    "config/api_keys.json",
    "src/db/db_config.py",
    "src/api/token_handler.py",
    "init/setup_env.sh"
]

RULE_IDS = ["SECRET_API_KEY", "HARDCODED_TOKEN", "ENV_SECRET", "PASSWORD_STRING"]

def random_past_time(days_back=10):
    now = datetime.utcnow()
    return (now - timedelta(days=random.randint(0, days_back), seconds=random.randint(0, 86400))).isoformat()

def generate_secret(rule_id, contributor):
    return {
        "RuleID": rule_id,
        "Category": CATEGORY,
        "Severity": random.choice(SEVERITY_LEVELS),
        "StartLine": random.randint(1, 100),
        "EndLine": random.randint(101, 200),
        "Match": "some_secret_value_here",
        "Contributor": contributor,
        "Title": f"{rule_id} Exposure"
    }

def generate_trivy_results(num_results=10):
    results = []
    for _ in range(num_results):
        file = random.choice(FILES)
        contributor = random.choice(CONTRIBUTORS)
        rule_id = random.choice(RULE_IDS)

        secrets = [generate_secret(rule_id, contributor) for _ in range(random.randint(1, 3))]

        results.append({
            "Target": file,
            "Class": "secret",
            "Type": "github",
            "Secrets": secrets,
            "Timestamp": random_past_time()
        })
    return {"Results": results}

def main():
    fake_data = generate_trivy_results(15)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(fake_data, f, indent=2)
    print(f"[generate_fake_trivy.py] Written to {OUTPUT_FILE} with {len(fake_data['Results'])} entries.")

if __name__ == "__main__":
    main()
