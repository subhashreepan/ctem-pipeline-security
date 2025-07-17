import os
from git import Repo

SCAN_RESULTS_BRANCH = "scan-results"
REPO_DIR = os.path.abspath(os.path.dirname(__file__))

def pull_latest_scan_results():
    repo = Repo(REPO_DIR)
    origin = repo.remotes.origin

    # Fetch all branches
    origin.fetch()

    # Checkout the scan-results branch locally (create if not exists)
    if SCAN_RESULTS_BRANCH in repo.heads:
        repo.heads[SCAN_RESULTS_BRANCH].checkout()
    else:
        repo.create_head(SCAN_RESULTS_BRANCH, origin.refs[SCAN_RESULTS_BRANCH])
        repo.heads[SCAN_RESULTS_BRANCH].checkout()

    # Pull latest changes
    origin.pull(SCAN_RESULTS_BRANCH)

    print(f"Pulled latest scan results from {SCAN_RESULTS_BRANCH} branch")

# Call this on app startup or on dashboard route
pull_latest_scan_results()
