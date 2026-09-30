"""BraimSec PR-bot live-test demo file (deliberately vulnerable)."""
import requests
from flask import request

# fake credential for the gitleaks path (deterministic comment)
GITHUB_TOKEN_FALLBACK = "ghp_aBcDeF1gHiJ2kLmN3oPqR4sTuV5wXyZ6aB7c"


def fetch():
    url = request.args.get("u")
    return requests.get(url, timeout=5).text
