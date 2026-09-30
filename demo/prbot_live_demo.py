"""BraimSec PR-bot live-test demo file (deliberately vulnerable)."""
import requests
from flask import request

# fake credential for the gitleaks path (deterministic comment)
GITHUB_TOKEN_FALLBACK = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"


def fetch():
    url = request.args.get("u")
    return requests.get(url, timeout=5).text
