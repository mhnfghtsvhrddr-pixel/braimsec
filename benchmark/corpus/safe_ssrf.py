import requests
from flask import request
ALLOWED = {"https://api.example.com/"}
def fetch():
    url = request.args.get("url", "")
    # SAFE: allowlist before requesting
    if url not in ALLOWED:
        raise ValueError("blocked")
    return requests.get(url, timeout=5).text
