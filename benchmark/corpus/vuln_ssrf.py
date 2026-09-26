import requests
from flask import request
def fetch():
    url = request.args.get("url", "")
    # VULN: server-side request to user-controlled URL
    return requests.get(url).text
