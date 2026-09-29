import requests
from flask import request, abort

ALLOWED = {"https://api.example.com", "https://cdn.example.com"}

def fetch():
    url = request.args.get("u")
    host = url.split("/")[2]
    if host not in ALLOWED:
        abort(400)
    return requests.get(url).text
