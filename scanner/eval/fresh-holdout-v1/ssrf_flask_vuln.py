import requests
from flask import request

app = None

def fetch():
    url = request.args.get("u")
    return requests.get(url).text
