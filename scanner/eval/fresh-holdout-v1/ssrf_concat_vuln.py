import requests
from flask import request

API = "https://api.example.com/"

def fetch():
    path = request.args.get("path")
    return requests.get(API + path).text
