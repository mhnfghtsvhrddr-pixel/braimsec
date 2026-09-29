import requests

def fetch():
    return requests.get("https://api.example.com/v1/status").text
