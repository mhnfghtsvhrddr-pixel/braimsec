import urllib.request
from flask import request

def fetch():
    u = request.form["u"]
    return urllib.request.urlopen(u).read()
