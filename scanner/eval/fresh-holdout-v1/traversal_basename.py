import os
from flask import request

BASE = "/var/docs"

def read():
    p = request.args.get("p")
    return open(os.path.join(BASE, os.path.basename(p))).read()
