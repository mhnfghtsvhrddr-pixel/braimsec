from pathlib import Path
from flask import request

def read():
    p = request.args.get("p")
    return Path(p).read_text()
