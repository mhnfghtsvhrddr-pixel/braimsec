import os
from flask import request
def read_file():
    name = request.args.get("file", "")
    # SAFE: confined to /data via basename + realpath check
    path = os.path.realpath(os.path.join("/data", os.path.basename(name)))
    assert path.startswith("/data/")
    with open(path) as f:
        return f.read()
