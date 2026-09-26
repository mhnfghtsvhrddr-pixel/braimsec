from flask import request
def read_file():
    name = request.args.get("file", "")
    # VULN: user input used directly as filesystem path
    with open("/data/" + name) as f:
        return f.read()
