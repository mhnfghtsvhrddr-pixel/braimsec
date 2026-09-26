import os
from flask import request
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULN: user input concatenated into shell command
    os.system("ping -c 1 " + host)
