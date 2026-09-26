import subprocess, ipaddress
from flask import request
def ping():
    host = request.args.get("host", "127.0.0.1")
    # SAFE: validated + no shell, arg list
    ipaddress.ip_address(host)
    subprocess.run(["ping", "-c", "1", host], check=False)
