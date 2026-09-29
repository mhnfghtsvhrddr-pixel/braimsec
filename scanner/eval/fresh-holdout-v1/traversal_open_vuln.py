from flask import request

def read():
    p = request.args.get("p")
    return open(p).read()
