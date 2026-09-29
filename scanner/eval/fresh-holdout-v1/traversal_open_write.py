from flask import request

def write():
    p = request.form.get("p")
    data = request.form.get("data")
    with open(p, "w") as fh:
        fh.write(data)
    return "ok"
