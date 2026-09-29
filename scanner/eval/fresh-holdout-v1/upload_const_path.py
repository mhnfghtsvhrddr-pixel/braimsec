from flask import request

def upload():
    f = request.files["f"]
    f.save("/var/uploads/fixed-name.bin")
    return "ok"
