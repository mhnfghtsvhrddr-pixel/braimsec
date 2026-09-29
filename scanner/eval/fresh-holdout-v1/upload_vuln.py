import os
from flask import request

UPLOAD_DIR = "/var/uploads"

def upload():
    f = request.files["f"]
    f.save(os.path.join(UPLOAD_DIR, f.filename))
    return "ok"
