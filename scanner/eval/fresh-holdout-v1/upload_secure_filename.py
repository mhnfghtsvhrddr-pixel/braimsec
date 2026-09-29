import os
from flask import request
from werkzeug.utils import secure_filename

UPLOAD_DIR = "/var/uploads"

def upload():
    f = request.files["f"]
    f.save(os.path.join(UPLOAD_DIR, secure_filename(f.filename)))
    return "ok"
