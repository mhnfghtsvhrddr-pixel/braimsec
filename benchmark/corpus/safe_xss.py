from flask import request
from markupsafe import escape
def profile():
    name = request.args.get("name", "")
    # SAFE: output is escaped
    return "<h1>Hello " + escape(name) + "</h1>"
