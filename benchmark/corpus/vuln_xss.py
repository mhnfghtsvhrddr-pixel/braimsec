from flask import request
def profile():
    name = request.args.get("name", "")
    # VULN: unescaped user input reflected into HTML
    return "<h1>Hello " + name + "</h1>"
