from flask import request
def calc():
    expr = request.args.get("expr", "")
    # VULN: eval on direct user input
    return str(eval(expr))
