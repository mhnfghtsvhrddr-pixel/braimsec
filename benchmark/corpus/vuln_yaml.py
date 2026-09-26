import yaml
from flask import request
def parse():
    # VULN: unsafe yaml load on request data (arbitrary code execution)
    return yaml.unsafe_load(request.data)
