import yaml
from flask import request
def parse():
    # SAFE: safe_load cannot construct arbitrary objects
    return yaml.safe_load(request.data)
