import json
from flask import request
def load():
    # SAFE: JSON instead of pickle
    return json.loads(request.data)
