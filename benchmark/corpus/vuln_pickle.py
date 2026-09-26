import pickle
from flask import request
def load():
    # VULN: deserializing untrusted request data
    return pickle.loads(request.data)
