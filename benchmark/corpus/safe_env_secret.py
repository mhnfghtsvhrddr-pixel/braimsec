import os
# SAFE: secret from environment, not hardcoded
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
