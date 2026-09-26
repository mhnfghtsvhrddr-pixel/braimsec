import secrets
def make_token():
    # SAFE: CSPRNG for security token
    return secrets.token_hex(16)
