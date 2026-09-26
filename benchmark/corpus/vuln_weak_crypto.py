import hashlib
def store_password(password):
    # VULN: fast broken hash for passwords
    return hashlib.md5(password.encode()).hexdigest()
