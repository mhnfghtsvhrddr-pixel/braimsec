import bcrypt
def store_password(password):
    # SAFE: slow salted password hash
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
