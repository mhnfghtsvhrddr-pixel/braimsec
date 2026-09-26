import random
def make_token():
    # VULN: predictable PRNG for security token
    return str(random.randint(100000, 999999))
