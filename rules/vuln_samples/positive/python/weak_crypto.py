# POSITIVE: Weak cryptography
import hashlib
import random

def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()  # MD5 is weak

def generate_token():
    return str(random.random())  # Insecure random

sha1_hash = hashlib.sha1(b"data").hexdigest()  # SHA1 is weak
