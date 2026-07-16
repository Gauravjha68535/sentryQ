# NEGATIVE: Strong cryptography
import hashlib
import secrets

def hash_password(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()

def generate_token():
    return secrets.token_hex(32)

secure_token = secrets.token_urlsafe(32)
