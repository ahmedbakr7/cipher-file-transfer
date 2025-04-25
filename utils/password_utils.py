import hashlib
import os
import json

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    password_bytes = password.encode('utf-8')
    salted_password = salt + password_bytes
    hashed = hashlib.sha256(salted_password).hexdigest()
    return hashed, salt.hex()

def verify_password(password, stored_hash, stored_salt):
    salt = bytes.fromhex(stored_salt)
    hashed_input, _ = hash_password(password, salt)
    return hashed_input == stored_hash