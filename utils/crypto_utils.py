
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
import os
import base64

BLOCK_SIZE = 128  # AES block size in bits

def generate_symmetric_key():
    return os.urandom(32)  # AES-256

def encrypt_file_content(content: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    padded_data = padder.update(content) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data  # Prepend IV for use in decryption

def decrypt_file_content(encrypted_content: bytes, key: bytes) -> bytes:
    iv = encrypted_content[:16]
    encrypted_data = encrypted_content[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

def hash_file_content(content: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(content)
    return digest.finalize().hex()