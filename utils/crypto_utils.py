from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag # Ensure this is imported
import os

BLOCK_SIZE = 128  # AES block size in bits
AES_KEY_SIZE = 32 # Bytes (256-bit for MEK and file keys)
RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537

def generate_salt(length: int = 16) -> bytes:
    """Generates a random salt of specified length."""
    return os.urandom(length)

def generate_symmetric_key(key_length: int = AES_KEY_SIZE) -> bytes:
    """Generates a random symmetric key (e.g., for AES)."""
    return os.urandom(key_length)

# --- Generic Symmetric Encryption/Decryption ---

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """
    Encrypts data using AES-CBC with a random IV prepended.
    Key length should match AES_KEY_SIZE (e.g., 32 bytes for AES-256).
    """
    if len(key) not in [16, 24, 32]: # AES-128, AES-192, AES-256
        raise ValueError(f"Invalid AES key length: {len(key)} bytes. Must be 16, 24, or 32.")
    iv = os.urandom(16)  # AES CBC IV is always 16 bytes (128 bits)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(BLOCK_SIZE).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_payload = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_payload # Prepend IV

def decrypt_data(encrypted_payload_with_iv: bytes, key: bytes) -> bytes:
    """
    Decrypts data encrypted with AES-CBC, assuming IV is prepended.
    Key length should match AES_KEY_SIZE.
    """
    if len(key) not in [16, 24, 32]:
        raise ValueError(f"Invalid AES key length: {len(key)} bytes. Must be 16, 24, or 32.")
    if len(encrypted_payload_with_iv) < 16: # IV size
        raise ValueError("Encrypted data is too short to contain an IV.")
    
    iv = encrypted_payload_with_iv[:16]
    encrypted_data = encrypted_payload_with_iv[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    try:
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(BLOCK_SIZE).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data
    except InvalidTag: 
        # CBC mode typically doesn't raise InvalidTag itself upon decryption failure with wrong key.
        # Instead, it produces garbage data which then fails at the unpadding stage (ValueError).
        # However, keeping it here is harmless and good practice if the mode were ever changed to an AEAD mode.
        print(f"{__name__}: Decryption failed due to InvalidTag (e.g. AEAD mode mismatch or corruption).")
        raise # Re-raise the original exception
    except ValueError as e: 
        # This is the more common exception for CBC with wrong key/corrupted data leading to padding errors.
        # print(f"{__name__}: Decryption failed, likely incorrect key or corrupted data leading to unpadding error: {e}")
        # Raising a more generic error or the original 'e' is fine.
        # For user feedback, a generic "decryption failed" is often better than exposing padding details.
        raise ValueError("Decryption failed. Incorrect key or data corruption suspected.") from e


# --- File Content Specific Wrappers (optional, can be removed if encrypt_data/decrypt_data are used directly) ---
def encrypt_file_content(content: bytes, key: bytes) -> bytes:
    """Wrapper for encrypt_data, specifically for file content."""
    return encrypt_data(content, key)

def decrypt_file_content(encrypted_content_with_iv: bytes, key: bytes) -> bytes:
    """Wrapper for decrypt_data, specifically for file content."""
    return decrypt_data(encrypted_content_with_iv, key)


def hash_file_content(content: bytes) -> str:
    """Hashes content using SHA-256 and returns hex digest."""
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(content)
    return digest.finalize().hex()

# --- RSA Functions ---
def generate_rsa_key_pair():
    """Generates an RSA private/public key pair and returns them as PEM-encoded bytes."""
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def encrypt_with_rsa_public_key(data_to_encrypt: bytes, public_key_pem: bytes) -> bytes:
    """Encrypts data using an RSA public key (PEM format) with OAEP padding."""
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )
    encrypted_data = public_key.encrypt(
        data_to_encrypt,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

def decrypt_with_rsa_private_key(encrypted_data: bytes, private_key_pem: bytes) -> bytes:
    """Decrypts data using an RSA private key (PEM format) with OAEP padding."""
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None, 
        backend=default_backend()
    )
    decrypted_data = private_key.decrypt(
        encrypted_data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data