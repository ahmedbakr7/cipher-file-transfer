from argon2 import PasswordHasher, Type as Argon2Type # Import Type
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash
# For raw key derivation, we might need low_level if PasswordHasher doesn't expose it easily
from argon2.low_level import hash_secret_raw, Type as Argon2LowLevelType # Ensure Type is available for hash_secret_raw, aliased for clarity

# Existing PasswordHasher for password storage (includes salt generation)
ph = PasswordHasher(
    time_cost=3,    
    memory_cost=65536, # 64MB
    parallelism=2,   
    hash_len=32,     # Length of the hash part in the encoded string
    salt_len=16,
    type=Argon2Type.ID # Use Argon2id by default for password hashing
)

def hash_password(password: str) -> str:
    """
    Hashes a password using Argon2 for storage.
    The salt is generated automatically and embedded in the hash string.
    """
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    if not password:
        raise ValueError("Password cannot be empty.")
    hashed_password_str = ph.hash(password.encode('utf-8')) 
    return hashed_password_str

def verify_password(password: str, stored_hash_str: str) -> bool:
    """Verifies a password against a stored Argon2 hash string."""
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    if not isinstance(stored_hash_str, str):
        raise TypeError("Stored hash must be a string.")
    if not password: 
        return False 
    if not stored_hash_str:
        raise ValueError("Stored hash cannot be empty.")

    try:
        ph.verify(stored_hash_str, password.encode('utf-8')) 
        return True
    except VerifyMismatchError:
        return False
    except VerificationError as e: 
        print(f"Argon2 VerificationError: {e}")
        return False
    except InvalidHash: 
        print(f"Argon2 InvalidHash error during verification.")
        return False
    except Exception as e: 
        print(f"Unexpected error during Argon2 password verification: {e}")
        return False

def needs_rehash(stored_hash_str: str) -> bool:
    """Checks if the given hash uses outdated Argon2 parameters defined in 'ph'."""
    if not isinstance(stored_hash_str, str) or not stored_hash_str:
        return False 
    try:
        return ph.check_needs_rehash(stored_hash_str)
    except (VerificationError, InvalidHash): 
        print(f"Hash '{stored_hash_str[:30]}...' is invalid or unparseable, considering for rehash.")
        return True

# --- New Argon2 Key Derivation Function ---
DEFAULT_MEK_LENGTH = 32 # For AES-256
DEFAULT_ARGON2_KDF_TIME_COST = 3
DEFAULT_ARGON2_KDF_MEMORY_COST = 65536 # 64MB
DEFAULT_ARGON2_KDF_PARALLELISM = 2 # Number of threads
DEFAULT_ARGON2_KDF_TYPE = Argon2Type.ID # Argon2id is generally recommended (same as ph)

def derive_key_with_argon2(password: str, salt: bytes, 
                           key_length: int = DEFAULT_MEK_LENGTH,
                           time_cost: int = DEFAULT_ARGON2_KDF_TIME_COST,
                           memory_cost: int = DEFAULT_ARGON2_KDF_MEMORY_COST,
                           parallelism: int = DEFAULT_ARGON2_KDF_PARALLELISM,
                           type: Argon2Type = DEFAULT_ARGON2_KDF_TYPE) -> bytes: # Changed type hint to Argon2Type
    """
    Derives a raw key of 'key_length' bytes from a password and salt using Argon2.
    Uses argon2.low_level.hash_secret_raw for direct key derivation.
    """
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    if not password:
        raise ValueError("Password cannot be empty for key derivation.")
    if not isinstance(salt, bytes) or len(salt) < 8: # Argon2 salt min length is 8 bytes
        raise ValueError("Salt must be bytes and at least 8 bytes long for Argon2 key derivation.")
    if not isinstance(key_length, int) or key_length <= 0:
        raise ValueError("Key length must be a positive integer.")

    # Ensure the 'type' parameter for hash_secret_raw uses the correct Argon2Type enum
    # The `type` parameter in the function signature was shadowing the built-in `type`.
    # Renaming it to `argon2_type` for clarity in the function call.
    argon2_type_for_raw = type # Use the passed 'type' parameter

    raw_derived_key = hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=key_length,
        type=argon2_type_for_raw, # Use the correctly scoped Argon2Type
        version=0x13 # Explicitly use Argon2 version 1.3 (19 decimal)
    )
    return raw_derived_key