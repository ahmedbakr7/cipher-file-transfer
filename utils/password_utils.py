





from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash 








ph = PasswordHasher(
    time_cost=3,    
    memory_cost=65536, 
    parallelism=2,   
    hash_len=32,     
    salt_len=16      
)

def hash_password(password: str) -> str:
    """
    Hashes a password using Argon2.
    The salt is generated automatically by PasswordHasher and embedded in the hash string.
    """
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    if not password:
        raise ValueError("Password cannot be empty.")
        
    
    hashed_password_str = ph.hash(password.encode('utf-8')) 
    return hashed_password_str

def verify_password(password: str, stored_hash_str: str) -> bool:
    """
    Verifies a password against a stored Argon2 hash string.
    The salt is extracted automatically by PasswordHasher from the stored_hash_str.
    """
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
    """
    Checks if the given hash uses outdated Argon2 parameters.
    """
    if not isinstance(stored_hash_str, str) or not stored_hash_str:
        return False 
    try:
        return ph.check_needs_rehash(stored_hash_str)
    except (VerificationError, InvalidHash):
        
        
        print(f"Hash '{stored_hash_str[:30]}...' is invalid or unparseable, considering for rehash.")
        return True