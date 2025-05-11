import unittest
from utils import password_utils # Assuming utils is in PYTHONPATH
from argon2.exceptions import VerifyMismatchError, InvalidHash, VerificationError
import os
from argon2 import Type as Argon2Type

class TestPasswordUtils(unittest.TestCase):

    def test_hash_and_verify_password_success(self):
        password = "correct_password123!"
        hashed_password = password_utils.hash_password(password)
        
        self.assertIsNotNone(hashed_password)
        self.assertIsInstance(hashed_password, str)
        self.assertTrue(hashed_password.startswith("$argon2id$"), "Hash should be Argon2id format.")
        
        self.assertTrue(password_utils.verify_password(password, hashed_password), 
                        "Verification of correct password should succeed.")

    def test_verify_password_failure_wrong_password(self):
        password = "correct_password123!"
        wrong_password = "wrong_passwordXYZ?"
        hashed_password = password_utils.hash_password(password)
        
        self.assertFalse(password_utils.verify_password(wrong_password, hashed_password),
                         "Verification of wrong password should fail.")

    def test_verify_password_failure_invalid_hash(self):
        password = "some_password"
        invalid_hash_string = "not_an_argon2_hash_string"
        # verify_password itself prints to console on InvalidHash, so this test also checks it doesn't crash.
        self.assertFalse(password_utils.verify_password(password, invalid_hash_string),
                         "Verification against an invalid hash string should fail.")

    def test_hash_password_empty(self):
        with self.assertRaises(ValueError, msg="Hashing an empty password should raise ValueError."):
            password_utils.hash_password("")

    def test_verify_password_empty_password_input(self):
        # Assuming verify_password returns False for empty password input, rather than raising error
        hashed_password = password_utils.hash_password("somepassword")
        self.assertFalse(password_utils.verify_password("", hashed_password),
                         "Verifying an empty password string should fail (return False).")

    def test_verify_password_empty_hash_input(self):
        with self.assertRaises(ValueError, msg="Verifying against an empty hash should raise ValueError."):
            password_utils.verify_password("somepassword", "")
            
    def test_needs_rehash_false_for_current_params(self):
        password = "a_good_password"
        hashed_password = password_utils.hash_password(password) # Uses current 'ph' params
        self.assertFalse(password_utils.needs_rehash(hashed_password),
                         "Hash generated with current parameters should not need rehash.")

    def test_needs_rehash_true_for_different_params(self):
        # Manually create a hash with slightly different (but valid) parameters
        # This is a bit more involved as it requires knowing the Argon2 string format
        # or using a different PasswordHasher instance.
        # For simplicity, we'll test against a known "older" valid Argon2 string if possible,
        # or an invalid one which should also trigger needs_rehash (as per current logic).
        
        # Example of an older Argon2i hash string (parameters might differ from current ph)
        # Note: This specific string might or might not trigger needs_rehash depending on ph's exact settings.
        # A more robust test would involve creating a hash with explicitly different parameters.
        older_argon2i_hash = "$argon2i$v=19$m=16,t=2,p=1$c29tZXNhbHQ$IMitqB42r9hcJ22TTQc2rg" # Example Argon2i
        
        # If current ph is Argon2id, this Argon2i hash should ideally need rehash.
        # Also, if parameters (m, t, p) are lower than ph's, it should need rehash.
        # The current needs_rehash also returns True for invalid/unparseable hashes.
        self.assertTrue(password_utils.needs_rehash(older_argon2i_hash),
                        "An older or differently parameterized hash should ideally need rehash.")

        invalid_hash_for_rehash = "definitely_not_a_hash"
        self.assertTrue(password_utils.needs_rehash(invalid_hash_for_rehash),
                        "An invalid hash string should be considered for rehash.")


    def test_derive_key_with_argon2_success(self):
        password = "mysecretpassword_for_kdf"
        salt = os.urandom(16) # Generate a random salt
        key_length = 32
        
        derived_key = password_utils.derive_key_with_argon2(password, salt, key_length=key_length)
        self.assertIsInstance(derived_key, bytes)
        self.assertEqual(len(derived_key), key_length)

        # Deriving again with same params should yield same key
        derived_key_again = password_utils.derive_key_with_argon2(password, salt, key_length=key_length)
        self.assertEqual(derived_key, derived_key_again)

        # Deriving with different salt should yield different key
        different_salt = os.urandom(16)
        self.assertNotEqual(salt, different_salt)
        derived_key_different_salt = password_utils.derive_key_with_argon2(password, different_salt, key_length=key_length)
        self.assertNotEqual(derived_key, derived_key_different_salt)
        
        # Deriving with different password should yield different key
        derived_key_different_pass = password_utils.derive_key_with_argon2("anotherpassword", salt, key_length=key_length)
        self.assertNotEqual(derived_key, derived_key_different_pass)

    def test_derive_key_with_argon2_invalid_inputs(self):
        password = "password"
        salt = os.urandom(16)

        with self.assertRaises(TypeError, msg="Password must be string for KDF."):
            password_utils.derive_key_with_argon2(123, salt)
        with self.assertRaises(ValueError, msg="Empty password for KDF should raise ValueError."):
            password_utils.derive_key_with_argon2("", salt)
        
        with self.assertRaises(ValueError, msg="Salt must be bytes and >= 8 chars for KDF."):
            password_utils.derive_key_with_argon2(password, b"short") # Too short
        with self.assertRaises(ValueError, msg="Salt must be bytes for KDF."):
            password_utils.derive_key_with_argon2(password, "notbytes")

        with self.assertRaises(ValueError, msg="Key length must be positive for KDF."):
            password_utils.derive_key_with_argon2(password, salt, key_length=0)
        with self.assertRaises(ValueError, msg="Key length must be positive for KDF."):
            password_utils.derive_key_with_argon2(password, salt, key_length=-5)

if __name__ == '__main__':
    unittest.main()