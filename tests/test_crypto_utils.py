import unittest
import os
from utils import crypto_utils # Assuming utils is in PYTHONPATH or tests is run from project root

class TestCryptoUtils(unittest.TestCase):

    def test_symmetric_encryption_decryption(self):
        key = crypto_utils.generate_symmetric_key()
        original_data = b"This is some secret test data for AES."
        
        encrypted_data = crypto_utils.encrypt_data(original_data, key)
        self.assertNotEqual(original_data, encrypted_data, "Encrypted data should not be same as original.")
        
        decrypted_data = crypto_utils.decrypt_data(encrypted_data, key)
        self.assertEqual(original_data, decrypted_data, "Decrypted data should match original.")

    def test_decryption_wrong_key(self):
        key1 = crypto_utils.generate_symmetric_key()
        key2 = crypto_utils.generate_symmetric_key()
        self.assertNotEqual(key1, key2) # Ensure keys are different
        
        original_data = b"Another piece of data."
        encrypted_data = crypto_utils.encrypt_data(original_data, key1)
        
        with self.assertRaises(ValueError, msg="Decrypting with wrong key should raise ValueError (padding error)."):
            crypto_utils.decrypt_data(encrypted_data, key2)

    def test_hash_file_content(self):
        data1 = b"Hello World"
        data2 = b"Hello world" # Different case
        
        hash1 = crypto_utils.hash_file_content(data1)
        hash1_again = crypto_utils.hash_file_content(data1)
        hash2 = crypto_utils.hash_file_content(data2)
        
        self.assertEqual(hash1, hash1_again, "Hashing same data should produce same hash.")
        self.assertNotEqual(hash1, hash2, "Hashing different data should produce different hashes.")
        self.assertEqual(len(hash1), 64, "SHA-256 hash should be 64 hex characters long.")

    def test_rsa_key_generation(self):
        priv_pem, pub_pem = crypto_utils.generate_rsa_key_pair()
        self.assertIsNotNone(priv_pem)
        self.assertIsNotNone(pub_pem)
        self.assertTrue(priv_pem.startswith(b'-----BEGIN PRIVATE KEY-----'))
        self.assertTrue(pub_pem.startswith(b'-----BEGIN PUBLIC KEY-----'))

    def test_rsa_encryption_decryption(self):
        priv_pem, pub_pem = crypto_utils.generate_rsa_key_pair()
        original_data = os.urandom(32) # e.g., an AES key
        
        encrypted_data = crypto_utils.encrypt_with_rsa_public_key(original_data, pub_pem)
        self.assertNotEqual(original_data, encrypted_data)
        
        decrypted_data = crypto_utils.decrypt_with_rsa_private_key(encrypted_data, priv_pem)
        self.assertEqual(original_data, decrypted_data)

    def test_generate_salt(self):
        salt1 = crypto_utils.generate_salt(16)
        salt2 = crypto_utils.generate_salt(16)
        self.assertEqual(len(salt1), 16)
        self.assertNotEqual(salt1, salt2, "Generated salts should be unique.")

if __name__ == '__main__':
    unittest.main()