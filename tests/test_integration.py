# tests/test_integration.py
import unittest
import socket
import os
import shutil
import threading
import time
import filecmp # For comparing files
import json # For checking metadata encryption

# Adjust paths if your project structure requires it for utils/peer/rendezvous to be found
# This assumes 'utils', 'peer.py', 'rendezvous_server.py' are in the Python path
# when running from the project root (e.g., via `python -m unittest ...`)
from utils import crypto_utils 
from peer import P2PClient, DEFAULT_CHUNK_SIZE, USER_DB_PATH as PEER_USER_DB_PATH_DEFAULT # Import P2PClient and constants
from rendezvous_server import RendezvousServer 

# Test Configuration
TEST_RENDEZVOUS_HOST = '127.0.0.1'
TEST_RENDEZVOUS_PORT = 5056 # Use a different port than default (5050) and previous test (5055)
CLIENT1_NAME = "test_client_alice"
CLIENT2_NAME = "test_client_bob"
CLIENT1_RECV_PORT = 6055 # Use different ports for test clients
CLIENT1_SEND_PORT = 0    # Let OS pick
CLIENT2_RECV_PORT = 6057
CLIENT2_SEND_PORT = 0    # Let OS pick

# Define a root directory for all test-generated data
TEST_DATA_ROOT = "test_run_data" 
# Specific filenames within TEST_DATA_ROOT
TEST_USER_REGISTRY_FILENAME = os.path.join(TEST_DATA_ROOT, "test_user_registry.json")

# Helper function to get client-specific paths within TEST_DATA_ROOT
def get_client_path(base_folder_name: str, client_name_suffix: str) -> str:
    return os.path.join(TEST_DATA_ROOT, f"{base_folder_name}_{client_name_suffix}")

def cleanup_test_environment():
    """Cleans up all directories and files created specifically for tests."""
    if os.path.exists(TEST_DATA_ROOT):
        shutil.rmtree(TEST_DATA_ROOT, ignore_errors=True)
    # Ensure the root test data directory is recreated for subsequent tests if needed by setup
    os.makedirs(TEST_DATA_ROOT, exist_ok=True)


class TestIntegrationScenarios(unittest.TestCase):
    
    rendezvous_server_instance: RendezvousServer = None
    rendezvous_thread: threading.Thread = None
    original_peer_user_db_path: str = None

    @classmethod
    def setUpClass(cls):
        """Set up for all tests in this class: Start Rendezvous Server."""
        print("\nSetting up TestIntegrationScenarios: Starting Rendezvous Server...")
        cleanup_test_environment() # Clean before starting server

        cls.rendezvous_server_instance = RendezvousServer(host=TEST_RENDEZVOUS_HOST, port=TEST_RENDEZVOUS_PORT)
        cls.rendezvous_thread = threading.Thread(target=cls.rendezvous_server_instance.start, daemon=True)
        cls.rendezvous_thread.name = "TestRendezvousThread"
        cls.rendezvous_thread.start()
        
        # Wait for server to start - check if socket is listening
        for _ in range(10): # Try for ~1 second
            time.sleep(0.1)
            try:
                with socket.create_connection((TEST_RENDEZVOUS_HOST, TEST_RENDEZVOUS_PORT), timeout=0.1) as s:
                    print("Rendezvous server confirmed listening.")
                    break
            except (ConnectionRefusedError, socket.timeout):
                continue
        else:
            print("Warning: Rendezvous server did not become available quickly.")


        # Patch peer.USER_DB_PATH to use a test-specific registry
        cls.original_peer_user_db_path = PEER_USER_DB_PATH_DEFAULT # Save original from peer.py
        # This modification affects all P2PClient instances created after this point
        # by directly changing the module-level variable in the imported peer module.
        # This is a common way to handle globals in tests if they aren't instance parameters.
        import peer # Import the module itself to modify its global
        peer.USER_DB_PATH = TEST_USER_REGISTRY_FILENAME


    @classmethod
    def tearDownClass(cls):
        """Tear down after all tests in this class: Stop Rendezvous Server."""
        print("\nTearing down TestIntegrationScenarios: Stopping Rendezvous Server...")
        if cls.rendezvous_server_instance:
            cls.rendezvous_server_instance.stop_server() 
        if cls.rendezvous_thread and cls.rendezvous_thread.is_alive():
            cls.rendezvous_thread.join(timeout=2.0) 
        
        # Restore original USER_DB_PATH in peer module
        import peer
        peer.USER_DB_PATH = cls.original_peer_user_db_path
        
        cleanup_test_environment() 
        print("Test environment cleaned up.")

    def setUp(self):
        """Set up for each test method: Create client instances."""
        # Clean user registry before each test method for true isolation of user data
        if os.path.exists(TEST_USER_REGISTRY_FILENAME):
            os.remove(TEST_USER_REGISTRY_FILENAME)
        
        # Ensure client-specific subdirectories within TEST_DATA_ROOT are clean (optional, depends on test needs)
        # For now, we assume cleanup_test_environment in setUpClass is enough for a fresh start,
        # and P2PClient will create its own directories under TEST_DATA_ROOT.

        # Client Alice
        self.client_alice = P2PClient(
            rendezvous_host=TEST_RENDEZVOUS_HOST, rendezvous_port=TEST_RENDEZVOUS_PORT,
            receive_port=CLIENT1_RECV_PORT, send_port=CLIENT1_SEND_PORT,
            client_name=CLIENT1_NAME,
            chunk_size=DEFAULT_CHUNK_SIZE // 4 # Use smaller chunks for testing
        )
        # Explicitly set paths to be within TEST_DATA_ROOT
        self.client_alice.client_data_dir = get_client_path("client_data", CLIENT1_NAME)
        self.client_alice.shared_folder_path = get_client_path("shared_files", CLIENT1_NAME)
        self.client_alice.downloads_folder_path = get_client_path("downloads", CLIENT1_NAME)
        self.client_alice.FILE_METADATA_PATH = os.path.join(self.client_alice.shared_folder_path, 'file_metadata.json')
        self.client_alice.metadata_salt_path = os.path.join(self.client_alice.client_data_dir, "metadata.salt")
        os.makedirs(self.client_alice.client_data_dir, exist_ok=True)
        os.makedirs(self.client_alice.shared_folder_path, exist_ok=True)
        os.makedirs(self.client_alice.downloads_folder_path, exist_ok=True)
        self.client_alice._load_or_generate_metadata_salt() # Call after paths are set


        # Client Bob
        self.client_bob = P2PClient(
            rendezvous_host=TEST_RENDEZVOUS_HOST, rendezvous_port=TEST_RENDEZVOUS_PORT,
            receive_port=CLIENT2_RECV_PORT, send_port=CLIENT2_SEND_PORT,
            client_name=CLIENT2_NAME,
            chunk_size=DEFAULT_CHUNK_SIZE // 4
        )
        self.client_bob.client_data_dir = get_client_path("client_data", CLIENT2_NAME)
        self.client_bob.shared_folder_path = get_client_path("shared_files", CLIENT2_NAME)
        self.client_bob.downloads_folder_path = get_client_path("downloads", CLIENT2_NAME)
        self.client_bob.FILE_METADATA_PATH = os.path.join(self.client_bob.shared_folder_path, 'file_metadata.json')
        self.client_bob.metadata_salt_path = os.path.join(self.client_bob.client_data_dir, "metadata.salt")
        os.makedirs(self.client_bob.client_data_dir, exist_ok=True)
        os.makedirs(self.client_bob.shared_folder_path, exist_ok=True)
        os.makedirs(self.client_bob.downloads_folder_path, exist_ok=True)
        self.client_bob._load_or_generate_metadata_salt()

    def tearDown(self):
        """Tear down after each test method: Stop clients."""
        if hasattr(self, 'client_alice') and self.client_alice and self.client_alice.running:
            self.client_alice.stop()
        if hasattr(self, 'client_bob') and self.client_bob and self.client_bob.running:
            self.client_bob.stop()
        # Individual test directory cleanup can be done here if needed,
        # but setUpClass/tearDownClass handle the main TEST_DATA_ROOT.

    def _create_test_file(self, directory: str, filename: str, size_kb: int) -> str:
        """Helper to create a dummy file with random content."""
        file_path = os.path.join(directory, filename)
        os.makedirs(os.path.dirname(file_path), exist_ok=True) # Ensure dir exists
        with open(file_path, "wb") as f:
            f.write(os.urandom(size_kb * 1024))
        return file_path

    def test_full_scenario_share_and_download(self):
        print("\nRunning scenario: Register, Login, Share, Discover, Download...")
        
        # --- Phase 1: Alice Registers, Logs In, and Shares a File ---
        alice_user = "alice_integration_test"
        alice_pass = "AliceSecureP@ssw0rd!"

        self.assertTrue(self.client_alice.register(username=alice_user, password=alice_pass), "Alice registration failed.")
        self.assertTrue(self.client_alice.login(username=alice_user, password=alice_pass), "Alice login failed.")
        self.assertTrue(self.client_alice.is_logged_in(), "Alice should be logged in.")
        self.assertIsNotNone(self.client_alice.master_encryption_key, "Alice MEK not derived after login.")
        
        # Start Alice's client services (listening thread, etc.) AFTER login
        self.client_alice.start()
        self.assertTrue(self.client_alice.running, "Alice's client failed to start services.")

        # Create a test file for Alice to share
        original_file_name = "integration_test_file.txt"
        # Create the source file outside Alice's shared folder initially
        temp_source_dir = os.path.join(TEST_DATA_ROOT, "temp_source_files")
        alice_source_file_path = self._create_test_file(temp_source_dir, original_file_name, size_kb=5) # 5KB test file
        
        self.assertTrue(self.client_alice.share_file(alice_source_file_path), "Alice share_file failed.")
        
        # Verify metadata file is encrypted (basic check: not valid JSON plaintext)
        time.sleep(0.2) # Give a moment for file operations
        self.assertTrue(os.path.exists(self.client_alice.FILE_METADATA_PATH), "Alice's metadata file not created.")
        with open(self.client_alice.FILE_METADATA_PATH, 'rb') as f_meta_alice:
            alice_meta_content_bytes = f_meta_alice.read()
        
        is_plaintext_json = False
        try:
            json.loads(alice_meta_content_bytes.decode('utf-8'))
            is_plaintext_json = True # Should not happen if encrypted
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass # Expected if encrypted (binary data or not valid UTF-8 JSON)
        self.assertFalse(is_plaintext_json, "Alice's metadata file appears to be plaintext JSON, but should be encrypted.")

        # Verify Alice can load her own (encrypted) metadata
        loaded_alice_metadata = self.client_alice._load_file_metadata() # MEK lock handled inside
        self.assertIn(original_file_name, loaded_alice_metadata, "Shared file not in Alice's loaded metadata.")


        # --- Phase 2: Bob Registers, Logs In, Discovers Alice's File ---
        bob_user = "bob_integration_test"
        bob_pass = "BobSecureP@ssw0rd!"

        self.assertTrue(self.client_bob.register(username=bob_user, password=bob_pass), "Bob registration failed.")
        self.assertTrue(self.client_bob.login(username=bob_user, password=bob_pass), "Bob login failed.")
        self.assertTrue(self.client_bob.is_logged_in(), "Bob should be logged in.")
        self.client_bob.start() # Start Bob's client services
        self.assertTrue(self.client_bob.running, "Bob's client failed to start services.")

        time.sleep(1.5) # Allow time for rendezvous updates (Alice's registration/file list)

        print("Bob refreshing peer list...")
        available_files = self.client_bob.list_available_files() # This calls get_peer_list
        
        self.assertIn(original_file_name, available_files, 
                      f"Alice's file '{original_file_name}' not found by Bob. Available: {list(available_files.keys())}")
        self.assertTrue(len(available_files[original_file_name]) > 0, "No sources found for Alice's file.")
        
        source_peer_id = available_files[original_file_name][0]['peer_id']
        self.assertEqual(source_peer_id, self.client_alice.client_id, "File source ID does not match Alice's ID.")

        # --- Phase 3: Bob Downloads the File ---
        print(f"Bob attempting to download '{original_file_name}' from Alice ({self.client_alice.client_id[:8]})...")
        self.assertTrue(self.client_bob.download_file(self.client_alice.client_id, original_file_name), "Bob download_file failed.")
        
        # Verify downloaded file
        bob_downloaded_file_path = os.path.join(self.client_bob.downloads_folder_path, original_file_name)
        self.assertTrue(os.path.exists(bob_downloaded_file_path), "Downloaded file not found in Bob's downloads.")
        
        # Compare original source with Bob's downloaded file
        self.assertTrue(filecmp.cmp(alice_source_file_path, bob_downloaded_file_path, shallow=False),
                        "Downloaded file content does not match original.")
        print(f"'{original_file_name}' downloaded and verified successfully by Bob.")

        # Clean up the temporary source file Alice used
        if os.path.exists(alice_source_file_path):
            os.remove(alice_source_file_path)
        if os.path.exists(temp_source_dir):
             shutil.rmtree(temp_source_dir, ignore_errors=True)


    def test_scenario_stop_sharing_and_attempt_download(self):
        print("\nRunning scenario: Alice Shares, then Stops Sharing; Bob Attempts Download...")
        
        # --- Phase 1: Alice Registers, Logs In, Shares a File ---
        alice_user = "alice_stopshare_test"
        alice_pass = "AliceStopShareP@ss!"

        self.assertTrue(self.client_alice.register(username=alice_user, password=alice_pass), "Alice registration failed.")
        self.assertTrue(self.client_alice.login(username=alice_user, password=alice_pass), "Alice login failed.")
        self.client_alice.start() # Start Alice's services
        self.assertTrue(self.client_alice.running, "Alice's client failed to start services.")

        original_file_name = "file_to_be_unshared.txt"
        temp_source_dir_alice = os.path.join(TEST_DATA_ROOT, "temp_alice_stopshare_source")
        alice_source_file_path = self._create_test_file(temp_source_dir_alice, original_file_name, size_kb=1) # 1KB file
        
        self.assertTrue(self.client_alice.share_file(alice_source_file_path), "Alice initial share_file failed.")
        
        # --- Phase 2: Bob Registers, Logs In, Confirms File is Available Initially ---
        bob_user = "bob_stopshare_test"
        bob_pass = "BobStopShareP@ss!"

        self.assertTrue(self.client_bob.register(username=bob_user, password=bob_pass), "Bob registration failed.")
        self.assertTrue(self.client_bob.login(username=bob_user, password=bob_pass), "Bob login failed.")
        self.client_bob.start() # Start Bob's services
        self.assertTrue(self.client_bob.running, "Bob's client failed to start services.")

        time.sleep(1.5) # Allow time for Alice's share to propagate via rendezvous

        print("Bob checking available files (before Alice stops sharing)...")
        available_files_before_stop = self.client_bob.list_available_files()
        self.assertIn(original_file_name, available_files_before_stop, 
                      f"Alice's file '{original_file_name}' should be available before she stops sharing. Found: {list(available_files_before_stop.keys())}")

        # --- Phase 3: Alice Stops Sharing the File ---
        print(f"Alice attempting to stop sharing '{original_file_name}'...")
        self.assertTrue(self.client_alice.stop_sharing_file(original_file_name), "Alice's stop_sharing_file method failed.")
        
        # Verify file is removed from Alice's local shared files list (internal state)
        alice_shared_now = self.client_alice.list_shared_files() # This calls _scan_shared_folder
        self.assertNotIn(original_file_name, [f.get('name') for f in alice_shared_now if isinstance(f, dict)], 
                         "File should be removed from Alice's internal shared list after stopping.")
        
        # Verify encrypted file is deleted from Alice's shared folder on disk
        alice_encrypted_file_path = os.path.join(self.client_alice.shared_folder_path, original_file_name)
        self.assertFalse(os.path.exists(alice_encrypted_file_path), 
                         "Encrypted file should be deleted from Alice's shared folder after stopping.")

        time.sleep(1.5) # Allow time for Alice's "stop sharing" update to propagate via rendezvous

        # --- Phase 4: Bob Confirms File is No Longer Available and Attempt to Download Fails ---
        print("Bob refreshing peer list (after Alice stopped sharing)...")
        available_files_after_stop = self.client_bob.list_available_files()
        self.assertNotIn(original_file_name, available_files_after_stop, 
                         f"Alice's file '{original_file_name}' should NOT be available after she stops sharing. Still found: {available_files_after_stop.get(original_file_name)}")

        # Attempting to download should ideally fail because the file is not listed.
        # If Bob somehow had old info and tried to download directly from Alice:
        print(f"Bob attempting to download '{original_file_name}' (which Alice stopped sharing)...")
        download_success = self.client_bob.download_file(self.client_alice.client_id, original_file_name)
        self.assertFalse(download_success, 
                         "Bob's download attempt for a file Alice stopped sharing should fail.")
        
        # Verify the file was not created in Bob's downloads folder
        bob_downloaded_file_path = os.path.join(self.client_bob.downloads_folder_path, original_file_name)
        self.assertFalse(os.path.exists(bob_downloaded_file_path), 
                         "File should not exist in Bob's downloads if download failed.")
        print(f"Verified that Bob cannot download '{original_file_name}' after Alice stopped sharing.")

        # Clean up the temporary source file Alice used
        if os.path.exists(alice_source_file_path):
            os.remove(alice_source_file_path)
        if os.path.exists(temp_source_dir_alice): # Remove the temp directory for this test
             shutil.rmtree(temp_source_dir_alice, ignore_errors=True)

# This allows running the tests directly using `python tests/test_integration.py`
# However, `python -m unittest tests.test_integration` from project root is preferred.
if __name__ == '__main__':
    # If running directly, ensure the project root is in sys.path for imports like 'utils'
    # This is a common pattern but might need adjustment based on how you structure imports.
    if __package__ is None: # Heuristic to check if run as script
        import sys
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.abspath(os.path.join(current_dir, '..'))
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        # Re-import after path adjustment if necessary (though direct imports at top should work if run via -m unittest)
        from peer import P2PClient, DEFAULT_CHUNK_SIZE, USER_DB_PATH as PEER_USER_DB_PATH_DEFAULT
        from rendezvous_server import RendezvousServer
        from utils import crypto_utils

    unittest.main()