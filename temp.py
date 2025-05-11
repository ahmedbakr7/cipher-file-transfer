# In ./peer.py
import json
import os
import socket
import threading
import time
import uuid

from utils import crypto_utils, password_utils # password_utils now has derive_key_with_argon2
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidTag 

from colored import Fore, Style

USER_DB_PATH = "user_registry.json"

class P2PClient:
    def __init__(self, rendezvous_host='localhost', rendezvous_port=5050, receive_port=0, send_port=0, client_name=None):
        self.logged_in_user = None
        self._current_password_for_mek: str = None # Temporarily store password for MEK derivation
        self.master_encryption_key: bytes = None # For encrypting file_metadata.json
        
        self.client_id = str(uuid.uuid4())
        safe_client_name_suffix = "".join(c if c.isalnum() else "_" for c in (client_name or self.client_id[:8]))
        self.client_name = client_name or self.client_id[:8]

        self.rendezvous_host = rendezvous_host
        self.rendezvous_port = rendezvous_port
        self.receive_port = receive_port
        self.send_port = send_port
        
        self.client_data_dir = f"client_data_{safe_client_name_suffix}"
        os.makedirs(self.client_data_dir, exist_ok=True)

        self.rsa_private_key_path = os.path.join(self.client_data_dir, "private_key.pem")
        self.rsa_public_key_path = os.path.join(self.client_data_dir, "public_key.pem")
        self.rsa_private_key_pem: bytes = None
        self.rsa_public_key_pem: bytes = None

        # Path for the salt used to derive MEK for file_metadata.json
        self.metadata_salt_path = os.path.join(self.client_data_dir, "metadata.salt")
        self.metadata_encryption_salt: bytes = None # Salt for MEK derivation

        default_shared_folder = f'shared_files_{safe_client_name_suffix}'
        default_downloads_folder = f'downloads_{safe_client_name_suffix}'
        self.shared_folder = os.environ.get('P2P_SHARED_FOLDER', default_shared_folder)
        self.downloads_folder = os.environ.get('P2P_DOWNLOADS_FOLDER', default_downloads_folder)
        
        self.FILE_METADATA_PATH = os.path.join(self.shared_folder, 'file_metadata.json')

        self.shared_files = []
        self.peers = {}
        self.listen_socket = None
        self.running = False
        self.connected = False
        
        os.makedirs(self.shared_folder, exist_ok=True)
        os.makedirs(self.downloads_folder, exist_ok=True)
        
        print(f"Client '{self.client_name}' initialized (ID: {self.client_id[:8]})")
        print(f"Data directory: {self.client_data_dir}")
        print(f"Using shared folder: {self.shared_folder}")
        print(f"Using downloads folder: {self.downloads_folder}")
        print(f"Using metadata file: {self.FILE_METADATA_PATH}")
        
        self._load_or_generate_metadata_salt() # Load or generate salt early

    def _load_or_generate_metadata_salt(self):
        """Loads the salt for metadata encryption or generates a new one."""
        try:
            if os.path.exists(self.metadata_salt_path):
                with open(self.metadata_salt_path, "rb") as f:
                    self.metadata_encryption_salt = f.read()
                if len(self.metadata_encryption_salt) < 8: # Argon2 salt min 8 bytes
                    print(f"{Fore.YELLOW}Warning: Metadata salt file '{self.metadata_salt_path}' is too short (< 8 bytes). Generating new salt.{Style.RESET}")
                    self.metadata_encryption_salt = None 
            
            if not self.metadata_encryption_salt:
                print(f"{Fore.YELLOW}Metadata salt not found or invalid, generating new one...{Style.RESET}")
                self.metadata_encryption_salt = crypto_utils.generate_salt(16) # 16-byte salt is good
                with open(self.metadata_salt_path, "wb") as f:
                    f.write(self.metadata_encryption_salt)
                print(f"{Fore.GREEN}New metadata salt generated and saved to '{self.metadata_salt_path}'.{Style.RESET}")
            else:
                print(f"{Fore.GREEN}Metadata salt loaded successfully.{Style.RESET}")

        except Exception as e:
            print(f"{Style.BOLD}{Fore.RED}Fatal Error: Could not load/generate metadata salt: {e}{Style.RESET}")
            self.metadata_encryption_salt = None 
            # Consider setting self.running = False if this is deemed critical enough to halt client
            
    def _derive_and_set_mek(self, password: str):
        """Derives and sets the Master Encryption Key from the password using Argon2."""
        if not password:
            # This case should ideally be prevented by input validation before calling login
            print(f"{Fore.RED}Cannot derive MEK: Password not provided.{Style.RESET}")
            self.master_encryption_key = None
            return

        if not self.metadata_encryption_salt:
            print(f"{Style.BOLD}{Fore.RED}Critical Error: Cannot derive MEK because metadata encryption salt is not available.{Style.RESET}")
            self.master_encryption_key = None
            # This is a severe issue; client might not function correctly for metadata operations.
            return
        
        try:
            self.master_encryption_key = password_utils.derive_key_with_argon2(
                password=password,
                salt=self.metadata_encryption_salt,
                key_length=crypto_utils.AES_KEY_SIZE 
            )
            # print(f"{Fore.GREEN}Master Encryption Key derived successfully using Argon2.{Style.RESET}") # Debug
        except Exception as e:
            print(f"{Style.BOLD}{Fore.RED}Error deriving Master Encryption Key with Argon2: {e}{Style.RESET}")
            self.master_encryption_key = None

    def _clear_mek_and_password(self):
        """Clears the MEK and the temporarily stored password."""
        self.master_encryption_key = None
        if hasattr(self, '_current_password_for_mek'): # Check if attr exists before deleting
            self._current_password_for_mek = None
        # print(f"{Fore.YELLOW}Master Encryption Key and temporary password cleared.{Style.RESET}") # Debug

    def _load_or_generate_rsa_keys(self):
        """Loads RSA keys if they exist, otherwise generates and saves them."""
        try:
            if os.path.exists(self.rsa_private_key_path) and os.path.exists(self.rsa_public_key_path):
                with open(self.rsa_private_key_path, "rb") as f:
                    self.rsa_private_key_pem = f.read()
                with open(self.rsa_public_key_path, "rb") as f:
                    self.rsa_public_key_pem = f.read()
                print(f"{Fore.GREEN}RSA keys loaded successfully for {self.client_name}.{Style.RESET}")
            else:
                print(f"{Fore.YELLOW}RSA keys not found for {self.client_name}, generating new ones...{Style.RESET}")
                private_pem_bytes, public_pem_bytes = crypto_utils.generate_rsa_key_pair()
                with open(self.rsa_private_key_path, "wb") as f:
                    f.write(private_pem_bytes)
                with open(self.rsa_public_key_path, "wb") as f:
                    f.write(public_pem_bytes)
                self.rsa_private_key_pem = private_pem_bytes
                self.rsa_public_key_pem = public_pem_bytes
                print(f"{Fore.GREEN}New RSA keys generated and saved for {self.client_name}.{Style.RESET}")
        except Exception as e:
            print(f"{Style.BOLD}{Fore.RED}Fatal Error: Could not load/generate RSA keys: {e}{Style.RESET}")
            self.running = False 

    def start(self):
        """Start the P2P client."""
        self.running = True
        self._setup_listen_socket() 
        self._load_or_generate_rsa_keys() 
        # self._load_or_generate_metadata_salt() # Moved to __init__

        if not self.running: 
            print(f"{Style.BOLD}{Fore.RED}Client cannot start due to critical errors (e.g. RSA keys/socket bind). Exiting.{Style.RESET}")
            if self.listen_socket: 
                self.listen_socket.close()
            return 

        self._scan_shared_folder() 
        self._connect_to_rendezvous() 
        self._start_listener_thread() 

    def _setup_listen_socket(self):
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.listen_socket.bind(('0.0.0.0', self.receive_port))
            self.receive_port = self.listen_socket.getsockname()[1]  

            if self.send_port == 0:
                temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                temp_socket.bind(('0.0.0.0', 0))
                self.send_port = temp_socket.getsockname()[1]
                temp_socket.close()

            self.listen_socket.listen(5)
            print(f"Listening for incoming connections on port {self.receive_port}")
            print(f"Using port {self.send_port} for outgoing connections")
        except socket.error as e:
            print(f"{Style.BOLD}{Fore.RED}Fatal Error: Could not bind listen socket: {e}{Style.RESET}")
            self.running = False 
            if self.listen_socket:
                self.listen_socket.close()
            self.listen_socket = None

    def _start_listener_thread(self):
        if not self.listen_socket: 
            print(f"{Fore.RED}Listener thread not started because listen socket is not available.{Style.RESET}")
            return
        listener_thread = threading.Thread(target=self._listen_for_connections)
        listener_thread.daemon = True
        listener_thread.start()
        print("Listener thread started.")

    def _scan_shared_folder(self):
        # ... (no changes from your provided version)
        previous_count = len(self.shared_files)
        self.shared_files = [] 

        if os.path.exists(self.shared_folder):
            for file_name in os.listdir(self.shared_folder):
                if file_name == os.path.basename(self.FILE_METADATA_PATH):
                    continue
                file_path = os.path.join(self.shared_folder, file_name)
                if os.path.isfile(file_path):
                    try:
                        file_size = os.path.getsize(file_path)
                        self.shared_files.append({
                            'name': file_name,
                            'size': file_size 
                        })
                    except OSError as e:
                        print(f"{Fore.YELLOW}Warning: Could not get size for file '{file_path}': {e}{Style.RESET}")
        
        if len(self.shared_files) != previous_count: 
            print(f"Sharing {len(self.shared_files)} files from '{self.shared_folder}'")


    def _connect_to_rendezvous(self):
        # ... (no changes from your provided version)
        if not self.running: return

        sock = None # Define sock outside try to ensure it's available in finally
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0) 
            sock.connect((self.rendezvous_host, self.rendezvous_port))
            sock.settimeout(None)

            register_data = {
                'command': 'register',
                'client_id': self.client_id,
                'receive_port': self.receive_port,
                'send_port': self.send_port,
                'files': self.shared_files 
            }
            sock.send(json.dumps(register_data).encode('utf-8'))

            response_raw = sock.recv(4096)
            if not response_raw:
                print(f"{Fore.RED}Failed to register with rendezvous: No response.{Style.RESET}")
                self.connected = False
                return

            response_data = json.loads(response_raw.decode('utf-8'))

            if response_data.get('status') == 'success':
                print(f"{Fore.GREEN}Successfully registered with rendezvous server as {self.client_id[:8]}.{Style.RESET}")
                self.connected = True
                update_thread = threading.Thread(target=self._update_rendezvous_periodically)
                update_thread.daemon = True
                update_thread.start()
            else:
                print(f"{Fore.RED}Failed to register with rendezvous server: {response_data.get('message')}{Style.RESET}")
                self.connected = False
            
        except socket.timeout:
            print(f"{Fore.RED}Failed to connect to rendezvous server: Connection timed out.{Style.RESET}")
            self.connected = False
        except ConnectionRefusedError:
            print(f"{Fore.RED}Failed to connect to rendezvous server: Connection refused.{Style.RESET}")
            self.connected = False
        except Exception as e:
            print(f"{Fore.RED}Failed to connect to rendezvous server: {e}{Style.RESET}")
            self.connected = False
        finally:
            if sock: sock.close()


    def _update_rendezvous_periodically(self):
        # ... (no changes from your provided version)
        while self.running and self.connected: 
            time.sleep(30) 
            if not self.running or not self.connected: break 

            sock = None
            try:
                self._scan_shared_folder() 

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((self.rendezvous_host, self.rendezvous_port))
                sock.settimeout(None)

                update_data = {
                    'command': 'update_files',
                    'client_id': self.client_id,
                    'files': self.shared_files
                }
                sock.send(json.dumps(update_data).encode('utf-8'))
            except socket.error as e: 
                print(f"{Fore.YELLOW}Failed to update rendezvous server (socket error): {e}. Will retry later.{Style.RESET}")
            except Exception as e:
                print(f"{Fore.YELLOW}Failed to update rendezvous server (general error): {e}. Will retry later.{Style.RESET}")
            finally:
                if sock: sock.close()

    def _listen_for_connections(self):
        # ... (no changes from your provided version)
        while self.running:
            try:
                if not self.listen_socket: 
                    print(f"{Fore.RED}Listen socket closed unexpectedly. Stopping listener.{Style.RESET}")
                    self.running = False 
                    break
                client_socket, address = self.listen_socket.accept()
                print(f"Accepted connection from {address}")
                client_handler = threading.Thread(target=self._handle_peer_connection, args=(client_socket, address))
                client_handler.daemon = True
                client_handler.start()
            except socket.error as e: 
                if self.running: 
                    print(f"{Style.BOLD}{Fore.RED}Socket error accepting connection: {e}{Style.RESET}")
                if isinstance(e, OSError) and e.errno == 9: 
                    if self.running:
                        print(f"{Fore.YELLOW}Listen socket seems to have been closed. Stopping listener.{Style.RESET}")
                    self.running = False 
                break 
            except Exception as e:
                if self.running:
                    print(f"{Style.BOLD}{Fore.RED}Error accepting connection: {e}{Style.RESET}")

    def _handle_peer_connection(self, client_socket, address): 
        # ... (no changes from your provided version regarding RSA key exchange)
        try:
            client_socket.settimeout(10.0) 
            data_bytes = client_socket.recv(2048) 
            client_socket.settimeout(None) 

            if not data_bytes:
                print(f"No data received from {address}. Closing connection.")
                return

            data = data_bytes.decode('utf-8')
            request = json.loads(data)
            print(f"Received request from {address}: {request.get('type')}")

            if request.get('type') == 'file_request_initiate_secure': 
                self._handle_secure_file_transfer_sharer(client_socket, request, address)
            else:
                print(f"Unknown request type '{request.get('type')}' from {address}.")
                error_msg = json.dumps({'status': 'error', 'message': 'Unknown request type.'})
                client_socket.send(error_msg.encode('utf-8'))

        except json.JSONDecodeError:
            print(f"{Fore.RED}Invalid JSON received from {address}.{Style.RESET}")
        except socket.timeout:
            print(f"{Fore.RED}Timeout waiting for request from {address}.{Style.RESET}")
        except ConnectionResetError:
            print(f"{Fore.RED}Connection reset by {address}.{Style.RESET}")
        except Exception as e:
            print(f"{Style.BOLD}{Fore.RED}Error handling peer connection from {address}: {e}{Style.RESET}")
            import traceback
            traceback.print_exc()
        finally:
            client_socket.close()
            print(f"Closed connection from {address}.")

    def _handle_secure_file_transfer_sharer(self, client_socket, request, address):
        # ... (no changes from your provided version regarding RSA key exchange)
        # This method uses _load_file_metadata(), which IS NOW CHANGED.
        file_name = request['file_name']
        downloader_public_key_pem_str = request['downloader_public_key']
        downloader_public_key_pem_bytes = downloader_public_key_pem_str.encode('utf-8')

        print(f"Processing secure file request for '{file_name}' from {address}...")

        encrypted_file_path_on_sharer = os.path.join(self.shared_folder, file_name)
        if not os.path.exists(encrypted_file_path_on_sharer):
            error_msg = json.dumps({'status': 'error', 'message': 'File not found on sender side.'})
            client_socket.send(error_msg.encode('utf-8'))
            print(f"{Fore.RED}Sharer: File '{file_name}' not found.{Style.RESET}")
            return

        all_metadata = self._load_file_metadata() # <<< THIS METHOD IS NOW MODIFIED
        if not all_metadata: # If metadata failed to load/decrypt
            error_msg = json.dumps({'status': 'error', 'message': 'Sharer could not load/decrypt file metadata.'})
            client_socket.send(error_msg.encode('utf-8'))
            print(f"{Fore.RED}Sharer: Could not load/decrypt metadata. Aborting share for '{file_name}'.{Style.RESET}")
            return

        file_meta = all_metadata.get(file_name)
        if not file_meta or 'key' not in file_meta or 'hash' not in file_meta:
            error_msg = json.dumps({'status': 'error', 'message': 'File metadata (key/hash) incomplete on sender side.'})
            client_socket.send(error_msg.encode('utf-8'))
            print(f"{Fore.RED}Sharer: Metadata for '{file_name}' incomplete or missing key/hash.{Style.RESET}")
            return

        symmetric_file_key_hex = file_meta['key']
        original_content_hash = file_meta['hash']
        
        try:
            symmetric_file_key_bytes = bytes.fromhex(symmetric_file_key_hex)
        except ValueError:
            error_msg = json.dumps({'status': 'error', 'message': 'Invalid symmetric key format in sharer metadata.'})
            client_socket.send(error_msg.encode('utf-8'))
            print(f"{Fore.RED}Sharer: Invalid symmetric key hex for '{file_name}'.{Style.RESET}")
            return

        try:
            rsa_encrypted_symmetric_key_bytes = crypto_utils.encrypt_with_rsa_public_key(
                symmetric_file_key_bytes,
                downloader_public_key_pem_bytes
            )
        except Exception as e:
            error_msg = json.dumps({'status': 'error', 'message': f'Sharer failed to RSA encrypt symmetric key: {e}'})
            client_socket.send(error_msg.encode('utf-8'))
            print(f"{Fore.RED}Sharer: Error RSA encrypting symmetric key for '{file_name}': {e}{Style.RESET}")
            return

        with open(encrypted_file_path_on_sharer, 'rb') as f:
            symmetrically_encrypted_content_to_send = f.read()
        symmetrically_encrypted_size = len(symmetrically_encrypted_content_to_send)

        response_payload = {
            'status': 'key_exchange_ok',
            'rsa_encrypted_symmetric_key_hex': rsa_encrypted_symmetric_key_bytes.hex(),
            'original_hash': original_content_hash,
            'symmetrically_encrypted_size': symmetrically_encrypted_size
        }
        client_socket.send(json.dumps(response_payload).encode('utf-8'))
        print(f"Sharer: Sent RSA-encrypted symmetric key for '{file_name}' to {address}. Waiting for ready signal...")

        client_socket.settimeout(20.0) 
        try:
            ready_signal = client_socket.recv(1024)
        except socket.timeout:
            print(f"{Fore.YELLOW}Sharer: Timeout waiting for 'ready_for_file_content' from {address} for '{file_name}'. Aborting.{Style.RESET}")
            return
        finally:
            client_socket.settimeout(None)

        if ready_signal != b'ready_for_file_content':
            print(f"{Fore.YELLOW}Sharer: Downloader not ready for '{file_name}' content (signal: {ready_signal!r}). Aborting.{Style.RESET}")
            return

        print(f"Sharer: Downloader {address} ready. Sending {symmetrically_encrypted_size} bytes of '{file_name}'...")
        try:
            client_socket.sendall(symmetrically_encrypted_content_to_send)
            print(f"{Fore.GREEN}Sharer: Sent (symmetrically) encrypted file '{file_name}' to {address} successfully.{Style.RESET}")
        except socket.error as e:
            print(f"{Fore.RED}Sharer: Socket error sending file content for '{file_name}' to {address}: {e}{Style.RESET}")

    def _load_file_metadata(self): # <<< MODIFIED FOR MEK DECRYPTION
        if not os.path.exists(self.FILE_METADATA_PATH):
            # print(f"Debug: Metadata file '{self.FILE_METADATA_PATH}' not found. Returning empty dict.")
            return {}

        try:
            with open(self.FILE_METADATA_PATH, 'rb') as f: 
                encrypted_or_plaintext_data = f.read()

            if not encrypted_or_plaintext_data:
                # print(f"Debug: Metadata file '{self.FILE_METADATA_PATH}' is empty. Returning empty dict.")
                return {}

            if not self.master_encryption_key:
                # print(f"Debug: MEK not available for metadata decryption.")
                # Attempt to load as plaintext (for backward compatibility or if MEK failed)
                try:
                    metadata_dict = json.loads(encrypted_or_plaintext_data.decode('utf-8'))
                    print(f"{Fore.YELLOW}Warning: Loaded metadata as plaintext. File should be re-saved while logged in to encrypt it.{Style.RESET}")
                    return metadata_dict
                except (UnicodeDecodeError, json.JSONDecodeError):
                    print(f"{Fore.RED}Error: Metadata file exists but MEK is not available for decryption, and it's not valid plaintext JSON.{Style.RESET}")
                    return {} 

            # MEK is available, attempt decryption
            # print(f"Debug: Attempting to decrypt metadata with MEK.")
            decrypted_json_bytes = crypto_utils.decrypt_data(encrypted_or_plaintext_data, self.master_encryption_key)
            metadata_dict = json.loads(decrypted_json_bytes.decode('utf-8'))
            # print(f"Debug: Metadata decrypted successfully.")
            return metadata_dict

        except ValueError as e: # Catches decrypt_data errors (bad key/padding) and json.JSONDecodeError from bad UTF-8
            if "Incorrect key or data corruption suspected" in str(e) or "unpack_from requires a buffer of at least" in str(e) or "PKCS7" in str(e).upper(): # More specific check for decryption/padding errors
                print(f"{Style.BOLD}{Fore.RED}Error decrypting metadata file '{self.FILE_METADATA_PATH}'.{Style.RESET}")
                print(f"{Fore.YELLOW}  Details: {e}{Style.RESET}")
                print(f"{Fore.YELLOW}  This may be due to an incorrect password (if MEK derived incorrectly), a corrupted file, or if it's an old plaintext file and MEK was expected.{Style.RESET}")
            else: # Other ValueErrors, e.g. from json.loads if decrypted content is not valid JSON
                print(f"{Style.BOLD}{Fore.RED}Error processing metadata file '{self.FILE_METADATA_PATH}': {e}{Style.RESET}")
            return {}
        except json.JSONDecodeError: # If decrypted content is not valid JSON
            print(f"{Fore.YELLOW}Warning: Metadata file '{self.FILE_METADATA_PATH}' content is corrupted (not valid JSON after potential decryption). Starting with empty metadata.{Style.RESET}")
            return {}
        except Exception as e:
            print(f"{Style.BOLD}{Fore.RED}An unexpected error occurred loading metadata file '{self.FILE_METADATA_PATH}': {type(e).__name__} - {e}{Style.RESET}")
            return {}


    def _save_file_metadata(self, metadata_dict: dict) -> bool: # <<< MODIFIED FOR MEK ENCRYPTION
        if not self.master_encryption_key:
            print(f"{Style.BOLD}{Fore.RED}Error saving metadata: Master Encryption Key not available (e.g., not logged in or MEK derivation failed). Metadata NOT saved.{Style.RESET}")
            return False 

        if not isinstance(metadata_dict, dict):
            print(f"{Style.BOLD}{Fore.RED}Error saving metadata: Input is not a dictionary.{Style.RESET}")
            return False

        try:
            metadata_json_bytes = json.dumps(metadata_dict, indent=2).encode('utf-8')
            encrypted_data = crypto_utils.encrypt_data(metadata_json_bytes, self.master_encryption_key)
            
            with open(self.FILE_METADATA_PATH, 'wb') as f: 
                f.write(encrypted_data)
            # print(f"{Fore.GREEN}Metadata saved and encrypted successfully to '{self.FILE_METADATA_PATH}'.{Style.RESET}") # Debug
            return True
        except IOError as e:
            print(f"{Style.BOLD}{Fore.RED}Error saving encrypted metadata to file '{self.FILE_METADATA_PATH}': {e}{Style.RESET}")
        except Exception as e:
            print(f"{Style.BOLD}{Fore.RED}An unexpected error occurred while saving encrypted metadata: {type(e).__name__} - {e}{Style.RESET}")
        return False

    def download_file(self, peer_id, file_name):
        # ... (no changes from your provided version regarding RSA key exchange)
        # This method uses _load_file_metadata() indirectly via _handle_secure_file_transfer_sharer on the other peer,
        # and its own file operations are for the downloaded file, not metadata.
        if not self.is_logged_in():
            print(f"{Style.BOLD}{Fore.RED}Please log in to download files.{Style.RESET}")
            return False

        if not self.rsa_private_key_pem or not self.rsa_public_key_pem: 
            print(f"{Style.BOLD}{Fore.RED}RSA keys not available. Cannot perform secure download.{Style.RESET}")
            return False

        if peer_id not in self.peers:
            print(f"{Fore.YELLOW}Peer {peer_id} not found. Try refreshing the peer list.{Style.RESET}")
            return False

        peer_info = self.peers[peer_id]
        peer_ip, peer_receive_port = peer_info['ip'], peer_info['receive_port']

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.send_port != 0:
                 sock.bind(('0.0.0.0', self.send_port))
            
            print(f"Downloader: Attempting to connect to peer {peer_id[:8]} at {peer_ip}:{peer_receive_port} for secure download of '{file_name}'...")
            sock.settimeout(10.0) 
            sock.connect((peer_ip, peer_receive_port))
            sock.settimeout(None) 
            print(f"Downloader: Connected. Initiating secure key exchange for '{file_name}'...")

            request_data = {
                'type': 'file_request_initiate_secure',
                'file_name': file_name,
                'downloader_public_key': self.rsa_public_key_pem.decode('utf-8') 
            }
            sock.send(json.dumps(request_data).encode('utf-8'))

            sock.settimeout(20.0) 
            key_exchange_response_raw = sock.recv(4096) 
            sock.settimeout(None)

            if not key_exchange_response_raw:
                print(f"{Fore.RED}Downloader: No response from peer during key exchange for '{file_name}'.{Style.RESET}")
                return False
            
            key_exchange_response = json.loads(key_exchange_response_raw.decode('utf-8'))

            if key_exchange_response.get('status') != 'key_exchange_ok':
                error_msg = key_exchange_response.get('message', 'Unknown error from sharer.')
                print(f"{Fore.RED}Downloader: Sharer error for '{file_name}': {error_msg}{Style.RESET}")
                return False

            rsa_enc_sym_key_hex = key_exchange_response['rsa_encrypted_symmetric_key_hex']
            original_hash = key_exchange_response['original_hash']
            s_enc_size = key_exchange_response['symmetrically_encrypted_size']
            
            print(f"Downloader: Received RSA-encrypted symmetric key for '{file_name}'. Decrypting...")
            decrypted_symmetric_file_key = crypto_utils.decrypt_with_rsa_private_key(
                bytes.fromhex(rsa_enc_sym_key_hex),
                self.rsa_private_key_pem 
            )
            print(f"{Fore.GREEN}Downloader: Symmetric key for '{file_name}' decrypted successfully.{Style.RESET}")

            sock.send(b'ready_for_file_content')
            print(f"Downloader: Signaled readiness for '{file_name}' content.")

            received_encrypted_chunks = []
            bytes_received = 0
            print(f"Downloader: Downloading (symmetrically) ENCRYPTED file '{file_name}' ({s_enc_size} bytes)...")
            
            sock.settimeout(30.0) 
            while bytes_received < s_enc_size:
                chunk_size = min(4096, s_enc_size - bytes_received)
                try:
                    chunk = sock.recv(chunk_size)
                except socket.timeout:
                    print(f"{Fore.RED}\nDownloader: Timeout receiving data for '{file_name}'. Received {bytes_received}/{s_enc_size}.{Style.RESET}")
                    return False 
                if not chunk:
                    print(f"{Fore.RED}\nDownloader: Connection lost during download of '{file_name}'. Received {bytes_received}/{s_enc_size}.{Style.RESET}")
                    return False
                received_encrypted_chunks.append(chunk)
                bytes_received += len(chunk)
                print(f"Download progress: {(bytes_received / s_enc_size) * 100:.1f}%", end='\r')
            sock.settimeout(None) 
            print("\nDownloader: (Symmetrically) ENCRYPTED download complete.                  ")

            full_s_enc_content = b''.join(received_encrypted_chunks)
            if len(full_s_enc_content) != s_enc_size:
                 print(f"{Fore.RED}Downloader: Downloaded encrypted size mismatch for '{file_name}'. Expected {s_enc_size}, got {len(full_s_enc_content)}{Style.RESET}")
                 return False

            print(f"Downloader: Decrypting content of '{file_name}'...")
            decrypted_content = crypto_utils.decrypt_file_content(full_s_enc_content, decrypted_symmetric_file_key)
            print("Downloader: File content decryption successful.")

            calc_hash = crypto_utils.hash_file_content(decrypted_content)
            if calc_hash == original_hash:
                print(f"{Fore.GREEN}Downloader: Integrity check PASSED for '{file_name}'.{Style.RESET}")
                dl_path = os.path.join(self.downloads_folder, file_name)
                with open(dl_path, 'wb') as f: f.write(decrypted_content)
                print(f"{Fore.GREEN}File '{file_name}' saved to '{dl_path}'.{Style.RESET}")
                return True
            else:
                print(f"{Style.BOLD}{Fore.RED}Downloader: CRITICAL - Integrity FAILED for '{file_name}'.{Style.RESET}")
                print(f"  Expected: {original_hash}\n  Calculated: {calc_hash}")
                return False

        except json.JSONDecodeError as e:
            print(f"{Fore.RED}Downloader: Invalid JSON from peer for '{file_name}': {e}{Style.RESET}")
            return False
        except ValueError as e: 
            print(f"{Fore.RED}Downloader: Data conversion error for '{file_name}': {e}{Style.RESET}")
            return False
        except InvalidTag: 
             print(f"{Style.BOLD}{Fore.RED}Downloader: Decryption failed for '{file_name}' - InvalidTag (data may be corrupt or key incorrect).{Style.RESET}")
             return False
        # except crypto_utils.rsa.pkcs1.DecryptionError: # This specific exception might not exist depending on cryptography version's RSA API
        #      print(f"{Style.BOLD}{Fore.RED}Downloader: RSA Decryption failed for symmetric key of '{file_name}'.{Style.RESET}")
        #      return False
        except socket.timeout:
            print(f"{Fore.RED}Downloader: Socket timeout during operation for '{file_name}'.{Style.RESET}")
            return False
        except ConnectionRefusedError:
            print(f"{Fore.RED}Downloader: Connection refused by peer {peer_id[:8]} for '{file_name}'.{Style.RESET}")
            return False
        except Exception as e: 
            print(f"{Style.BOLD}{Fore.RED}Downloader: Error downloading '{file_name}': {type(e).__name__} - {e}{Style.RESET}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            if sock: sock.close()

    def share_file(self, file_path): 
        # This method uses _load_file_metadata() and _save_file_metadata(), which ARE NOW CHANGED.
        if not self.is_logged_in():
            print(f"{Style.BOLD}{Fore.RED}Please log in to share files.{Style.RESET}")
            return False
        
        if not self.master_encryption_key:
            print(f"{Style.BOLD}{Fore.RED}Cannot share file: MEK not available. Please log in again.{Style.RESET}")
            return False

        if not os.path.exists(file_path):
            print(f"{Fore.RED}File {file_path} does not exist.{Style.RESET}")
            return False

        file_name = os.path.basename(file_path)
        dest_path = os.path.join(self.shared_folder, file_name) 

        try:
            with open(file_path, 'rb') as f:
                original_content = f.read()
            
            file_key = crypto_utils.generate_symmetric_key()
            encrypted_content = crypto_utils.encrypt_file_content(original_content, file_key)

            with open(dest_path, 'wb') as f:
                f.write(encrypted_content)
            print(f"{Fore.GREEN}File '{file_name}' encrypted and saved to shared folder '{dest_path}'.{Style.RESET}")
            
            original_hash = crypto_utils.hash_file_content(original_content)
            
            metadata = self._load_file_metadata() # Load potentially encrypted metadata
            if metadata is None: # Indicates a critical error during load
                print(f"{Style.BOLD}{Fore.RED}Failed to load existing metadata. Cannot share file.{Style.RESET}")
                # Clean up the just-encrypted file to avoid inconsistency
                if os.path.exists(dest_path): os.remove(dest_path)
                return False

            metadata[file_name] = {
                'hash': original_hash,    
                'key': file_key.hex() 
            }
            
            if not self._save_file_metadata(metadata): # Save (and encrypt) metadata
                print(f"{Style.BOLD}{Fore.RED}Failed to save updated metadata. File sharing might be inconsistent.{Style.RESET}")
                # Decide if we should roll back the file save to shared_folder
                # For now, we'll leave the encrypted file but warn about metadata save failure.
                # return False # Or allow sharing but with a warning
            else:
                print(f"Metadata (original hash and symmetric key) for '{file_name}' saved and encrypted.")

            self._scan_shared_folder() 
            return True

        except Exception as e:
            print(f"{Style.BOLD}{Fore.RED}Error sharing file '{file_name}': {type(e).__name__} - {e}{Style.RESET}")
            # Clean up partially shared file if an error occurs before metadata is saved
            if os.path.exists(dest_path) and ('metadata' not in locals() or not self._save_file_metadata(locals().get('metadata', {}))):
                 try: 
                     if os.path.exists(dest_path): os.remove(dest_path)
                 except Exception as e_remove:
                     print(f"{Fore.YELLOW}Warning: Could not remove partially shared file '{dest_path}': {e_remove}{Style.RESET}")
            return False

    def list_shared_files(self):
        # ... (no changes from your provided version)
        self._scan_shared_folder() 
        return self.shared_files

    def list_available_files(self):
        # ... (no changes from your provided version)
        self.get_peer_list() 
        all_files = {}

        for peer_id, peer_info in self.peers.items():
            if peer_id == self.client_id: 
                continue

            for file_info in peer_info.get('files', []):
                file_name = file_info['name']
                if file_name not in all_files:
                    all_files[file_name] = []
                
                all_files[file_name].append({
                    'peer_id': peer_id,
                    'size': file_info['size'] 
                })
        return all_files

    def get_peer_list(self): 
        # ... (no changes from your provided version)
        if not self.connected and self.running: 
            print(f"{Fore.YELLOW}Not connected to rendezvous. Attempting to re-register...{Style.RESET}")
            self._connect_to_rendezvous()
            if not self.connected:
                print(f"{Fore.RED}Still not connected to rendezvous. Cannot get peer list.{Style.RESET}")
                return {} 

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((self.rendezvous_host, self.rendezvous_port))
            sock.settimeout(None)

            request_data = {'command': 'get_peers'}
            sock.send(json.dumps(request_data).encode('utf-8'))

            response_raw = sock.recv(8192) 
            if not response_raw:
                print(f"{Fore.RED}Failed to retrieve peer list: No response from rendezvous.{Style.RESET}")
                return self.peers 

            response_data = json.loads(response_raw.decode('utf-8'))

            if response_data.get('status') == 'success':
                self.peers = response_data.get('peers', {})
                if self.client_id in self.peers:
                    del self.peers[self.client_id]
                print(f"Retrieved {len(self.peers)} other peers from rendezvous server.")
            else:
                print(f"{Fore.RED}Failed to retrieve peer list: {response_data.get('message')}{Style.RESET}")
            return self.peers
        except socket.timeout:
            print(f"{Fore.RED}Error retrieving peer list: Connection to rendezvous timed out.{Style.RESET}")
            return self.peers 
        except ConnectionRefusedError:
            print(f"{Fore.RED}Error retrieving peer list: Connection to rendezvous refused.{Style.RESET}")
            self.connected = False 
            return {}
        except Exception as e:
            print(f"{Fore.RED}Error retrieving peer list: {e}{Style.RESET}")
            return self.peers 
        finally:
            if sock: sock.close()

    def stop(self):
        # ... (no changes from your provided version)
        print(f"Stopping P2P client {self.client_id[:8]}...")
        self.running = False 

        if self.connected: 
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0) 
                sock.connect((self.rendezvous_host, self.rendezvous_port))
                unregister_data = {'command': 'unregister', 'client_id': self.client_id}
                sock.send(json.dumps(unregister_data).encode('utf-8'))
                print(f"Sent unregister request for {self.client_id[:8]}.")
            except Exception as e:
                print(f"{Fore.YELLOW}Could not unregister from rendezvous: {e}{Style.RESET}")
            finally:
                if sock: sock.close()
        
        self.connected = False 

        if self.listen_socket:
            print("Closing listen socket...")
            try:
                self.listen_socket.close()
                self.listen_socket = None
                print("Listen socket closed.")
            except Exception as e:
                print(f"{Fore.RED}Error closing listen socket: {e}{Style.RESET}")
        
        self._clear_mek_and_password() # Ensure MEK is cleared on stop
        print(f"P2P client {self.client_id[:8]} stopped.")


    def _load_users(self):
        # ... (no changes from your provided version)
        if not os.path.exists(USER_DB_PATH):
            return {}
        try:
            with open(USER_DB_PATH, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"{Fore.YELLOW}Warning: User registry '{USER_DB_PATH}' is corrupted. Returning empty registry.{Style.RESET}")
            return {}
        except Exception as e:
            print(f"{Fore.RED}Error loading user registry '{USER_DB_PATH}': {e}{Style.RESET}")
            return {}


    def _save_users(self, users):
        # ... (no changes from your provided version)
        try:
            with open(USER_DB_PATH, 'w') as f:
                json.dump(users, f, indent=2)
        except IOError as e:
            print(f"{Style.BOLD}{Fore.RED}Error saving user registry '{USER_DB_PATH}': {e}{Style.RESET}")


    def register(self):
        # ... (no changes from your provided version)
        users = self._load_users()
        username = input("Choose a username: ").strip()
        if not username:
            print(f"{Style.BOLD}{Fore.RED}Username cannot be empty.{Style.RESET}")
            return False
        if username in users:
            print(f"{Style.BOLD}{Fore.RED}Username already exists. Try Again.{Style.RESET}")
            return False

        password = input("Choose a password: ").strip()
        if not password: 
            print(f"{Style.BOLD}{Fore.RED}Password cannot be empty.{Style.RESET}")
            return False
        try:
            hashed_password_string = password_utils.hash_password(password)
            users[username] = {'hash': hashed_password_string} 
            self._save_users(users)
            print(f"{Style.BOLD}{Fore.GREEN}Registration successful with Argon2.{Style.RESET}")
            return True
        except Exception as e:
            print(f"{Style.BOLD}{Fore.RED}Error during registration: {e}{Style.RESET}")
            return False

    def login(self): # <<< MODIFIED FOR MEK DERIVATION & HANDLING
        if self.is_logged_in():
            print(f"{Fore.MAGENTA}Already logged in as '{self.logged_in_user}'. Please logout first.{Style.RESET}")
            return True 

        users = self._load_users()
        username = input("Username: ").strip()
        # Temporarily store password for MEK derivation if login is successful
        # This is sensitive; ensure it's cleared.
        self._current_password_for_mek = input("Password: ").strip() 

        if not username or not self._current_password_for_mek:
            print(f"{Style.BOLD}{Fore.RED}Username and password cannot be empty.{Style.RESET}")
            self._clear_mek_and_password()
            return False

        if username not in users:
            print(f"{Style.BOLD}{Fore.RED}User '{username}' not found.{Style.RESET}")
            self._clear_mek_and_password()
            return False

        user_data = users[username]
        stored_hash_str = user_data.get('hash')

        # Assuming all users now have Argon2 hashes due to clean user_registry.json start
        if not stored_hash_str or not stored_hash_str.startswith('$argon2'):
            print(f"{Style.BOLD}{Fore.RED}Error: User '{username}' has an invalid or missing password hash.{Style.RESET}")
            self._clear_mek_and_password()
            return False
        
        try:
            if password_utils.verify_password(self._current_password_for_mek, stored_hash_str):
                self.logged_in_user = username
                
                # Derive MEK immediately after successful password verification
                self._derive_and_set_mek(self._current_password_for_mek)
                
                print(f"{Style.BOLD}{Fore.GREEN}Logged in as {username} (Argon2 verified).{Style.RESET}")
                if not self.master_encryption_key:
                     print(f"{Style.BOLD}{Fore.YELLOW}Warning: MEK derivation failed post-login. Metadata operations will be affected.{Style.RESET}")
                else:
                    # Attempt to load metadata now that MEK is available
                    # This also serves as a check if the MEK (derived from current password) can decrypt existing metadata
                    print(f"Loading file metadata for user {username}...")
                    loaded_meta = self._load_file_metadata()
                    if not isinstance(loaded_meta, dict): # Check if load failed badly
                         print(f"{Style.BOLD}{Fore.YELLOW}Warning: Could not properly load file metadata after login.{Style.RESET}")
                    # else:
                         # print(f"Debug: Metadata loaded: {loaded_meta}")


                if password_utils.needs_rehash(stored_hash_str):
                    print(f"{Fore.YELLOW}Password hash for {username} uses outdated Argon2 parameters. Re-hashing...{Style.RESET}")
                    try:
                        new_hashed_password_string = password_utils.hash_password(self._current_password_for_mek)
                        users[username]['hash'] = new_hashed_password_string # Corrected: update existing user's hash
                        self._save_users(users)
                        print(f"{Fore.GREEN}Password hash updated to new Argon2 parameters.{Style.RESET}")
                    except Exception as e_rehash:
                        print(f"{Style.BOLD}{Fore.RED}Error re-hashing password during login: {e_rehash}{Style.RESET}")
                
                # Clear the temporarily stored password after all operations that need it are done
                # self._current_password_for_mek = None # Cleared by _clear_mek_and_password on logout/failure
                return True
            else:
                print(f"{Style.BOLD}{Fore.RED}Invalid password.{Style.RESET}")
                self._clear_mek_and_password() 
                return False
        except Exception as e: 
            print(f"{Style.BOLD}{Fore.RED}Error during login for {username}: {type(e).__name__} - {e}{Style.RESET}")
            self._clear_mek_and_password() 
            return False
        
    def is_logged_in(self):
        return self.logged_in_user is not None

    def logout(self): # <<< MODIFIED TO CLEAR MEK
        if self.is_logged_in():
            print(f"{Style.BOLD}{Fore.RED}User '{self.logged_in_user}' has been logged out.{Style.RESET}")
            self.logged_in_user = None
            self._clear_mek_and_password() # Crucial: Clear MEK and any temp password on logout
        else:
            print("No user is currently logged in.")

    def printSessionInfo(self):
        # ... (no changes from your provided version)
        if self.is_logged_in():
            print(f"{Style.BOLD}{Fore.MAGENTA}Currently logged in as: {self.logged_in_user}{Style.RESET}") 
        else:
            print("Not logged in.")