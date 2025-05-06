import json
import os
import socket
import threading
import time
import uuid

from utils import crypto_utils
from utils import password_utils

# FILE_HASHES_PATH = 'shared_files/file_hashes.json'
# FILE_METADATA_PATH = 'shared_files/file_metadata.json' # New metadata file

from colored import Fore, Style


USER_DB_PATH = "user_registry.json"

class P2PClient:
    def __init__(self, rendezvous_host='localhost', rendezvous_port=5050, receive_port=0, send_port=0, client_name=None):
        self.logged_in_user = None
        self.client_id = str(uuid.uuid4())
        self.client_name = client_name or self.client_id[:8]  
        self.rendezvous_host = rendezvous_host
        self.rendezvous_port = rendezvous_port
        self.receive_port = receive_port
        self.send_port = send_port
        
        
        self.shared_folder = os.environ.get('P2P_SHARED_FOLDER', 'shared_files')
        self.downloads_folder = os.environ.get('P2P_DOWNLOADS_FOLDER', 'downloads')

        self.FILE_METADATA_PATH = os.path.join(self.shared_folder, 'file_metadata.json')

        
        self.shared_files = []
        self.peers = {}
        self.listen_socket = None
        self.running = False
        self.connected = False
        
        
        os.makedirs(self.shared_folder, exist_ok=True)
        os.makedirs(self.downloads_folder, exist_ok=True)
        
        print(f"Client '{self.client_name}' initialized")
        print(f"Using shared folder: {self.shared_folder}")
        print(f"Using downloads folder: {self.downloads_folder}")
        print(f"Using metadata file: {self.FILE_METADATA_PATH}")

    def _load_file_metadata(self):
        if os.path.exists(self.FILE_METADATA_PATH):
            try:
                with open(self.FILE_METADATA_PATH, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                print(f"{Fore.YELLOW}Warning: Metadata file '{self.FILE_METADATA_PATH}' is corrupted. Starting with empty metadata.{Style.RESET}")
                return {}
        return {}

    def _save_file_metadata(self, metadata):
        try:
            with open(self.FILE_METADATA_PATH, 'w') as f:
                json.dump(metadata, f, indent=2)
        except IOError as e:
            print(f"{Style.BOLD}{Fore.RED}Error saving metadata file: {e}{Style.RESET}")


    def start(self):
        """Start the P2P client by setting up listening socket and connecting to rendezvous"""
        self.running = True
        self._setup_listen_socket()
        self._scan_shared_folder()
        self._connect_to_rendezvous()
        self._start_listener_thread()

    def _setup_listen_socket(self):
        """Setup the socket that listens for incoming connections from other peers"""
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        
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

    def _start_listener_thread(self):
        """Start a thread to listen for incoming connections"""
        listener_thread = threading.Thread(target=self._listen_for_connections)
        listener_thread.daemon = True
        listener_thread.start()

    def _listen_for_connections(self):
        """Listen for and handle incoming connections from other peers"""
        while self.running:
            try:
                client_socket, address = self.listen_socket.accept()
                client_handler = threading.Thread(target=self._handle_peer_connection, args=(client_socket,))
                client_handler.daemon = True
                client_handler.start()
            except Exception as e:
                if self.running:
                    print(f"{Style.BOLD}{Fore.red}Error accepting connection: {e}{Style.reset}")

    def _handle_peer_connection(self, client_socket):
        """Handle an incoming connection from another peer"""
        try:
            data = client_socket.recv(1024).decode('utf-8')
            request = json.loads(data)

            if request['type'] == 'file_request':
                file_name = request['file_name']
                self._send_file(client_socket, file_name)

        except Exception as e:
            print(f"Error handling peer connection: {e}")
        finally:
            client_socket.close()

    def _scan_shared_folder(self):
        """Scan the shared folder for files to share"""
        previous_count = len(self.shared_files)
        self.shared_files = []

        if os.path.exists(self.shared_folder):
            for file in os.listdir(self.shared_folder):
                file_path = os.path.join(self.shared_folder, file)
                if os.path.isfile(file_path):
                    file_size = os.path.getsize(file_path)
                    self.shared_files.append({
                        'name': file,
                        'size': file_size
                    })

        # Only print if the number of files changed
        if len(self.shared_files) != previous_count:
            print(f"Sharing {len(self.shared_files)} files")

    def _connect_to_rendezvous(self):
        """Connect to the rendezvous server and register this peer"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.rendezvous_host, self.rendezvous_port))

            
            register_data = {
                'command': 'register',
                'client_id': self.client_id,
                'receive_port': self.receive_port,
                'send_port': self.send_port,
                'files': self.shared_files
            }
            sock.send(json.dumps(register_data).encode('utf-8'))

            response = sock.recv(4096).decode('utf-8')
            response_data = json.loads(response)

            if response_data.get('status') == 'success':
                print(f"Successfully registered with rendezvous server as {self.client_id}")
                self.connected = True
            else:
                print(f"Failed to register with rendezvous server: {response_data.get('message')}")

            sock.close()

            
            update_thread = threading.Thread(target=self._update_rendezvous_periodically)
            update_thread.daemon = True
            update_thread.start()

        except Exception as e:
            print(f"Failed to connect to rendezvous server: {e}")

    def _update_rendezvous_periodically(self):
        """Periodically update the rendezvous server with our status and file list"""
        while self.running and self.connected:
            try:
                self._scan_shared_folder()
                time.sleep(30)

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.rendezvous_host, self.rendezvous_port))

                update_data = {
                    'command': 'update_files',
                    'client_id': self.client_id,
                    'files': self.shared_files
                }
                sock.send(json.dumps(update_data).encode('utf-8'))
                sock.close()

            except Exception as e:
                print(f"Failed to update rendezvous server: {e}")
                self.connected = False
                break

    def get_peer_list(self):
        """Get the list of peers from the rendezvous server"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.rendezvous_host, self.rendezvous_port))

            request_data = {
                'command': 'get_peers'
            }
            sock.send(json.dumps(request_data).encode('utf-8'))

            response = sock.recv(8192).decode('utf-8')
            response_data = json.loads(response)

            if response_data.get('status') == 'success':
                self.peers = response_data.get('peers', {})
                print(f"Retrieved {len(self.peers)} peers from rendezvous server")
            else:
                print("Failed to retrieve peer list")

            sock.close()
            return self.peers
        except Exception as e:
            print(f"Error retrieving peer list: {e}")
            return {}


    def download_file(self, peer_id, file_name):
        if not self.is_logged_in():
            print(f"{Style.BOLD}{Fore.RED}Please log in to download files.{Style.RESET}")
            return False

        if peer_id not in self.peers:
            print(f"{Fore.YELLOW}Peer {peer_id} not found. Try refreshing the peer list.{Style.RESET}")
            return False

        peer_info = self.peers[peer_id]
        peer_ip = peer_info['ip']
        peer_receive_port = peer_info['receive_port'] # This is the port the other peer is listening on

        sock = None # Initialize sock to None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Bind to the client's specific sending port if it's set and not 0. OS assigns otherwise.
            if self.send_port != 0:
                 sock.bind(('0.0.0.0', self.send_port)) # Use configured send_port
            sock.connect((peer_ip, peer_receive_port))

            # Request the file
            request_data = {'type': 'file_request', 'file_name': file_name}
            sock.send(json.dumps(request_data).encode('utf-8'))
            print(f"Requesting '{file_name}' from peer {peer_id[:8]}...")

            # 1. Receive metadata: encrypted_size, original_file_hash, file_key_hex
            meta_response_raw = sock.recv(2048) # Increased buffer for metadata
            if not meta_response_raw:
                print(f"{Fore.RED}Error: No metadata received from peer.{Style.RESET}")
                if sock: sock.close()
                return False
            
            try:
                meta_payload_from_sender = json.loads(meta_response_raw.decode('utf-8'))
            except json.JSONDecodeError:
                print(f"{Fore.RED}Error: Received invalid JSON metadata from peer: {meta_response_raw.decode('utf-8', errors='ignore')}{Style.RESET}")
                if sock: sock.close()
                return False

            if 'error' in meta_payload_from_sender:
                print(f"{Fore.RED}Error from sending peer: {meta_payload_from_sender['error']}{Style.RESET}")
                if sock: sock.close()
                return False

            encrypted_size = meta_payload_from_sender.get('size')
            original_hash_from_sender = meta_payload_from_sender.get('hash')
            file_key_hex_from_sender = meta_payload_from_sender.get('key')

            if not all([isinstance(encrypted_size, int), original_hash_from_sender, file_key_hex_from_sender]):
                print(f"{Fore.RED}Error: Incomplete or malformed metadata received: {meta_payload_from_sender}{Style.RESET}")
                if sock: sock.close()
                return False
            
            print(f"Received metadata: Enc_size={encrypted_size}, Orig_hash={original_hash_from_sender[:8]}..., Key_hex={file_key_hex_from_sender[:8]}...")

            # 2. Decode the file_key from hex
            try:
                file_key_for_decryption = bytes.fromhex(file_key_hex_from_sender)
            except ValueError:
                print(f"{Fore.RED}Error: Invalid key format received (not hex).{Style.RESET}")
                if sock: sock.close()
                return False

            # 3. Send 'ready' signal to sender
            sock.send(b'ready')

            # 4. Receive the ENCRYPTED file content
            received_encrypted_chunks = []
            bytes_received = 0
            print(f"Downloading ENCRYPTED file '{file_name}' ({encrypted_size} bytes)...")
            while bytes_received < encrypted_size:
                chunk_size_to_receive = min(4096, encrypted_size - bytes_received)
                chunk = sock.recv(chunk_size_to_receive)
                if not chunk:
                    print(f"{Fore.RED}\nError: Connection lost prematurely during download of '{file_name}'. Received {bytes_received}/{encrypted_size} bytes.{Style.RESET}")
                    if sock: sock.close()
                    return False
                received_encrypted_chunks.append(chunk)
                bytes_received += len(chunk)
                progress = (bytes_received / encrypted_size) * 100
                print(f"Download progress: {progress:.1f}%", end='\r')
            print("\nENCRYPTED download complete.                                  ") # Spaces to clear progress

            full_encrypted_content = b''.join(received_encrypted_chunks)
            if len(full_encrypted_content) != encrypted_size:
                 print(f"{Fore.RED}Error: Downloaded encrypted size mismatch. Expected {encrypted_size}, got {len(full_encrypted_content)}{Style.RESET}")
                 if sock: sock.close()
                 return False

            # 5. Decrypt the received content
            print(f"Decrypting '{file_name}'...")
            try:
                decrypted_content = crypto_utils.decrypt_file_content(full_encrypted_content, file_key_for_decryption)
            except Exception as e: 
                print(f"{Style.BOLD}{Fore.RED}Error decrypting file '{file_name}': {e}{Style.RESET}")
                print(f"  Key used (first 8 bytes hex): {file_key_for_decryption[:8].hex()}")
                print(f"  IV (first 16 bytes of encrypted data hex): {full_encrypted_content[:16].hex()}")
                if sock: sock.close()
                return False
            print("Decryption successful.")

            # 6. Calculate the hash of the (now decrypted) content
            calculated_hash_of_decrypted_file = crypto_utils.hash_file_content(decrypted_content)
            print(f"Calculated hash of decrypted content: {calculated_hash_of_decrypted_file[:8]}...")

            # 7. Compare hashes for integrity
            if calculated_hash_of_decrypted_file == original_hash_from_sender:
                print(f"{Fore.GREEN}Integrity check PASSED for '{file_name}'.{Style.RESET}")
                
                download_path = os.path.join(self.downloads_folder, file_name)
                with open(download_path, 'wb') as f:
                    f.write(decrypted_content)
                print(f"{Fore.GREEN}File '{file_name}' saved successfully to '{download_path}'.{Style.RESET}")
                return True
            else:
                print(f"{Style.BOLD}{Fore.RED}CRITICAL: Integrity check FAILED for '{file_name}'.{Style.RESET}")
                print(f"  Expected hash from sender: {original_hash_from_sender}")
                print(f"  Calculated hash of download: {calculated_hash_of_decrypted_file}")
                print(f"{Fore.YELLOW}The downloaded file is corrupted or has been tampered with. Discarding.{Style.RESET}")
                return False

        except socket.timeout:
            print(f"{Fore.RED}Error: Connection to peer {peer_id[:8]} timed out.{Style.RESET}")
            return False
        except ConnectionRefusedError:
            print(f"{Fore.RED}Error: Connection to peer {peer_id[:8]} ({peer_ip}:{peer_receive_port}) was refused.{Style.RESET}")
            return False
        except Exception as e:
            print(f"{Style.BOLD}{Fore.RED}An unexpected error occurred while downloading '{file_name}': {e}{Style.RESET}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            if sock:
                sock.close()
    def share_file(self, file_path):
        if not self.is_logged_in():
            print(f"{Style.BOLD}{Fore.RED}Please log in to share files.{Style.RESET}")
            return False

        if not os.path.exists(file_path):
            print(f"{Fore.RED}File {file_path} does not exist.{Style.RESET}")
            return False

        file_name = os.path.basename(file_path)
        # This dest_path will store the ENCRYPTED file
        dest_path = os.path.join(self.shared_folder, file_name)

        try:
            with open(file_path, 'rb') as f:
                original_content = f.read()

            # 1. Generate a unique symmetric key for this file
            file_key = crypto_utils.generate_symmetric_key() # From your crypto_utils

            # 2. Encrypt the file content with this unique key
            encrypted_content = crypto_utils.encrypt_file_content(original_content, file_key)

            # 3. Store the encrypted content in the shared_folder
            with open(dest_path, 'wb') as f:
                f.write(encrypted_content)
            print(f"{Fore.GREEN}File '{file_name}' encrypted and saved to shared folder.{Style.RESET}")

            # 4. Calculate the hash of the original, unencrypted file content
            original_hash = crypto_utils.hash_file_content(original_content)

            # 5. Store file_hash and file_key (hex-encoded) in metadata
            metadata = self._load_file_metadata()
            metadata[file_name] = {
                'hash': original_hash,    # Hash of the original content
                'key': file_key.hex()     # Symmetric key for this file, hex-encoded
            }
            self._save_file_metadata(metadata)
            print(f"Metadata (hash and key) for '{file_name}' saved.")

            self._scan_shared_folder() # This updates self.shared_files (name, ENCRYPTED_size)
            # You might want to trigger an update to the rendezvous server here if it's not periodic
            # self._connect_to_rendezvous() # Or a more specific update function

            return True

        except Exception as e:
            print(f"{Style.BOLD}{Fore.RED}Error sharing file '{file_name}': {e}{Style.RESET}")
            # Consider cleanup if error occurs mid-process
            if os.path.exists(dest_path) and 'encrypted_content' not in locals():
                 # If dest_path was created but encryption failed before writing
                 try: os.remove(dest_path)
                 except: pass
            return False

    def list_shared_files(self):
        """List all files currently being shared"""
        self._scan_shared_folder()
        return self.shared_files

    def list_available_files(self):
        """List all files available for download from peers"""
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

    def stop(self):
        """Stop the P2P client and clean up"""
        self.running = False

        if self.connected:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.rendezvous_host, self.rendezvous_port))

                unregister_data = {
                    'command': 'unregister',
                    'client_id': self.client_id
                }
                sock.send(json.dumps(unregister_data).encode('utf-8'))
                sock.close()
            except:
                pass

        if self.listen_socket:
            self.listen_socket.close()

        print("P2P client stopped")

    def _load_users(self):
        if not os.path.exists(USER_DB_PATH):
            return {}
        with open(USER_DB_PATH, 'r') as f:
            return json.load(f)

    def _save_users(self, users):
        with open(USER_DB_PATH, 'w') as f:
            json.dump(users, f, indent=2)

    def register(self):
        users = self._load_users()
        username = input("Choose a username: ").strip()
        if username in users:
            print(f"{Style.BOLD}{Fore.red}Username already exists. Try Again.{Style.reset}")
            return False

        password = input("Choose a password: ").strip()
        hashed, salt = password_utils.hash_password(password)
        users[username] = {'hash': hashed, 'salt': salt}
        self._save_users(users)
        print(f"{Style.BOLD}{Fore.green}Registration successful.{Style.reset}")
        return True

    def login(self):
        if self.is_logged_in():
            print(f"{Fore.magenta}Already logged in as '{self.logged_in_user}'. Please logout first.{Style.reset}")
            return False

        users = self._load_users()
        username = input("Username: ").strip()
        password = input("Password: ").strip()

        if username not in users:
            print("User not found.")
            return False

        stored_hash = users[username]['hash']
        stored_salt = users[username]['salt']
        if password_utils.verify_password(password, stored_hash, stored_salt):
            self.logged_in_user = username
            print(f"{Style.BOLD}{Fore.green}Logged in as {username}{Style.reset}")
            return True
        else:
            print(f"{Style.BOLD}{Fore.red}Invalid password.{Style.reset}")
            return False
        
    def is_logged_in(self):
        return self.logged_in_user is not None

    def logout(self):
        if self.is_logged_in():
            print(f"{Style.BOLD}{Fore.red}User '{self.logged_in_user}' has been logged out.{Style.reset}")
            self.logged_in_user = None
        else:
            print("No user is currently logged in.")

    def printSessionInfo(self):
        if self.is_logged_in():
            print(f"{Style.BOLD}{Fore.magenta}Currently logged in as: {self.logged_in_user}{Style.reset}")
        else:
            print("Not logged in.")


    def _send_file(self, client_socket, file_name):
        try:
            encrypted_file_path = os.path.join(self.shared_folder, file_name)

            if not os.path.exists(encrypted_file_path):
                error_msg = json.dumps({'error': 'File not found on sender side.'}).encode('utf-8')
                client_socket.send(error_msg)
                print(f"{Fore.RED}Error: Requested file '{file_name}' not found in shared folder for sending.{Style.RESET}")
                return

            # 1. Lookup file_name in file_metadata.json to get its original hash and file_key
            all_metadata = self._load_file_metadata()
            file_meta = all_metadata.get(file_name)

            if not file_meta:
                error_msg = json.dumps({'error': 'File metadata not found on sender side.'}).encode('utf-8')
                client_socket.send(error_msg)
                print(f"{Fore.RED}Error: Metadata for '{file_name}' not found.{Style.RESET}")
                return

            original_content_hash = file_meta['hash']
            file_key_hex = file_meta['key'] # This is the hex-encoded symmetric key

            # 2. Read the already ENCRYPTED content from shared_folder
            with open(encrypted_file_path, 'rb') as f:
                encrypted_content_to_send = f.read()

            encrypted_size = len(encrypted_content_to_send)

            # 3. Protocol Change: Send metadata first
            # (encrypted_size, original_content_hash, file_key_hex)
            meta_payload_for_download = {
                'size': encrypted_size,              # Size of the ENCRYPTED file
                'hash': original_content_hash,       # Hash of the ORIGINAL, unencrypted file
                'key': file_key_hex                  # Hex-encoded symmetric key for this file
            }
            client_socket.send(json.dumps(meta_payload_for_download).encode('utf-8'))
            print(f"Sent metadata for '{file_name}': enc_size={encrypted_size}, orig_hash={original_content_hash[:8]}..., key={file_key_hex[:8]}...")

            # Wait for 'ready' signal from the downloader
            ready_signal = client_socket.recv(1024)
            if ready_signal != b'ready':
                print(f"{Fore.YELLOW}Downloader not ready for '{file_name}'. Aborting send.{Style.RESET}")
                return

            # 4. Send the ENCRYPTED file content in chunks
            bytes_sent = 0
            buffer_size = 4096
            while bytes_sent < encrypted_size:
                chunk = encrypted_content_to_send[bytes_sent : bytes_sent + buffer_size]
                client_socket.send(chunk)
                bytes_sent += len(chunk)
            
            print(f"{Fore.GREEN}Sent ENCRYPTED file '{file_name}' ({encrypted_size} bytes) successfully.{Style.RESET}")

        except ConnectionResetError:
            print(f"{Fore.RED}Connection reset by peer while sending '{file_name}'.{Style.RESET}")
        except BrokenPipeError:
            print(f"{Fore.RED}Broken pipe while sending '{file_name}'. Peer may have disconnected.{Style.RESET}")
        except Exception as e:
            print(f"{Style.BOLD}{Fore.RED}Error sending file '{file_name}': {e}{Style.RESET}")
            # Attempt to inform the client if possible
            try:
                error_msg = json.dumps({'error': f'Server error during send: {str(e)}'}).encode('utf-8')
                client_socket.send(error_msg)
            except:
                pass # Socket might already be closed