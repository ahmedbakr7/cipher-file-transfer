import json
import os
import socket
import threading
import time
import uuid

from utils import crypto_utils
from utils import password_utils

FILE_HASHES_PATH = 'shared_files/file_hashes.json'
from colored import Fore, Style

USER_DB_PATH = "user_registry.json"

class P2PClient:
    def __init__(self, rendezvous_host='localhost', rendezvous_port=5000, receive_port=0, send_port=0, client_name=None):
        self.logged_in_user = None
        self.client_id = str(uuid.uuid4())
        self.client_name = client_name or self.client_id[:8]  
        self.rendezvous_host = rendezvous_host
        self.rendezvous_port = rendezvous_port
        self.receive_port = receive_port
        self.send_port = send_port
        
        
        self.shared_folder = os.environ.get('P2P_SHARED_FOLDER', 'shared_files')
        self.downloads_folder = os.environ.get('P2P_DOWNLOADS_FOLDER', 'downloads')
        
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

        if peer_id not in self.peers:
            print(f"Peer {peer_id} not found. Try refreshing the peer list.")
            return False

        peer_info = self.peers[peer_id]
        peer_ip = peer_info['ip']
        peer_receive_port = peer_info['receive_port']  

        try:
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('0.0.0.0', self.send_port))
            sock.connect((peer_ip, peer_receive_port))

            
            request_data = {
                'type': 'file_request',
                'file_name': file_name
            }
            sock.send(json.dumps(request_data).encode('utf-8'))

            
            size_data = sock.recv(1024).decode('utf-8')
            size_info = json.loads(size_data)

            if 'error' in size_info:
                print(f"Error from peer: {size_info['error']}")
                sock.close()
                return False

            file_size = size_info['size']
            print(f"Downloading {file_name} ({file_size} bytes)")

            
            sock.send(b'ready')

            
            download_path = os.path.join(self.downloads_folder, file_name)

            with open(download_path, 'wb') as f:
                bytes_received = 0

                while bytes_received < file_size:
                    chunk = sock.recv(min(4096, file_size - bytes_received))
                    if not chunk:
                        break
                    f.write(chunk)
                    bytes_received += len(chunk)

                    
                    progress = (bytes_received / file_size) * 100
                    print(f"Download progress: {progress:.1f}%", end='\r')

                print()  

            print(f"File downloaded successfully to {download_path}")
            sock.close()
            return True

        except Exception as e:
            print(f"Error downloading file: {e}")
            return False

    def share_file(self, file_path):
        """Encrypt a file and move it to the shared folder"""

        if not os.path.exists(file_path):
            print(f"File {file_path} does not exist.")
            return False

        file_name = os.path.basename(file_path)
        dest_path = os.path.join(self.shared_folder, file_name)

        try:
            # Read original content
            with open(file_path, 'rb') as f:
                original_content = f.read()

            # Encrypt
            symmetric_key = b'SECRET_KEY_MUST_BE_32BYTES_LONG!!'[:32]
            encrypted_content = crypto_utils.encrypt_file_content(original_content, symmetric_key)

            # Save to shared folder
            with open(dest_path, 'wb') as f:
                f.write(encrypted_content)

            # Save hash
            file_hash = crypto_utils.hash_file_content(original_content)
            if os.path.exists(FILE_HASHES_PATH):
                with open(FILE_HASHES_PATH, 'r') as fh:
                    hashes = json.load(fh)
            else:
                hashes = {}
            hashes[file_name] = file_hash
            with open(FILE_HASHES_PATH, 'w') as fh:
                json.dump(hashes, fh)

            print(f"Encrypted and shared file: {file_name}")
            self._scan_shared_folder()
            return True

        except Exception as e:
            print(f"Error sharing file: {e}")
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
        """Send an encrypted file to the requesting peer after verifying integrity"""
        try:
            file_path = os.path.join(self.shared_folder, file_name)
            symmetric_key = b'SECRET_KEY_MUST_BE_32BYTES_LONG!!'[:32]

            if not os.path.exists(file_path):
                error_msg = json.dumps({'error': 'File not found'}).encode('utf-8')
                client_socket.send(error_msg)
                return

            with open(file_path, 'rb') as f:
                encrypted_content = f.read()
                file_data = crypto_utils.decrypt_file_content(encrypted_content, symmetric_key)

            decrypted_hash = crypto_utils.hash_file_content(file_data)
            with open(FILE_HASHES_PATH, 'r') as fh:
                hashes = json.load(fh)
            expected_hash = hashes.get(file_name)

            if decrypted_hash != expected_hash:
                print(f"[!] Integrity check failed for {file_name}")
                error_msg = json.dumps({'error': 'File integrity verification failed'}).encode('utf-8')
                client_socket.send(error_msg)
                return

            # Send size first
            file_size = len(file_data)
            size_info = json.dumps({'size': file_size}).encode('utf-8')
            client_socket.send(size_info)

            # Wait for peer to be ready
            ready = client_socket.recv(1024)
            if ready != b'ready':
                return

            # Send file in chunks
            bytes_sent = 0
            while bytes_sent < file_size:
                chunk = file_data[bytes_sent:bytes_sent+4096]
                client_socket.send(chunk)
                bytes_sent += len(chunk)

            print(f"Sent file {file_name} ({file_size} bytes)")

        except Exception as e:
            print(f"Error sending file {file_name}: {e}")
