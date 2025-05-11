import json
import os
import socket
import threading
import time
import uuid

from utils import crypto_utils, password_utils
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidTag 

from colored import Fore, Style

USER_DB_PATH = "user_registry.json"
DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MB

class P2PClient:
    def __init__(self, rendezvous_host='localhost', rendezvous_port=5050, receive_port=0, send_port=0, client_name=None, chunk_size=DEFAULT_CHUNK_SIZE):
        self.logged_in_user = None
        self._current_password_for_mek: str = None 
        self.master_encryption_key: bytes = None 
        self.running = True # Assume runnable; set to False on critical init errors
        
        self.client_id = str(uuid.uuid4())
        safe_client_name_suffix = "".join(c if c.isalnum() else "_" for c in (client_name or self.client_id[:8]))
        self.client_name = client_name or self.client_id[:8]

        self.rendezvous_host = rendezvous_host
        self.rendezvous_port = rendezvous_port
        self.receive_port = receive_port
        self.send_port = send_port
        self.chunk_size = chunk_size
        
        self.client_data_dir = f"client_data_{safe_client_name_suffix}"
        self.shared_folder_path = os.environ.get('P2P_SHARED_FOLDER', f'shared_files_{safe_client_name_suffix}')
        self.downloads_folder_path = os.environ.get('P2P_DOWNLOADS_FOLDER', f'downloads_{safe_client_name_suffix}')

        try:
            os.makedirs(self.client_data_dir, exist_ok=True)
            os.makedirs(self.shared_folder_path, exist_ok=True)
            os.makedirs(self.downloads_folder_path, exist_ok=True)
        except OSError as e:
            print(f"{Style.BOLD}{Fore.RED}Fatal Error: Could not create required directory '{e.filename}': {e.strerror}{Style.RESET}")
            self.running = False # Critical failure, client cannot operate

        self.rsa_private_key_path = os.path.join(self.client_data_dir, "private_key.pem")
        self.rsa_public_key_path = os.path.join(self.client_data_dir, "public_key.pem")
        self.rsa_private_key_pem: bytes = None
        self.rsa_public_key_pem: bytes = None

        self.metadata_salt_path = os.path.join(self.client_data_dir, "metadata.salt")
        self.metadata_encryption_salt: bytes = None

        self.FILE_METADATA_PATH = os.path.join(self.shared_folder_path, 'file_metadata.json')

        self.shared_files = []  # List of dicts {'name': str, 'size': int}
        self.peers = {}         # Dict of peer_id -> peer_info
        
        # Threading Locks
        self.shared_files_lock = threading.Lock()
        self.peers_lock = threading.Lock()
        self.mek_lock = threading.RLock() # Protects MEK and _current_password_for_mek

        self.listen_socket: socket.socket = None
        self.connected_to_rendezvous = False

        print(f"Client '{self.client_name}' initialized (ID: {self.client_id[:8]})")
        print(f"Data directory: {self.client_data_dir}")
        print(f"Shared folder: {self.shared_folder_path}")
        print(f"Downloads folder: {self.downloads_folder_path}")
        print(f"Metadata file: {self.FILE_METADATA_PATH}")
        print(f"Chunk size for transfers: {self.chunk_size / (1024*1024):.2f} MB")
        
        if self.running: # Only proceed if basic directory setup was okay
            self._load_or_generate_metadata_salt()
        else:
            # Ensure salt is None if running is false from the start
            self.metadata_encryption_salt = None
            print(f"{Style.BOLD}{Fore.RED}Client initialization failed. Halting further setup.{Style.RESET}")


    def _load_or_generate_metadata_salt(self):
        """Loads the salt for metadata encryption or generates a new one. Sets self.running=False on critical failure."""
        if not self.running:  # Should have been caught by __init__ if dir creation failed
            self.metadata_encryption_salt = None
            return

        try:
            if os.path.exists(self.metadata_salt_path):
                with open(self.metadata_salt_path, "rb") as f:
                    self.metadata_encryption_salt = f.read()
                if not self.metadata_encryption_salt or len(self.metadata_encryption_salt) < 8: # Argon2 salt min 8 bytes
                    print(f"{Fore.YELLOW}Warning: Metadata salt file '{self.metadata_salt_path}' empty or too short. Regenerating.{Style.RESET}")
                    self.metadata_encryption_salt = None # Force regeneration
            
            if not self.metadata_encryption_salt: # If not loaded or needs regeneration
                print(f"{Fore.YELLOW}Metadata salt not found or invalid, generating new one...{Style.RESET}")
                self.metadata_encryption_salt = crypto_utils.generate_salt(16) # 16-byte salt is good
                with open(self.metadata_salt_path, "wb") as f:
                    f.write(self.metadata_encryption_salt)
                print(f"{Fore.GREEN}New metadata salt generated and saved to '{self.metadata_salt_path}'.{Style.RESET}")
            else:
                print(f"{Fore.GREEN}Metadata salt loaded successfully.{Style.RESET}")

        except (IOError, OSError) as e:
            print(f"{Style.BOLD}{Fore.RED}Fatal Error: File operation for metadata salt failed at '{self.metadata_salt_path}': {e.strerror}{Style.RESET}")
            self.metadata_encryption_salt = None 
            self.running = False # This is critical for metadata security
        except Exception as e: # Catch any other unexpected error
            print(f"{Style.BOLD}{Fore.RED}Unexpected fatal error during metadata salt handling: {type(e).__name__} - {e}{Style.RESET}")
            self.metadata_encryption_salt = None
            self.running = False
            
    def _derive_and_set_mek(self, password: str):
        """Derives and sets the Master Encryption Key from the password using Argon2."""
        # This method is called after password input, so password should be non-empty.
        # The salt availability is critical.
        if not self.metadata_encryption_salt:
            print(f"{Style.BOLD}{Fore.RED}Critical Error: Cannot derive MEK - metadata encryption salt unavailable.{Style.RESET}")
            with self.mek_lock:
                self.master_encryption_key = None
            return # MEK cannot be derived
        
        with self.mek_lock: # Protects self.master_encryption_key
            try:
                self.master_encryption_key = password_utils.derive_key_with_argon2(
                    password=password, # Password should be validated as non-empty by login()
                    salt=self.metadata_encryption_salt,
                    key_length=crypto_utils.AES_KEY_SIZE 
                )
                # print(f"{Fore.GREEN}Master Encryption Key derived successfully.{Style.RESET}") # Debug
            except (ValueError, TypeError) as e: # Specific errors from KDF
                 print(f"{Style.BOLD}{Fore.RED}MEK Derivation Error ({type(e).__name__}): {e}{Style.RESET}")
                 self.master_encryption_key = None # Ensure it's None on failure
            except Exception as e: # Catch-all for other Argon2 internal errors
                print(f"{Style.BOLD}{Fore.RED}Unexpected error deriving Master Encryption Key with Argon2: {type(e).__name__} - {e}{Style.RESET}")
                self.master_encryption_key = None


    def _clear_mek_and_password(self):
        """Clears the MEK and the temporarily stored password. Thread-safe."""
        with self.mek_lock: # Ensure thread-safe modification
            self.master_encryption_key = None
            # _current_password_for_mek is also protected by mek_lock implicitly by being in this method
            if hasattr(self, '_current_password_for_mek'): 
                self._current_password_for_mek = None
        # print(f"{Fore.YELLOW}MEK and temporary password cleared.{Style.RESET}") # Optional debug

    def _load_or_generate_rsa_keys(self):
        """
        Loads RSA keys if they exist, otherwise generates and saves them.
        Sets self.running=False on critical failure.
        """
        if not self.running: # If client is already marked as not running from __init__
            return

        try:
            if os.path.exists(self.rsa_private_key_path) and \
               os.path.exists(self.rsa_public_key_path):
                # Ensure files are not empty before reading
                if os.path.getsize(self.rsa_private_key_path) > 0 and \
                   os.path.getsize(self.rsa_public_key_path) > 0:
                    with open(self.rsa_private_key_path, "rb") as f_priv, \
                         open(self.rsa_public_key_path, "rb") as f_pub:
                        self.rsa_private_key_pem = f_priv.read()
                        self.rsa_public_key_pem = f_pub.read()
                    # Basic validation of loaded PEMs (optional, but good)
                    if not self.rsa_private_key_pem or not self.rsa_public_key_pem:
                        print(f"{Fore.YELLOW}Warning: RSA key files were empty. Regenerating.{Style.RESET}")
                        # Fall through to generation logic by ensuring one is None
                        self.rsa_private_key_pem = None 
                    else:
                        print(f"{Fore.GREEN}RSA keys loaded successfully for {self.client_name}.{Style.RESET}")
                else:
                    print(f"{Fore.YELLOW}Warning: One or both RSA key files are empty. Regenerating.{Style.RESET}")
                    self.rsa_private_key_pem = None # Force regeneration
            
            if not self.rsa_private_key_pem or not self.rsa_public_key_pem: # If not loaded or files were empty
                print(f"{Fore.YELLOW}RSA keys not found or invalid, generating new ones...{Style.RESET}")
                # Ensure crypto_utils.generate_rsa_key_pair() handles its own exceptions or this try-except catches them
                private_pem_bytes, public_pem_bytes = crypto_utils.generate_rsa_key_pair()
                with open(self.rsa_private_key_path, "wb") as f_priv, \
                     open(self.rsa_public_key_path, "wb") as f_pub:
                    f_priv.write(private_pem_bytes)
                    f_pub.write(public_pem_bytes)
                self.rsa_private_key_pem = private_pem_bytes
                self.rsa_public_key_pem = public_pem_bytes
                print(f"{Fore.GREEN}New RSA keys generated and saved for {self.client_name}.{Style.RESET}")

        except (IOError, OSError) as e:
            print(f"{Style.BOLD}{Fore.RED}Fatal Error: File operation failed during RSA key load/save at '{e.filename}': {e.strerror}{Style.RESET}")
            self.running = False # Critical failure
        except Exception as e: # Catch other errors, e.g., from crypto_utils.generate_rsa_key_pair
            print(f"{Style.BOLD}{Fore.RED}Fatal Error: Could not load/generate RSA keys: {type(e).__name__} - {e}{Style.RESET}")
            self.running = False # Critical failure

    def start(self):
        """Initializes and starts all client services: listening socket, RSA keys, metadata salt, and connects to rendezvous."""
        if not self.running:
            print(f"{Style.BOLD}{Fore.RED}Client initialization failed (e.g. directory creation). Cannot start.{Style.RESET}")
            return

        # _load_or_generate_metadata_salt() is called in __init__ and sets self.running
        if not self.running or not self.metadata_encryption_salt:
            print(f"{Style.BOLD}{Fore.RED}Client metadata salt setup failed or salt unavailable. Cannot start securely.{Style.RESET}")
            # No socket to close yet if this fails early
            return

        self._setup_listen_socket() 
        if not self.running or not self.listen_socket: # Check both self.running and actual socket object
            print(f"{Style.BOLD}{Fore.RED}Client socket setup failed. Cannot start.{Style.RESET}")
            # _setup_listen_socket should handle closing its socket on failure
            return

        self._load_or_generate_rsa_keys() 
        if not self.running or not self.rsa_private_key_pem or not self.rsa_public_key_pem:
            print(f"{Style.BOLD}{Fore.RED}Client RSA key setup failed or keys unavailable. Cannot start.{Style.RESET}")
            if self.listen_socket: 
                try: self.listen_socket.close()
                except socket.error: pass # Ignore error if already closed
            self.running = False # Ensure it's marked as not running
            return 

        # All critical initializations passed, proceed with network operations
        self._scan_shared_folder()  # Lock handled within this method
        self._connect_to_rendezvous() # Handles its own connection state (self.connected_to_rendezvous)
        
        # Only start listener thread if successfully connected to rendezvous,
        # or decide if listener should start regardless (current logic starts it if socket is up).
        # For now, keeping existing logic: starts if socket is up.
        self._start_listener_thread() 

        if self.running:
            print(f"{Fore.GREEN}P2P Client '{self.client_name}' started successfully.{Style.RESET}")
        else:
            print(f"{Fore.RED}P2P Client '{self.client_name}' failed to start fully.{Style.RESET}")


    def _setup_listen_socket(self):
        """
        Sets up the primary listening socket for incoming peer connections.
        Sets self.running=False on critical failure.
        """
        # self.listen_socket is initialized to None in __init__
        try:
            self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listen_socket.bind(('0.0.0.0', self.receive_port))
            # Update receive_port to the actual port if 0 was passed (OS assigned)
            self.receive_port = self.listen_socket.getsockname()[1]  

            if self.send_port == 0:
                # Bind to a temporary socket to get an OS-assigned ephemeral port for sending
                # Using 'with' ensures the temporary socket is closed.
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as temp_socket:
                    temp_socket.bind(('0.0.0.0', 0))
                    self.send_port = temp_socket.getsockname()[1]
            
            self.listen_socket.listen(10) # Increased backlog slightly (was 5)
            print(f"Listening for incoming connections on port {self.receive_port}")
            print(f"Will use port {self.send_port} for outgoing connections") # Clarified wording

        except socket.error as e:
            print(f"{Style.BOLD}{Fore.RED}Fatal Error: Could not set up listen socket: {e}{Style.RESET}")
            self.running = False # Mark client as not runnable
            if self.listen_socket:
                try:
                    self.listen_socket.close()
                except socket.error: # Ignore errors if closing a problematic socket
                    pass 
            self.listen_socket = None # Ensure it's None on failure
        except Exception as e: # Catch any other unexpected error during setup
            print(f"{Style.BOLD}{Fore.RED}Unexpected fatal error during listen socket setup: {e}{Style.RESET}")
            self.running = False
            if self.listen_socket:
                try: self.listen_socket.close()
                except socket.error: pass
            self.listen_socket = None


    def _start_listener_thread(self):
        """
        Starts the thread that listens for incoming peer connections.
        Only starts if the listen socket is available and the client is marked as running.
        """
        if not self.listen_socket: 
            print(f"{Fore.RED}Listener thread not started: listen socket is not available.{Style.RESET}")
            return
        if not self.running: # Check if client is in a runnable state
            print(f"{Fore.YELLOW}Listener thread not started: client is not in a running state.{Style.RESET}")
            return
            
        listener_thread = threading.Thread(
            target=self._listen_for_connections, 
            name=f"ListenerThread-{self.client_name[:8]}" # Named thread for easier debugging
        )
        listener_thread.daemon = True # Ensure thread exits when main program exits
        listener_thread.start()
        print("Listener thread started.")


    def _scan_shared_folder(self):
        """
        Scans the shared folder for files and updates self.shared_files.
        This method is thread-safe using self.shared_files_lock.
        Uses self.shared_folder_path.
        """
        new_shared_files_list = []
        if not os.path.exists(self.shared_folder_path):
            # If the shared folder itself doesn't exist, log it and clear shared files.
            # This could happen if the directory was deleted externally.
            # __init__ tries to create it, so this is more for runtime robustness.
            if hasattr(self, 'shared_files_lock'): # Check if lock is initialized
                 with self.shared_files_lock:
                    if self.shared_files: # Only print if there was something to clear
                        print(f"{Fore.YELLOW}Warning (scan_shared): Shared folder '{self.shared_folder_path}' not found. Clearing shared files list.{Style.RESET}")
                    self.shared_files = []
            else: # Should not happen if __init__ completed
                self.shared_files = [] 
            return

        try:
            # os.listdir can raise OSError if path is invalid or permissions are wrong
            for file_name in os.listdir(self.shared_folder_path):
                if file_name == os.path.basename(self.FILE_METADATA_PATH):
                    continue # Skip the metadata file itself
                
                file_path = os.path.join(self.shared_folder_path, file_name)
                # Ensure it's a file and not a directory, symlink, etc.
                if os.path.isfile(file_path): 
                    try:
                        file_size = os.path.getsize(file_path)
                        new_shared_files_list.append({
                            'name': file_name,
                            'size': file_size 
                        })
                    except OSError as e: # Specific error for os.path.getsize
                        print(f"{Fore.YELLOW}Warning (scan_shared): Could not get size for file '{file_path}': {e.strerror}{Style.RESET}")
        except OSError as e:
            print(f"{Fore.YELLOW}Warning (scan_shared): Could not list directory '{self.shared_folder_path}': {e.strerror}{Style.RESET}")
            # If listing fails, we might not want to wipe self.shared_files,
            # or we might. Current behavior: new_shared_files_list will be empty or partial.
        
        with self.shared_files_lock: # Acquire lock to update self.shared_files
            # Your existing change detection logic is fine.
            # This simplified version just checks if the lists are different.
            # For more precise change detection, comparing sets of frozensets of dict items is robust.
            current_set = {tuple(sorted(d.items())) for d in self.shared_files}
            new_set = {tuple(sorted(d.items())) for d in new_shared_files_list}

            if current_set != new_set:
                print(f"Sharing {len(new_shared_files_list)} files from '{self.shared_folder_path}' (list updated).")
            self.shared_files = new_shared_files_list


    def _connect_to_rendezvous(self):
        """
        Connects to the rendezvous server, registers the client, and starts periodic updates.
        Uses self.connected_to_rendezvous flag.
        """
        if not self.running: 
            print(f"{Fore.YELLOW}ConnectRendezvous: Client not running, aborting connection.{Style.RESET}")
            return

        sock = None 
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0) # Increased timeout for connect
            print(f"Connecting to rendezvous at {self.rendezvous_host}:{self.rendezvous_port}...")
            sock.connect((self.rendezvous_host, self.rendezvous_port))
            sock.settimeout(None) # Reset timeout after connection

            with self.shared_files_lock: # Access shared_files under lock
                # Create a copy for the payload to avoid issues if it's modified elsewhere
                files_payload = list(self.shared_files) 
            
            register_data = {
                'command': 'register',
                'client_id': self.client_id,
                'receive_port': self.receive_port,
                'send_port': self.send_port,
                'files': files_payload 
            }
            
            try:
                sock.sendall(json.dumps(register_data).encode('utf-8')) # Use sendall
            except (socket.error, BrokenPipeError) as e:
                print(f"{Fore.RED}Rendezvous register: Error sending registration data: {e}{Style.RESET}")
                self.connected_to_rendezvous = False
                return # Cannot proceed if send fails

            response_raw = sock.recv(4096)
            if not response_raw:
                print(f"{Fore.RED}Rendezvous register: No response from server.{Style.RESET}")
                self.connected_to_rendezvous = False
                return

            response_data = json.loads(response_raw.decode('utf-8')) # Catch JSONDecodeError below

            if response_data.get('status') == 'success':
                print(f"{Fore.GREEN}Successfully registered with rendezvous server as {self.client_id[:8]}.{Style.RESET}")
                self.connected_to_rendezvous = True # Use the renamed attribute
                update_thread = threading.Thread(
                    target=self._update_rendezvous_periodically, 
                    name=f"RUpdate-{self.client_name[:8]}" # Named thread
                )
                update_thread.daemon = True
                update_thread.start()
            else:
                message = response_data.get('message', 'Unknown error.')
                print(f"{Fore.RED}Rendezvous register failed: {message}{Style.RESET}")
                self.connected_to_rendezvous = False
            
        except socket.timeout:
            print(f"{Fore.RED}Rendezvous connection timed out ({self.rendezvous_host}:{self.rendezvous_port}).{Style.RESET}")
            self.connected_to_rendezvous = False
        except ConnectionRefusedError:
            print(f"{Fore.RED}Rendezvous connection refused by {self.rendezvous_host}:{self.rendezvous_port}.{Style.RESET}")
            self.connected_to_rendezvous = False
        except socket.gaierror as e: # For DNS or address errors
            print(f"{Fore.RED}Rendezvous address error for {self.rendezvous_host}: {e}{Style.RESET}")
            self.connected_to_rendezvous = False
        except socket.error as e: # General socket errors
            print(f"{Fore.RED}Rendezvous socket error: {e}{Style.RESET}")
            self.connected_to_rendezvous = False
        except json.JSONDecodeError as e:
            print(f"{Fore.RED}Rendezvous register: Malformed JSON response from server: {e}{Style.RESET}")
            self.connected_to_rendezvous = False
        except UnicodeDecodeError as e:
            print(f"{Fore.RED}Rendezvous register: Invalid UTF-8 response from server: {e}{Style.RESET}")
            self.connected_to_rendezvous = False
        except Exception as e: # Catch any other unexpected error
            print(f"{Fore.RED}Unexpected error connecting to rendezvous: {type(e).__name__} - {e}{Style.RESET}")
            self.connected_to_rendezvous = False
        finally:
            if sock:
                try:
                    sock.shutdown(socket.SHUT_RDWR) # Attempt graceful shutdown
                except (socket.error, OSError): pass # Ignore if already closed/problematic
                try:
                    sock.close()
                except (socket.error, OSError): pass


    def _update_rendezvous_periodically(self):
        """Periodically updates the rendezvous server with the current list of shared files."""
        consecutive_failures = 0
        max_failures_before_disconnect = 3 # Configurable: how many failures before assuming disconnected

        # Use self.connected_to_rendezvous
        while self.running and self.connected_to_rendezvous: 
            time.sleep(30) # Initial sleep before first update in loop
            
            # Re-check flags before proceeding, as they might change during sleep
            if not self.running or not self.connected_to_rendezvous: 
                break 

            sock = None
            try:
                self._scan_shared_folder() # Lock handled within _scan_shared_folder

                with self.shared_files_lock: # Access shared_files under lock
                    # Create a copy for the payload
                    files_payload = list(self.shared_files) 
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10.0) # Timeout for connect and send
                sock.connect((self.rendezvous_host, self.rendezvous_port))
                # No need to reset timeout to None if only doing one sendall
                
                update_data = {
                    'command': 'update_files',
                    'client_id': self.client_id,
                    'files': files_payload
                }
                sock.sendall(json.dumps(update_data).encode('utf-8')) # Use sendall
                # print(f"DEBUG: Sent file list update to rendezvous: {len(files_payload)} files") # Optional debug
                consecutive_failures = 0 # Reset on success

            except (socket.timeout, ConnectionRefusedError, socket.gaierror, BrokenPipeError, ConnectionResetError, socket.error) as e: 
                print(f"{Fore.YELLOW}Rendezvous update failed (socket error: {type(e).__name__}). Will retry.{Style.RESET}")
                consecutive_failures += 1
                if consecutive_failures >= max_failures_before_disconnect:
                    print(f"{Fore.RED}Too many consecutive rendezvous update failures. Marking as disconnected.{Style.RESET}")
                    self.connected_to_rendezvous = False # This will stop the loop
            except json.JSONDecodeError as e: # Should not happen when sending, but good practice if expecting response
                print(f"{Fore.YELLOW}Rendezvous update failed (JSON error: {e}). Will retry.{Style.RESET}")
                consecutive_failures +=1
            except Exception as e: # Catch any other unexpected error
                print(f"{Fore.YELLOW}Rendezvous update failed (general error: {type(e).__name__} - {e}). Will retry.{Style.RESET}")
                consecutive_failures += 1
            finally:
                if sock:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except (socket.error, OSError): pass
                    try:
                        sock.close()
                    except (socket.error, OSError): pass
        print(f"{Fore.CYAN}Rendezvous update thread finished.{Style.RESET}")


    def _listen_for_connections(self):
        """
        Listens for incoming connections from other peers and starts a new thread 
        to handle each connection.
        """
        print(f"Listener active on {self.listen_socket.getsockname() if self.listen_socket else 'N/A'}")
        while self.running:
            try:
                if not self.listen_socket: 
                    print(f"{Fore.RED}Listener: Listen socket is no longer available. Stopping listener thread.{Style.RESET}")
                    self.running = False # Ensure client stops if critical socket is gone
                    break
                
                # accept() is a blocking call. It will only raise an error if the socket is closed
                # or another interruption occurs.
                client_socket, address = self.listen_socket.accept()
                print(f"Accepted connection from peer at {address}")
                
                # Name the handler thread for better debugging
                handler_thread_name = f"PeerHandler-{address[0]}-{address[1]}"
                client_handler = threading.Thread(
                    target=self._handle_peer_connection, 
                    args=(client_socket, address),
                    name=handler_thread_name
                )
                client_handler.daemon = True # Ensure thread exits when main program exits
                client_handler.start()

            except socket.timeout:
                # This typically won't happen for a server's listen socket unless a timeout was explicitly set on it.
                # If it does, we can just continue listening.
                if self.running: # Only print if we are supposed to be running
                    print(f"{Fore.YELLOW}Listener: Socket accept timed out (unexpected for listen socket). Continuing...{Style.RESET}")
                continue
            except socket.error as e: 
                # This will catch errors like the socket being closed by another thread (e.g., in self.stop())
                if self.running: # If we are supposed to be running, this is an unexpected error
                    print(f"{Style.BOLD}{Fore.RED}Listener: Socket error during accept: {e}{Style.RESET}")
                    # Check for specific "socket closed" conditions if not already caught by OSError below
                    if isinstance(e, OSError) and e.errno in [9, 10004, 10038]: # 9 (EBADF), 10004 (WSAEINTR), 10038 (WSAENOTSOCK)
                        print(f"{Fore.YELLOW}Listener: Listen socket closed or operation interrupted. Stopping listener.{Style.RESET}")
                        self.running = False # Signal to stop
                # In any case of socket error, it's usually best to break the loop.
                break 
            except Exception as e: # Catch any other unexpected error
                if self.running:
                    print(f"{Style.BOLD}{Fore.RED}Listener: Unexpected error during accept: {type(e).__name__} - {e}{Style.RESET}")
                # Depending on the error, might need to break or continue.
                # For safety, if it's unexpected, breaking might be better.
                break 
        
        print(f"{Fore.CYAN}Listener thread for {self.client_name} finished.{Style.RESET}")


    def _send_error_to_peer(self, peer_socket: socket.socket, message: str, context: str = ""):
        """Helper to send a JSON error message to a peer. To be added if not already present."""
        error_context = f" ({context})" if context else ""
        # Log the error on the server/peer side as well
        print(f"{Fore.RED}Peer Error{error_context}: {message}{Style.RESET}")
        try:
            error_payload = json.dumps({'status': 'error', 'message': message})
            # Use sendall for potentially small error messages to ensure they are fully sent
            peer_socket.sendall(error_payload.encode('utf-8'))
        except (socket.error, BrokenPipeError, ConnectionResetError) as e:
            # It's common for this to fail if the other side already closed the connection
            print(f"{Fore.YELLOW}Could not send error message to peer{error_context}, peer may have disconnected: {e}{Style.RESET}")


    def _handle_peer_connection(self, client_socket: socket.socket, address: tuple): 
        """
        Handles an incoming connection from another peer.
        Receives an initial request and dispatches to appropriate handlers.
        Ensures the client_socket is closed.
        """
        print(f"Handling connection from {address}...")
        request_type = "Unknown" # For logging in case of early failure
        try:
            # Set a timeout for receiving the initial request from the peer
            client_socket.settimeout(20.0) # Increased timeout slightly
            
            # Buffer size should be adequate for initial JSON requests (e.g., public key)
            data_bytes = client_socket.recv(4096) # Increased buffer slightly
            
            # Reset timeout after the initial blocking receive
            client_socket.settimeout(None) 

            if not data_bytes:
                print(f"No data received from {address}. Peer may have disconnected immediately.")
                return # Nothing more to do

            # Attempt to decode and parse the request
            try:
                data_str = data_bytes.decode('utf-8')
                request = json.loads(data_str)
            except UnicodeDecodeError:
                print(f"{Fore.RED}Invalid UTF-8 data received from {address}. Discarding request.{Style.RESET}")
                self._send_error_to_peer(client_socket, "Invalid UTF-8 data in request.", f"PeerConn-{address}")
                return
            except json.JSONDecodeError:
                print(f"{Fore.RED}Invalid JSON format received from {address}. Discarding request.{Style.RESET}")
                self._send_error_to_peer(client_socket, "Invalid JSON format in request.", f"PeerConn-{address}")
                return

            request_type = request.get('type', 'UnknownType') # For logging
            print(f"Received request type '{request_type}' from {address}.")

            if request_type == 'file_request_initiate_secure': 
                # This method will handle its own errors and socket interactions
                self._handle_secure_file_transfer_sharer(client_socket, request, address)
            else:
                print(f"Unknown request type '{request_type}' received from {address}.")
                self._send_error_to_peer(client_socket, f"Unknown request type: {request_type}", f"PeerConn-{address}")

        except socket.timeout:
            print(f"{Fore.RED}Timeout waiting for initial request from {address}.{Style.RESET}")
            # No need to send error back, peer is unresponsive
        except (ConnectionResetError, BrokenPipeError) as e:
            # These errors indicate the peer closed the connection abruptly.
            print(f"{Fore.RED}Connection with {address} lost (reset/broken pipe) during request type '{request_type}': {e}{Style.RESET}")
        except socket.error as e: # Catch other socket-related errors
            print(f"{Style.BOLD}{Fore.RED}Socket error handling connection from {address} (request type '{request_type}'): {e}{Style.RESET}")
        except Exception as e: # Catch any other unexpected error
            print(f"{Style.BOLD}{Fore.RED}Unexpected error handling peer connection from {address} (request type '{request_type}'): {type(e).__name__} - {e}{Style.RESET}")
            # import traceback # Uncomment for full traceback during debugging
            # traceback.print_exc()
        finally:
            # Ensure the socket is always closed properly
            print(f"Closing connection from {address} (last request type: '{request_type}').")
            try:
                # Attempt a graceful shutdown of the socket
                client_socket.shutdown(socket.SHUT_RDWR)
            except (socket.error, OSError):
                # Ignore errors if socket is already closed or in a bad state
                pass
            try:
                client_socket.close()
            except (socket.error, OSError):
                pass # Ignore errors if closing a problematic socket


    def _handle_secure_file_transfer_sharer(self, client_socket: socket.socket, request: dict, address: tuple):
        """
        Handles the sharer-side logic for a secure file transfer, including key exchange
        and sending the file in chunks.
        The client_socket is managed (and closed) by the calling _handle_peer_connection method.
        """
        file_name = request.get('file_name') # Use .get() for safer access
        downloader_public_key_pem_str = request.get('downloader_public_key')

        # Validate essential request parameters
        if not file_name or not downloader_public_key_pem_str:
            self._send_error_to_peer(client_socket, "Malformed file request (missing file_name or public_key).", f"Sharer-{file_name or 'UnknownFile'}")
            return
        
        downloader_public_key_pem_bytes = downloader_public_key_pem_str.encode('utf-8') # Assuming UTF-8 for PEM string
        context_log_prefix = f"Sharer-{file_name}-{address[0]}:{address[1]}" # For logging context

        print(f"{context_log_prefix}: Processing secure file request...")

        # Use the correct shared folder path attribute
        encrypted_file_path_on_sharer = os.path.join(self.shared_folder_path, file_name) 
        if not os.path.exists(encrypted_file_path_on_sharer):
            self._send_error_to_peer(client_socket, "File not found on sender side.", context_log_prefix)
            return

        # Load metadata (MEK lock is handled within _load_file_metadata)
        # _load_file_metadata should return {} or a dict, not None, on failure/success.
        all_metadata = self._load_file_metadata() 
        if not isinstance(all_metadata, dict): # Should be a dict, even if empty
             # This indicates a more severe issue with _load_file_metadata if it returns None
            self._send_error_to_peer(client_socket, "Internal server error: Sharer metadata load failed unexpectedly.", context_log_prefix)
            return

        file_meta = all_metadata.get(file_name)
        if not file_meta or 'key' not in file_meta or 'hash' not in file_meta:
            self._send_error_to_peer(client_socket, "File metadata (key/hash) incomplete or missing on sender side.", context_log_prefix)
            return

        symmetric_file_key_hex = file_meta['key']
        original_content_hash = file_meta['hash']
        
        try:
            symmetric_file_key_bytes = bytes.fromhex(symmetric_file_key_hex)
            # Get total size of the (already encrypted) file to be sent
            symmetrically_encrypted_total_size = os.path.getsize(encrypted_file_path_on_sharer)
            rsa_encrypted_symmetric_key_bytes = crypto_utils.encrypt_with_rsa_public_key(
                symmetric_file_key_bytes,
                downloader_public_key_pem_bytes
            )
        except ValueError: # From bytes.fromhex
            self._send_error_to_peer(client_socket, "Invalid symmetric key format in sharer metadata.", context_log_prefix)
            return
        except OSError as e: # From os.path.getsize
            self._send_error_to_peer(client_socket, f"Sharer could not get file size: {e.strerror}", context_log_prefix)
            return
        except Exception as e: # From crypto_utils.encrypt_with_rsa_public_key or other unexpected
            self._send_error_to_peer(client_socket, f"Sharer failed to prepare key for exchange: {type(e).__name__}", context_log_prefix)
            print(f"{Style.BOLD}{Fore.RED}{context_log_prefix}: Error preparing key for exchange: {e}{Style.RESET}") # Log more details server-side
            return

        response_payload = {
            'status': 'key_exchange_ok',
            'rsa_encrypted_symmetric_key_hex': rsa_encrypted_symmetric_key_bytes.hex(),
            'original_hash': original_content_hash,
            'symmetrically_encrypted_total_size': symmetrically_encrypted_total_size
            # 'chunk_size': self.chunk_size # Optional, downloader can manage its own recv buffer
        }
        
        try:
            client_socket.sendall(json.dumps(response_payload).encode('utf-8')) # Use sendall
        except (socket.error, BrokenPipeError, ConnectionResetError) as e:
            print(f"{Fore.RED}{context_log_prefix}: Socket error sending key exchange payload: {e}{Style.RESET}")
            return # Cannot proceed if this fails

        print(f"{context_log_prefix}: Sent key exchange payload. Waiting for ready signal...")

        client_socket.settimeout(30.0) # Increased timeout for ready signal
        ready_signal = b'' # Initialize
        try:
            ready_signal = client_socket.recv(1024)
        except socket.timeout:
            print(f"{Fore.YELLOW}{context_log_prefix}: Timeout waiting for 'ready_for_file_content' signal. Aborting.{Style.RESET}")
            return
        except (socket.error, ConnectionResetError, BrokenPipeError) as e:
            print(f"{Fore.RED}{context_log_prefix}: Socket error waiting for ready signal: {e}{Style.RESET}")
            return
        finally:
            client_socket.settimeout(None) # Reset timeout

        if ready_signal != b'ready_for_file_content':
            print(f"{Fore.YELLOW}{context_log_prefix}: Downloader not ready (signal: {ready_signal!r}). Aborting.{Style.RESET}")
            # Optionally send an error message back if signal is unexpected but connection is alive
            # self._send_error_to_peer(client_socket, "Unexpected ready signal.", context_log_prefix)
            return

        print(f"{context_log_prefix}: Downloader ready. Sending {symmetrically_encrypted_total_size} bytes in chunks of up to {self.chunk_size} bytes...")
        bytes_sent_total = 0
        try:
            with open(encrypted_file_path_on_sharer, 'rb') as f:
                while True:
                    chunk_to_send = f.read(self.chunk_size)
                    if not chunk_to_send:
                        break # End of file
                    client_socket.sendall(chunk_to_send) # sendall will loop until all bytes in chunk are sent or error
                    bytes_sent_total += len(chunk_to_send)
                    # print(f"{context_log_prefix}: Sent chunk, total sent: {bytes_sent_total}", end='\r') # Verbose
            # print() # Newline after progress if verbose logging was on
            
            if bytes_sent_total == symmetrically_encrypted_total_size:
                print(f"{Fore.GREEN}{context_log_prefix}: Successfully sent all chunks ({bytes_sent_total} bytes).{Style.RESET}")
            else:
                # This case should ideally not happen if EOF is handled correctly and no errors occurred.
                print(f"{Fore.YELLOW}{context_log_prefix}: Sent {bytes_sent_total} bytes, but expected {symmetrically_encrypted_total_size}. Transfer may be incomplete.{Style.RESET}")

        except (socket.error, BrokenPipeError, ConnectionResetError) as e:
            print(f"{Fore.RED}{context_log_prefix}: Socket error during chunked send: {e}{Style.RESET}")
        except IOError as e: # Error reading the local file to be shared
            print(f"{Fore.RED}{context_log_prefix}: IO error reading file '{encrypted_file_path_on_sharer}' for sending: {e.strerror}{Style.RESET}")
        except Exception as e: # Catch any other unexpected error during send
            print(f"{Style.BOLD}{Fore.RED}{context_log_prefix}: Unexpected error sending file chunks: {type(e).__name__} - {e}{Style.RESET}")
        
        # Note: The client_socket is closed by the calling _handle_peer_connection's finally block.

    def _load_file_metadata(self) -> dict:
        """
        Loads, decrypts (if MEK available), and parses the file_metadata.json.
        Handles MEK lock internally. Returns an empty dict on failure.
        """
        if not os.path.exists(self.FILE_METADATA_PATH):
            return {} # File not found, normal for new user or no shared files

        try:
            with open(self.FILE_METADATA_PATH, 'rb') as f: 
                file_content_bytes = f.read()

            if not file_content_bytes: # File is empty
                return {}
            
            # Acquire MEK under lock for decryption
            with self.mek_lock:
                current_mek = self.master_encryption_key

            if not current_mek:
                # MEK not available (user not logged in, or derivation failed).
                # Attempt to load as plaintext (for backward compatibility or if MEK failed).
                try:
                    metadata_dict = json.loads(file_content_bytes.decode('utf-8'))
                    print(f"{Fore.YELLOW}Warning: Loaded metadata as plaintext (MEK unavailable). File should be re-saved while logged in to encrypt it.{Style.RESET}")
                    return metadata_dict
                except (UnicodeDecodeError, json.JSONDecodeError):
                    # It's not plaintext JSON, and we can't decrypt without MEK.
                    print(f"{Fore.RED}Error: Metadata file '{self.FILE_METADATA_PATH}' exists but MEK is unavailable for decryption, and it's not valid plaintext JSON.{Style.RESET}")
                    return {} 

            # MEK is available, attempt decryption
            try:
                decrypted_json_bytes = crypto_utils.decrypt_data(file_content_bytes, current_mek)
                metadata_dict = json.loads(decrypted_json_bytes.decode('utf-8'))
                # print(f"{Fore.GREEN}Metadata decrypted successfully.{Style.RESET}") # Debug
                return metadata_dict
            except ValueError as e: # Catches decrypt_data errors (bad key/padding)
                print(f"{Style.BOLD}{Fore.RED}Error decrypting metadata file '{self.FILE_METADATA_PATH}'.{Style.RESET}")
                print(f"{Fore.YELLOW}  Details: {e}{Style.RESET}")
                print(f"{Fore.YELLOW}  (Possible incorrect password, corrupted file, or old plaintext if MEK was expected).{Style.RESET}")
                return {}
            except (UnicodeDecodeError, json.JSONDecodeError): # If decrypted content is not valid JSON or UTF-8
                print(f"{Fore.YELLOW}Warning: Metadata file '{self.FILE_METADATA_PATH}' content is corrupted (not valid JSON/UTF-8 after potential decryption).{Style.RESET}")
                return {}

        except (IOError, OSError) as e: # Errors reading the file
            print(f"{Style.BOLD}{Fore.RED}File error loading metadata '{self.FILE_METADATA_PATH}': {e.strerror}{Style.RESET}")
            return {}
        except Exception as e: # Catch-all for other unexpected errors
            print(f"{Style.BOLD}{Fore.RED}Unexpected error loading metadata file '{self.FILE_METADATA_PATH}': {type(e).__name__} - {e}{Style.RESET}")
            return {}


    def _save_file_metadata(self, metadata_dict: dict) -> bool:
        """
        Encrypts (if MEK available) and saves the metadata_dict to file_metadata.json.
        Handles MEK lock internally. Returns True on success, False on failure.
        """
        if not isinstance(metadata_dict, dict): # Basic type check
            print(f"{Style.BOLD}{Fore.RED}Error saving metadata: Input is not a dictionary.{Style.RESET}")
            return False

        # Acquire MEK under lock for encryption
        with self.mek_lock:
            current_mek = self.master_encryption_key
            if not current_mek:
                print(f"{Style.BOLD}{Fore.RED}Error saving metadata: MEK unavailable (e.g., not logged in or derivation failed). Metadata NOT saved.{Style.RESET}")
                return False 

        try:
            metadata_json_bytes = json.dumps(metadata_dict, indent=2).encode('utf-8')
            encrypted_data = crypto_utils.encrypt_data(metadata_json_bytes, current_mek) # Use MEK obtained under lock
            
            with open(self.FILE_METADATA_PATH, 'wb') as f: 
                f.write(encrypted_data)
            # print(f"{Fore.GREEN}Metadata saved and encrypted successfully to '{self.FILE_METADATA_PATH}'.{Style.RESET}") # Debug
            return True
        except (IOError, OSError) as e: # File writing errors
            print(f"{Style.BOLD}{Fore.RED}Error saving encrypted metadata to file '{self.FILE_METADATA_PATH}': {e.strerror}{Style.RESET}")
        except TypeError as e: # json.dumps can raise TypeError for non-serializable objects
            print(f"{Style.BOLD}{Fore.RED}Error serializing metadata to JSON: {e}{Style.RESET}")
        except ValueError as e: # crypto_utils.encrypt_data can raise ValueError (e.g. bad key length, though MEK should be correct)
            print(f"{Style.BOLD}{Fore.RED}Error encrypting metadata: {e}{Style.RESET}")
        except Exception as e: # Catch-all for other unexpected errors
            print(f"{Style.BOLD}{Fore.RED}Unexpected error while saving encrypted metadata: {type(e).__name__} - {e}{Style.RESET}")
        return False


    def download_file(self, peer_id: str, file_name: str) -> bool:
        """
        Downloads a file from a specified peer after performing a secure key exchange.
        Receives the file in chunks and reassembles it.
        """
        if not self.is_logged_in():
            print(f"{Style.BOLD}{Fore.RED}Download Error: Please log in to download files.{Style.RESET}")
            return False
        if not self.rsa_private_key_pem or not self.rsa_public_key_pem: 
            print(f"{Style.BOLD}{Fore.RED}Download Error: RSA keys unavailable. Cannot perform secure download.{Style.RESET}")
            return False

        with self.peers_lock: # Access self.peers under lock
            peer_info = self.peers.get(peer_id) # Use .get() for safer access

        if not peer_info:
            print(f"{Fore.YELLOW}Download Error: Peer {peer_id} not found in current peer list. Try refreshing.{Style.RESET}")
            return False

        peer_ip, peer_receive_port = peer_info.get('ip'), peer_info.get('receive_port')
        if not peer_ip or not isinstance(peer_receive_port, int):
            print(f"{Fore.RED}Download Error: Invalid peer information for {peer_id}.{Style.RESET}")
            return False

        context_log_prefix = f"Downloader-{file_name}-from-{peer_id[:8]}"
        sock: socket.socket = None # Type hint
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.send_port != 0:
                 # This bind is optional and can sometimes cause "address already in use"
                 # if not handled carefully, especially with many concurrent downloads.
                 # Often, it's fine to let the OS pick an ephemeral port for outgoing connections.
                 # For simplicity, keeping it, but be aware.
                 try:
                     sock.bind(('0.0.0.0', self.send_port))
                 except socket.error as bind_err:
                     print(f"{Fore.YELLOW}{context_log_prefix}: Could not bind send port {self.send_port} ({bind_err}). Using OS-assigned port.{Style.RESET}")
            
            print(f"{context_log_prefix}: Attempting to connect to peer at {peer_ip}:{peer_receive_port}...")
            sock.settimeout(15.0) # Connection timeout (was 10.0)
            sock.connect((peer_ip, peer_receive_port))
            sock.settimeout(None) # Reset timeout after connection
            print(f"{context_log_prefix}: Connected. Initiating secure key exchange...")

            request_data = {
                'type': 'file_request_initiate_secure',
                'file_name': file_name,
                'downloader_public_key': self.rsa_public_key_pem.decode('utf-8') 
            }
            try:
                sock.sendall(json.dumps(request_data).encode('utf-8')) # Use sendall
            except (socket.error, BrokenPipeError, ConnectionResetError) as e:
                print(f"{Fore.RED}{context_log_prefix}: Error sending file request: {e}{Style.RESET}")
                return False

            sock.settimeout(30.0) # Timeout for key exchange response (was 20.0)
            key_exchange_response_raw = sock.recv(4096) # Buffer for JSON response
            sock.settimeout(None)

            if not key_exchange_response_raw:
                print(f"{Fore.RED}{context_log_prefix}: No response from peer during key exchange.{Style.RESET}")
                return False
            
            try:
                key_exchange_response = json.loads(key_exchange_response_raw.decode('utf-8'))
            except UnicodeDecodeError:
                print(f"{Fore.RED}{context_log_prefix}: Invalid UTF-8 in key exchange response.{Style.RESET}"); return False
            except json.JSONDecodeError:
                print(f"{Fore.RED}{context_log_prefix}: Invalid JSON in key exchange response.{Style.RESET}"); return False

            if key_exchange_response.get('status') != 'key_exchange_ok':
                error_msg = key_exchange_response.get('message', 'Unknown error from sharer.')
                print(f"{Fore.RED}{context_log_prefix}: Sharer returned error: {error_msg}{Style.RESET}")
                return False

            # Validate all expected fields from the key exchange response
            rsa_enc_sym_key_hex = key_exchange_response.get('rsa_encrypted_symmetric_key_hex')
            original_hash = key_exchange_response.get('original_hash')
            s_enc_total_size = key_exchange_response.get('symmetrically_encrypted_total_size')

            if not all([rsa_enc_sym_key_hex, original_hash, isinstance(s_enc_total_size, int)]):
                print(f"{Fore.RED}{context_log_prefix}: Malformed key exchange response from peer (missing fields).{Style.RESET}")
                return False
            if s_enc_total_size < 0: # Basic sanity check for size
                print(f"{Fore.RED}{context_log_prefix}: Invalid file size ({s_enc_total_size}) in key exchange response.{Style.RESET}")
                return False
            
            print(f"{context_log_prefix}: Received RSA-encrypted symmetric key. Decrypting...")
            try:
                decrypted_symmetric_file_key = crypto_utils.decrypt_with_rsa_private_key(
                    bytes.fromhex(rsa_enc_sym_key_hex),
                    self.rsa_private_key_pem 
                )
            except ValueError as e: # Catches fromhex errors or crypto errors re-raised as ValueError
                print(f"{Fore.RED}{context_log_prefix}: Error decrypting symmetric key (ValueError): {e}{Style.RESET}"); return False
            except Exception as e: # Catch other potential crypto errors
                print(f"{Fore.RED}{context_log_prefix}: Error decrypting symmetric key ({type(e).__name__}): {e}{Style.RESET}"); return False

            print(f"{Fore.GREEN}{context_log_prefix}: Symmetric key decrypted successfully.{Style.RESET}")

            try:
                sock.sendall(b'ready_for_file_content') # Use sendall
            except (socket.error, BrokenPipeError, ConnectionResetError) as e:
                print(f"{Fore.RED}{context_log_prefix}: Error sending ready signal: {e}{Style.RESET}"); return False
            print(f"{context_log_prefix}: Signaled readiness for file content.")

            received_encrypted_chunks_list = []
            bytes_received = 0
            print(f"{context_log_prefix}: Downloading ENCRYPTED file ({s_enc_total_size} bytes)...")
            
            receive_buffer_size = min(self.chunk_size, 16384) # e.g., up to 16KB or self.chunk_size

            # Set a timeout for individual recv calls during chunk reception
            # Total download time can be long, but each part should arrive reasonably fast.
            sock.settimeout(60.0) # Increased timeout for receiving data chunks (was 30.0)

            while bytes_received < s_enc_total_size:
                bytes_to_get = min(receive_buffer_size, s_enc_total_size - bytes_received)
                try:
                    chunk_data_part = sock.recv(bytes_to_get)
                except socket.timeout:
                    print(f"{Fore.RED}\n{context_log_prefix}: Timeout receiving data. Received {bytes_received}/{s_enc_total_size}.{Style.RESET}")
                    return False 
                
                if not chunk_data_part: # Peer closed connection prematurely
                    print(f"{Fore.RED}\n{context_log_prefix}: Connection lost during download. Received {bytes_received}/{s_enc_total_size}.{Style.RESET}")
                    return False
                
                received_encrypted_chunks_list.append(chunk_data_part)
                bytes_received += len(chunk_data_part)
                progress = (bytes_received / s_enc_total_size) * 100 if s_enc_total_size > 0 else 100.0
                print(f"Download progress: {progress:.1f}% ({bytes_received}/{s_enc_total_size})", end='\r')
            
            sock.settimeout(None) # Reset timeout
            print(f"\n{context_log_prefix}: ENCRYPTED download complete. Received {bytes_received} bytes.                  ")

            if bytes_received != s_enc_total_size:
                 print(f"{Fore.RED}{context_log_prefix}: Downloaded encrypted size mismatch. Expected {s_enc_total_size}, got {bytes_received}{Style.RESET}")
                 return False

            full_s_enc_content = b''.join(received_encrypted_chunks_list)
            
            print(f"{context_log_prefix}: Decrypting content...")
            try:
                decrypted_content = crypto_utils.decrypt_file_content(full_s_enc_content, decrypted_symmetric_file_key)
            except ValueError as e: # From crypto_utils.decrypt_data if key is wrong/data corrupt
                print(f"{Style.BOLD}{Fore.RED}{context_log_prefix}: Decryption failed: {e}{Style.RESET}"); return False
            except InvalidTag: # Should be caught by ValueError from decrypt_data's PKCS7 unpadding
                 print(f"{Style.BOLD}{Fore.RED}{context_log_prefix}: Decryption failed (InvalidTag).{Style.RESET}"); return False
            print(f"{context_log_prefix}: File content decryption successful.")

            calc_hash = crypto_utils.hash_file_content(decrypted_content)
            if calc_hash == original_hash:
                print(f"{Fore.GREEN}{context_log_prefix}: Integrity check PASSED.{Style.RESET}")
                # Use the correct downloads folder path attribute
                dl_path = os.path.join(self.downloads_folder_path, file_name) 
                try:
                    with open(dl_path, 'wb') as f: f.write(decrypted_content)
                    print(f"{Fore.GREEN}File '{file_name}' saved to '{dl_path}'.{Style.RESET}")
                    return True
                except (IOError, OSError) as e:
                    print(f"{Style.BOLD}{Fore.RED}{context_log_prefix}: Error saving downloaded file to '{dl_path}': {e.strerror}{Style.RESET}")
                    return False
            else:
                print(f"{Style.BOLD}{Fore.RED}{context_log_prefix}: CRITICAL - Integrity FAILED.{Style.RESET}")
                print(f"  Expected hash: {original_hash}\n  Calculated hash: {calc_hash}")
                return False

        except socket.timeout:
            print(f"{Fore.RED}{context_log_prefix}: Socket timeout during operation.{Style.RESET}")
        except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, socket.gaierror, socket.error) as e: 
            print(f"{Fore.RED}{context_log_prefix}: Connection/Socket error: {type(e).__name__} - {e}{Style.RESET}")
        except json.JSONDecodeError as e: # From loading key_exchange_response
            print(f"{Fore.RED}{context_log_prefix}: Invalid JSON from peer: {e}{Style.RESET}")
        except ValueError as e:  # Catches crypto errors re-raised as ValueError, or bytes.fromhex errors
            print(f"{Fore.RED}{context_log_prefix}: Data processing/decryption error: {e}{Style.RESET}")
        # InvalidTag is usually caught by ValueError from decrypt_data for CBC+PKCS7
        # except InvalidTag: 
        #      print(f"{Style.BOLD}{Fore.RED}{context_log_prefix}: Decryption failed (InvalidTag).{Style.RESET}")
        except Exception as e: # Catch-all for any other unexpected error
            print(f"{Style.BOLD}{Fore.RED}{context_log_prefix}: Unexpected error downloading: {type(e).__name__} - {e}{Style.RESET}")
            # import traceback # Uncomment for detailed debugging
            # traceback.print_exc()
        finally:
            if sock:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except (socket.error, OSError): pass
                try:
                    sock.close()
                except (socket.error, OSError): pass
        return False # Explicitly return False if any exception path is taken that doesn't return True


    # Helper function (can be outside class or static method if preferred, or defined locally if only used here)
    # Moved this helper to be defined once in the class scope or as a global utility if used elsewhere.
    # For now, let's assume it's a private helper method if it's only for share_file cleanup.
    def _try_remove_file(self, file_path: str, context_msg: str = ""):
        """Attempts to remove a file, logging any errors."""
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"{Fore.YELLOW}Info ({context_msg}): Cleaned up file '{file_path}'.{Style.RESET}")
        except (IOError, OSError) as e_remove:
            print(f"{Fore.YELLOW}Warning ({context_msg}): Could not remove file '{file_path}': {e_remove.strerror}{Style.RESET}")


    def share_file(self, file_path: str) -> bool:
        """
        Encrypts a given file, saves it to the shared folder, and updates the encrypted metadata.
        Attempts to notify the rendezvous server of the change.
        Returns True on success, False on failure.
        """
        if not self.is_logged_in():
            print(f"{Style.BOLD}{Fore.RED}Share Error: Please log in to share files.{Style.RESET}")
            return False
        
        with self.mek_lock: # Thread-safe check for MEK availability
            if not self.master_encryption_key:
                print(f"{Style.BOLD}{Fore.RED}Share Error: Master Encryption Key not available. Please log in again.{Style.RESET}")
                return False

        if not os.path.exists(file_path):
            print(f"{Fore.RED}Share Error: Source file '{file_path}' does not exist.{Style.RESET}")
            return False
        if not os.path.isfile(file_path):
            print(f"{Fore.RED}Share Error: Source path '{file_path}' is not a file.{Style.RESET}")
            return False

        file_name = os.path.basename(file_path)
        # Use the correct shared folder path attribute from __init__
        encrypted_dest_path = os.path.join(self.shared_folder_path, file_name) 

        original_content = None
        encrypted_content_written = False # Flag to track if encrypted file was successfully written
        
        try:
            print(f"Reading original file '{file_path}'...")
            with open(file_path, 'rb') as f_orig:
                original_content = f_orig.read()
            
            # Handle empty file case (allow sharing, but warn)
            if not original_content and os.path.getsize(file_path) > 0 : 
                print(f"{Fore.RED}Share Error: Failed to read content from '{file_path}' or file became empty after size check.{Style.RESET}")
                return False
            if not original_content and os.path.getsize(file_path) == 0:
                print(f"{Fore.YELLOW}Warning: Sharing an empty file: '{file_path}'.{Style.RESET}")

            print(f"Encrypting '{file_name}'...")
            file_symmetric_key = crypto_utils.generate_symmetric_key()
            encrypted_content_bytes = crypto_utils.encrypt_file_content(original_content, file_symmetric_key)

            print(f"Saving encrypted file to '{encrypted_dest_path}'...")
            with open(encrypted_dest_path, 'wb') as f_enc:
                f_enc.write(encrypted_content_bytes)
            encrypted_content_written = True # Mark as successfully written
            print(f"{Fore.GREEN}File '{file_name}' encrypted and saved to shared folder.{Style.RESET}")
            
            original_hash = crypto_utils.hash_file_content(original_content)
            
            print("Loading existing file metadata...")
            metadata = self._load_file_metadata() # MEK lock handled inside
            if not isinstance(metadata, dict): 
                print(f"{Style.BOLD}{Fore.RED}Share Error: Failed to load existing metadata correctly. Cannot update.{Style.RESET}")
                if encrypted_content_written: # Only remove if it was written
                    self._try_remove_file(encrypted_dest_path, "Share Error Cleanup - Metadata Load Failed")
                return False

            metadata[file_name] = {
                'hash': original_hash,    
                'key': file_symmetric_key.hex() 
            }
            
            print(f"Saving updated metadata for '{file_name}'...")
            if not self._save_file_metadata(metadata): # MEK lock handled inside
                print(f"{Style.BOLD}{Fore.RED}Share Error: Failed to save updated metadata. File sharing might be inconsistent.{Style.RESET}")
                if encrypted_content_written:
                    self._try_remove_file(encrypted_dest_path, "Share Error Cleanup - Metadata Save Failed")
                return False 
            
            print(f"Metadata for '{file_name}' saved and encrypted successfully.")

            self._scan_shared_folder() # Updates self.shared_files (lock handled inside)
            
            # <<< NOTIFY RENDEZVOUS OF THE UPDATE >>>
            print(f"Attempting to notify rendezvous server of new/updated shared file '{file_name}'...")
            self._notify_rendezvous_of_update() 
            
            return True

        except (IOError, OSError) as e:
            print(f"{Style.BOLD}{Fore.RED}Share Error (File Operation): Failed to process file '{file_path}' or '{encrypted_dest_path}': {e.strerror}{Style.RESET}")
            if encrypted_content_written: 
                self._try_remove_file(encrypted_dest_path, "Share File IO/OS Error Cleanup")
        except ValueError as e: # Can be from crypto_utils or other value issues
            print(f"{Style.BOLD}{Fore.RED}Share Error (Value Error): {e}{Style.RESET}")
            if encrypted_content_written:
                self._try_remove_file(encrypted_dest_path, "Share File Value Error Cleanup")
        except Exception as e: 
            print(f"{Style.BOLD}{Fore.RED}Unexpected error sharing file '{file_name}': {type(e).__name__} - {e}{Style.RESET}")
            if encrypted_content_written: # Check flag instead of complex condition
                 self._try_remove_file(encrypted_dest_path, "Share File Unexpected Error Cleanup")
        return False
    
    def stop_sharing_file(self, file_name_to_stop: str) -> bool:
        """
        Stops sharing a specified file. This involves:
        - Removing its entry from the (encrypted) file_metadata.json.
        - Deleting the encrypted file from the shared folder.
        - Updating the internal list of shared files and notifying the rendezvous server.
        Returns True if the file was successfully un-shared, False otherwise.
        """
        if not self.is_logged_in():
            print(f"{Style.BOLD}{Fore.RED}Stop Share Error: Please log in to manage shared files.{Style.RESET}")
            return False
        
        with self.mek_lock: # Ensure MEK is available for metadata operations
            if not self.master_encryption_key:
                print(f"{Style.BOLD}{Fore.RED}Stop Share Error: MEK unavailable. Please log in again.{Style.RESET}")
                return False

        context_log_prefix = f"StopShare-{file_name_to_stop}"
        print(f"{context_log_prefix}: Attempting to stop sharing...")

        # 1. Load current metadata (MEK lock handled inside _load_file_metadata)
        metadata = self._load_file_metadata()
        if not isinstance(metadata, dict): # Should be a dict, even if empty
            print(f"{Style.BOLD}{Fore.RED}{context_log_prefix}: Failed to load metadata. Cannot stop sharing.{Style.RESET}")
            return False

        if file_name_to_stop not in metadata:
            print(f"{Fore.YELLOW}{context_log_prefix}: File is not currently in shared metadata (already unshared or never shared).{Style.RESET}")
            # Optionally, still run _scan_shared_folder and notify rendezvous to ensure consistency
            self._scan_shared_folder()
            self._notify_rendezvous_of_update()
            return True # Considered success as the file is not shared

        # 2. Remove file entry from metadata
        del metadata[file_name_to_stop]
        print(f"{context_log_prefix}: Removed '{file_name_to_stop}' from metadata.")

        # 3. Save updated metadata (MEK lock and encryption handled inside)
        if not self._save_file_metadata(metadata):
            print(f"{Style.BOLD}{Fore.RED}{context_log_prefix}: Failed to save updated metadata. File may still appear shared locally until next successful save.{Style.RESET}")
            # This is a problematic state. The file might still be on disk.
            # For now, we'll return False, but the user might need to manually resolve or retry.
            return False
        print(f"{context_log_prefix}: Updated metadata saved successfully.")

        # 4. Delete the encrypted file from the shared folder
        encrypted_file_path = os.path.join(self.shared_folder_path, file_name_to_stop)
        if os.path.exists(encrypted_file_path):
            try:
                os.remove(encrypted_file_path)
                print(f"{context_log_prefix}: Deleted encrypted file '{encrypted_file_path}'.")
            except (IOError, OSError) as e:
                print(f"{Fore.YELLOW}{context_log_prefix}: Warning - Could not delete file '{encrypted_file_path}': {e.strerror}. Please remove manually if needed.{Style.RESET}")
                # Continue, as metadata is updated, but warn user.
        else:
            print(f"{Fore.YELLOW}{context_log_prefix}: Encrypted file '{encrypted_file_path}' not found for deletion (already removed?).{Style.RESET}")

        # 5. Rescan shared folder to update internal list (self.shared_files)
        self._scan_shared_folder() # Lock handled inside

        # 6. Notify rendezvous server of the change in shared files
        print(f"{context_log_prefix}: Notifying rendezvous server of updated shared file list...")
        self._notify_rendezvous_of_update()
        
        print(f"{Fore.GREEN}{context_log_prefix}: Successfully stopped sharing '{file_name_to_stop}'.{Style.RESET}")
        return True


    def list_shared_files(self) -> list:
        """
        Returns a list of files currently being shared by this client.
        Ensures the list is up-to-date by scanning the shared folder. Thread-safe.
        """
        self._scan_shared_folder() # This method handles its own shared_files_lock
        with self.shared_files_lock:
            # Return a copy of the list to prevent external modification of the internal state
            return list(self.shared_files) 

    def list_available_files(self) -> dict:
        """
        Retrieves the list of available files from all known peers.
        Returns a dictionary 전쟁of file_name -> list of sources. Thread-safe.
        """
        # get_peer_list() updates self.peers and handles its own peers_lock internally.
        # It returns a copy, so we don't need to re-lock for iteration here if we use that copy.
        current_peers_copy = self.get_peer_list() # This now returns a copy
        
        all_files = {}
        if not isinstance(current_peers_copy, dict): # Should be a dict
            print(f"{Fore.YELLOW}Warning (list_available): Could not retrieve a valid peer list.{Style.RESET}")
            return all_files # Return empty if peer list is invalid

        for peer_id, peer_info in current_peers_copy.items():
            # self.client_id should already be filtered out by get_peer_list, but double-check if needed.
            # if peer_id == self.client_id: 
            #     continue

            # Ensure peer_info is a dictionary and 'files' key exists and is a list
            if not isinstance(peer_info, dict):
                # print(f"{Fore.YELLOW}Warning (list_available): Invalid peer_info for {peer_id}.{Style.RESET}")
                continue
            
            peer_file_list = peer_info.get('files', [])
            if not isinstance(peer_file_list, list):
                # print(f"{Fore.YELLOW}Warning (list_available): Invalid 'files' list for {peer_id}.{Style.RESET}")
                continue

            for file_info in peer_file_list:
                # Ensure file_info is a dictionary and contains 'name' and 'size'
                if not isinstance(file_info, dict):
                    # print(f"{Fore.YELLOW}Warning (list_available): Invalid file_info entry for {peer_id}.{Style.RESET}")
                    continue
                
                file_name = file_info.get('name')
                file_size = file_info.get('size')

                if file_name and isinstance(file_size, int): # Basic validation
                    if file_name not in all_files:
                        all_files[file_name] = []
                    
                    all_files[file_name].append({
                        'peer_id': peer_id,
                        'size': file_size 
                    })
                # else:
                    # print(f"{Fore.YELLOW}Warning (list_available): Missing name/size in file_info from {peer_id} for file '{file_name}'.{Style.RESET}")
        return all_files

    def get_peers_copy(self) -> dict: # Helper method added in previous full file example
        """Returns a shallow copy of the current peers dictionary, thread-safely."""
        with self.peers_lock:
            return dict(self.peers) # Return a copy

    def get_peer_list(self) -> dict: 
        """
        Retrieves the list of peers from the rendezvous server and updates self.peers.
        Returns a *copy* of the current peers list. Thread-safe.
        """
        # Use the renamed attribute for rendezvous connection status
        if not self.connected_to_rendezvous and self.running: 
            print(f"{Fore.YELLOW}GetPeerList: Not connected to rendezvous. Attempting to re-register...{Style.RESET}")
            self._connect_to_rendezvous() # This method handles setting self.connected_to_rendezvous
            if not self.connected_to_rendezvous:
                print(f"{Fore.RED}GetPeerList: Still not connected to rendezvous. Cannot get peer list.{Style.RESET}")
                return self.get_peers_copy() # Return copy of (possibly empty or stale) current peers

        sock: socket.socket = None # Type hint
        context_log_prefix = "GetPeerList"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0) # Increased timeout for connect + send + recv
            # print(f"{context_log_prefix}: Connecting to rendezvous {self.rendezvous_host}:{self.rendezvous_port}...")
            sock.connect((self.rendezvous_host, self.rendezvous_port))
            # No need to reset timeout to None if only one send/recv sequence

            request_data = {'command': 'get_peers'}
            try:
                sock.sendall(json.dumps(request_data).encode('utf-8')) # Use sendall
            except (socket.error, BrokenPipeError) as e:
                print(f"{Fore.RED}{context_log_prefix}: Error sending request: {e}{Style.RESET}")
                return self.get_peers_copy() # Return current state on send failure

            response_raw = sock.recv(8192 * 2) # Increased buffer for potentially large peer lists
            if not response_raw:
                print(f"{Fore.RED}{context_log_prefix}: No response from rendezvous server.{Style.RESET}")
                return self.get_peers_copy() # Return current state

            try:
                response_data_str = response_raw.decode('utf-8')
                response_data = json.loads(response_data_str)
            except UnicodeDecodeError:
                print(f"{Fore.RED}{context_log_prefix}: Invalid UTF-8 in response.{Style.RESET}"); return self.get_peers_copy()
            except json.JSONDecodeError:
                print(f"{Fore.RED}{context_log_prefix}: Malformed JSON response from rendezvous.{Style.RESET}"); return self.get_peers_copy()


            if response_data.get('status') == 'success':
                peers_from_server = response_data.get('peers', {})
                if not isinstance(peers_from_server, dict):
                    print(f"{Fore.RED}{context_log_prefix}: Invalid 'peers' data format in response.{Style.RESET}")
                    # Keep existing self.peers rather than overwriting with bad data
                else:
                    with self.peers_lock: # Acquire lock to update self.peers
                        self.peers = peers_from_server
                        # Filter out self from peer list if present (rendezvous might send it)
                        if self.client_id in self.peers:
                            del self.peers[self.client_id]
                    print(f"Retrieved {len(self.peers)} other peers from rendezvous server.")
            else:
                message = response_data.get('message', 'Unknown error.')
                print(f"{Fore.RED}{context_log_prefix}: Failed to retrieve peer list: {message}{Style.RESET}")
            
            return self.get_peers_copy() # Return a copy of the (potentially updated) peers

        except socket.timeout:
            print(f"{Fore.RED}{context_log_prefix}: Connection to rendezvous timed out.{Style.RESET}")
        except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError) as e: 
            print(f"{Fore.RED}{context_log_prefix}: Connection error ({type(e).__name__}): {e}{Style.RESET}")
            self.connected_to_rendezvous = False # Mark as disconnected on these errors
        except socket.gaierror as e: # For DNS or address errors
            print(f"{Fore.RED}{context_log_prefix}: Address error for {self.rendezvous_host}: {e}{Style.RESET}")
            self.connected_to_rendezvous = False
        except socket.error as e: # General socket errors
            print(f"{Fore.RED}{context_log_prefix}: Socket error: {e}{Style.RESET}")
        except Exception as e: # Catch any other unexpected error
            print(f"{Fore.RED}{context_log_prefix}: Unexpected error: {type(e).__name__} - {e}{Style.RESET}")
        finally:
            if sock:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except (socket.error, OSError): pass
                try:
                    sock.close()
                except (socket.error, OSError): pass
        
        # If any exception occurred, return a copy of the current (possibly stale or empty) peers list
        return self.get_peers_copy()


    def stop(self):
        """
        Stops the P2P client, unregisters from rendezvous, closes sockets,
        and signals threads to terminate.
        """
        print(f"Stopping P2P client {self.client_name} (ID: {self.client_id[:8]})...")
        self.running = False # Signal all threads that rely on this flag to stop their loops

        # Attempt to unregister from rendezvous server
        # Use the renamed attribute self.connected_to_rendezvous
        if self.connected_to_rendezvous: 
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0) # Increased timeout slightly for unregister
                sock.connect((self.rendezvous_host, self.rendezvous_port))
                unregister_data = {'command': 'unregister', 'client_id': self.client_id}
                sock.sendall(json.dumps(unregister_data).encode('utf-8')) # Use sendall
                print(f"Sent unregister request for {self.client_id[:8]}.")
            except (socket.error, json.JSONDecodeError, Exception) as e: # Catch broad exceptions on stop
                # Suppress errors during unregistration on stop, as client is shutting down anyway
                print(f"{Fore.YELLOW}Warning: Could not unregister from rendezvous during stop: {type(e).__name__}{Style.RESET}")
            finally:
                if sock:
                    try: sock.shutdown(socket.SHUT_RDWR)
                    except (socket.error, OSError): pass
                    try: sock.close()
                    except (socket.error, OSError): pass
        
        self.connected_to_rendezvous = False # Mark as disconnected

        # Close the listening socket
        # This will cause the _listen_for_connections thread's accept() to raise an error and exit its loop.
        if self.listen_socket:
            print("Closing listen socket...")
            try:
                # For some OSes, shutting down before closing can help unblock accept()
                self.listen_socket.shutdown(socket.SHUT_RDWR)
            except (socket.error, OSError):
                 # This might fail if socket is already closed or not connected, which is fine.
                pass
            try:
                self.listen_socket.close()
                print("Listen socket closed.")
            except (socket.error, OSError) as e:
                print(f"{Fore.RED}Error closing listen socket: {e}{Style.RESET}")
            self.listen_socket = None # Ensure it's None after closing
        
        self._clear_mek_and_password() # Ensure MEK and temporary password are cleared
        print(f"P2P client {self.client_name} (ID: {self.client_id[:8]}) stopped.")


    def _load_users(self) -> dict:
        """Loads user data from USER_DB_PATH. Returns empty dict on failure."""
        if not os.path.exists(USER_DB_PATH):
            return {} # Normal if no users registered yet
        try:
            with open(USER_DB_PATH, 'r', encoding='utf-8') as f: # Specify encoding
                users_data = json.load(f)
            if not isinstance(users_data, dict):
                print(f"{Fore.YELLOW}Warning: User registry '{USER_DB_PATH}' does not contain a valid JSON object. Returning empty.{Style.RESET}")
                return {}
            return users_data
        except json.JSONDecodeError:
            print(f"{Fore.YELLOW}Warning: User registry '{USER_DB_PATH}' is corrupted (invalid JSON). Returning empty registry.{Style.RESET}")
            return {}
        except (IOError, OSError) as e: # More specific file errors
            print(f"{Fore.RED}File error loading user registry '{USER_DB_PATH}': {e.strerror}{Style.RESET}")
            return {}
        except Exception as e: # Catch-all for other unexpected errors
            print(f"{Fore.RED}Unexpected error loading user registry '{USER_DB_PATH}': {type(e).__name__} - {e}{Style.RESET}")
            return {}


    def _save_users(self, users_dict: dict):
        """Saves user data to USER_DB_PATH."""
        if not isinstance(users_dict, dict):
            print(f"{Style.BOLD}{Fore.RED}Error saving user registry: Input is not a dictionary.{Style.RESET}")
            return # Or raise TypeError

        try:
            with open(USER_DB_PATH, 'w', encoding='utf-8') as f: # Specify encoding
                json.dump(users_dict, f, indent=2)
        except (IOError, OSError) as e: # More specific file errors
            print(f"{Style.BOLD}{Fore.RED}File error saving user registry '{USER_DB_PATH}': {e.strerror}{Style.RESET}")
        except TypeError as e: # If users_dict contains non-JSON-serializable data
            print(f"{Style.BOLD}{Fore.RED}Type error saving user registry (data not JSON serializable?): {e}{Style.RESET}")
        except Exception as e: # Catch-all for other unexpected errors
            print(f"{Style.BOLD}{Fore.RED}Unexpected error saving user registry: {type(e).__name__} - {e}{Style.RESET}")


    def register(self) -> bool:
        """Registers a new user with Argon2 password hashing."""
        users = self._load_users() # Handles its own errors, returns {} on failure
        
        username = input("Choose a username: ").strip()
        if not username:
            print(f"{Style.BOLD}{Fore.RED}Username cannot be empty.{Style.RESET}")
            return False
        if username in users:
            print(f"{Style.BOLD}{Fore.RED}Username '{username}' already exists. Please try a different one.{Style.RESET}")
            return False

        password = input("Choose a password: ").strip()
        if not password: 
            print(f"{Style.BOLD}{Fore.RED}Password cannot be empty.{Style.RESET}")
            return False
            
        try:
            # password_utils.hash_password can raise ValueError or TypeError
            hashed_password_string = password_utils.hash_password(password)
            users[username] = {'hash': hashed_password_string} 
            self._save_users(users) # Handles its own errors
            print(f"{Style.BOLD}{Fore.GREEN}Registration successful for user '{username}'.{Style.RESET}")
            return True
        except (ValueError, TypeError) as e: # From hash_password
            print(f"{Style.BOLD}{Fore.RED}Password hashing error during registration: {e}{Style.RESET}")
            return False
        except Exception as e: # Catch-all for other unexpected errors
            print(f"{Style.BOLD}{Fore.RED}Unexpected error during registration: {type(e).__name__} - {e}{Style.RESET}")
            return False

    def register(self, username: str = None, password: str = None) -> bool: # Added optional params
        """Registers a new user. Uses provided credentials or prompts if None."""
        users = self._load_users() 
        
        # Use provided username or prompt if None
        input_username = username if username is not None else input("Choose a username: ").strip()
        if not input_username:
            print(f"{Style.BOLD}{Fore.RED}Username cannot be empty.{Style.RESET}")
            return False
        if input_username in users:
            print(f"{Style.BOLD}{Fore.RED}Username '{input_username}' already exists. Please try a different one.{Style.RESET}")
            return False

        # Use provided password or prompt if None
        input_password = password if password is not None else input("Choose a password: ").strip()
        if not input_password: 
            print(f"{Style.BOLD}{Fore.RED}Password cannot be empty.{Style.RESET}")
            return False
            
        try:
            hashed_password_string = password_utils.hash_password(input_password)
            users[input_username] = {'hash': hashed_password_string} 
            self._save_users(users) 
            print(f"{Style.BOLD}{Fore.GREEN}Registration successful for user '{input_username}'.{Style.RESET}")
            return True
        except (ValueError, TypeError) as e: # From hash_password
            print(f"{Style.BOLD}{Fore.RED}Password hashing error during registration: {e}{Style.RESET}")
            return False
        except Exception as e: 
            print(f"{Style.BOLD}{Fore.RED}Unexpected error during registration: {type(e).__name__} - {e}{Style.RESET}")
            return False

    def login(self, username: str = None, password: str = None) -> bool: # Added optional params
        """Logs in an existing user. Uses provided credentials or prompts if None."""
        if self.is_logged_in():
            print(f"{Fore.MAGENTA}Already logged in as '{self.logged_in_user}'. Please logout first.{Style.RESET}")
            return True 

        users = self._load_users()
        
        input_username = username if username is not None else input("Username: ").strip()
        
        # Use mek_lock when dealing with _current_password_for_mek
        # password_to_verify will hold the actual password used (either from param or input)
        with self.mek_lock:
            # If password param is given, use it, else prompt.
            # Store it in _current_password_for_mek for MEK derivation if login succeeds.
            self._current_password_for_mek = password if password is not None else input("Password: ").strip()
            password_to_verify = self._current_password_for_mek 

        if not input_username or not password_to_verify:
            print(f"{Style.BOLD}{Fore.RED}Username and password cannot be empty.{Style.RESET}")
            self._clear_mek_and_password() # This handles its own lock
            return False

        if input_username not in users:
            print(f"{Style.BOLD}{Fore.RED}User '{input_username}' not found.{Style.RESET}")
            self._clear_mek_and_password()
            return False

        user_data = users.get(input_username)
        if not user_data: # Should be caught by 'username not in users' but good for robustness
             print(f"{Style.BOLD}{Fore.RED}Internal error: User data not found for '{input_username}'.{Style.RESET}")
             self._clear_mek_and_password(); return False

        stored_hash_str = user_data.get('hash')
        if not stored_hash_str or not stored_hash_str.startswith('$argon2'):
            print(f"{Style.BOLD}{Fore.RED}Error: User '{input_username}' has an invalid or missing password hash.{Style.RESET}")
            self._clear_mek_and_password()
            return False
        
        try:
            if password_utils.verify_password(password_to_verify, stored_hash_str):
                self.logged_in_user = input_username 
                self._derive_and_set_mek(password_to_verify) # This handles its own mek_lock
                
                print(f"{Style.BOLD}{Fore.GREEN}Logged in as {input_username} (Argon2 verified).{Style.RESET}")
                
                with self.mek_lock: # Check MEK under lock
                    if not self.master_encryption_key:
                        print(f"{Style.BOLD}{Fore.YELLOW}Warning: MEK derivation failed post-login. Metadata operations will be affected.{Style.RESET}")
                    else:
                        print(f"Loading file metadata for user {input_username}...")
                        loaded_meta = self._load_file_metadata() # This handles its own mek_lock
                        if not isinstance(loaded_meta, dict): 
                            print(f"{Style.BOLD}{Fore.YELLOW}Warning: Could not properly load file metadata after login.{Style.RESET}")

                if password_utils.needs_rehash(stored_hash_str):
                    print(f"{Fore.YELLOW}Password hash for {input_username} uses outdated Argon2 parameters. Re-hashing...{Style.RESET}")
                    try:
                        new_hashed_password_string = password_utils.hash_password(password_to_verify)
                        users[input_username]['hash'] = new_hashed_password_string 
                        self._save_users(users) 
                        print(f"{Fore.GREEN}Password hash updated to new Argon2 parameters.{Style.RESET}")
                    except (ValueError, TypeError) as e_rehash_hash: 
                        print(f"{Style.BOLD}{Fore.RED}Error during password re-hashing (hashing step): {e_rehash_hash}{Style.RESET}")
                    except Exception as e_rehash_other: 
                        print(f"{Style.BOLD}{Fore.RED}Unexpected error re-hashing password during login: {e_rehash_other}{Style.RESET}")
                
                # On successful login, _current_password_for_mek (which holds the plaintext password)
                # should be cleared if it's no longer needed. _derive_and_set_mek has used it.
                # _clear_mek_and_password() clears both MEK and this temp password.
                # However, we want to keep the MEK. So, just clear the temp password.
                with self.mek_lock:
                    self._current_password_for_mek = None
                return True
            else:
                print(f"{Style.BOLD}{Fore.RED}Invalid password.{Style.RESET}")
                self._clear_mek_and_password() 
                return False
        except (ValueError, TypeError) as e_verify: # From verify_password
            print(f"{Style.BOLD}{Fore.RED}Error during password verification for {input_username}: {e_verify}{Style.RESET}")
            self._clear_mek_and_password()
            return False
        except Exception as e: 
            print(f"{Style.BOLD}{Fore.RED}Unexpected error during login for {input_username}: {type(e).__name__} - {e}{Style.RESET}")
            self._clear_mek_and_password() 
            return False
        
    def is_logged_in(self) -> bool:
        """Checks if a user is currently logged in."""
        return self.logged_in_user is not None

    def logout(self):
        """Logs out the current user and clears sensitive session data."""
        if self.is_logged_in():
            print(f"{Style.BOLD}{Fore.RED}User '{self.logged_in_user}' has been logged out.{Style.RESET}")
            self.logged_in_user = None
            self._clear_mek_and_password() # This handles mek_lock internally
        else:
            print(f"{Fore.YELLOW}No user is currently logged in.{Style.RESET}") # Changed color for consistency

    
    def _notify_rendezvous_of_update(self):
        """Attempts to send an immediate file list update to the rendezvous server."""
        # Use the correct attribute for rendezvous connection status
        if not self.running or not self.connected_to_rendezvous:
            # print(f"Debug ({self.client_name}): Cannot notify rendezvous, not running or connected.")
            return

        sock = None
        try:
            # _scan_shared_folder() was called by share_file before this,
            # so self.shared_files should be up-to-date.
            with self.shared_files_lock:
                files_payload = list(self.shared_files) # Send a copy
            
            # print(f"Debug ({self.client_name}): Notifying rendezvous with {len(files_payload)} files.")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0) # Shorter timeout for a quick update
            sock.connect((self.rendezvous_host, self.rendezvous_port))
            
            update_data = {
                'command': 'update_files',
                'client_id': self.client_id,
                'files': files_payload
            }
            sock.sendall(json.dumps(update_data).encode('utf-8'))
            print(f"{Fore.CYAN}Info ({self.client_name}): Sent immediate file list update to rendezvous.{Style.RESET}")
        except (socket.error, json.JSONDecodeError, ConnectionRefusedError, socket.timeout, BrokenPipeError) as e:
            # These errors are common if rendezvous is temporarily down or busy.
            # The periodic update will try again later.
            print(f"{Fore.YELLOW}Warning ({self.client_name}): Failed to send immediate file list update to rendezvous: {type(e).__name__} - {e}{Style.RESET}")
        except Exception as e: # Catch any other unexpected error
            print(f"{Fore.YELLOW}Warning ({self.client_name}): Unexpected error during immediate rendezvous update: {type(e).__name__} - {e}{Style.RESET}")
        finally:
            if sock:
                try: sock.shutdown(socket.SHUT_RDWR)
                except (socket.error, OSError): pass
                try: sock.close()
                except (socket.error, OSError): pass
    
    
    def printSessionInfo(self):
        """Prints information about the current user session."""
        if self.is_logged_in():
            print(f"{Style.BOLD}{Fore.MAGENTA}Currently logged in as: {self.logged_in_user}{Style.RESET}") 
        else:
            print("Not logged in.")