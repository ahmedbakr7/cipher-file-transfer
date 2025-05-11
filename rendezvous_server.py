import socket
import threading
import json
import time
from colored import Fore, Style # Assuming you might want colored output here too

# Define a timeout for client inactivity (e.g., 5 minutes = 300 seconds)
# This was already used in send_peers_list, making it a constant is good.
CLIENT_TIMEOUT_SECONDS = 300 
# Define a default buffer size for receiving data from clients
DEFAULT_RECV_BUFFER_SIZE = 4096

class RendezvousServer:
    def __init__(self, host='0.0.0.0', port=5050): # Default host to 0.0.0.0
        self.host = host
        self.port = port
        self.server_socket: socket.socket = None # Type hint
        self.clients = {}  # client_id -> { 'ip': str, 'receive_port': int, 'send_port': int, 'files': list, 'last_seen': float }
        self.lock = threading.Lock() # Protects self.clients
        self.running = True # Flag to control the main server loop

    def start(self):
        """Initializes and starts the rendezvous server."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10) # Listen backlog
            # Corrected line:
            print(f"{Style.BOLD}{Fore.GREEN}Rendezvous server started on {self.host}:{self.port}{Style.RESET}")
        except socket.error as e:
            print(f"{Style.BOLD}{Fore.RED}Fatal Error: Could not start rendezvous server: {e}{Style.RESET}")
            self.running = False
            return # Cannot proceed
        except Exception as e: # Catch any other unexpected error during setup
            print(f"{Style.BOLD}{Fore.RED}Unexpected fatal error during server setup: {e}{Style.RESET}")
            self.running = False
            return

        # Start a thread to periodically clean up inactive clients
        cleanup_thread = threading.Thread(target=self._cleanup_inactive_clients_periodically, daemon=True)
        cleanup_thread.name = "RendezvousClientCleanupThread"
        cleanup_thread.start()

        while self.running:
            try:
                self.server_socket.settimeout(1.0) 
                client_socket, address = self.server_socket.accept()
                client_socket.settimeout(10.0) 

                print(f"Accepted connection from {address}")
                client_thread = threading.Thread(
                    target=self.handle_client, 
                    args=(client_socket, address),
                    name=f"ClientHandler-{address[0]}-{address[1]}"
                )
                client_thread.daemon = True 
                client_thread.start()
            except socket.timeout:
                continue 
            except socket.error as e: 
                if self.running: 
                    print(f"{Fore.RED}Error accepting new connection: {e}{Style.RESET}")
                if not self.running: break 
            except Exception as e: 
                 if self.running:
                    print(f"{Style.BOLD}{Fore.RED}Unexpected error in server accept loop: {e}{Style.RESET}")
                 break 

        print("Rendezvous server main loop terminated.")


    def stop_server(self):
        """Signals the server to stop and closes the server socket."""
        print("Rendezvous server shutting down...")
        self.running = False
        if self.server_socket:
            try:
                # To unblock accept(), connect to it briefly (optional, OS dependent)
                # Or rely on the timeout on accept()
                self.server_socket.close()
            except socket.error as e:
                print(f"{Fore.YELLOW}Warning: Error closing server socket: {e}{Style.RESET}")
        print("Rendezvous server shutdown signal sent.")


    def handle_client(self, client_socket: socket.socket, address: tuple):
        """Handles communication with a connected client."""
        client_id_for_log = None # For logging if unregister happens
        try:
            while self.running: # Check server running state
                try:
                    # Set timeout for recv, otherwise it can block indefinitely if client misbehaves
                    client_socket.settimeout(60.0) # e.g., 60 seconds for a request
                    data_bytes = client_socket.recv(DEFAULT_RECV_BUFFER_SIZE)
                    client_socket.settimeout(None) # Reset after successful recv
                except socket.timeout:
                    print(f"{Fore.YELLOW}Timeout receiving data from {address}. Closing connection.{Style.RESET}")
                    break
                except (ConnectionResetError, BrokenPipeError, socket.error) as e:
                    print(f"{Fore.YELLOW}Socket error receiving from {address}: {e}. Closing connection.{Style.RESET}")
                    break

                if not data_bytes:
                    print(f"Client {address} disconnected (no data).")
                    break # Connection closed by client

                try:
                    request_str = data_bytes.decode('utf-8')
                    request = json.loads(request_str)
                except UnicodeDecodeError:
                    print(f"{Fore.RED}Invalid UTF-8 data from {address}. Ignoring.{Style.RESET}")
                    # Optionally send error back, but client might be malicious/broken
                    self._send_json_response(client_socket, {'status': 'error', 'message': 'Invalid UTF-8 data.'})
                    continue # Or break, depending on policy
                except json.JSONDecodeError:
                    print(f"{Fore.RED}Invalid JSON from {address}. Ignoring.{Style.RESET}")
                    self._send_json_response(client_socket, {'status': 'error', 'message': 'Invalid JSON format.'})
                    continue # Or break

                command = request.get('command')
                client_id_for_log = request.get('client_id', 'UnknownClient') # For logging

                if command == 'register':
                    self.register_client(client_socket, request, address)
                elif command == 'get_peers':
                    self.send_peers_list(client_socket, client_id_for_log) # Pass client_id for filtering self
                elif command == 'update_files':
                    self.update_client_files(request) # This doesn't send a response
                elif command == 'unregister':
                    self.unregister_client(request)
                    print(f"Client {client_id_for_log} at {address} explicitly unregistered. Closing connection.")
                    break # Exit loop after unregister
                else:
                    print(f"{Fore.YELLOW}Unknown command '{command}' from {address}.{Style.RESET}")
                    self._send_json_response(client_socket, {'status': 'error', 'message': f"Unknown command: {command}"})
        
        except Exception as e: # Catch-all for unexpected errors in this client handler thread
            print(f"{Style.BOLD}{Fore.RED}Unexpected error handling client {client_id_for_log or address}: {type(e).__name__} - {e}{Style.RESET}")
            # import traceback; traceback.print_exc() # For debugging
        finally:
            print(f"Closing connection for client {client_id_for_log or address}.")
            try:
                client_socket.shutdown(socket.SHUT_RDWR)
            except (socket.error, OSError): pass
            try:
                client_socket.close()
            except (socket.error, OSError): pass


    def _send_json_response(self, client_socket: socket.socket, response_data: dict):
        """Helper to send a JSON response to a client, handling potential errors."""
        try:
            client_socket.sendall(json.dumps(response_data).encode('utf-8'))
        except (socket.error, BrokenPipeError, ConnectionResetError) as e:
            print(f"{Fore.YELLOW}Could not send response to client: {e}{Style.RESET}")


    def register_client(self, client_socket: socket.socket, request: dict, address: tuple):
        client_id = request.get('client_id')
        # Basic validation of received data
        try:
            receive_port = int(request.get('receive_port', 0))
            send_port = int(request.get('send_port', 0)) # Can be 0 if client lets OS pick
            shared_files = request.get('files', [])
            if not client_id or not isinstance(receive_port, int) or receive_port <= 0 or \
               not isinstance(send_port, int) or send_port < 0 or not isinstance(shared_files, list):
                raise ValueError("Invalid registration data types or values.")
            # Further validation for shared_files structure could be added here
            for item in shared_files:
                if not isinstance(item, dict) or 'name' not in item or 'size' not in item:
                    raise ValueError("Invalid file entry in shared_files list.")
        except (ValueError, TypeError) as e:
            print(f"{Fore.RED}Invalid registration data from {address} for client '{client_id}': {e}{Style.RESET}")
            self._send_json_response(client_socket, {'status': 'error', 'message': f"Invalid registration data: {e}"})
            return

        with self.lock:
            self.clients[client_id] = {
                'ip': address[0], # Use the IP from the connection, not from client (security)
                'receive_port': receive_port,
                'send_port': send_port,
                'files': shared_files,
                'last_seen': time.time()
            }
        print(f"Registered client: {client_id[:12]}... at {address[0]}:{receive_port}")
        self._send_json_response(client_socket, {"status": "success", "message": "Registration successful"})


    def update_client_files(self, request: dict):
        client_id = request.get('client_id')
        files = request.get('files', []) # Default to empty list if not provided

        if not client_id:
            print(f"{Fore.YELLOW}Update files: Received request with no client_id.{Style.RESET}")
            return # No client_socket to send error to here, as client doesn't wait for response

        # Basic validation
        if not isinstance(files, list):
            print(f"{Fore.YELLOW}Update files: Invalid 'files' data type from {client_id}. Ignoring.{Style.RESET}")
            return
        for item in files:
            if not isinstance(item, dict) or 'name' not in item or 'size' not in item:
                print(f"{Fore.YELLOW}Update files: Invalid file entry in 'files' list from {client_id}. Ignoring update.{Style.RESET}")
                return

        with self.lock:
            if client_id in self.clients:
                self.clients[client_id]['files'] = files
                self.clients[client_id]['last_seen'] = time.time()
                # print(f"Updated files for client {client_id[:12]}... ({len(files)} files)") # Verbose
            else:
                print(f"{Fore.YELLOW}Update files: Client {client_id} not registered. Ignoring update.{Style.RESET}")
        # No response is sent for 'update_files' command by current design


    def unregister_client(self, request: dict):
        client_id = request.get('client_id')
        if not client_id:
            print(f"{Fore.YELLOW}Unregister: Received request with no client_id.{Style.RESET}")
            return # No client_socket to send error to here

        removed = False
        with self.lock:
            if client_id in self.clients:
                del self.clients[client_id]
                removed = True
        if removed:
            print(f"Unregistered client: {client_id[:12]}...")
        else:
            print(f"{Fore.YELLOW}Unregister: Client {client_id} not found for unregistration.{Style.RESET}")
        # No response typically sent for unregister, as client might be disconnecting


    def send_peers_list(self, client_socket: socket.socket, requesting_client_id: str):
        active_clients_payload = {}
        with self.lock:
            current_time = time.time()
            # Create a new dict for the response to avoid sending internal structures directly
            # and to filter out the requesting client itself.
            for client_id, client_data in self.clients.items():
                if client_id == requesting_client_id: # Don't send the client its own info
                    continue
                if (current_time - client_data.get('last_seen', 0)) < CLIENT_TIMEOUT_SECONDS:
                    # Only include necessary info for peer discovery
                    active_clients_payload[client_id] = {
                        'ip': client_data['ip'],
                        'receive_port': client_data['receive_port'],
                        # 'send_port': client_data['send_port'], # Optional, client usually doesn't need this for connection
                        'files': client_data.get('files', []) # Send files list
                    }
        
        response = {"status": "success", "peers": active_clients_payload}
        self._send_json_response(client_socket, response)

    def _cleanup_inactive_clients_periodically(self):
        """Periodically removes clients that haven't been seen for CLIENT_TIMEOUT_SECONDS."""
        while self.running:
            time.sleep(CLIENT_TIMEOUT_SECONDS / 2) # Check somewhat frequently
            if not self.running: break

            inactive_clients_to_remove = []
            current_time = time.time()
            with self.lock: # Hold lock while iterating and identifying
                for client_id, client_data in self.clients.items():
                    if (current_time - client_data.get('last_seen', 0)) >= CLIENT_TIMEOUT_SECONDS:
                        inactive_clients_to_remove.append(client_id)
            
            if inactive_clients_to_remove: # Perform removal outside the main iteration lock if possible
                with self.lock: # Re-acquire lock for modification
                    for client_id in inactive_clients_to_remove:
                        if client_id in self.clients: # Check again, state might have changed
                            del self.clients[client_id]
                            print(f"{Fore.CYAN}Cleaned up inactive client: {client_id[:12]}...{Style.RESET}")
        print(f"{Fore.CYAN}Client cleanup thread finished.{Style.RESET}")

# Main execution block
if __name__ == "__main__":
    server = RendezvousServer()
    try:
        server.start() # This now blocks until server.running is False or an error occurs
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt received. Shutting down server...")
    except Exception as e: # Catch any other exception that might bring down start()
        print(f"{Style.BOLD}{Fore.RED}Rendezvous server crashed: {e}{Style.RESET}")
        import traceback
        traceback.print_exc()
    finally:
        server.stop_server() # Ensure stop_server is called to attempt cleanup