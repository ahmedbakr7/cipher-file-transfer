import socket
import threading
import json
import time

class RendezvousServer:
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}  # Dictionary to store connected clients {client_id: (ip, port, files)}
        self.lock = threading.Lock()

    def start(self):
        """Start the rendezvous server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            print(f"Rendezvous server started on {self.host}:{self.port}")

            while True:
                client_socket, address = self.server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, address))
                client_thread.daemon = True
                client_thread.start()

        except KeyboardInterrupt:
            print("Server shutdown requested.")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
                print("Server shutdown complete.")

    def handle_client(self, client_socket, address):
        """Handle a client connection"""
        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break

                request = json.loads(data.decode('utf-8'))
                command = request.get('command')

                if command == 'register':
                    self.register_client(client_socket, request, address)
                elif command == 'get_peers':
                    self.send_peers_list(client_socket)
                elif command == 'update_files':
                    self.update_client_files(request)
                elif command == 'unregister':
                    self.unregister_client(request)
                    break

        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            client_socket.close()

    def register_client(self, client_socket, request, address):
        """Register a new client with the server"""
        client_id = request.get('client_id')
        receive_port = request.get('receive_port')
        send_port = request.get('send_port')
        shared_files = request.get('files', [])

        with self.lock:
            self.clients[client_id] = {
                'ip': address[0],
                'receive_port': receive_port,
                'send_port': send_port,
                'files': shared_files,
                'last_seen': time.time()
            }

        print(f"Registered client: {client_id} at {address[0]}:{receive_port}")
        response = {"status": "success", "message": "Registration successful"}
        client_socket.send(json.dumps(response).encode('utf-8'))

    def update_client_files(self, request):
        """Update the list of files a client is sharing"""
        client_id = request.get('client_id')
        files = request.get('files', [])

        with self.lock:
            if client_id in self.clients:
                self.clients[client_id]['files'] = files
                self.clients[client_id]['last_seen'] = time.time()
                print(f"Updated files for client {client_id}: {files}")

    def unregister_client(self, request):
        """Remove a client from the server"""
        client_id = request.get('client_id')

        with self.lock:
            if client_id in self.clients:
                del self.clients[client_id]
                print(f"Unregistered client: {client_id}")

    def send_peers_list(self, client_socket):
        """Send list of all connected peers to the requesting client"""
        with self.lock:
            # Filter out clients that haven't been seen in 5 minutes
            current_time = time.time()
            active_clients = {
                client_id: client_data
                for client_id, client_data in self.clients.items()
                if current_time - client_data['last_seen'] < 300
            }

            response = {
                "status": "success",
                "peers": active_clients
            }
            client_socket.send(json.dumps(response).encode('utf-8'))

if __name__ == "__main__":
    server = RendezvousServer()
    server.start()