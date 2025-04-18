import socket
import threading
import json
import os
import uuid
import time
import upnpclient
import requests
from pathlib import Path


class P2PClient:
    def __init__(self, rendezvous_host='localhost', rendezvous_port=5000, listen_port=0):
        self.client_id = str(uuid.uuid4())
        self.rendezvous_host = rendezvous_host
        self.rendezvous_port = rendezvous_port
        self.listen_port = listen_port
        self.shared_folder = 'shared_files'
        self.downloads_folder = 'downloads'
        self.shared_files = []
        self.peers = {}
        self.listen_socket = None
        self.running = False
        self.connected = False

        # Port forwarding attributes
        self.port_forwarding_active = False
        self.upnp_device = None
        self.external_ip = None
        self.external_port = None
        self.port_mapping = None

        # Create folders if they don't exist
        os.makedirs(self.shared_folder, exist_ok=True)
        os.makedirs(self.downloads_folder, exist_ok=True)

    def start(self):
        """Start the P2P client by setting up listening socket and connecting to rendezvous"""
        self.running = True
        self._setup_listen_socket()
        self._scan_shared_folder()
        self.setup_port_forwarding(self.listen_port)
        self._connect_to_rendezvous()
        self._start_listener_thread()

    def _setup_listen_socket(self):
        """Setup the socket that listens for incoming connections from other peers"""
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # If listen_port is 0, the OS will assign a port
        self.listen_socket.bind(('0.0.0.0', self.listen_port))
        self.listen_port = self.listen_socket.getsockname()[1]  # Get the assigned port
        self.listen_socket.listen(5)
        print(f"Listening for connections on port {self.listen_port}")

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
                    print(f"Error accepting connection: {e}")

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

        print(f"Sharing {len(self.shared_files)} files")

    def _connect_to_rendezvous(self):
        """Connect to the rendezvous server and register this peer"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.rendezvous_host, self.rendezvous_port))

            # Register with the rendezvous server
            register_data = {
                'command': 'register',
                'client_id': self.client_id,
                'port': self.listen_port,
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

            # Start a thread to periodically update the rendezvous server
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
        """Download a file from a specific peer"""
        if peer_id not in self.peers:
            print(f"Peer {peer_id} not found. Try refreshing the peer list.")
            return False

        peer_info = self.peers[peer_id]
        peer_ip = peer_info['ip']
        peer_port = peer_info['port']

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_ip, peer_port))

            # Send file request
            request_data = {
                'type': 'file_request',
                'file_name': file_name
            }
            sock.send(json.dumps(request_data).encode('utf-8'))

            # Receive the file size
            size_data = sock.recv(1024).decode('utf-8')
            size_info = json.loads(size_data)

            if 'error' in size_info:
                print(f"Error from peer: {size_info['error']}")
                sock.close()
                return False

            file_size = size_info['size']
            print(f"Downloading {file_name} ({file_size} bytes)")

            # Acknowledge receipt of file size
            sock.send(b'ready')

            # Create download path and open file
            download_path = os.path.join(self.downloads_folder, file_name)

            with open(download_path, 'wb') as f:
                bytes_received = 0

                while bytes_received < file_size:
                    chunk = sock.recv(min(4096, file_size - bytes_received))
                    if not chunk:
                        break
                    f.write(chunk)
                    bytes_received += len(chunk)

                    # Print progress
                    progress = (bytes_received / file_size) * 100
                    print(f"Download progress: {progress:.1f}%", end='\r')

                print()  # New line after progress

            print(f"File downloaded successfully to {download_path}")
            sock.close()
            return True

        except Exception as e:
            print(f"Error downloading file: {e}")
            return False

    def _send_file(self, client_socket, file_name):
        """Send a file to a peer who requested it"""
        file_path = os.path.join(self.shared_folder, file_name)

        if not os.path.exists(file_path):
            error_response = {'error': 'File not found'}
            client_socket.send(json.dumps(error_response).encode('utf-8'))
            return

        file_size = os.path.getsize(file_path)
        size_info = {'size': file_size}
        client_socket.send(json.dumps(size_info).encode('utf-8'))

        # Wait for acknowledgment
        client_socket.recv(1024)

        # Send the file
        with open(file_path, 'rb') as f:
            bytes_sent = 0
            while bytes_sent < file_size:
                chunk = f.read(4096)
                if not chunk:
                    break
                client_socket.send(chunk)
                bytes_sent += len(chunk)

        print(f"Sent file {file_name} ({file_size} bytes)")

    def share_file(self, file_path):
        """Add a file to the shared folder"""
        if not os.path.exists(file_path):
            print(f"File {file_path} does not exist.")
            return False

        file_name = os.path.basename(file_path)
        dest_path = os.path.join(self.shared_folder, file_name)

        # Copy the file to the shared folder
        try:
            with open(file_path, 'rb') as src_file:
                with open(dest_path, 'wb') as dst_file:
                    dst_file.write(src_file.read())

            print(f"File {file_name} added to shared folder")
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

    def setup_port_forwarding(self, port=None):
        """Set up UPnP port forwarding on the router"""
        if port is None:
            port = self.listen_port
        
        try:
            # Discover UPnP devices on the network
            devices = upnpclient.discover()
            if not devices:
                print("No UPnP devices found on the network")
                return False
            
            # Find a device that supports port mapping
            for device in devices:
                if 'WANIPConnection' in str(device) or 'WANPPPConnection' in str(device):
                    self.upnp_device = device
                    break
            
            if not self.upnp_device:
                print("No UPnP-compatible router found")
                return False
            
            # Get the external IP address
            for service in self.upnp_device.services:
                if 'WANIPConnection' in service.name or 'WANPPPConnection' in service.name:
                    self.external_ip = service.GetExternalIPAddress()['NewExternalIPAddress']
                    
                    # Create a port mapping
                    self.external_port = port
                    response = service.AddPortMapping(
                        NewRemoteHost='',
                        NewExternalPort=port,
                        NewProtocol='TCP',
                        NewInternalPort=port,
                        NewInternalClient=socket.gethostbyname(socket.gethostname()),
                        NewEnabled=1,
                        NewPortMappingDescription='P2P File Sharing',
                        NewLeaseDuration=0
                    )
                    
                    self.port_mapping = {
                        'service': service,
                        'external_port': port,
                        'internal_port': port,
                        'protocol': 'TCP'
                    }
                    self.port_forwarding_active = True
                    return True
            
            return False
        except Exception as e:
            print(f"Port forwarding error: {e}")
            return False

    def check_port_forwarding_status(self):
        """Check the status of port forwarding"""
        status = {
            'active': self.port_forwarding_active,
            'external_ip': None,
            'external_port': None,
            'internal_port': None
        }
        
        if self.port_forwarding_active and self.port_mapping:
            status['external_ip'] = self.external_ip
            status['external_port'] = self.port_mapping['external_port']
            status['internal_port'] = self.port_mapping['internal_port']
            
            # Verify that the port mapping still exists
            try:
                # Try to check if the mapping still exists
                # This is implementation-dependent and might not work on all routers
                pass
            except Exception:
                pass
        
        return status

    def remove_port_forwarding(self):
        """Remove the port forwarding rule"""
        if not self.port_forwarding_active or not self.port_mapping:
            return False
        
        try:
            service = self.port_mapping['service']
            service.DeletePortMapping(
                NewRemoteHost='',
                NewExternalPort=self.port_mapping['external_port'],
                NewProtocol=self.port_mapping['protocol']
            )
            self.port_forwarding_active = False
            return True
        except Exception as e:
            print(f"Failed to remove port mapping: {e}")
            return False

    def stop(self):
        """Stop the P2P client and clean up"""
        # Clean up port forwarding if active
        if self.port_forwarding_active:
            self.remove_port_forwarding()

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