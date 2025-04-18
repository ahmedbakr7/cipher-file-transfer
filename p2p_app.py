import argparse
import os
import time
from peer import P2PClient

def display_menu():
    print("\n===== P2P File Sharing =====")
    print("1. List my shared files")
    print("2. List available files from peers")
    print("3. Share a file")
    print("4. Download a file")
    print("5. Refresh peer list")
    print("6. Show connection details")
    print("7. Exit")
    print("============================")
    return input("Enter your choice (1-7): ")

def list_shared_files(client):
    files = client.list_shared_files()
    if not files:
        print("\nYou are not currently sharing any files.")
        return

    print("\nYour shared files:")
    for idx, file_info in enumerate(files, 1):
        size_kb = file_info['size'] / 1024
        print(f"{idx}. {file_info['name']} ({size_kb:.1f} KB)")

def list_available_files(client):
    files = client.list_available_files()
    if not files:
        print("\nNo files available from peers.")
        return

    print("\nFiles available for download:")
    for idx, (file_name, sources) in enumerate(files.items(), 1):
        peers_count = len(sources)
        # Get the size from the first source
        size_kb = sources[0]['size'] / 1024
        print(f"{idx}. {file_name} ({size_kb:.1f} KB) - Available from {peers_count} peer(s)")

    return files

def share_file(client):
    file_path = input("\nEnter the full path of the file to share: ")
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return

    success = client.share_file(file_path)
    if success:
        print(f"File is now being shared.")
    else:
        print("Failed to share the file.")

def download_file(client):
    available_files = list_available_files(client)
    if not available_files:
        return

    try:
        selection = int(input("\nEnter the number of the file to download: "))
        if selection < 1 or selection > len(available_files):
            print("Invalid selection.")
            return

        # Get the file name from the selection
        file_name = list(available_files.keys())[selection - 1]
        sources = available_files[file_name]

        print(f"\nSources for {file_name}:")
        for idx, source in enumerate(sources, 1):
            peer_id = source['peer_id'][:8] + "..."  # Show just part of the UUID
            size_kb = source['size'] / 1024
            print(f"{idx}. Peer {peer_id} ({size_kb:.1f} KB)")

        source_idx = int(input("\nSelect source (number): "))
        if source_idx < 1 or source_idx > len(sources):
            print("Invalid source selection.")
            return

        selected_source = sources[source_idx - 1]
        peer_id = selected_source['peer_id']

        print(f"\nDownloading {file_name} from peer {peer_id[:8]}...")
        success = client.download_file(peer_id, file_name)

        if success:
            print(f"\nDownload complete! File saved to the 'downloads' folder.")
        else:
            print("\nDownload failed.")

    except ValueError:
        print("Please enter a valid number.")
    except Exception as e:
        print(f"Error: {e}")

def show_connection_details(client):
    """Display connection details for the peer"""
    print("\n=== Connection Details ===")
    print(f"Client ID: {client.client_id}")
    print(f"Receiving on port: {client.receive_port}")
    print(f"Sending from port: {client.send_port}")
    print(f"Rendezvous server: {client.rendezvous_host}:{client.rendezvous_port}")
    
    # Try to get local IP address
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't actually connect but helps get local IP
        s.connect((client.rendezvous_host, client.rendezvous_port)) 
        local_ip = s.getsockname()[0]
        s.close()
        print(f"Local IP address: {local_ip}")
    except:
        print("Could not determine local IP address")
    
    # Get peer count
    peers = client.get_peer_list()
    print(f"Connected peers: {len(peers)}")

def main():
    parser = argparse.ArgumentParser(description="P2P File Sharing Application")
    parser.add_argument("-s", "--server", default="localhost", help="Rendezvous server address")
    parser.add_argument("-p", "--port", type=int, default=5000, help="Rendezvous server port")
    parser.add_argument("--receive-port", type=int, default=0, help="Specify port for receiving connections (0 for random)")
    parser.add_argument("--send-port", type=int, default=0, help="Specify port for sending connections (0 for random)")
    parser.add_argument("--client-name", default=None, help="Specify a name for this client")
    args = parser.parse_args()

    print("Starting P2P File Sharing Application...")
    client = P2PClient(rendezvous_host=args.server, rendezvous_port=args.port, 
                       receive_port=args.receive_port, send_port=args.send_port,
                       client_name=args.client_name)

    try:
        client.start()
        print(f"Connected to rendezvous server at {args.server}:{args.port}")
        print(f"Your client ID is: {client.client_id}")
        print(f"Receiving connections on port: {client.receive_port}")
        print(f"Sending connections from port: {client.send_port}")

        while True:
            choice = display_menu()

            if choice == '1':
                list_shared_files(client)
            elif choice == '2':
                list_available_files(client)
            elif choice == '3':
                share_file(client)
            elif choice == '4':
                download_file(client)
            elif choice == '5':
                print("Refreshing peer list...")
                peers = client.get_peer_list()
                print(f"Found {len(peers)} peers.")
            elif choice == '6':
                show_connection_details(client)
            elif choice == '7':
                print("Exiting...")
                break
            else:
                print("Invalid choice. Please try again.")

    except KeyboardInterrupt:
        print("\nShutdown requested...")
    finally:
        print("Stopping P2P client...")
        client.stop()
        print("Goodbye!")

if __name__ == "__main__":
    main()