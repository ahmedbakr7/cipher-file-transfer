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
    print("6. Configure port forwarding")
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

def configure_port_forwarding(client):
    print("\n=== Port Forwarding Configuration ===")
    print("1. Enable UPnP port forwarding")
    print("2. Check port forwarding status")
    print("3. Disable port forwarding")
    print("4. Back to main menu")
    
    choice = input("Enter your choice (1-4): ")
    
    if choice == '1':
        port = input("Enter the port to forward (default is client's listening port): ") or str(client.port)
        success = client.setup_port_forwarding(int(port))
        if success:
            print(f"Successfully set up port forwarding for port {port}")
        else:
            print("Failed to set up port forwarding. Your router may not support UPnP.")
            print("You will need to manually configure port forwarding in your router settings.")
    elif choice == '2':
        status = client.check_port_forwarding_status()
        if status['active']:
            print(f"Port forwarding is active: External port {status['external_port']} -> Internal port {status['internal_port']}")
            print(f"Your external IP address is: {status['external_ip']}")
        else:
            print("Port forwarding is not currently active")
    elif choice == '3':
        success = client.remove_port_forwarding()
        if success:
            print("Port forwarding has been disabled")
        else:
            print("Failed to disable port forwarding")
    elif choice == '4':
        return
    else:
        print("Invalid choice")

def main():
    parser = argparse.ArgumentParser(description="P2P File Sharing Application")
    parser.add_argument("-s", "--server", default="localhost", help="Rendezvous server address")
    parser.add_argument("-p", "--port", type=int, default=5000, help="Rendezvous server port")
    parser.add_argument("--upnp", action="store_true", help="Enable UPnP port forwarding automatically")
    parser.add_argument("--client-port", type=int, default=0, help="Specify client listening port (0 for random)")
    args = parser.parse_args()

    print("Starting P2P File Sharing Application...")
    client = P2PClient(rendezvous_host=args.server, rendezvous_port=args.port, client_port=args.client_port)

    try:
        client.start()
        print(f"Connected to rendezvous server at {args.server}:{args.port}")
        print(f"Your client ID is: {client.client_id}")
        print(f"Your client is listening on port: {client.port}")
        
        # Set up UPnP port forwarding if requested
        if args.upnp:
            print("Setting up UPnP port forwarding...")
            success = client.setup_port_forwarding()
            if success:
                print(f"Port forwarding configured successfully")
            else:
                print("Failed to set up port forwarding. Your router may not support UPnP.")
                print("You can manually configure port forwarding from the menu.")

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
                configure_port_forwarding(client)
            elif choice == '7':
                print("Exiting...")
                break
            else:
                print("Invalid choice. Please try again.")

    except KeyboardInterrupt:
        print("\nShutdown requested...")
    finally:
        # Make sure to clean up port forwarding when exiting
        if hasattr(client, 'port_forwarding_active') and client.port_forwarding_active:
            print("Removing port forwarding rules...")
            client.remove_port_forwarding()
        
        print("Stopping P2P client...")
        client.stop()
        print("Goodbye!")

if __name__ == "__main__":
    main()