import argparse
import os
import time
from peer import P2PClient
from colored import Fore,Back,Style


logged_in = False

def display_menu(is_logged_in: bool):
    """Show main menu. Swap Login / Logout based on login state."""
    print(f"{Style.BOLD}{Fore.cyan}\n===== P2P File Sharing ====={Style.reset}")
    print("1. List my shared files")
    print("2. List available files from peers")
    print("3. Share a file")
    print("4. Download a file")
    print("5. Refresh peer list")
    print("6. Show connection details")
    print("7. Exit")
    print("8. Retrieve Current Session Info")
    if is_logged_in:
        print("9. Logout")
    else:
        print("9. Login")
    print("============================")
    return input("Enter your choice (1-9): ")



def list_shared_files(client):
    files = client.list_shared_files()
    if not files:
        print(f"{Fore.yellow}\nYou are not currently sharing any files.")
        return

    print(f'{Fore.blue}\nYour shared files:{Style.reset}')
    for idx, file_info in enumerate(files, 1):
        size_kb = file_info['size'] / 1024
        print(f"{idx}. {file_info['name']} ({size_kb:.1f} KB)")

def list_available_files(client):
    files = client.list_available_files()
    if not files:
        print(f'{Style.BOLD}{Fore.red}\nNo files available from peers.{Style.reset}')
        return

    print("\nFiles available for download:")
    for idx, (file_name, sources) in enumerate(files.items(), 1):
        peers_count = len(sources)
        
        size_kb = sources[0]['size'] / 1024
        print(f"{idx}. {file_name} ({size_kb:.1f} KB) - Available from {peers_count} peer(s)")

    return files

def share_file(client):
    global logged_in
    if not logged_in:
        print(f"{Style.BOLD}{Fore.red}Please log in to share files.{Style.reset}")
        return False
    else:
        file_path = input("\nEnter the full path of the file to share: ")
    if not os.path.exists(file_path):
        print(f"{Fore.red}File not found: {file_path}{Style.reset}")
        return

    success = client.share_file(file_path)
    if success:
        print(f'{Style.BOLD}{Fore.green}File is now being shared.{Style.reset}')
    else:
        print(f"{Style.BOLD}{Fore.red}Failed to share the file.{Style.reset}")

def download_file(client):
    global logged_in
    if not logged_in:
        print(f"{Style.BOLD}{Fore.red}Please log in to download files.{Style.reset}")
        return False
    available_files = list_available_files(client)
    if not available_files:
        return
    try:
        selection = int(input("\nEnter the number of the file to download: "))
        if selection < 1 or selection > len(available_files):
            print(f"{Style.BOLD}{Fore.red}Invalid selection.{Style.reset}")
            return

        
        file_name = list(available_files.keys())[selection - 1]
        sources = available_files[file_name]

        print(f"\nSources for {file_name}:")
        for idx, source in enumerate(sources, 1):
            peer_id = source['peer_id'][:8] + "..."  
            size_kb = source['size'] / 1024
            print(f"{idx}. Peer {peer_id} ({size_kb:.1f} KB)")

        source_idx = int(input("\nSelect source (number): "))
        if source_idx < 1 or source_idx > len(sources):
            print(f"{Style.BOLD}{Fore.red}Invalid source selection.{Style.reset}")
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
    
    
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        s.connect((client.rendezvous_host, client.rendezvous_port)) 
        local_ip = s.getsockname()[0]
        s.close()
        print(f"Local IP address: {local_ip}")
    except:
        print("Could not determine local IP address")
    
    
    peers = client.get_peer_list()
    print(f"Connected peers: {len(peers)}")

def main():

    global logged_in

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

        while True:
            print(f"{Style.BOLD}{Fore.cyan}\n=== Authentication ==={Style.reset}")
            print("1. Register")
            print("2. Login")
            print("3. Exit")
            auth_choice = input("Choose an option: ")

            if auth_choice == '1':
                if client.register():
                    continue
            elif auth_choice == '2':
                if client.login():
                    logged_in = True
                    break
            elif auth_choice == '3':
                print(f"{Style.BOLD}{Fore.Green}Goodbye.{Style.reset}")
                return
            else:
                print(f'{Style.BOLD}{Fore.red}Invalid choice.{Style.reset}')


        client.start()
        print(f"Connected to rendezvous server at {args.server}:{args.port}")
        print(f"Your client ID is: {client.client_id}")
        print(f"Receiving connections on port: {client.receive_port}")
        print(f"Sending connections from port: {client.send_port}")

        while True:
            choice = display_menu(logged_in)

            if choice == '1':
                list_shared_files(client)
            elif choice == '2':
                list_available_files(client)
            elif choice == '3':
                share_file(client)
            elif choice == '4':
                download_file(client)
            elif choice == '5':
                print(f"{Style.BOLD}{Fore.cyan}Refreshing peer list...{Style.reset}")
                peers = client.get_peer_list()
                print(f"{Fore.cyan}Found {len(peers)} peers.{Style.reset}")
            elif choice == '6':
                show_connection_details(client)
            elif choice == '7':
                print(f"{Fore.cyan}Exiting...{Style.reset}")
                break
            elif choice == '8':
                client.printSessionInfo()
            elif choice == '9':
                if logged_in:
                    client.logout()
                    logged_in = False  
                    print(f"{Style.BOLD}{Fore.green}Logged out successfully.{Style.reset}")
                else:
                    if client.login():
                        logged_in = True  
                        client.start() 
                        print(f"{Style.BOLD}{Fore.green}Reconnected as {client.client_id}{Style.reset}")
            else:
                print(f'{Style.BOLD}{Fore.red}Invalid choice. Please try again.{Style.reset}')


    except KeyboardInterrupt:
        print("\nShutdown requested...")
    finally:
        print("Stopping P2P client...")
        client.stop()
        print("Goodbye!")

if __name__ == "__main__":
    main()