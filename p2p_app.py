import argparse
import os
import socket # Added for show_connection_details_ui's s.connect
from peer import P2PClient, DEFAULT_CHUNK_SIZE 
from colored import Fore, Style 

g_is_logged_in = False 

def display_menu(is_logged_in_currently: bool):
    """Shows the main menu, dynamically adjusting Login/Logout option."""
    print(f"{Style.BOLD}{Fore.cyan}\n===== CipherShare P2P File Sharing ====={Style.reset}")
    print("1. List my shared files")
    print("2. List available files from peers")
    print("3. Share a file")
    print("4. Download a file")
    print("5. Refresh peer list and show count")
    print("6. Show my connection details")
    print("7. Stop sharing a file") # <<< NEW OPTION
    print("8. Show current session info")
    if is_logged_in_currently:
        print("9. Logout")
    else:
        print("9. Login")
    print("10. Exit") # <<< EXIT IS NOW 10
    print("====================================")
    
    while True:
        choice = input("Enter your choice (1-10): ").strip() # <<< ADJUSTED RANGE
        if choice.isdigit() and 1 <= int(choice) <= 10: # <<< ADJUSTED RANGE
            return choice
        else:
            print(f"{Fore.RED}Invalid choice. Please enter a number between 1 and 10.{Style.RESET}")

def get_valid_path_from_user(prompt_message: str) -> str | None:
    """Prompts user for a file path and validates its existence."""
    while True:
        file_path = input(prompt_message).strip()
        if not file_path:
            print(f"{Fore.YELLOW}File path cannot be empty. Please try again or press Ctrl+C to cancel.{Style.RESET}")
            continue
        
        expanded_path = os.path.expanduser(file_path)
        if os.path.exists(expanded_path):
            if os.path.isfile(expanded_path):
                return expanded_path
            else:
                print(f"{Fore.RED}Path exists but is not a file: {expanded_path}{Style.RESET}")
        else:
            print(f"{Fore.RED}File not found: {expanded_path}{Style.RESET}")

def list_shared_files_ui(client: P2PClient):
    """UI wrapper for listing shared files."""
    files = client.list_shared_files() 
    if not files:
        print(f"{Fore.YELLOW}\nYou are not currently sharing any files.{Style.RESET}")
        return

    print(f"{Fore.BLUE}\nYour shared files:{Style.RESET}")
    for idx, file_info in enumerate(files, 1):
        if isinstance(file_info, dict) and 'name' in file_info and 'size' in file_info:
            size_kb = file_info['size'] / 1024
            print(f"{idx}. {file_info['name']} ({size_kb:.1f} KB)")
        else:
            print(f"{Fore.YELLOW}Warning: Encountered malformed shared file entry.{Style.RESET}")

def list_available_files_ui(client: P2PClient) -> dict | None:
    """UI wrapper for listing available files from peers. Returns files if any."""
    files = client.list_available_files()
    if not files:
        print(f'{Style.BOLD}{Fore.RED}\nNo files available from peers at the moment.{Style.RESET}')
        return None

    print("\nFiles available for download:")
    for idx, (file_name, sources) in enumerate(files.items(), 1):
        if sources and isinstance(sources, list) and sources[0].get('size') is not None:
            peers_count = len(sources)
            size_kb = sources[0]['size'] / 1024 
            print(f"{idx}. {file_name} ({size_kb:.1f} KB) - Available from {peers_count} peer(s)")
        else:
            print(f"{Fore.YELLOW}Warning: Malformed sources list for file '{file_name}'.{Style.RESET}")
    return files

def share_file_ui(client: P2PClient):
    """UI wrapper for sharing a file."""
    global g_is_logged_in
    if not g_is_logged_in:
        print(f"{Style.BOLD}{Fore.RED}Please log in to share files.{Style.RESET}")
        return

    file_path = get_valid_path_from_user("\nEnter the full path of the file to share: ")
    if not file_path:
        print("File sharing cancelled.")
        return

    if client.share_file(file_path):
        print(f'{Style.BOLD}{Fore.GREEN}File is now being shared successfully.{Style.RESET}')
    else:
        print(f"{Style.BOLD}{Fore.RED}Failed to share the file. Check client logs for details.{Style.RESET}")

def download_file_ui(client: P2PClient):
    """UI wrapper for downloading a file."""
    global g_is_logged_in
    if not g_is_logged_in:
        print(f"{Style.BOLD}{Fore.RED}Please log in to download files.{Style.RESET}")
        return

    available_files_dict = list_available_files_ui(client)
    if not available_files_dict:
        return

    file_names_list = list(available_files_dict.keys())

    while True:
        try:
            selection_str = input(f"\nEnter the number of the file to download (1-{len(file_names_list)}), or 0 to cancel: ").strip() # Added cancel option
            if not selection_str: continue
            selection = int(selection_str)
            if selection == 0: print("Download cancelled."); return # Added cancel
            if 1 <= selection <= len(file_names_list):
                break
            else:
                print(f"{Style.BOLD}{Fore.RED}Invalid selection. Number out of range.{Style.RESET}")
        except ValueError:
            print(f"{Style.BOLD}{Fore.RED}Invalid input. Please enter a number.{Style.RESET}")

    selected_file_name = file_names_list[selection - 1]
    sources = available_files_dict[selected_file_name]

    selected_source_peer_id = None
    if len(sources) > 1:
        print(f"\nSources for {selected_file_name}:")
        for idx, source in enumerate(sources, 1):
            peer_id_short = source.get('peer_id', 'UnknownPeerID')[:8] + "..."  
            size_kb = source.get('size', 0) / 1024
            print(f"{idx}. Peer {peer_id_short} ({size_kb:.1f} KB)")
        
        while True:
            try:
                source_idx_str = input(f"\nSelect source (1-{len(sources)}), or 0 to cancel: ").strip() # Added cancel
                if not source_idx_str: continue
                source_idx = int(source_idx_str)
                if source_idx == 0: print("Download cancelled."); return # Added cancel
                if 1 <= source_idx <= len(sources):
                    selected_source_peer_id = sources[source_idx - 1]['peer_id']
                    break
                else:
                    print(f"{Style.BOLD}{Fore.RED}Invalid source selection. Number out of range.{Style.RESET}")
            except ValueError:
                print(f"{Style.BOLD}{Fore.RED}Invalid input. Please enter a number.{Style.RESET}")
    elif sources: 
        selected_source_peer_id = sources[0]['peer_id']
    
    if not selected_source_peer_id:
        print(f"{Fore.RED}No valid source selected for {selected_file_name}, cannot download.{Style.RESET}")
        return
        
    print(f"\nDownloading {selected_file_name} from peer {selected_source_peer_id[:8]}...")
    if client.download_file(selected_source_peer_id, selected_file_name):
        print(f"\n{Fore.GREEN}Download complete! File saved to '{client.downloads_folder_path}'.{Style.RESET}")
    else:
        print(f"\n{Fore.RED}Download failed. Check client logs for details.{Style.RESET}")

# <<< NEW UI FUNCTION >>>
def stop_sharing_file_ui(client: P2PClient):
    """UI wrapper for stopping the sharing of a file."""
    global g_is_logged_in
    if not g_is_logged_in:
        print(f"{Style.BOLD}{Fore.RED}Please log in to manage shared files.{Style.RESET}")
        return

    shared_files = client.list_shared_files() 
    if not shared_files:
        print(f"{Fore.YELLOW}\nYou are not currently sharing any files to stop.{Style.RESET}")
        return

    print(f"{Fore.BLUE}\nYour currently shared files:{Style.RESET}")
    for idx, file_info in enumerate(shared_files, 1):
        if isinstance(file_info, dict) and 'name' in file_info: # Size not strictly needed here
            print(f"{idx}. {file_info['name']}")
        else:
            print(f"{idx}. Malformed file entry") # Should not happen if list_shared_files_ui is robust
    
    while True:
        try:
            selection_str = input(f"\nEnter the number of the file to stop sharing (1-{len(shared_files)}), or 0 to cancel: ").strip()
            if not selection_str: continue
            selection = int(selection_str)
            if selection == 0:
                print("Operation cancelled.")
                return
            if 1 <= selection <= len(shared_files):
                break
            else:
                print(f"{Style.BOLD}{Fore.RED}Invalid selection. Number out of range.{Style.RESET}")
        except ValueError:
            print(f"{Style.BOLD}{Fore.RED}Invalid input. Please enter a number.{Style.RESET}")

    # Ensure the selected file_info is a dictionary and has a 'name'
    if isinstance(shared_files[selection - 1], dict) and 'name' in shared_files[selection - 1]:
        file_to_stop = shared_files[selection - 1]['name']
    else:
        print(f"{Fore.RED}Error: Selected file entry is malformed. Cannot proceed.{Style.RESET}")
        return
    
    confirm = input(f"{Fore.YELLOW}Are you sure you want to stop sharing '{file_to_stop}'? (yes/no): {Style.RESET}").strip().lower()
    if confirm != 'yes':
        print("Operation cancelled by user.")
        return

    if client.stop_sharing_file(file_to_stop): # P2PClient.stop_sharing_file prints its own success
        pass 
    else:
        # P2PClient.stop_sharing_file should print specific errors. This is a fallback.
        print(f"{Fore.RED}Could not stop sharing '{file_to_stop}'. Check client logs for details.{Style.RESET}")


def show_connection_details_ui(client: P2PClient):
    """UI wrapper for showing connection details."""
    print("\n=== Connection Details ===")
    print(f"Client Name: {client.client_name} (ID: {client.client_id})")
    print(f"Listening on port: {client.receive_port}")
    print(f"Sending from port: {client.send_port}") 
    print(f"Rendezvous Server: {client.rendezvous_host}:{client.rendezvous_port}")
    
    s_info = None # Define s_info to ensure it's in scope for finally
    try:
        s_info = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s_info.settimeout(0.5) 
        s_info.connect((client.rendezvous_host, client.rendezvous_port)) 
        local_ip = s_info.getsockname()[0]
        print(f"Local IP (best guess): {local_ip}")
    except Exception: 
        print(f"{Fore.YELLOW}Could not determine local IP address for rendezvous connection.{Style.RESET}")
    finally:
        if s_info: s_info.close() 
    
    peers_dict = client.get_peer_list() 
    print(f"Connected to {len(peers_dict)} other peers.")


def main():
    global g_is_logged_in 

    parser = argparse.ArgumentParser(description="CipherShare: Secure P2P File Sharing Application")
    parser.add_argument("-s", "--server", default="127.0.0.1", help="Rendezvous server address (default: 127.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=5050, help="Rendezvous server port (default: 5050)")
    parser.add_argument("--receive-port", type=int, default=0, help="Port for receiving connections (0 for random OS-assigned)")
    parser.add_argument("--send-port", type=int, default=0, help="Port for sending connections (0 for random OS-assigned)")
    parser.add_argument("--client-name", default=None, help="Persistent name for this client instance (recommended)")
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE, help=f"Chunk size for transfers in bytes (default: {DEFAULT_CHUNK_SIZE})")
    args = parser.parse_args()

    print("Starting CipherShare P2P Application...")
    client_instance = None # Initialize to None for finally block
    try:
        client_instance = P2PClient(rendezvous_host=args.server, 
                           rendezvous_port=args.port, 
                           receive_port=args.receive_port, 
                           send_port=args.send_port,
                           client_name=args.client_name,
                           chunk_size=args.chunk_size)

        auth_success = False
        while not auth_success:
            print(f"{Style.BOLD}{Fore.cyan}\n=== Authentication Required ==={Style.RESET}")
            print("1. Register new account")
            print("2. Login to existing account")
            print("3. Exit application")
            auth_choice = input("Choose an option (1-3): ").strip()

            if auth_choice == '1':
                if client_instance.register(): 
                    print(f"{Fore.GREEN}Registration successful. Please log in.{Style.RESET}")
                    if client_instance.login(): 
                        g_is_logged_in = True
                        auth_success = True
            elif auth_choice == '2':
                if client_instance.login():
                    g_is_logged_in = True
                    auth_success = True
            elif auth_choice == '3':
                print(f"{Fore.GREEN}Exiting application.{Style.RESET}")
                # client_instance.stop() will be called in finally
                return 
            else:
                print(f'{Style.BOLD}{Fore.RED}Invalid authentication choice. Please try again.{Style.RESET}')

        if not g_is_logged_in: 
            print(f"{Fore.RED}Authentication failed. Exiting.{Style.RESET}")
            # client_instance.stop() will be called in finally
            return

        client_instance.start() 
        if not client_instance.running: 
            print(f"{Fore.RED}Client failed to start properly. Please check logs. Exiting.{Style.RESET}")
            return

        print(f"{Fore.GREEN}Successfully connected to rendezvous server at {args.server}:{args.port}{Style.RESET}")
        print(f"Your Client Name: {client_instance.client_name} (ID: {client_instance.client_id})")
        print(f"Listening for connections on port: {client_instance.receive_port}")
        print(f"Sending connections from port: {client_instance.send_port}")

        while True:
            choice = display_menu(g_is_logged_in) 

            if choice == '1': list_shared_files_ui(client_instance)
            elif choice == '2': list_available_files_ui(client_instance)
            elif choice == '3': share_file_ui(client_instance)
            elif choice == '4': download_file_ui(client_instance)
            elif choice == '5':
                print(f"{Style.BOLD}{Fore.CYAN}Refreshing peer list...{Style.RESET}")
                peers = client_instance.get_peer_list() 
                print(f"{Fore.CYAN}Found {len(peers)} other peers.{Style.RESET}")
            elif choice == '6': show_connection_details_ui(client_instance)
            elif choice == '7': # <<< New: Stop sharing a file
                stop_sharing_file_ui(client_instance)
            elif choice == '8': client_instance.printSessionInfo() 
            elif choice == '9': # Login/Logout
                if g_is_logged_in:
                    client_instance.logout() 
                    g_is_logged_in = False  
                    print(f"{Style.BOLD}{Fore.GREEN}Logged out successfully.{Style.RESET}")
                else: 
                    if client_instance.login():
                        g_is_logged_in = True
                        if not client_instance.running: 
                            print(f"{Fore.YELLOW}Client was not fully running. Attempting to restart services...{Style.RESET}")
                            client_instance.start() 
                            if not client_instance.running:
                                print(f"{Fore.RED}Failed to restart client services after login. Exiting.{Style.RESET}")
                                break 
                        print(f"{Style.BOLD}{Fore.GREEN}Logged in successfully as {client_instance.client_name}.{Style.RESET}")
            elif choice == '10': # <<< New: Exit
                print(f"{Fore.CYAN}Exiting application...{Style.RESET}")
                break 
    except KeyboardInterrupt:
        print("\nShutdown requested by user (Ctrl+C)...")
    except Exception as e: 
        print(f"{Style.BOLD}{Fore.RED}\nAn unexpected error occurred in the application: {type(e).__name__} - {e}{Style.RESET}")
        import traceback
        traceback.print_exc()
    finally:
        print("Stopping P2P client services...")
        if client_instance: # Check if client_instance was successfully created
            client_instance.stop() 
        print("CipherShare application terminated. Goodbye!")

if __name__ == "__main__":
    main()