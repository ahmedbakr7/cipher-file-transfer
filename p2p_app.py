import argparse
import os
from peer import P2PClient, DEFAULT_CHUNK_SIZE # Assuming P2PClient is in peer.py
from colored import Fore, Style # Assuming 'colored' library is used

# Global variable for login state, managed by main()
# This is okay for a simple CLI app, but for more complex UIs,
# passing state or using a UI framework's state management is better.
g_is_logged_in = False 

def display_menu(is_logged_in_currently: bool): # Parameter name changed for clarity
    """Shows the main menu, dynamically adjusting Login/Logout option."""
    print(f"{Style.BOLD}{Fore.cyan}\n===== CipherShare P2P File Sharing ====={Style.reset}")
    print("1. List my shared files")
    print("2. List available files from peers")
    print("3. Share a file")
    print("4. Download a file")
    print("5. Refresh peer list and show count") # Clarified action
    print("6. Show my connection details")    # Clarified action
    print("7. Exit")
    print("8. Show current session info")     # Clarified action
    if is_logged_in_currently:
        print("9. Logout")
    else:
        print("9. Login")
    print("====================================")
    
    while True:
        choice = input("Enter your choice (1-9): ").strip()
        if choice.isdigit() and 1 <= int(choice) <= 9:
            return choice
        else:
            print(f"{Fore.RED}Invalid choice. Please enter a number between 1 and 9.{Style.RESET}")

def get_valid_path_from_user(prompt_message: str) -> str | None:
    """Prompts user for a file path and validates its existence."""
    while True:
        file_path = input(prompt_message).strip()
        if not file_path:
            print(f"{Fore.YELLOW}File path cannot be empty. Please try again or press Ctrl+C to cancel.{Style.RESET}")
            continue # Re-prompt
        
        # Basic tilde expansion for user convenience
        expanded_path = os.path.expanduser(file_path)

        if os.path.exists(expanded_path):
            if os.path.isfile(expanded_path):
                return expanded_path
            else:
                print(f"{Fore.RED}Path exists but is not a file: {expanded_path}{Style.RESET}")
        else:
            print(f"{Fore.RED}File not found: {expanded_path}{Style.RESET}")
        
        # Option to cancel if path is repeatedly wrong
        # retry = input("Try a different path? (yes/no): ").strip().lower()
        # if retry != 'yes':
        #     return None


def list_shared_files_ui(client: P2PClient): # Renamed for clarity (UI function)
    """UI wrapper for listing shared files."""
    # P2PClient.list_shared_files() now returns a copy of the list
    files = client.list_shared_files() 
    if not files: # Handles empty list or None if P2PClient.list_shared_files could return None
        print(f"{Fore.YELLOW}\nYou are not currently sharing any files.{Style.RESET}")
        return

    print(f"{Fore.BLUE}\nYour shared files:{Style.RESET}")
    for idx, file_info in enumerate(files, 1):
        # Ensure file_info is a dict and has expected keys
        if isinstance(file_info, dict) and 'name' in file_info and 'size' in file_info:
            size_kb = file_info['size'] / 1024
            print(f"{idx}. {file_info['name']} ({size_kb:.1f} KB)")
        else:
            print(f"{Fore.YELLOW}Warning: Encountered malformed shared file entry.{Style.RESET}")


def list_available_files_ui(client: P2PClient) -> dict | None: # Renamed for clarity
    """UI wrapper for listing available files from peers. Returns files if any."""
    # P2PClient.list_available_files() now returns a dict (possibly empty)
    files = client.list_available_files()
    if not files: # Handles empty dict or None
        print(f'{Style.BOLD}{Fore.RED}\nNo files available from peers at the moment.{Style.RESET}')
        return None # Explicitly return None

    print("\nFiles available for download:")
    for idx, (file_name, sources) in enumerate(files.items(), 1):
        if sources and isinstance(sources, list) and sources[0].get('size') is not None:
            peers_count = len(sources)
            size_kb = sources[0]['size'] / 1024 # Assumes first source has representative size
            print(f"{idx}. {file_name} ({size_kb:.1f} KB) - Available from {peers_count} peer(s)")
        else:
            print(f"{Fore.YELLOW}Warning: Malformed sources list for file '{file_name}'.{Style.RESET}")
    return files


def share_file_ui(client: P2PClient): # Renamed for clarity
    """UI wrapper for sharing a file."""
    global g_is_logged_in # Use the global login state
    if not g_is_logged_in:
        print(f"{Style.BOLD}{Fore.RED}Please log in to share files.{Style.RESET}")
        return

    file_path = get_valid_path_from_user("\nEnter the full path of the file to share: ")
    if not file_path: # User cancelled or path validation failed
        print("File sharing cancelled.")
        return

    # P2PClient.share_file now returns True/False
    if client.share_file(file_path):
        print(f'{Style.BOLD}{Fore.GREEN}File is now being shared successfully.{Style.RESET}')
    else:
        # P2PClient.share_file should print specific errors. This is a fallback.
        print(f"{Style.BOLD}{Fore.RED}Failed to share the file. Check client logs for details.{Style.RESET}")


def download_file_ui(client: P2PClient): # Renamed for clarity
    """UI wrapper for downloading a file."""
    global g_is_logged_in
    if not g_is_logged_in:
        print(f"{Style.BOLD}{Fore.RED}Please log in to download files.{Style.RESET}")
        return

    available_files_dict = list_available_files_ui(client)
    if not available_files_dict: # No files or UI function returned None
        return

    # Convert dict keys to a list for indexed access
    file_names_list = list(available_files_dict.keys())

    while True:
        try:
            selection_str = input(f"\nEnter the number of the file to download (1-{len(file_names_list)}): ").strip()
            if not selection_str: continue # Re-prompt if empty
            selection = int(selection_str)
            if 1 <= selection <= len(file_names_list):
                break
            else:
                print(f"{Style.BOLD}{Fore.RED}Invalid selection. Number out of range.{Style.RESET}")
        except ValueError:
            print(f"{Style.BOLD}{Fore.RED}Invalid input. Please enter a number.{Style.RESET}")

    selected_file_name = file_names_list[selection - 1]
    sources = available_files_dict[selected_file_name]

    if len(sources) > 1:
        print(f"\nSources for {selected_file_name}:")
        for idx, source in enumerate(sources, 1):
            peer_id_short = source.get('peer_id', 'UnknownPeerID')[:8] + "..."  
            size_kb = source.get('size', 0) / 1024
            print(f"{idx}. Peer {peer_id_short} ({size_kb:.1f} KB)")
        
        while True:
            try:
                source_idx_str = input(f"\nSelect source (1-{len(sources)}): ").strip()
                if not source_idx_str: continue
                source_idx = int(source_idx_str)
                if 1 <= source_idx <= len(sources):
                    break
                else:
                    print(f"{Style.BOLD}{Fore.RED}Invalid source selection. Number out of range.{Style.RESET}")
            except ValueError:
                print(f"{Style.BOLD}{Fore.RED}Invalid input. Please enter a number.{Style.RESET}")
        selected_source_peer_id = sources[source_idx - 1]['peer_id']
    elif sources: # Only one source
        selected_source_peer_id = sources[0]['peer_id']
    else: # Should not happen if list_available_files_ui worked
        print(f"{Fore.RED}No sources found for {selected_file_name}, cannot download.{Style.RESET}")
        return
        
    print(f"\nDownloading {selected_file_name} from peer {selected_source_peer_id[:8]}...")
    # P2PClient.download_file now returns True/False
    if client.download_file(selected_source_peer_id, selected_file_name):
        print(f"\n{Fore.GREEN}Download complete! File saved to the '{client.downloads_folder_path}'.{Style.RESET}")
    else:
        # P2PClient.download_file should print specific errors. This is a fallback.
        print(f"\n{Fore.RED}Download failed. Check client logs for details.{Style.RESET}")


def show_connection_details_ui(client: P2PClient): # Renamed for clarity
    """UI wrapper for showing connection details."""
    print("\n=== Connection Details ===")
    print(f"Client Name: {client.client_name} (ID: {client.client_id})")
    print(f"Listening on port: {client.receive_port}")
    print(f"Sending from port: {client.send_port}") # Clarified
    print(f"Rendezvous Server: {client.rendezvous_host}:{client.rendezvous_port}")
    
    try:
        # Attempt to determine local IP used for rendezvous connection (best effort)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5) # Prevent long block if rendezvous is unreachable
        s.connect((client.rendezvous_host, client.rendezvous_port)) 
        local_ip = s.getsockname()[0]
        print(f"Local IP (best guess): {local_ip}")
    except Exception: # Catch all exceptions for this non-critical info
        print(f"{Fore.YELLOW}Could not determine local IP address for rendezvous connection.{Style.RESET}")
    finally:
        if 's' in locals() and s: s.close() # Ensure socket is closed
    
    # P2PClient.get_peer_list() now returns a copy of the peers dict
    peers_dict = client.get_peer_list() 
    print(f"Connected to {len(peers_dict)} other peers.")


def main():
    global g_is_logged_in # Use the global login state

    parser = argparse.ArgumentParser(description="CipherShare: Secure P2P File Sharing Application")
    parser.add_argument("-s", "--server", default="127.0.0.1", help="Rendezvous server address (default: 127.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=5050, help="Rendezvous server port (default: 5050)")
    parser.add_argument("--receive-port", type=int, default=0, help="Port for receiving connections (0 for random OS-assigned)")
    parser.add_argument("--send-port", type=int, default=0, help="Port for sending connections (0 for random OS-assigned)")
    parser.add_argument("--client-name", default=None, help="Persistent name for this client instance (recommended)")
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE, help=f"Chunk size for transfers in bytes (default: {DEFAULT_CHUNK_SIZE})")
    args = parser.parse_args()

    print("Starting CipherShare P2P Application...")
    client = P2PClient(rendezvous_host=args.server, 
                       rendezvous_port=args.port, 
                       receive_port=args.receive_port, 
                       send_port=args.send_port,
                       client_name=args.client_name,
                       chunk_size=args.chunk_size)

    # Initial authentication loop
    auth_success = False
    while not auth_success:
        print(f"{Style.BOLD}{Fore.cyan}\n=== Authentication Required ==={Style.RESET}")
        print("1. Register new account")
        print("2. Login to existing account")
        print("3. Exit application")
        auth_choice = input("Choose an option (1-3): ").strip()

        if auth_choice == '1':
            if client.register(): # register() returns True/False
                print(f"{Fore.GREEN}Registration successful. Please log in.{Style.RESET}")
                # Optionally proceed to login automatically or prompt again
                if client.login(): # login() returns True/False
                    g_is_logged_in = True
                    auth_success = True
            # else: client.register() prints its own errors
        elif auth_choice == '2':
            if client.login():
                g_is_logged_in = True
                auth_success = True
            # else: client.login() prints its own errors
        elif auth_choice == '3':
            print(f"{Fore.GREEN}Exiting application.{Style.RESET}")
            client.stop() # Ensure client stops if exiting before full start
            return # Exit main
        else:
            print(f'{Style.BOLD}{Fore.RED}Invalid authentication choice. Please try again.{Style.RESET}')

    if not g_is_logged_in: # Should not happen if auth_success is True, but as a safeguard
        print(f"{Fore.RED}Authentication failed. Exiting.{Style.RESET}")
        client.stop()
        return

    # Start client services only after successful authentication
    # P2PClient.start() now has internal checks and self.running state
    client.start() 
    if not client.running: # Check if client failed to start critical services
        print(f"{Fore.RED}Client failed to start properly. Please check logs. Exiting.{Style.RESET}")
        # client.stop() would have been called internally if start failed critically
        return

    print(f"{Fore.GREEN}Successfully connected to rendezvous server at {args.server}:{args.port}{Style.RESET}")
    print(f"Your Client Name: {client.client_name} (ID: {client.client_id})")
    print(f"Listening for connections on port: {client.receive_port}")
    print(f"Sending connections from port: {client.send_port}")

    # Main application loop
    try:
        while True:
            choice = display_menu(g_is_logged_in) # display_menu now validates input

            if choice == '1': list_shared_files_ui(client)
            elif choice == '2': list_available_files_ui(client)
            elif choice == '3': share_file_ui(client)
            elif choice == '4': download_file_ui(client)
            elif choice == '5':
                print(f"{Style.BOLD}{Fore.CYAN}Refreshing peer list...{Style.RESET}")
                peers = client.get_peer_list() # get_peer_list returns a copy
                print(f"{Fore.CYAN}Found {len(peers)} other peers.{Style.RESET}")
            elif choice == '6': show_connection_details_ui(client)
            elif choice == '7':
                print(f"{Fore.CYAN}Exiting application...{Style.RESET}")
                break # Exit main loop, finally block will call client.stop()
            elif choice == '8': client.printSessionInfo() # Assumes P2PClient.printSessionInfo exists
            elif choice == '9':
                if g_is_logged_in:
                    client.logout() # logout() handles clearing MEK etc.
                    g_is_logged_in = False  
                    print(f"{Style.BOLD}{Fore.GREEN}Logged out successfully.{Style.RESET}")
                    # Optional: loop back to auth menu or exit
                    # For now, continues to main menu but as logged-out user
                else: # User chose "Login"
                    if client.login():
                        g_is_logged_in = True
                        # If client was stopped or partially started, ensure it's fully started
                        if not client.running: # Or a more specific check like !client.listen_socket.fileno() != -1
                            print(f"{Fore.YELLOW}Client was not fully running. Attempting to restart services...{Style.RESET}")
                            client.start() 
                            if not client.running:
                                print(f"{Fore.RED}Failed to restart client services after login. Exiting.{Style.RESET}")
                                break # Exit main loop
                        print(f"{Style.BOLD}{Fore.GREEN}Logged in successfully as {client.client_name}.{Style.RESET}")
                    # else: client.login() prints its own errors
            # No 'else' needed here as display_menu validates choice
    except KeyboardInterrupt:
        print("\nShutdown requested by user (Ctrl+C)...")
    except Exception as e: # Catch-all for unexpected errors in the main app loop
        print(f"{Style.BOLD}{Fore.RED}\nAn unexpected error occurred in the application: {type(e).__name__} - {e}{Style.RESET}")
        import traceback
        traceback.print_exc()
    finally:
        print("Stopping P2P client services...")
        if 'client' in locals() and client: # Ensure client object exists
            client.stop() # This handles unregistering, closing sockets, clearing MEK
        print("CipherShare application terminated. Goodbye!")

if __name__ == "__main__":
    main()