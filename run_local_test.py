import os
import subprocess
import time
import sys
import threading

def ensure_directories(client_name):
    """Create separate directories for each client"""
    shared_dir = f"shared_files_{client_name}"
    downloads_dir = f"downloads_{client_name}"
    
    # Create directories if they don't exist
    os.makedirs(shared_dir, exist_ok=True)
    os.makedirs(downloads_dir, exist_ok=True)
    
    return shared_dir, downloads_dir

def run_client(receive_port, send_port, client_name):
    """Run a P2P client instance with specified ports and directories"""
    print(f"Starting {client_name} client on receive port {receive_port}, send port {send_port}...")
    
    # Create separate directories for this client
    shared_dir, downloads_dir = ensure_directories(client_name)
    
    # Create a new environment for each client process
    # This ensures each client has its own independent environment variables
    env = os.environ.copy()
    env["P2P_SHARED_FOLDER"] = shared_dir
    env["P2P_DOWNLOADS_FOLDER"] = downloads_dir
    
    cmd = f"python p2p_app.py --receive-port {receive_port} --send-port {send_port} --client-name {client_name}"
    
    # Use a different console window on Windows - each will have its own environment
    if os.name == 'nt':
        subprocess.Popen(f"start cmd /k \"{cmd}\"", shell=True, env=env)
    else:
        # For Linux/Mac, we'll launch separate processes with their own environments
        subprocess.Popen(cmd, shell=True, env=env)

def main():
    print("Starting local P2P file sharing test with two clients...")
    
    # Start two separate clients with different ports and separate environments
    run_client(5001, 5002, "client1")
    time.sleep(1)  # Small delay to ensure first client starts
    run_client(5003, 5004, "client2")
    
    print("\nTest setup complete!")
    print("\nInstructions:")
    print("1. In the first client, share a file")
    print("2. In the second client, refresh the peer list and download the file")
    print("3. You can share files from either client to test bidirectional transfer")
    print("\nDirectories:")
    print("- First client: shared_files_client1, downloads_client1")
    print("- Second client: shared_files_client2, downloads_client2")
    print("\nPress Ctrl+C to exit this script when done")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nExiting test script")

if __name__ == "__main__":
    main()