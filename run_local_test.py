# ./run_local_test.py
import os
import subprocess
import time
import sys
import shutil # For rmtree
import argparse # For command-line arguments

CLIENT_PROCESSES = []

def ensure_directories(client_name_suffix):
    """Create separate directories for each client based on a suffix."""
    # These are the base names, the P2PClient will use these with the suffix
    # if P2P_SHARED_FOLDER and P2P_DOWNLOADS_FOLDER are set.
    # The client_data directory is handled separately.
    
    shared_dir_env_var = f"shared_files_{client_name_suffix}"
    downloads_dir_env_var = f"downloads_{client_name_suffix}"
    
    os.makedirs(shared_dir_env_var, exist_ok=True)
    os.makedirs(downloads_dir_env_var, exist_ok=True)
    
    # The P2PClient itself creates client_data_{client_name_suffix}
    # We don't need to create it here, but we will clean it up.
    
    return shared_dir_env_var, downloads_dir_env_var

def cleanup_client_directories(client_name_suffix):
    """Remove directories associated with a client suffix."""
    dirs_to_remove = [
        f"client_data_{client_name_suffix}",
        f"shared_files_{client_name_suffix}",
        f"downloads_{client_name_suffix}"
    ]
    for dir_path in dirs_to_remove:
        if os.path.exists(dir_path):
            try:
                shutil.rmtree(dir_path)
                print(f"Cleaned up directory: {dir_path}")
            except OSError as e:
                print(f"Error cleaning up directory {dir_path}: {e}")
        else:
            print(f"Directory not found for cleanup (already clean or never created): {dir_path}")


def run_client(receive_port, send_port, client_name_suffix, rendezvous_host, rendezvous_port):
    """Run a P2P client instance with specified ports and directories."""
    print(f"Starting client '{client_name_suffix}' (recv:{receive_port}, send:{send_port})...")
    
    # These directories will be used by P2PClient if the env vars are set
    shared_dir_for_env, downloads_dir_for_env = ensure_directories(client_name_suffix)
    
    env = os.environ.copy()
    env["P2P_SHARED_FOLDER"] = shared_dir_for_env
    env["P2P_DOWNLOADS_FOLDER"] = downloads_dir_for_env
    
    # Construct the command
    cmd_args = [
        sys.executable,  # Path to Python interpreter
        "p2p_app.py",
        "--server", rendezvous_host,
        "--port", str(rendezvous_port),
        "--receive-port", str(receive_port),
        "--send-port", str(send_port),
        "--client-name", client_name_suffix # This name is used for the client_data_ directory
    ]
    
    # How to run depends on OS for interactive windows
    if os.name == 'nt': # Windows
        # Using "start cmd /c" would run and close. "/k" keeps window open.
        # For testing where you want to see output, /k is better.
        # For fully automated tests, you'd capture output and not use "start".
        process = subprocess.Popen(f"start cmd /k \"{' '.join(cmd_args)}\"", shell=True, env=env)
    else: # Linux/macOS
        # To open in a new terminal window (behavior varies by terminal emulator):
        # This is a common way for gnome-terminal. Others (xterm, konsole, etc.) have different syntax.
        # For simplicity, we'll run it in the background of the current terminal.
        # You'd typically open new terminal tabs/windows manually for interaction.
        # If you want separate visible terminals, you might need to adjust this:
        # e.g., for gnome-terminal: ['gnome-terminal', '--', *cmd_args]
        # For now, let's just Popen it. Output will be mixed if not redirected.
        # For manual testing, it's often easier to just run them in separate terminals yourself.
        # However, to manage them from this script:
        process = subprocess.Popen(cmd_args, env=env)
        
    CLIENT_PROCESSES.append(process)
    print(f"Client '{client_name_suffix}' started (PID: {process.pid if hasattr(process, 'pid') else 'N/A on Win+start'}).")
    return process

def main():
    parser = argparse.ArgumentParser(description="Run local P2P file sharing test with multiple clients.")
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Clean up client-specific directories before starting."
    )
    parser.add_argument("--rendezvous-host", default="127.0.0.1", help="Rendezvous server host.")
    parser.add_argument("--rendezvous-port", type=int, default=5050, help="Rendezvous server port.")
    args = parser.parse_args()

    client_configs = [
        {"name_suffix": "client1", "recv_port": 6001, "send_port": 6002},
        {"name_suffix": "client2", "recv_port": 6003, "send_port": 6004},
        # Add more clients here if needed
        # {"name_suffix": "client3", "recv_port": 6005, "send_port": 6006},
    ]

    if args.clean:
        print("--- Cleaning up client directories ---")
        for config in client_configs:
            cleanup_client_directories(config["name_suffix"])
        print("--- Cleanup complete ---")

    print(f"\nStarting local P2P file sharing test with {len(client_configs)} clients...")
    print(f"Rendezvous server should be running at {args.rendezvous_host}:{args.rendezvous_port}")
    print("Ensure the rendezvous_server.py is running in a separate terminal.")

    try:
        for i, config in enumerate(client_configs):
            run_client(
                config["recv_port"],
                config["send_port"],
                config["name_suffix"],
                args.rendezvous_host,
                args.rendezvous_port
            )
            if i < len(client_configs) - 1:
                time.sleep(2)  # Stagger client starts slightly

        print("\n--- Test Setup Complete ---")
        print("Clients are starting up. Check their individual windows/output.")
        print("\nInstructions for manual testing:")
        print("1. In one client, register/login and share a file.")
        print("2. In another client, register/login, refresh peer list, and download the file.")
        print("\nClient-specific directories (relative to where you run this script):")
        for config in client_configs:
            print(f"- {config['name_suffix']}: "
                  f"client_data_{config['name_suffix']}, "
                  f"shared_files_{config['name_suffix']}, "
                  f"downloads_{config['name_suffix']}")
        print("\nPress Ctrl+C in this window to attempt to stop all launched client processes and exit.")
        
        while True:
            time.sleep(1) # Keep the main script alive

    except KeyboardInterrupt:
        print("\nShutdown requested by user (Ctrl+C).")
    finally:
        print("--- Stopping client processes ---")
        for i, process in enumerate(CLIENT_PROCESSES):
            try:
                # For processes started with "start cmd /k" on Windows,
                # process.terminate() might not close the window itself,
                # but it should terminate the python p2p_app.py within it if possible.
                # For direct Popen, this works better.
                if process.poll() is None: # Check if process is still running
                    print(f"Terminating client process {i+1} (PID: {process.pid if hasattr(process, 'pid') else 'N/A'})...")
                    process.terminate() # Send SIGTERM
                    try:
                        process.wait(timeout=5) # Wait for graceful termination
                        print(f"Client process {i+1} terminated.")
                    except subprocess.TimeoutExpired:
                        print(f"Client process {i+1} did not terminate gracefully, killing...")
                        process.kill() # Send SIGKILL
                        print(f"Client process {i+1} killed.")
                else:
                    print(f"Client process {i+1} already terminated.")
            except Exception as e:
                print(f"Error terminating client process {i+1}: {e}")
        print("--- All client processes handled. Exiting test script. ---")

if __name__ == "__main__":
    main()