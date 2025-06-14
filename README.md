# CipherShare: Secure P2P File Sharing Application

CipherShare is a peer-to-peer (P2P) file sharing application implemented in Python. It prioritizes security by ensuring that files are encrypted both in transit and at rest on the sharing user's machine, and that user credentials are handled securely.

## Core Features

-   **Secure User Authentication:** Users register and log in with strong password hashing (Argon2).
-   **End-to-End Encryption for Files:**
    -   Files are encrypted with AES-256 before being shared.
    -   Symmetric file keys are exchanged securely between peers using RSA encryption.
-   **File Chunking:** Large files are broken into chunks during transfer for improved reliability.
-   **Secure Local Key Storage:**
    -   The metadata file (`file_metadata.json`), which stores symmetric keys for shared files, is itself encrypted on the client's machine using a key derived from the user's password (Argon2 KDF + AES).
-   **File Integrity Verification:** SHA-256 hashes ensure files are not corrupted or tampered with during transfer.
-   **File Management:** Users can share files and also stop sharing files they previously shared.
-   **Peer Discovery:** Utilizes a rendezvous server for discovering other peers on the network.
-   **Direct P2P File Transfers:** Files are transferred directly between peers after secure key exchange.
-   **Command-Line Interface:** Simple CLI for interacting with the application.
-   **Persistent Client Data:** Client-specific RSA keys, metadata encryption salt, and shared file status are stored locally to maintain identity and security across sessions when a consistent client name is used.

## Project Structure

-   `rendezvous_server.py`: Central server for peer discovery.
-   `peer.py`: P2P client logic, handling cryptography, networking, and file operations.
-   `p2p_app.py`: Command-line interface for the P2P client.
-   `utils/`: Directory containing utility modules:
    -   `crypto_utils.py`: Cryptographic functions (AES, RSA, hashing, KDF salt generation).
    -   `password_utils.py`: Password hashing and Argon2-based key derivation functions.
-   `tests/`: Directory containing automated tests:
    -   `test_crypto_utils.py`, `test_password_utils.py`: Unit tests for utility modules.
    -   `test_integration.py`: Integration tests for end-to-end scenarios.
-   `client_data_<client_name>/`: Directory created by each client instance to store:
    -   `private_key.pem`, `public_key.pem`: Client's RSA key pair.
    -   `metadata.salt`: Salt used for deriving the key to encrypt `file_metadata.json`.
-   `shared_files_<client_name>/`: Directory where a client stores files it intends to share (files are stored encrypted here).
    -   `file_metadata.json`: (Stored encrypted) Contains metadata about shared files, including their original hashes and symmetric keys.
-   `downloads_<client_name>/`: Default directory for downloaded files.
-   `user_registry.json`: Stores usernames and their Argon2-hashed passwords.
-   `Dockerfile` and `docker-compose.yml`: Docker setup for easy deployment.
-   `run_local_test.py`: Script to facilitate manual local testing of multiple client instances.
-   `requirements.txt`: Lists Python package dependencies.

## Running with Docker

(Note: Docker configurations may need adjustments for persistent volume mapping to align with the `client_data_<client_name>` and `shared_files_<client_name>` structures if data persistence across container restarts is desired.)

### Using Docker Compose (recommended)

1.  Make sure Docker and Docker Compose are installed.
2.  Run the entire setup (server and two peers):
    ```bash
    docker-compose up
    ```
    (The `docker-compose.yml` should define volumes for client-specific data for persistence.)
3.  To interact with a peer:
    ```bash
    docker attach <container_name_of_peer1> 
    ```
    or
    ```bash
    docker attach <container_name_of_peer2>
    ```

### Using Docker Directly

1.  Build the Docker image:
    ```bash
    docker build -t ciphershare-p2p .
    ```
2.  Run the rendezvous server:
    ```bash
    docker run -p 5050:5050 --rm --name rendezvous ciphershare-p2p
    ```
3.  Run a peer client (use volumes for data persistence and specify `--client-name`):
    ```bash
    # Example for a client named 'client1'
    docker run -it --rm \
      -v $(pwd)/client_data_client1:/app/client_data_client1 \
      -v $(pwd)/shared_files_client1:/app/shared_files_client1 \
      -v $(pwd)/downloads_client1:/app/downloads_client1 \
      -v $(pwd)/user_registry.json:/app/user_registry.json \
      ciphershare-p2p python p2p_app.py --server rendezvous --client-name client1
    ```
    (Adjust paths and use the service name, e.g., `rendezvous`, if clients are on the same Docker network as the server.)

## Running without Docker

### Prerequisites
- Python 3.x
- Required libraries: Install using `pip install -r requirements.txt`
  (Key libraries: `argon2-cffi`, `cryptography`, `colored`)

### Direct Execution

1.  **Start the Rendezvous Server:**
    In one terminal:
    ```bash
    python rendezvous_server.py
    ```
    The server will start, typically on `127.0.0.1:5050`.

2.  **Run Peer Clients:**
    In separate terminals, run each client. **It is crucial to use the `--client-name` argument for each client instance to ensure its data (RSA keys, metadata salt, shared files) persists across sessions.**
    You can also specify a custom `--chunk-size` (in bytes).

    *   **Client 1 (e.g., "Alice"):**
        ```bash
        python p2p_app.py --client-name Alice
        # To use a custom chunk size (e.g., 512KB = 512 * 1024 bytes):
        # python p2p_app.py --client-name Alice --chunk-size 524288
        ```
    *   **Client 2 (e.g., "Bob"):**
        ```bash
        python p2p_app.py --client-name Bob --receive-port 6003 --send-port 6004 
        ```
        (Using different `--receive-port` and `--send-port` for multiple clients on the same machine is recommended.)

## Usage

1.  **Start Clients:** Launch `p2p_app.py` with a unique `--client-name` for each instance.
2.  **Register/Login:** Each client will prompt for registration or login.
3.  **Share Files:** Select "Share a file". The file will be encrypted and stored in `shared_files_<client_name>`. Its metadata will be stored in an encrypted `file_metadata.json`.
4.  **Stop Sharing Files:** Select "Stop sharing a file" to remove a file from your shared list and delete its encrypted copy.
5.  **Discover Peers & Files:** Use "Refresh peer list" and "List available files from peers".
6.  **Download Files:** Select a file. The file's AES key is securely exchanged (RSA). Files are transferred in chunks. The downloaded file is decrypted, integrity-checked, and saved to `downloads_<client_name>`.

## Security Overview

CipherShare implements several layers of security:

-   **User Authentication:** Passwords are hashed using Argon2id.
-   **Confidentiality (Files at Rest on Sharer):** Files are AES-256 encrypted. The `file_metadata.json` (containing file AES keys) is also AES-256 encrypted, using a key derived from the user's password via Argon2id (KDF).
-   **Confidentiality (Files in Transit):** File content is transferred AES-256 encrypted. Symmetric AES keys are exchanged using RSA encryption.
-   **Integrity:** SHA-256 hashes verify file integrity.
-   **Client-Side Keys:** RSA private keys and the metadata salt are stored locally per client.

## Testing

The project includes:
-   **Unit Tests:** Located in the `tests/` directory (e.g., `test_crypto_utils.py`, `test_password_utils.py`). Run with `python -m unittest discover tests`.
-   **Integration Tests:** `tests/test_integration.py` covers end-to-end scenarios. Run with `python -m unittest tests.test_integration`.
-   **Manual E2E Testing:** Use `run_local_test.py` to launch multiple client instances for manual testing of the CLI application.

## Notes

-   The rendezvous server is only for peer discovery; it doesn't handle file content or keys. Communication with it is currently unencrypted.
-   File transfers are direct P2P.
-   Use unique `--client-name` for data persistence.
-   Protect `user_registry.json` and `client_data_<client_name>/` directories.