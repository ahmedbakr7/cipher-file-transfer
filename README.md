# P2P File Sharing Application

A basic peer-to-peer file sharing application implemented in Python using only sockets for network communication.

## Features

-   Rendezvous server for peer discovery
-   Direct P2P file transfers
-   Simple command-line interface
-   File listing and browsing

## Project Structure

-   `rendezvous_server.py` - Central server for peer discovery
-   `peer.py` - P2P client implementation for file sharing
-   `p2p_app.py` - Command-line interface for the P2P client
-   `Dockerfile` and `docker-compose.yml` - Docker setup for easy deployment

## Running with Docker

### Using Docker Compose (recommended)

1. Make sure Docker and Docker Compose are installed
2. Run the entire setup (server and two peers):

    ```
    docker-compose up
    ```

3. To interact with a peer:

    ```
    docker attach cipher-major_peer1_1
    ```

    or

    ```
    docker attach cipher-major_peer2_1
    ```

4. To run just the rendezvous server:
    ```
    docker-compose up rendezvous-server
    ```

### Using Docker Directly

1. Build the Docker image:

    ```
    docker build -t p2p-file-sharing .
    ```

2. Run the rendezvous server:

    ```
    docker run -p 5000:5000 p2p-file-sharing
    ```

3. Run a peer client:
    ```
    docker run -it p2p-file-sharing python p2p_app.py --server <server_ip>
    ```

## Running without Docker

### Using Poetry

1. Make sure Poetry is installed:

    ```
    pip install poetry
    ```

2. Install dependencies:

    ```
    poetry install
    ```

3. Run the rendezvous server:

    ```
    poetry run python rendezvous_server.py
    ```

4. In another terminal, run a peer:
    ```
    poetry run python p2p_app.py
    ```

### Direct Execution

1. Run the rendezvous server:

    ```
    python rendezvous_server.py
    ```

2. Run peer clients (in separate terminals):
    ```
    python p2p_app.py
    ```

## Usage

1. Start by sharing files through the "Share a file" option
2. Refresh the peer list to discover other connected peers
3. View available files from peers
4. Download files directly from other peers

## Notes

-   The rendezvous server is only used for peer discovery, not for file transfers
-   File transfers are direct P2P connections between clients
-   Currently, file transfers are unencrypted
-   For testing on a single machine, all connections default to localhost
