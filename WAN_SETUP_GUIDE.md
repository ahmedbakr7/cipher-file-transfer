# WAN Setup Guide for P2P File Sharing Application

This guide explains how to set up the P2P file sharing application to work across the internet (WAN).

## Step 1: Set Up the Rendezvous Server

The rendezvous server needs to be accessible from the internet.

### Option A: Run on a machine with public IP

If you have a server with a public IP address:

```bash
# Navigate to the server directory
cd server

# Start the server
poetry run python rendezvous_server.py
```

### Option B: Run on your local machine with port forwarding

1. Start the rendezvous server:

```bash
poetry run python server/rendezvous_server.py
```

2. Set up port forwarding on your router:

   - Access your router admin page (typically 192.168.0.1 or 192.168.1.1)
   - Find the port forwarding section
   - Create a rule that forwards TCP traffic on port 5000 to your computer's local IP address
   - You can find your local IP with `ipconfig` (Windows) or `ifconfig` (Linux/Mac)

3. Find your public IP:
   - Visit a site like https://whatismyip.com
   - This is the IP address peers will use to connect to your rendezvous server

## Step 2: Start the P2P Client

### For the host with the rendezvous server:

```bash
# Use --upnp to automatically set up port forwarding
poetry run python p2p_app.py --upnp
```

### For other peers connecting across the internet:

```bash
# Replace PUBLIC_IP with the actual public IP of the rendezvous server
poetry run python p2p_app.py -s PUBLIC_IP -p 5000 --upnp
```

## Troubleshooting

### UPnP Port Forwarding Issues

If automatic UPnP port forwarding doesn't work:

1. Choose a specific port for your client:

```bash
poetry run python p2p_app.py -s PUBLIC_IP -p 5000 --client-port 6000
```

2. Manually set up port forwarding on your router for that port (6000)

3. Use the port forwarding menu in the application (option 6) to check your external IP and port

### Connection Problems

1. Make sure firewalls are configured to allow the necessary ports
2. Verify that port forwarding is working using an online port checker
3. If you're behind a carrier-grade NAT (common with mobile networks), you might need a VPN or relay server

## Testing Across WAN

To confirm your setup works across WAN:

1. Have a friend connect to your rendezvous server from their internet connection
2. Both share files and verify that you can see each other's shared files
3. Try downloading files to confirm the direct P2P connection works

## Local Testing (Simulating WAN)

To test on a single machine:

1. Start the rendezvous server
2. Start two clients with different ports:

```bash
poetry run python p2p_app.py --client-port 5001
poetry run python p2p_app.py --client-port 5002
```

This simulates two peers connecting, but doesn't fully test WAN connectivity.
