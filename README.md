# Lab Assignment 3: Kerberos Under Partial Compromise using Schnorr Multi-Signatures

## Overview
This project implements a Kerberos-inspired authentication system resilient to partial authority compromise. The system uses a 2-of-3 Schnorr multi-signature scheme to distribute trust among three independent Authentication Servers (AS) and three Ticket Granting Servers (TGS).

## Requirements
- Python 3.8+
- `cryptography` library (for symmetric AES-256-CBC encryption)

Install dependencies:
```bash
pip install cryptography
```

## Running the Architecture
The system consists of independent processes that do not communicate with each other. Follow these steps:

1. **Generate Cryptographic Keys & Configuration**
   ```bash
   # Generates keys for 1 client (default)
   python master_keygen.py
   
   # Or generate keys for N multiple clients
   python master_keygen.py 3
   ```
   *This outputs isolated `<NodeID>_config.json` files containing only the private keys and seeds specific to that node (e.g., `AS_1_config.json`). It also generates `public_info.json` mapping public keys and ports globally, and `client_keys.json`.*

2. **Start the Authorities & Services**
   Open separate terminals for each node:
   ```bash
   python as_node.py AS_1
   python as_node.py AS_2
   python as_node.py AS_3
   
   python tgs_node.py TGS_1
   python tgs_node.py TGS_2
   python tgs_node.py TGS_3
   
   python service_server.py Service_1
   ```

3. **Run the Normal Client Flow**
   In another terminal, run the client to simulate a successful 3-phase authentication process. The client orchestrates querying multiple AS/TGS nodes and collecting required partial signatures.
   
   ```bash
   # Runs as Client_1
   python client.py 
   
   # Or run as a specific client (if you generated multiple)
   python client.py Client_3
   ```

4. **Run Mandatory Attack Scenarios**
   To see how the system handles compromise and verification failures autonomously:
   ```bash
   python attacks.py
   ```
   *Note: `attacks.py` orchestrates its own local server instances to simulate the flow, so you do not need the manual servers running.*

## Project Structure
- `master_keygen.py`: Generates key material securely for all nodes
- `crypto_utils.py`: Contains manual implementations of modular arithmetic, base PKCS7 padding, and Schnorr signature generation and verification over a 1024-bit prime group
- `client.py`: Implements client-side multi-signature collection logic
- `as_node.py`: Implements the Authentication Server logic
- `tgs_node.py`: Implements the Ticket Granting Server logic
- `service_server.py`: Service backend
- `attacks.py`: Automated tests demonstrating the 6 required failure scenarios
