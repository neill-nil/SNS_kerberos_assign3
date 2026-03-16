"""
as_node.py
Authentication Server (AS) Node for Kerberos Multi-Signature System.

Each AS node runs as an independent server process on its own port.
It verifies client credentials and issues a partial TGT response consisting of:
  - An encrypted session key (for the client)
  - An encrypted TGT (for TGS)
  - An independent Schnorr signature over the ticket payload

Usage:
    python as_node.py --id 1 --port 5001 --keys-dir keys
    python as_node.py --id 2 --port 5002 --keys-dir keys
    python as_node.py --id 3 --port 5003 --keys-dir keys
"""

import argparse
import base64
import hashlib
import json
import os
import socket
import sys
import threading
import time

from crypto_utils import (
    load_json,
    deserialize_params,
    schnorr_sign,
    aes_encrypt,
    generate_session_key,
)

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

DEFAULT_TGT_LIFETIME = 600   # 10 minutes
BUFFER_SIZE = 65536


# ─────────────────────────────────────────────
# AS Node Class
# ─────────────────────────────────────────────

class ASNode:
    def __init__(self, node_id, port, keys_dir):
        self.authority_id = f"AS{node_id}"
        self.port = port
        self.keys_dir = keys_dir

        # Load keys and parameters
        self._load_keys()

        print(f"[{self.authority_id}] Initialized on port {self.port}")
        print(f"    Key version: {self.key_version}")
        print(f"    Clients registered: {list(self.client_db.keys())}")

    def _load_keys(self):
        """Load private key, public params, and client database."""
        # Load Schnorr parameters
        public_params = load_json(os.path.join(self.keys_dir, "public_params.json"))
        self.p, self.q, self.g = deserialize_params(public_params["schnorr_params"])
        self.key_version = public_params["key_version"]

        # Load this AS's private key
        private_data = load_json(
            os.path.join(self.keys_dir, f"as_private_{self.authority_id[-1]}.json")
        )
        self.private_key = int(private_data["private_key"])

        # Load client database
        db = load_json(os.path.join(self.keys_dir, "client_db.json"))
        self.client_db = db["clients"]
        self.tgs_secret_key = db["tgs_secret_key"]

    def verify_client(self, client_id, password_hash):
        """Verify client credentials against the database."""
        if client_id not in self.client_db:
            return False, "Unknown client"
        stored_hash = self.client_db[client_id]["password_hash"]
        if password_hash != stored_hash:
            return False, "Invalid password"
        return True, "OK"

    def build_ticket_payload(self, client_id, timestamp):
        """
        Build the canonical ticket payload string that gets signed.
        This must be deterministic given the same inputs — all AS nodes
        must produce the SAME string for the SAME request.

        Format: "client_id||tgs||timestamp||lifetime||key_version"
        """
        payload = f"{client_id}||tgs||{timestamp}||{DEFAULT_TGT_LIFETIME}||{self.key_version}"
        return payload

    def process_auth_request(self, request):
        """
        Process a client authentication request.

        Input:
            {
                "type": "AUTH_REQUEST",
                "client_id": "alice",
                "password_hash": "...",
                "timestamp": 1234567890
            }

        Output:
            {
                "type": "AUTH_RESPONSE",
                "status": "success" | "error",
                "authority_id": "AS1",
                "ticket_payload": "client_id||tgs||ts||lifetime||kv",
                "encrypted_tgt": "<base64>",
                "encrypted_session_info": "<base64>",
                "signature_R": "...",
                "signature_s": "...",
                "key_version": 1
            }
        """
        client_id = request.get("client_id")
        password_hash = request.get("password_hash")
        timestamp = request.get("timestamp")

        # Step 1: Verify credentials
        valid, reason = self.verify_client(client_id, password_hash)
        if not valid:
            print(f"[{self.authority_id}] Auth FAILED for {client_id}: {reason}")
            return {
                "type": "AUTH_RESPONSE",
                "status": "error",
                "authority_id": self.authority_id,
                "error": reason,
            }

        print(f"[{self.authority_id}] Auth OK for {client_id}")

        # Step 2: Build the ticket payload (signed part — deterministic)
        ticket_payload = self.build_ticket_payload(client_id, timestamp)

        # Step 3: Generate a session key K_c_tgs
        session_key = generate_session_key()  # 32 bytes random

        # Step 4: Build the full TGT (includes session key) and encrypt with K_tgs
        tgt_content = {
            "client_id": client_id,
            "service_id": "tgs",
            "timestamp": timestamp,
            "lifetime": DEFAULT_TGT_LIFETIME,
            "session_key": session_key.hex(),
            "key_version": self.key_version,
            "issuing_authority": self.authority_id,
        }
        tgt_bytes = json.dumps(tgt_content).encode('utf-8')
        tgs_key = bytes.fromhex(self.tgs_secret_key)
        encrypted_tgt = aes_encrypt(tgs_key, tgt_bytes)

        # Step 5: Encrypt session key info for the client
        # Client decrypts this with K_c (derived from password)
        client_key = self._derive_client_key(password_hash)
        session_info = json.dumps({
            "session_key": session_key.hex(),
            "tgs_id": "tgs",
            "timestamp": timestamp,
            "lifetime": DEFAULT_TGT_LIFETIME,
        }).encode('utf-8')
        encrypted_session_info = aes_encrypt(client_key, session_info)

        # Step 6: Sign the ticket payload with our Schnorr key
        R_i, s_i, auth_id = schnorr_sign(
            ticket_payload, self.private_key, self.authority_id,
            self.p, self.q, self.g
        )

        print(f"[{self.authority_id}] Issued TGT for {client_id} "
              f"(sig R={str(R_i)[:20]}...)")

        return {
            "type": "AUTH_RESPONSE",
            "status": "success",
            "authority_id": self.authority_id,
            "ticket_payload": ticket_payload,
            "encrypted_tgt": base64.b64encode(encrypted_tgt).decode('ascii'),
            "encrypted_session_info": base64.b64encode(
                encrypted_session_info).decode('ascii'),
            "signature_R": str(R_i),
            "signature_s": str(s_i),
            "key_version": self.key_version,
        }

    def _derive_client_key(self, password_hash):
        """
        Derive a 32-byte AES key from the client's password hash.
        K_c = SHA-256(password_hash)[:32]
        """
        return hashlib.sha256(password_hash.encode('utf-8')).digest()

    def handle_client(self, conn, addr):
        """Handle a single client connection."""
        try:
            data = conn.recv(BUFFER_SIZE)
            if not data:
                return

            request = json.loads(data.decode('utf-8'))
            msg_type = request.get("type")

            if msg_type == "AUTH_REQUEST":
                response = self.process_auth_request(request)
            elif msg_type == "PING":
                response = {"type": "PONG", "authority_id": self.authority_id}
            else:
                response = {
                    "type": "ERROR",
                    "error": f"Unknown message type: {msg_type}"
                }

            conn.sendall(json.dumps(response).encode('utf-8'))

        except Exception as e:
            print(f"[{self.authority_id}] Error handling {addr}: {e}")
            try:
                error_resp = json.dumps({
                    "type": "ERROR", "error": str(e)
                }).encode('utf-8')
                conn.sendall(error_resp)
            except:
                pass
        finally:
            conn.close()

    def start(self):
        """Start the AS server."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('localhost', self.port))
        server_socket.listen(5)

        print(f"\n[{self.authority_id}] Listening on localhost:{self.port}")
        print(f"[{self.authority_id}] Ready to process authentication requests\n")

        try:
            while True:
                conn, addr = server_socket.accept()
                thread = threading.Thread(
                    target=self.handle_client, args=(conn, addr)
                )
                thread.daemon = True
                thread.start()
        except KeyboardInterrupt:
            print(f"\n[{self.authority_id}] Shutting down...")
        finally:
            server_socket.close()


def main():
    parser = argparse.ArgumentParser(
        description="AS Node for Kerberos Multi-Signature System"
    )
    parser.add_argument("--id", type=int, required=True, choices=[1, 2, 3],
                        help="Authority node ID (1, 2, or 3)")
    parser.add_argument("--port", type=int, required=True,
                        help="Port to listen on")
    parser.add_argument("--keys-dir", type=str, default="keys",
                        help="Directory containing key files")
    args = parser.parse_args()

    node = ASNode(args.id, args.port, args.keys_dir)
    node.start()


if __name__ == "__main__":
    main()
