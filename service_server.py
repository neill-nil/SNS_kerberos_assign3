"""
service_server.py
Service Server for Kerberos Multi-Signature System.

Each service server runs as an independent process on its own port.
It verifies service tickets by:
  1. Verifying ≥2 TGS Schnorr signatures on the ticket payload
  2. Decrypting the service ticket with its service key
  3. Verifying the client authenticator with the service session key
  4. Checking key version (reject outdated)

Usage:
    python service_server.py --service file_server --port 7001 --keys-dir keys
    python service_server.py --service print_server --port 7002 --keys-dir keys
"""

import argparse
import base64
import json
import os
import socket
import threading
import time

from crypto_utils import (
    load_json,
    deserialize_params,
    schnorr_verify,
    verify_multi_signatures,
    aes_encrypt,
    aes_decrypt,
)

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

BUFFER_SIZE = 65536
MAX_CLOCK_SKEW = 300  # 5 minutes


# ─────────────────────────────────────────────
# Service Server Class
# ─────────────────────────────────────────────

class ServiceServer:
    def __init__(self, service_id, port, keys_dir):
        self.service_id = service_id
        self.port = port
        self.keys_dir = keys_dir

        self._load_keys()

        print(f"[{self.service_id}] Initialized on port {self.port}")
        print(f"    Key version: {self.key_version}")

    def _load_keys(self):
        """Load service key, TGS public keys, and Schnorr parameters."""
        # Load Schnorr parameters
        public_params = load_json(os.path.join(self.keys_dir, "public_params.json"))
        self.p, self.q, self.g = deserialize_params(public_params["schnorr_params"])
        self.key_version = public_params["key_version"]
        self.required_signatures = public_params["required_signatures"]

        # Load TGS public keys (for verifying service ticket signatures)
        self.tgs_public_keys = {
            auth_id: int(y_str)
            for auth_id, y_str in public_params["tgs_public_keys"].items()
        }

        # Load this service's symmetric key
        db = load_json(os.path.join(self.keys_dir, "client_db.json"))
        if self.service_id not in db["services"]:
            raise ValueError(f"Service '{self.service_id}' not found in client_db")
        self.service_key = db["services"][self.service_id]["service_key"]

    def verify_service_ticket(self, ticket_payload, signatures, encrypted_ticket):
        """
        Verify a service ticket:
          1. Verify ≥2 valid TGS Schnorr signatures
          2. Decrypt the service ticket
          3. Check expiry and key version
          4. Verify payload consistency

        Returns: (success, ticket_content or error_message)
        """
        # Step 1: Verify multi-signatures from TGS authorities
        sig_tuples = []
        for sig in signatures:
            sig_tuples.append((
                int(sig["R"]),
                int(sig["s"]),
                sig["authority_id"]
            ))

        is_valid, valid_count, details = verify_multi_signatures(
            ticket_payload, sig_tuples, self.tgs_public_keys,
            self.p, self.q, self.g, required=self.required_signatures
        )

        if not is_valid:
            detail_str = "; ".join(
                f"{d[0]}={'OK' if d[1] else 'FAIL'}({d[2]})" for d in details
            )
            return False, f"Insufficient valid signatures ({valid_count}/{self.required_signatures}): {detail_str}"

        # Step 2: Decrypt service ticket
        try:
            svc_key = bytes.fromhex(self.service_key)
            ticket_bytes = aes_decrypt(svc_key, base64.b64decode(encrypted_ticket))
            ticket_content = json.loads(ticket_bytes.decode('utf-8'))
        except Exception as e:
            return False, f"Service ticket decryption failed: {e}"

        # Step 3: Check ticket lifetime
        issue_time = ticket_content.get("timestamp", 0)
        lifetime = ticket_content.get("lifetime", 0)
        current_time = int(time.time())

        if current_time > issue_time + lifetime + MAX_CLOCK_SKEW:
            return False, "Service ticket has expired"

        # Step 4: Check key version
        ticket_kv = ticket_content.get("key_version", 0)
        if ticket_kv != self.key_version:
            return False, f"Outdated key version (ticket: {ticket_kv}, current: {self.key_version})"

        # Step 5: Verify payload matches decrypted content
        expected_payload = (
            f"{ticket_content['client_id']}||{ticket_content['service_id']}"
            f"||{ticket_content['timestamp']}||{ticket_content['lifetime']}"
            f"||{ticket_content['key_version']}"
        )
        if ticket_payload != expected_payload:
            return False, "Ticket payload mismatch with encrypted content"

        # Step 6: Verify service_id matches this server
        if ticket_content.get("service_id") != self.service_id:
            return False, f"Ticket is for '{ticket_content.get('service_id')}', not '{self.service_id}'"

        return True, ticket_content

    def verify_authenticator(self, encrypted_authenticator, session_key, expected_client_id):
        """Verify client authenticator using service session key."""
        try:
            key = bytes.fromhex(session_key)
            auth_bytes = aes_decrypt(key, base64.b64decode(encrypted_authenticator))
            authenticator = json.loads(auth_bytes.decode('utf-8'))
        except Exception as e:
            return False, f"Authenticator decryption failed: {e}"

        if authenticator.get("client_id") != expected_client_id:
            return False, "Client ID mismatch in authenticator"

        auth_time = authenticator.get("timestamp", 0)
        current_time = int(time.time())
        if abs(current_time - auth_time) > MAX_CLOCK_SKEW:
            return False, "Authenticator timestamp out of range"

        return True, authenticator

    def process_service_request(self, request):
        """
        Process a client's service access request.

        Input:
            {
                "type": "SERVICE_REQUEST",
                "service_ticket_payload": "alice||file_server||...",
                "encrypted_service_ticket": "<base64>",
                "signatures": [
                    {"R": "...", "s": "...", "authority_id": "TGS1"},
                    {"R": "...", "s": "...", "authority_id": "TGS2"}
                ],
                "authenticator": "<base64>"
            }

        Output:
            {
                "type": "SERVICE_RESPONSE",
                "status": "success" | "error",
                "service_id": "file_server",
                "server_authenticator": "<base64>",
                "message": "Access granted"
            }
        """
        ticket_payload = request.get("service_ticket_payload")
        encrypted_ticket = request.get("encrypted_service_ticket")
        signatures = request.get("signatures", [])
        authenticator = request.get("authenticator")

        # Step 1: Verify service ticket
        ticket_valid, ticket_result = self.verify_service_ticket(
            ticket_payload, signatures, encrypted_ticket
        )
        if not ticket_valid:
            print(f"[{self.service_id}] Ticket verification FAILED: {ticket_result}")
            return {
                "type": "SERVICE_RESPONSE",
                "status": "error",
                "service_id": self.service_id,
                "error": f"Ticket verification failed: {ticket_result}",
            }

        ticket_content = ticket_result
        client_id = ticket_content["client_id"]
        session_key = ticket_content["session_key"]

        print(f"[{self.service_id}] Ticket verified for {client_id}")

        # Step 2: Verify authenticator
        auth_valid, auth_result = self.verify_authenticator(
            authenticator, session_key, client_id
        )
        if not auth_valid:
            print(f"[{self.service_id}] Authenticator FAILED: {auth_result}")
            return {
                "type": "SERVICE_RESPONSE",
                "status": "error",
                "service_id": self.service_id,
                "error": f"Authenticator failed: {auth_result}",
            }

        auth_timestamp = auth_result["timestamp"]

        # Step 3: Build server authenticator (proves server identity to client)
        # Server sends back timestamp + 1, encrypted with K_c_v
        server_auth = json.dumps({
            "timestamp": auth_timestamp + 1,
            "service_id": self.service_id,
        }).encode('utf-8')
        k_c_v = bytes.fromhex(session_key)
        encrypted_server_auth = aes_encrypt(k_c_v, server_auth)

        print(f"[{self.service_id}] ACCESS GRANTED to {client_id}")

        return {
            "type": "SERVICE_RESPONSE",
            "status": "success",
            "service_id": self.service_id,
            "server_authenticator": base64.b64encode(
                encrypted_server_auth).decode('ascii'),
            "message": f"Access granted to {client_id}",
        }

    def handle_client(self, conn, addr):
        """Handle a single client connection."""
        try:
            data = conn.recv(BUFFER_SIZE)
            if not data:
                return

            request = json.loads(data.decode('utf-8'))
            msg_type = request.get("type")

            if msg_type == "SERVICE_REQUEST":
                response = self.process_service_request(request)
            elif msg_type == "PING":
                response = {"type": "PONG", "service_id": self.service_id}
            else:
                response = {
                    "type": "ERROR",
                    "error": f"Unknown message type: {msg_type}"
                }

            conn.sendall(json.dumps(response).encode('utf-8'))

        except Exception as e:
            print(f"[{self.service_id}] Error handling {addr}: {e}")
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
        """Start the service server."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('localhost', self.port))
        server_socket.listen(5)

        print(f"\n[{self.service_id}] Listening on localhost:{self.port}")
        print(f"[{self.service_id}] Ready to process service requests\n")

        try:
            while True:
                conn, addr = server_socket.accept()
                thread = threading.Thread(
                    target=self.handle_client, args=(conn, addr)
                )
                thread.daemon = True
                thread.start()
        except KeyboardInterrupt:
            print(f"\n[{self.service_id}] Shutting down...")
        finally:
            server_socket.close()


def main():
    parser = argparse.ArgumentParser(
        description="Service Server for Kerberos Multi-Signature System"
    )
    parser.add_argument("--service", type=str, required=True,
                        help="Service ID (e.g., file_server, print_server)")
    parser.add_argument("--port", type=int, required=True,
                        help="Port to listen on")
    parser.add_argument("--keys-dir", type=str, default="keys",
                        help="Directory containing key files")
    args = parser.parse_args()

    server = ServiceServer(args.service, args.port, args.keys_dir)
    server.start()


if __name__ == "__main__":
    main()
