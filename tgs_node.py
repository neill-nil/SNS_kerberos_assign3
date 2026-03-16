"""
tgs_node.py
Ticket Granting Server (TGS) Node for Kerberos Multi-Signature System.

Each TGS node runs as an independent server process on its own port.
It verifies TGT multi-signatures, then issues a partial Service Ticket response:
  - An encrypted service session key (for the client, encrypted with K_c_tgs)
  - An encrypted Service Ticket (for the target service)
  - An independent Schnorr signature over the service ticket payload

Usage:
    python tgs_node.py --id 1 --port 6001 --keys-dir keys
    python tgs_node.py --id 2 --port 6002 --keys-dir keys
    python tgs_node.py --id 3 --port 6003 --keys-dir keys
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
    schnorr_sign,
    schnorr_verify,
    verify_multi_signatures,
    aes_encrypt,
    aes_decrypt,
    generate_session_key,
)

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

DEFAULT_SERVICE_TICKET_LIFETIME = 600   # 10 minutes
BUFFER_SIZE = 65536
MAX_CLOCK_SKEW = 300                    # 5 minutes tolerance


# ─────────────────────────────────────────────
# TGS Node Class
# ─────────────────────────────────────────────

class TGSNode:
    def __init__(self, node_id, port, keys_dir):
        self.authority_id = f"TGS{node_id}"
        self.port = port
        self.keys_dir = keys_dir

        # Load keys and parameters
        self._load_keys()

        print(f"[{self.authority_id}] Initialized on port {self.port}")
        print(f"    Key version: {self.key_version}")
        print(f"    Services registered: {list(self.services.keys())}")

    def _load_keys(self):
        """Load private key, public params, AS public keys, and service registry."""
        # Load Schnorr parameters
        public_params = load_json(os.path.join(self.keys_dir, "public_params.json"))
        self.p, self.q, self.g = deserialize_params(public_params["schnorr_params"])
        self.key_version = public_params["key_version"]
        self.required_signatures = public_params["required_signatures"]

        # Load AS public keys (for verifying TGT signatures)
        self.as_public_keys = {
            auth_id: int(y_str)
            for auth_id, y_str in public_params["as_public_keys"].items()
        }

        # Load this TGS's private key
        private_data = load_json(
            os.path.join(self.keys_dir, f"tgs_private_{self.authority_id[-1]}.json")
        )
        self.private_key = int(private_data["private_key"])

        # Load shared secrets
        db = load_json(os.path.join(self.keys_dir, "client_db.json"))
        self.tgs_secret_key = db["tgs_secret_key"]
        self.services = db["services"]

    def verify_tgt(self, ticket_payload, signatures, encrypted_tgt):
        """
        Verify a TGT:
          1. Verify ≥2 valid Schnorr signatures from AS authorities
          2. Decrypt the encrypted TGT using the shared TGS key
          3. Verify ticket hasn't expired
          4. Verify key version is current

        Returns: (success, tgt_content or error_message)
        """
        # Step 1: Verify multi-signatures
        sig_tuples = []
        for sig in signatures:
            sig_tuples.append((
                int(sig["R"]),
                int(sig["s"]),
                sig["authority_id"]
            ))

        is_valid, valid_count, details = verify_multi_signatures(
            ticket_payload, sig_tuples, self.as_public_keys,
            self.p, self.q, self.g, required=self.required_signatures
        )

        if not is_valid:
            detail_str = "; ".join(
                f"{d[0]}={'OK' if d[1] else 'FAIL'}({d[2]})" for d in details
            )
            return False, f"Insufficient valid signatures ({valid_count}/{self.required_signatures}): {detail_str}"

        # Step 2: Decrypt TGT
        try:
            tgs_key = bytes.fromhex(self.tgs_secret_key)
            tgt_bytes = aes_decrypt(tgs_key, base64.b64decode(encrypted_tgt))
            tgt_content = json.loads(tgt_bytes.decode('utf-8'))
        except Exception as e:
            return False, f"TGT decryption failed: {e}"

        # Step 3: Check ticket lifetime
        issue_time = tgt_content.get("timestamp", 0)
        lifetime = tgt_content.get("lifetime", 0)
        current_time = int(time.time())

        if current_time > issue_time + lifetime + MAX_CLOCK_SKEW:
            return False, "TGT has expired"

        # Step 4: Check key version
        ticket_kv = tgt_content.get("key_version", 0)
        if ticket_kv != self.key_version:
            return False, f"Outdated key version (ticket: {ticket_kv}, current: {self.key_version})"

        # Step 5: Verify ticket payload matches decrypted content
        expected_payload = (
            f"{tgt_content['client_id']}||tgs||{tgt_content['timestamp']}"
            f"||{tgt_content['lifetime']}||{tgt_content['key_version']}"
        )
        if ticket_payload != expected_payload:
            return False, "Ticket payload mismatch with encrypted content"

        return True, tgt_content

    def verify_authenticator(self, encrypted_authenticator, session_key, expected_client_id):
        """
        Verify the client authenticator:
          - Decrypt with session key K_c_tgs
          - Check client_id matches
          - Check timestamp is recent (within clock skew)
        """
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

    def build_service_ticket_payload(self, client_id, service_id, timestamp):
        """
        Build the canonical service ticket payload string for signing.
        Must be deterministic given the same inputs.

        Format: "client_id||service_id||timestamp||lifetime||key_version"
        """
        payload = (
            f"{client_id}||{service_id}||{timestamp}"
            f"||{DEFAULT_SERVICE_TICKET_LIFETIME}||{self.key_version}"
        )
        return payload

    def process_tgs_request(self, request):
        """
        Process a client's TGS request.

        Input:
            {
                "type": "TGS_REQUEST",
                "ticket_payload": "alice||tgs||...",
                "encrypted_tgt": "<base64>",
                "signatures": [
                    {"R": "...", "s": "...", "authority_id": "AS1"},
                    {"R": "...", "s": "...", "authority_id": "AS2"}
                ],
                "authenticator": "<base64>",
                "target_service": "file_server"
            }

        Output:
            {
                "type": "TGS_RESPONSE",
                "status": "success" | "error",
                "authority_id": "TGS1",
                "service_ticket_payload": "alice||file_server||...",
                "encrypted_service_ticket": "<base64>",
                "encrypted_session_info": "<base64>",
                "signature_R": "...",
                "signature_s": "...",
                "key_version": 1
            }
        """
        ticket_payload = request.get("ticket_payload")
        encrypted_tgt = request.get("encrypted_tgt")
        signatures = request.get("signatures", [])
        authenticator = request.get("authenticator")
        target_service = request.get("target_service")

        # Step 1: Verify TGT (multi-signature + decryption)
        tgt_valid, tgt_result = self.verify_tgt(
            ticket_payload, signatures, encrypted_tgt
        )
        if not tgt_valid:
            print(f"[{self.authority_id}] TGT verification FAILED: {tgt_result}")
            return {
                "type": "TGS_RESPONSE",
                "status": "error",
                "authority_id": self.authority_id,
                "error": f"TGT verification failed: {tgt_result}",
            }

        tgt_content = tgt_result
        client_id = tgt_content["client_id"]
        session_key = tgt_content["session_key"]

        print(f"[{self.authority_id}] TGT verified for {client_id}")

        # Step 2: Verify authenticator
        auth_valid, auth_result = self.verify_authenticator(
            authenticator, session_key, client_id
        )
        if not auth_valid:
            print(f"[{self.authority_id}] Authenticator FAILED: {auth_result}")
            return {
                "type": "TGS_RESPONSE",
                "status": "error",
                "authority_id": self.authority_id,
                "error": f"Authenticator failed: {auth_result}",
            }

        # Step 3: Verify target service exists
        if target_service not in self.services:
            return {
                "type": "TGS_RESPONSE",
                "status": "error",
                "authority_id": self.authority_id,
                "error": f"Unknown service: {target_service}",
            }

        # Step 4: Generate service session key K_c_v
        service_session_key = generate_session_key()  # 32 bytes random
        timestamp = int(time.time())

        # Step 5: Build service ticket payload (signed part)
        service_ticket_payload = self.build_service_ticket_payload(
            client_id, target_service, timestamp
        )

        # Step 6: Build encrypted service ticket (for the service server)
        service_ticket_content = {
            "client_id": client_id,
            "service_id": target_service,
            "timestamp": timestamp,
            "lifetime": DEFAULT_SERVICE_TICKET_LIFETIME,
            "session_key": service_session_key.hex(),
            "key_version": self.key_version,
            "issuing_authority": self.authority_id,
        }
        service_key = bytes.fromhex(self.services[target_service]["service_key"])
        encrypted_service_ticket = aes_encrypt(
            service_key,
            json.dumps(service_ticket_content).encode('utf-8')
        )

        # Step 7: Encrypt service session key for the client (with K_c_tgs)
        session_info = json.dumps({
            "session_key": service_session_key.hex(),
            "service_id": target_service,
            "timestamp": timestamp,
            "lifetime": DEFAULT_SERVICE_TICKET_LIFETIME,
        }).encode('utf-8')
        k_c_tgs = bytes.fromhex(session_key)
        encrypted_session_info = aes_encrypt(k_c_tgs, session_info)

        # Step 8: Sign the service ticket payload with our Schnorr key
        R_i, s_i, auth_id = schnorr_sign(
            service_ticket_payload, self.private_key, self.authority_id,
            self.p, self.q, self.g
        )

        print(f"[{self.authority_id}] Issued Service Ticket for "
              f"{client_id} → {target_service}")

        return {
            "type": "TGS_RESPONSE",
            "status": "success",
            "authority_id": self.authority_id,
            "service_ticket_payload": service_ticket_payload,
            "encrypted_service_ticket": base64.b64encode(
                encrypted_service_ticket).decode('ascii'),
            "encrypted_session_info": base64.b64encode(
                encrypted_session_info).decode('ascii'),
            "signature_R": str(R_i),
            "signature_s": str(s_i),
            "key_version": self.key_version,
        }

    def handle_client(self, conn, addr):
        """Handle a single client connection."""
        try:
            data = conn.recv(BUFFER_SIZE)
            if not data:
                return

            request = json.loads(data.decode('utf-8'))
            msg_type = request.get("type")

            if msg_type == "TGS_REQUEST":
                response = self.process_tgs_request(request)
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
        """Start the TGS server."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('localhost', self.port))
        server_socket.listen(5)

        print(f"\n[{self.authority_id}] Listening on localhost:{self.port}")
        print(f"[{self.authority_id}] Ready to process TGS requests\n")

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
        description="TGS Node for Kerberos Multi-Signature System"
    )
    parser.add_argument("--id", type=int, required=True, choices=[1, 2, 3],
                        help="Authority node ID (1, 2, or 3)")
    parser.add_argument("--port", type=int, required=True,
                        help="Port to listen on")
    parser.add_argument("--keys-dir", type=str, default="keys",
                        help="Directory containing key files")
    args = parser.parse_args()

    node = TGSNode(args.id, args.port, args.keys_dir)
    node.start()


if __name__ == "__main__":
    main()
