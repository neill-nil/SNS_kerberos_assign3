"""
client.py
Client for Kerberos Multi-Signature System.

Orchestrates the full 3-phase authentication protocol:
  Phase 1: Contact AS cluster → collect ≥2 signatures → assemble TGT
  Phase 2: Contact TGS cluster → collect ≥2 signatures → assemble Service Ticket
  Phase 3: Contact Service Server → access service

Usage:
    python client.py --client-id alice --password alice_password \\
                     --service file_server --keys-dir keys

    Optional: specify custom ports:
    python client.py --client-id alice --password alice_password \\
                     --service file_server \\
                     --as-ports 5001,5002,5003 \\
                     --tgs-ports 6001,6002,6003 \\
                     --service-port 7001
"""

import argparse
import base64
import hashlib
import json
import socket
import sys
import time

from crypto_utils import (
    load_json,
    deserialize_params,
    schnorr_verify,
    aes_decrypt,
    aes_encrypt,
)

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

BUFFER_SIZE = 65536
SOCKET_TIMEOUT = 10  # seconds


# ─────────────────────────────────────────────
# Network Helpers
# ─────────────────────────────────────────────

def send_request(host, port, request):
    """
    Send a JSON request to a server and return the JSON response.
    Returns None if the connection fails (authority offline).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)
        sock.connect((host, port))
        sock.sendall(json.dumps(request).encode('utf-8'))
        data = sock.recv(BUFFER_SIZE)
        sock.close()
        return json.loads(data.decode('utf-8'))
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        return None
    except Exception as e:
        print(f"    [!] Unexpected error contacting {host}:{port}: {e}")
        return None


# ─────────────────────────────────────────────
# Client Class
# ─────────────────────────────────────────────

class KerberosClient:
    def __init__(self, client_id, password, keys_dir,
                 as_ports=None, tgs_ports=None, service_port=None):
        self.client_id = client_id
        self.password = password
        self.password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        self.keys_dir = keys_dir

        # Default ports
        self.as_ports = as_ports or [5001, 5002, 5003]
        self.tgs_ports = tgs_ports or [6001, 6002, 6003]
        self.service_port = service_port or 7001

        # Load public parameters
        self._load_params()

        # State (populated during protocol)
        self.session_key_tgs = None   # K_c_tgs (from Phase 1)
        self.tgt_data = None          # TGT bundle (from Phase 1)
        self.session_key_service = None  # K_c_v (from Phase 2)
        self.service_ticket_data = None  # Service ticket bundle (from Phase 2)

    def _load_params(self):
        """Load public parameters and all authority public keys."""
        public_params = load_json(
            f"{self.keys_dir}/public_params.json"
        )
        self.p, self.q, self.g = deserialize_params(
            public_params["schnorr_params"]
        )
        self.key_version = public_params["key_version"]
        self.required_signatures = public_params["required_signatures"]

        self.as_public_keys = {
            auth_id: int(y_str)
            for auth_id, y_str in public_params["as_public_keys"].items()
        }
        self.tgs_public_keys = {
            auth_id: int(y_str)
            for auth_id, y_str in public_params["tgs_public_keys"].items()
        }

    def _derive_client_key(self):
        """Derive AES key from password hash (same as AS does)."""
        return hashlib.sha256(self.password_hash.encode('utf-8')).digest()

    # ═════════════════════════════════════════════
    # Phase 1: AS Exchange — Obtain TGT
    # ═════════════════════════════════════════════

    def phase1_get_tgt(self):
        """
        Contact AS cluster, collect ≥2 valid signatures, assemble TGT.

        Returns True on success, False on failure.
        """
        print("\n" + "=" * 60)
        print("  Phase 1: Authentication Service Exchange (TGT)")
        print("=" * 60)

        timestamp = int(time.time())

        auth_request = {
            "type": "AUTH_REQUEST",
            "client_id": self.client_id,
            "password_hash": self.password_hash,
            "timestamp": timestamp,
        }

        # Contact all AS nodes
        responses = []
        for i, port in enumerate(self.as_ports):
            auth_id = f"AS{i + 1}"
            print(f"\n  [{auth_id}] Contacting localhost:{port}...")
            resp = send_request('localhost', port, auth_request)

            if resp is None:
                print(f"  [{auth_id}] ⚠ OFFLINE (connection refused)")
                continue
            if resp.get("status") == "error":
                print(f"  [{auth_id}] ✗ Error: {resp.get('error')}")
                continue

            # Verify the signature from this AS
            ticket_payload = resp["ticket_payload"]
            R_i = int(resp["signature_R"])
            s_i = int(resp["signature_s"])
            authority_id = resp["authority_id"]

            if authority_id not in self.as_public_keys:
                print(f"  [{auth_id}] ✗ Unknown authority ID: {authority_id}")
                continue

            y_i = self.as_public_keys[authority_id]
            if schnorr_verify(ticket_payload, R_i, s_i, authority_id,
                              y_i, self.p, self.q, self.g):
                print(f"  [{auth_id}] ✓ Signature verified")
                responses.append(resp)
            else:
                print(f"  [{auth_id}] ✗ Invalid signature!")

        # Check we have enough valid responses
        if len(responses) < self.required_signatures:
            print(f"\n  ✗ FAILED: Only {len(responses)} valid responses "
                  f"(need {self.required_signatures})")
            return False

        print(f"\n  Collected {len(responses)} valid AS signatures "
              f"(need {self.required_signatures}) ✓")

        # Use the first response's encrypted TGT and session info
        primary = responses[0]

        # Decrypt session info to get K_c_tgs
        client_key = self._derive_client_key()
        try:
            session_info_bytes = aes_decrypt(
                client_key,
                base64.b64decode(primary["encrypted_session_info"])
            )
            session_info = json.loads(session_info_bytes.decode('utf-8'))
            self.session_key_tgs = session_info["session_key"]
            print(f"  Session key K_c_tgs obtained ✓")
        except Exception as e:
            print(f"  ✗ Failed to decrypt session info: {e}")
            return False

        # Bundle TGT data
        signatures = []
        for resp in responses:
            signatures.append({
                "R": resp["signature_R"],
                "s": resp["signature_s"],
                "authority_id": resp["authority_id"],
            })

        self.tgt_data = {
            "ticket_payload": primary["ticket_payload"],
            "encrypted_tgt": primary["encrypted_tgt"],
            "signatures": signatures,
            "key_version": primary["key_version"],
        }

        print(f"\n  ✓ TGT assembled successfully")
        print(f"    Ticket payload: {primary['ticket_payload']}")
        print(f"    Signatures from: "
              f"{[s['authority_id'] for s in signatures]}")
        return True

    # ═════════════════════════════════════════════
    # Phase 2: TGS Exchange — Obtain Service Ticket
    # ═════════════════════════════════════════════

    def phase2_get_service_ticket(self, target_service):
        """
        Contact TGS cluster with TGT, collect ≥2 valid signatures,
        assemble Service Ticket.

        Returns True on success, False on failure.
        """
        print("\n" + "=" * 60)
        print(f"  Phase 2: TGS Exchange (Service Ticket for '{target_service}')")
        print("=" * 60)

        if self.tgt_data is None or self.session_key_tgs is None:
            print("  ✗ No TGT available. Run Phase 1 first.")
            return False

        # Build authenticator
        timestamp = int(time.time())
        authenticator = json.dumps({
            "client_id": self.client_id,
            "timestamp": timestamp,
        }).encode('utf-8')
        k_c_tgs = bytes.fromhex(self.session_key_tgs)
        encrypted_authenticator = aes_encrypt(k_c_tgs, authenticator)

        tgs_request = {
            "type": "TGS_REQUEST",
            "ticket_payload": self.tgt_data["ticket_payload"],
            "encrypted_tgt": self.tgt_data["encrypted_tgt"],
            "signatures": self.tgt_data["signatures"],
            "authenticator": base64.b64encode(
                encrypted_authenticator).decode('ascii'),
            "target_service": target_service,
        }

        # Contact all TGS nodes
        responses = []
        for i, port in enumerate(self.tgs_ports):
            tgs_id = f"TGS{i + 1}"
            print(f"\n  [{tgs_id}] Contacting localhost:{port}...")
            resp = send_request('localhost', port, tgs_request)

            if resp is None:
                print(f"  [{tgs_id}] ⚠ OFFLINE (connection refused)")
                continue
            if resp.get("status") == "error":
                print(f"  [{tgs_id}] ✗ Error: {resp.get('error')}")
                continue

            # Verify the TGS signature
            svc_ticket_payload = resp["service_ticket_payload"]
            R_i = int(resp["signature_R"])
            s_i = int(resp["signature_s"])
            authority_id = resp["authority_id"]

            if authority_id not in self.tgs_public_keys:
                print(f"  [{tgs_id}] ✗ Unknown authority ID: {authority_id}")
                continue

            y_i = self.tgs_public_keys[authority_id]
            if schnorr_verify(svc_ticket_payload, R_i, s_i, authority_id,
                              y_i, self.p, self.q, self.g):
                print(f"  [{tgs_id}] ✓ Signature verified")
                responses.append(resp)
            else:
                print(f"  [{tgs_id}] ✗ Invalid signature!")

        if len(responses) < self.required_signatures:
            print(f"\n  ✗ FAILED: Only {len(responses)} valid responses "
                  f"(need {self.required_signatures})")
            return False

        print(f"\n  Collected {len(responses)} valid TGS signatures "
              f"(need {self.required_signatures}) ✓")

        # Use the first response's encrypted service ticket and session info
        primary = responses[0]

        # Decrypt session info to get K_c_v
        try:
            session_info_bytes = aes_decrypt(
                k_c_tgs,
                base64.b64decode(primary["encrypted_session_info"])
            )
            session_info = json.loads(session_info_bytes.decode('utf-8'))
            self.session_key_service = session_info["session_key"]
            print(f"  Service session key K_c_v obtained ✓")
        except Exception as e:
            print(f"  ✗ Failed to decrypt session info: {e}")
            return False

        # Bundle service ticket data
        signatures = []
        for resp in responses:
            signatures.append({
                "R": resp["signature_R"],
                "s": resp["signature_s"],
                "authority_id": resp["authority_id"],
            })

        self.service_ticket_data = {
            "service_ticket_payload": primary["service_ticket_payload"],
            "encrypted_service_ticket": primary["encrypted_service_ticket"],
            "signatures": signatures,
            "key_version": primary["key_version"],
        }

        print(f"\n  ✓ Service Ticket assembled successfully")
        print(f"    Payload: {primary['service_ticket_payload']}")
        print(f"    Signatures from: "
              f"{[s['authority_id'] for s in signatures]}")
        return True

    # ═════════════════════════════════════════════
    # Phase 3: Service Access
    # ═════════════════════════════════════════════

    def phase3_access_service(self, service_port=None):
        """
        Contact the Service Server with the Service Ticket.

        Returns True on success, False on failure.
        """
        port = service_port or self.service_port

        print("\n" + "=" * 60)
        print(f"  Phase 3: Service Access (port {port})")
        print("=" * 60)

        if self.service_ticket_data is None or self.session_key_service is None:
            print("  ✗ No Service Ticket available. Run Phase 2 first.")
            return False

        # Build authenticator for the service
        timestamp = int(time.time())
        authenticator = json.dumps({
            "client_id": self.client_id,
            "timestamp": timestamp,
        }).encode('utf-8')
        k_c_v = bytes.fromhex(self.session_key_service)
        encrypted_authenticator = aes_encrypt(k_c_v, authenticator)

        service_request = {
            "type": "SERVICE_REQUEST",
            "service_ticket_payload": self.service_ticket_data[
                "service_ticket_payload"],
            "encrypted_service_ticket": self.service_ticket_data[
                "encrypted_service_ticket"],
            "signatures": self.service_ticket_data["signatures"],
            "authenticator": base64.b64encode(
                encrypted_authenticator).decode('ascii'),
        }

        print(f"\n  Contacting service at localhost:{port}...")
        resp = send_request('localhost', port, service_request)

        if resp is None:
            print(f"  ✗ Service OFFLINE (connection refused)")
            return False

        if resp.get("status") == "error":
            print(f"  ✗ Service error: {resp.get('error')}")
            return False

        # Verify server authenticator (mutual authentication)
        try:
            server_auth_bytes = aes_decrypt(
                k_c_v,
                base64.b64decode(resp["server_authenticator"])
            )
            server_auth = json.loads(server_auth_bytes.decode('utf-8'))

            if server_auth.get("timestamp") == timestamp + 1:
                print(f"  ✓ Server authenticated (timestamp+1 verified)")
            else:
                print(f"  ⚠ Server authenticator timestamp mismatch")
        except Exception as e:
            print(f"  ⚠ Could not verify server authenticator: {e}")

        print(f"\n  ✓ ACCESS GRANTED")
        print(f"    Service: {resp.get('service_id')}")
        print(f"    Message: {resp.get('message')}")
        return True

    # ═════════════════════════════════════════════
    # Full Protocol Run
    # ═════════════════════════════════════════════

    def run_full_protocol(self, target_service, service_port=None):
        """Execute the complete 3-phase Kerberos protocol."""
        print("\n" + "╔" + "═" * 58 + "╗")
        print("║  KERBEROS MULTI-SIGNATURE CLIENT                        ║")
        print("╚" + "═" * 58 + "╝")
        print(f"  Client: {self.client_id}")
        print(f"  Target: {target_service}")

        # Phase 1
        if not self.phase1_get_tgt():
            print("\n  ✗ Protocol failed at Phase 1")
            return False

        # Phase 2
        if not self.phase2_get_service_ticket(target_service):
            print("\n  ✗ Protocol failed at Phase 2")
            return False

        # Phase 3
        if not self.phase3_access_service(service_port):
            print("\n  ✗ Protocol failed at Phase 3")
            return False

        print("\n" + "╔" + "═" * 58 + "╗")
        print("║  PROTOCOL COMPLETE — ALL PHASES SUCCESSFUL              ║")
        print("╚" + "═" * 58 + "╝")
        return True


def main():
    parser = argparse.ArgumentParser(
        description="Kerberos Multi-Signature Client"
    )
    parser.add_argument("--client-id", type=str, required=True,
                        help="Client identifier (e.g., alice, bob)")
    parser.add_argument("--password", type=str, required=True,
                        help="Client password")
    parser.add_argument("--service", type=str, required=True,
                        help="Target service (e.g., file_server)")
    parser.add_argument("--keys-dir", type=str, default="keys",
                        help="Directory containing public_params.json")
    parser.add_argument("--as-ports", type=str, default="5001,5002,5003",
                        help="Comma-separated AS ports")
    parser.add_argument("--tgs-ports", type=str, default="6001,6002,6003",
                        help="Comma-separated TGS ports")
    parser.add_argument("--service-port", type=int, default=7001,
                        help="Service server port")
    args = parser.parse_args()

    as_ports = [int(p) for p in args.as_ports.split(',')]
    tgs_ports = [int(p) for p in args.tgs_ports.split(',')]

    client = KerberosClient(
        client_id=args.client_id,
        password=args.password,
        keys_dir=args.keys_dir,
        as_ports=as_ports,
        tgs_ports=tgs_ports,
        service_port=args.service_port,
    )

    success = client.run_full_protocol(args.service, args.service_port)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
