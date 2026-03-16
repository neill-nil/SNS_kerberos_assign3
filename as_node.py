SECURITY.mdimport sys
import json
import socket
import socketserver
import hashlib
from crypto_utils import aes_cbc_encrypt, schnorr_sign

class ASNodeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(4096).decode('utf-8')
        if not data:
            return
        req = json.loads(data)
        
        client_id = req["client_id"]
        tgs_id = req["tgs_id"]
        client_timestamp = req["timestamp"]
        
        server = self.server
        print(f"[{server.as_id}] Received Phase 1 request from {client_id}")
        k_c = bytes.fromhex(server.config["clients"][client_id]["k_c"])
        k_tgs = bytes.fromhex(server.config["shared_keys"]["k_tgs"])
        as_seed = server.config["shared_keys"]["as_seed"]
        
        # Deterministically generate Session Key (Client <-> TGS)
        hasher = hashlib.sha256()
        hasher.update(as_seed.encode())
        hasher.update(client_id.encode())
        hasher.update(tgs_id.encode())
        hasher.update(client_timestamp.encode())
        session_key_c_tgs = hasher.hexdigest()[:32] # 32 bytes for AES-256
        
        lifetime = "3600" # 1 hour
        key_version = "1"
        
        # Construct exact plain ticket
        ticket_plaintext = f"{client_id},{tgs_id},{client_timestamp},{lifetime},{session_key_c_tgs},{key_version}"
        
        # Sign the plain ticket
        private_key = server.config["as_nodes"][server.as_id]["private_key"]
        R, s = schnorr_sign(ticket_plaintext.encode('utf-8'), private_key, server.as_id)
        
        # Encrypt the ticket with TGS key
        encrypted_ticket = aes_cbc_encrypt(k_tgs, ticket_plaintext.encode('utf-8'))
        
        # Encrypt the session key for the client
        client_payload = f"{session_key_c_tgs},{tgs_id},{client_timestamp}"
        encrypted_session_key = aes_cbc_encrypt(k_c, client_payload.encode('utf-8'))
        
        resp = {
            "auth_id": server.as_id,
            "encrypted_session_key": encrypted_session_key.hex(),
            "encrypted_ticket": encrypted_ticket.hex(),
            "signature": {"R": R, "s": s}
        }
        
        self.request.sendall(json.dumps(resp).encode('utf-8'))

def start_server(as_id):
    with open("config.json", "r") as f:
        config = json.load(f)
    
    port = config["as_nodes"][as_id]["port"]
    
    server = socketserver.ThreadingTCPServer(("127.0.0.1", port), ASNodeHandler)
    server.config = config
    server.as_id = as_id
    
    print(f"[{as_id}] Authentication Server listening on port {port}...")
    server.serve_forever()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python as_node.py <AS_ID> (e.g. AS_1)")
        sys.exit(1)
    start_server(sys.argv[1])
