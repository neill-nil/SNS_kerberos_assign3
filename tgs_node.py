import sys
import json
import socket
import socketserver
import hashlib
from crypto_utils import aes_cbc_encrypt, aes_cbc_decrypt, schnorr_verify, schnorr_sign

class TGSNodeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(16384).decode('utf-8')
        if not data:
            return
        req = json.loads(data)
        
        service_id = req.get("service_id")
        tgt_ticket = req.get("tgt_ticket")
        encrypted_authenticator = bytes.fromhex(req.get("authenticator", ""))
        client_timestamp2 = req.get("timestamp")
        
        server = self.server
        config = server.config
        
        # Determine client ID for logging (since it comes encrypted, we log an attempt first)
        print(f"[{server.tgs_id}] Received Phase 2 TGT presentation")
        
        k_tgs = bytes.fromhex(config["shared_keys"]["k_tgs"])
        
        # 1. Decrypt TGT
        try:
            encrypted_ticket_bytes = bytes.fromhex(tgt_ticket["encrypted_ticket"])
            ticket_plaintext_bytes = aes_cbc_decrypt(k_tgs, encrypted_ticket_bytes)
            ticket_plaintext = ticket_plaintext_bytes.decode('utf-8')
        except Exception as e:
            self.request.sendall(json.dumps({"error": "Failed to decrypt TGT"}).encode('utf-8'))
            return
            
        parts = ticket_plaintext.split(',')
        if len(parts) != 6:
            self.request.sendall(json.dumps({"error": "Invalid TGT format"}).encode('utf-8'))
            return
            
        client_id, tgs_id_tgt, client_timestamp, lifetime, session_key_c_tgs, key_version = parts
        
        # 2. Verify Signatures on the unencrypted payload
        valid_sigs = 0
        used_auths = set()
        
        for sig_data in tgt_ticket.get("signatures", []):
            auth_id = sig_data.get("auth_id")
            if not auth_id or auth_id in used_auths:
                continue 
            
            if auth_id not in config["public_info"]["as_nodes"]:
                continue
                
            pub_key = config["public_info"]["as_nodes"][auth_id]["public_key"]
            R = sig_data["R"]
            s = sig_data["s"]
            
            if schnorr_verify(ticket_plaintext_bytes, R, s, pub_key, auth_id):
                valid_sigs += 1
                used_auths.add(auth_id)
                
        if valid_sigs < 2:
            self.request.sendall(json.dumps({"error": f"Insufficient valid signatures: {valid_sigs}/2 required"}).encode('utf-8'))
            return
            
        # 3. Decrypt Authenticator
        session_key_bytes = bytes.fromhex(session_key_c_tgs)
        if len(session_key_bytes) < 32:
            session_key_bytes = session_key_bytes.rjust(32, b'\0')
        elif len(session_key_bytes) > 32:
            session_key_bytes = session_key_bytes[:32]
            
        try:
            auth_plaintext_bytes = aes_cbc_decrypt(session_key_bytes, encrypted_authenticator)
            auth_plaintext = auth_plaintext_bytes.decode('utf-8')
        except Exception as e:
            self.request.sendall(json.dumps({"error": "Failed to decrypt Authenticator"}).encode('utf-8'))
            return
            
        auth_client_id, auth_timestamp = auth_plaintext.split(',')
        if auth_client_id != client_id or auth_timestamp != client_timestamp2:
            self.request.sendall(json.dumps({"error": "Authenticator mismatch"}).encode('utf-8'))
            return
            
        print(f"[{server.tgs_id}] Successfully authenticated {client_id}. Issuing Service Ticket for {service_id}")
            
        # 4. Generate Service Ticket
        tgs_seed = config["shared_keys"]["tgs_seed"]
        
        hasher = hashlib.sha256()
        hasher.update(tgs_seed.encode())
        hasher.update(client_id.encode())
        hasher.update(service_id.encode())
        hasher.update(client_timestamp2.encode())
        service_session_key = hasher.hexdigest()[:32]
        
        k_v = bytes.fromhex(config["services"][service_id]["k_v"])
        
        service_ticket_plaintext = f"{client_id},{service_id},{client_timestamp2},{lifetime},{service_session_key},{key_version}"
        
        private_key = config["node_data"]["private_key"]
        R, s = schnorr_sign(service_ticket_plaintext.encode('utf-8'), private_key, server.tgs_id)
        
        encrypted_service_ticket = aes_cbc_encrypt(k_v, service_ticket_plaintext.encode('utf-8'))
        
        client_payload = f"{service_session_key},{service_id},{client_timestamp2}"
        encrypted_client_payload = aes_cbc_encrypt(session_key_bytes, client_payload.encode('utf-8'))
        
        resp = {
            "auth_id": server.tgs_id,
            "encrypted_session_key": encrypted_client_payload.hex(),
            "encrypted_ticket": encrypted_service_ticket.hex(),
            "signature": {"R": R, "s": s}
        }
        
        self.request.sendall(json.dumps(resp).encode('utf-8'))

def start_server(tgs_id):
    with open(f"{tgs_id}_config.json", "r") as f:
        config = json.load(f)
    
    port = config["node_data"]["port"]
    
    server = socketserver.ThreadingTCPServer(("127.0.0.1", port), TGSNodeHandler)
    server.config = config
    server.tgs_id = tgs_id
    
    print(f"[{tgs_id}] TGS Server listening on port {port}...")
    server.serve_forever()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python tgs_node.py <TGS_ID> (e.g. TGS_1)")
        sys.exit(1)
    start_server(sys.argv[1])
