import sys
import json
import socket
import socketserver
from crypto_utils import aes_cbc_decrypt, schnorr_verify

class ServiceHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(16384).decode('utf-8')
        if not data:
            return
        req = json.loads(data)
        
        service_ticket = req.get("service_ticket")
        encrypted_authenticator = bytes.fromhex(req.get("authenticator", ""))
        client_timestamp3 = req.get("timestamp")
        
        server = self.server
        config = server.config
        
        print(f"[{server.service_id}] Received Phase 3 Service presentation")
        
        k_v = bytes.fromhex(config["node_data"]["k_v"])
        
        # 1. Decrypt Service Ticket
        try:
            encrypted_ticket_bytes = bytes.fromhex(service_ticket["encrypted_ticket"])
            ticket_plaintext_bytes = aes_cbc_decrypt(k_v, encrypted_ticket_bytes)
            ticket_plaintext = ticket_plaintext_bytes.decode('utf-8')
        except Exception as e:
            self.request.sendall(json.dumps({"error": "Failed to decrypt Service Ticket"}).encode('utf-8'))
            return
            
        parts = ticket_plaintext.split(',')
        if len(parts) != 6:
            self.request.sendall(json.dumps({"error": "Invalid Ticket format"}).encode('utf-8'))
            return
            
        client_id, service_id_ticket, client_timestamp2, lifetime, service_session_key, key_version = parts
        
        # 2. Verify Signatures on the unencrypted payload
        valid_sigs = 0
        used_auths = set()
        
        for sig_data in service_ticket.get("signatures", []):
            auth_id = sig_data.get("auth_id")
            if not auth_id or auth_id in used_auths:
                continue
                
            if auth_id not in config["public_info"]["tgs_nodes"]:
                continue
                
            pub_key = config["public_info"]["tgs_nodes"][auth_id]["public_key"]
            R = sig_data["R"]
            s = sig_data["s"]
            
            if schnorr_verify(ticket_plaintext_bytes, R, s, pub_key, auth_id):
                valid_sigs += 1
                used_auths.add(auth_id)
                
        if valid_sigs < 2:
            self.request.sendall(json.dumps({"error": f"Insufficient valid TGS signatures: {valid_sigs}/2 required"}).encode('utf-8'))
            return
            
        # 3. Decrypt Authenticator
        session_key_bytes = bytes.fromhex(service_session_key)
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
        if auth_client_id != client_id or auth_timestamp != client_timestamp3:
            self.request.sendall(json.dumps({"error": "Authenticator mismatch"}).encode('utf-8'))
            return
            
        print(f"[{server.service_id}] ACCESS GRANTED: User {client_id} verified by {valid_sigs} TGS signatures!")
            
        # Authentication successful
        resp = {
            "status": "success",
            "message": f"Welcome {client_id}! You have been successfully authenticated by 2-of-3 Schnorr multi-signature Kerberos."
        }
        
        self.request.sendall(json.dumps(resp).encode('utf-8'))

def start_server(service_id):
    with open(f"{service_id}_config.json", "r") as f:
        config = json.load(f)
    
    port = config["node_data"]["port"]
    
    server = socketserver.ThreadingTCPServer(("127.0.0.1", port), ServiceHandler)
    server.config = config
    server.service_id = service_id
    
    print(f"[{service_id}] Service Server listening on port {port}...")
    server.serve_forever()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python service_server.py <Service_ID> (e.g. Service_1)")
        sys.exit(1)
    start_server(sys.argv[1])
