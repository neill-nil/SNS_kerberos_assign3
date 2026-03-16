import json
import socket
import time
from crypto_utils import aes_cbc_decrypt, aes_cbc_encrypt

def send_request(port, req_dict):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(("127.0.0.1", port))
        s.sendall(json.dumps(req_dict).encode('utf-8'))
        resp = s.recv(16384).decode('utf-8')
        s.close()
        return json.loads(resp) if resp else None
    except Exception as e:
        return {"error": str(e)}

def run_client(client_id="Client_1"):
    with open("client_keys.json", "r") as f:
        client_keys = json.load(f)
    with open("public_info.json", "r") as f:
        public_info = json.load(f)
        
    if client_id not in client_keys:
        print(f"[Error] No cryptographic material found for {client_id} in client_keys.json")
        return
        
    tgs_id = "TGS_1"
    service_id = "Service_1"
    k_c = bytes.fromhex(client_keys[client_id]["k_c"])
    
    print("\n[Phase 1] Contacting Authentication Servers (AS cluster)...")
    timestamp1 = str(int(time.time()))
    req_as = {
        "client_id": client_id,
        "tgs_id": tgs_id,
        "timestamp": timestamp1
    }
    
    as_responses = []
    for as_node, as_info in public_info["as_nodes"].items():
        resp = send_request(as_info["port"], req_as)
        if resp and "error" not in resp:
            as_responses.append(resp)
            print(f"  Received valid AS response from {as_node}")
        else:
            print(f"  Failed to get valid AS response from {as_node}: {resp}")
            
    if len(as_responses) < 2:
        print("[Error] Failed to collect 2 signatures from AS cluster.")
        return
        
    print(f"  Collected {len(as_responses)} signatures.")
    
    # Extract
    first_resp = as_responses[0]
    enc_session_key = bytes.fromhex(first_resp["encrypted_session_key"])
    
    try:
        session_payload_bytes = aes_cbc_decrypt(k_c, enc_session_key)
        session_payload = session_payload_bytes.decode('utf-8').rstrip('\0')
        session_key_c_tgs, tgs_id_resp, ts_resp = session_payload.split(',')
        if tgs_id_resp != tgs_id or ts_resp != timestamp1:
            raise Exception("Session payload mismatch")
    except Exception as e:
        print(f"[Error] Failed to decrypt session key from AS: {e}")
        return
        
    tgt_ticket = {
        "encrypted_ticket": first_resp["encrypted_ticket"],
        "signatures": []
    }
    for resp in as_responses:
        sig = resp["signature"]
        sig["auth_id"] = resp["auth_id"]
        tgt_ticket["signatures"].append(sig)
        
    print("\n[Phase 2] Contacting Ticket Granting Servers (TGS cluster)...")
    timestamp2 = str(int(time.time()))
    authenticator_payload = f"{client_id},{timestamp2}"
    
    session_key_c_tgs_bytes = bytes.fromhex(session_key_c_tgs)
    if len(session_key_c_tgs_bytes) < 32:
        session_key_c_tgs_bytes = session_key_c_tgs_bytes.rjust(32, b'\0')
    elif len(session_key_c_tgs_bytes) > 32:
        session_key_c_tgs_bytes = session_key_c_tgs_bytes[:32]
        
    enc_authenticator = aes_cbc_encrypt(session_key_c_tgs_bytes, authenticator_payload.encode('utf-8'))
    
    req_tgs = {
        "service_id": service_id,
        "tgt_ticket": tgt_ticket,
        "authenticator": enc_authenticator.hex(),
        "timestamp": timestamp2
    }
    
    tgs_responses = []
    for tgs_node, tgs_info in public_info["tgs_nodes"].items():
        resp = send_request(tgs_info["port"], req_tgs)
        if resp and "error" not in resp:
            tgs_responses.append(resp)
            print(f"  Received valid TGS response from {tgs_node}")
        else:
            print(f"  Failed to get valid TGS response from {tgs_node}: {resp}")
            
    if len(tgs_responses) < 2:
        print("[Error] Failed to collect 2 signatures from TGS cluster.")
        return
        
    print(f"  Collected {len(tgs_responses)} signatures.")
    
    first_tgs_resp = tgs_responses[0]
    enc_service_session_key = bytes.fromhex(first_tgs_resp["encrypted_session_key"])
    
    try:
        service_payload_bytes = aes_cbc_decrypt(session_key_c_tgs_bytes, enc_service_session_key)
        service_payload = service_payload_bytes.decode('utf-8').rstrip('\0')
        service_session_key, srv_id_resp, ts_resp2 = service_payload.split(',')
        if srv_id_resp != service_id or ts_resp2 != timestamp2:
            raise Exception("Service Session payload mismatch")
    except Exception as e:
        print(f"[Error] Failed to decrypt service session key from TGS: {e}")
        return
        
    service_ticket = {
        "encrypted_ticket": first_tgs_resp["encrypted_ticket"],
        "signatures": []
    }
    for resp in tgs_responses:
        sig = resp["signature"]
        sig["auth_id"] = resp["auth_id"]
        service_ticket["signatures"].append(sig)
        
    print("\n[Phase 3] Contacting Service Server...")
    timestamp3 = str(int(time.time()))
    auth3_payload = f"{client_id},{timestamp3}"
    
    service_session_key_bytes = bytes.fromhex(service_session_key)
    if len(service_session_key_bytes) < 32:
        service_session_key_bytes = service_session_key_bytes.rjust(32, b'\0')
    elif len(service_session_key_bytes) > 32:
        service_session_key_bytes = service_session_key_bytes[:32]
        
    enc_authenticator3 = aes_cbc_encrypt(service_session_key_bytes, auth3_payload.encode('utf-8'))
    
    req_service = {
        "service_ticket": service_ticket,
        "authenticator": enc_authenticator3.hex(),
        "timestamp": timestamp3
    }
    
    srv_port = public_info["services"][service_id]["port"]
    resp = send_request(srv_port, req_service)
    
    if resp and resp.get("status") == "success":
        print(f"\n[SUCCESS] Server responded: {resp.get('message')}")
    else:
        print(f"\n[FAILURE] Server responded: {resp}")

if __name__ == "__main__":
    import sys
    # Example usage: python client.py Client_2
    cid = sys.argv[1] if len(sys.argv) > 1 else "Client_1"
    run_client(cid)
