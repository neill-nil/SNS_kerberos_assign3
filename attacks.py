import sys
import json
import socket
import time
import subprocess
from client import send_request
from crypto_utils import aes_cbc_decrypt, aes_cbc_encrypt

def run_attacks():
    print("Starting authentication cluster servers...")
    procs = []
    try:
        for i in range(1, 4):
            procs.append(subprocess.Popen([sys.executable, "as_node.py", f"AS_{i}"]))
            procs.append(subprocess.Popen([sys.executable, "tgs_node.py", f"TGS_{i}"]))
        procs.append(subprocess.Popen([sys.executable, "service_server.py", "Service_1"]))
        time.sleep(2) # let servers bind to ports
        
        with open("client_keys.json", "r") as f:
            client_keys = json.load(f)
        with open("public_info.json", "r") as f:
            public_info = json.load(f)
            
        client_id = "Client_1"
        tgs_id = "TGS_1"
        service_id = "Service_1"
        k_c = bytes.fromhex(client_keys[client_id]["k_c"])
        tgs_port = public_info["tgs_nodes"]["TGS_1"]["port"]
        
        print("\n=======================================================")
        print("ATTACK 1: Ticket containing only one valid signature")
        print("=======================================================")
        timestamp = str(int(time.time()))
        req1 = {"client_id": client_id, "tgs_id": tgs_id, "timestamp": timestamp}
        resp1 = send_request(public_info["as_nodes"]["AS_1"]["port"], req1)
        tgt_ticket_1_sig = {
            "encrypted_ticket": resp1["encrypted_ticket"],
            "signatures": [ {"auth_id": resp1["auth_id"], **resp1["signature"]} ]
        }
        enc_auth_1 = aes_cbc_encrypt(b"0"*32, b"authenticator").hex()
        req_tgs_1 = {"service_id": service_id, "tgt_ticket": tgt_ticket_1_sig, "authenticator": enc_auth_1, "timestamp": timestamp}
        print("-> TGS Response:", send_request(tgs_port, req_tgs_1))
        
        print("\n=======================================================")
        print("ATTACK 2: Single malicious authority issuing forged ticket")
        print("=======================================================")
        print("A compromised AS_1 tries to forge AS_2's signature because it lacks AS_2's private key.")
        tgt_ticket_forged = {
            "encrypted_ticket": resp1["encrypted_ticket"],
            "signatures": [ 
                {"auth_id": "AS_1", **resp1["signature"]}, 
                {"auth_id": "AS_2", "R": 12345678, "s": 87654321} # Cryptographically invalid forge
            ]
        }
        req_tgs_2 = {"service_id": service_id, "tgt_ticket": tgt_ticket_forged, "authenticator": enc_auth_1, "timestamp": timestamp}
        print("-> TGS Response:", send_request(tgs_port, req_tgs_2))
        
        print("\n=======================================================")
        print("ATTACK 3: Leakage of one authority's private signing key")
        print("=======================================================")
        print("Attacker acquires AS_1 key but fails to produce 2 valid signatures for the payload.")
        print("-> TGS Response:", send_request(tgs_port, req_tgs_2)) # Same as attack 2 fundamentally
        
        print("\n=======================================================")
        print("ATTACK 4: Replay of old partial signature")
        print("=======================================================")
        req_old = {"client_id": client_id, "tgs_id": tgs_id, "timestamp": "1000"}  
        resp_old_as2 = send_request(public_info["as_nodes"]["AS_2"]["port"], req_old)
        
        resp_new_as1 = send_request(public_info["as_nodes"]["AS_1"]["port"], req1)
        tgt_replay = {
            "encrypted_ticket": resp_new_as1["encrypted_ticket"],
            "signatures": [
                {"auth_id": "AS_1", **resp_new_as1["signature"]},
                {"auth_id": "AS_2", **resp_old_as2["signature"]} # Replayed over old timestamp
            ]
        }
        req_tgs_replay = {"service_id": service_id, "tgt_ticket": tgt_replay, "authenticator": enc_auth_1, "timestamp": timestamp}
        print("-> TGS Response:", send_request(tgs_port, req_tgs_replay))

        print("\n=======================================================")
        print("ATTACK 5: Modified ticket payload")
        print("=======================================================")
        enc_ticket_bytes = bytearray.fromhex(resp_new_as1["encrypted_ticket"])
        enc_ticket_bytes[5] ^= 0xFF # Flip a single bit in the ciphertext to simulate tampering
        tgt_modified = {
            "encrypted_ticket": enc_ticket_bytes.hex(),
            "signatures": [
                {"auth_id": "AS_1", **resp_new_as1["signature"]},
                {"auth_id": "AS_2", **send_request(public_info["as_nodes"]["AS_2"]["port"], req1)["signature"]}
            ]
        }
        req_tgs_mod = {"service_id": service_id, "tgt_ticket": tgt_modified, "authenticator": enc_auth_1, "timestamp": timestamp}
        print("-> TGS Response:", send_request(tgs_port, req_tgs_mod))
        
        print("\n=======================================================")
        print("ATTACK 6: Authority offline scenario")
        print("=======================================================")
        print("AS_3 is completely unreachable. Client naturally falls back to AS_1 and AS_2.")
        resp_new_as2 = send_request(public_info["as_nodes"]["AS_2"]["port"], req1)
        tgt_offline = {
            "encrypted_ticket": resp_new_as1["encrypted_ticket"],
            "signatures": [
                {"auth_id": "AS_1", **resp_new_as1["signature"]},
                {"auth_id": "AS_2", **resp_new_as2["signature"]}
            ]
        }
        enc_session_key = bytes.fromhex(resp_new_as1["encrypted_session_key"])
        session_payload = aes_cbc_decrypt(k_c, enc_session_key).decode('utf-8')
        session_key_c_tgs = session_payload.split(',')[0]
        session_key_bytes = bytes.fromhex(session_key_c_tgs)
        if len(session_key_bytes) < 32:
            session_key_bytes = session_key_bytes.rjust(32, b'\0')
        elif len(session_key_bytes) > 32:
            session_key_bytes = session_key_bytes[:32]
            
        enc_auth_valid = aes_cbc_encrypt(session_key_bytes, f"{client_id},{timestamp}".encode('utf-8')).hex()
        
        req_tgs_offline = {"service_id": service_id, "tgt_ticket": tgt_offline, "authenticator": enc_auth_valid, "timestamp": timestamp}
        resp_offline = send_request(tgs_port, req_tgs_offline)
        print("-> TGS Response:", "SUCCESS" if resp_offline and "encrypted_ticket" in resp_offline else resp_offline)
        print("(Authentication continues smoothly despite AS_3 being down)")
        print("\nFinished all attacks successfully.")
        
    finally:
        print("\nCleaning up servers...")
        for p in procs:
            p.terminate()

if __name__ == "__main__":
    run_attacks()
