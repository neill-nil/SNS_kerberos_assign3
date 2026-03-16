import json
import os
from crypto_utils import generate_schnorr_keypair

def main():
    config = {
        "clients": {},
        "services": {},
        "as_nodes": {},
        "tgs_nodes": {},
        "shared_keys": {}
    }
    num_clients = int(sys.argv[1]) if len(sys.argv) > 1 else 1

    # Multiple Clients can be supported
    for i in range(1, num_clients + 1):
        config["clients"][f"Client_{i}"] = {
            "k_c": os.urandom(32).hex() # Client long-term key shared with AS cluster
        }
    
    # AS Nodes
    for i in range(1, 4):
        x, y = generate_schnorr_keypair()
        config["as_nodes"][f"AS_{i}"] = {
            "private_key": x,
            "public_key": y,
            "port": 5000 + i
        }
    
    # TGS Nodes
    for i in range(1, 4):
        x, y = generate_schnorr_keypair()
        config["tgs_nodes"][f"TGS_{i}"] = {
            "private_key": x,
            "public_key": y,
            "port": 6000 + i
        }
    
    # Service Config
    config["services"]["Service_1"] = {
        "k_v": os.urandom(32).hex(), # Service long-term key shared with TGS cluster
        "port": 7001
    }
    
    # Cluster shared keys/seeds
    config["shared_keys"]["k_tgs"] = os.urandom(32).hex() # TGT encryption key (AS <-> TGS) 
    config["shared_keys"]["as_seed"] = os.urandom(32).hex() # Master AS seed for deterministic session keys
    config["shared_keys"]["tgs_seed"] = os.urandom(32).hex() # Master TGS seed for deterministic session keys
    
    with open("config.json", "w") as f:
        json.dump(config, f, indent=4)
        
    print("Successfully generated all cryptographic material securely in config.json")

if __name__ == "__main__":
    import sys
    main()
