import json
import os
import sys
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
    
    # Dump Public Information
    public_config = {
        "as_nodes": {k: {"public_key": v["public_key"], "port": v["port"]} for k,v in config["as_nodes"].items()},
        "tgs_nodes": {k: {"public_key": v["public_key"], "port": v["port"]} for k,v in config["tgs_nodes"].items()},
        "services": {k: {"port": v["port"]} for k,v in config["services"].items()}
    }
    with open("public_info.json", "w") as f:
        json.dump(public_config, f, indent=4)
        
    # Dump Node-Specific Configs
    for as_id, as_data in config["as_nodes"].items():
        node_cfg = {
            "node_data": as_data,
            "clients": config["clients"],
            "shared_keys": {"k_tgs": config["shared_keys"]["k_tgs"], "as_seed": config["shared_keys"]["as_seed"]},
            "public_info": public_config
        }
        with open(f"{as_id}_config.json", "w") as f:
            json.dump(node_cfg, f, indent=4)
            
    for tgs_id, tgs_data in config["tgs_nodes"].items():
        node_cfg = {
            "node_data": tgs_data,
            "shared_keys": {"k_tgs": config["shared_keys"]["k_tgs"], "tgs_seed": config["shared_keys"]["tgs_seed"]},
            "services": config["services"],
            "public_info": public_config
        }
        with open(f"{tgs_id}_config.json", "w") as f:
            json.dump(node_cfg, f, indent=4)
            
    for srv_id, srv_data in config["services"].items():
        node_cfg = {
            "node_data": srv_data,
            "public_info": public_config
        }
        with open(f"{srv_id}_config.json", "w") as f:
            json.dump(node_cfg, f, indent=4)
            
    # Dump Client Keys
    with open("client_keys.json", "w") as f:
        json.dump(config["clients"], f, indent=4)
        
    print("Successfully generated all isolated cryptographic material into individual config files.")

if __name__ == "__main__":
    main()
