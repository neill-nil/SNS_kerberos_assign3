"""
attacks.py
Mandatory Attack Scenarios for Kerberos Multi-Signature System.

Demonstrates 6 attack scenarios and shows that the system contains them:
  1. Single malicious authority issuing forged ticket
  2. Modified ticket payload
  3. Replay of old partial signature
  4. Leakage of one authority's private signing key
  5. Authority offline scenario
  6. Ticket containing only one valid signature

Usage:
    # First generate keys and start all servers, then:
    python attacks.py --keys-dir keys

    # Or run a specific attack:
    python attacks.py --keys-dir keys --attack 1
"""

import argparse
import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import signal

from crypto_utils import (
    load_json,
    deserialize_params,
    schnorr_sign,
    schnorr_verify,
    verify_multi_signatures,
    aes_encrypt,
    aes_decrypt,
    generate_session_key,
    mod_exp,
    secure_random,
    hash_to_challenge,
    mod_add,
    mod_mul,
)

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

BUFFER_SIZE = 65536
SOCKET_TIMEOUT = 5


def send_request(host, port, request):
    """Send JSON request, return JSON response or None."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)
        sock.connect((host, port))
        sock.sendall(json.dumps(request).encode('utf-8'))
        data = sock.recv(BUFFER_SIZE)
        sock.close()
        return json.loads(data.decode('utf-8'))
    except Exception:
        return None


def derive_client_key(password_hash):
    return hashlib.sha256(password_hash.encode('utf-8')).digest()


def load_system_params(keys_dir):
    """Load all system parameters for attack simulations."""
    public_params = load_json(os.path.join(keys_dir, "public_params.json"))
    p, q, g = deserialize_params(public_params["schnorr_params"])

    as_public_keys = {
        k: int(v) for k, v in public_params["as_public_keys"].items()
    }
    tgs_public_keys = {
        k: int(v) for k, v in public_params["tgs_public_keys"].items()
    }

    db = load_json(os.path.join(keys_dir, "client_db.json"))
    key_version = public_params["key_version"]

    return {
        "p": p, "q": q, "g": g,
        "as_public_keys": as_public_keys,
        "tgs_public_keys": tgs_public_keys,
        "key_version": key_version,
        "client_db": db,
    }


def get_legitimate_tgt(keys_dir, client_id="alice", password="alice_password"):
    """Get a legitimate TGT by contacting AS nodes (requires servers running)."""
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    timestamp = int(time.time())

    auth_request = {
        "type": "AUTH_REQUEST",
        "client_id": client_id,
        "password_hash": password_hash,
        "timestamp": timestamp,
    }

    responses = []
    for port in [5001, 5002, 5003]:
        resp = send_request('localhost', port, auth_request)
        if resp and resp.get("status") == "success":
            responses.append(resp)

    if len(responses) < 2:
        return None

    primary = responses[0]
    client_key = derive_client_key(password_hash)
    session_info_bytes = aes_decrypt(
        client_key, base64.b64decode(primary["encrypted_session_info"])
    )
    session_info = json.loads(session_info_bytes.decode('utf-8'))

    signatures = [
        {"R": r["signature_R"], "s": r["signature_s"],
         "authority_id": r["authority_id"]}
        for r in responses
    ]

    return {
        "ticket_payload": primary["ticket_payload"],
        "encrypted_tgt": primary["encrypted_tgt"],
        "signatures": signatures,
        "session_key": session_info["session_key"],
        "key_version": primary["key_version"],
    }


def print_header(attack_num, title):
    print("\n" + "=" * 65)
    print(f"  ATTACK {attack_num}: {title}")
    print("=" * 65)


def print_result(success, message):
    icon = "✓ CONTAINED" if success else "✗ VULNERABLE"
    print(f"\n  [{icon}] {message}")


# ─────────────────────────────────────────────
# Attack 1: Single Malicious Authority Forged Ticket
# ─────────────────────────────────────────────

def attack_1_single_malicious_authority(params, keys_dir):
    """
    Scenario: Attacker has fully compromised AS1 and tries to issue
    a forged TGT signed only by AS1. The system must reject it
    because only 1 valid signature is present (need 2).
    """
    print_header(1, "Single Malicious Authority Issuing Forged Ticket")
    p, q, g = params["p"], params["q"], params["g"]

    # Attacker loads AS1's private key (compromised)
    as1_private = load_json(os.path.join(keys_dir, "as_private_1.json"))
    x_compromised = int(as1_private["private_key"])
    print("  [Attacker] Compromised AS1, obtained private key")

    # Attacker forges a TGT for user 'mallory' (not a real user)
    forged_payload = f"mallory||tgs||{int(time.time())}||600||1"
    print(f"  [Attacker] Forging TGT: {forged_payload}")

    # Attacker signs with AS1's key
    R1, s1, _ = schnorr_sign(forged_payload, x_compromised, "AS1", p, q, g)
    print(f"  [Attacker] Signed with compromised AS1 key")

    # Attacker also tries to sign as AS2 with AS1's key (wrong key)
    R2_fake, s2_fake, _ = schnorr_sign(
        forged_payload, x_compromised, "AS2", p, q, g
    )
    print(f"  [Attacker] Attempting to sign as AS2 using AS1's key")

    # Verify: AS1's signature should be valid
    y_as1 = params["as_public_keys"]["AS1"]
    sig1_valid = schnorr_verify(
        forged_payload, R1, s1, "AS1", y_as1, p, q, g
    )
    print(f"\n  [Verifier] AS1 signature valid? {sig1_valid}")

    # Verify: Fake AS2 signature should fail
    y_as2 = params["as_public_keys"]["AS2"]
    sig2_valid = schnorr_verify(
        forged_payload, R2_fake, s2_fake, "AS2", y_as2, p, q, g
    )
    print(f"  [Verifier] Fake AS2 signature valid? {sig2_valid}")

    # Multi-sig check
    sigs = [(R1, s1, "AS1"), (R2_fake, s2_fake, "AS2")]
    is_valid, count, details = verify_multi_signatures(
        forged_payload, sigs, params["as_public_keys"], p, q, g, required=2
    )
    print(f"  [Verifier] Multi-sig valid (≥2)? {is_valid} "
          f"(valid: {count}/2)")

    for auth_id, valid, reason in details:
        print(f"    {auth_id}: {reason}")

    contained = not is_valid
    print_result(
        contained,
        "Single compromised authority CANNOT forge a valid ticket "
        "(only 1 valid signature, need 2)"
        if contained else "SECURITY BREACH: Forged ticket accepted!"
    )
    return contained


# ─────────────────────────────────────────────
# Attack 2: Modified Ticket Payload
# ─────────────────────────────────────────────

def attack_2_modified_payload(params, keys_dir):
    """
    Scenario: Attacker intercepts a legitimate TGT and modifies the
    payload (e.g., changes client_id). The signatures should become
    invalid because they were over the original payload.
    """
    print_header(2, "Modified Ticket Payload")
    p, q, g = params["p"], params["q"], params["g"]

    # Get a legitimate TGT
    tgt = get_legitimate_tgt(keys_dir)
    if tgt is None:
        print("  [!] Could not obtain legitimate TGT (are servers running?)")
        return False

    original_payload = tgt["ticket_payload"]
    print(f"  [Legitimate] Original payload: {original_payload}")

    # Attacker modifies the payload — changes client_id
    parts = original_payload.split("||")
    parts[0] = "mallory"  # change alice → mallory
    modified_payload = "||".join(parts)
    print(f"  [Attacker]   Modified payload: {modified_payload}")

    # Check signatures against the MODIFIED payload
    sig_tuples = [
        (int(s["R"]), int(s["s"]), s["authority_id"])
        for s in tgt["signatures"]
    ]

    # Original should verify
    is_valid_original, count_orig, _ = verify_multi_signatures(
        original_payload, sig_tuples, params["as_public_keys"],
        p, q, g, required=2
    )
    print(f"\n  [Verifier] Original payload verification: "
          f"valid={is_valid_original} ({count_orig} valid sigs)")

    # Modified should fail
    is_valid_modified, count_mod, details = verify_multi_signatures(
        modified_payload, sig_tuples, params["as_public_keys"],
        p, q, g, required=2
    )
    print(f"  [Verifier] Modified payload verification: "
          f"valid={is_valid_modified} ({count_mod} valid sigs)")

    for auth_id, valid, reason in details:
        print(f"    {auth_id}: {reason}")

    contained = is_valid_original and not is_valid_modified
    print_result(
        contained,
        "Payload modification detected — signatures invalid on tampered data"
        if contained else "SECURITY BREACH: Modified payload accepted!"
    )
    return contained


# ─────────────────────────────────────────────
# Attack 3: Replay of Old Signature
# ─────────────────────────────────────────────

def attack_3_replay_old_signature(params, keys_dir):
    """
    Scenario: Attacker captures a valid signature from a previous session
    and tries to attach it to a new ticket payload. The signature should
    be invalid because the payload (including timestamp) has changed.
    """
    print_header(3, "Replay of Old Partial Signature")
    p, q, g = params["p"], params["q"], params["g"]

    # Get a legitimate TGT (old session)
    old_tgt = get_legitimate_tgt(keys_dir)
    if old_tgt is None:
        print("  [!] Could not obtain TGT (are servers running?)")
        return False

    old_payload = old_tgt["ticket_payload"]
    old_sigs = old_tgt["signatures"]
    print(f"  [Captured] Old payload: {old_payload}")
    print(f"  [Captured] Old signatures from: "
          f"{[s['authority_id'] for s in old_sigs]}")

    # Wait briefly and create a new payload (different timestamp)
    time.sleep(1)
    new_timestamp = int(time.time())
    new_payload = f"alice||tgs||{new_timestamp}||600||1"
    print(f"\n  [Attacker] New payload:  {new_payload}")
    print(f"  [Attacker] Attaching old signatures to new payload...")

    # Try to verify old signatures on new payload
    sig_tuples = [
        (int(s["R"]), int(s["s"]), s["authority_id"])
        for s in old_sigs
    ]

    is_valid, count, details = verify_multi_signatures(
        new_payload, sig_tuples, params["as_public_keys"],
        p, q, g, required=2
    )
    print(f"\n  [Verifier] Replayed signatures on new payload: "
          f"valid={is_valid} ({count} valid sigs)")
    for auth_id, valid, reason in details:
        print(f"    {auth_id}: {reason}")

    contained = not is_valid
    print_result(
        contained,
        "Replay attack BLOCKED — old signatures don't match new payload"
        if contained else "SECURITY BREACH: Replayed signatures accepted!"
    )
    return contained


# ─────────────────────────────────────────────
# Attack 4: Leakage of One Authority's Private Key
# ─────────────────────────────────────────────

def attack_4_key_leakage(params, keys_dir):
    """
    Scenario: One authority's private key is leaked. Attacker can sign
    as that authority, but still cannot produce a valid ticket alone
    (needs 2 signatures from different authorities).
    Demonstrates that leaking 1 key is insufficient.
    """
    print_header(4, "Leakage of One Authority's Private Signing Key")
    p, q, g = params["p"], params["q"], params["g"]

    # Attacker obtains AS2's leaked private key
    as2_private = load_json(os.path.join(keys_dir, "as_private_2.json"))
    x_leaked = int(as2_private["private_key"])
    print("  [Attacker] Obtained leaked AS2 private key")

    # Attacker creates a forged payload
    forged_payload = f"evil_user||tgs||{int(time.time())}||600||1"
    print(f"  [Attacker] Forging ticket: {forged_payload}")

    # Attacker signs as AS2 (valid, since they have the real key)
    R2, s2, _ = schnorr_sign(forged_payload, x_leaked, "AS2", p, q, g)
    y_as2 = params["as_public_keys"]["AS2"]
    sig_valid = schnorr_verify(forged_payload, R2, s2, "AS2", y_as2, p, q, g)
    print(f"  [Attacker] AS2 signature (with leaked key): valid={sig_valid}")

    # Attacker tries to create a second signature with a random key
    x_fake = secure_random(q)
    R_fake, s_fake, _ = schnorr_sign(
        forged_payload, x_fake, "AS1", p, q, g
    )
    y_as1 = params["as_public_keys"]["AS1"]
    sig_fake_valid = schnorr_verify(
        forged_payload, R_fake, s_fake, "AS1", y_as1, p, q, g
    )
    print(f"  [Attacker] Fake AS1 signature (random key): "
          f"valid={sig_fake_valid}")

    # Multi-sig verification
    sigs = [(R2, s2, "AS2"), (R_fake, s_fake, "AS1")]
    is_valid, count, details = verify_multi_signatures(
        forged_payload, sigs, params["as_public_keys"],
        p, q, g, required=2
    )
    print(f"\n  [Verifier] Multi-sig check: valid={is_valid} ({count}/2)")
    for auth_id, valid, reason in details:
        print(f"    {auth_id}: {reason}")

    contained = sig_valid and not is_valid
    print_result(
        contained,
        "Key leakage of 1 authority is INSUFFICIENT — attacker can only "
        "produce 1 valid signature, still needs a second from another authority"
        if contained else "SECURITY BREACH!"
    )
    return contained


# ─────────────────────────────────────────────
# Attack 5: Authority Offline Scenario
# ─────────────────────────────────────────────

def attack_5_authority_offline(params, keys_dir):
    """
    Scenario: One AS node is offline (simulated by not contacting it).
    The system should still work with the remaining 2 authorities,
    demonstrating fault tolerance.
    """
    print_header(5, "Authority Offline Scenario")

    password = "alice_password"
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    timestamp = int(time.time())
    p, q, g = params["p"], params["q"], params["g"]

    auth_request = {
        "type": "AUTH_REQUEST",
        "client_id": "alice",
        "password_hash": password_hash,
        "timestamp": timestamp,
    }

    # Only contact AS2 and AS3 (AS1 is "offline")
    print("  [Scenario] AS1 is OFFLINE")
    print("  [Client] Contacting only AS2 (port 5002) and AS3 (port 5003)...")

    responses = []
    for port, as_id in [(5002, "AS2"), (5003, "AS3")]:
        resp = send_request('localhost', port, auth_request)
        if resp and resp.get("status") == "success":
            R_i = int(resp["signature_R"])
            s_i = int(resp["signature_s"])
            auth_id = resp["authority_id"]
            y_i = params["as_public_keys"][auth_id]
            if schnorr_verify(
                resp["ticket_payload"], R_i, s_i, auth_id,
                y_i, p, q, g
            ):
                responses.append(resp)
                print(f"  [{as_id}] ✓ Response received and signature valid")
            else:
                print(f"  [{as_id}] ✗ Invalid signature")
        else:
            print(f"  [{as_id}] ✗ Failed to contact")

    success = len(responses) >= 2
    if success:
        # Verify the collected signatures work as a valid multi-sig
        payload = responses[0]["ticket_payload"]
        sig_tuples = [
            (int(r["signature_R"]), int(r["signature_s"]),
             r["authority_id"])
            for r in responses
        ]
        is_valid, count, _ = verify_multi_signatures(
            payload, sig_tuples, params["as_public_keys"],
            p, q, g, required=2
        )
        print(f"\n  [Verifier] Multi-sig with 2 authorities: "
              f"valid={is_valid} ({count}/2)")

    print_result(
        success,
        "System operates normally with 1 authority offline — "
        "2 remaining authorities provide sufficient signatures"
        if success else
        "System FAILED with 1 authority offline"
    )
    return success


# ─────────────────────────────────────────────
# Attack 6: Ticket with Only One Valid Signature
# ─────────────────────────────────────────────

def attack_6_single_signature_ticket(params, keys_dir):
    """
    Scenario: A ticket is presented with only one valid signature.
    The system must reject it (requirement: ≥2 valid signatures).
    Also tests submitting the ticket to TGS to confirm rejection.
    """
    print_header(6, "Ticket Containing Only One Valid Signature")
    p, q, g = params["p"], params["q"], params["g"]

    # Get a legitimate TGT
    tgt = get_legitimate_tgt(keys_dir)
    if tgt is None:
        print("  [!] Could not obtain TGT (are servers running?)")
        return False

    payload = tgt["ticket_payload"]
    all_sigs = tgt["signatures"]

    # Only keep 1 signature
    single_sig = [all_sigs[0]]
    print(f"  [Scenario] Ticket with only 1 signature: "
          f"{single_sig[0]['authority_id']}")

    # Local verification
    sig_tuples = [
        (int(s["R"]), int(s["s"]), s["authority_id"])
        for s in single_sig
    ]
    is_valid, count, details = verify_multi_signatures(
        payload, sig_tuples, params["as_public_keys"],
        p, q, g, required=2
    )
    print(f"\n  [Local Verifier] Multi-sig check: valid={is_valid} "
          f"({count}/2 required)")
    for auth_id, valid, reason in details:
        print(f"    {auth_id}: {reason}")

    # Try submitting to TGS with only 1 signature
    print(f"\n  [Client] Submitting single-sig TGT to TGS1...")
    authenticator = json.dumps({
        "client_id": "alice",
        "timestamp": int(time.time()),
    }).encode('utf-8')
    k_c_tgs = bytes.fromhex(tgt["session_key"])
    enc_auth = aes_encrypt(k_c_tgs, authenticator)

    tgs_request = {
        "type": "TGS_REQUEST",
        "ticket_payload": payload,
        "encrypted_tgt": tgt["encrypted_tgt"],
        "signatures": single_sig,
        "authenticator": base64.b64encode(enc_auth).decode('ascii'),
        "target_service": "file_server",
    }
    resp = send_request('localhost', 6001, tgs_request)
    if resp:
        tgs_rejected = resp.get("status") == "error"
        print(f"  [TGS1] Response: {resp.get('status')}")
        if tgs_rejected:
            print(f"  [TGS1] Error: {resp.get('error')}")
    else:
        tgs_rejected = True
        print(f"  [TGS1] No response (offline?)")

    contained = not is_valid and tgs_rejected
    print_result(
        contained,
        "Ticket with only 1 signature REJECTED — "
        "need ≥2 valid signatures from different authorities"
        if contained else "SECURITY BREACH: Single-signature ticket accepted!"
    )
    return contained


# ─────────────────────────────────────────────
# Server Management Helpers
# ─────────────────────────────────────────────

def start_servers(keys_dir):
    """Start all 7 servers as background processes."""
    procs = []
    server_cmds = [
        ["python", "as_node.py", "--id", "1", "--port", "5001",
         "--keys-dir", keys_dir],
        ["python", "as_node.py", "--id", "2", "--port", "5002",
         "--keys-dir", keys_dir],
        ["python", "as_node.py", "--id", "3", "--port", "5003",
         "--keys-dir", keys_dir],
        ["python", "tgs_node.py", "--id", "1", "--port", "6001",
         "--keys-dir", keys_dir],
        ["python", "tgs_node.py", "--id", "2", "--port", "6002",
         "--keys-dir", keys_dir],
        ["python", "tgs_node.py", "--id", "3", "--port", "6003",
         "--keys-dir", keys_dir],
        ["python", "service_server.py", "--service", "file_server",
         "--port", "7001", "--keys-dir", keys_dir],
    ]

    for cmd in server_cmds:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        procs.append(proc)

    time.sleep(2)  # Wait for servers to start
    print(f"  Started {len(procs)} server processes")
    return procs


def stop_servers(procs):
    """Stop all server processes."""
    for p in procs:
        p.terminate()
    for p in procs:
        p.wait()
    print(f"  Stopped {len(procs)} server processes")


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Attack Scenarios for Kerberos Multi-Signature System"
    )
    parser.add_argument("--keys-dir", type=str, default="keys",
                        help="Directory containing key files")
    parser.add_argument("--attack", type=int, default=0,
                        help="Run specific attack (1-6), 0 for all")
    parser.add_argument("--no-servers", action="store_true",
                        help="Don't start/stop servers (assume already running)")
    args = parser.parse_args()

    params = load_system_params(args.keys_dir)

    print("\n" + "╔" + "═" * 63 + "╗")
    print("║  KERBEROS MULTI-SIGNATURE — ATTACK SCENARIO TESTING           ║")
    print("╚" + "═" * 63 + "╝")

    # Start servers if needed
    procs = []
    if not args.no_servers:
        print("\n  Starting servers...")
        procs = start_servers(args.keys_dir)

    attacks = {
        1: ("Single Malicious Authority",
            lambda: attack_1_single_malicious_authority(params, args.keys_dir)),
        2: ("Modified Ticket Payload",
            lambda: attack_2_modified_payload(params, args.keys_dir)),
        3: ("Replay Old Signature",
            lambda: attack_3_replay_old_signature(params, args.keys_dir)),
        4: ("Key Leakage",
            lambda: attack_4_key_leakage(params, args.keys_dir)),
        5: ("Authority Offline",
            lambda: attack_5_authority_offline(params, args.keys_dir)),
        6: ("Single Signature Ticket",
            lambda: attack_6_single_signature_ticket(params, args.keys_dir)),
    }

    results = {}
    try:
        if args.attack == 0:
            # Run all attacks
            for num, (name, fn) in attacks.items():
                results[num] = fn()
        elif args.attack in attacks:
            num = args.attack
            results[num] = attacks[num][1]()
        else:
            print(f"  Unknown attack number: {args.attack}")
            sys.exit(1)
    finally:
        # Stop servers
        if procs:
            print("\n  Stopping servers...")
            stop_servers(procs)

    # Summary
    print("\n" + "=" * 65)
    print("  ATTACK SCENARIO SUMMARY")
    print("=" * 65)
    all_passed = True
    for num, passed in sorted(results.items()):
        name = attacks[num][0]
        status = "✓ CONTAINED" if passed else "✗ FAILED"
        print(f"  Attack {num}: {name:40s} [{status}]")
        if not passed:
            all_passed = False

    if all_passed:
        print(f"\n  ✓ ALL ATTACKS CONTAINED — System is resilient to "
              f"partial compromise")
    else:
        print(f"\n  ✗ SOME ATTACKS SUCCEEDED — Review security model")

    print("=" * 65)


if __name__ == "__main__":
    main()
