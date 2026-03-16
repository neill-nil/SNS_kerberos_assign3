"""
master_keygen.py
Offline Master Key Generation for Kerberos Multi-Signature System.

Each authority independently gets its own Schnorr key pair (x_i, y_i).
All authorities share the same Schnorr group parameters (p, q, g).

This script performs the one-time setup:
  1. Generate Schnorr parameters (p, q, g) where q | (p-1)
  2. Generate independent key pairs for AS1, AS2, AS3
  3. Generate independent key pairs for TGS1, TGS2, TGS3
  4. Save public params (including all public keys) and individual private keys

Usage:
    python master_keygen.py [--q-bits 256] [--p-bits 2048] [--output-dir keys]

Output files:
    keys/public_params.json     — (p, q, g) + all authority public keys
    keys/as_private_1.json      — AS1's private key
    keys/as_private_2.json      — AS2's private key
    keys/as_private_3.json      — AS3's private key
    keys/tgs_private_1.json     — TGS1's private key
    keys/tgs_private_2.json     — TGS2's private key
    keys/tgs_private_3.json     — TGS3's private key
    keys/client_db.json         — test user credentials + service registry
"""

import os
import argparse
import time

from crypto_utils import (
    generate_schnorr_params,
    mod_exp,
    secure_random,
    serialize_params,
    deserialize_params,
    save_json,
    load_json,
    schnorr_sign,
    schnorr_verify,
)


def generate_authority_keypair(p, q, g, authority_id):
    """
    Generate an independent Schnorr key pair for a single authority.

    Private key:  x_i ∈ Z_q
    Public key:   y_i = g^(x_i) mod p

    Returns (x_i, y_i)
    """
    x_i = secure_random(q)
    y_i = mod_exp(g, x_i, p)

    # Self-test: sign and verify a test message
    test_msg = f"keygen_test_{authority_id}"
    R, s, auth_id = schnorr_sign(test_msg, x_i, authority_id, p, q, g)
    assert schnorr_verify(test_msg, R, s, auth_id, y_i, p, q, g), \
        f"Schnorr self-test FAILED for {authority_id}!"

    print(f"    {authority_id}: y = {str(y_i)[:40]}...  ✓ self-test passed")
    return x_i, y_i


def generate_authority_cluster(p, q, g, prefix, count=3):
    """
    Generate independent key pairs for a cluster of authorities.

    Args:
        p, q, g: Schnorr parameters
        prefix: "AS" or "TGS"
        count: number of authorities (3)

    Returns:
        keys: list of (authority_id, x_i, y_i)
    """
    keys = []
    for i in range(1, count + 1):
        authority_id = f"{prefix}{i}"
        x_i, y_i = generate_authority_keypair(p, q, g, authority_id)
        keys.append((authority_id, x_i, y_i))
    return keys


def save_private_key(authority_id, x_i, y_i, prefix, index, output_dir, key_version=1):
    """Save an authority's private key to a JSON file."""
    key_data = {
        "authority_id": authority_id,
        "private_key": str(x_i),
        "public_key": str(y_i),
        "key_version": key_version,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    filepath = os.path.join(output_dir, f"{prefix.lower()}_private_{index}.json")
    save_json(key_data, filepath)
    return filepath


def rotate_keys(keys_dir):
    """
    Key Rotation: Generate new authority keypairs while keeping the
    same Schnorr parameters (p, q, g). Increments key_version.
    Old tickets with previous key_version will be rejected.
    """
    print("=" * 60)
    print("  KERBEROS MULTI-SIGNATURE — KEY ROTATION")
    print("=" * 60)

    # Load existing params
    public_params = load_json(os.path.join(keys_dir, "public_params.json"))
    p, q, g = deserialize_params(public_params["schnorr_params"])
    old_version = public_params["key_version"]
    new_version = old_version + 1

    print(f"\n  Rotating keys: version {old_version} → {new_version}")
    print(f"  Reusing existing Schnorr parameters (p, q, g)")

    # Generate new AS keypairs
    print(f"\n[Phase 1] Generating new AS authority key pairs...")
    as_keys = generate_authority_cluster(p, q, g, "AS", count=3)

    # Generate new TGS keypairs
    print(f"\n[Phase 2] Generating new TGS authority key pairs...")
    tgs_keys = generate_authority_cluster(p, q, g, "TGS", count=3)

    # Save updated public params
    print(f"\n[Phase 3] Saving rotated key material...")
    as_public_keys = {auth_id: str(y_i) for auth_id, _, y_i in as_keys}
    tgs_public_keys = {auth_id: str(y_i) for auth_id, _, y_i in tgs_keys}

    public_params["as_public_keys"] = as_public_keys
    public_params["tgs_public_keys"] = tgs_public_keys
    public_params["key_version"] = new_version
    public_params["rotated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    save_json(public_params, os.path.join(keys_dir, "public_params.json"))

    # Save new private keys
    for auth_id, x_i, y_i in as_keys:
        idx = int(auth_id[-1])
        save_private_key(auth_id, x_i, y_i, "AS", idx, keys_dir, new_version)
    for auth_id, x_i, y_i in tgs_keys:
        idx = int(auth_id[-1])
        save_private_key(auth_id, x_i, y_i, "TGS", idx, keys_dir, new_version)

    print(f"\n  ✓ Key rotation complete (version {new_version})")
    print(f"  ⚠  All authorities must be restarted to load new keys")
    print(f"  ⚠  Tickets signed with version {old_version} will be REJECTED")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Master Key Generation for Kerberos Multi-Signature System"
    )
    parser.add_argument("--q-bits", type=int, default=256,
                        help="Bit length for prime q (default: 256)")
    parser.add_argument("--p-bits", type=int, default=2048,
                        help="Bit length for prime p (default: 2048)")
    parser.add_argument("--output-dir", type=str, default="keys",
                        help="Output directory for key files (default: keys)")
    parser.add_argument("--rotate", action="store_true",
                        help="Rotate keys (reuse params, new keypairs, bump version)")
    args = parser.parse_args()

    output_dir = args.output_dir

    # Key rotation mode
    if args.rotate:
        rotate_keys(output_dir)
        return

    os.makedirs(output_dir, exist_ok=True)

    print("=" * 60)
    print("  KERBEROS MULTI-SIGNATURE — MASTER KEY GENERATION")
    print("=" * 60)

    # ─── Step 1: Generate Schnorr Parameters ───
    print(f"\n[Phase 1] Generating Schnorr parameters "
          f"(q={args.q_bits}-bit, p={args.p_bits}-bit)...")
    start = time.time()
    p, q, g = generate_schnorr_params(q_bits=args.q_bits, p_bits=args.p_bits)
    elapsed = time.time() - start
    print(f"    Generated in {elapsed:.1f}s")

    # ─── Step 2: Generate AS Authority Key Pairs ───
    print(f"\n[Phase 2] Generating AS authority key pairs...")
    as_keys = generate_authority_cluster(p, q, g, "AS", count=3)

    # ─── Step 3: Generate TGS Authority Key Pairs ───
    print(f"\n[Phase 3] Generating TGS authority key pairs...")
    tgs_keys = generate_authority_cluster(p, q, g, "TGS", count=3)

    # ─── Step 4: Save Public Parameters ───
    print(f"\n[Phase 4] Saving key material...")

    # Build public keys dict
    as_public_keys = {}
    for auth_id, x_i, y_i in as_keys:
        as_public_keys[auth_id] = str(y_i)

    tgs_public_keys = {}
    for auth_id, x_i, y_i in tgs_keys:
        tgs_public_keys[auth_id] = str(y_i)

    public_params = {
        "schnorr_params": serialize_params(p, q, g),
        "as_public_keys": as_public_keys,    # {"AS1": "y1", "AS2": "y2", "AS3": "y3"}
        "tgs_public_keys": tgs_public_keys,  # {"TGS1": "y1", "TGS2": "y2", "TGS3": "y3"}
        "key_version": 1,
        "required_signatures": 2,
        "total_authorities": 3,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    save_json(public_params, os.path.join(output_dir, "public_params.json"))

    # ─── Step 5: Save Individual Private Keys ───
    key_version = 1
    for auth_id, x_i, y_i in as_keys:
        index = int(auth_id[-1])
        save_private_key(auth_id, x_i, y_i, "AS", index, output_dir, key_version)

    for auth_id, x_i, y_i in tgs_keys:
        index = int(auth_id[-1])
        save_private_key(auth_id, x_i, y_i, "TGS", index, output_dir, key_version)

    # ─── Step 6: Save Client Database ───
    # TGS shared encryption key: used by AS to encrypt TGTs, by TGS to decrypt them.
    # This is a symmetric key separate from the Schnorr signing keys.
    tgs_secret_key = os.urandom(32).hex()
    print(f"    ✓ Generated TGS shared encryption key")

    client_db = {
        "tgs_secret_key": tgs_secret_key,
        "clients": {
            "alice": {
                "password_hash": __import__('hashlib').sha256(
                    b"alice_password").hexdigest(),
                "client_id": "alice"
            },
            "bob": {
                "password_hash": __import__('hashlib').sha256(
                    b"bob_password").hexdigest(),
                "client_id": "bob"
            },
            "charlie": {
                "password_hash": __import__('hashlib').sha256(
                    b"charlie_password").hexdigest(),
                "client_id": "charlie"
            }
        },
        "services": {
            "file_server": {
                "service_id": "file_server",
                "service_key": os.urandom(32).hex()
            },
            "print_server": {
                "service_id": "print_server",
                "service_key": os.urandom(32).hex()
            }
        }
    }
    save_json(client_db, os.path.join(output_dir, "client_db.json"))

    # ─── Summary ───
    print("\n" + "=" * 60)
    print("  KEY GENERATION COMPLETE")
    print("=" * 60)
    print(f"\n  Output directory: {output_dir}/")
    print(f"  Files generated:")
    print(f"    • public_params.json         — Schnorr params + all public keys")
    print(f"    • as_private_{{1,2,3}}.json    — AS authority private keys")
    print(f"    • tgs_private_{{1,2,3}}.json   — TGS authority private keys")
    print(f"    • client_db.json             — test user credentials + services")
    print(f"\n  Multi-signature: 2-of-3 (need ≥2 valid independent signatures)")
    print(f"  Key version: {key_version}")
    print(f"\n  ⚠  SECURITY: Private key files must be distributed securely!")
    print(f"      Each authority should only receive its own private key file.")
    print("=" * 60)


if __name__ == "__main__":
    main()
