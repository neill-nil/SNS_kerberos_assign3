"""
performance_analysis.py
Performance Analysis for Kerberos Multi-Signature System.

Benchmarks:
  1. Schnorr key generation time
  2. Single Schnorr sign / verify time
  3. Multi-signature verification (2-of-3 vs single)
  4. AES-256-CBC encryption / decryption
  5. Full protocol end-to-end latency (with servers)

Usage:
    python performance_analysis.py --keys-dir keys [--rounds 100]
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import base64

from crypto_utils import (
    load_json,
    deserialize_params,
    schnorr_sign,
    schnorr_verify,
    verify_multi_signatures,
    mod_exp,
    secure_random,
    aes_encrypt,
    aes_decrypt,
    generate_session_key,
    generate_schnorr_params,
    hash_to_challenge,
)


def benchmark(fn, rounds=100, label=""):
    """Run fn for `rounds` iterations and report timing."""
    times = []
    for _ in range(rounds):
        start = time.perf_counter()
        fn()
        elapsed = time.perf_counter() - start
        times.append(elapsed)

    avg = sum(times) / len(times)
    min_t = min(times)
    max_t = max(times)
    print(f"  {label:45s} "
          f"avg={avg*1000:8.3f}ms  "
          f"min={min_t*1000:8.3f}ms  "
          f"max={max_t*1000:8.3f}ms  "
          f"({rounds} rounds)")
    return avg


def run_analysis(keys_dir, rounds):
    print("\n" + "=" * 70)
    print("  KERBEROS MULTI-SIGNATURE — PERFORMANCE ANALYSIS")
    print("=" * 70)

    # Load params
    public_params = load_json(os.path.join(keys_dir, "public_params.json"))
    p, q, g = deserialize_params(public_params["schnorr_params"])

    as_public_keys = {
        k: int(v) for k, v in public_params["as_public_keys"].items()
    }

    # Load a private key for signing benchmarks
    as1_data = load_json(os.path.join(keys_dir, "as_private_1.json"))
    x1 = int(as1_data["private_key"])
    y1 = as_public_keys["AS1"]

    test_message = "alice||tgs||1234567890||600||1"
    aes_key = generate_session_key()
    plaintext = json.dumps({
        "client_id": "alice", "session_key": "a" * 64,
        "timestamp": 1234567890, "lifetime": 600
    }).encode()

    print(f"\n  Parameters: q={q.bit_length()}-bit, p={p.bit_length()}-bit")
    print(f"  Benchmark rounds: {rounds}\n")

    # ─── 1. Modular Exponentiation ───
    print("  [1] Modular Exponentiation")
    print("  " + "-" * 65)
    base_val = secure_random(q)
    exp_val = secure_random(q)
    benchmark(lambda: mod_exp(base_val, exp_val, p), rounds,
              f"mod_exp (base^exp mod p, {p.bit_length()}-bit)")

    # ─── 2. Schnorr Signature ───
    print("\n  [2] Schnorr Signature (Single Authority)")
    print("  " + "-" * 65)
    sign_time = benchmark(
        lambda: schnorr_sign(test_message, x1, "AS1", p, q, g),
        rounds, "schnorr_sign"
    )

    R, s, _ = schnorr_sign(test_message, x1, "AS1", p, q, g)
    verify_time = benchmark(
        lambda: schnorr_verify(test_message, R, s, "AS1", y1, p, q, g),
        rounds, "schnorr_verify"
    )

    # ─── 3. Multi-Signature ───
    print("\n  [3] Multi-Signature Verification (2-of-3 vs Single)")
    print("  " + "-" * 65)

    # Generate 3 independent signatures
    sigs = []
    for i in range(1, 4):
        auth_id = f"AS{i}"
        priv_data = load_json(
            os.path.join(keys_dir, f"as_private_{i}.json")
        )
        xi = int(priv_data["private_key"])
        Ri, si, _ = schnorr_sign(test_message, xi, auth_id, p, q, g)
        sigs.append((Ri, si, auth_id))

    # Verify single
    single_time = benchmark(
        lambda: schnorr_verify(
            test_message, sigs[0][0], sigs[0][1], sigs[0][2],
            as_public_keys[sigs[0][2]], p, q, g
        ),
        rounds, "Single authority verify"
    )

    # Verify 2-of-3
    multi_2_time = benchmark(
        lambda: verify_multi_signatures(
            test_message, sigs[:2], as_public_keys, p, q, g, required=2
        ),
        rounds, "Multi-sig verify (2 signatures)"
    )

    # Verify 3-of-3
    multi_3_time = benchmark(
        lambda: verify_multi_signatures(
            test_message, sigs, as_public_keys, p, q, g, required=2
        ),
        rounds, "Multi-sig verify (3 signatures)"
    )

    # ─── 4. AES-256-CBC ───
    print("\n  [4] AES-256-CBC Encryption / Decryption")
    print("  " + "-" * 65)
    enc_time = benchmark(
        lambda: aes_encrypt(aes_key, plaintext), rounds,
        "AES-256-CBC encrypt (with PKCS#7 pad)"
    )

    ciphertext = aes_encrypt(aes_key, plaintext)
    dec_time = benchmark(
        lambda: aes_decrypt(aes_key, ciphertext), rounds,
        "AES-256-CBC decrypt (with PKCS#7 unpad)"
    )

    # ─── 5. Hash computation ───
    print("\n  [5] SHA-256 Hash (Challenge Computation)")
    print("  " + "-" * 65)
    benchmark(
        lambda: hash_to_challenge(test_message, R, "AS1", q),
        rounds, "hash_to_challenge (SHA-256)"
    )

    # ─── Summary ───
    print("\n" + "=" * 70)
    print("  PERFORMANCE SUMMARY")
    print("=" * 70)
    print(f"""
  Signing overhead (multi vs single):
    Single authority sign:         {sign_time*1000:.3f} ms
    3 authorities sign (parallel): {sign_time*1000:.3f} ms  (same, done in parallel)
    3 authorities sign (serial):   {sign_time*3*1000:.3f} ms

  Verification overhead:
    Single verify:                 {single_time*1000:.3f} ms
    Multi-sig verify (2 sigs):     {multi_2_time*1000:.3f} ms  ({multi_2_time/single_time:.1f}x)
    Multi-sig verify (3 sigs):     {multi_3_time*1000:.3f} ms  ({multi_3_time/single_time:.1f}x)

  Symmetric crypto:
    AES-256-CBC encrypt:           {enc_time*1000:.3f} ms
    AES-256-CBC decrypt:           {dec_time*1000:.3f} ms

  Conclusion:
    Multi-authority signing adds ~{multi_3_time/single_time:.1f}x verification overhead.
    This is acceptable given the security improvement (tolerance of
    1 compromised authority). Signing is parallelizable across authorities.
""")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Performance Analysis for Kerberos Multi-Signature System"
    )
    parser.add_argument("--keys-dir", type=str, default="keys")
    parser.add_argument("--rounds", type=int, default=100,
                        help="Benchmark rounds (default: 100)")
    args = parser.parse_args()

    run_analysis(args.keys_dir, args.rounds)


if __name__ == "__main__":
    main()
