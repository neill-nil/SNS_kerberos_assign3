"""
crypto_utils.py
Core cryptographic primitives for Kerberos Multi-Signature System.
  - Manual modular exponentiation
  - Modular arithmetic over Z_q
  - Schnorr signature generation and verification
  - Multi-signature verification (2-of-3)
  - AES-256-CBC with manual PKCS#7 padding
  - SHA-256 hashing
  - Secure random number generation
"""

import hashlib
import os
import json
import secrets
import time

# ─────────────────────────────────────────────
# 1. Modular Arithmetic (manual implementations)
# ─────────────────────────────────────────────

def mod_exp(base, exp, mod):
    """
    Manual square-and-multiply modular exponentiation.
    Computes base^exp mod mod without using Python's built-in pow(b,e,m).
    """
    if mod == 1:
        return 0
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result


def mod_inv(a, m):
    """
    Compute modular inverse of a mod m using Extended Euclidean Algorithm.
    Returns a^{-1} mod m.
    """
    if a < 0:
        a = a % m
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist for a={a}, m={m}")
    return x % m


def _extended_gcd(a, b):
    """Extended Euclidean Algorithm. Returns (gcd, x, y) such that a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def mod_add(a, b, m):
    """Modular addition: (a + b) mod m"""
    return (a % m + b % m) % m


def mod_sub(a, b, m):
    """Modular subtraction: (a - b) mod m"""
    return (a % m - b % m + m) % m


def mod_mul(a, b, m):
    """Modular multiplication: (a * b) mod m"""
    return ((a % m) * (b % m)) % m


# ─────────────────────────────────────────────
# 2. Secure Random Number Generation
# ─────────────────────────────────────────────

def secure_random(n):
    """Generate a cryptographically secure random integer in [1, n-1]."""
    return secrets.randbelow(n - 1) + 1


# ─────────────────────────────────────────────
# 3. Prime Generation (for Schnorr parameters)
# ─────────────────────────────────────────────

def _is_miller_rabin_prime(n, rounds=20):
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # random in [2, n-2]
        x = mod_exp(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = mod_exp(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits):
    """Generate a random prime of specified bit length."""
    while True:
        n = secrets.randbits(bits)
        n |= (1 << (bits - 1)) | 1  # Set MSB and LSB
        if _is_miller_rabin_prime(n):
            return n


def generate_schnorr_params(q_bits=256, p_bits=2048):
    """
    Generate Schnorr signature parameters (p, q, g) where:
      - q is a prime of q_bits bits
      - p is a prime such that q | (p-1), of approximately p_bits bits
      - g is a generator of the subgroup of order q in Z*_p
    """
    print(f"[*] Generating {q_bits}-bit prime q...")
    q = generate_prime(q_bits)

    print(f"[*] Generating {p_bits}-bit prime p such that q | (p-1)...")
    min_k = (1 << (p_bits - 1)) // q
    max_k = (1 << p_bits) // q

    while True:
        k = secrets.randbelow(max_k - min_k) + min_k
        if k % 2 == 1:
            k += 1
        p = k * q + 1
        if p.bit_length() >= p_bits and _is_miller_rabin_prime(p, rounds=10):
            break

    print(f"[*] Finding generator g of order q in Z*_p...")
    while True:
        h = secrets.randbelow(p - 3) + 2
        g = mod_exp(h, (p - 1) // q, p)
        if g != 1:
            break

    print(f"[+] Schnorr parameters generated successfully.")
    print(f"    q = {q_bits}-bit prime")
    print(f"    p = {p.bit_length()}-bit prime")
    return p, q, g


# ─────────────────────────────────────────────
# 4. SHA-256 Hashing
# ─────────────────────────────────────────────

def hash_message(message):
    """
    SHA-256 hash of a message. Accepts str or bytes.
    Returns the hash as an integer.
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    return int(hashlib.sha256(message).hexdigest(), 16)


def hash_to_challenge(message, R, authority_id, q):
    """
    Compute Schnorr challenge: e = SHA-256(m || R || ID) mod q

    Per the assignment:
        e_i = H(m || R_i || ID_i)
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    R_bytes = str(R).encode('utf-8')
    id_bytes = str(authority_id).encode('utf-8')
    digest = hashlib.sha256(message + R_bytes + id_bytes).hexdigest()
    return int(digest, 16) % q


# ─────────────────────────────────────────────
# 5. Schnorr Signature (Independent per authority)
# ─────────────────────────────────────────────

def schnorr_sign(message, x_i, authority_id, p, q, g):
    """
    Schnorr signature by authority i.

    Each authority independently:
      k_i ∈ Z_q            (fresh random nonce)
      R_i = g^k_i mod p
      e_i = H(m || R_i || ID_i)
      s_i = k_i + e_i * x_i mod q

    Returns (R_i, s_i, authority_id)
    """
    k_i = secure_random(q)                            # fresh nonce
    R_i = mod_exp(g, k_i, p)                          # commitment
    e_i = hash_to_challenge(message, R_i, authority_id, q)  # challenge
    s_i = mod_add(k_i, mod_mul(e_i, x_i, q), q)      # signature
    return R_i, s_i, authority_id


def schnorr_verify(message, R_i, s_i, authority_id, y_i, p, q, g):
    """
    Verify Schnorr signature (R_i, s_i) from authority_id using public key y_i.

    Check: g^s_i ≡ R_i · y_i^e_i (mod p)
    where  e_i = H(m || R_i || ID_i)
    """
    e_i = hash_to_challenge(message, R_i, authority_id, q)
    lhs = mod_exp(g, s_i, p)
    rhs = mod_mul(R_i, mod_exp(y_i, e_i, p), p)
    return lhs == rhs


# ─────────────────────────────────────────────
# 6. Multi-Signature Verification (2-of-3)
# ─────────────────────────────────────────────

def verify_multi_signatures(message, signatures, public_keys, p, q, g, required=2):
    """
    Verify that a ticket has at least `required` valid independent Schnorr signatures.

    Args:
        message: the signed ticket payload (str or bytes)
        signatures: list of (R_i, s_i, authority_id) tuples
        public_keys: dict mapping authority_id -> y_i (public key)
        p, q, g: Schnorr parameters
        required: minimum number of valid signatures needed (default 2)

    Returns:
        (is_valid, valid_count, details)
    """
    valid_count = 0
    details = []
    seen_authorities = set()

    for R_i, s_i, auth_id in signatures:
        # Reject duplicate authority signatures
        if auth_id in seen_authorities:
            details.append((auth_id, False, "Duplicate authority"))
            continue
        seen_authorities.add(auth_id)

        # Look up public key
        if auth_id not in public_keys:
            details.append((auth_id, False, "Unknown authority"))
            continue

        y_i = public_keys[auth_id]
        is_valid = schnorr_verify(message, R_i, s_i, auth_id, y_i, p, q, g)
        details.append((auth_id, is_valid, "Valid" if is_valid else "Invalid signature"))
        if is_valid:
            valid_count += 1

    return valid_count >= required, valid_count, details


# ─────────────────────────────────────────────
# 7. AES-256-CBC
# ─────────────────────────────────────────────

try:
    from Crypto.Cipher import AES as _AES
    _AES_BACKEND = "pycryptodome"
except ImportError:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        _AES_BACKEND = "cryptography"
    except ImportError:
        raise ImportError(
            "Either pycryptodome or cryptography library is required for AES. "
            "Install with: pip install pycryptodome"
        )


def pkcs7_pad(data, block_size=16):
    """Manual PKCS#7 padding."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding


def pkcs7_unpad(data):
    """Manual PKCS#7 unpadding."""
    if len(data) == 0:
        raise ValueError("Cannot unpad empty data")
    padding_len = data[-1]
    if padding_len < 1 or padding_len > 16:
        raise ValueError(f"Invalid PKCS#7 padding length: {padding_len}")
    for i in range(padding_len):
        if data[-(i + 1)] != padding_len:
            raise ValueError("Invalid PKCS#7 padding bytes")
    return data[:-padding_len]


def aes_encrypt(key, plaintext):
    """
    AES-256-CBC encryption with manual PKCS#7 padding.
    Key must be 32 bytes. Returns: IV (16 bytes) + ciphertext.
    """
    if isinstance(key, str):
        key = bytes.fromhex(key)
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if len(key) != 32:
        raise ValueError(f"AES-256 requires 32-byte key, got {len(key)}")

    iv = os.urandom(16)
    padded = pkcs7_pad(plaintext)

    if _AES_BACKEND == "pycryptodome":
        cipher = _AES.new(key, _AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded)
    else:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

    return iv + ciphertext


def aes_decrypt(key, data):
    """
    AES-256-CBC decryption with manual PKCS#7 unpadding.
    Key must be 32 bytes. data = IV (first 16 bytes) + ciphertext.
    Returns: plaintext bytes.
    """
    if isinstance(key, str):
        key = bytes.fromhex(key)
    if len(key) != 32:
        raise ValueError(f"AES-256 requires 32-byte key, got {len(key)}")
    if len(data) < 32:
        raise ValueError("Data too short (need at least IV + 1 block)")

    iv = data[:16]
    ciphertext = data[16:]

    if _AES_BACKEND == "pycryptodome":
        cipher = _AES.new(key, _AES.MODE_CBC, iv)
        padded = cipher.decrypt(ciphertext)
    else:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()

    return pkcs7_unpad(padded)


def generate_session_key():
    """Generate a random 256-bit (32 byte) AES session key."""
    return os.urandom(32)


# ─────────────────────────────────────────────
# 8. Serialization Helpers
# ─────────────────────────────────────────────

def serialize_params(p, q, g):
    """Serialize Schnorr public parameters to a dictionary."""
    return {
        "p": str(p),
        "q": str(q),
        "g": str(g),
    }


def deserialize_params(params):
    """Deserialize Schnorr public parameters from a dictionary."""
    return (
        int(params["p"]),
        int(params["q"]),
        int(params["g"]),
    )


def save_json(data, filepath):
    """Save data as JSON to file."""
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"[+] Saved: {filepath}")


def load_json(filepath):
    """Load data from JSON file."""
    with open(filepath, 'r') as f:
        return json.load(f)
