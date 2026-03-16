import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# RFC 5114 1024-bit MODP with 160-bit prime order subgroup
P = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
Q = int("F518AA8781A8DF278ABA4E7D64B7CB9D49462353", 16)
G = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)

def mod_exp(base, exp, mod):
    # Manual modular exponentiation (square and multiply) as per assignment requirements
    res = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            res = (res * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return res

def mod_inverse(a, m):
    # Manual modular inverse using extended euclidean algorithm
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

def generate_schnorr_keypair():
    # x in Zq
    x = int.from_bytes(os.urandom(20), 'big') % Q
    if x == 0:
        x = 1
    y = mod_exp(G, x, P)
    return x, y

def schnorr_sign(message: bytes, private_key: int, auth_id: str):
    # k in Zq
    k = int.from_bytes(os.urandom(20), 'big') % Q
    if k == 0:
        k = 1
    R = mod_exp(G, k, P)
    
    # e = H(m || R || ID)
    hasher = hashlib.sha256()
    hasher.update(message)
    hasher.update(str(R).encode())
    hasher.update(str(auth_id).encode())
    e = int(hasher.hexdigest(), 16) % Q
    
    s = (k + e * private_key) % Q
    return R, s

def schnorr_verify(message: bytes, R: int, s: int, public_key: int, auth_id: str):
    if R <= 0 or R >= P or s <= 0 or s >= Q:
        return False
        
    hasher = hashlib.sha256()
    hasher.update(message)
    hasher.update(str(R).encode())
    hasher.update(str(auth_id).encode())
    e = int(hasher.hexdigest(), 16) % Q
    
    # g^s == R * y^e mod p
    left = mod_exp(G, s, P)
    right = (R * mod_exp(public_key, e, P)) % P
    return left == right

def pkcs7_pad(data: bytes, block_size=16):
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)

def pkcs7_unpad(data: bytes):
    padding_len = data[-1]
    return data[:-padding_len]

def aes_cbc_encrypt(key: bytes, plaintext: bytes) -> bytes:
    # Key must be 32 bytes for AES-256
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded = pkcs7_pad(plaintext)
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv + ciphertext

def aes_cbc_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(actual_ciphertext) + decryptor.finalize()
    return pkcs7_unpad(padded)
