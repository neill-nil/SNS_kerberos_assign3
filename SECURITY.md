--# Security Analysis — Kerberos Multi-Signature System

## 1. Why One Compromised Authority Cannot Forge Tickets

In our system, a ticket is valid **only if it contains at least 2 valid, independent Schnorr signatures** from different authorities. Each authority has its own independent key pair `(x_i, y_i)`.

If an attacker compromises **one** authority (e.g., AS1), they obtain `x_1` and can produce a valid signature `(R_1, s_1)` verified by `y_1`. However:

- They **cannot** sign as AS2 or AS3 because they don't know `x_2` or `x_3`
- Fabricating a signature for AS2 would require solving the **discrete logarithm problem** (computing `x_2` from `y_2 = g^{x_2} mod p`), which is computationally infeasible
- The verifier checks each signature against the **specific public key** of the claimed authority: `g^{s_i} ≡ R_i · y_i^{e_i} (mod p)` where `e_i = H(m || R_i || ID_i)`

Therefore, one compromised authority can produce at most **1 valid signature**, which is insufficient.

## 2. Why Two Compromised Authorities Break Security

If an adversary compromises **two** authorities (e.g., AS1 and AS2), they possess both `x_1` and `x_2`. They can independently produce:

- A valid `(R_1, s_1)` verifiable by `y_1`
- A valid `(R_2, s_2)` verifiable by `y_2`

This yields **2 valid signatures**, meeting the system's threshold. The attacker can now forge arbitrary tickets for any user or service, completely bypassing authentication. This is why the threat model explicitly assumes that **at most one** authority is compromised.

## 3. Why Requiring Two Independent Schnorr Signatures Prevents Single-Authority Forgery

The multi-signature scheme uses **independent key pairs** — each authority `i` has:
- Private key: `x_i ∈ Z_q` (known only to authority `i`)
- Public key: `y_i = g^{x_i} mod p` (known to all)

The critical property is that possession of `x_i` gives **zero information** about `x_j` (for `j ≠ i`). The keys are independently generated random values.

Unlike a threshold scheme where a single secret is split, our multi-signature approach requires the attacker to independently break into **two separate systems** to forge a ticket. The security reduces to:

> *An attacker must compromise ≥2 independent authorities, OR solve the discrete logarithm problem.*

## 4. Nonce Reuse Risks

Each Schnorr signature uses a fresh random nonce `k_i`:
```
R_i = g^{k_i} mod p
e_i = H(m || R_i || ID_i)
s_i = k_i + e_i · x_i  mod q
```

**If the same nonce `k_i` is reused for two different messages** `m` and `m'`:
```
s  = k_i + e  · x_i  mod q
s' = k_i + e' · x_i  mod q
```

An attacker can compute:
```
s - s' = (e - e') · x_i  mod q
x_i = (s - s') · (e - e')^{-1}  mod q
```

This **completely reveals the private key** of authority `i`. Our implementation mitigates this by:
- Using `os.urandom()` / `secrets` module for cryptographically secure nonce generation
- Generating a **fresh nonce for every signature operation**
- Never storing or reusing nonces

## 5. Key Leakage Impact

If one authority's private key `x_i` is leaked:

| Impact | Severity |
|--------|----------|
| Attacker can sign as authority `i` | ⚠️ Moderate |
| Attacker can forge tickets | ❌ No (needs 2 sigs) |
| Past tickets are invalidated | ❌ No |
| Other authorities compromised | ❌ No (independent keys) |

**Containment**: The leaked key affects only one authority. The system remains secure as long as no second authority is compromised. The recommended response is **key rotation**: generate a new key pair for the affected authority and increment the key version.

## 6. Performance Overhead of Multi-Authority Signing

| Operation | Single Authority | Multi-Authority (2-of-3) |
|-----------|-----------------|--------------------------|
| **Signature Generation** | 1 modular exponentiation | 3 (one per authority) |
| **Signature Verification** | 1 check | 2–3 checks |
| **Network Round Trips** | 1 | 3 (parallel) |
| **Ticket Size** | 1 signature `(R, s)` | 2–3 signatures `(R_i, s_i, ID_i)` |

The overhead is approximately **2–3x** in computation and ticket size. However:
- Network requests can be sent **in parallel** to all authorities
- The computation cost is dominated by modular exponentiation, which is fast for 256-bit `q`
- The security gain (tolerance of 1 compromised authority) **far outweighs** the performance cost
- In practice, the AES encryption/decryption of ticket payloads has comparable cost to the signature operations
