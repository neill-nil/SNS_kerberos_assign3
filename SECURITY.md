# SECURITY.md - System Threat Model & Analysis

## 1. Why one compromised authority cannot forge tickets
In classical Kerberos, all trust is placed in a single authority (AS or TGS). In this model, the Client's ticket is validated independently by separate public keys. The verifier enforces that a ticket must hold **at least two** valid signatures from different authorities. 
If an attacker compromises `AS_1` (a partial compromise), they only possess the private Schnorr key `x_1` of `AS_1`. They can successfully forge `Signature_1`, but they lack the key `x_2` or `x_3` needed to produce a valid second signature. Without at least two independent valid signatures, the Service or TGS trivially rejects the ticket.

## 2. Why two compromised authorities break security
The protocol specifically utilizes a **2-of-3 threshold trust model**. If an attacker compromises both `AS_1` and `AS_2`, they gain access to private keys `x_1` and `x_2`. They can now construct arbitrary valid-looking tickets and successfully sign them with two independent, valid cryptographic signatures. The TGS node verifier, seeing exactly what it was designed to accept (two independent signatures), will accept the forged ticket representing total compromise.

## 3. Why requiring two independent Schnorr signatures prevents a single compromised authority from forging tickets
A single compromised authority, possessing only `x_1`, can sign any piece of data and generate `(R_1, s_1)`. However, a verification node strictly checks the identity markers (`auth_id`) appended to the signatures and verifies them against the globally known public keys `(y_1, y_2, y_3)`. 
The mathematical difficulty of the Discrete Logarithm Problem guarantees that without `x_2`, the compromised authority cannot output a pair `(R_2, s_2)` such that `g^{s_2} ≡ R_2 * y_2^e (mod p)`. The verifier forces a count of valid verifications > 1, thus completely blocking the single forgery.

## 4. Nonce reuse risks
In Schnorr signatures, a random nonce `k` is used to compute `R = g^k (mod p)`, and the signature component `s = (k + e * x) (mod q)`. 
If an authority issues two signatures using the **same nonce `k`** but different messages (producing different `e` parameters `e_1` and `e_2`), an observer obtains:
- `s_1 = k + e_1 * x (mod q)`
- `s_2 = k + e_2 * x (mod q)`

By subtracting the two equations:
`s_1 - s_2 = x(e_1 - e_2) (mod q)`
`x = (s_1 - s_2)(e_1 - e_2)^-1 (mod q)`

This completely exposes the private long-term key `x`, catastrophically destroying the system's security. Our `crypto_utils.py` relies on `os.urandom` to ensure `k` is mathematically fresh for every single signature event.

## 5. Key share leakage impact
If a single private signing key leaks (e.g., `x_1`), the exact impact is mathematically bounded to a "Partial Compromise" condition. The leaked key grants the attacker the ability to form exactly one signature per ticket. Due to the 2-of-3 design, the system remains resilient, and the attacker is mathematically isolated. The Service node still correctly waits for `x_2` or `x_3` to independently validate the transaction before granting access.

## 6. Performance overhead of multi-authority signing
Introducing multi-signature Kerberos significantly multiplies the performance overhead compared to classical symmetric Kerberos.
- **Client Latency:** The client must now make 3 separate network calls (or parallel calls) instead of 1 for both the AS and TGS phases.
- **Computation Bottlenecks:** Symmetric encryption (AES) is exceptionally fast. But the authorities must perform modular exponentiation over large 1024-bit primes:
  - Generation requires modular exponentiation (`R = g^k (mod p)`).
  - Verification is exceptionally expensive, requiring two exponentiations per signature (`g^s` and `y^e (mod p)`). Since the TGS receives 2 signatures, it computes 4 heavy modular exponentiations per Client phase.
This scales linearly in cost but dramatically improves distributed confidence.
