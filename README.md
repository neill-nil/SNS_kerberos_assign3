# Kerberos Under Partial Compromise using Schnorr Multi-Signatures

A Kerberos-inspired authentication system resilient to partial authority compromise using a 2-of-3 Schnorr multi-signature scheme.

## Architecture

```
┌────────┐     ┌─────────────────────┐     ┌─────────────────────┐     ┌──────────────┐
│ Client │────▶│  AS1, AS2, AS3      │────▶│  TGS1, TGS2, TGS3  │────▶│  Service     │
│        │◀────│  (ports 5001-5003)  │◀────│  (ports 6001-6003)  │◀────│  (port 7001) │
└────────┘     └─────────────────────┘     └─────────────────────┘     └──────────────┘
```

- **3 AS nodes**: Verify client credentials, sign TGT payloads
- **3 TGS nodes**: Verify TGTs, sign Service Ticket payloads
- **Service Servers**: Verify multi-signatures, grant access
- **Clients**: Orchestrate the 3-phase protocol

## Requirements

- Python 3.8+
- `pycryptodome` for AES-256-CBC: `pip install pycryptodome`

## Quick Start

### 1. Generate Keys (one-time setup)

```bash
# Production parameters (slow, ~30-60s)
python master_keygen.py

# Quick test with smaller parameters
python master_keygen.py --q-bits 64 --p-bits 256
```

### 2. Start All Servers

```bash
# AS cluster
python as_node.py --id 1 --port 5001 &
python as_node.py --id 2 --port 5002 &
python as_node.py --id 3 --port 5003 &

# TGS cluster
python tgs_node.py --id 1 --port 6001 &
python tgs_node.py --id 2 --port 6002 &
python tgs_node.py --id 3 --port 6003 &

# Service server
python service_server.py --service file_server --port 7001 &
```

### 3. Run Client

```bash
python client.py --client-id alice --password alice_password --service file_server
```

### 4. Run Attack Scenarios

```bash
# Run all 6 attacks (auto-starts/stops servers)
python attacks.py

# Run with servers already running
python attacks.py --no-servers

# Run a specific attack
python attacks.py --attack 1
```

### 5. Key Rotation

```bash
# Rotate keys (bumps key_version, generates new keypairs, reuses p/q/g)
python master_keygen.py --rotate

# Then restart all servers to load new keys
# Tickets signed with old key_version will be REJECTED
```

### 6. Performance Analysis

```bash
python performance_analysis.py --rounds 100
```

## Files

| File | Description |
|------|-------------|
| `master_keygen.py` | Generate Schnorr parameters and independent authority key pairs |
| `crypto_utils.py` | Manual modular exponentiation, Schnorr signatures, AES-256-CBC, PKCS#7 |
| `as_node.py` | Authentication Server — verify credentials, sign TGT payloads |
| `tgs_node.py` | Ticket Granting Server — verify TGTs, sign Service Tickets |
| `service_server.py` | Service Server — verify multi-signatures, grant access |
| `client.py` | Client — full 3-phase Kerberos protocol |
| `attacks.py` | 6 mandatory attack scenarios with containment verification |
| `performance_analysis.py` | Benchmarks for all crypto operations and overhead analysis |
| `SECURITY.md` | Security analysis and cryptographic reasoning |

## Cryptographic Primitives

| Component | Implementation |
|-----------|---------------|
| Schnorr Signature | Manual (no asymmetric crypto libraries) |
| Modular Exponentiation | Square-and-multiply |
| Hash Function | SHA-256 |
| Symmetric Encryption | AES-256-CBC (pycryptodome) |
| Padding | Manual PKCS#7 |
| Randomness | `secrets` / `os.urandom` (OS-level CSPRNG) |

## Test Users

| Username | Password |
|----------|----------|
| alice | `alice_password` |
| bob | `bob_password` |
| charlie | `charlie_password` |

## Attack Scenarios

| # | Scenario | Expected Result |
|---|----------|-----------------|
| 1 | Single malicious authority forges ticket | Rejected (only 1 valid sig) |
| 2 | Ticket payload modified after signing | Rejected (signatures invalid) |
| 3 | Old signatures replayed on new payload | Rejected (payload mismatch) |
| 4 | One authority's private key leaked | Cannot forge (need 2 keys) |
| 5 | One authority goes offline | System works (2 remaining suffice) |
| 6 | Ticket with only 1 signature submitted | Rejected by TGS |
