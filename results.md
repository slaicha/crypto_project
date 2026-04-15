# Week 1 Results: One-Time Signatures (OTS)

## 1. Implementation Overview

We implemented two primary hash-based one-time signature schemes using Python and the SHA-256 hash function:

- **Lamport OTS**: A classic scheme where each bit of the message hash is signed by revealing one of two secret blocks.
- **Winternitz OTS (WOTS)**: An optimized scheme that uses hash chains to sign multi-bit digits, significantly reducing signature size at the cost of increased computation.

### Project Structure
```
crypto_project/
├── src/
│   ├── utils.py               # Hashing and bit manipulation
│   ├── lamport.py             # Lamport OTS implementation
│   ├── wots.py                # Winternitz OTS implementation
│   └── security_simulation.py  # Key reuse attack demonstration
├── benchmarks/
│   └── week1_analysis.py      # Performance measurement script
└── tests/
    └── run_tests.py           # Unit tests
```

## 2. Performance Benchmarking

The following benchmarks were recorded on the local system (time in milliseconds, size in bytes).

| Scheme | KeyGen (ms) | Sign (ms) | Verify (ms) | Signature Size (Bytes) |
| :--- | :--- | :--- | :--- | :--- |
| **Lamport** | 0.61 | 0.03 | 0.17 | 8192 |
| **WOTS (w=4)** | 0.29 | 0.17 | 0.16 | 4256 |
| **WOTS (w=16)** | 0.58 | 0.29 | 0.30 | 2144 |
| **WOTS (w=256)** | 4.59 | 2.28 | 2.33 | 1088 |

### Observation: The Winternitz Trade-off
As the Winternitz parameter $w$ increases:
- **Signature size decreases**: WOTS (w=256) is ~7.5x smaller than Lamport.
- **Computation time increases**: WOTS (w=256) requires significantly more hash operations during key generation, signing, and verification.

## 3. Security Analysis: Key Reuse Simulation

### Findings
- Lamport signatures are strictly **one-time**.
- Reusing a secret key to sign multiple messages reveals multiple secret blocks.
- In our simulation, signing **20 random messages** with the same key revealed enough secret material to successfully **forge a valid signature** for an arbitrary target message ("Retreat at noon").

### Simulation Logs
The detailed log of the attack can be found in `benchmarks/simulation_results.txt`.

**Raw Output:**
```text
Signing 20 messages with the SAME key...

SUCCESS: Forged signature for 'Retreat at noon'!
Verification of forged signature: True
```

**Impact**: Key reuse completely breaks the security of OTS schemes. This necessitates the use of more complex structures like Merkle Trees (Week 2) to manage multiple keys securely.

## 4. Verification
All implementations were verified using unit tests covering:
- Correctness (valid signatures verify successfully).
- Integrity (signatures fail if the message or signature is tampered with).
- Parameter variations (WOTS with different $w$ values).
