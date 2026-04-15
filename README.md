# Post-Quantum Cryptography: Hash-Based Signatures

This project implements and analyzes various hash-based signature schemes, building from basic One-Time Signatures (OTS) to complex Merkle Signature Schemes (MSS).

## Implementation Overview

During **Week 1**, we implemented two primary one-time signature schemes using SHA-256:

- **Lamport OTS**: A classic scheme where each bit of the message hash is signed by revealing one of two secret blocks.
- **Winternitz OTS (WOTS)**: An optimized scheme that uses hash chains to sign multi-bit digits, significantly reducing signature size at the cost of increased computation.

## Project Structure
```
crypto_project/
├── src/
│   ├── utils.py               # Hashing and bit manipulation
│   ├── lamport.py             # Lamport OTS implementation
│   ├── wots.py                # Winternitz OTS implementation
│   └── security_simulation.py  # Key reuse attack demonstration
├── benchmarks/
│   ├── week1_analysis.py      # Performance measurement script
│   └── simulation_results.txt  # Detailed attack log
├── tests/
│   ├── run_tests.py           # Simple test runner
│   └── test_ots.py            # Unit tests
├── results.md                 # Detailed performance and security analysis
└── README.md                  # This file
```

## How to Run

### Benchmarking
To compare the performance of Lamport and WOTS:
```bash
python3 benchmarks/week1_analysis.py
```

### Security Simulation
To observe the key reuse vulnerability in Lamport:
```bash
PYTHONPATH=. python3 src/security_simulation.py
```

### Tests
To run the automated test suite:
```bash
python3 tests/run_tests.py
```
