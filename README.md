# Hash-Based Digital Signatures

Implementation and evaluation of hash-based signature schemes (Lamport OTS → WOTS → Merkle Signature Scheme).

## Project Structure

```
crypto_project/
├── src/
│   ├── utils.py                 # SHA-256 hashing, bit manipulation, secure randomness
│   ├── lamport.py               # Lamport One-Time Signature scheme
│   ├── wots.py                  # Winternitz OTS with configurable parameter w
│   ├── merkle.py                # Merkle Signature Scheme (MSS) with auth paths
│   └── security_simulation.py   # Lamport key-reuse attack demonstration
├── benchmarks/
│   ├── parameter_sweep.py       # Full OTS + MSS benchmark across (w, h) parameter space
│   ├── plot_benchmarks.py       # Generates 6 performance plots from benchmark data
│   ├── security_analysis.py     # Quantitative key-reuse study (200 trials per k)
│   ├── benchmark_results.json   # Raw benchmark data
│   ├── security_results.json    # Raw security analysis data
│   ├── recovered_secret_key.json# Full recovered Lamport secret key (512 blocks)
│   ├── ots_sig_size.png         # OTS signature size vs w
│   ├── ots_times.png            # OTS computation times vs w
│   ├── mss_keygen.png           # MSS KeyGen time vs tree height
│   ├── mss_sign_verify.png      # MSS Sign & Verify time vs height
│   ├── mss_sig_size.png         # MSS signature size vs height
│   ├── mss_w_tradeoff.png       # MSS size-vs-speed trade-off (h=4)
│   ├── forgery_probability.png  # Forgery success rate vs key reuses
│   └── key_exposure.png         # Secret key exposure vs reuses
├── tests/
│   ├── run_tests.py             # Simple test runner for OTS schemes
│   ├── test_ots.py              # Unit tests for Lamport and WOTS
│   └── test_merkle.py           # Unit tests for Merkle Signature Scheme
├── report.tex                   # LaTeX project report
├── crypto_project.pdf           # Project specification
└── README.md
```

## How to Run

### Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install matplotlib numpy pytest
```

### Tests
```bash
# Run all OTS tests
python3 tests/run_tests.py

# Run Merkle tests with verbose output
python3 -m pytest tests/test_merkle.py -v
```

### Benchmarks
```bash
# Run the full parameter sweep (~55 seconds)
python3 benchmarks/parameter_sweep.py

# Generate all benchmark plots
python3 benchmarks/plot_benchmarks.py
```

### Security Analysis
```bash
# Run key-reuse attack simulation + secret key recovery
PYTHONPATH=. python3 benchmarks/security_analysis.py

# Quick key-reuse demo
PYTHONPATH=. python3 src/security_simulation.py
```

### Report
```bash
pdflatex report.tex && pdflatex report.tex
```

## Selected Results

### OTS Performance

| Scheme | Sign (ms) | Verify (ms) | Signature Size |
|---|---|---|---|
| Lamport | 0.03 | 0.17 | 8,192 B |
| WOTS (w=16) | 0.30 | 0.28 | 2,144 B |
| WOTS (w=256) | 2.28 | 2.29 | 1,088 B |

### MSS Performance (WOTS w=16)

| Height | Leaves | KeyGen (ms) | Signature Size |
|---|---|---|---|
| h=4 | 16 | 9.08 | 4,420 B |
| h=6 | 64 | 36.31 | 4,484 B |
| h=8 | 256 | 144.46 | 4,548 B |

### Key-Reuse Attack

| Reuses (k) | Forgery Probability | Secret Key Exposed |
|---|---|---|
| 8 | 38.5% | 99.6% |
| 10 | 83.5% | 99.9% |
| 15 | 100% | 100% |

After 20 reuses, the attacker recovers the **complete** 512-block secret key byte-for-byte.

## Authors

- **Aicha Slaitane** — aicha.slaitane@kaust.edu.sa
- **Abdullah Algethami** — abdullah.algethami@kaust.edu.sa
