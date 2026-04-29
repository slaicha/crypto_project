"""
Generate plots for the Week 2 Merkle Signature benchmarks.

Produces two PNGs in benchmarks/:
    - week2_keygen.png : KeyGen time vs tree height (scales as 2**h)
    - week2_signature_size.png : Signature size vs tree height (Lamport vs WOTS)

Run with:
    python benchmarks/plot_week2.py
"""

import os
import sys
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import matplotlib
matplotlib.use("Agg")            # non-interactive backend, safe on any machine
import matplotlib.pyplot as plt

from src.merkle import MerkleSignature
from benchmarks.week2_analysis import _signature_size_bytes


HEIGHTS = [2, 3, 4, 5, 6]
MESSAGE = "Post-quantum cryptography rocks"


def measure(height, ots_scheme, w=16):
    """Return (keygen_ms, sign_ms, verify_ms, sig_size_bytes) for one config."""
    mss = MerkleSignature(height=height, ots_scheme=ots_scheme, w=w)

    t0 = time.time()
    sk, pk = mss.generate_keypair()
    keygen_ms = (time.time() - t0) * 1000

    t0 = time.time()
    sig = mss.sign(MESSAGE, sk)
    sign_ms = (time.time() - t0) * 1000

    t0 = time.time()
    mss.verify(MESSAGE, sig, pk)
    verify_ms = (time.time() - t0) * 1000

    return keygen_ms, sign_ms, verify_ms, _signature_size_bytes(sig)


def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))

    lamport_keygen, lamport_size = [], []
    wots_keygen, wots_size = [], []

    for h in HEIGHTS:
        kg, _, _, sz = measure(h, "lamport")
        lamport_keygen.append(kg)
        lamport_size.append(sz)

        kg, _, _, sz = measure(h, "wots", w=16)
        wots_keygen.append(kg)
        wots_size.append(sz)

    # -- Plot 1: KeyGen time vs height (log scale, since it grows as 2**h) --
    plt.figure(figsize=(7, 4.5))
    plt.plot(HEIGHTS, lamport_keygen, "o-", label="Lamport leaves")
    plt.plot(HEIGHTS, wots_keygen, "s-", label="WOTS (w=16) leaves")
    plt.xlabel("Tree height h  (scheme can sign 2^h messages)")
    plt.ylabel("KeyGen time (ms)")
    plt.title("Week 2 — Merkle KeyGen scales as 2^h")
    plt.yscale("log")
    plt.grid(True, which="both", alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "week2_keygen.png"), dpi=120)
    plt.close()

    # -- Plot 2: Signature size vs height (almost flat — only the auth path grows) --
    plt.figure(figsize=(7, 4.5))
    plt.plot(HEIGHTS, lamport_size, "o-", label="Lamport leaves")
    plt.plot(HEIGHTS, wots_size, "s-", label="WOTS (w=16) leaves")
    plt.xlabel("Tree height h")
    plt.ylabel("Signature size (bytes)")
    plt.title("Week 2 — Signature size barely grows with h")
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "week2_signature_size.png"), dpi=120)
    plt.close()

    print("Wrote week2_keygen.png and week2_signature_size.png to", out_dir)


if __name__ == "__main__":
    main()
