"""
Week 2 benchmarks — Merkle Signature Scheme.

Measures, for a few tree heights and OTS choices:
    - key generation time (dominated by generating 2**h OTS keypairs),
    - signing time (one OTS sign + walking the tree),
    - verification time (one OTS verify + hashing up the path),
    - signature size in bytes.

Run with:
    python benchmarks/week2_analysis.py
"""

import os
import sys
import time

# Allow "from src...." imports when run from the project root.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.merkle import MerkleSignature


def _signature_size_bytes(signature):
    """
    Approximate on-the-wire size of an MSS signature:
        - OTS signature: list of 32-byte blocks
        - OTS public key: list of 32-byte blocks (Lamport stores pairs)
        - auth path: `height` sibling hashes of 32 bytes each
        - leaf_index: 4 bytes (a plain integer)
    """
    size = 4  # leaf_index
    # OTS signature: always a flat list of 32-byte blocks in this project.
    size += 32 * len(signature["ots_signature"])
    # OTS public key: tuples for Lamport, raw blocks for WOTS.
    for item in signature["ots_public_key"]:
        if isinstance(item, tuple):
            size += 32 * len(item)
        else:
            size += 32
    size += 32 * len(signature["auth_path"])
    return size


def benchmark(height, ots_scheme, w=16, message="Post-quantum rocks"):
    mss = MerkleSignature(height=height, ots_scheme=ots_scheme, w=w)

    start = time.time()
    sk, pk = mss.generate_keypair()
    keygen_ms = (time.time() - start) * 1000

    start = time.time()
    sig = mss.sign(message, sk)
    sign_ms = (time.time() - start) * 1000

    start = time.time()
    ok = mss.verify(message, sig, pk)
    verify_ms = (time.time() - start) * 1000

    label = f"MSS h={height}, {ots_scheme}"
    if ots_scheme == "wots":
        label += f" (w={w})"

    print(f"--- {label} ---")
    print(f"Leaves      : {mss.num_leaves}")
    print(f"KeyGen      : {keygen_ms:.2f} ms")
    print(f"Sign        : {sign_ms:.2f} ms")
    print(f"Verify      : {verify_ms:.2f} ms  (result: {ok})")
    print(f"Sig size    : {_signature_size_bytes(sig)} bytes")
    print()


def run_all():
    # Small heights keep keygen fast while still being illustrative.
    # Week 3 will push these numbers further.
    for h in (2, 4, 6):
        benchmark(h, "lamport")
    for h in (2, 4, 6):
        benchmark(h, "wots", w=16)


if __name__ == "__main__":
    run_all()
