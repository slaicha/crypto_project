"""
Hypertree benchmark — KeyGen speedup vs flat MSS.

The point we are showing is simple and powerful:

    For the SAME total signing capacity N = 2^(h_top + h_bot), a 2-layer
    hypertree finishes its (initial) KeyGen much faster than a single flat
    Merkle tree, because it only materializes the top tree and the FIRST
    bottom tree upfront.

We measure three configurations side by side:
    - Flat MSS (h = 8) ........... 256 signatures, 1 tree of 256 leaves
    - Hypertree (h_top=4, h_bot=4) 256 signatures, 16 + 16 leaves built lazily
    - Flat MSS (h = 10) .......... 1024 signatures, 1 tree of 1024 leaves
    - Hypertree (h_top=5, h_bot=5) 1024 signatures, 32 + 32 leaves built lazily

For each config we record KeyGen time, single-Sign time, single-Verify time,
and signature size in bytes. We then plot KeyGen time vs total capacity for
both schemes.
"""

import json
import os
import sys
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from src.merkle import MerkleSignature
from src.hypertree import Hypertree

OTS_SCHEME = "wots"
W = 16
MESSAGE = b"benchmark message"


# ---------- helpers ----------
def measure_flat(height):
    mss = MerkleSignature(height=height, ots_scheme=OTS_SCHEME, w=W)
    t0 = time.time()
    sk, pk = mss.generate_keypair()
    keygen_ms = (time.time() - t0) * 1000

    t0 = time.time()
    sig = mss.sign(MESSAGE, sk)
    sign_ms = (time.time() - t0) * 1000

    t0 = time.time()
    ok = mss.verify(MESSAGE, sig, pk)
    verify_ms = (time.time() - t0) * 1000

    sig_bytes = _approx_mss_sig_size(sig)
    return {
        "scheme": f"Flat MSS (h={height})",
        "capacity": 1 << height,
        "keygen_ms": keygen_ms,
        "sign_ms": sign_ms,
        "verify_ms": verify_ms,
        "sig_bytes": sig_bytes,
        "verified": ok,
    }


def measure_hyper(h_top, h_bot):
    ht = Hypertree(h_top=h_top, h_bot=h_bot, ots_scheme=OTS_SCHEME, w=W)
    t0 = time.time()
    sk, pk = ht.generate_keypair()
    keygen_ms = (time.time() - t0) * 1000

    t0 = time.time()
    sig = ht.sign(MESSAGE, sk)
    sign_ms = (time.time() - t0) * 1000

    t0 = time.time()
    ok = ht.verify(MESSAGE, sig, pk)
    verify_ms = (time.time() - t0) * 1000

    sig_bytes = _approx_hyper_sig_size(sig)
    return {
        "scheme": f"Hypertree (h_top={h_top}, h_bot={h_bot})",
        "capacity": 1 << (h_top + h_bot),
        "keygen_ms": keygen_ms,
        "sign_ms": sign_ms,
        "verify_ms": verify_ms,
        "sig_bytes": sig_bytes,
        "verified": ok,
    }


def _approx_mss_sig_size(sig):
    """Sum of bytes in an MSS signature: OTS pk + OTS sig + auth path + index."""
    n = 4  # leaf_index
    for item in sig["ots_public_key"]:
        if isinstance(item, tuple):
            n += 32 * len(item)
        else:
            n += 32
    n += 32 * len(sig["ots_signature"])
    n += 32 * len(sig["auth_path"])
    return n


def _approx_hyper_sig_size(sig):
    """A hypertree sig is two MSS sigs + the bottom-root + the bottom_index."""
    return (4                                              # bottom_index
            + 32                                           # bottom_root
            + _approx_mss_sig_size(sig["bottom_signature"])
            + _approx_mss_sig_size(sig["top_signature_on_root"]))


# ---------- run ----------
def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))
    results = []

    print("Benchmarking flat MSS vs 2-layer Hypertree at matched capacities...\n")
    configs = [
        ("flat",  {"height": 8}),
        ("hyper", {"h_top": 4, "h_bot": 4}),
        ("flat",  {"height": 10}),
        ("hyper", {"h_top": 5, "h_bot": 5}),
    ]
    for kind, kwargs in configs:
        if kind == "flat":
            r = measure_flat(**kwargs)
        else:
            r = measure_hyper(**kwargs)
        results.append(r)
        print(f"  {r['scheme']:<35} cap={r['capacity']:<6} "
              f"KG={r['keygen_ms']:8.2f} ms  sign={r['sign_ms']:6.2f} ms  "
              f"verify={r['verify_ms']:6.2f} ms  sig={r['sig_bytes']} B")

    # Save raw numbers
    json_path = os.path.join(out_dir, "hypertree_results.json")
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)

    # Pair up: index 0 vs 1 (capacity 256), index 2 vs 3 (capacity 1024)
    flat_keygen  = [results[0]["keygen_ms"], results[2]["keygen_ms"]]
    hyper_keygen = [results[1]["keygen_ms"], results[3]["keygen_ms"]]
    capacities   = [results[0]["capacity"], results[2]["capacity"]]

    x = range(len(capacities))
    width = 0.35

    plt.figure(figsize=(7, 4.5))
    plt.bar([i - width / 2 for i in x], flat_keygen, width=width,
            label="Flat MSS (single tree)", color="#7F7F7F")
    plt.bar([i + width / 2 for i in x], hyper_keygen, width=width,
            label="2-layer Hypertree", color="#2A9D8F")
    for i, val in enumerate(flat_keygen):
        plt.text(i - width / 2, val * 1.02, f"{val:.0f}", ha="center", fontsize=9)
    for i, val in enumerate(hyper_keygen):
        plt.text(i + width / 2, val * 1.02, f"{val:.0f}", ha="center", fontsize=9)
    plt.xticks(list(x), [f"N = {c}" for c in capacities])
    plt.ylabel("Initial KeyGen time (ms)")
    plt.title("Hypertree slashes initial KeyGen time at matched signing capacity")
    plt.legend()
    plt.grid(True, axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "hypertree_keygen.png"), dpi=120)
    plt.close()

    print("\nWrote:")
    print(" -", os.path.join(out_dir, "hypertree_keygen.png"))
    print(" -", json_path)


if __name__ == "__main__":
    main()
