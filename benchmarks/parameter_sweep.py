"""
Parameter Sweep — Performance Evaluation & Parameter Tuning.

Runs three systematic sweeps and saves the raw numbers to a JSON file
that plot_benchmarks.py turns into publication-quality figures.

Sweeps
------
1. OTS primitive: Lamport + WOTS for w in {4, 8, 16, 32, 64, 128, 256}
   → keygen, sign, verify times + signature / key sizes.
2. MSS height sweep: h in {1..8} for both Lamport and WOTS (w=16)
   → keygen, sign, verify times + signature size.
3. MSS w-sweep at fixed h=4: WOTS w in {4, 8, 16, 32, 64, 128, 256}
   → shows how w affects the full Merkle scheme.

Run with:
    python benchmarks/parameter_sweep.py
"""

import json
import os
import sys
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.lamport import LamportOTS
from src.wots import WOTS
from src.merkle import MerkleSignature

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
RUNS = 5                      # repetitions per configuration (mean + variance reported)
MESSAGE = "Post-quantum cryptography is exciting!"

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
JSON_PATH = os.path.join(OUT_DIR, "benchmark_results.json")


def _mean(values):
    """Arithmetic mean (average) of a list of numbers."""
    return sum(values) / len(values)


def _variance(values):
    """
    Sample variance of a list of numbers.
    Measures how much the individual runs spread around the mean —
    a small variance means the measurement is stable and reliable.
    """
    m = _mean(values)
    return sum((x - m) ** 2 for x in values) / (len(values) - 1)


def _ots_sig_size(sig, scheme_name):
    """Compute raw signature size in bytes."""
    if scheme_name == "lamport":
        return len(sig) * 32            # 256 blocks × 32 B
    else:  # wots
        return len(sig) * 32


def _ots_pk_size(pk, scheme_name):
    """Compute raw public key size in bytes."""
    if scheme_name == "lamport":
        return len(pk) * 2 * 32        # 256 pairs × 2 × 32 B
    else:  # wots
        return len(pk) * 32


def _ots_sk_size(sk, scheme_name):
    """Compute raw secret key size in bytes."""
    if scheme_name == "lamport":
        return len(sk) * 2 * 32
    else:
        return len(sk) * 32


def _mss_sig_size(signature):
    """
    Calculates the total MSS signature size on-the-wire.
    Formula: index (4B) + OTS signature + OTS public key + Merkle auth path (h * 32B)
    """
    size = 4  # 4 bytes for the leaf index
    size += 32 * len(signature["ots_signature"])
    # Calculate size of the serialized OTS public key
    for item in signature["ots_public_key"]:
        if isinstance(item, tuple): # Lamport uses tuples of (pk0, pk1)
            size += 32 * len(item)
        else: # WOTS uses flat lists
            size += 32
    # Add authentication path size (h nodes * 32 bytes each)
    size += 32 * len(signature["auth_path"])
    return size


# ---------------------------------------------------------------------------
# Sweep 1: OTS primitives
# ---------------------------------------------------------------------------
def sweep_ots():
    """
    Benchmarks the underlying One-Time Signature schemes.
    Compares Lamport against WOTS with varying 'w' parameters.
    """
    results = []

    # --- Lamport ---
    entry = {"scheme": "Lamport", "w": None}
    kg_t, sg_t, vf_t = [], [], []
    for _ in range(RUNS):
        ots = LamportOTS()
        # Measure KeyGen, Signing, and Verification time independently
        t0 = time.time(); sk, pk = ots.generate_keypair(); kg_t.append((time.time() - t0) * 1000)
        t0 = time.time(); sig = ots.sign(MESSAGE, sk);     sg_t.append((time.time() - t0) * 1000)
        t0 = time.time(); ots.verify(MESSAGE, sig, pk);    vf_t.append((time.time() - t0) * 1000)
    
    # Store the mean and variance of the runs
    entry["keygen_ms"]       = round(_mean(kg_t), 4)
    entry["keygen_var"]      = round(_variance(kg_t), 6)
    entry["sign_ms"]         = round(_mean(sg_t), 4)
    entry["sign_var"]        = round(_variance(sg_t), 6)
    entry["verify_ms"]       = round(_mean(vf_t), 4)
    entry["verify_var"]      = round(_variance(vf_t), 6)
    entry["sig_size"]        = _ots_sig_size(sig, "lamport")
    entry["pk_size"]         = _ots_pk_size(pk, "lamport")
    entry["sk_size"]         = _ots_sk_size(sk, "lamport")
    results.append(entry)

    # --- WOTS Parameter Sweep ---
    # We test w from 4 to 256 to show the size-time trade-off
    for w in [4, 8, 16, 32, 64, 128, 256]:
        entry = {"scheme": f"WOTS", "w": w}
        kg_t, sg_t, vf_t = [], [], []
        for _ in range(RUNS):
            ots = WOTS(w=w)
            t0 = time.time(); sk, pk = ots.generate_keypair(); kg_t.append((time.time() - t0) * 1000)
            t0 = time.time(); sig = ots.sign(MESSAGE, sk);     sg_t.append((time.time() - t0) * 1000)
            t0 = time.time(); ots.verify(MESSAGE, sig, pk);    vf_t.append((time.time() - t0) * 1000)
        
        entry["keygen_ms"]   = round(_mean(kg_t), 4)
        entry["keygen_var"]  = round(_variance(kg_t), 6)
        entry["sign_ms"]     = round(_mean(sg_t), 4)
        entry["sign_var"]    = round(_variance(sg_t), 6)
        entry["verify_ms"]   = round(_mean(vf_t), 4)
        entry["verify_var"]  = round(_variance(vf_t), 6)
        entry["sig_size"]    = _ots_sig_size(sig, "wots")
        entry["pk_size"]     = _ots_pk_size(pk, "wots")
        entry["sk_size"]     = _ots_sk_size(sk, "wots")
        results.append(entry)

    return results


# ---------------------------------------------------------------------------
# Sweep 2: MSS tree height
# ---------------------------------------------------------------------------
def sweep_mss_height():
    """
    Benchmarks how the Merkle Signature Scheme scales with tree height (h).
    Tests h from 1 to 8 (2 to 256 messages).
    """
    results = []
    heights = list(range(1, 9))  # h = 1..8

    for ots_scheme, w in [("lamport", 16), ("wots", 16)]:
        for h in heights:
            label = f"MSS h={h}, {ots_scheme}" + (f" (w={w})" if ots_scheme == "wots" else "")
            print(f"  measuring {label} ...", flush=True)
            
            entry = {"scheme": ots_scheme, "w": w if ots_scheme == "wots" else None,
                     "height": h, "leaves": 1 << h}
            kg_t, sg_t, vf_t = [], [], []
            sig_size = 0
            
            for _ in range(RUNS):
                mss = MerkleSignature(height=h, ots_scheme=ots_scheme, w=w)
                t0 = time.time(); sk, pk = mss.generate_keypair(); kg_t.append((time.time() - t0) * 1000)
                t0 = time.time(); sig = mss.sign(MESSAGE, sk);     sg_t.append((time.time() - t0) * 1000)
                t0 = time.time(); mss.verify(MESSAGE, sig, pk);    vf_t.append((time.time() - t0) * 1000)
                sig_size = _mss_sig_size(sig)
            
            entry["keygen_ms"]  = round(_mean(kg_t), 4)
            entry["keygen_var"] = round(_variance(kg_t), 6)
            entry["sign_ms"]    = round(_mean(sg_t), 4)
            entry["sign_var"]   = round(_variance(sg_t), 6)
            entry["verify_ms"]  = round(_mean(vf_t), 4)
            entry["verify_var"] = round(_variance(vf_t), 6)
            entry["sig_size"]   = sig_size
            results.append(entry)

    return results


# ---------------------------------------------------------------------------
# Sweep 3: MSS w-sweep at fixed height
# ---------------------------------------------------------------------------
def sweep_mss_w(fixed_h=4):
    """
    Analyzes the trade-off of the 'w' parameter within the full Merkle scheme.
    Keeps tree height constant (h=4) while varying the Winternitz parameter.
    """
    results = []
    # Test w from 4 up to 256
    for w in [4, 8, 16, 32, 64, 128, 256]:
        label = f"MSS h={fixed_h}, WOTS w={w}"
        print(f"  measuring {label} ...", flush=True)
        
        entry = {"scheme": "wots", "w": w, "height": fixed_h, "leaves": 1 << fixed_h}
        kg_t, sg_t, vf_t = [], [], []
        sig_size = 0
        
        for _ in range(RUNS):
            mss = MerkleSignature(height=fixed_h, ots_scheme="wots", w=w)
            t0 = time.time(); sk, pk = mss.generate_keypair(); kg_t.append((time.time() - t0) * 1000)
            t0 = time.time(); sig = mss.sign(MESSAGE, sk);     sg_t.append((time.time() - t0) * 1000)
            t0 = time.time(); mss.verify(MESSAGE, sig, pk);    vf_t.append((time.time() - t0) * 1000)
            sig_size = _mss_sig_size(sig)
            
        entry["keygen_ms"]  = round(_mean(kg_t), 4)
        entry["keygen_var"] = round(_variance(kg_t), 6)
        entry["sign_ms"]    = round(_mean(sg_t), 4)
        entry["sign_var"]   = round(_variance(sg_t), 6)
        entry["verify_ms"]  = round(_mean(vf_t), 4)
        entry["verify_var"] = round(_variance(vf_t), 6)
        entry["sig_size"]   = sig_size
        results.append(entry)

    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("=" * 60)
    print("Comprehensive Performance Evaluation")
    print("=" * 60)

    # 1. Benchmark basic One-Time Signature schemes
    print("\n[1/3] OTS primitive sweep ...")
    ots_results = sweep_ots()
    print("  done.\n")

    # 2. Benchmark how Merkle tree scaling affects performance
    print("[2/3] MSS height sweep (h = 1..8) ...")
    mss_height_results = sweep_mss_height()
    print("  done.\n")

    # 3. Benchmark parameter tuning for the full MSS system
    print("[3/3] MSS w-sweep at h=4 ...")
    mss_w_results = sweep_mss_w(fixed_h=4)
    print("  done.\n")

    # Combine all raw data into one dictionary
    all_results = {
        "ots_sweep": ots_results,
        "mss_height_sweep": mss_height_results,
        "mss_w_sweep": mss_w_results,
    }

    # Save data to JSON for the plotting script
    with open(JSON_PATH, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"Results saved to {JSON_PATH}")

    # --- Pretty-print summary tables ---
    print("\n" + "=" * 78)
    print("OTS Primitive Comparison  (time = mean +/- variance over 5 runs)")
    print("=" * 78)
    print(f"{'Scheme':<16} {'KeyGen (ms)':>18} {'Sign (ms)':>18} {'Verify (ms)':>18} {'Sig(B)':>8}")
    print("-" * 80)
    for r in ots_results:
        name = r["scheme"] + (f" (w={r['w']})" if r["w"] else "")
        kg = f"{r['keygen_ms']:.2f}+-{r['keygen_var']:.4f}"
        sg = f"{r['sign_ms']:.2f}+-{r['sign_var']:.4f}"
        vf = f"{r['verify_ms']:.2f}+-{r['verify_var']:.4f}"
        print(f"{name:<16} {kg:>18} {sg:>18} {vf:>18} {r['sig_size']:>8}")

    print("\n" + "=" * 78)
    print("MSS Height Sweep  (time = mean +/- variance over 5 runs)")
    print("=" * 78)
    print(f"{'Config':<22} {'KeyGen (ms)':>18} {'Sign (ms)':>18} {'Verify (ms)':>18}")
    print("-" * 80)
    for r in mss_height_results:
        name = f"h={r['height']}, {r['scheme']}" + (f" w={r['w']}" if r['w'] else "")
        kg = f"{r['keygen_ms']:.2f}+-{r['keygen_var']:.4f}"
        sg = f"{r['sign_ms']:.2f}+-{r['sign_var']:.4f}"
        vf = f"{r['verify_ms']:.2f}+-{r['verify_var']:.4f}"
        print(f"{name:<22} {kg:>18} {sg:>18} {vf:>18}")

    print("\n" + "=" * 78)
    print("MSS w-Sweep (h=4, WOTS)  (time = mean +/- variance over 5 runs)")
    print("=" * 78)
    print(f"{'w':>5} {'KeyGen (ms)':>18} {'Sign (ms)':>18} {'Verify (ms)':>18}")
    print("-" * 62)
    for r in mss_w_results:
        kg = f"{r['keygen_ms']:.2f}+-{r['keygen_var']:.4f}"
        sg = f"{r['sign_ms']:.2f}+-{r['sign_var']:.4f}"
        vf = f"{r['verify_ms']:.2f}+-{r['verify_var']:.4f}"
        print(f"{r['w']:>5} {kg:>18} {sg:>18} {vf:>18}")


if __name__ == "__main__":
    main()
