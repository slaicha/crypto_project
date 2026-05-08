"""
Benchmark plots — publication-quality figures for the performance evaluation.

Reads the JSON produced by parameter_sweep.py and generates six plots:
  1. OTS signature size vs w
  2. OTS sign + verify time vs w
  3. MSS keygen time vs tree height
  4. MSS sign & verify time vs tree height
  5. MSS signature size vs tree height
  6. MSS trade-off at fixed h (sig size vs computation, varying w)

Run with:
    python benchmarks/plot_benchmarks.py
"""

import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
JSON_PATH = os.path.join(OUT_DIR, "benchmark_results.json")

# ---- Styling ----
plt.rcParams.update({
    "figure.facecolor": "#ffffff",
    "axes.facecolor":   "#ffffff",
    "axes.edgecolor":   "#cccccc",
    "axes.grid":        True,
    "grid.alpha":       0.3,
    "font.size":        11,
    "axes.titlesize":   13,
    "axes.labelsize":   12,
    "legend.fontsize":  10,
    "figure.dpi":       130,
})

LAMPORT_COLOR = "#2563eb"
WOTS_COLOR    = "#e11d48"
ACCENT        = "#7c3aed"


def load():
    with open(JSON_PATH) as f:
        return json.load(f)


# ======================================================================== #
# Plot 1 — OTS: Signature size vs w
# ======================================================================== #
def plot_ots_sig_size(data):
    ots = data["ots_sweep"]
    lamport = [r for r in ots if r["scheme"] == "Lamport"][0]
    wots    = [r for r in ots if r["scheme"] == "WOTS"]

    ws   = [r["w"] for r in wots]
    sizes = [r["sig_size"] for r in wots]

    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    x = np.arange(len(ws))
    ax.bar(x, sizes, color=WOTS_COLOR, alpha=0.85, label="WOTS", zorder=3)
    ax.axhline(y=lamport["sig_size"], color=LAMPORT_COLOR, ls="--", lw=2,
               label=f"Lamport ({lamport['sig_size']:,} B)", zorder=4)
    ax.set_xticks(x)
    ax.set_xticklabels([str(w) for w in ws])
    ax.set_xlabel("Winternitz parameter w")
    ax.set_ylabel("Signature size (bytes)")
    ax.set_title("OTS Signature Size — WOTS shrinks as w grows")
    ax.legend()

    # value labels on bars
    for i, v in enumerate(sizes):
        ax.text(i, v + 200, f"{v:,}", ha="center", va="bottom", fontsize=9)

    fig.tight_layout()
    path = os.path.join(OUT_DIR, "ots_sig_size.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  → {path}")


# ======================================================================== #
# Plot 2 — OTS: Sign + Verify time vs w
# ======================================================================== #
def plot_ots_times(data):
    ots = data["ots_sweep"]
    lamport = [r for r in ots if r["scheme"] == "Lamport"][0]
    wots    = [r for r in ots if r["scheme"] == "WOTS"]

    ws   = [r["w"] for r in wots]
    sign_t  = [r["sign_ms"] for r in wots]
    ver_t   = [r["verify_ms"] for r in wots]

    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    x = np.arange(len(ws))
    width = 0.35
    ax.bar(x - width/2, sign_t,  width, label="Sign",   color=WOTS_COLOR, alpha=0.80, zorder=3)
    ax.bar(x + width/2, ver_t,   width, label="Verify", color=ACCENT,     alpha=0.80, zorder=3)
    ax.axhline(y=lamport["sign_ms"],   color=LAMPORT_COLOR, ls="--", lw=1.5,
               label=f"Lamport Sign ({lamport['sign_ms']:.2f} ms)")
    ax.axhline(y=lamport["verify_ms"], color=LAMPORT_COLOR, ls=":",  lw=1.5,
               label=f"Lamport Verify ({lamport['verify_ms']:.2f} ms)")
    ax.set_xticks(x)
    ax.set_xticklabels([str(w) for w in ws])
    ax.set_xlabel("Winternitz parameter w")
    ax.set_ylabel("Time (ms)")
    ax.set_title("OTS Computation Cost — larger w means more hash chains")
    ax.legend(fontsize=9, ncol=2)
    fig.tight_layout()
    path = os.path.join(OUT_DIR, "ots_times.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  → {path}")


# ======================================================================== #
# Plot 3 — MSS: KeyGen time vs tree height
# ======================================================================== #
def plot_mss_keygen(data):
    mss = data["mss_height_sweep"]
    lam = [r for r in mss if r["scheme"] == "lamport"]
    wot = [r for r in mss if r["scheme"] == "wots"]

    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    ax.plot([r["height"] for r in lam], [r["keygen_ms"] for r in lam],
            "o-", color=LAMPORT_COLOR, lw=2, ms=7, label="Lamport leaves")
    ax.plot([r["height"] for r in wot], [r["keygen_ms"] for r in wot],
            "s-", color=WOTS_COLOR, lw=2, ms=7, label="WOTS (w=16) leaves")
    ax.set_xlabel("Tree height h  (signs up to 2^h messages)")
    ax.set_ylabel("KeyGen time (ms)")
    ax.set_yscale("log")
    ax.set_title("MSS KeyGen — exponential in tree height")
    ax.legend()
    fig.tight_layout()
    path = os.path.join(OUT_DIR, "mss_keygen.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  → {path}")


# ======================================================================== #
# Plot 4a — MSS: Sign time vs tree height
# ======================================================================== #
def plot_mss_sign(data):
    mss = data["mss_height_sweep"]
    lam = [r for r in mss if r["scheme"] == "lamport"]
    wot = [r for r in mss if r["scheme"] == "wots"]

    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    ax.plot([r["height"] for r in lam], [r["sign_ms"] for r in lam],
            "o-", color=LAMPORT_COLOR, lw=2, ms=7, label="Lamport leaves")
    ax.plot([r["height"] for r in wot], [r["sign_ms"] for r in wot],
            "s-", color=WOTS_COLOR, lw=2, ms=7, label="WOTS (w=16) leaves")
    ax.set_xlabel("Tree height h  (signs up to 2^h messages)")
    ax.set_ylabel("Sign time (ms)")
    ax.set_title("MSS Sign Time — nearly constant in tree height")
    ax.legend()
    fig.tight_layout()
    path = os.path.join(OUT_DIR, "mss_sign.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  → {path}")


# ======================================================================== #
# Plot 4b — MSS: Verify time vs tree height
# ======================================================================== #
def plot_mss_verify(data):
    mss = data["mss_height_sweep"]
    lam = [r for r in mss if r["scheme"] == "lamport"]
    wot = [r for r in mss if r["scheme"] == "wots"]

    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    ax.plot([r["height"] for r in lam], [r["verify_ms"] for r in lam],
            "o-", color=LAMPORT_COLOR, lw=2, ms=7, label="Lamport leaves")
    ax.plot([r["height"] for r in wot], [r["verify_ms"] for r in wot],
            "s-", color=WOTS_COLOR, lw=2, ms=7, label="WOTS (w=16) leaves")
    ax.set_xlabel("Tree height h  (signs up to 2^h messages)")
    ax.set_ylabel("Verify time (ms)")
    ax.set_title("MSS Verify Time — nearly constant in tree height")
    ax.legend()
    fig.tight_layout()
    path = os.path.join(OUT_DIR, "mss_verify.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  → {path}")


# ======================================================================== #
# Plot 5 — MSS: Signature size vs tree height
# ======================================================================== #
def plot_mss_sig_size(data):
    mss = data["mss_height_sweep"]
    lam = [r for r in mss if r["scheme"] == "lamport"]
    wot = [r for r in mss if r["scheme"] == "wots"]

    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    ax.plot([r["height"] for r in lam], [r["sig_size"] for r in lam],
            "o-", color=LAMPORT_COLOR, lw=2, ms=7, label="Lamport leaves")
    ax.plot([r["height"] for r in wot], [r["sig_size"] for r in wot],
            "s-", color=WOTS_COLOR, lw=2, ms=7, label="WOTS (w=16) leaves")
    ax.set_xlabel("Tree height h")
    ax.set_ylabel("Signature size (bytes)")
    ax.set_title("MSS Signature Size — grows by 32 B per level")
    ax.legend()
    fig.tight_layout()
    path = os.path.join(OUT_DIR, "mss_sig_size.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  → {path}")


# ======================================================================== #
# Plot 6 — MSS w-sweep: trade-off at fixed h=4
# ======================================================================== #
def plot_mss_w_tradeoff(data):
    mss_w = data["mss_w_sweep"]

    ws        = [r["w"] for r in mss_w]
    sig_sizes = [r["sig_size"] for r in mss_w]
    total_t   = [r["sign_ms"] + r["verify_ms"] for r in mss_w]

    fig, ax1 = plt.subplots(figsize=(7.5, 4.5))
    ax2 = ax1.twinx()

    bar_x = np.arange(len(ws))
    bars = ax1.bar(bar_x, sig_sizes, color=WOTS_COLOR, alpha=0.7, label="Sig size", zorder=3)
    line = ax2.plot(bar_x, total_t, "o-", color=ACCENT, lw=2.5, ms=8,
                    label="Sign + Verify time", zorder=4)

    ax1.set_xticks(bar_x)
    ax1.set_xticklabels([str(w) for w in ws])
    ax1.set_xlabel("Winternitz parameter w  (tree height fixed at h = 4)")
    ax1.set_ylabel("Signature size (bytes)", color=WOTS_COLOR)
    ax2.set_ylabel("Sign + Verify time (ms)", color=ACCENT)
    ax1.set_title("MSS Trade-off — smaller signatures cost more computation")

    # Combined legend
    handles = [bars, line[0]]
    labels  = ["Sig size (bytes)", "Sign + Verify (ms)"]
    ax1.legend(handles, labels, loc="center right")

    fig.tight_layout()
    path = os.path.join(OUT_DIR, "mss_w_tradeoff.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  → {path}")


# ======================================================================== #
def main():
    data = load()
    print("Generating benchmark plots ...")
    plot_ots_sig_size(data)
    plot_ots_times(data)
    plot_mss_keygen(data)
    plot_mss_sign(data)
    plot_mss_verify(data)
    plot_mss_sig_size(data)
    plot_mss_w_tradeoff(data)
    print("Done.")


if __name__ == "__main__":
    main()
