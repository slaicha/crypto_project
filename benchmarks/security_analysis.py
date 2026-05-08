"""
Security Analysis — Lamport Key-Reuse Attack.

This script extends the Lamport key-reuse demo into a quantitative
study, and produces three artifacts:

    benchmarks/forgery_probability.png   - empirical forgery probability vs k
    benchmarks/key_exposure.png          - fraction of secret bits revealed vs k
    benchmarks/security_results.json     - raw numbers for the report

Theory recap
------------
A Lamport secret key is a 256x2 array of 32-byte blocks. Signing a message
reveals exactly one block of each row (the one selected by the corresponding
bit of the message hash). After signing `k` independent random messages with
the SAME key, the probability that a SPECIFIC block (say SK[i][b]) has NOT
been revealed is (1/2)**k.

To forge a signature on a TARGET message, the attacker needs the 256 specific
blocks chosen by the target's hash bits. The probability that all 256 needed
blocks have been revealed after k reuses is

    P_forge(k) = (1 - (1/2)**k) ** 256.

Quick numerical reference:
    k=8   -> ~ 36.6%
    k=10  -> ~ 78.0%
    k=12  -> ~ 94.0%
    k=15  -> ~ 99.2%
    k=20  -> ~ 99.98%

This script verifies the prediction empirically by repeating the experiment
many times for each k and counting forgery successes.
"""

import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from src.lamport import LamportOTS
from src.utils import get_hash, bytes_to_bits, generate_random_bytes


# Sweep these values of k = "number of times the same secret key is reused".
KS = [1, 2, 4, 6, 8, 10, 12, 14, 16, 20]
TRIALS_PER_K = 200             # higher -> smoother curve, slower to run


def attempt_forgery(reuses):
    """
    Run one trial: generate a fresh Lamport keypair, sign `reuses` random
    messages, then try to forge a signature for one final random target.

    Returns
    -------
    forged_ok : bool   - True if every needed block was revealed
    bits_revealed : int - how many of the 512 (256 rows x 2 cols) blocks were exposed
    """
    ots = LamportOTS()
    sk, pk = ots.generate_keypair()

    revealed = [[False, False] for _ in range(256)]   # which blocks have been exposed
    revealed_block = [[None, None] for _ in range(256)]

    # Sign `reuses` random messages with the same key.
    for _ in range(reuses):
        msg = generate_random_bytes(32)
        sig = ots.sign(msg, sk)
        bits = bytes_to_bits(get_hash(msg))
        for i in range(256):
            b = bits[i]
            revealed[i][b] = True
            revealed_block[i][b] = sig[i]

    # Try to forge a signature on a fresh random target.
    target = generate_random_bytes(32)
    target_bits = bytes_to_bits(get_hash(target))

    forged = []
    for i in range(256):
        b = target_bits[i]
        if not revealed[i][b]:
            # Missing a block we need -> attack fails for this target.
            return False, sum(r[0] + r[1] for r in revealed)
        forged.append(revealed_block[i][b])

    # Sanity check: the forged signature really should verify.
    assert ots.verify(target, forged, pk), "forged signature failed to verify"

    return True, sum(r[0] + r[1] for r in revealed)


def theoretical_forgery_prob(k):
    """P_forge(k) = (1 - (1/2)**k) ** 256."""
    return (1.0 - (0.5 ** k)) ** 256


def recover_secret_material(reuses=20, dump_path=None):
    """
    Explicit "recover secret material" demonstration for the mandatory extension.

    Generates one Lamport keypair, signs `reuses` random messages with it,
    rebuilds as much of the 256x2 secret-key matrix as the leaked signatures
    allow, and (a) reports how complete the recovered key is, (b) verifies
    that recovered blocks match the true ones, and (c) optionally writes the
    recovered key out as JSON for inspection.

    Returns
    -------
    stats : dict with keys
        total_blocks, recovered_blocks, recovery_pct, blocks_match
    """
    ots = LamportOTS()
    true_sk, pk = ots.generate_keypair()       # the secret we (the attacker) want to learn

    # The attacker only sees signatures. Start with an empty 256x2 matrix.
    recovered = [[None, None] for _ in range(256)]

    for _ in range(reuses):
        msg = generate_random_bytes(32)
        sig = ots.sign(msg, true_sk)
        bits = bytes_to_bits(get_hash(msg))
        for i in range(256):
            b = bits[i]
            recovered[i][b] = sig[i]           # this revealed block IS sk[i][b]

    # Tally: how complete is the recovered key, and do the blocks we have match the truth?
    recovered_blocks = 0
    blocks_match = 0
    for i in range(256):
        for b in (0, 1):
            if recovered[i][b] is not None:
                recovered_blocks += 1
                if recovered[i][b] == true_sk[i][b]:
                    blocks_match += 1

    total_blocks = 256 * 2
    recovery_pct = 100.0 * recovered_blocks / total_blocks

    print("\n=== RECOVERING SECRET MATERIAL ===")
    print(f"Reuses observed by attacker : {reuses}")
    print(f"Secret-key blocks total     : {total_blocks}  (256 rows x 2 columns)")
    print(f"Blocks recovered            : {recovered_blocks} ({recovery_pct:.1f}%)")
    print(f"Recovered blocks that match : {blocks_match} / {recovered_blocks}  "
          f"-> recovery is byte-exact: {blocks_match == recovered_blocks}")

    # Show the first row of the secret key side-by-side as concrete proof.
    print("\nExample — secret-key row 0 (true vs recovered, hex-truncated):")
    for b in (0, 1):
        true_hex = true_sk[0][b].hex()[:24] + "..."
        rec_hex = (recovered[0][b].hex()[:24] + "...") if recovered[0][b] is not None else "<not revealed>"
        match = "OK" if recovered[0][b] == true_sk[0][b] else ("MISSING" if recovered[0][b] is None else "MISMATCH")
        print(f"  sk[0][{b}]  true={true_hex}  recovered={rec_hex}  [{match}]")

    if dump_path is not None:
        dump = {
            "reuses": reuses,
            "total_blocks": total_blocks,
            "recovered_blocks": recovered_blocks,
            "recovery_pct": recovery_pct,
            "all_recovered_blocks_match_true_key": blocks_match == recovered_blocks,
            # Save the recovered key in hex so it is human-inspectable.
            "recovered_secret_key_hex": [
                [recovered[i][0].hex() if recovered[i][0] is not None else None,
                 recovered[i][1].hex() if recovered[i][1] is not None else None]
                for i in range(256)
            ],
        }
        with open(dump_path, "w") as f:
            json.dump(dump, f, indent=2)
        print(f"\nFull recovered secret key written to: {dump_path}")

    return {
        "total_blocks": total_blocks,
        "recovered_blocks": recovered_blocks,
        "recovery_pct": recovery_pct,
        "blocks_match": blocks_match == recovered_blocks,
    }


def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))

    # Step 0: explicit secret-material recovery for the mandatory extension.
    recover_secret_material(
        reuses=20,
        dump_path=os.path.join(out_dir, "recovered_secret_key.json"),
    )

    empirical_rate = []
    theoretical_rate = []
    avg_bits_revealed_frac = []

    print(f"Running {TRIALS_PER_K} trials per k for k in {KS}...")
    for k in KS:
        successes = 0
        bits_total = 0
        for _ in range(TRIALS_PER_K):
            ok, bits = attempt_forgery(k)
            if ok:
                successes += 1
            bits_total += bits

        rate = successes / TRIALS_PER_K
        bits_frac = bits_total / (TRIALS_PER_K * 512)   # 512 = 256 rows x 2 cols
        theo = theoretical_forgery_prob(k)

        empirical_rate.append(rate)
        theoretical_rate.append(theo)
        avg_bits_revealed_frac.append(bits_frac)

        print(f"  k={k:>3}: forgery rate empirical={rate:.3f}  "
              f"theoretical={theo:.3f}  "
              f"avg blocks revealed={bits_frac*100:.1f}%")

    # Save raw data so the README numbers stay reproducible.
    results = {
        "trials_per_k": TRIALS_PER_K,
        "k_values": KS,
        "empirical_forgery_rate": empirical_rate,
        "theoretical_forgery_rate": theoretical_rate,
        "fraction_blocks_revealed": avg_bits_revealed_frac,
    }
    json_path = os.path.join(out_dir, "security_results.json")
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)

    # Plot 1: forgery rate (empirical vs theoretical)
    plt.figure(figsize=(7, 4.5))
    plt.plot(KS, theoretical_rate, "k--", label="Theoretical  $(1 - 2^{-k})^{256}$")
    plt.plot(KS, empirical_rate, "o-", label=f"Empirical (n={TRIALS_PER_K} trials per k)")
    plt.xlabel("k = number of times the same Lamport key was reused")
    plt.ylabel("Probability of successfully forging an arbitrary message")
    plt.title("Lamport key reuse: forgery probability grows fast with k")
    plt.ylim(-0.02, 1.05)
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "forgery_probability.png"), dpi=120)
    plt.close()

    # Plot 2: how much of the secret material the attacker has collected
    plt.figure(figsize=(7, 4.5))
    plt.plot(KS, [f * 100 for f in avg_bits_revealed_frac], "s-", color="firebrick")
    plt.xlabel("k = number of reused signatures observed")
    plt.ylabel("Average fraction of secret blocks exposed (%)")
    plt.title("Each reuse leaks more of the 512-block Lamport secret key")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "key_exposure.png"), dpi=120)
    plt.close()

    print("\nWrote:")
    print(" -", os.path.join(out_dir, "forgery_probability.png"))
    print(" -", os.path.join(out_dir, "key_exposure.png"))
    print(" -", json_path)


if __name__ == "__main__":
    main()
