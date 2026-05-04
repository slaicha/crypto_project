# Week 1 Results: One-Time Signatures (OTS)

## 1. Performance Benchmarking

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

## 2. Security Analysis: Key Reuse Simulation

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

## 3. Verification
All implementations were verified using unit tests covering:
- Correctness (valid signatures verify successfully).
- Integrity (signatures fail if the message or signature is tampered with).
- Parameter variations (WOTS with different $w$ values).

---

# Week 3 Results: Performance Evaluation & Parameter Tuning

## 1. OTS Primitive Comparison (Full Sweep)

We benchmarked Lamport OTS and WOTS across all power-of-two Winternitz parameters from $w=4$ to $w=256$. Each configuration was measured 5 times; medians are reported.

| Scheme | KeyGen (ms) | Sign (ms) | Verify (ms) | Sig Size (B) | PK Size (B) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Lamport** | 0.53 | 0.03 | 0.17 | 8,192 | 16,384 |
| **WOTS (w=4)** | 0.29 | 0.15 | 0.15 | 4,256 | 4,256 |
| **WOTS (w=8)** | 0.38 | 0.18 | 0.21 | 2,880 | 2,880 |
| **WOTS (w=16)** | 0.56 | 0.30 | 0.28 | 2,144 | 2,144 |
| **WOTS (w=32)** | 0.92 | 0.47 | 0.47 | 1,760 | 1,760 |
| **WOTS (w=64)** | 1.49 | 0.68 | 0.84 | 1,440 | 1,440 |
| **WOTS (w=128)** | 2.53 | 1.27 | 1.31 | 1,248 | 1,248 |
| **WOTS (w=256)** | 4.47 | 2.28 | 2.29 | 1,088 | 1,088 |

### Observations
- **Signature size decreases logarithmically** with $w$: each doubling of $w$ reduces the number of chains by roughly the number of bits per digit ($\log_2 w$), shrinking the signature accordingly.
- **Computation cost grows linearly** with $w$: each chain is $w-1$ hashes long, so doubling $w$ roughly doubles signing and verification time.
- **Sweet spot**: $w=16$ offers a good balance — signatures are 3.8× smaller than Lamport, and sign+verify is still under 0.6 ms.

## 2. MSS Height Sweep (h = 1 … 8)

Measured Merkle Signature Scheme with both Lamport and WOTS ($w=16$) leaves.

| Config | Leaves | KeyGen (ms) | Sign (ms) | Verify (ms) | Sig Size (B) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **h=1, Lamport** | 2 | 1.24 | 0.03 | 0.27 | 24,612 |
| **h=2, Lamport** | 4 | 2.49 | 0.04 | 0.27 | 24,644 |
| **h=3, Lamport** | 8 | 5.11 | 0.05 | 0.26 | 24,676 |
| **h=4, Lamport** | 16 | 10.04 | 0.05 | 0.28 | 24,708 |
| **h=5, Lamport** | 32 | 20.35 | 0.05 | 0.27 | 24,740 |
| **h=6, Lamport** | 64 | 41.65 | 0.05 | 0.27 | 24,772 |
| **h=7, Lamport** | 128 | 84.26 | 0.08 | 0.28 | 24,804 |
| **h=8, Lamport** | 256 | 174.39 | 0.10 | 0.30 | 24,836 |
| **h=1, WOTS w=16** | 2 | 1.15 | 0.31 | 0.30 | 4,324 |
| **h=2, WOTS w=16** | 4 | 2.30 | 0.30 | 0.30 | 4,356 |
| **h=3, WOTS w=16** | 8 | 4.49 | 0.29 | 0.29 | 4,388 |
| **h=4, WOTS w=16** | 16 | 9.08 | 0.30 | 0.30 | 4,420 |
| **h=5, WOTS w=16** | 32 | 18.28 | 0.30 | 0.31 | 4,452 |
| **h=6, WOTS w=16** | 64 | 36.31 | 0.32 | 0.30 | 4,484 |
| **h=7, WOTS w=16** | 128 | 72.30 | 0.30 | 0.30 | 4,516 |
| **h=8, WOTS w=16** | 256 | 144.46 | 0.31 | 0.30 | 4,548 |

### Observations
1. **KeyGen scales as $O(2^h)$**: doubling the tree height doubles the number of OTS keypairs to generate, confirmed by the near-perfect exponential growth on the log-scale plot.
2. **Sign and Verify are constant in $h$**: the $h$ extra SHA-256 hashes for the authentication path are negligible compared to the OTS work itself.
3. **Signature size grows by exactly 32 bytes per level**: each tree level adds one sibling hash (32 B for SHA-256). Going from $h=1$ to $h=8$ adds only 224 B — a tiny fraction of the OTS signature.
4. **WOTS leaves produce ~5.5× smaller signatures**: ~4.5 KB vs ~24.7 KB, consistent across all heights.

## 3. MSS w-Sweep (h = 4, WOTS)

Fixed tree height $h=4$ (16 leaves) and varied the Winternitz parameter.

| w | KeyGen (ms) | Sign (ms) | Verify (ms) | Sig Size (B) |
| :--- | :--- | :--- | :--- | :--- |
| **4** | 4.95 | 0.16 | 0.18 | 8,644 |
| **8** | 6.23 | 0.18 | 0.23 | 5,892 |
| **16** | 9.09 | 0.30 | 0.30 | 4,420 |
| **32** | 14.65 | 0.48 | 0.47 | 3,652 |
| **64** | 23.52 | 0.65 | 0.84 | 3,012 |
| **128** | 40.59 | 1.22 | 1.34 | 2,628 |
| **256** | 70.59 | 2.26 | 2.26 | 2,308 |

### Observations
- The trade-off is even more pronounced in the full MSS context because KeyGen must run $w$-length chains for all $2^h = 16$ leaves.
- Going from $w=4$ to $w=256$ shrinks signatures by 3.7× but increases total computation (sign+verify) by 13×.
- **Recommended parameter**: $w=16$ with $h=4$–$6$ offers the best practical balance: signatures under 4.5 KB, sign+verify under 0.6 ms, and keygen under 40 ms.

## 4. Parameter Tuning Summary

| Priority | Recommended Config | Sig Size | Sign+Verify | Messages |
| :--- | :--- | :--- | :--- | :--- |
| **Min signature size** | WOTS w=256, h=4 | 2,308 B | 4.52 ms | 16 |
| **Min computation** | Lamport, h=4 | 24,708 B | 0.33 ms | 16 |
| **Balanced** | WOTS w=16, h=5 | 4,452 B | 0.61 ms | 32 |
| **Max capacity** | WOTS w=16, h=8 | 4,548 B | 0.61 ms | 256 |
