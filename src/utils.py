"""
Cryptographic utility functions used across all signature schemes.

All schemes in this project rely on these four primitives.
We use SHA-256 (hashlib) as the hash function and the 'secrets' module
for cryptographically secure randomness (backed by the OS's CSPRNG).
"""

import hashlib
import secrets


def get_hash(data):
    """
    Compute the SHA-256 hash of the input data.

    Accepts both str (auto-encoded to UTF-8) and bytes.
    Returns a 32-byte (256-bit) digest in raw bytes.

    This is the ONE-WAY function that all security proofs depend on:
    given get_hash(x), it must be infeasible to find x.
    """
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).digest()


def hash_n(data, n):
    """
    Apply SHA-256 iteratively n times:  H^n(data) = H(H(...H(data)...))

    Used by WOTS to walk along hash chains:
      - Signing:    sig[i] = H^{d_i}(SK[i])       (hash d_i times)
      - Verifying:  H^{w-1-d_i}(sig[i]) == PK[i]  (hash forward to chain end)

    When n=0, returns the data unchanged (identity, no hashing).
    """
    result = data
    for _ in range(n):
        result = get_hash(result)
    return result


def bytes_to_bits(data):
    """
    Convert raw bytes to a list of individual bits (MSB first per byte).

    Example: b'\\xa3' = 10100011 → [1, 0, 1, 0, 0, 0, 1, 1]

    Used by Lamport to determine which secret block to reveal per bit
    of the message hash.
    """
    bits = []
    for byte in data:
        for i in range(7, -1, -1):        # MSB first
            bits.append((byte >> i) & 1)
    return bits


def generate_random_bytes(n):
    """
    Generate n cryptographically secure random bytes.

    Uses Python's 'secrets' module, which is backed by the operating system's
    CSPRNG (/dev/urandom on Linux). This is essential for key generation —
    weak randomness would compromise the entire scheme.
    """
    return secrets.token_bytes(n)
