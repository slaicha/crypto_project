import hashlib
import secrets

def get_hash(data):
    """Computes SHA-256 hash of data."""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).digest()

def hash_n(data, n):
    """Applies SHA-256 hash n times."""
    result = data
    for _ in range(n):
        result = get_hash(result)
    return result

def bytes_to_bits(data):
    """Converts bytes to a list of bits."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def generate_random_bytes(n):
    """Generates n cryptographically secure random bytes."""
    return secrets.token_bytes(n)
