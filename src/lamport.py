"""
Lamport One-Time Signature (OTS) scheme using SHA-256.

Security assumption:
    The scheme is secure as long as SHA-256 is preimage-resistant, i.e.,
    given H(x), it is computationally infeasible to find x.

Key insight:
    Each bit of the message hash is "signed" independently by revealing
    one of two secret blocks. The verifier checks that hashing the
    revealed block yields the corresponding public key entry.

Limitation:
    Strictly ONE-TIME. Reusing the same key leaks additional secret blocks,
    eventually enabling forgery (see security_simulation.py).
"""

from src.utils import get_hash, generate_random_bytes, bytes_to_bits

class LamportOTS:
    """
    Implements the Lamport One-Time Signature scheme using SHA-256.
    """
    def __init__(self):
        self.sk_size = 256  # SHA-256 produces a 256-bit hash
        self.block_size = 32 # Each secret block is 32 bytes (256 bits)

    def generate_keypair(self):
        """
        Generates a Lamport keypair.

        Secret Key (SK):
            A 256×2 matrix of random 32-byte blocks.
            SK[i] = (sk_0, sk_1) — one block for bit=0, one for bit=1.

        Public Key (PK):
            PK[i] = (H(sk_0), H(sk_1)) — the hash of each secret block.
            Publishing PK is safe because H is one-way: knowing H(x)
            does not reveal x.

        Total sizes:
            SK = 256 × 2 × 32 = 16,384 bytes
            PK = 256 × 2 × 32 = 16,384 bytes
        """
        secret_key = []
        public_key = []
        
        for _ in range(self.sk_size):
            # Generate two independent random blocks per bit position
            sk_0 = generate_random_bytes(self.block_size)
            sk_1 = generate_random_bytes(self.block_size)
            
            secret_key.append((sk_0, sk_1))
            # The public key is the hash image — safe to publish
            public_key.append((get_hash(sk_0), get_hash(sk_1)))
            
        return secret_key, public_key

    def sign(self, message, secret_key):
        """
        Signs a message by selectively revealing secret blocks.

        Process:
            1. Hash the message: h = H(message)  →  256-bit digest
            2. For each bit i of h:
               - If h[i] == 0, reveal SK[i][0]
               - If h[i] == 1, reveal SK[i][1]

        The signature is a list of 256 blocks (each 32 bytes).
        Note: signing does NOT compute any hashes on the secret blocks —
        it only selects and copies them. This is why Lamport signing
        is extremely fast (~0.03 ms).

        Signature size = 256 × 32 = 8,192 bytes
        """
        msg_hash = get_hash(message)
        bits = bytes_to_bits(msg_hash)
        
        signature = []
        for i in range(self.sk_size):
            # Reveal the secret block corresponding to this bit
            if bits[i] == 0:
                signature.append(secret_key[i][0])
            else:
                signature.append(secret_key[i][1])
                
        return signature

    def verify(self, message, signature, public_key):
        """
        Verifies a Lamport signature.

        Process:
            1. Hash the message to get the same 256-bit digest.
            2. For each bit i, hash the revealed block: H(sig[i])
            3. Compare against the expected PK entry:
               - If h[i] == 0, check H(sig[i]) == PK[i][0]
               - If h[i] == 1, check H(sig[i]) == PK[i][1]

        Why this is secure:
            An attacker who does NOT know SK[i][b] cannot produce a value
            that hashes to PK[i][b], because SHA-256 is preimage-resistant.
        """
        if len(signature) != self.sk_size:
            return False
            
        msg_hash = get_hash(message)
        bits = bytes_to_bits(msg_hash)
        
        for i in range(self.sk_size):
            # Hash the revealed block from the signature
            signed_block_hash = get_hash(signature[i])
            # Select the expected PK entry based on the message bit
            expected_pk_hash = public_key[i][0] if bits[i] == 0 else public_key[i][1]
            
            # If any block fails, the signature is invalid
            if signed_block_hash != expected_pk_hash:
                return False
                
        return True
