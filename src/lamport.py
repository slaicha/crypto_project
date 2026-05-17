"""Lamport One-Time Signature (OTS) scheme using SHA-256."""

from src.utils import get_hash, generate_random_bytes, bytes_to_bits

class LamportOTS:
    """Implements the Lamport One-Time Signature scheme."""
    def __init__(self):
        self.sk_size = 256
        self.block_size = 32

    def generate_keypair(self):
        """Generates a Lamport keypair (Secret Key and Public Key)."""
        secret_key = []
        public_key = []
        
        for _ in range(self.sk_size):
            sk_0 = generate_random_bytes(self.block_size)
            sk_1 = generate_random_bytes(self.block_size)
            
            secret_key.append((sk_0, sk_1))
            public_key.append((get_hash(sk_0), get_hash(sk_1)))
            
        return secret_key, public_key

    def sign(self, message, secret_key):
        """Signs a message by selectively revealing secret blocks."""
        msg_hash = get_hash(message)
        bits = bytes_to_bits(msg_hash)
        
        signature = []
        for i in range(self.sk_size):
            if bits[i] == 0:
                signature.append(secret_key[i][0])
            else:
                signature.append(secret_key[i][1])
                
        return signature

    def verify(self, message, signature, public_key):
        """Verifies a Lamport signature."""
        if len(signature) != self.sk_size:
            return False
            
        msg_hash = get_hash(message)
        bits = bytes_to_bits(msg_hash)
        
        for i in range(self.sk_size):
            signed_block_hash = get_hash(signature[i])
            expected_pk_hash = public_key[i][0] if bits[i] == 0 else public_key[i][1]
            
            if signed_block_hash != expected_pk_hash:
                return False
                
        return True
