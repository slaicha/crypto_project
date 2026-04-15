from src.utils import get_hash, generate_random_bytes, bytes_to_bits

class LamportOTS:
    """
    Implements the Lamport One-Time Signature scheme using SHA-256.
    """
    def __init__(self):
        self.sk_size = 256  # 256 bits in the hash
        self.block_size = 32 # 32 bytes (256 bits) for each SK block

    def generate_keypair(self):
        """
        Generates a keypair.
        SK: 256 pairs of 32-byte random values.
        PK: Hashes of the SK values.
        """
        secret_key = []
        public_key = []
        
        for _ in range(self.sk_size):
            # Each bit of the hash has two secret values
            sk_0 = generate_random_bytes(self.block_size)
            sk_1 = generate_random_bytes(self.block_size)
            
            secret_key.append((sk_0, sk_1))
            public_key.append((get_hash(sk_0), get_hash(sk_1)))
            
        return secret_key, public_key

    def sign(self, message, secret_key):
        """
        Signs a message.
        message: The data to be signed (can be string or bytes).
        Returns: A list of 256 blocks (each 32 bytes).
        """
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
        """
        Verifies a signature.
        """
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
