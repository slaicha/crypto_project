"""Winternitz One-Time Signature (WOTS) scheme."""

import math
from src.utils import get_hash, hash_n, generate_random_bytes

class WOTS:
    """Implements the Winternitz One-Time Signature (WOTS) scheme."""
    def __init__(self, w=16):
        self.w = w
        self.log_w = int(math.log2(w))   # Bits per digit (e.g., 4 for w=16)
        self.block_size = 32              # 32 bytes for SHA-256 output
        
        m = 256
        self.l1 = math.ceil(m / self.log_w)
        self.l2 = math.floor(math.log2(self.l1 * (w - 1)) / self.log_w) + 1
        self.l = self.l1 + self.l2

    def _get_message_digits(self, message_hash):
        """Splits the 256-bit message hash into l1 base-w digits."""
        digits = []
        # Convert hash bytes into a continuous bitstream
        bitstream = ""
        for byte in message_hash:
            bitstream += bin(byte)[2:].zfill(8)
            
        # Extract l1 digits, each log_w bits wide
        for i in range(0, self.l1 * self.log_w, self.log_w):
            digits.append(int(bitstream[i:i+self.log_w], 2))
            
        return digits

    def _get_checksum_digits(self, message_digits):
        """Computes the checksum and encodes it as l2 base-w digits."""
        checksum = 0
        for d in message_digits:
            checksum += (self.w - 1 - d)

        # base conversion from decimal to base w    
        # Encode the checksum integer as l2 base-w digits
        checksum_digits = []
        for _ in range(self.l2):
            checksum_digits.append(checksum % self.w)
            checksum //= self.w
            
        # Reverse to get most-significant digit first
        return checksum_digits[::-1]

    def generate_keypair(self):
        """Generates a WOTS keypair."""
        secret_key = [generate_random_bytes(self.block_size) for _ in range(self.l)]
        # Each public key element is the secret hashed (w-1) times
        public_key = [hash_n(sk, self.w - 1) for sk in secret_key]
        return secret_key, public_key

    def sign(self, message, secret_key):
        """Signs a message using WOTS."""
        msg_hash = get_hash(message)
        msg_digits = self._get_message_digits(msg_hash)
        checksum_digits = self._get_checksum_digits(msg_digits)
        # Concatenate message digits + checksum digits (total = l digits)
        all_digits = msg_digits + checksum_digits
        
        signature = []
        for i in range(self.l):
            # Hash the secret block d_i times to produce the signature element
            signature.append(hash_n(secret_key[i], all_digits[i]))
            
        return signature

    def verify(self, message, signature, public_key):
        """Verifies a WOTS signature."""
        if len(signature) != self.l:
            return False
            
        msg_hash = get_hash(message)
        msg_digits = self._get_message_digits(msg_hash)
        checksum_digits = self._get_checksum_digits(msg_digits)
        all_digits = msg_digits + checksum_digits
        
        for i in range(self.l):
            # Complete the hash chain: apply the remaining (w-1-d_i) hashes
            remaining_steps = self.w - 1 - all_digits[i]
            verified_pk_part = hash_n(signature[i], remaining_steps)
            
            if verified_pk_part != public_key[i]:
                return False
                
        return True
