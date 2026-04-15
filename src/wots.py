import math
from src.utils import get_hash, hash_n, generate_random_bytes

class WOTS:
    """
    Implements the Winternitz One-Time Signature (WOTS) scheme.
    """
    def __init__(self, w=16):
        self.w = w
        self.log_w = int(math.log2(w))
        self.block_size = 32 # 32 bytes (256 bits) for SHA-256
        
        # Calculate l1, l2, l
        # For SHA-256, m=256 bits
        m = 256
        self.l1 = math.ceil(m / self.log_w)
        self.l2 = math.floor(math.log2(self.l1 * (w - 1)) / self.log_w) + 1
        self.l = self.l1 + self.l2

    def _get_message_digits(self, message_hash):
        """
        Converts the message hash into base-w digits.
        """
        digits = []
        # Each byte contains 8/log_w digits (assuming log_w divides 8 or 8 divides log_w)
        # For simplicity, we'll convert the whole hash to a bitstream and then take log_w bits
        bitstream = ""
        for byte in message_hash:
            bitstream += bin(byte)[2:].zfill(8)
            
        for i in range(0, self.l1 * self.log_w, self.log_w):
            digits.append(int(bitstream[i:i+self.log_w], 2))
            
        return digits

    def _get_checksum_digits(self, message_digits):
        """
        Computes the checksum and converts it to base-w digits.
        """
        checksum = 0
        for d in message_digits:
            checksum += (self.w - 1 - d)
            
        # Convert checksum to l2 digits of base w
        checksum_digits = []
        for _ in range(self.l2):
            checksum_digits.append(checksum % self.w)
            checksum //= self.w
            
        # Checksum digits are usually appended in reverse (most significant first)
        return checksum_digits[::-1]

    def generate_keypair(self):
        """
        Generates a keypair.
        SK: l random 256-bit values.
        PK: Hashes of SK values chained w-1 times.
        """
        secret_key = [generate_random_bytes(self.block_size) for _ in range(self.l)]
        public_key = [hash_n(sk, self.w - 1) for sk in secret_key]
        return secret_key, public_key

    def sign(self, message, secret_key):
        """
        Signs a message.
        """
        msg_hash = get_hash(message)
        msg_digits = self._get_message_digits(msg_hash)
        checksum_digits = self._get_checksum_digits(msg_digits)
        all_digits = msg_digits + checksum_digits
        
        signature = []
        for i in range(self.l):
            signature.append(hash_n(secret_key[i], all_digits[i]))
            
        return signature

    def verify(self, message, signature, public_key):
        """
        Verifies a signature.
        """
        if len(signature) != self.l:
            return False
            
        msg_hash = get_hash(message)
        msg_digits = self._get_message_digits(msg_hash)
        checksum_digits = self._get_checksum_digits(msg_digits)
        all_digits = msg_digits + checksum_digits
        
        for i in range(self.l):
            # Compute remaining hash chain: (w - 1 - digit) steps
            remaining_steps = self.w - 1 - all_digits[i]
            verified_pk_part = hash_n(signature[i], remaining_steps)
            
            if verified_pk_part != public_key[i]:
                return False
                
        return True
