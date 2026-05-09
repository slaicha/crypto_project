"""
Winternitz One-Time Signature (WOTS) scheme.

Key idea (compared to Lamport):
    Instead of signing one bit at a time (Lamport), WOTS groups the hash
    into base-w digits and uses iterated hash chains. This dramatically
    reduces signature size at the cost of more hash computations.

    Example: with w=16, each digit encodes 4 bits (log2(16) = 4),
    so 256 bits need only 64 chains instead of Lamport's 256 pairs.

The checksum:
    Without a checksum, an attacker who sees a signature could forge a
    new one by INCREASING hash chain values (applying more hashes).
    The checksum prevents this: if any message digit decreases, the
    checksum digits must increase, which requires computing MORE hashes
    from the secret key — something only the signer can do.

Security assumption:
    Same as Lamport — preimage resistance of SHA-256.
"""

import math
from src.utils import get_hash, hash_n, generate_random_bytes

class WOTS:
    """
    Implements the Winternitz One-Time Signature (WOTS) scheme.
    """
    def __init__(self, w=16):
        self.w = w
        self.log_w = int(math.log2(w))   # Bits per digit (e.g., 4 for w=16)
        self.block_size = 32              # 32 bytes for SHA-256 output
        
        # --- Parameter computation (RFC 8391 / WOTS+ standard) ---
        # l1: number of chains for the message digits
        #     We need ceil(256 / log2(w)) digits to represent a 256-bit hash
        m = 256  # SHA-256 output length in bits
        self.l1 = math.ceil(m / self.log_w)
        
        # l2: number of chains for the checksum
        #     The maximum checksum value is l1 * (w-1), so we need enough
        #     base-w digits to represent it
        self.l2 = math.floor(math.log2(self.l1 * (w - 1)) / self.log_w) + 1
        
        # l = l1 + l2: total number of hash chains
        # This determines the signature size = l × 32 bytes
        self.l = self.l1 + self.l2

    def _get_message_digits(self, message_hash):
        """
        Splits the 256-bit message hash into l1 base-w digits.

        Example (w=16, log_w=4):
            Each byte → 2 digits (4 bits each)
            32 bytes → 64 digits  (= l1 = ceil(256/4))
        """
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
        """
        Computes the checksum and encodes it as l2 base-w digits.

        Checksum = sum(w - 1 - d_i) for all message digits d_i.

        Why this works:
            If an attacker tries to DECREASE a message digit (to forge a
            different message), the checksum INCREASES. But increasing a
            checksum digit means applying MORE hashes from the secret block,
            which requires knowledge of the secret key. This makes forgery
            infeasible.
        """
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
        """
        Generates a WOTS keypair.

        Secret Key: l random 32-byte blocks (one per chain).
        Public Key: PK[i] = H^{w-1}(SK[i])  — the END of each hash chain.

        Each chain is w-1 hashes long. Larger w → longer chains → slower
        keygen, but fewer chains → smaller signatures.
        """
        secret_key = [generate_random_bytes(self.block_size) for _ in range(self.l)]
        # Each public key element is the secret hashed (w-1) times
        public_key = [hash_n(sk, self.w - 1) for sk in secret_key]
        return secret_key, public_key

    def sign(self, message, secret_key):
        """
        Signs a message using WOTS.

        For each chain i with digit d_i:
            sig[i] = H^{d_i}(SK[i])  — hash the secret d_i times.

        The signature reveals an intermediate point on each hash chain.
        The verifier can then hash forward (w-1-d_i) more times to reach PK[i].
        """
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
        """
        Verifies a WOTS signature.

        For each chain i with digit d_i:
            Compute H^{w-1-d_i}(sig[i])  — hash the signature forward
            to the end of the chain.
            Check that it equals PK[i].

        This works because:
            H^{w-1-d_i}(sig[i]) = H^{w-1-d_i}(H^{d_i}(SK[i]))
                                 = H^{w-1}(SK[i])
                                 = PK[i]  ✓
        """
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
