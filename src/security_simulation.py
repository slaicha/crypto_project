"""
Lamport Key-Reuse Attack Demonstration.

This script shows WHY Lamport OTS must only be used once.
It demonstrates a complete forgery by signing 20 messages with the same key
and then forging a signature on a message the signer never signed.

The attack:
    Each Lamport signature reveals 256 secret blocks (one per hash bit).
    With random messages, each block is revealed with probability 1/2 per
    signing. After k signings, the probability that a specific block
    remains hidden is (1/2)^k.

    To forge a signature on a target message, the attacker needs all 256
    blocks selected by the target's hash bits. The forgery probability is:

        P_forge(k) = (1 - 2^{-k})^256

    k=8  → ~37%  chance of forgery
    k=10 → ~78%  chance of forgery
    k=15 → ~99.8% chance of forgery
    k=20 → effectively 100%

    This is a PASSIVE attack: the attacker only observes legitimate
    signatures and does not interact with the signer at all.
"""

from src.lamport import LamportOTS
from src.utils import get_hash, bytes_to_bits

def simulate_key_reuse():
    """
    Simulates the reuse of a Lamport secret key and demonstrates a forgery.
    """
    ots = LamportOTS()
    sk, pk = ots.generate_keypair()
    
    # --- Target message: the attacker wants to forge a signature for this ---
    target_msg = "Retreat at noon"
    target_hash = get_hash(target_msg)
    target_bits = bytes_to_bits(target_hash)
    
    # --- Accumulator: collect revealed secret blocks from observed signatures ---
    # As the attacker observes each legitimate signature, they record
    # which SK[i][0] and SK[i][1] blocks have been revealed.
    revealed_sk_0 = {} # i -> SK[i][0] block (revealed when message bit i = 0)
    revealed_sk_1 = {} # i -> SK[i][1] block (revealed when message bit i = 1)
    
    # Prepare 20 messages to be legitimately signed (simulating reuse)
    messages = [
        "Attack at dawn",
        "Attack at dusk",
        "Hold the line",
        "Advance south",
        "Regroup at base"
    ]
    import random
    for i in range(15):
        messages.append(f"Random message {random.random()}")

    print(f"Signing {len(messages)} messages with the SAME key...")
    
    # --- Phase 1: observe signatures and accumulate secret blocks ---
    for msg in messages:
        sig = ots.sign(msg, sk)
        msg_bits = bytes_to_bits(get_hash(msg))
        for i in range(256):
            # Each signature reveals one block per position:
            # if bit = 0, we learn SK[i][0]; if bit = 1, we learn SK[i][1]
            if msg_bits[i] == 0:
                revealed_sk_0[i] = sig[i]
            else:
                revealed_sk_1[i] = sig[i]
    
    # --- Phase 2: attempt to forge a signature on the target ---
    # For each bit position of the target hash, check if the attacker
    # has the required secret block from the observed signatures.
    forged_sig = []
    success = True
    for i in range(256):
        target_bit = target_bits[i]
        if target_bit == 0 and i in revealed_sk_0:
            forged_sig.append(revealed_sk_0[i])
        elif target_bit == 1 and i in revealed_sk_1:
            forged_sig.append(revealed_sk_1[i])
        else:
            # Missing block — forgery fails for this target
            success = False
            break
            
    if success:
        print(f"\nSUCCESS: Forged signature for '{target_msg}'!")
        # Use the LEGITIMATE verifier to confirm — this should return True
        verified = ots.verify(target_msg, forged_sig, pk)
        print(f"Verification of forged signature: {verified}")
    else:
        print(f"\nFAILURE: Could not forge signature for '{target_msg}'.")
        print(f"Blocks revealed: {len(revealed_sk_0)} zeroes, {len(revealed_sk_1)} ones.")

if __name__ == "__main__":
    simulate_key_reuse()
