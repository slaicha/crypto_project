from src.lamport import LamportOTS
from src.utils import get_hash, bytes_to_bits

def simulate_key_reuse():
    """
    Simulates the reuse of a Lamport secret key and demonstrates a forgery.
    """
    ots = LamportOTS()
    sk, pk = ots.generate_keypair()
    
    # We will sign several random messages until we reveal enough SK blocks
    # to forge a specific target message.
    target_msg = "Retreat at noon"
    target_hash = get_hash(target_msg)
    target_bits = bytes_to_bits(target_hash)
    
    revealed_sk_0 = {} # i -> block
    revealed_sk_1 = {} # i -> block
    
    messages = [
        "Attack at dawn",
        "Attack at dusk",
        "Hold the line",
        "Advance south",
        "Regroup at base"
    ]
    # Add more random messages if necessary
    import random
    for i in range(15):
        messages.append(f"Random message {random.random()}")

    print(f"Signing {len(messages)} messages with the SAME key...")
    
    for msg in messages:
        sig = ots.sign(msg, sk)
        msg_bits = bytes_to_bits(get_hash(msg))
        for i in range(256):
            if msg_bits[i] == 0:
                revealed_sk_0[i] = sig[i]
            else:
                revealed_sk_1[i] = sig[i]
    
    # Attempt forgery
    forged_sig = []
    success = True
    for i in range(256):
        target_bit = target_bits[i]
        if target_bit == 0 and i in revealed_sk_0:
            forged_sig.append(revealed_sk_0[i])
        elif target_bit == 1 and i in revealed_sk_1:
            forged_sig.append(revealed_sk_1[i])
        else:
            success = False
            break
            
    if success:
        print(f"\nSUCCESS: Forged signature for '{target_msg}'!")
        verified = ots.verify(target_msg, forged_sig, pk)
        print(f"Verification of forged signature: {verified}")
    else:
        print(f"\nFAILURE: Could not forge signature for '{target_msg}'.")
        print(f"Blocks revealed: {len(revealed_sk_0)} zeroes, {len(revealed_sk_1)} ones.")

if __name__ == "__main__":
    simulate_key_reuse()
    
    # More systematic approach: how many messages are needed to forge an arbitrary message?
    # Each message reveals 256 secret blocks.
    # Probability that a specific block SK[i][j] is NOT revealed after k random messages is (1/2)^k.
    # Probability that at least one of the 256 required blocks is missing is 1 - (1 - (1/2)^k)^256.
    # For k=10, prob is ~22%. For k=15, prob is < 1%.
