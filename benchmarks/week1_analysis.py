import time
import sys
import os

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.lamport import LamportOTS
from src.wots import WOTS

def measure_performance(scheme, name, message):
    print(f"--- Benchmarking {name} ---")
    
    # Key Generation
    start = time.time()
    sk, pk = scheme.generate_keypair()
    keygen_time = (time.time() - start) * 1000
    print(f"KeyGen: {keygen_time:.2f} ms")
    
    # Signing
    start = time.time()
    sig = scheme.sign(message, sk)
    sign_time = (time.time() - start) * 1000
    print(f"Sign: {sign_time:.2f} ms")
    
    # Verification
    start = time.time()
    verified = scheme.verify(message, sig, pk)
    verify_time = (time.time() - start) * 1000
    print(f"Verify: {verify_time:.2f} ms (Result: {verified})")
    
    # Signature Size
    # Sig is a list of blocks, each block is 32 bytes
    sig_size = len(sig) * 32
    print(f"Signature Size: {sig_size} bytes")
    print()
    
    return {
        "name": name,
        "keygen": keygen_time,
        "sign": sign_time,
        "verify": verify_time,
        "size": sig_size
    }

def run_benchmarks():
    message = "Post-Quantum Cryptography is exciting!"
    results = []
    
    # Lamport
    results.append(measure_performance(LamportOTS(), "Lamport", message))
    
    # WOTS w=4
    results.append(measure_performance(WOTS(w=4), "WOTS (w=4)", message))
    
    # WOTS w=16
    results.append(measure_performance(WOTS(w=16), "WOTS (w=16)", message))
    
    # WOTS w=256
    results.append(measure_performance(WOTS(w=256), "WOTS (w=256)", message))
    
    return results

if __name__ == "__main__":
    run_benchmarks()
