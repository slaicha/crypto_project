import sys
import os

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.lamport import LamportOTS
from src.wots import WOTS

def run_tests():
    print("Running tests...")
    
    # Lamport
    ots = LamportOTS()
    sk, pk = ots.generate_keypair()
    msg = "Test message"
    sig = ots.sign(msg, sk)
    assert ots.verify(msg, sig, pk) == True
    assert ots.verify("Wrong", sig, pk) == False
    print("Lamport tests passed!")
    
    # WOTS
    for w in [4, 16, 256]:
        ots = WOTS(w=w)
        sk, pk = ots.generate_keypair()
        sig = ots.sign(msg, sk)
        assert ots.verify(msg, sig, pk) == True
        assert ots.verify("Wrong", sig, pk) == False
        print(f"WOTS (w={w}) tests passed!")
    
    print("All tests passed successfully!")

if __name__ == "__main__":
    try:
        run_tests()
    except AssertionError as e:
        print(f"Test failed!")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)
