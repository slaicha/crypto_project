import pytest
import sys
import os

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.lamport import LamportOTS
from src.wots import WOTS

def test_lamport_correctness():
    ots = LamportOTS()
    sk, pk = ots.generate_keypair()
    msg = "Test message"
    sig = ots.sign(msg, sk)
    assert ots.verify(msg, sig, pk) == True

def test_lamport_invalid_msg():
    ots = LamportOTS()
    sk, pk = ots.generate_keypair()
    msg = "Test message"
    sig = ots.sign(msg, sk)
    assert ots.verify("Wrong message", sig, pk) == False

def test_wots_correctness():
    for w in [4, 16, 256]:
        ots = WOTS(w=w)
        sk, pk = ots.generate_keypair()
        msg = "Test message"
        sig = ots.sign(msg, sk)
        assert ots.verify(msg, sig, pk) == True

def test_wots_invalid_msg():
    ots = WOTS(w=16)
    sk, pk = ots.generate_keypair()
    msg = "Test message"
    sig = ots.sign(msg, sk)
    assert ots.verify("Wrong message", sig, pk) == False

def test_wots_invalid_sig():
    ots = WOTS(w=16)
    sk, pk = ots.generate_keypair()
    msg = "Test message"
    sig = ots.sign(msg, sk)
    # Tamper with signature
    sig[0] = b'\x00' * 32
    assert ots.verify(msg, sig, pk) == False
