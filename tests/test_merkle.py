"""
Tests for the Merkle Signature Scheme (Week 2).

Run with:
    pytest tests/test_merkle.py
"""

import sys
import os
import pytest

# Allow "from src...." imports when pytest is run from the project root.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.merkle import MerkleSignature


# ---------------------------------------------------------------------- #
# Correctness: a freshly signed message must verify.
# ---------------------------------------------------------------------- #
@pytest.mark.parametrize("ots_scheme,w", [("lamport", None), ("wots", 16)])
def test_sign_and_verify_single_message(ots_scheme, w):
    mss = MerkleSignature(height=3, ots_scheme=ots_scheme, w=w or 16)
    sk, pk = mss.generate_keypair()
    sig = mss.sign("hello world", sk)
    assert mss.verify("hello world", sig, pk) is True


# ---------------------------------------------------------------------- #
# Every leaf of the tree must produce an independently valid signature.
# ---------------------------------------------------------------------- #
def test_sign_all_leaves():
    mss = MerkleSignature(height=3, ots_scheme="lamport")  # 8 leaves
    sk, pk = mss.generate_keypair()
    for i in range(mss.num_leaves):
        sig = mss.sign(f"message #{i}", sk)
        assert sig["leaf_index"] == i
        assert mss.verify(f"message #{i}", sig, pk) is True


# ---------------------------------------------------------------------- #
# Signing more messages than leaves must fail cleanly.
# ---------------------------------------------------------------------- #
def test_exhaustion_raises():
    mss = MerkleSignature(height=2, ots_scheme="lamport")  # 4 leaves
    sk, _ = mss.generate_keypair()
    for i in range(4):
        mss.sign(f"m{i}", sk)
    with pytest.raises(RuntimeError):
        mss.sign("one too many", sk)


# ---------------------------------------------------------------------- #
# Tampering with the message must cause verification to fail.
# ---------------------------------------------------------------------- #
def test_wrong_message_rejected():
    mss = MerkleSignature(height=2, ots_scheme="wots", w=16)
    sk, pk = mss.generate_keypair()
    sig = mss.sign("original", sk)
    assert mss.verify("tampered", sig, pk) is False


# ---------------------------------------------------------------------- #
# Tampering with the auth path must cause verification to fail.
# ---------------------------------------------------------------------- #
def test_bad_auth_path_rejected():
    mss = MerkleSignature(height=3, ots_scheme="lamport")
    sk, pk = mss.generate_keypair()
    sig = mss.sign("hi", sk)
    # Corrupt one sibling hash in the auth path.
    sig["auth_path"][0] = b"\x00" * 32
    assert mss.verify("hi", sig, pk) is False


# ---------------------------------------------------------------------- #
# A signature produced under a different root must not verify.
# ---------------------------------------------------------------------- #
def test_wrong_root_rejected():
    mss = MerkleSignature(height=2, ots_scheme="lamport")
    sk_a, _ = mss.generate_keypair()
    _, pk_b = mss.generate_keypair()                     # different tree, different root
    sig = mss.sign("hello", sk_a)
    assert mss.verify("hello", sig, pk_b) is False
