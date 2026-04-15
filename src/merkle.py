"""
Merkle Signature Scheme (MSS) — Week 2 of the Hash-Based Signatures project.

Motivation
----------
Lamport and WOTS are ONE-TIME signature schemes: using a secret key more than once
leaks enough secret material to forge signatures (see `security_simulation.py`).
A Merkle tree lets us aggregate many one-time key pairs under a single, reusable
public key (the tree's root hash).

How it works
------------
1.  Choose a tree height `h`. The tree has N = 2**h leaves.
2.  Generate N independent OTS key pairs (Lamport or WOTS).
3.  Each leaf i is the hash of the i-th OTS public key.
4.  Internal nodes are hashes of the concatenation of their two children.
5.  The MSS public key is the tree root.
6.  To sign the i-th message:
        - sign it with the i-th OTS secret key, and
        - include the "authentication path": the h sibling hashes along the way
          from leaf i up to the root.
7.  To verify, the verifier
        - verifies the OTS signature against the OTS public key,
        - recomputes the leaf hash and walks up using the auth path,
        - checks that the reconstructed root equals the MSS public key.

Each leaf may be used AT MOST ONCE, so an MSS keypair can sign up to N messages.
This module is intentionally small and readable; performance tuning and larger
constructions (stateless SPHINCS+, hypertrees) come in Weeks 3 and 4.
"""

from src.utils import get_hash
from src.lamport import LamportOTS
from src.wots import WOTS


def _serialize_ots_public_key(ots_pk):
    """
    Flatten an OTS public key into raw bytes so it can be hashed into a leaf.

    - Lamport public keys are lists of (pk_0, pk_1) tuples of 32-byte hashes.
    - WOTS public keys are flat lists of 32-byte hashes.

    We concatenate all the bytes in order. The exact layout does not matter for
    security as long as the signer and verifier agree on it.
    """
    buf = b""
    for item in ots_pk:
        if isinstance(item, tuple):           # Lamport: (pk_0, pk_1)
            buf += item[0] + item[1]
        else:                                 # WOTS: raw 32-byte block
            buf += item
    return buf


def _leaf_hash(ots_pk):
    """Hash an OTS public key to produce a Merkle-tree leaf."""
    return get_hash(_serialize_ots_public_key(ots_pk))


def _parent_hash(left, right):
    """Hash two sibling nodes to produce their parent."""
    return get_hash(left + right)


class MerkleSignature:
    """
    Merkle Signature Scheme built on top of a one-time signature (OTS) primitive.

    Parameters
    ----------
    height : int
        Tree height. The scheme can sign up to 2**height messages.
    ots_scheme : str
        Which one-time signature to use at the leaves: "lamport" or "wots".
    w : int
        Winternitz parameter, only used when ots_scheme == "wots".
    """

    def __init__(self, height=4, ots_scheme="lamport", w=16):
        if height < 1:
            raise ValueError("height must be >= 1")
        if ots_scheme not in ("lamport", "wots"):
            raise ValueError("ots_scheme must be 'lamport' or 'wots'")

        self.height = height
        self.num_leaves = 1 << height          # 2**height
        self.ots_scheme = ots_scheme
        self.w = w

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _new_ots(self):
        """Create a fresh OTS instance of the chosen scheme."""
        if self.ots_scheme == "lamport":
            return LamportOTS()
        return WOTS(w=self.w)

    # ------------------------------------------------------------------ #
    # Key generation
    # ------------------------------------------------------------------ #
    def generate_keypair(self):
        """
        Generate an MSS keypair.

        Returns
        -------
        secret_key : dict
            {
                "ots_secret_keys"  : list of N OTS secret keys,
                "ots_public_keys"  : list of N OTS public keys,
                "tree"             : list of levels, level 0 = leaves, last = root,
                "next_leaf"        : next unused leaf index (starts at 0)
            }
        public_key : bytes
            The Merkle root (32 bytes for SHA-256).
        """
        ots = self._new_ots()

        # Step 1: generate one OTS keypair per leaf.
        ots_secret_keys = []
        ots_public_keys = []
        for _ in range(self.num_leaves):
            sk, pk = ots.generate_keypair()
            ots_secret_keys.append(sk)
            ots_public_keys.append(pk)

        # Step 2: compute the leaves (hash of each OTS public key).
        leaves = [_leaf_hash(pk) for pk in ots_public_keys]

        # Step 3: build the tree level by level.
        # tree[0] = leaves, tree[1] = their parents, ..., tree[height] = [root].
        tree = [leaves]
        current = leaves
        while len(current) > 1:
            parents = []
            for i in range(0, len(current), 2):
                parents.append(_parent_hash(current[i], current[i + 1]))
            tree.append(parents)
            current = parents

        root = tree[-1][0]

        secret_key = {
            "ots_secret_keys": ots_secret_keys,
            "ots_public_keys": ots_public_keys,
            "tree": tree,
            "next_leaf": 0,
        }
        return secret_key, root

    # ------------------------------------------------------------------ #
    # Authentication path
    # ------------------------------------------------------------------ #
    def _auth_path(self, tree, leaf_index):
        """
        Return the list of sibling hashes needed to reconstruct the root from
        the leaf at `leaf_index`. One sibling per tree level (length == height).
        """
        path = []
        index = leaf_index
        # Walk up from leaves (level 0) to just below the root.
        for level in range(self.height):
            sibling_index = index ^ 1          # flip the last bit -> sibling
            path.append(tree[level][sibling_index])
            index >>= 1                        # move to the parent's index
        return path

    # ------------------------------------------------------------------ #
    # Signing
    # ------------------------------------------------------------------ #
    def sign(self, message, secret_key):
        """
        Sign `message` using the next unused leaf.

        Returns
        -------
        signature : dict
            {
                "leaf_index" : int,            # which leaf was used
                "ots_public_key" : OTS pk,     # verifier needs this to check OTS sig
                "ots_signature"  : OTS sig,    # the one-time signature itself
                "auth_path"      : list[bytes] # sibling hashes, leaves -> root
            }
        """
        idx = secret_key["next_leaf"]
        if idx >= self.num_leaves:
            raise RuntimeError(
                f"Merkle keypair exhausted: already signed {self.num_leaves} messages."
            )

        ots = self._new_ots()
        ots_sig = ots.sign(message, secret_key["ots_secret_keys"][idx])

        signature = {
            "leaf_index": idx,
            "ots_public_key": secret_key["ots_public_keys"][idx],
            "ots_signature": ots_sig,
            "auth_path": self._auth_path(secret_key["tree"], idx),
        }

        # Advance the state so this leaf is never reused.
        secret_key["next_leaf"] = idx + 1
        return signature

    # ------------------------------------------------------------------ #
    # Verification
    # ------------------------------------------------------------------ #
    def verify(self, message, signature, public_key):
        """
        Verify an MSS signature against the root `public_key`.

        Two checks must both pass:
          (a) the OTS signature is valid for the embedded OTS public key;
          (b) hashing that OTS public key into a leaf and walking up the tree
              with the provided auth path yields the expected root.
        """
        idx = signature["leaf_index"]
        if idx < 0 or idx >= self.num_leaves:
            return False
        if len(signature["auth_path"]) != self.height:
            return False

        # (a) verify the one-time signature.
        ots = self._new_ots()
        if not ots.verify(message, signature["ots_signature"], signature["ots_public_key"]):
            return False

        # (b) reconstruct the root from the leaf upward.
        node = _leaf_hash(signature["ots_public_key"])
        index = idx
        for sibling in signature["auth_path"]:
            if index % 2 == 0:
                # current node is the left child
                node = _parent_hash(node, sibling)
            else:
                # current node is the right child
                node = _parent_hash(sibling, node)
            index >>= 1

        return node == public_key
