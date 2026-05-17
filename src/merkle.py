"""Merkle Signature Scheme (MSS)."""

from src.utils import get_hash
from src.lamport import LamportOTS
from src.wots import WOTS


def _serialize_ots_public_key(ots_pk):
    """Flatten an OTS public key into raw bytes so it can be hashed into a leaf."""
    buf = b"" #initialize an empty byte string to store the serialized public key
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
    """Hash two sibling nodes to produce their parent: H(left || right)."""
    return get_hash(left + right)


class MerkleSignature:
    """Merkle Signature Scheme built on top of a one-time signature (OTS) primitive."""

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
        """Generates an MSS keypair."""
        ots = self._new_ots()

        # Step 1: generate one OTS keypair per leaf
        ots_secret_keys = []
        ots_public_keys = []
        for _ in range(self.num_leaves):
            sk, pk = ots.generate_keypair()
            ots_secret_keys.append(sk)
            ots_public_keys.append(pk)

        # Step 2: compute the leaves (hash of each OTS public key)
        leaves = [_leaf_hash(pk) for pk in ots_public_keys]

        # Step 3: build the tree level by level (bottom-up)
        # tree[0] = leaves, tree[1] = their parents, ..., tree[height] = [root]
        tree = [leaves]
        current = leaves
        while len(current) > 1:
            parents = []
            for i in range(0, len(current), 2):
                parents.append(_parent_hash(current[i], current[i + 1]))
            tree.append(parents)
            current = parents

        root = tree[-1][0]  # The single node at the top

        secret_key = {
            "ots_secret_keys": ots_secret_keys,
            "ots_public_keys": ots_public_keys,
            "tree": tree,
            "next_leaf": 0,  # Tracks which leaf to use next (stateful!)
        }
        return secret_key, root

    # ------------------------------------------------------------------ #
    # Authentication path
    # ------------------------------------------------------------------ #
    def _auth_path(self, tree, leaf_index):
        """Computes the authentication path for the given leaf."""
        path = []
        index = leaf_index
        # Walk up from leaves (level 0) to just below the root
        for level in range(self.height):
            sibling_index = index ^ 1          # XOR with 1 flips the last bit → sibling
            path.append(tree[level][sibling_index])
            index >>= 1                        # Move to the parent's index
        return path

    # ------------------------------------------------------------------ #
    # Signing
    # ------------------------------------------------------------------ #
    def sign(self, message, secret_key):
        """Signs a message using the next unused leaf."""
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

        # Advance the state so this leaf is never reused
        secret_key["next_leaf"] = idx + 1
        return signature

    # ------------------------------------------------------------------ #
    # Verification
    # ------------------------------------------------------------------ #
    def verify(self, message, signature, public_key):
        """Verifies an MSS signature against the root (public_key)."""
        idx = signature["leaf_index"]
        if idx < 0 or idx >= self.num_leaves:
            return False
        if len(signature["auth_path"]) != self.height:
            return False

        # Check (a): verify the one-time signature
        ots = self._new_ots()
        if not ots.verify(message, signature["ots_signature"], signature["ots_public_key"]):
            return False

        # Check (b): reconstruct the root from the leaf upward
        node = _leaf_hash(signature["ots_public_key"])
        index = idx
        for sibling in signature["auth_path"]:
            if index % 2 == 0:
                # Current node is the left child
                node = _parent_hash(node, sibling)
            else:
                # Current node is the right child
                node = _parent_hash(sibling, node)
            index >>= 1

        # Final check: does the reconstructed root match the public key?
        return node == public_key
