"""
Merkle Signature Scheme (MSS) — lifts the one-time restriction.

Problem solved:
    Lamport and WOTS are ONE-TIME signature schemes: using a secret key
    more than once leaks secret material and enables forgery.
    The Merkle tree lets us aggregate many OTS keypairs under a single,
    reusable public key (the tree's root hash).

How it works:
    1. Choose a tree height h → the scheme can sign N = 2^h messages.
    2. Generate N independent OTS keypairs (Lamport or WOTS).
    3. Each leaf = H(OTS_public_key_i).
    4. Internal nodes = H(left_child || right_child).
    5. The MSS public key = the tree root (a single 32-byte hash).
    6. To sign the i-th message:
       - Sign with OTS keypair i
       - Include the "authentication path": h sibling hashes from leaf to root
    7. The verifier:
       - Verifies the OTS signature
       - Reconstructs the root using the auth path
       - Checks that the reconstructed root == the published public key

Key trade-off:
    - KeyGen is expensive: O(2^h) OTS keypairs must be generated upfront.
    - Sign/Verify are cheap: one OTS operation + h hashes (negligible).
    - Signature size grows by only 32 bytes per tree level.
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

        Steps:
            1. Generate 2^h independent OTS keypairs (the dominant cost).
            2. Hash each OTS public key → leaf node.
            3. Build the binary hash tree bottom-up:
               parent = H(left_child || right_child)
            4. The root of the tree is the MSS public key.

        Returns
        -------
        secret_key : dict
            Contains all OTS keys, the full tree, and a leaf counter.
        public_key : bytes
            The Merkle root (32 bytes for SHA-256).
        """
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
        """
        Compute the authentication path for the given leaf.

        The auth path is the list of SIBLING hashes needed to reconstruct
        the root from the leaf. One sibling per tree level (length = h).

        Example for h=3, leaf_index=5 (binary: 101):
            Level 0: sibling of node 5 is node 4  (flip last bit: 5^1=4)
            Level 1: sibling of node 2 is node 3  (5>>1=2, 2^1=3)
            Level 2: sibling of node 1 is node 0  (2>>1=1, 1^1=0)
        """
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
        """
        Sign a message using the next unused leaf.

        The signature contains four parts:
            1. leaf_index    — which leaf was used (so verifier knows the path)
            2. ots_public_key — the OTS public key at this leaf
            3. ots_signature  — the one-time signature of the message
            4. auth_path      — h sibling hashes from leaf to root

        State management:
            next_leaf is incremented after each signing to ensure no leaf
            is ever reused. Once all 2^h leaves are exhausted, signing
            raises a RuntimeError. This stateful tracking is what prevents
            the key-reuse vulnerability demonstrated in security_simulation.py.
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

        # Advance the state so this leaf is never reused
        secret_key["next_leaf"] = idx + 1
        return signature

    # ------------------------------------------------------------------ #
    # Verification
    # ------------------------------------------------------------------ #
    def verify(self, message, signature, public_key):
        """
        Verify an MSS signature against the root (public_key).

        Two independent checks must BOTH pass:

        Check (a) — OTS validity:
            Verify that the one-time signature is valid for the given
            OTS public key. This confirms the message was actually signed.

        Check (b) — Tree membership:
            Hash the OTS public key into a leaf, then walk UP the tree
            using the authentication path, combining with siblings at
            each level. If the reconstructed root matches the published
            public key, the leaf is authentic.

            Walk-up logic:
                If current index is EVEN → current node is LEFT child
                    parent = H(node || sibling)
                If current index is ODD  → current node is RIGHT child
                    parent = H(sibling || node)

        Why both checks are needed:
            (a) alone doesn't prove the OTS key belongs to this tree.
            (b) alone doesn't prove the message was signed correctly.
            Together, they guarantee: "this message was signed by a key
            that is part of the Merkle tree whose root I trust."
        """
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
