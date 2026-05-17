"""
Hypertree Signature Scheme — multi-layer Merkle aggregation.

Uses a top tree to certify bottom trees, lazily building bottom trees
on demand. This square-root reduction turns KeyGen time from O(2^h)
to O(2 * 2^(h/2)).
"""

from src.merkle import MerkleSignature


class Hypertree:
    """Two-layer hypertree built on top of MerkleSignature."""

    def __init__(self, h_top=4, h_bot=4, ots_scheme="wots", w=16):
        if h_top < 1 or h_bot < 1:
            raise ValueError("both h_top and h_bot must be >= 1")
        self.h_top = h_top
        self.h_bot = h_bot
        self.ots_scheme = ots_scheme
        self.w = w
        # Signing scratch (set by generate_keypair)
        self.num_bottom_trees = 1 << h_top
        self.total_capacity = 1 << (h_top + h_bot)

    # ------------------------------------------------------------------ #
    # Key generation
    # ------------------------------------------------------------------ #
    def generate_keypair(self):
        """Generates the hypertree keypair."""
        # 1) Top tree: each top leaf will sign one bottom-tree's root.
        top = MerkleSignature(height=self.h_top, ots_scheme=self.ots_scheme, w=self.w)
        top_sk, top_root = top.generate_keypair()

        # 2) Pre-allocate slots for bottom trees; build them lazily.
        bottom_slots = [None] * self.num_bottom_trees

        # Build the first bottom tree so the keypair is immediately usable.
        first_bottom_sk, first_bottom_root, first_top_sig = self._build_bottom(
            top, top_sk, bottom_index=0
        )
        bottom_slots[0] = {
            "secret_key": first_bottom_sk,
            "root": first_bottom_root,
            "top_signature": first_top_sig,  # certifies this bottom tree's root
        }

        secret_key = {
            "top_scheme": top,
            "top_secret_key": top_sk,
            "top_public_key": top_root,
            "bottom_slots": bottom_slots,
            "next_index": 0,  # global index in [0, 2^(h_top+h_bot))
        }
        return secret_key, top_root

    # ------------------------------------------------------------------ #
    # Internal: build one bottom tree and have the top tree certify it
    # ------------------------------------------------------------------ #
    def _build_bottom(self, top, top_sk, bottom_index):
        """Generates a bottom-tree keypair and has the top tree sign its root."""
        bottom = MerkleSignature(
            height=self.h_bot, ots_scheme=self.ots_scheme, w=self.w
        )
        bot_sk, bot_root = bottom.generate_keypair()

        # The top tree signs the bottom tree's root.
        # Each top-tree leaf is used exactly once for exactly one bottom tree.
        top_sig = top.sign(bot_root, top_sk)

        return bot_sk, bot_root, top_sig

    # ------------------------------------------------------------------ #
    # Signing
    # ------------------------------------------------------------------ #
    def sign(self, message, secret_key):
        """Signs a message using the next available slot."""
        idx = secret_key["next_index"]
        if idx >= self.total_capacity:
            raise RuntimeError(
                f"Hypertree exhausted: already signed {self.total_capacity} messages."
            )

        bottom_index = idx >> self.h_bot          # high bits → which bottom tree
        # leaf_in_bottom = idx & ((1 << self.h_bot) - 1)  # low bits — used internally by MSS

        # Lazily build the bottom tree if we have not yet.
        slot = secret_key["bottom_slots"][bottom_index]
        if slot is None:
            bot_sk, bot_root, top_sig = self._build_bottom(
                secret_key["top_scheme"],
                secret_key["top_secret_key"],
                bottom_index,
            )
            slot = {
                "secret_key": bot_sk,
                "root": bot_root,
                "top_signature": top_sig,
            }
            secret_key["bottom_slots"][bottom_index] = slot

        # Sign the message with this bottom tree (it will use its own next_leaf).
        bottom_scheme = MerkleSignature(
            height=self.h_bot, ots_scheme=self.ots_scheme, w=self.w
        )
        bottom_sig = bottom_scheme.sign(message, slot["secret_key"])

        secret_key["next_index"] = idx + 1

        return {
            "bottom_index": bottom_index,
            "bottom_signature": bottom_sig,
            "bottom_root": slot["root"],
            "top_signature_on_root": slot["top_signature"],
        }

    # ------------------------------------------------------------------ #
    # Verification
    # ------------------------------------------------------------------ #
    def verify(self, message, signature, public_key):
        """Verifies a hypertree signature against the global public key."""
        bottom_index = signature["bottom_index"]
        if bottom_index < 0 or bottom_index >= self.num_bottom_trees:
            return False

        # Check (3a): the top-tree certificate must point to this bottom_index.
        if signature["top_signature_on_root"]["leaf_index"] != bottom_index:
            return False

        # Check (1): bottom-tree signature on the user's message.
        bottom_scheme = MerkleSignature(
            height=self.h_bot, ots_scheme=self.ots_scheme, w=self.w
        )
        if not bottom_scheme.verify(
            message, signature["bottom_signature"], signature["bottom_root"]
        ):
            return False

        # Check (2): top-tree signature on the bottom_root, under the public key.
        top_scheme = MerkleSignature(
            height=self.h_top, ots_scheme=self.ots_scheme, w=self.w
        )
        if not top_scheme.verify(
            signature["bottom_root"], signature["top_signature_on_root"], public_key
        ):
            return False

        return True
