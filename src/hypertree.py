"""
Hypertree Signature Scheme — multi-layer Merkle aggregation.

Problem solved:
    A single Merkle tree of height h supports 2^h signatures, but KeyGen
    cost grows as O(2^h) because we must materialize every leaf upfront.
    For h = 16 (~65k signatures) this becomes minutes; for h = 20 (~1M
    signatures) it becomes hours. Our own benchmarks confirm this.

How a 2-layer hypertree fixes it:
    Use a TOP tree of height h_top whose leaves do NOT sign messages
    directly. Instead, each top-tree leaf "certifies" the public-key root
    of a BOTTOM tree of height h_bot. Messages are signed by the bottom
    tree, and the resulting signature is bundled with the top tree's
    certification of that bottom tree's root.

    Total signing capacity: 2^h_top * 2^h_bot = 2^(h_top + h_bot).
    KeyGen capacity boost: instead of O(2^h) up front, we only materialize
    the top tree (2^h_top leaves) plus ONE bottom tree on demand. With
    h_top = h_bot = h/2, that is roughly O(2 * 2^(h/2)) — a square-root
    speedup that turns hours into seconds.

Why this is the right Week-4 extension:
    - Plugs directly into the MerkleSignature class we already built.
    - Solves a problem our own Week-3 KeyGen plot exposes (O(2^h) blow-up).
    - This is exactly the construction SPHINCS+ / SLH-DSA uses internally.

Trade-offs:
    + KeyGen amortizes nicely (only top tree + first bottom tree upfront).
    + Same one-message-per-bottom-leaf safety as plain MSS.
    - Signature size doubles (we now carry two MSS signatures and two
      OTS public keys) — but it stays O(h_top + h_bot) hashes total.
    - Bottom trees must be regenerated when their leaves are exhausted.
      This is why real schemes (SPHINCS+) make leaf selection stateless,
      but for our 2-layer demonstration we keep it simple and stateful.
"""

from src.merkle import MerkleSignature


class Hypertree:
    """
    Two-layer hypertree built on top of MerkleSignature.

    Parameters
    ----------
    h_top : int
        Height of the top tree. Number of bottom trees = 2^h_top.
    h_bot : int
        Height of each bottom tree. Each bottom tree signs 2^h_bot messages.
    ots_scheme : str
        Which one-time signature to use at the bottom-tree leaves
        ("lamport" or "wots").
    w : int
        Winternitz parameter, only used when ots_scheme == "wots".

    Total signing capacity: 2^(h_top + h_bot) messages.
    """

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
        """
        Build the hypertree:
            1. Generate the TOP tree's keypair using MerkleSignature.
               Its leaves are independent OTS keypairs whose public keys
               will be used to sign bottom-tree roots.
            2. Generate the FIRST bottom tree (lazily) so we can start
               signing immediately. Subsequent bottom trees are created
               on demand inside sign().

        Returns
        -------
        secret_key : dict
            Holds the top-tree secret key, a list of bottom-tree slots
            (most starting as None and built lazily), and a global
            "next_index" counter for which message slot to use next.
        public_key : bytes
            The TOP tree's Merkle root — a single 32-byte hash that
            commits to all 2^(h_top + h_bot) signing slots.
        """
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
        """
        Generate a fresh bottom-tree keypair, then have the top tree sign
        its root. The top-tree signature acts as a certificate that this
        bottom-tree root is part of the overall hypertree.
        """
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
        """
        Sign a message using the next available slot.

        Layout of a global signature index `idx` (h_top + h_bot bits):
            high h_top bits → which BOTTOM TREE
            low  h_bot bits → which LEAF in that bottom tree

        If we move into a bottom tree that has not been built yet,
        we materialize it on demand (this is the lazy KeyGen win).

        The returned hypertree signature contains:
            - bottom_index           : which bottom tree was used
            - bottom_signature       : the MSS signature on `message`
            - bottom_root            : the public key (root) of that bottom tree
            - top_signature_on_root  : the top tree's MSS signature certifying
                                       that bottom_root is part of this hypertree
        """
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
        """
        Verify a hypertree signature.

        Three independent checks must all pass:

        Check (1) — Bottom-layer signature:
            The bottom tree's MSS signature must validate `message` under
            its bottom_root.

        Check (2) — Top-layer certification:
            The top tree's MSS signature must validate `bottom_root` under
            the hypertree's top_public_key (which is the published public key).

        Check (3) — Leaf-index consistency:
            The bottom_signature's leaf index must lie within the bottom tree,
            and the top_signature's leaf index must equal bottom_index.
            (This prevents an attacker from re-mixing valid pieces from
            different positions of the hypertree.)
        """
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
