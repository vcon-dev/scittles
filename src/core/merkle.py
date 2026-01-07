import hashlib
import time
from typing import List, Optional
from opentelemetry import trace

from ..observability.logging import get_logger
from ..observability.metrics import get_metrics

logger = get_logger(__name__)
metrics = get_metrics()
tracer = trace.get_tracer(__name__)


class MerkleTree:
    """
    RFC 9162-compatible Merkle tree implementation.

    Uses SHA-256 hashing with domain separation for leaf and node hashes.
    """

    LEAF_PREFIX = b"\x00"
    NODE_PREFIX = b"\x01"

    @staticmethod
    def hash_leaf(data: bytes) -> bytes:
        """
        Hash a leaf node.

        RFC 9162: MTH({d[0]}) = SHA-256(0x00 || d[0])
        """
        return hashlib.sha256(MerkleTree.LEAF_PREFIX + data).digest()

    @staticmethod
    def hash_children(left: bytes, right: bytes) -> bytes:
        """
        Hash two child nodes.

        RFC 9162: MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
        """
        return hashlib.sha256(MerkleTree.NODE_PREFIX + left + right).digest()

    @staticmethod
    def calculate_root(leaves: List[bytes]) -> Optional[bytes]:
        """
        Calculate Merkle tree root hash from list of leaves.

        Args:
            leaves: List of leaf data (not pre-hashed)

        Returns:
            Root hash or None if no leaves
        """
        if not leaves:
            return None

        if len(leaves) == 1:
            return MerkleTree.hash_leaf(leaves[0])

        # Hash all leaves
        nodes = [MerkleTree.hash_leaf(leaf) for leaf in leaves]

        # Build tree bottom-up
        while len(nodes) > 1:
            next_level = []
            for i in range(0, len(nodes), 2):
                if i + 1 < len(nodes):
                    # Pair exists
                    parent = MerkleTree.hash_children(nodes[i], nodes[i + 1])
                else:
                    # Odd node, promote to next level
                    parent = nodes[i]
                next_level.append(parent)
            nodes = next_level

        return nodes[0]

    @staticmethod
    def generate_inclusion_proof(
        leaf_index: int, tree_size: int, leaves: List[bytes]
    ) -> List[bytes]:
        """
        Generate an inclusion proof for a leaf.

        Args:
            leaf_index: Index of the leaf to prove
            tree_size: Size of the tree when proof is generated
            leaves: All leaf data in the tree

        Returns:
            List of sibling hashes needed for proof verification
        """
        if leaf_index >= tree_size or tree_size > len(leaves):
            raise ValueError("Invalid leaf index or tree size")

        if tree_size == 1:
            return []  # No siblings needed

        # Hash all leaves up to tree_size
        nodes = [MerkleTree.hash_leaf(leaf) for leaf in leaves[:tree_size]]
        proof = []
        index = leaf_index

        # Collect sibling hashes while building tree
        while len(nodes) > 1:
            next_level = []
            for i in range(0, len(nodes), 2):
                if i + 1 < len(nodes):
                    # Pair exists
                    if i == index or i + 1 == index:
                        # This is our path, record sibling
                        if i == index:
                            proof.append(nodes[i + 1])
                        else:
                            proof.append(nodes[i])
                    parent = MerkleTree.hash_children(nodes[i], nodes[i + 1])
                else:
                    # Odd node
                    parent = nodes[i]
                next_level.append(parent)

            # Update index for next level
            index = index // 2
            nodes = next_level

        return proof

    @staticmethod
    def verify_inclusion_proof(
        leaf_hash: bytes,
        leaf_index: int,
        proof: List[bytes],
        tree_size: int,
        root_hash: bytes,
    ) -> bool:
        """
        Verify an inclusion proof.

        Args:
            leaf_hash: Hash of the leaf to verify
            leaf_index: Index of the leaf
            proof: List of sibling hashes
            tree_size: Size of the tree
            root_hash: Expected root hash

        Returns:
            True if proof is valid
        """
        if leaf_index >= tree_size:
            return False

        if tree_size == 1:
            return leaf_hash == root_hash and len(proof) == 0

        # Reconstruct path to root, handling incomplete trees per RFC 9162
        current_hash = leaf_hash
        current_index = leaf_index
        current_size = tree_size
        proof_idx = 0

        while current_size > 1:
            # Check if current node is a rightmost unpaired node (gets promoted)
            if current_index == current_size - 1 and current_size % 2 == 1:
                # This node gets promoted without a sibling
                # Don't consume a proof element, just update for next level
                current_index = current_index // 2
                current_size = (current_size + 1) // 2
                continue

            # Normal case: node has a sibling
            if proof_idx >= len(proof):
                return False  # Not enough proof elements

            sibling = proof[proof_idx]
            proof_idx += 1

            if current_index % 2 == 0:
                # Current node is left child
                current_hash = MerkleTree.hash_children(current_hash, sibling)
            else:
                # Current node is right child
                current_hash = MerkleTree.hash_children(sibling, current_hash)

            current_index = current_index // 2
            current_size = (current_size + 1) // 2

        return current_hash == root_hash and proof_idx == len(proof)


class MerkleTreeBuilder:
    """
    Incremental Merkle tree builder with storage backend.
    """

    def __init__(self, storage):
        self.storage = storage
        self._leaf_cache: List[bytes] = []

    async def add_leaf(self, leaf_data: bytes) -> int:
        """
        Add a leaf to the tree.

        Returns:
            Leaf index
        """
        start_time = time.time()

        with tracer.start_as_current_span("merkle.add_leaf") as span:
            try:
                leaf_index = len(self._leaf_cache)
                self._leaf_cache.append(leaf_data)

                # Calculate and store root for this tree size
                tree_size = leaf_index + 1
                root = MerkleTree.calculate_root(self._leaf_cache[:tree_size])

                span.set_attribute("merkle.leaf_index", leaf_index)
                span.set_attribute("merkle.tree_size", tree_size)

                if root:
                    await self.storage.store_merkle_node(tree_size, 0, root)

                duration = time.time() - start_time
                metrics.merkle_operation_duration.record(duration, {"operation": "add_leaf"})
                metrics.merkle_tree_size.add(1)

                logger.debug(
                    "merkle_leaf_added",
                    leaf_index=leaf_index,
                    tree_size=tree_size,
                    duration_seconds=duration,
                )

                return leaf_index

            except Exception as e:
                duration = time.time() - start_time
                span.record_exception(e)
                logger.exception(
                    "merkle_operation_failed",
                    operation="add_leaf",
                    error=str(e),
                )
                raise

    async def get_inclusion_proof(
        self, leaf_index: int, tree_size: Optional[int] = None
    ) -> List[bytes]:
        """
        Get inclusion proof for a leaf.

        Args:
            leaf_index: Index of leaf to prove
            tree_size: Size of tree (defaults to current size)

        Returns:
            Inclusion proof
        """
        start_time = time.time()

        with tracer.start_as_current_span("merkle.get_inclusion_proof") as span:
            span.set_attribute("merkle.leaf_index", leaf_index)

            try:
                if tree_size is None:
                    tree_size = len(self._leaf_cache)

                span.set_attribute("merkle.tree_size", tree_size)

                proof = MerkleTree.generate_inclusion_proof(
                    leaf_index, tree_size, self._leaf_cache
                )

                duration = time.time() - start_time
                metrics.merkle_operation_duration.record(
                    duration, {"operation": "get_inclusion_proof"}
                )
                metrics.merkle_proof_generation_count.add(1)
                span.set_attribute("merkle.proof_length", len(proof))

                logger.debug(
                    "merkle_proof_generated",
                    leaf_index=leaf_index,
                    tree_size=tree_size,
                    proof_length=len(proof),
                    duration_seconds=duration,
                )

                return proof

            except Exception as e:
                duration = time.time() - start_time
                span.record_exception(e)
                logger.exception(
                    "merkle_operation_failed",
                    operation="get_inclusion_proof",
                    leaf_index=leaf_index,
                    tree_size=tree_size,
                    error=str(e),
                )
                raise

    async def get_root(self, tree_size: Optional[int] = None) -> Optional[bytes]:
        """Get root hash for a specific tree size."""
        if tree_size is None:
            tree_size = len(self._leaf_cache)

        # Check storage first
        root = await self.storage.get_merkle_node(tree_size, 0)
        if root:
            return root

        # Calculate if not stored
        return MerkleTree.calculate_root(self._leaf_cache[:tree_size])
