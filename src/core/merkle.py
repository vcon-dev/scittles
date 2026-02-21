import hashlib
import time
from typing import Dict, List, Optional, Tuple
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
    O(log n) incremental Merkle tree builder using the compact range / frontier algorithm.

    Maintains:
    - _frontier: List[bytes] — O(log n) perfect subtree roots (right-to-left merge)
    - _nodes: Dict[(level, index), bytes] — internal nodes from add_leaf (complete subtrees only)
    - _tree_size: int — number of leaves added

    Each add_leaf() does O(log n) hash operations. Each get_inclusion_proof() does
    O(log n) node lookups with occasional recursive computation for edge nodes in
    non-power-of-2 trees. This replaces the previous O(n) implementation.
    """

    def __init__(self, storage=None):
        self.storage = storage
        self._frontier: List[bytes] = []
        self._nodes: Dict[Tuple[int, int], bytes] = {}
        self._tree_size: int = 0

    async def warm_up(self) -> None:
        """
        Rebuild in-memory state from storage on startup.
        Loads frontier + all tree nodes from DB.
        """
        if not self.storage:
            return

        with tracer.start_as_current_span("merkle.warm_up") as span:
            try:
                frontier, tree_size = await self.storage.get_frontier()
                if tree_size > 0:
                    self._frontier = frontier
                    self._tree_size = tree_size

                    # Load all persisted nodes
                    all_nodes = await self.storage.get_all_tree_nodes()
                    for level, index, node_hash in all_nodes:
                        self._nodes[(level, index)] = node_hash

                    span.set_attribute("merkle.tree_size", tree_size)
                    span.set_attribute("merkle.nodes_loaded", len(self._nodes))
                    span.set_attribute("merkle.frontier_size", len(self._frontier))

                    logger.info(
                        "merkle_warm_up_complete",
                        tree_size=tree_size,
                        nodes_loaded=len(self._nodes),
                        frontier_size=len(self._frontier),
                    )
                else:
                    # No frontier stored — check if there's a tree_size in service_state
                    db_tree_size = await self.storage.get_tree_size()
                    if db_tree_size > 0:
                        logger.info(
                            "merkle_warm_up_rebuilding",
                            tree_size=db_tree_size,
                        )
                        await self._rebuild_from_entries(db_tree_size)
                        span.set_attribute("merkle.rebuilt", True)
                        span.set_attribute("merkle.tree_size", self._tree_size)

            except NotImplementedError:
                # Storage doesn't support new methods — fall back to entry rebuild
                db_tree_size = await self.storage.get_tree_size()
                if db_tree_size > 0:
                    await self._rebuild_from_entries(db_tree_size)
            except Exception as e:
                logger.exception("merkle_warm_up_failed", error=str(e))
                raise

    async def _rebuild_from_entries(self, tree_size: int) -> None:
        """Rebuild the Merkle tree incrementally from stored entries."""
        for i in range(tree_size):
            entry = await self.storage.get_entry_by_index(i)
            if entry:
                self._add_leaf_internal(entry["statement_hash"])

        # Persist the rebuilt state
        try:
            await self.persist_all_nodes()
        except NotImplementedError:
            pass

        logger.info(
            "merkle_rebuild_complete",
            tree_size=self._tree_size,
            nodes=len(self._nodes),
        )

    def _add_leaf_internal(self, leaf_data: bytes) -> int:
        """
        Add a leaf to the tree (in-memory only, no storage I/O).

        Uses the compact range / frontier algorithm:
        1. Hash the leaf
        2. Store it as a level-0 node
        3. Merge with frontier right-to-left where trailing bits of (index+1) are set

        Returns the leaf index.
        """
        leaf_index = self._tree_size
        leaf_hash = MerkleTree.hash_leaf(leaf_data)

        # Store leaf node at level 0
        self._nodes[(0, leaf_index)] = leaf_hash

        # Merge into frontier
        current = leaf_hash
        level = 0
        idx = leaf_index

        # Number of merges = number of trailing 1-bits in (leaf_index + 1)
        n = leaf_index + 1
        while n % 2 == 0:
            # Pop the last frontier entry (left sibling) and merge
            left = self._frontier.pop()
            sibling_idx = idx - 1
            level += 1
            parent_idx = sibling_idx // 2
            current = MerkleTree.hash_children(left, current)
            self._nodes[(level, parent_idx)] = current
            idx = parent_idx
            n = n // 2

        self._frontier.append(current)
        self._tree_size = leaf_index + 1

        return leaf_index

    async def add_leaf(self, leaf_data: bytes) -> int:
        """
        Add a leaf to the tree with storage persistence.

        Returns:
            Leaf index
        """
        start_time = time.time()

        with tracer.start_as_current_span("merkle.add_leaf") as span:
            try:
                leaf_index = self._add_leaf_internal(leaf_data)
                tree_size = self._tree_size

                span.set_attribute("merkle.leaf_index", leaf_index)
                span.set_attribute("merkle.tree_size", tree_size)

                # Persist frontier
                if self.storage:
                    try:
                        await self.storage.store_frontier(
                            list(self._frontier), self._tree_size
                        )
                    except NotImplementedError:
                        pass

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

    async def persist_all_nodes(self) -> None:
        """Persist all in-memory nodes to storage (for migration/rebuild)."""
        if not self.storage:
            return

        nodes = [(level, idx, h) for (level, idx), h in self._nodes.items()]
        try:
            await self.storage.store_tree_nodes_batch(nodes)
            await self.storage.store_frontier(list(self._frontier), self._tree_size)
        except NotImplementedError:
            pass

    def _level_size(self, level: int, tree_size: int) -> int:
        """Compute the number of nodes at a given level in the pairwise tree."""
        n = tree_size
        for _ in range(level):
            n = (n + 1) // 2
        return n

    def _node_hash_at(self, level: int, position: int, tree_size: int) -> bytes:
        """
        Compute hash of a node at (level, position) in the pairwise reference tree.

        For nodes stored during add_leaf (complete perfect subtrees), this is a direct
        dict lookup. For edge nodes in non-power-of-2 trees that include promoted
        children, this recursively computes the hash from stored descendants.

        The recursion depth is O(log n) and only follows promotion chains (no hashing)
        for promoted nodes, so practical cost is O(log n) lookups per call.
        """
        # Fast path: stored node
        stored = self._nodes.get((level, position))
        if stored is not None:
            return stored

        if level == 0:
            raise ValueError(f"Leaf node (0, {position}) not found")

        # Compute from children at level-1
        child_level_size = self._level_size(level - 1, tree_size)
        left_idx = 2 * position
        right_idx = 2 * position + 1

        left = self._node_hash_at(level - 1, left_idx, tree_size)

        if right_idx < child_level_size:
            right = self._node_hash_at(level - 1, right_idx, tree_size)
            return MerkleTree.hash_children(left, right)
        else:
            # Right child doesn't exist — left is promoted
            return left

    def get_inclusion_proof_sync(
        self, leaf_index: int, tree_size: Optional[int] = None
    ) -> List[bytes]:
        """
        Generate inclusion proof using stored nodes — O(log n) with O(log n) hash ops
        for edge nodes in non-power-of-2 trees.

        Walks from the leaf level to the root, collecting sibling hashes. Uses
        _node_hash_at() which recursively computes edge nodes not directly stored.
        """
        if tree_size is None:
            tree_size = self._tree_size

        if leaf_index >= tree_size:
            raise ValueError(f"Invalid leaf index {leaf_index} for tree size {tree_size}")

        if tree_size == 1:
            return []

        proof = []
        current_index = leaf_index
        current_size = tree_size
        level = 0

        while current_size > 1:
            # Rightmost unpaired node — promoted without a sibling
            if current_index == current_size - 1 and current_size % 2 == 1:
                current_index = current_index // 2
                current_size = (current_size + 1) // 2
                level += 1
                continue

            # Determine sibling index
            if current_index % 2 == 0:
                sibling_index = current_index + 1
            else:
                sibling_index = current_index - 1

            # Look up sibling hash (may recurse for edge nodes)
            sibling_hash = self._node_hash_at(level, sibling_index, tree_size)
            proof.append(sibling_hash)

            current_index = current_index // 2
            current_size = (current_size + 1) // 2
            level += 1

        return proof

    async def get_inclusion_proof(
        self, leaf_index: int, tree_size: Optional[int] = None
    ) -> List[bytes]:
        """
        Get inclusion proof for a leaf — O(log n).

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
                    tree_size = self._tree_size

                span.set_attribute("merkle.tree_size", tree_size)

                proof = self.get_inclusion_proof_sync(leaf_index, tree_size)

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

    def get_root_sync(self, tree_size: Optional[int] = None) -> Optional[bytes]:
        """
        Compute root hash from frontier — O(log n).

        Hashes frontier entries right-to-left to produce the root.
        """
        if tree_size is not None and tree_size != self._tree_size:
            # For a historical tree size, compute from nodes
            return self._compute_root_for_size(tree_size)

        if self._tree_size == 0:
            return None

        if len(self._frontier) == 0:
            return None

        # Hash frontier right-to-left
        result = self._frontier[-1]
        for i in range(len(self._frontier) - 2, -1, -1):
            result = MerkleTree.hash_children(self._frontier[i], result)

        return result

    def _compute_root_for_size(self, tree_size: int) -> Optional[bytes]:
        """Compute root for a specific tree size using _node_hash_at."""
        if tree_size == 0:
            return None
        if tree_size == 1:
            return self._nodes.get((0, 0))

        # Find the root level
        level = 0
        size = tree_size
        while size > 1:
            level += 1
            size = (size + 1) // 2

        return self._node_hash_at(level, 0, tree_size)

    async def get_root(self, tree_size: Optional[int] = None) -> Optional[bytes]:
        """Get root hash for a specific tree size."""
        return self.get_root_sync(tree_size)
