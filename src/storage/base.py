from abc import ABC, abstractmethod
from typing import List, Optional, Tuple


class StorageBackend(ABC):
    """Abstract base class for storage backends."""

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the storage backend."""
        pass

    @abstractmethod
    async def append_entry(
        self,
        statement_hash: bytes,
        cose_sign1: bytes,
        issuer: Optional[str] = None,
        subject: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> int:
        """
        Append a new entry to the log.

        Args:
            statement_hash: Hash of the signed statement
            cose_sign1: COSE_Sign1 message bytes
            issuer: Issuer identifier
            subject: Subject identifier
            content_type: Content type of payload

        Returns:
            Leaf index of the new entry
        """
        pass

    @abstractmethod
    async def get_entry_by_hash(self, statement_hash: bytes) -> Optional[dict]:
        """Retrieve an entry by its statement hash."""
        pass

    @abstractmethod
    async def get_entry_by_index(self, leaf_index: int) -> Optional[dict]:
        """Retrieve an entry by its leaf index."""
        pass

    @abstractmethod
    async def get_tree_size(self) -> int:
        """Get current size of the Merkle tree."""
        pass

    @abstractmethod
    async def store_merkle_node(
        self, tree_size: int, position: int, node_hash: bytes
    ) -> None:
        """Store a Merkle tree node (legacy interface)."""
        pass

    @abstractmethod
    async def get_merkle_node(self, tree_size: int, position: int) -> Optional[bytes]:
        """Retrieve a Merkle tree node (legacy interface)."""
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close the storage backend."""
        pass

    # --- New methods for O(log n) Merkle tree ---

    async def store_tree_node(self, level: int, index: int, node_hash: bytes) -> None:
        """Store an internal Merkle tree node by (level, index)."""
        raise NotImplementedError

    async def get_tree_node(self, level: int, index: int) -> Optional[bytes]:
        """Retrieve an internal Merkle tree node by (level, index)."""
        raise NotImplementedError

    async def get_all_tree_nodes(self) -> List[Tuple[int, int, bytes]]:
        """Retrieve all internal Merkle tree nodes as (level, index, hash) tuples."""
        raise NotImplementedError

    async def store_frontier(self, frontier: List[bytes], tree_size: int) -> None:
        """Store the current Merkle frontier and tree size."""
        raise NotImplementedError

    async def get_frontier(self) -> Tuple[List[bytes], int]:
        """Retrieve the stored Merkle frontier and tree size. Returns ([], 0) if none."""
        raise NotImplementedError

    async def store_tree_nodes_batch(
        self, nodes: List[Tuple[int, int, bytes]]
    ) -> None:
        """Store multiple tree nodes in a single transaction. Default: call store_tree_node for each."""
        for level, index, node_hash in nodes:
            await self.store_tree_node(level, index, node_hash)
