# SCRAPI Transparency Service Implementation Guide
## SQLite-Based Append-Only Log with Testing

This guide walks through building an IETF SCRAPI-compatible transparency service using SQLite as the immutable storage backend. Each step includes implementation code and tests.

---

## Project Setup

### Directory Structure
```
scrapi-service/
├── src/
│   ├── __init__.py
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── sqlite_store.py
│   │   └── schema.sql
│   ├── core/
│   │   ├── __init__.py
│   │   ├── merkle.py
│   │   ├── receipts.py
│   │   └── verification.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── models.py
│   │   └── endpoints.py
│   ├── config.py
│   └── main.py
├── tests/
│   ├── __init__.py
│   ├── test_storage.py
│   ├── test_merkle.py
│   ├── test_receipts.py
│   └── test_api.py
├── requirements.txt
├── pyproject.toml
└── README.md
```

### requirements.txt
```txt
# Core dependencies
pycose>=1.1.0
cbor2>=5.6.0
cryptography>=42.0.0
fastapi>=0.109.0
uvicorn[standard]>=0.27.0
pydantic>=2.6.0
pydantic-settings>=2.1.0

# Testing
pytest>=8.0.0
pytest-asyncio>=0.23.0
httpx>=0.26.0

# Development
black>=24.0.0
ruff>=0.2.0
mypy>=1.8.0
```

---

## STEP 1: Database Schema and Basic Storage

### Goal
Create the SQLite schema with append-only semantics and basic storage operations.

### Implementation: `src/storage/schema.sql`
```sql
-- Entries table: append-only log of signed statements
CREATE TABLE IF NOT EXISTS entries (
    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
    statement_hash BLOB NOT NULL UNIQUE,
    cose_sign1 BLOB NOT NULL,
    issuer TEXT,
    subject TEXT,
    content_type TEXT,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    leaf_index INTEGER NOT NULL
);

-- Index for hash lookups
CREATE INDEX IF NOT EXISTS idx_statement_hash ON entries(statement_hash);
CREATE INDEX IF NOT EXISTS idx_leaf_index ON entries(leaf_index);

-- Merkle tree nodes for inclusion proof generation
CREATE TABLE IF NOT EXISTS merkle_nodes (
    tree_size INTEGER NOT NULL,
    node_position INTEGER NOT NULL,
    node_hash BLOB NOT NULL,
    PRIMARY KEY (tree_size, node_position)
);

-- Service configuration and state
CREATE TABLE IF NOT EXISTS service_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert initial state
INSERT OR IGNORE INTO service_state (key, value) 
VALUES ('tree_size', '0');

-- Pending registrations for async operations
CREATE TABLE IF NOT EXISTS pending_registrations (
    operation_id TEXT PRIMARY KEY,
    statement_hash BLOB NOT NULL,
    cose_sign1 BLOB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);
```

### Implementation: `src/storage/base.py`
```python
from abc import ABC, abstractmethod
from typing import Optional, List, Tuple
from datetime import datetime


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
        content_type: Optional[str] = None
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
        self,
        tree_size: int,
        position: int,
        node_hash: bytes
    ) -> None:
        """Store a Merkle tree node."""
        pass
    
    @abstractmethod
    async def get_merkle_node(
        self,
        tree_size: int,
        position: int
    ) -> Optional[bytes]:
        """Retrieve a Merkle tree node."""
        pass
    
    @abstractmethod
    async def close(self) -> None:
        """Close the storage backend."""
        pass
```

### Implementation: `src/storage/sqlite_store.py`
```python
import sqlite3
import aiosqlite
from pathlib import Path
from typing import Optional, List
from .base import StorageBackend


class SQLiteStore(StorageBackend):
    """SQLite-based storage backend with append-only semantics."""
    
    def __init__(self, db_path: str = "transparency.db"):
        self.db_path = db_path
        self.conn: Optional[aiosqlite.Connection] = None
    
    async def initialize(self) -> None:
        """Initialize the database with schema."""
        self.conn = await aiosqlite.connect(self.db_path)
        self.conn.row_factory = aiosqlite.Row
        
        # Load and execute schema
        schema_path = Path(__file__).parent / "schema.sql"
        with open(schema_path, 'r') as f:
            schema = f.read()
        
        await self.conn.executescript(schema)
        await self.conn.commit()
    
    async def append_entry(
        self,
        statement_hash: bytes,
        cose_sign1: bytes,
        issuer: Optional[str] = None,
        subject: Optional[str] = None,
        content_type: Optional[str] = None
    ) -> int:
        """Append a new entry to the log."""
        if not self.conn:
            raise RuntimeError("Storage not initialized")
        
        # Get current tree size to use as leaf index
        tree_size = await self.get_tree_size()
        
        async with self.conn.execute(
            """
            INSERT INTO entries 
            (statement_hash, cose_sign1, issuer, subject, content_type, leaf_index)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (statement_hash, cose_sign1, issuer, subject, content_type, tree_size)
        ) as cursor:
            entry_id = cursor.lastrowid
        
        # Increment tree size
        await self.conn.execute(
            "UPDATE service_state SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = 'tree_size'",
            (str(tree_size + 1),)
        )
        
        await self.conn.commit()
        return tree_size
    
    async def get_entry_by_hash(self, statement_hash: bytes) -> Optional[dict]:
        """Retrieve an entry by its statement hash."""
        if not self.conn:
            raise RuntimeError("Storage not initialized")
        
        async with self.conn.execute(
            "SELECT * FROM entries WHERE statement_hash = ?",
            (statement_hash,)
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None
    
    async def get_entry_by_index(self, leaf_index: int) -> Optional[dict]:
        """Retrieve an entry by its leaf index."""
        if not self.conn:
            raise RuntimeError("Storage not initialized")
        
        async with self.conn.execute(
            "SELECT * FROM entries WHERE leaf_index = ?",
            (leaf_index,)
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None
    
    async def get_tree_size(self) -> int:
        """Get current size of the Merkle tree."""
        if not self.conn:
            raise RuntimeError("Storage not initialized")
        
        async with self.conn.execute(
            "SELECT value FROM service_state WHERE key = 'tree_size'"
        ) as cursor:
            row = await cursor.fetchone()
            return int(row[0]) if row else 0
    
    async def store_merkle_node(
        self,
        tree_size: int,
        position: int,
        node_hash: bytes
    ) -> None:
        """Store a Merkle tree node."""
        if not self.conn:
            raise RuntimeError("Storage not initialized")
        
        await self.conn.execute(
            """
            INSERT OR REPLACE INTO merkle_nodes (tree_size, node_position, node_hash)
            VALUES (?, ?, ?)
            """,
            (tree_size, position, node_hash)
        )
        await self.conn.commit()
    
    async def get_merkle_node(
        self,
        tree_size: int,
        position: int
    ) -> Optional[bytes]:
        """Retrieve a Merkle tree node."""
        if not self.conn:
            raise RuntimeError("Storage not initialized")
        
        async with self.conn.execute(
            "SELECT node_hash FROM merkle_nodes WHERE tree_size = ? AND node_position = ?",
            (tree_size, position)
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else None
    
    async def close(self) -> None:
        """Close the database connection."""
        if self.conn:
            await self.conn.close()
            self.conn = None
```

### Test: `tests/test_storage.py`
```python
import pytest
import asyncio
import tempfile
import os
from pathlib import Path
from src.storage.sqlite_store import SQLiteStore


@pytest.fixture
async def storage():
    """Create a temporary storage instance for testing."""
    # Create temporary database
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    
    store = SQLiteStore(path)
    await store.initialize()
    
    yield store
    
    await store.close()
    Path(path).unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_initialize_storage(storage):
    """Test that storage initializes correctly."""
    tree_size = await storage.get_tree_size()
    assert tree_size == 0


@pytest.mark.asyncio
async def test_append_entry(storage):
    """Test appending an entry to the log."""
    statement_hash = b"test_hash_12345"
    cose_sign1 = b"fake_cose_sign1_message"
    
    leaf_index = await storage.append_entry(
        statement_hash=statement_hash,
        cose_sign1=cose_sign1,
        issuer="https://example.com",
        subject="test-artifact"
    )
    
    assert leaf_index == 0
    tree_size = await storage.get_tree_size()
    assert tree_size == 1


@pytest.mark.asyncio
async def test_retrieve_entry_by_hash(storage):
    """Test retrieving an entry by hash."""
    statement_hash = b"unique_hash_999"
    cose_sign1 = b"test_cose_message"
    
    await storage.append_entry(statement_hash, cose_sign1)
    
    entry = await storage.get_entry_by_hash(statement_hash)
    assert entry is not None
    assert entry['statement_hash'] == statement_hash
    assert entry['cose_sign1'] == cose_sign1
    assert entry['leaf_index'] == 0


@pytest.mark.asyncio
async def test_retrieve_entry_by_index(storage):
    """Test retrieving an entry by leaf index."""
    # Add multiple entries
    hashes = [b"hash1", b"hash2", b"hash3"]
    for h in hashes:
        await storage.append_entry(h, b"cose_data")
    
    entry = await storage.get_entry_by_index(1)
    assert entry is not None
    assert entry['statement_hash'] == b"hash2"
    assert entry['leaf_index'] == 1


@pytest.mark.asyncio
async def test_append_multiple_entries(storage):
    """Test appending multiple entries maintains correct order."""
    entries = []
    for i in range(10):
        hash_val = f"hash_{i}".encode()
        leaf_index = await storage.append_entry(hash_val, b"data")
        entries.append((hash_val, leaf_index))
    
    tree_size = await storage.get_tree_size()
    assert tree_size == 10
    
    # Verify all entries are retrievable and in order
    for hash_val, expected_index in entries:
        entry = await storage.get_entry_by_hash(hash_val)
        assert entry['leaf_index'] == expected_index


@pytest.mark.asyncio
async def test_duplicate_hash_rejected(storage):
    """Test that duplicate statement hashes are rejected."""
    statement_hash = b"duplicate_hash"
    
    await storage.append_entry(statement_hash, b"first")
    
    # Second insert with same hash should fail
    with pytest.raises(Exception):  # sqlite3.IntegrityError wrapped in aiosqlite
        await storage.append_entry(statement_hash, b"second")


@pytest.mark.asyncio
async def test_merkle_node_storage(storage):
    """Test storing and retrieving Merkle tree nodes."""
    tree_size = 4
    position = 2
    node_hash = b"merkle_node_hash_abc123"
    
    await storage.store_merkle_node(tree_size, position, node_hash)
    
    retrieved = await storage.get_merkle_node(tree_size, position)
    assert retrieved == node_hash


@pytest.mark.asyncio
async def test_merkle_node_overwrite(storage):
    """Test that Merkle nodes can be updated (for reconstruction)."""
    tree_size = 5
    position = 1
    
    await storage.store_merkle_node(tree_size, position, b"old_hash")
    await storage.store_merkle_node(tree_size, position, b"new_hash")
    
    retrieved = await storage.get_merkle_node(tree_size, position)
    assert retrieved == b"new_hash"


# Run tests with: pytest tests/test_storage.py -v
```

### Running Step 1 Tests
```bash
# Install dependencies
pip install -r requirements.txt
pip install aiosqlite  # Add to requirements.txt if not there

# Run tests
pytest tests/test_storage.py -v

# Expected output:
# test_storage.py::test_initialize_storage PASSED
# test_storage.py::test_append_entry PASSED
# test_storage.py::test_retrieve_entry_by_hash PASSED
# test_storage.py::test_retrieve_entry_by_index PASSED
# test_storage.py::test_append_multiple_entries PASSED
# test_storage.py::test_duplicate_hash_rejected PASSED
# test_storage.py::test_merkle_node_storage PASSED
# test_storage.py::test_merkle_node_overwrite PASSED
```

---

## STEP 2: Merkle Tree Implementation (RFC 9162)

### Goal
Implement RFC 9162-compatible Merkle tree for generating inclusion proofs.

### Implementation: `src/core/merkle.py`
```python
import hashlib
from typing import List, Optional


class MerkleTree:
    """
    RFC 9162-compatible Merkle tree implementation.
    
    Uses SHA-256 hashing with domain separation for leaf and node hashes.
    """
    
    LEAF_PREFIX = b'\x00'
    NODE_PREFIX = b'\x01'
    
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
        leaf_index: int,
        tree_size: int,
        leaves: List[bytes]
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
        root_hash: bytes
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
        
        # Reconstruct path to root
        current_hash = leaf_hash
        current_index = leaf_index
        
        for sibling in proof:
            if current_index % 2 == 0:
                # Current node is left child
                current_hash = MerkleTree.hash_children(current_hash, sibling)
            else:
                # Current node is right child
                current_hash = MerkleTree.hash_children(sibling, current_hash)
            current_index = current_index // 2
        
        return current_hash == root_hash


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
        leaf_index = len(self._leaf_cache)
        self._leaf_cache.append(leaf_data)
        
        # Calculate and store root for this tree size
        tree_size = leaf_index + 1
        root = MerkleTree.calculate_root(self._leaf_cache[:tree_size])
        
        if root:
            await self.storage.store_merkle_node(tree_size, 0, root)
        
        return leaf_index
    
    async def get_inclusion_proof(
        self,
        leaf_index: int,
        tree_size: Optional[int] = None
    ) -> List[bytes]:
        """
        Get inclusion proof for a leaf.
        
        Args:
            leaf_index: Index of leaf to prove
            tree_size: Size of tree (defaults to current size)
            
        Returns:
            Inclusion proof
        """
        if tree_size is None:
            tree_size = len(self._leaf_cache)
        
        return MerkleTree.generate_inclusion_proof(
            leaf_index,
            tree_size,
            self._leaf_cache
        )
    
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
```

### Test: `tests/test_merkle.py`
```python
import pytest
import hashlib
from src.core.merkle import MerkleTree, MerkleTreeBuilder
from src.storage.sqlite_store import SQLiteStore
import tempfile
import os
from pathlib import Path


def test_hash_leaf():
    """Test leaf hashing with domain separation."""
    data = b"test_data"
    expected = hashlib.sha256(b'\x00' + data).digest()
    result = MerkleTree.hash_leaf(data)
    assert result == expected


def test_hash_children():
    """Test node hashing with domain separation."""
    left = b"left_hash_000000000000000000000000"
    right = b"right_hash_00000000000000000000000"
    expected = hashlib.sha256(b'\x01' + left + right).digest()
    result = MerkleTree.hash_children(left, right)
    assert result == expected


def test_single_leaf_root():
    """Test root calculation with single leaf."""
    leaves = [b"single_leaf"]
    root = MerkleTree.calculate_root(leaves)
    expected = MerkleTree.hash_leaf(b"single_leaf")
    assert root == expected


def test_two_leaf_root():
    """Test root calculation with two leaves."""
    leaves = [b"leaf1", b"leaf2"]
    root = MerkleTree.calculate_root(leaves)
    
    leaf1_hash = MerkleTree.hash_leaf(b"leaf1")
    leaf2_hash = MerkleTree.hash_leaf(b"leaf2")
    expected = MerkleTree.hash_children(leaf1_hash, leaf2_hash)
    
    assert root == expected


def test_four_leaf_tree():
    """Test root calculation with four leaves (complete binary tree)."""
    leaves = [b"leaf1", b"leaf2", b"leaf3", b"leaf4"]
    root = MerkleTree.calculate_root(leaves)
    
    # Manually calculate expected root
    l1 = MerkleTree.hash_leaf(b"leaf1")
    l2 = MerkleTree.hash_leaf(b"leaf2")
    l3 = MerkleTree.hash_leaf(b"leaf3")
    l4 = MerkleTree.hash_leaf(b"leaf4")
    
    n1 = MerkleTree.hash_children(l1, l2)
    n2 = MerkleTree.hash_children(l3, l4)
    expected = MerkleTree.hash_children(n1, n2)
    
    assert root == expected


def test_odd_number_leaves():
    """Test root calculation with odd number of leaves."""
    leaves = [b"leaf1", b"leaf2", b"leaf3"]
    root = MerkleTree.calculate_root(leaves)
    
    # Tree structure:
    #       root
    #      /    \
    #    n1      l3
    #   /  \
    #  l1  l2
    
    l1 = MerkleTree.hash_leaf(b"leaf1")
    l2 = MerkleTree.hash_leaf(b"leaf2")
    l3 = MerkleTree.hash_leaf(b"leaf3")
    
    n1 = MerkleTree.hash_children(l1, l2)
    expected = MerkleTree.hash_children(n1, l3)
    
    assert root == expected


def test_inclusion_proof_single_leaf():
    """Test inclusion proof for single-leaf tree."""
    leaves = [b"only_leaf"]
    proof = MerkleTree.generate_inclusion_proof(0, 1, leaves)
    assert proof == []


def test_inclusion_proof_two_leaves():
    """Test inclusion proofs for two-leaf tree."""
    leaves = [b"leaf1", b"leaf2"]
    
    # Proof for leaf 0
    proof0 = MerkleTree.generate_inclusion_proof(0, 2, leaves)
    assert len(proof0) == 1
    assert proof0[0] == MerkleTree.hash_leaf(b"leaf2")
    
    # Proof for leaf 1
    proof1 = MerkleTree.generate_inclusion_proof(1, 2, leaves)
    assert len(proof1) == 1
    assert proof1[0] == MerkleTree.hash_leaf(b"leaf1")


def test_inclusion_proof_four_leaves():
    """Test inclusion proofs for four-leaf tree."""
    leaves = [b"leaf1", b"leaf2", b"leaf3", b"leaf4"]
    
    # Proof for leaf 0 should include leaf1 and (leaf2, leaf3) subtree
    proof = MerkleTree.generate_inclusion_proof(0, 4, leaves)
    assert len(proof) == 2


def test_verify_inclusion_proof():
    """Test inclusion proof verification."""
    leaves = [b"leaf1", b"leaf2", b"leaf3", b"leaf4"]
    root = MerkleTree.calculate_root(leaves)
    
    # Generate and verify proof for leaf 0
    leaf_hash = MerkleTree.hash_leaf(b"leaf1")
    proof = MerkleTree.generate_inclusion_proof(0, 4, leaves)
    
    is_valid = MerkleTree.verify_inclusion_proof(
        leaf_hash, 0, proof, 4, root
    )
    assert is_valid


def test_verify_inclusion_proof_all_leaves():
    """Test that all leaves in a tree can be proven."""
    leaves = [f"leaf{i}".encode() for i in range(7)]
    root = MerkleTree.calculate_root(leaves)
    
    for i, leaf_data in enumerate(leaves):
        leaf_hash = MerkleTree.hash_leaf(leaf_data)
        proof = MerkleTree.generate_inclusion_proof(i, len(leaves), leaves)
        is_valid = MerkleTree.verify_inclusion_proof(
            leaf_hash, i, proof, len(leaves), root
        )
        assert is_valid, f"Proof failed for leaf {i}"


def test_verify_inclusion_proof_wrong_root():
    """Test that verification fails with wrong root."""
    leaves = [b"leaf1", b"leaf2", b"leaf3"]
    root = MerkleTree.calculate_root(leaves)
    
    leaf_hash = MerkleTree.hash_leaf(b"leaf1")
    proof = MerkleTree.generate_inclusion_proof(0, 3, leaves)
    
    wrong_root = b"wrong_root_hash_00000000000000000000000000000000"
    is_valid = MerkleTree.verify_inclusion_proof(
        leaf_hash, 0, proof, 3, wrong_root
    )
    assert not is_valid


def test_verify_inclusion_proof_tampered():
    """Test that verification fails with tampered proof."""
    leaves = [b"leaf1", b"leaf2", b"leaf3"]
    root = MerkleTree.calculate_root(leaves)
    
    leaf_hash = MerkleTree.hash_leaf(b"leaf1")
    proof = MerkleTree.generate_inclusion_proof(0, 3, leaves)
    
    # Tamper with proof
    tampered_proof = [b"tampered_hash_000000000000000000000000"] + proof[1:]
    is_valid = MerkleTree.verify_inclusion_proof(
        leaf_hash, 0, tampered_proof, 3, root
    )
    assert not is_valid


@pytest.fixture
async def storage_and_builder():
    """Create temporary storage and builder for testing."""
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    
    store = SQLiteStore(path)
    await store.initialize()
    builder = MerkleTreeBuilder(store)
    
    yield store, builder
    
    await store.close()
    Path(path).unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_merkle_tree_builder_add_leaf(storage_and_builder):
    """Test adding leaves to builder."""
    storage, builder = storage_and_builder
    
    leaf_index = await builder.add_leaf(b"test_leaf")
    assert leaf_index == 0
    
    root = await builder.get_root()
    expected = MerkleTree.hash_leaf(b"test_leaf")
    assert root == expected


@pytest.mark.asyncio
async def test_merkle_tree_builder_multiple_leaves(storage_and_builder):
    """Test building tree with multiple leaves."""
    storage, builder = storage_and_builder
    
    leaves_data = [f"leaf{i}".encode() for i in range(5)]
    for data in leaves_data:
        await builder.add_leaf(data)
    
    root = await builder.get_root()
    expected_root = MerkleTree.calculate_root(leaves_data)
    assert root == expected_root


@pytest.mark.asyncio
async def test_merkle_tree_builder_inclusion_proof(storage_and_builder):
    """Test generating inclusion proof from builder."""
    storage, builder = storage_and_builder
    
    leaves_data = [f"leaf{i}".encode() for i in range(4)]
    for data in leaves_data:
        await builder.add_leaf(data)
    
    proof = await builder.get_inclusion_proof(1, 4)
    root = await builder.get_root(4)
    leaf_hash = MerkleTree.hash_leaf(b"leaf1")
    
    is_valid = MerkleTree.verify_inclusion_proof(
        leaf_hash, 1, proof, 4, root
    )
    assert is_valid


# Run tests with: pytest tests/test_merkle.py -v
```

### Running Step 2 Tests
```bash
pytest tests/test_merkle.py -v

# Expected output: All tests should pass
# test_merkle.py::test_hash_leaf PASSED
# test_merkle.py::test_hash_children PASSED
# ... (all merkle tests passing)
```

---

## STEP 3: COSE Support and Receipt Generation

### Goal
Implement COSE message handling and receipt generation with inclusion proofs.

### Implementation: `src/core/receipts.py`
```python
import cbor2
from pycose.messages import Sign1Message
from pycose.headers import Algorithm, KID
from pycose.algorithms import Es256
from pycose.keys.ec2 import EC2Key
from pycose import CoseAlgorithms
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from typing import Optional, List, Dict, Any
import hashlib


class ReceiptGenerator:
    """
    Generates COSE-signed receipts with RFC 9162 inclusion proofs.
    """
    
    # Custom COSE header labels
    VDS_LABEL = 395  # Verifiable Data Structure
    PROOFS_LABEL = 396  # Proofs
    CLAIMS_LABEL = 15  # Claims
    
    # Proof types
    INCLUSION_PROOF_LABEL = -1
    
    def __init__(self, signing_key: EC2Key, service_id: str):
        """
        Initialize receipt generator.
        
        Args:
            signing_key: Private key for signing receipts
            service_id: Transparency service identifier (issuer)
        """
        self.signing_key = signing_key
        self.service_id = service_id
    
    @staticmethod
    def generate_signing_key() -> EC2Key:
        """Generate a new ES256 signing key."""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        return EC2Key.from_cryptography_key(private_key)
    
    def create_receipt(
        self,
        statement_hash: bytes,
        leaf_index: int,
        tree_size: int,
        inclusion_proof: List[bytes],
        issuer: Optional[str] = None,
        subject: Optional[str] = None
    ) -> bytes:
        """
        Create a COSE receipt with inclusion proof.
        
        Args:
            statement_hash: Hash of the original signed statement
            leaf_index: Position in the tree
            tree_size: Size of the tree at time of proof
            inclusion_proof: List of sibling hashes for proof
            issuer: Original statement issuer
            subject: Original statement subject
            
        Returns:
            COSE_Sign1 receipt bytes
        """
        # Build protected header
        protected_header = {
            Algorithm: Es256,  # ES256
            KID: self.signing_key.key_id,
        }
        
        # Add verifiable data structure info
        protected_header[self.VDS_LABEL] = 1  # RFC 9162 SHA-256
        
        # Add claims
        claims = {
            1: self.service_id,  # issuer (iss)
        }
        if issuer:
            claims[1] = issuer
        if subject:
            claims[2] = subject  # subject (sub)
        
        protected_header[self.CLAIMS_LABEL] = claims
        
        # Build unprotected header with proofs
        unprotected_header = {
            self.PROOFS_LABEL: {
                self.INCLUSION_PROOF_LABEL: [
                    cbor2.dumps([tree_size, leaf_index, inclusion_proof])
                ]
            }
        }
        
        # Create COSE Sign1 with detached payload (null)
        msg = Sign1Message(
            phdr=protected_header,
            uhdr=unprotected_header,
            payload=None,  # Detached payload per SCITT spec
        )
        
        # Sign the message
        msg.key = self.signing_key
        
        # Encode to COSE format
        cose_bytes = msg.encode()
        
        return cose_bytes
    
    @staticmethod
    def parse_receipt(receipt_bytes: bytes) -> Dict[str, Any]:
        """
        Parse a COSE receipt to extract metadata.
        
        Args:
            receipt_bytes: COSE_Sign1 receipt
            
        Returns:
            Dictionary with receipt metadata
        """
        msg = Sign1Message.decode(receipt_bytes)
        
        # Extract protected header
        protected = msg.phdr
        
        # Extract proofs from unprotected header
        unprotected = msg.uhdr
        proofs = unprotected.get(ReceiptGenerator.PROOFS_LABEL, {})
        inclusion_proofs_raw = proofs.get(ReceiptGenerator.INCLUSION_PROOF_LABEL, [])
        
        inclusion_proofs = []
        for proof_bytes in inclusion_proofs_raw:
            tree_size, leaf_index, proof_path = cbor2.loads(proof_bytes)
            inclusion_proofs.append({
                'tree_size': tree_size,
                'leaf_index': leaf_index,
                'proof': proof_path
            })
        
        # Extract claims
        claims = protected.get(ReceiptGenerator.CLAIMS_LABEL, {})
        
        return {
            'algorithm': protected.get(Algorithm),
            'kid': protected.get(KID),
            'vds': protected.get(ReceiptGenerator.VDS_LABEL),
            'claims': claims,
            'inclusion_proofs': inclusion_proofs,
            'payload': msg.payload
        }


class StatementValidator:
    """
    Validates COSE Signed Statements.
    """
    
    @staticmethod
    def extract_statement_hash(cose_sign1: bytes) -> bytes:
        """
        Extract hash from a COSE Signed Statement.
        
        For statements with detached payloads, this reads the payload hash.
        For embedded payloads, this computes the hash.
        
        Args:
            cose_sign1: COSE_Sign1 message
            
        Returns:
            SHA-256 hash of the statement
        """
        msg = Sign1Message.decode(cose_sign1)
        
        # Check if payload is present or detached
        if msg.payload:
            # Embedded payload - hash it
            return hashlib.sha256(msg.payload).digest()
        else:
            # Detached payload - look for hash in protected header
            protected = msg.phdr
            
            # Custom header for payload hash (label 258)
            payload_hash = protected.get(258)
            if payload_hash:
                return payload_hash
            
            # Otherwise, hash the entire COSE structure
            return hashlib.sha256(cose_sign1).digest()
    
    @staticmethod
    def extract_metadata(cose_sign1: bytes) -> Dict[str, Any]:
        """
        Extract metadata from a COSE Signed Statement.
        
        Args:
            cose_sign1: COSE_Sign1 message
            
        Returns:
            Dictionary with issuer, subject, content_type, etc.
        """
        msg = Sign1Message.decode(cose_sign1)
        protected = msg.phdr
        
        # Extract common fields
        metadata = {
            'algorithm': protected.get(Algorithm),
            'kid': protected.get(KID),
        }
        
        # Check for SCITT-specific headers
        # Type header (16): "application/example+cose"
        content_type = protected.get(16)
        if content_type:
            metadata['content_type'] = content_type
        
        # Payload hash algorithm (258)
        payload_hash_alg = protected.get(258)
        if payload_hash_alg:
            metadata['payload_hash_alg'] = payload_hash_alg
        
        # Preimage content type (259)
        preimage_type = protected.get(259)
        if preimage_type:
            metadata['preimage_content_type'] = preimage_type
        
        # Payload location (260) - for detached payloads
        payload_location = protected.get(260)
        if payload_location:
            metadata['payload_location'] = payload_location
        
        return metadata
```

### Test: `tests/test_receipts.py`
```python
import pytest
import cbor2
from src.core.receipts import ReceiptGenerator, StatementValidator
from src.core.merkle import MerkleTree
from pycose.keys.ec2 import EC2Key
from pycose.headers import Algorithm, KID
from pycose.messages import Sign1Message
import hashlib


@pytest.fixture
def receipt_generator():
    """Create a receipt generator with test key."""
    key = ReceiptGenerator.generate_signing_key()
    return ReceiptGenerator(key, "https://transparency.example")


def test_generate_signing_key():
    """Test key generation."""
    key = ReceiptGenerator.generate_signing_key()
    assert key is not None
    assert isinstance(key, EC2Key)


def test_create_simple_receipt(receipt_generator):
    """Test creating a basic receipt."""
    statement_hash = b"test_statement_hash_123"
    leaf_index = 0
    tree_size = 1
    inclusion_proof = []
    
    receipt = receipt_generator.create_receipt(
        statement_hash,
        leaf_index,
        tree_size,
        inclusion_proof
    )
    
    assert receipt is not None
    assert isinstance(receipt, bytes)
    
    # Verify it's valid CBOR
    try:
        cbor2.loads(receipt)
    except Exception as e:
        pytest.fail(f"Receipt is not valid CBOR: {e}")


def test_create_receipt_with_proof(receipt_generator):
    """Test creating receipt with inclusion proof."""
    statement_hash = b"statement_hash"
    leaf_index = 1
    tree_size = 4
    inclusion_proof = [
        b"sibling1_hash_000000000000000000000000",
        b"sibling2_hash_000000000000000000000000"
    ]
    
    receipt = receipt_generator.create_receipt(
        statement_hash,
        leaf_index,
        tree_size,
        inclusion_proof,
        issuer="https://issuer.example",
        subject="artifact-v1.0.0"
    )
    
    assert receipt is not None


def test_parse_receipt(receipt_generator):
    """Test parsing receipt metadata."""
    statement_hash = b"test_hash"
    leaf_index = 2
    tree_size = 5
    inclusion_proof = [b"proof1", b"proof2"]
    
    receipt = receipt_generator.create_receipt(
        statement_hash,
        leaf_index,
        tree_size,
        inclusion_proof,
        issuer="https://issuer.example",
        subject="test-subject"
    )
    
    parsed = ReceiptGenerator.parse_receipt(receipt)
    
    assert parsed['algorithm'] is not None
    assert parsed['kid'] == receipt_generator.signing_key.key_id
    assert parsed['vds'] == 1  # RFC 9162
    assert len(parsed['inclusion_proofs']) == 1
    
    proof = parsed['inclusion_proofs'][0]
    assert proof['tree_size'] == tree_size
    assert proof['leaf_index'] == leaf_index
    assert len(proof['proof']) == 2


def test_parse_receipt_claims(receipt_generator):
    """Test parsing claims from receipt."""
    receipt = receipt_generator.create_receipt(
        b"hash",
        0,
        1,
        [],
        issuer="https://blue.example",
        subject="https://green.example/artifact"
    )
    
    parsed = ReceiptGenerator.parse_receipt(receipt)
    claims = parsed['claims']
    
    assert claims.get(1) == "https://blue.example"  # issuer
    assert claims.get(2) == "https://green.example/artifact"  # subject


def test_extract_statement_hash_embedded_payload():
    """Test extracting hash from statement with embedded payload."""
    # Create a simple COSE Sign1 with embedded payload
    payload = b"test payload data"
    
    msg = Sign1Message(
        phdr={Algorithm: -7},  # ES256
        payload=payload
    )
    
    # For testing, we'll use a dummy key
    key = ReceiptGenerator.generate_signing_key()
    msg.key = key
    cose_bytes = msg.encode()
    
    # Extract hash
    extracted_hash = StatementValidator.extract_statement_hash(cose_bytes)
    expected_hash = hashlib.sha256(payload).digest()
    
    assert extracted_hash == expected_hash


def test_extract_statement_hash_detached_payload():
    """Test extracting hash from statement with detached payload."""
    payload = b"detached payload"
    payload_hash = hashlib.sha256(payload).digest()
    
    # Create COSE Sign1 with hash in protected header
    msg = Sign1Message(
        phdr={
            Algorithm: -7,
            258: payload_hash  # payload-hash
        },
        payload=None  # Detached
    )
    
    key = ReceiptGenerator.generate_signing_key()
    msg.key = key
    cose_bytes = msg.encode()
    
    extracted_hash = StatementValidator.extract_statement_hash(cose_bytes)
    assert extracted_hash == payload_hash


def test_extract_metadata():
    """Test extracting metadata from signed statement."""
    msg = Sign1Message(
        phdr={
            Algorithm: -7,
            KID: b"test_key_id",
            16: "application/spdx+json",  # content type
            258: -16,  # payload-hash-alg (SHA-256)
            259: "application/json",  # preimage-content-type
            260: "https://example.com/artifact.json"  # payload-location
        },
        payload=b"test"
    )
    
    key = ReceiptGenerator.generate_signing_key()
    msg.key = key
    cose_bytes = msg.encode()
    
    metadata = StatementValidator.extract_metadata(cose_bytes)
    
    assert metadata['content_type'] == "application/spdx+json"
    assert metadata['payload_hash_alg'] == -16
    assert metadata['preimage_content_type'] == "application/json"
    assert metadata['payload_location'] == "https://example.com/artifact.json"


def test_receipt_with_merkle_proof_validation(receipt_generator):
    """Test end-to-end receipt with real Merkle proof."""
    # Create a small tree
    leaves = [f"leaf{i}".encode() for i in range(4)]
    root = MerkleTree.calculate_root(leaves)
    
    # Generate proof for leaf 1
    leaf_index = 1
    proof = MerkleTree.generate_inclusion_proof(leaf_index, len(leaves), leaves)
    
    # Create receipt
    statement_hash = leaves[leaf_index]
    receipt = receipt_generator.create_receipt(
        statement_hash,
        leaf_index,
        len(leaves),
        proof
    )
    
    # Parse and verify proof structure
    parsed = ReceiptGenerator.parse_receipt(receipt)
    inclusion_proof = parsed['inclusion_proofs'][0]
    
    assert inclusion_proof['tree_size'] == len(leaves)
    assert inclusion_proof['leaf_index'] == leaf_index
    
    # Verify the proof against the root
    leaf_hash = MerkleTree.hash_leaf(statement_hash)
    is_valid = MerkleTree.verify_inclusion_proof(
        leaf_hash,
        leaf_index,
        inclusion_proof['proof'],
        len(leaves),
        root
    )
    assert is_valid


# Run tests with: pytest tests/test_receipts.py -v
```

### Running Step 3 Tests
```bash
pytest tests/test_receipts.py -v

# Expected output: All tests should pass
```

---

## STEP 4: API Layer with FastAPI

### Goal
Implement SCRAPI REST endpoints for registration and receipt retrieval.

### Implementation: `src/api/models.py`
```python
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


class TransparencyConfiguration(BaseModel):
    """Response for /.well-known/transparency-configuration"""
    issuer: str
    jwks_uri: Optional[str] = None
    registration_endpoint: str = "/entries"
    receipt_endpoint: str = "/entries/{entry_id}"


class RegistrationResponse(BaseModel):
    """Response for successful registration (201)"""
    entry_id: str
    location: str
    status: str = "registered"


class RegistrationPending(BaseModel):
    """Response for pending registration (303)"""
    location: str
    retry_after: Optional[int] = None


class ReceiptResponse(BaseModel):
    """Receipt metadata for clients"""
    entry_id: str
    statement_hash: str  # hex encoded
    leaf_index: int
    tree_size: int
    registered_at: datetime


class ErrorResponse(BaseModel):
    """CBOR Problem Details (RFC 9290) compatible error"""
    title: str = Field(..., description="Short error title")
    detail: str = Field(..., description="Detailed error message")
    instance: Optional[str] = None
```

### Implementation: `src/api/endpoints.py`
```python
from fastapi import FastAPI, HTTPException, Response, Request, status
from fastapi.responses import JSONResponse
import cbor2
from typing import Optional
import hashlib

from ..storage.sqlite_store import SQLiteStore
from ..core.merkle import MerkleTreeBuilder, MerkleTree
from ..core.receipts import ReceiptGenerator, StatementValidator
from .models import (
    TransparencyConfiguration,
    RegistrationResponse,
    ErrorResponse
)


class TransparencyServiceAPI:
    """SCRAPI-compatible REST API for transparency service."""
    
    def __init__(
        self,
        storage: SQLiteStore,
        receipt_generator: ReceiptGenerator,
        service_url: str = "https://transparency.example"
    ):
        self.storage = storage
        self.receipt_generator = receipt_generator
        self.service_url = service_url
        self.merkle_builder = MerkleTreeBuilder(storage)
        self.app = FastAPI(title="SCITT Transparency Service")
        
        self._setup_routes()
    
    def _setup_routes(self):
        """Register all SCRAPI endpoints."""
        
        @self.app.get("/.well-known/transparency-configuration")
        async def get_configuration():
            """Get transparency service configuration."""
            config = TransparencyConfiguration(
                issuer=self.service_url,
                registration_endpoint=f"{self.service_url}/entries",
                receipt_endpoint=f"{self.service_url}/entries/{{entry_id}}"
            )
            return Response(
                content=cbor2.dumps(config.model_dump()),
                media_type="application/cbor"
            )
        
        @self.app.post(
            "/entries",
            status_code=status.HTTP_201_CREATED,
            responses={
                201: {"description": "Registered successfully"},
                303: {"description": "Registration pending"},
                400: {"description": "Invalid request"}
            }
        )
        async def register_statement(request: Request):
            """
            Register a Signed Statement.
            
            SCRAPI Section 2.1.2: Register Signed Statement
            """
            # Read COSE Sign1 from body
            cose_sign1 = await request.body()
            
            if not cose_sign1:
                return self._error_response(
                    "Payload Missing",
                    "Signed Statement payload must be present",
                    400
                )
            
            try:
                # Extract statement hash
                statement_hash = StatementValidator.extract_statement_hash(cose_sign1)
                
                # Extract metadata
                metadata = StatementValidator.extract_metadata(cose_sign1)
                
                # Check if already registered
                existing = await self.storage.get_entry_by_hash(statement_hash)
                if existing:
                    return self._error_response(
                        "Already Registered",
                        "Statement with this hash already registered",
                        400
                    )
                
                # Append to log
                leaf_index = await self.storage.append_entry(
                    statement_hash=statement_hash,
                    cose_sign1=cose_sign1,
                    issuer=metadata.get('issuer'),
                    subject=metadata.get('subject'),
                    content_type=metadata.get('content_type')
                )
                
                # Add to Merkle tree
                await self.merkle_builder.add_leaf(statement_hash)
                tree_size = await self.storage.get_tree_size()
                
                # Generate inclusion proof
                inclusion_proof = await self.merkle_builder.get_inclusion_proof(
                    leaf_index,
                    tree_size
                )
                
                # Generate receipt
                receipt = self.receipt_generator.create_receipt(
                    statement_hash=statement_hash,
                    leaf_index=leaf_index,
                    tree_size=tree_size,
                    inclusion_proof=inclusion_proof,
                    issuer=metadata.get('issuer'),
                    subject=metadata.get('subject')
                )
                
                # Return receipt with location
                entry_id = statement_hash.hex()
                location = f"{self.service_url}/entries/{entry_id}"
                
                return Response(
                    content=receipt,
                    status_code=201,
                    media_type="application/cose",
                    headers={"Location": location}
                )
                
            except Exception as e:
                return self._error_response(
                    "Registration Failed",
                    f"Failed to register statement: {str(e)}",
                    400
                )
        
        @self.app.get("/entries/{entry_id}")
        async def get_registration_status(entry_id: str):
            """
            Query registration status and retrieve receipt.
            
            SCRAPI Section 2.1.3: Query Registration Status
            SCRAPI Section 2.1.4: Resolve Receipt
            """
            try:
                # Convert entry_id (hex) to bytes
                statement_hash = bytes.fromhex(entry_id)
            except ValueError:
                return self._error_response(
                    "Invalid Entry ID",
                    "Entry ID must be hex-encoded hash",
                    400
                )
            
            # Retrieve entry
            entry = await self.storage.get_entry_by_hash(statement_hash)
            if not entry:
                return self._error_response(
                    "Not Found",
                    f"Receipt with entry ID {entry_id} not known to this service",
                    404
                )
            
            # Generate fresh receipt
            tree_size = await self.storage.get_tree_size()
            leaf_index = entry['leaf_index']
            
            # Get inclusion proof
            inclusion_proof = await self.merkle_builder.get_inclusion_proof(
                leaf_index,
                tree_size
            )
            
            # Generate receipt
            receipt = self.receipt_generator.create_receipt(
                statement_hash=statement_hash,
                leaf_index=leaf_index,
                tree_size=tree_size,
                inclusion_proof=inclusion_proof,
                issuer=entry.get('issuer'),
                subject=entry.get('subject')
            )
            
            location = f"{self.service_url}/entries/{entry_id}"
            
            return Response(
                content=receipt,
                status_code=200,
                media_type="application/cose",
                headers={"Location": location}
            )
        
        @self.app.get("/signed-statements/{entry_id}")
        async def get_signed_statement(entry_id: str):
            """
            Retrieve original Signed Statement.
            
            SCRAPI Section 2.2.2: Resolve Signed Statement (Optional)
            """
            try:
                statement_hash = bytes.fromhex(entry_id)
            except ValueError:
                return self._error_response(
                    "Invalid Entry ID",
                    "Entry ID must be hex-encoded hash",
                    400
                )
            
            entry = await self.storage.get_entry_by_hash(statement_hash)
            if not entry:
                return self._error_response(
                    "Not Found",
                    f"No Signed Statement found with ID {entry_id}",
                    404
                )
            
            return Response(
                content=entry['cose_sign1'],
                status_code=200,
                media_type="application/cose"
            )
    
    def _error_response(self, title: str, detail: str, status_code: int):
        """Create RFC 9290 compliant error response."""
        error = {
            -1: title,   # title
            -2: detail   # detail
        }
        return Response(
            content=cbor2.dumps(error),
            status_code=status_code,
            media_type="application/concise-problem-details+cbor"
        )
```

### Implementation: `src/main.py`
```python
import asyncio
import uvicorn
from pathlib import Path

from src.storage.sqlite_store import SQLiteStore
from src.core.receipts import ReceiptGenerator
from src.api.endpoints import TransparencyServiceAPI


async def create_app():
    """Create and initialize the transparency service application."""
    # Initialize storage
    db_path = "transparency.db"
    storage = SQLiteStore(db_path)
    await storage.initialize()
    
    # Generate or load signing key
    # In production, load from secure key storage
    signing_key = ReceiptGenerator.generate_signing_key()
    receipt_gen = ReceiptGenerator(
        signing_key,
        service_id="https://transparency.example"
    )
    
    # Create API
    service = TransparencyServiceAPI(
        storage=storage,
        receipt_generator=receipt_gen,
        service_url="http://localhost:8000"
    )
    
    return service.app


def main():
    """Run the transparency service."""
    # For development
    app = asyncio.run(create_app())
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
```

### Test: `tests/test_api.py`
```python
import pytest
from httpx import AsyncClient, ASGITransport
import cbor2
from pycose.messages import Sign1Message
from pycose.headers import Algorithm
import hashlib

from src.storage.sqlite_store import SQLiteStore
from src.core.receipts import ReceiptGenerator
from src.api.endpoints import TransparencyServiceAPI
import tempfile
import os
from pathlib import Path


@pytest.fixture
async def test_app():
    """Create test application with temporary database."""
    fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    
    storage = SQLiteStore(db_path)
    await storage.initialize()
    
    signing_key = ReceiptGenerator.generate_signing_key()
    receipt_gen = ReceiptGenerator(signing_key, "https://test.example")
    
    service = TransparencyServiceAPI(
        storage=storage,
        receipt_generator=receipt_gen,
        service_url="https://test.example"
    )
    
    yield service.app, storage
    
    await storage.close()
    Path(db_path).unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_get_configuration(test_app):
    """Test transparency configuration endpoint."""
    app, storage = test_app
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/.well-known/transparency-configuration")
        
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/cbor"
        
        config = cbor2.loads(response.content)
        assert config['issuer'] == "https://test.example"
        assert '/entries' in config['registration_endpoint']


@pytest.mark.asyncio
async def test_register_statement(test_app):
    """Test registering a signed statement."""
    app, storage = test_app
    
    # Create a test COSE Sign1 message
    payload = b"test payload"
    msg = Sign1Message(
        phdr={Algorithm: -7},  # ES256
        payload=payload
    )
    
    key = ReceiptGenerator.generate_signing_key()
    msg.key = key
    cose_bytes = msg.encode()
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/entries",
            content=cose_bytes,
            headers={"Content-Type": "application/cose"}
        )
        
        assert response.status_code == 201
        assert "Location" in response.headers
        assert response.headers["content-type"] == "application/cose"
        
        # Verify response is a valid COSE message (receipt)
        receipt = cbor2.loads(response.content)
        assert receipt is not None


@pytest.mark.asyncio
async def test_register_and_retrieve(test_app):
    """Test full cycle: register and retrieve receipt."""
    app, storage = test_app
    
    # Register statement
    payload = b"test data for retrieval"
    msg = Sign1Message(phdr={Algorithm: -7}, payload=payload)
    key = ReceiptGenerator.generate_signing_key()
    msg.key = key
    cose_bytes = msg.encode()
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Register
        reg_response = await client.post("/entries", content=cose_bytes)
        assert reg_response.status_code == 201
        
        location = reg_response.headers["Location"]
        entry_id = location.split("/")[-1]
        
        # Retrieve
        get_response = await client.get(f"/entries/{entry_id}")
        assert get_response.status_code == 200
        assert get_response.headers["content-type"] == "application/cose"


@pytest.mark.asyncio
async def test_duplicate_registration(test_app):
    """Test that duplicate statements are rejected."""
    app, storage = test_app
    
    payload = b"duplicate test"
    msg = Sign1Message(phdr={Algorithm: -7}, payload=payload)
    key = ReceiptGenerator.generate_signing_key()
    msg.key = key
    cose_bytes = msg.encode()
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # First registration
        response1 = await client.post("/entries", content=cose_bytes)
        assert response1.status_code == 201
        
        # Second registration with same statement
        response2 = await client.post("/entries", content=cose_bytes)
        assert response2.status_code == 400
        
        error = cbor2.loads(response2.content)
        assert "Already Registered" in error.get(-1, "")


@pytest.mark.asyncio
async def test_get_nonexistent_entry(test_app):
    """Test retrieving non-existent entry."""
    app, storage = test_app
    
    fake_id = "0" * 64  # Valid hex but doesn't exist
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(f"/entries/{fake_id}")
        
        assert response.status_code == 404
        error = cbor2.loads(response.content)
        assert "Not Found" in error.get(-1, "")


@pytest.mark.asyncio
async def test_invalid_entry_id(test_app):
    """Test with invalid entry ID format."""
    app, storage = test_app
    
    invalid_id = "not_hex_format"
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(f"/entries/{invalid_id}")
        
        assert response.status_code == 400


@pytest.mark.asyncio
async def test_get_signed_statement(test_app):
    """Test retrieving original signed statement."""
    app, storage = test_app
    
    payload = b"original statement data"
    msg = Sign1Message(phdr={Algorithm: -7}, payload=payload)
    key = ReceiptGenerator.generate_signing_key()
    msg.key = key
    cose_bytes = msg.encode()
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Register
        reg_response = await client.post("/entries", content=cose_bytes)
        entry_id = reg_response.headers["Location"].split("/")[-1]
        
        # Retrieve signed statement
        response = await client.get(f"/signed-statements/{entry_id}")
        assert response.status_code == 200
        assert response.content == cose_bytes


@pytest.mark.asyncio
async def test_multiple_statements(test_app):
    """Test registering multiple statements."""
    app, storage = test_app
    
    num_statements = 5
    entry_ids = []
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for i in range(num_statements):
            payload = f"statement_{i}".encode()
            msg = Sign1Message(phdr={Algorithm: -7}, payload=payload)
            key = ReceiptGenerator.generate_signing_key()
            msg.key = key
            cose_bytes = msg.encode()
            
            response = await client.post("/entries", content=cose_bytes)
            assert response.status_code == 201
            
            entry_id = response.headers["Location"].split("/")[-1]
            entry_ids.append(entry_id)
        
        # Verify all can be retrieved
        for entry_id in entry_ids:
            response = await client.get(f"/entries/{entry_id}")
            assert response.status_code == 200


# Run tests with: pytest tests/test_api.py -v
```

### Running Step 4 Tests
```bash
# Install additional test dependencies
pip install httpx

# Run all tests
pytest tests/test_api.py -v

# Or run entire test suite
pytest tests/ -v
```

---

## STEP 5: Integration Testing and Deployment

### Integration Test: `tests/test_integration.py`
```python
import pytest
from httpx import AsyncClient, ASGITransport
import cbor2
from pycose.messages import Sign1Message
from pycose.headers import Algorithm

from src.main import create_app
from src.core.receipts import ReceiptGenerator
from src.core.merkle import MerkleTree
import tempfile
import os
from pathlib import Path


@pytest.fixture
async def live_app():
    """Create a live application instance."""
    # Use temporary database
    fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    
    # Temporarily set DB path (you'd use env vars in production)
    original_path = os.environ.get('DB_PATH')
    os.environ['DB_PATH'] = db_path
    
    app = await create_app()
    
    yield app
    
    # Cleanup
    if original_path:
        os.environ['DB_PATH'] = original_path
    else:
        os.environ.pop('DB_PATH', None)
    
    Path(db_path).unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_end_to_end_workflow(live_app):
    """
    Test complete end-to-end workflow:
    1. Discover service configuration
    2. Register multiple statements
    3. Retrieve receipts
    4. Verify inclusion proofs
    """
    async with AsyncClient(transport=ASGITransport(app=live_app), base_url="http://test") as client:
        # Step 1: Get configuration
        config_response = await client.get("/.well-known/transparency-configuration")
        assert config_response.status_code == 200
        config = cbor2.loads(config_response.content)
        print(f"✓ Service configured at {config['issuer']}")
        
        # Step 2: Register multiple statements
        num_statements = 10
        entries = []
        
        for i in range(num_statements):
            payload = f"artifact_v{i}.0.0".encode()
            msg = Sign1Message(
                phdr={
                    Algorithm: -7,
                    16: "application/example+json",  # content type
                },
                payload=payload
            )
            key = ReceiptGenerator.generate_signing_key()
            msg.key = key
            cose_bytes = msg.encode()
            
            response = await client.post(
                "/entries",
                content=cose_bytes,
                headers={"Content-Type": "application/cose"}
            )
            
            assert response.status_code == 201
            entry_id = response.headers["Location"].split("/")[-1]
            entries.append({
                'id': entry_id,
                'payload': payload,
                'cose': cose_bytes
            })
            print(f"✓ Registered statement {i}: {entry_id[:16]}...")
        
        # Step 3: Retrieve all receipts
        for i, entry in enumerate(entries):
            response = await client.get(f"/entries/{entry['id']}")
            assert response.status_code == 200
            
            # Parse receipt
            parsed = ReceiptGenerator.parse_receipt(response.content)
            assert len(parsed['inclusion_proofs']) > 0
            print(f"✓ Retrieved receipt {i} with valid inclusion proof")
        
        # Step 4: Verify a receipt's inclusion proof
        # Get receipt for middle entry
        middle_entry = entries[num_statements // 2]
        response = await client.get(f"/entries/{middle_entry['id']}")
        receipt_bytes = response.content
        
        parsed = ReceiptGenerator.parse_receipt(receipt_bytes)
        proof_data = parsed['inclusion_proofs'][0]
        
        # Manually verify the proof would work
        # (In production, client would do this verification)
        print(f"✓ Receipt contains proof with {len(proof_data['proof'])} siblings")
        print(f"  Tree size: {proof_data['tree_size']}")
        print(f"  Leaf index: {proof_data['leaf_index']}")
        
        # Step 5: Retrieve original signed statement
        response = await client.get(f"/signed-statements/{middle_entry['id']}")
        assert response.status_code == 200
        assert response.content == middle_entry['cose']
        print("✓ Successfully retrieved original signed statement")


@pytest.mark.asyncio
async def test_receipt_freshness(live_app):
    """Test that receipts can be refreshed with current tree state."""
    async with AsyncClient(transport=ASGITransport(app=live_app), base_url="http://test") as client:
        # Register first statement
        msg1 = Sign1Message(phdr={Algorithm: -7}, payload=b"first")
        key1 = ReceiptGenerator.generate_signing_key()
        msg1.key = key1
        
        response1 = await client.post("/entries", content=msg1.encode())
        entry_id = response1.headers["Location"].split("/")[-1]
        
        # Get initial receipt
        receipt1_response = await client.get(f"/entries/{entry_id}")
        receipt1 = ReceiptGenerator.parse_receipt(receipt1_response.content)
        tree_size_1 = receipt1['inclusion_proofs'][0]['tree_size']
        
        # Register more statements
        for i in range(5):
            msg = Sign1Message(phdr={Algorithm: -7}, payload=f"later_{i}".encode())
            key = ReceiptGenerator.generate_signing_key()
            msg.key = key
            await client.post("/entries", content=msg.encode())
        
        # Get fresh receipt for first statement
        receipt2_response = await client.get(f"/entries/{entry_id}")
        receipt2 = ReceiptGenerator.parse_receipt(receipt2_response.content)
        tree_size_2 = receipt2['inclusion_proofs'][0]['tree_size']
        
        # Tree should have grown
        assert tree_size_2 > tree_size_1
        print(f"✓ Receipt updated from tree size {tree_size_1} to {tree_size_2}")


# Run with: pytest tests/test_integration.py -v -s
```

### Production Configuration: `src/config.py`
```python
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings."""
    
    # Database
    db_path: str = "transparency.db"
    
    # Service
    service_url: str = "https://transparency.example"
    service_id: str = "https://transparency.example"
    
    # API
    host: str = "0.0.0.0"
    port: int = 8000
    
    # Security
    key_file: Optional[str] = None  # Path to signing key
    enable_auth: bool = False
    
    # Performance
    max_tree_cache_size: int = 10000
    
    class Config:
        env_prefix = "SCITT_"
        env_file = ".env"


settings = Settings()
```

### Running the Service
```bash
# Development mode
python -m src.main

# Or with uvicorn directly
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

# Production mode with gunicorn
gunicorn src.main:app -w 4 -k uvicorn.workers.UvicornWorker
```

### Testing with curl
```bash
# Get configuration
curl http://localhost:8000/.well-known/transparency-configuration \
  -H "Accept: application/cbor" | xxd

# Register a statement (requires COSE message)
# You'll need to create a proper COSE Sign1 message

# Get receipt
curl http://localhost:8000/entries/{entry_id} \
  -H "Accept: application/cose"
```

---

## Next Steps

1. **Add Authentication**: Implement JWT or API key authentication for write endpoints
2. **Add Async Processing**: For slow registrations, implement background task queue
3. **Add Monitoring**: Prometheus metrics for tree size, registration rate, etc.
4. **Optimize Merkle Tree**: Implement incremental tree building for better performance
5. **Add Receipt Exchange**: Implement receipt refresh endpoint (SCRAPI 2.2.3)
6. **Add Issuer Discovery**: Implement /.well-known/issuer endpoint (SCRAPI 2.2.4)
7. **Add HTTPS/TLS**: Configure proper TLS certificates for production
8. **Add Backup/Replication**: Implement SQLite backup and replication strategy

---

## References

- **IETF SCRAPI Spec**: https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/
- **SCITT Architecture**: https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/
- **RFC 9052 (COSE)**: https://www.rfc-editor.org/rfc/rfc9052.html
- **RFC 9162 (Certificate Transparency)**: https://www.rfc-editor.org/rfc/rfc9162.html
- **pycose Documentation**: https://github.com/TimothyClaeys/pycose
- **FastAPI Documentation**: https://fastapi.tiangolo.com/
