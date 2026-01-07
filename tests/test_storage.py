import pytest


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
        subject="test-artifact",
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
    assert entry["statement_hash"] == statement_hash
    assert entry["cose_sign1"] == cose_sign1
    assert entry["leaf_index"] == 0


@pytest.mark.asyncio
async def test_retrieve_entry_by_index(storage):
    """Test retrieving an entry by leaf index."""
    # Add multiple entries
    hashes = [b"hash1", b"hash2", b"hash3"]
    for h in hashes:
        await storage.append_entry(h, b"cose_data")

    entry = await storage.get_entry_by_index(1)
    assert entry is not None
    assert entry["statement_hash"] == b"hash2"
    assert entry["leaf_index"] == 1


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
        assert entry["leaf_index"] == expected_index


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
