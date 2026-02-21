"""Performance tests for O(log n) Merkle tree operations."""

import time
import pytest
from src.core.merkle import MerkleTree, MerkleTreeBuilder


@pytest.mark.asyncio
async def test_add_leaf_performance_10k():
    """Create 10,000 entries, assert p99 add_leaf < 1ms."""
    builder = MerkleTreeBuilder()
    durations = []

    for i in range(10_000):
        leaf = f"perf_leaf_{i}".encode()
        start = time.monotonic()
        await builder.add_leaf(leaf)
        durations.append(time.monotonic() - start)

    durations.sort()
    p99 = durations[9899]  # 99th percentile
    max_duration = durations[-1]

    assert p99 < 0.001, (
        f"p99 add_leaf was {p99 * 1000:.2f}ms, expected < 1ms "
        f"(max was {max_duration * 1000:.2f}ms)"
    )


@pytest.mark.asyncio
async def test_get_inclusion_proof_performance_10k():
    """After 10K entries, assert each get_inclusion_proof < 10ms."""
    builder = MerkleTreeBuilder()
    leaves = [f"perf_leaf_{i}".encode() for i in range(10_000)]

    for leaf in leaves:
        await builder.add_leaf(leaf)

    tree_size = builder._tree_size
    max_duration = 0
    slow_count = 0

    # Test proofs for a sample of leaves (every 100th + first + last)
    indices = [0] + list(range(99, 10_000, 100)) + [9_999]
    for idx in indices:
        start = time.monotonic()
        proof = await builder.get_inclusion_proof(idx, tree_size)
        duration = time.monotonic() - start

        if duration > max_duration:
            max_duration = duration
        if duration > 0.010:  # 10ms
            slow_count += 1

    assert slow_count == 0, (
        f"{slow_count} out of {len(indices)} get_inclusion_proof calls exceeded 10ms "
        f"(max was {max_duration * 1000:.2f}ms)"
    )


@pytest.mark.asyncio
async def test_proof_correctness_10k():
    """After 10K entries, verify all sampled proofs are correct."""
    builder = MerkleTreeBuilder()
    leaves = [f"perf_leaf_{i}".encode() for i in range(10_000)]

    for leaf in leaves:
        await builder.add_leaf(leaf)

    tree_size = builder._tree_size
    root = await builder.get_root()

    # Cross-validate root with reference implementation
    expected_root = MerkleTree.calculate_root(leaves)
    assert root == expected_root, "Root hash mismatch between builder and reference"

    # Verify proofs for a sample
    indices = [0, 1, 2, 100, 999, 5000, 7777, 9998, 9999]
    for idx in indices:
        leaf_hash = MerkleTree.hash_leaf(leaves[idx])
        proof = await builder.get_inclusion_proof(idx, tree_size)
        assert MerkleTree.verify_inclusion_proof(leaf_hash, idx, proof, tree_size, root), \
            f"Proof verification failed for leaf {idx}"


@pytest.mark.asyncio
async def test_get_root_performance():
    """After 10K entries, get_root should be < 1ms."""
    builder = MerkleTreeBuilder()
    for i in range(10_000):
        await builder.add_leaf(f"perf_leaf_{i}".encode())

    start = time.monotonic()
    for _ in range(1000):
        await builder.get_root()
    total = time.monotonic() - start

    avg_ms = (total / 1000) * 1000
    assert avg_ms < 1.0, f"Average get_root took {avg_ms:.3f}ms, expected < 1ms"
