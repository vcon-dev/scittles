import pytest
import hashlib
from src.core.merkle import MerkleTree, MerkleTreeBuilder


def test_hash_leaf():
    """Test leaf hashing with domain separation."""
    data = b"test_data"
    expected = hashlib.sha256(b"\x00" + data).digest()
    result = MerkleTree.hash_leaf(data)
    assert result == expected


def test_hash_children():
    """Test node hashing with domain separation."""
    left = b"left_hash_000000000000000000000000"
    right = b"right_hash_00000000000000000000000"
    expected = hashlib.sha256(b"\x01" + left + right).digest()
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


def test_empty_leaves():
    """Test root calculation with no leaves."""
    leaves = []
    root = MerkleTree.calculate_root(leaves)
    assert root is None


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

    is_valid = MerkleTree.verify_inclusion_proof(leaf_hash, 0, proof, 4, root)
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
    is_valid = MerkleTree.verify_inclusion_proof(leaf_hash, 0, proof, 3, wrong_root)
    assert not is_valid


def test_verify_inclusion_proof_tampered():
    """Test that verification fails with tampered proof."""
    leaves = [b"leaf1", b"leaf2", b"leaf3"]
    root = MerkleTree.calculate_root(leaves)

    leaf_hash = MerkleTree.hash_leaf(b"leaf1")
    proof = MerkleTree.generate_inclusion_proof(0, 3, leaves)

    # Tamper with proof
    tampered_proof = [b"tampered_hash_000000000000000000000000"] + proof[1:]
    is_valid = MerkleTree.verify_inclusion_proof(leaf_hash, 0, tampered_proof, 3, root)
    assert not is_valid


def test_invalid_leaf_index():
    """Test that invalid leaf index raises error."""
    leaves = [b"leaf1", b"leaf2"]
    with pytest.raises(ValueError):
        MerkleTree.generate_inclusion_proof(5, 2, leaves)


def test_invalid_tree_size():
    """Test that invalid tree size raises error."""
    leaves = [b"leaf1", b"leaf2"]
    with pytest.raises(ValueError):
        MerkleTree.generate_inclusion_proof(0, 5, leaves)


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

    is_valid = MerkleTree.verify_inclusion_proof(leaf_hash, 1, proof, 4, root)
    assert is_valid
