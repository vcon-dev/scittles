"""Verification utilities for transparency service."""

from typing import List
from .merkle import MerkleTree


def verify_inclusion(
    leaf_data: bytes,
    leaf_index: int,
    proof: List[bytes],
    tree_size: int,
    root_hash: bytes,
) -> bool:
    """
    Verify that a leaf is included in the tree.

    Args:
        leaf_data: Original leaf data (will be hashed)
        leaf_index: Position of the leaf in the tree
        proof: Inclusion proof (list of sibling hashes)
        tree_size: Size of the tree
        root_hash: Expected root hash

    Returns:
        True if the leaf is verified to be in the tree
    """
    leaf_hash = MerkleTree.hash_leaf(leaf_data)
    return MerkleTree.verify_inclusion_proof(
        leaf_hash, leaf_index, proof, tree_size, root_hash
    )
