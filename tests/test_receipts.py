import pytest
import cbor2
import hashlib
from src.core.receipts import ReceiptGenerator, StatementValidator
from src.core.merkle import MerkleTree
from pycose.keys.ec2 import EC2Key
from pycose.headers import Algorithm
from pycose.messages import Sign1Message


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
        statement_hash, leaf_index, tree_size, inclusion_proof
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
        b"sibling2_hash_000000000000000000000000",
    ]

    receipt = receipt_generator.create_receipt(
        statement_hash,
        leaf_index,
        tree_size,
        inclusion_proof,
        issuer="https://issuer.example",
        subject="artifact-v1.0.0",
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
        subject="test-subject",
    )

    parsed = ReceiptGenerator.parse_receipt(receipt)

    assert parsed["algorithm"] is not None
    assert parsed["vds"] == 1  # RFC 9162
    assert len(parsed["inclusion_proofs"]) == 1

    proof = parsed["inclusion_proofs"][0]
    assert proof["tree_size"] == tree_size
    assert proof["leaf_index"] == leaf_index
    assert len(proof["proof"]) == 2


def test_parse_receipt_claims(receipt_generator):
    """Test parsing claims from receipt."""
    receipt = receipt_generator.create_receipt(
        b"hash",
        0,
        1,
        [],
        issuer="https://blue.example",
        subject="https://green.example/artifact",
    )

    parsed = ReceiptGenerator.parse_receipt(receipt)
    claims = parsed["claims"]

    assert claims.get(1) == "https://blue.example"  # issuer
    assert claims.get(2) == "https://green.example/artifact"  # subject


def test_extract_statement_hash_embedded_payload():
    """Test extracting hash from statement with embedded payload."""
    # Create a simple COSE Sign1 with embedded payload
    payload = b"test payload data"

    msg = Sign1Message(phdr={Algorithm: -7}, payload=payload)  # ES256

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
        phdr={Algorithm: -7, 258: payload_hash},  # payload-hash
        payload=None,  # Detached
    )

    key = ReceiptGenerator.generate_signing_key()
    msg.key = key
    # For detached payloads, must provide the detached content when encoding
    cose_bytes = msg.encode(detached_payload=payload)

    extracted_hash = StatementValidator.extract_statement_hash(cose_bytes)
    assert extracted_hash == payload_hash


def test_extract_metadata():
    """Test extracting metadata from signed statement."""
    msg = Sign1Message(
        phdr={
            Algorithm: -7,
            16: "application/spdx+json",  # content type
            258: -16,  # payload-hash-alg (SHA-256)
            259: "application/json",  # preimage-content-type
            260: "https://example.com/artifact.json",  # payload-location
        },
        payload=b"test",
    )

    key = ReceiptGenerator.generate_signing_key()
    msg.key = key
    cose_bytes = msg.encode()

    metadata = StatementValidator.extract_metadata(cose_bytes)

    assert metadata["content_type"] == "application/spdx+json"
    assert metadata["payload_hash_alg"] == -16
    assert metadata["preimage_content_type"] == "application/json"
    assert metadata["payload_location"] == "https://example.com/artifact.json"


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
        statement_hash, leaf_index, len(leaves), proof
    )

    # Parse and verify proof structure
    parsed = ReceiptGenerator.parse_receipt(receipt)
    inclusion_proof = parsed["inclusion_proofs"][0]

    assert inclusion_proof["tree_size"] == len(leaves)
    assert inclusion_proof["leaf_index"] == leaf_index

    # Verify the proof against the root
    leaf_hash = MerkleTree.hash_leaf(statement_hash)
    is_valid = MerkleTree.verify_inclusion_proof(
        leaf_hash, leaf_index, inclusion_proof["proof"], len(leaves), root
    )
    assert is_valid


def test_receipt_no_issuer_subject(receipt_generator):
    """Test creating receipt without issuer and subject."""
    receipt = receipt_generator.create_receipt(
        b"hash",
        0,
        1,
        [],
    )

    parsed = ReceiptGenerator.parse_receipt(receipt)
    claims = parsed["claims"]

    # Should have service_id as issuer
    assert claims.get(1) == "https://test.example"
    assert claims.get(2) is None
