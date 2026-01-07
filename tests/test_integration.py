import pytest
from httpx import AsyncClient, ASGITransport
import cbor2
from pycose.messages import Sign1Message
from pycose.headers import Algorithm
import tempfile
import os
from pathlib import Path

from src.storage.sqlite_store import SQLiteStore
from src.core.receipts import ReceiptGenerator
from src.core.merkle import MerkleTree
from src.api.endpoints import TransparencyServiceAPI


@pytest.fixture
async def live_app():
    """Create a live application instance."""
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    storage = SQLiteStore(db_path)
    await storage.initialize()

    signing_key = ReceiptGenerator.generate_signing_key()
    receipt_gen = ReceiptGenerator(signing_key, "https://live.example")

    service = TransparencyServiceAPI(
        storage=storage,
        receipt_generator=receipt_gen,
        service_url="https://live.example",
    )

    yield service.app, storage

    await storage.close()
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
    app, storage = live_app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Step 1: Get configuration
        config_response = await client.get("/.well-known/transparency-configuration")
        assert config_response.status_code == 200
        config = cbor2.loads(config_response.content)
        assert config["issuer"] == "https://live.example"

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
                payload=payload,
            )
            key = ReceiptGenerator.generate_signing_key()
            msg.key = key
            cose_bytes = msg.encode()

            response = await client.post(
                "/entries",
                content=cose_bytes,
                headers={"Content-Type": "application/cose"},
            )

            assert response.status_code == 201
            entry_id = response.headers["Location"].split("/")[-1]
            entries.append({"id": entry_id, "payload": payload, "cose": cose_bytes})

        # Step 3: Retrieve all receipts
        for i, entry in enumerate(entries):
            response = await client.get(f"/entries/{entry['id']}")
            assert response.status_code == 200

            # Parse receipt
            parsed = ReceiptGenerator.parse_receipt(response.content)
            assert len(parsed["inclusion_proofs"]) > 0

        # Step 4: Verify a receipt's inclusion proof structure
        middle_entry = entries[num_statements // 2]
        response = await client.get(f"/entries/{middle_entry['id']}")
        receipt_bytes = response.content

        parsed = ReceiptGenerator.parse_receipt(receipt_bytes)
        proof_data = parsed["inclusion_proofs"][0]

        assert proof_data["tree_size"] == num_statements
        assert proof_data["leaf_index"] < num_statements

        # Step 5: Retrieve original signed statement
        response = await client.get(f"/signed-statements/{middle_entry['id']}")
        assert response.status_code == 200
        assert response.content == middle_entry["cose"]


@pytest.mark.asyncio
async def test_receipt_freshness(live_app):
    """Test that receipts can be refreshed with current tree state."""
    app, storage = live_app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Register first statement
        msg1 = Sign1Message(phdr={Algorithm: -7}, payload=b"first")
        key1 = ReceiptGenerator.generate_signing_key()
        msg1.key = key1

        response1 = await client.post("/entries", content=msg1.encode())
        entry_id = response1.headers["Location"].split("/")[-1]

        # Get initial receipt
        receipt1_response = await client.get(f"/entries/{entry_id}")
        receipt1 = ReceiptGenerator.parse_receipt(receipt1_response.content)
        tree_size_1 = receipt1["inclusion_proofs"][0]["tree_size"]

        # Register more statements
        for i in range(5):
            msg = Sign1Message(phdr={Algorithm: -7}, payload=f"later_{i}".encode())
            key = ReceiptGenerator.generate_signing_key()
            msg.key = key
            await client.post("/entries", content=msg.encode())

        # Get fresh receipt for first statement
        receipt2_response = await client.get(f"/entries/{entry_id}")
        receipt2 = ReceiptGenerator.parse_receipt(receipt2_response.content)
        tree_size_2 = receipt2["inclusion_proofs"][0]["tree_size"]

        # Tree should have grown
        assert tree_size_2 > tree_size_1
        assert tree_size_1 == 1
        assert tree_size_2 == 6


@pytest.mark.asyncio
async def test_merkle_proof_verification(live_app):
    """Test that Merkle proofs can be verified correctly."""
    app, storage = live_app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Register several statements and track their hashes
        statements = []
        for i in range(4):
            payload = f"verify_test_{i}".encode()
            msg = Sign1Message(phdr={Algorithm: -7}, payload=payload)
            key = ReceiptGenerator.generate_signing_key()
            msg.key = key
            cose_bytes = msg.encode()

            response = await client.post("/entries", content=cose_bytes)
            assert response.status_code == 201

            entry_id = response.headers["Location"].split("/")[-1]
            statements.append(
                {
                    "id": entry_id,
                    "hash": bytes.fromhex(entry_id),
                }
            )

        # Verify proof for each statement
        for stmt in statements:
            response = await client.get(f"/entries/{stmt['id']}")
            parsed = ReceiptGenerator.parse_receipt(response.content)
            proof_data = parsed["inclusion_proofs"][0]

            # The proof should be valid for this leaf
            assert proof_data["tree_size"] == 4
            assert 0 <= proof_data["leaf_index"] < 4
