import pytest
from httpx import AsyncClient, ASGITransport
import cbor2
from pycose.messages import Sign1Message
from pycose.headers import Algorithm

from src.core.receipts import ReceiptGenerator


@pytest.mark.asyncio
async def test_get_configuration(test_app):
    """Test transparency configuration endpoint."""
    app, storage = test_app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/.well-known/transparency-configuration")

        assert response.status_code == 200
        assert response.headers["content-type"] == "application/cbor"

        config = cbor2.loads(response.content)
        assert config["issuer"] == "https://test.example"
        assert "/entries" in config["registration_endpoint"]


@pytest.mark.asyncio
async def test_register_statement(test_app):
    """Test registering a signed statement."""
    app, storage = test_app

    # Create a test COSE Sign1 message
    payload = b"test payload"
    msg = Sign1Message(phdr={Algorithm: -7}, payload=payload)  # ES256

    key = ReceiptGenerator.generate_signing_key()
    msg.key = key
    cose_bytes = msg.encode()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/entries", content=cose_bytes, headers={"Content-Type": "application/cose"}
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

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(f"/entries/{fake_id}")

        assert response.status_code == 404
        error = cbor2.loads(response.content)
        assert "Not Found" in error.get(-1, "")


@pytest.mark.asyncio
async def test_invalid_entry_id(test_app):
    """Test with invalid entry ID format."""
    app, storage = test_app

    invalid_id = "not_hex_format"

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
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


@pytest.mark.asyncio
async def test_empty_payload(test_app):
    """Test that empty payload is rejected."""
    app, storage = test_app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/entries", content=b"", headers={"Content-Type": "application/cose"}
        )

        assert response.status_code == 400
