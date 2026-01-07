"""Shared pytest fixtures for the transparency service tests."""

import pytest
import tempfile
import os
from pathlib import Path

from src.storage.sqlite_store import SQLiteStore
from src.core.receipts import ReceiptGenerator
from src.core.merkle import MerkleTreeBuilder
from src.api.endpoints import TransparencyServiceAPI


@pytest.fixture
async def storage():
    """Create a temporary storage instance for testing."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    store = SQLiteStore(path)
    await store.initialize()

    yield store

    await store.close()
    Path(path).unlink(missing_ok=True)


@pytest.fixture
def signing_key():
    """Generate a test signing key."""
    return ReceiptGenerator.generate_signing_key()


@pytest.fixture
def receipt_generator(signing_key):
    """Create a receipt generator with test key."""
    return ReceiptGenerator(signing_key, "https://test.example")


@pytest.fixture
async def storage_and_builder(storage):
    """Create storage and Merkle tree builder for testing."""
    builder = MerkleTreeBuilder(storage)
    yield storage, builder


@pytest.fixture
async def test_app(storage, receipt_generator):
    """Create test application with temporary database."""
    service = TransparencyServiceAPI(
        storage=storage,
        receipt_generator=receipt_generator,
        service_url="https://test.example",
    )

    yield service.app, storage
