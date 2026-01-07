import asyncio
import uvicorn
import os

from src.storage.sqlite_store import SQLiteStore
from src.core.receipts import ReceiptGenerator
from src.api.endpoints import TransparencyServiceAPI
from src.config import settings


async def create_app():
    """Create and initialize the transparency service application."""
    # Initialize storage
    db_path = os.environ.get("DB_PATH", settings.db_path)
    storage = SQLiteStore(db_path)
    await storage.initialize()

    # Generate or load signing key
    # In production, load from secure key storage
    signing_key = ReceiptGenerator.generate_signing_key()
    receipt_gen = ReceiptGenerator(signing_key, service_id=settings.service_id)

    # Create API
    service = TransparencyServiceAPI(
        storage=storage,
        receipt_generator=receipt_gen,
        service_url=settings.service_url,
    )

    return service.app


def main():
    """Run the transparency service."""
    # For development
    app = asyncio.run(create_app())
    uvicorn.run(app, host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
