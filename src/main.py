import asyncio
import uvicorn
import os

from src.storage.sqlite_store import SQLiteStore
from src.core.receipts import ReceiptGenerator
from src.api.endpoints import TransparencyServiceAPI
from src.config import settings
from src.observability import setup_logging, setup_opentelemetry
from src.observability.middleware import ObservabilityMiddleware
from src.observability.prometheus import setup_prometheus_exporter, get_metrics_endpoint


async def create_app():
    """Create and initialize the transparency service application."""
    # Initialize observability
    setup_logging()
    setup_opentelemetry()

    # Initialize storage backend
    # For postgres, defer pool creation to startup event (asyncpg pools are
    # bound to the event loop they're created in, and asyncio.run() uses a
    # different loop than uvicorn).
    if settings.storage_backend == "postgres":
        from src.storage.postgres_store import PostgresStore

        storage = PostgresStore(
            dsn=settings.postgres_url,
            pool_min=settings.postgres_pool_min,
            pool_max=settings.postgres_pool_max,
        )
        # Don't initialize yet — deferred to startup event
    else:
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

    # Register startup/shutdown events
    @service.app.on_event("startup")
    async def on_startup():
        # For postgres, create pool in uvicorn's event loop
        if settings.storage_backend == "postgres":
            await storage.initialize()
        # Warm up Merkle tree from persisted state
        await service.merkle_builder.warm_up()

    @service.app.on_event("shutdown")
    async def on_shutdown():
        await storage.close()

    # Add observability middleware
    service.app.add_middleware(ObservabilityMiddleware)

    # Add Prometheus metrics endpoint if enabled
    exporters = [e.strip() for e in settings.otel_exporter.split(",")]
    if "prometheus" in exporters:
        setup_prometheus_exporter()
        service.app.get("/metrics")(get_metrics_endpoint())

    return service.app


def main():
    """Run the transparency service."""
    # For development
    app = asyncio.run(create_app())
    uvicorn.run(app, host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
