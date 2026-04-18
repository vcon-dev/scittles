import asyncio
import uvicorn
import os

import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, NoEncryption, load_pem_private_key
)
from pycose.keys.ec2 import EC2Key
from pycose.keys.curves import P256

from src.storage.sqlite_store import SQLiteStore
from src.core.receipts import ReceiptGenerator
from src.api.endpoints import TransparencyServiceAPI
from src.config import settings
from src.observability import setup_logging, setup_opentelemetry
from src.observability.middleware import ObservabilityMiddleware
from src.observability.prometheus import setup_prometheus_exporter, get_metrics_endpoint


def _ec2key_from_cryptography(private_key) -> EC2Key:
    """Construct an EC2Key from a cryptography EC private key."""
    priv_numbers = private_key.private_numbers()
    pub_numbers = priv_numbers.public_numbers
    return EC2Key(
        crv=P256,
        x=pub_numbers.x.to_bytes(32, "big"),
        y=pub_numbers.y.to_bytes(32, "big"),
        d=priv_numbers.private_value.to_bytes(32, "big"),
    )


def _load_or_create_signing_key(signing_key: str | None, key_file: str | None) -> EC2Key:
    """Load signing key from env var (base64 PEM), file, or generate a new one.

    Priority:
    1. SCITT_SIGNING_KEY env var — base64-encoded PEM (k8s Secret / Docker env)
    2. SCITT_KEY_FILE path — load from file; generate-and-persist if absent (local dev)
    3. Neither set — ephemeral key (dev only, receipts invalid after restart)
    """
    if signing_key:
        pem = base64.b64decode(signing_key)
        private_key = load_pem_private_key(pem, password=None)
        return _ec2key_from_cryptography(private_key)

    if key_file:
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                private_key = load_pem_private_key(f.read(), password=None)
            return _ec2key_from_cryptography(private_key)
        else:
            private_key = ec.generate_private_key(ec.SECP256R1())
            pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
            os.makedirs(os.path.dirname(os.path.abspath(key_file)), exist_ok=True)
            with open(key_file, "wb") as f:
                f.write(pem)
            return _ec2key_from_cryptography(private_key)

    return ReceiptGenerator.generate_signing_key()


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

    signing_key = _load_or_create_signing_key(settings.signing_key, settings.key_file)
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
