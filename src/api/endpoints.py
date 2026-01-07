from fastapi import FastAPI, Response, Request, status
import cbor2
import time
from opentelemetry import trace

from ..storage.sqlite_store import SQLiteStore
from ..core.merkle import MerkleTreeBuilder
from ..core.receipts import ReceiptGenerator, StatementValidator
from .models import TransparencyConfiguration
from ..observability.logging import get_logger
from ..observability.metrics import get_metrics

logger = get_logger(__name__)
metrics = get_metrics()
tracer = trace.get_tracer(__name__)


class TransparencyServiceAPI:
    """SCRAPI-compatible REST API for transparency service."""

    def __init__(
        self,
        storage: SQLiteStore,
        receipt_generator: ReceiptGenerator,
        service_url: str = "https://transparency.example",
    ):
        self.storage = storage
        self.receipt_generator = receipt_generator
        self.service_url = service_url
        self.merkle_builder = MerkleTreeBuilder(storage)
        self.app = FastAPI(title="SCITT Transparency Service")

        self._setup_routes()

    def _setup_routes(self):
        """Register all SCRAPI endpoints."""

        @self.app.get("/.well-known/transparency-configuration")
        async def get_configuration():
            """Get transparency service configuration."""
            config = TransparencyConfiguration(
                issuer=self.service_url,
                registration_endpoint=f"{self.service_url}/entries",
                receipt_endpoint=f"{self.service_url}/entries/{{entry_id}}",
            )
            return Response(
                content=cbor2.dumps(config.model_dump()),
                media_type="application/cbor",
            )

        @self.app.post(
            "/entries",
            status_code=status.HTTP_201_CREATED,
            responses={
                201: {"description": "Registered successfully"},
                303: {"description": "Registration pending"},
                400: {"description": "Invalid request"},
            },
        )
        async def register_statement(request: Request):
            """
            Register a Signed Statement.

            SCRAPI Section 2.1.2: Register Signed Statement
            """
            start_time = time.time()
            request_id = getattr(request.state, "request_id", None)

            with tracer.start_as_current_span("register_statement") as span:
                # Read COSE Sign1 from body
                cose_sign1 = await request.body()

                if not cose_sign1:
                    logger.warning(
                        "registration_failed",
                        request_id=request_id,
                        reason="payload_missing",
                    )
                    return self._error_response(
                        "Payload Missing", "Signed Statement payload must be present", 400
                    )

                try:
                    # Extract statement hash
                    statement_hash = StatementValidator.extract_statement_hash(cose_sign1)
                    entry_id = statement_hash.hex()
                    span.set_attribute("entry.id", entry_id)
                    span.set_attribute("statement.hash", entry_id)

                    # Extract metadata
                    metadata = StatementValidator.extract_metadata(cose_sign1)
                    if metadata.get("issuer"):
                        span.set_attribute("statement.issuer", metadata.get("issuer"))
                    if metadata.get("subject"):
                        span.set_attribute("statement.subject", metadata.get("subject"))

                    logger.info(
                        "registration_started",
                        request_id=request_id,
                        entry_id=entry_id,
                        issuer=metadata.get("issuer"),
                        subject=metadata.get("subject"),
                    )

                    # Check if already registered
                    existing = await self.storage.get_entry_by_hash(statement_hash)
                    if existing:
                        logger.warning(
                            "registration_failed",
                            request_id=request_id,
                            entry_id=entry_id,
                            reason="already_registered",
                        )
                        return self._error_response(
                            "Already Registered",
                            "Statement with this hash already registered",
                            400,
                        )

                    # Append to log
                    leaf_index = await self.storage.append_entry(
                        statement_hash=statement_hash,
                        cose_sign1=cose_sign1,
                        issuer=metadata.get("issuer"),
                        subject=metadata.get("subject"),
                        content_type=metadata.get("content_type"),
                    )
                    span.set_attribute("entry.leaf_index", leaf_index)

                    # Add to Merkle tree
                    await self.merkle_builder.add_leaf(statement_hash)
                    tree_size = await self.storage.get_tree_size()
                    span.set_attribute("merkle.tree_size", tree_size)

                    # Generate inclusion proof
                    inclusion_proof = await self.merkle_builder.get_inclusion_proof(
                        leaf_index, tree_size
                    )
                    span.set_attribute("merkle.proof_length", len(inclusion_proof))

                    # Generate receipt
                    receipt = self.receipt_generator.create_receipt(
                        statement_hash=statement_hash,
                        leaf_index=leaf_index,
                        tree_size=tree_size,
                        inclusion_proof=inclusion_proof,
                        issuer=metadata.get("issuer"),
                        subject=metadata.get("subject"),
                    )

                    # Return receipt with location
                    location = f"{self.service_url}/entries/{entry_id}"

                    duration = time.time() - start_time
                    metrics.entry_registration_count.add(1)
                    metrics.entry_registration_duration.record(duration)

                    logger.info(
                        "registration_completed",
                        request_id=request_id,
                        entry_id=entry_id,
                        leaf_index=leaf_index,
                        tree_size=tree_size,
                        duration_seconds=duration,
                    )

                    return Response(
                        content=receipt,
                        status_code=201,
                        media_type="application/cose",
                        headers={"Location": location},
                    )

                except Exception as e:
                    span.record_exception(e)
                    logger.exception(
                        "registration_failed",
                        request_id=request_id,
                        error=str(e),
                    )
                    return self._error_response(
                        "Registration Failed", f"Failed to register statement: {str(e)}", 400
                    )

        @self.app.get("/entries/{entry_id}")
        async def get_registration_status(entry_id: str, request: Request):
            """
            Query registration status and retrieve receipt.

            SCRAPI Section 2.1.3: Query Registration Status
            SCRAPI Section 2.1.4: Resolve Receipt
            """
            request_id = getattr(request.state, "request_id", None)

            with tracer.start_as_current_span("get_registration_status") as span:
                span.set_attribute("entry.id", entry_id)

                try:
                    # Convert entry_id (hex) to bytes
                    statement_hash = bytes.fromhex(entry_id)
                except ValueError:
                    logger.warning(
                        "invalid_entry_id",
                        request_id=request_id,
                        entry_id=entry_id,
                    )
                    return self._error_response(
                        "Invalid Entry ID", "Entry ID must be hex-encoded hash", 400
                    )

                # Retrieve entry
                entry = await self.storage.get_entry_by_hash(statement_hash)
                if not entry:
                    logger.warning(
                        "entry_not_found",
                        request_id=request_id,
                        entry_id=entry_id,
                    )
                    return self._error_response(
                        "Not Found",
                        f"Receipt with entry ID {entry_id} not known to this service",
                        404,
                    )

                # Generate fresh receipt
                tree_size = await self.storage.get_tree_size()
                leaf_index = entry["leaf_index"]
                span.set_attribute("entry.leaf_index", leaf_index)
                span.set_attribute("merkle.tree_size", tree_size)

                # Get inclusion proof
                inclusion_proof = await self.merkle_builder.get_inclusion_proof(
                    leaf_index, tree_size
                )
                span.set_attribute("merkle.proof_length", len(inclusion_proof))

                # Generate receipt
                receipt = self.receipt_generator.create_receipt(
                    statement_hash=statement_hash,
                    leaf_index=leaf_index,
                    tree_size=tree_size,
                    inclusion_proof=inclusion_proof,
                    issuer=entry.get("issuer"),
                    subject=entry.get("subject"),
                )

                location = f"{self.service_url}/entries/{entry_id}"

                logger.info(
                    "receipt_retrieved",
                    request_id=request_id,
                    entry_id=entry_id,
                    leaf_index=leaf_index,
                    tree_size=tree_size,
                )

                return Response(
                    content=receipt,
                    status_code=200,
                    media_type="application/cose",
                    headers={"Location": location},
                )

        @self.app.get("/signed-statements/{entry_id}")
        async def get_signed_statement(entry_id: str, request: Request):
            """
            Retrieve original Signed Statement.

            SCRAPI Section 2.2.2: Resolve Signed Statement (Optional)
            """
            request_id = getattr(request.state, "request_id", None)

            with tracer.start_as_current_span("get_signed_statement") as span:
                span.set_attribute("entry.id", entry_id)

                try:
                    statement_hash = bytes.fromhex(entry_id)
                except ValueError:
                    logger.warning(
                        "invalid_entry_id",
                        request_id=request_id,
                        entry_id=entry_id,
                    )
                    return self._error_response(
                        "Invalid Entry ID", "Entry ID must be hex-encoded hash", 400
                    )

                entry = await self.storage.get_entry_by_hash(statement_hash)
                if not entry:
                    logger.warning(
                        "statement_not_found",
                        request_id=request_id,
                        entry_id=entry_id,
                    )
                    return self._error_response(
                        "Not Found", f"No Signed Statement found with ID {entry_id}", 404
                    )

                logger.info(
                    "statement_retrieved",
                    request_id=request_id,
                    entry_id=entry_id,
                )

                return Response(
                    content=entry["cose_sign1"], status_code=200, media_type="application/cose"
                )

    def _error_response(self, title: str, detail: str, status_code: int):
        """Create RFC 9290 compliant error response."""
        error = {-1: title, -2: detail}  # title  # detail
        return Response(
            content=cbor2.dumps(error),
            status_code=status_code,
            media_type="application/concise-problem-details+cbor",
        )
