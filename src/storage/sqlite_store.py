import aiosqlite
import time
from pathlib import Path
from typing import Optional
from opentelemetry import trace

from .base import StorageBackend
from ..observability.logging import get_logger
from ..observability.metrics import get_metrics

logger = get_logger(__name__)
metrics = get_metrics()
tracer = trace.get_tracer(__name__)


class SQLiteStore(StorageBackend):
    """SQLite-based storage backend with append-only semantics."""

    def __init__(self, db_path: str = "transparency.db"):
        self.db_path = db_path
        self.conn: Optional[aiosqlite.Connection] = None

    async def initialize(self) -> None:
        """Initialize the database with schema."""
        self.conn = await aiosqlite.connect(self.db_path)
        self.conn.row_factory = aiosqlite.Row

        # Load and execute schema
        schema_path = Path(__file__).parent / "schema.sql"
        with open(schema_path, "r") as f:
            schema = f.read()

        await self.conn.executescript(schema)
        await self.conn.commit()

    async def append_entry(
        self,
        statement_hash: bytes,
        cose_sign1: bytes,
        issuer: Optional[str] = None,
        subject: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> int:
        """Append a new entry to the log."""
        start_time = time.time()
        entry_id = statement_hash.hex()

        with tracer.start_as_current_span("db.append_entry") as span:
            span.set_attribute("db.operation", "append_entry")
            span.set_attribute("entry.id", entry_id)

            if not self.conn:
                error = RuntimeError("Storage not initialized")
                span.record_exception(error)
                raise error

            try:
                # Get current tree size to use as leaf index
                tree_size = await self.get_tree_size()

                async with self.conn.execute(
                    """
                    INSERT INTO entries
                    (statement_hash, cose_sign1, issuer, subject, content_type, leaf_index)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (statement_hash, cose_sign1, issuer, subject, content_type, tree_size),
                ) as cursor:
                    pass  # We don't need the entry_id

                # Increment tree size
                await self.conn.execute(
                    "UPDATE service_state SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = 'tree_size'",
                    (str(tree_size + 1),),
                )

                await self.conn.commit()

                duration = time.time() - start_time
                metrics.db_operation_duration.record(duration, {"operation": "append_entry"})
                metrics.db_operation_count.add(1, {"operation": "append_entry"})
                span.set_attribute("entry.leaf_index", tree_size)

                logger.debug(
                    "entry_appended",
                    entry_id=entry_id,
                    leaf_index=tree_size,
                    duration_seconds=duration,
                )

                return tree_size

            except Exception as e:
                duration = time.time() - start_time
                metrics.db_error_count.add(1, {"operation": "append_entry"})
                span.record_exception(e)
                logger.exception(
                    "db_operation_failed",
                    operation="append_entry",
                    entry_id=entry_id,
                    error=str(e),
                )
                raise

    async def get_entry_by_hash(self, statement_hash: bytes) -> Optional[dict]:
        """Retrieve an entry by its statement hash."""
        start_time = time.time()
        entry_id = statement_hash.hex()

        with tracer.start_as_current_span("db.get_entry_by_hash") as span:
            span.set_attribute("db.operation", "get_entry_by_hash")
            span.set_attribute("entry.id", entry_id)

            if not self.conn:
                error = RuntimeError("Storage not initialized")
                span.record_exception(error)
                raise error

            try:
                async with self.conn.execute(
                    "SELECT * FROM entries WHERE statement_hash = ?", (statement_hash,)
                ) as cursor:
                    row = await cursor.fetchone()
                    result = dict(row) if row else None

                    duration = time.time() - start_time
                    metrics.db_operation_duration.record(duration, {"operation": "get_entry_by_hash"})
                    metrics.db_operation_count.add(1, {"operation": "get_entry_by_hash"})

                    if result:
                        span.set_attribute("entry.found", True)
                        span.set_attribute("entry.leaf_index", result.get("leaf_index"))
                    else:
                        span.set_attribute("entry.found", False)

                    return result

            except Exception as e:
                duration = time.time() - start_time
                metrics.db_error_count.add(1, {"operation": "get_entry_by_hash"})
                span.record_exception(e)
                logger.exception(
                    "db_operation_failed",
                    operation="get_entry_by_hash",
                    entry_id=entry_id,
                    error=str(e),
                )
                raise

    async def get_entry_by_index(self, leaf_index: int) -> Optional[dict]:
        """Retrieve an entry by its leaf index."""
        if not self.conn:
            raise RuntimeError("Storage not initialized")

        async with self.conn.execute(
            "SELECT * FROM entries WHERE leaf_index = ?", (leaf_index,)
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def get_tree_size(self) -> int:
        """Get current size of the Merkle tree."""
        start_time = time.time()

        with tracer.start_as_current_span("db.get_tree_size") as span:
            span.set_attribute("db.operation", "get_tree_size")

            if not self.conn:
                error = RuntimeError("Storage not initialized")
                span.record_exception(error)
                raise error

            try:
                async with self.conn.execute(
                    "SELECT value FROM service_state WHERE key = 'tree_size'"
                ) as cursor:
                    row = await cursor.fetchone()
                    tree_size = int(row[0]) if row else 0

                    duration = time.time() - start_time
                    metrics.db_operation_duration.record(duration, {"operation": "get_tree_size"})
                    metrics.db_operation_count.add(1, {"operation": "get_tree_size"})
                    span.set_attribute("merkle.tree_size", tree_size)

                    return tree_size

            except Exception as e:
                duration = time.time() - start_time
                metrics.db_error_count.add(1, {"operation": "get_tree_size"})
                span.record_exception(e)
                logger.exception(
                    "db_operation_failed",
                    operation="get_tree_size",
                    error=str(e),
                )
                raise

    async def store_merkle_node(
        self, tree_size: int, position: int, node_hash: bytes
    ) -> None:
        """Store a Merkle tree node."""
        start_time = time.time()

        with tracer.start_as_current_span("db.store_merkle_node") as span:
            span.set_attribute("db.operation", "store_merkle_node")
            span.set_attribute("merkle.tree_size", tree_size)
            span.set_attribute("merkle.node_position", position)

            if not self.conn:
                error = RuntimeError("Storage not initialized")
                span.record_exception(error)
                raise error

            try:
                await self.conn.execute(
                    """
                    INSERT OR REPLACE INTO merkle_nodes (tree_size, node_position, node_hash)
                    VALUES (?, ?, ?)
                    """,
                    (tree_size, position, node_hash),
                )
                await self.conn.commit()

                duration = time.time() - start_time
                metrics.db_operation_duration.record(duration, {"operation": "store_merkle_node"})
                metrics.db_operation_count.add(1, {"operation": "store_merkle_node"})

            except Exception as e:
                duration = time.time() - start_time
                metrics.db_error_count.add(1, {"operation": "store_merkle_node"})
                span.record_exception(e)
                logger.exception(
                    "db_operation_failed",
                    operation="store_merkle_node",
                    tree_size=tree_size,
                    position=position,
                    error=str(e),
                )
                raise

    async def get_merkle_node(self, tree_size: int, position: int) -> Optional[bytes]:
        """Retrieve a Merkle tree node."""
        start_time = time.time()

        with tracer.start_as_current_span("db.get_merkle_node") as span:
            span.set_attribute("db.operation", "get_merkle_node")
            span.set_attribute("merkle.tree_size", tree_size)
            span.set_attribute("merkle.node_position", position)

            if not self.conn:
                error = RuntimeError("Storage not initialized")
                span.record_exception(error)
                raise error

            try:
                async with self.conn.execute(
                    "SELECT node_hash FROM merkle_nodes WHERE tree_size = ? AND node_position = ?",
                    (tree_size, position),
                ) as cursor:
                    row = await cursor.fetchone()
                    result = row[0] if row else None

                    duration = time.time() - start_time
                    metrics.db_operation_duration.record(duration, {"operation": "get_merkle_node"})
                    metrics.db_operation_count.add(1, {"operation": "get_merkle_node"})
                    span.set_attribute("merkle.node_found", result is not None)

                    return result

            except Exception as e:
                duration = time.time() - start_time
                metrics.db_error_count.add(1, {"operation": "get_merkle_node"})
                span.record_exception(e)
                logger.exception(
                    "db_operation_failed",
                    operation="get_merkle_node",
                    tree_size=tree_size,
                    position=position,
                    error=str(e),
                )
                raise

    async def close(self) -> None:
        """Close the database connection."""
        if self.conn:
            await self.conn.close()
            self.conn = None
