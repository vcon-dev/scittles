import time
from typing import List, Optional, Tuple
from opentelemetry import trace

from .base import StorageBackend
from ..observability.logging import get_logger
from ..observability.metrics import get_metrics

logger = get_logger(__name__)
metrics = get_metrics()
tracer = trace.get_tracer(__name__)

try:
    import asyncpg
except ImportError:
    asyncpg = None


class PostgresStore(StorageBackend):
    """PostgreSQL-based storage backend using asyncpg with connection pooling."""

    SCHEMA_SQL = """
    CREATE SCHEMA IF NOT EXISTS scitt;

    CREATE TABLE IF NOT EXISTS scitt.entries (
        entry_id SERIAL PRIMARY KEY,
        statement_hash BYTEA NOT NULL UNIQUE,
        cose_sign1 BYTEA NOT NULL,
        issuer TEXT,
        subject TEXT,
        content_type TEXT,
        registered_at TIMESTAMPTZ DEFAULT NOW(),
        leaf_index INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_scitt_statement_hash ON scitt.entries(statement_hash);
    CREATE INDEX IF NOT EXISTS idx_scitt_leaf_index ON scitt.entries(leaf_index);
    CREATE INDEX IF NOT EXISTS idx_scitt_subject ON scitt.entries(subject);

    CREATE TABLE IF NOT EXISTS scitt.merkle_tree_nodes (
        level INTEGER NOT NULL,
        position INTEGER NOT NULL,
        node_hash BYTEA NOT NULL,
        PRIMARY KEY (level, position)
    );

    CREATE TABLE IF NOT EXISTS scitt.merkle_frontier (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        tree_size INTEGER NOT NULL DEFAULT 0,
        frontier BYTEA NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS scitt.service_state (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    INSERT INTO scitt.service_state (key, value)
    VALUES ('tree_size', '0')
    ON CONFLICT (key) DO NOTHING;
    """

    def __init__(
        self,
        dsn: str,
        pool_min: int = 2,
        pool_max: int = 10,
    ):
        if asyncpg is None:
            raise ImportError("asyncpg is required for PostgreSQL backend: pip install asyncpg")

        self.dsn = dsn
        self.pool_min = pool_min
        self.pool_max = pool_max
        self.pool: Optional[asyncpg.Pool] = None

    async def initialize(self) -> None:
        """Initialize connection pool and create schema."""
        self.pool = await asyncpg.create_pool(
            dsn=self.dsn,
            min_size=self.pool_min,
            max_size=self.pool_max,
        )

        async with self.pool.acquire() as conn:
            await conn.execute(self.SCHEMA_SQL)

        logger.info("postgres_store_initialized", dsn=self.dsn.split("@")[-1])

    async def append_entry(
        self,
        statement_hash: bytes,
        cose_sign1: bytes,
        issuer: Optional[str] = None,
        subject: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> int:
        """Append a new entry atomically using PostgreSQL row-level locking."""
        start_time = time.time()
        entry_id = statement_hash.hex()

        with tracer.start_as_current_span("db.append_entry") as span:
            span.set_attribute("db.operation", "append_entry")
            span.set_attribute("entry.id", entry_id)

            if not self.pool:
                raise RuntimeError("Storage not initialized")

            try:
                async with self.pool.acquire() as conn:
                    async with conn.transaction():
                        # Atomic increment: UPDATE ... RETURNING gives us the leaf index
                        row = await conn.fetchrow(
                            """
                            UPDATE scitt.service_state
                            SET value = (value::int + 1)::text, updated_at = NOW()
                            WHERE key = 'tree_size'
                            RETURNING (value::int - 1) AS leaf_index
                            """
                        )
                        leaf_index = row["leaf_index"]

                        await conn.execute(
                            """
                            INSERT INTO scitt.entries
                            (statement_hash, cose_sign1, issuer, subject, content_type, leaf_index)
                            VALUES ($1, $2, $3, $4, $5, $6)
                            """,
                            statement_hash, cose_sign1, issuer, subject, content_type, leaf_index,
                        )

                duration = time.time() - start_time
                metrics.db_operation_duration.record(duration, {"operation": "append_entry"})
                metrics.db_operation_count.add(1, {"operation": "append_entry"})
                span.set_attribute("entry.leaf_index", leaf_index)

                logger.debug(
                    "entry_appended",
                    entry_id=entry_id,
                    leaf_index=leaf_index,
                    duration_seconds=duration,
                )

                return leaf_index

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

        with tracer.start_as_current_span("db.get_entry_by_hash") as span:
            span.set_attribute("db.operation", "get_entry_by_hash")

            if not self.pool:
                raise RuntimeError("Storage not initialized")

            try:
                async with self.pool.acquire() as conn:
                    row = await conn.fetchrow(
                        "SELECT * FROM scitt.entries WHERE statement_hash = $1",
                        statement_hash,
                    )

                duration = time.time() - start_time
                metrics.db_operation_duration.record(duration, {"operation": "get_entry_by_hash"})
                metrics.db_operation_count.add(1, {"operation": "get_entry_by_hash"})

                if row:
                    span.set_attribute("entry.found", True)
                    return dict(row)
                else:
                    span.set_attribute("entry.found", False)
                    return None

            except Exception as e:
                metrics.db_error_count.add(1, {"operation": "get_entry_by_hash"})
                span.record_exception(e)
                logger.exception("db_operation_failed", operation="get_entry_by_hash", error=str(e))
                raise

    async def get_entry_by_index(self, leaf_index: int) -> Optional[dict]:
        """Retrieve an entry by its leaf index."""
        if not self.pool:
            raise RuntimeError("Storage not initialized")

        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM scitt.entries WHERE leaf_index = $1", leaf_index
            )
            return dict(row) if row else None

    async def get_entries_batch(
        self, start_index: int, end_index: int
    ) -> List[dict]:
        """Retrieve entries by leaf index range [start_index, end_index)."""
        if not self.pool:
            raise RuntimeError("Storage not initialized")

        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM scitt.entries WHERE leaf_index >= $1 AND leaf_index < $2 ORDER BY leaf_index",
                start_index, end_index,
            )
            return [dict(row) for row in rows]

    async def get_tree_size(self) -> int:
        """Get current size of the Merkle tree."""
        if not self.pool:
            raise RuntimeError("Storage not initialized")

        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT value FROM scitt.service_state WHERE key = 'tree_size'"
            )
            return int(row["value"]) if row else 0

    async def store_merkle_node(
        self, tree_size: int, position: int, node_hash: bytes
    ) -> None:
        """Store a Merkle tree node (legacy interface)."""
        pass  # Not used with new builder, but required by ABC

    async def get_merkle_node(self, tree_size: int, position: int) -> Optional[bytes]:
        """Retrieve a Merkle tree node (legacy interface)."""
        return None  # Not used with new builder

    # --- New methods for O(log n) Merkle tree ---

    async def store_tree_node(self, level: int, index: int, node_hash: bytes) -> None:
        """Store an internal Merkle tree node."""
        if not self.pool:
            raise RuntimeError("Storage not initialized")

        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO scitt.merkle_tree_nodes (level, position, node_hash)
                VALUES ($1, $2, $3)
                ON CONFLICT (level, position) DO UPDATE SET node_hash = $3
                """,
                level, index, node_hash,
            )

    async def get_tree_node(self, level: int, index: int) -> Optional[bytes]:
        """Retrieve an internal Merkle tree node."""
        if not self.pool:
            raise RuntimeError("Storage not initialized")

        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT node_hash FROM scitt.merkle_tree_nodes WHERE level = $1 AND position = $2",
                level, index,
            )
            return row["node_hash"] if row else None

    async def get_all_tree_nodes(self) -> List[Tuple[int, int, bytes]]:
        """Retrieve all internal Merkle tree nodes."""
        if not self.pool:
            raise RuntimeError("Storage not initialized")

        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT level, position, node_hash FROM scitt.merkle_tree_nodes"
            )
            return [(row["level"], row["position"], row["node_hash"]) for row in rows]

    async def store_frontier(self, frontier: List[bytes], tree_size: int) -> None:
        """Store the current Merkle frontier and tree size."""
        if not self.pool:
            raise RuntimeError("Storage not initialized")

        frontier_blob = b"".join(frontier)

        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO scitt.merkle_frontier (id, tree_size, frontier)
                VALUES (1, $1, $2)
                ON CONFLICT (id) DO UPDATE SET tree_size = $1, frontier = $2
                """,
                tree_size, frontier_blob,
            )

    async def get_frontier(self) -> Tuple[List[bytes], int]:
        """Retrieve the stored Merkle frontier and tree size."""
        if not self.pool:
            raise RuntimeError("Storage not initialized")

        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT tree_size, frontier FROM scitt.merkle_frontier WHERE id = 1"
            )
            if not row:
                return [], 0

            tree_size = row["tree_size"]
            frontier_blob = row["frontier"]

            frontier = []
            if frontier_blob:
                for i in range(0, len(frontier_blob), 32):
                    frontier.append(frontier_blob[i : i + 32])

            return frontier, tree_size

    async def store_tree_nodes_batch(
        self, nodes: List[Tuple[int, int, bytes]]
    ) -> None:
        """Store multiple tree nodes in a single transaction."""
        if not self.pool or not nodes:
            return

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await conn.executemany(
                    """
                    INSERT INTO scitt.merkle_tree_nodes (level, position, node_hash)
                    VALUES ($1, $2, $3)
                    ON CONFLICT (level, position) DO UPDATE SET node_hash = $3
                    """,
                    nodes,
                )

    async def close(self) -> None:
        """Close the connection pool."""
        if self.pool:
            await self.pool.close()
            self.pool = None
