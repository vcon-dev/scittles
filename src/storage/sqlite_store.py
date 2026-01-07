import aiosqlite
from pathlib import Path
from typing import Optional
from .base import StorageBackend


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
        if not self.conn:
            raise RuntimeError("Storage not initialized")

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
        return tree_size

    async def get_entry_by_hash(self, statement_hash: bytes) -> Optional[dict]:
        """Retrieve an entry by its statement hash."""
        if not self.conn:
            raise RuntimeError("Storage not initialized")

        async with self.conn.execute(
            "SELECT * FROM entries WHERE statement_hash = ?", (statement_hash,)
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

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
        if not self.conn:
            raise RuntimeError("Storage not initialized")

        async with self.conn.execute(
            "SELECT value FROM service_state WHERE key = 'tree_size'"
        ) as cursor:
            row = await cursor.fetchone()
            return int(row[0]) if row else 0

    async def store_merkle_node(
        self, tree_size: int, position: int, node_hash: bytes
    ) -> None:
        """Store a Merkle tree node."""
        if not self.conn:
            raise RuntimeError("Storage not initialized")

        await self.conn.execute(
            """
            INSERT OR REPLACE INTO merkle_nodes (tree_size, node_position, node_hash)
            VALUES (?, ?, ?)
            """,
            (tree_size, position, node_hash),
        )
        await self.conn.commit()

    async def get_merkle_node(self, tree_size: int, position: int) -> Optional[bytes]:
        """Retrieve a Merkle tree node."""
        if not self.conn:
            raise RuntimeError("Storage not initialized")

        async with self.conn.execute(
            "SELECT node_hash FROM merkle_nodes WHERE tree_size = ? AND node_position = ?",
            (tree_size, position),
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else None

    async def close(self) -> None:
        """Close the database connection."""
        if self.conn:
            await self.conn.close()
            self.conn = None
