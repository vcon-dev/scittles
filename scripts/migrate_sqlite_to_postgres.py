#!/usr/bin/env python3
"""
Migrate SCITTLEs data from SQLite to PostgreSQL.

Reads all entries from the existing SQLite database, inserts them into PostgreSQL
in batches, and rebuilds the Merkle tree incrementally using the O(log n) builder.

Usage:
    python scripts/migrate_sqlite_to_postgres.py \
        --sqlite-path /app/data/transparency.db \
        --postgres-url postgresql://postgres:PASSWORD@supabase-db:5432/postgres \
        [--batch-size 1000]
"""

import argparse
import asyncio
import sqlite3
import sys
import time

# Add parent dir to path so we can import src
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))

import asyncpg
from src.core.merkle import MerkleTreeBuilder, MerkleTree


async def migrate(sqlite_path: str, postgres_url: str, batch_size: int = 1000):
    print(f"Migration: SQLite ({sqlite_path}) → PostgreSQL")
    print(f"Batch size: {batch_size}")

    # Connect to SQLite (synchronous — it's read-only)
    sqlite_conn = sqlite3.connect(sqlite_path)
    sqlite_conn.row_factory = sqlite3.Row

    # Count entries
    cursor = sqlite_conn.execute("SELECT COUNT(*) FROM entries")
    total = cursor.fetchone()[0]
    print(f"Total entries in SQLite: {total}")

    if total == 0:
        print("Nothing to migrate.")
        return

    # Connect to PostgreSQL
    pg_pool = await asyncpg.create_pool(dsn=postgres_url, min_size=2, max_size=5)

    # Create schema
    async with pg_pool.acquire() as conn:
        await conn.execute("""
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
        """)

    # Check if there's existing data in postgres
    async with pg_pool.acquire() as conn:
        pg_count = await conn.fetchval("SELECT COUNT(*) FROM scitt.entries")
        if pg_count > 0:
            print(f"WARNING: PostgreSQL already has {pg_count} entries.")
            print("Skipping entries that already exist (by statement_hash).")

    # Build Merkle tree incrementally
    builder = MerkleTreeBuilder()
    migrated = 0
    skipped = 0
    start_time = time.time()

    # Read entries in leaf_index order
    cursor = sqlite_conn.execute(
        "SELECT statement_hash, cose_sign1, issuer, subject, content_type, leaf_index, registered_at "
        "FROM entries ORDER BY leaf_index ASC"
    )

    batch = []
    for row in cursor:
        statement_hash = bytes(row["statement_hash"])
        cose_sign1 = bytes(row["cose_sign1"])
        issuer = row["issuer"]
        subject = row["subject"]
        content_type = row["content_type"]
        leaf_index = row["leaf_index"]

        # Add to Merkle tree
        builder._add_leaf_internal(statement_hash)

        batch.append((statement_hash, cose_sign1, issuer, subject, content_type, leaf_index))

        if len(batch) >= batch_size:
            inserted, skip = await _insert_batch(pg_pool, batch)
            migrated += inserted
            skipped += skip
            batch = []

            elapsed = time.time() - start_time
            rate = migrated / elapsed if elapsed > 0 else 0
            print(f"  Migrated {migrated}/{total} entries ({rate:.0f}/s)...")

    # Final batch
    if batch:
        inserted, skip = await _insert_batch(pg_pool, batch)
        migrated += inserted
        skipped += skip

    elapsed = time.time() - start_time
    print(f"\nEntries migrated: {migrated}, skipped (already exist): {skipped}")
    print(f"Time: {elapsed:.1f}s ({migrated / elapsed:.0f} entries/s)")

    # Persist Merkle tree nodes and frontier
    print(f"\nPersisting Merkle tree ({len(builder._nodes)} nodes, frontier size {len(builder._frontier)})...")
    node_start = time.time()

    nodes = [(level, idx, h) for (level, idx), h in builder._nodes.items()]
    # Insert nodes in batches
    for i in range(0, len(nodes), batch_size):
        batch_nodes = nodes[i : i + batch_size]
        async with pg_pool.acquire() as conn:
            async with conn.transaction():
                await conn.executemany(
                    """
                    INSERT INTO scitt.merkle_tree_nodes (level, position, node_hash)
                    VALUES ($1, $2, $3)
                    ON CONFLICT (level, position) DO UPDATE SET node_hash = $3
                    """,
                    batch_nodes,
                )

    # Store frontier
    frontier_blob = b"".join(builder._frontier)
    async with pg_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO scitt.merkle_frontier (id, tree_size, frontier)
            VALUES (1, $1, $2)
            ON CONFLICT (id) DO UPDATE SET tree_size = $1, frontier = $2
            """,
            builder._tree_size, frontier_blob,
        )

        # Update tree_size in service_state
        await conn.execute(
            "UPDATE scitt.service_state SET value = $1, updated_at = NOW() WHERE key = 'tree_size'",
            str(builder._tree_size),
        )

    node_elapsed = time.time() - node_start
    print(f"Merkle tree persisted in {node_elapsed:.1f}s")

    # Verify
    async with pg_pool.acquire() as conn:
        pg_count = await conn.fetchval("SELECT COUNT(*) FROM scitt.entries")
        pg_tree_size = await conn.fetchval(
            "SELECT value FROM scitt.service_state WHERE key = 'tree_size'"
        )
        pg_node_count = await conn.fetchval("SELECT COUNT(*) FROM scitt.merkle_tree_nodes")

    print(f"\nVerification:")
    print(f"  SQLite entries:     {total}")
    print(f"  PostgreSQL entries: {pg_count}")
    print(f"  Tree size:          {pg_tree_size}")
    print(f"  Tree nodes:         {pg_node_count}")
    print(f"  Builder tree_size:  {builder._tree_size}")
    print(f"  Builder nodes:      {len(builder._nodes)}")

    if int(pg_tree_size) == total and pg_count == total:
        print("\n✓ Migration successful!")
    else:
        print("\n✗ COUNT MISMATCH — verify data integrity!")

    sqlite_conn.close()
    await pg_pool.close()


async def _insert_batch(pool, batch):
    """Insert a batch of entries, skipping duplicates."""
    inserted = 0
    skipped = 0

    async with pool.acquire() as conn:
        async with conn.transaction():
            for statement_hash, cose_sign1, issuer, subject, content_type, leaf_index in batch:
                try:
                    await conn.execute(
                        """
                        INSERT INTO scitt.entries
                        (statement_hash, cose_sign1, issuer, subject, content_type, leaf_index)
                        VALUES ($1, $2, $3, $4, $5, $6)
                        ON CONFLICT (statement_hash) DO NOTHING
                        """,
                        statement_hash, cose_sign1, issuer, subject, content_type, leaf_index,
                    )
                    inserted += 1
                except Exception:
                    skipped += 1

    return inserted, skipped


def main():
    parser = argparse.ArgumentParser(description="Migrate SCITTLEs from SQLite to PostgreSQL")
    parser.add_argument("--sqlite-path", required=True, help="Path to SQLite database")
    parser.add_argument("--postgres-url", required=True, help="PostgreSQL connection URL")
    parser.add_argument("--batch-size", type=int, default=1000, help="Batch size for inserts")
    args = parser.parse_args()

    asyncio.run(migrate(args.sqlite_path, args.postgres_url, args.batch_size))


if __name__ == "__main__":
    main()
