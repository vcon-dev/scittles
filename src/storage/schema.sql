-- Entries table: append-only log of signed statements
CREATE TABLE IF NOT EXISTS entries (
    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
    statement_hash BLOB NOT NULL UNIQUE,
    cose_sign1 BLOB NOT NULL,
    issuer TEXT,
    subject TEXT,
    content_type TEXT,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    leaf_index INTEGER NOT NULL
);

-- Index for hash lookups
CREATE INDEX IF NOT EXISTS idx_statement_hash ON entries(statement_hash);
CREATE INDEX IF NOT EXISTS idx_leaf_index ON entries(leaf_index);

-- Merkle tree nodes for inclusion proof generation (legacy)
CREATE TABLE IF NOT EXISTS merkle_nodes (
    tree_size INTEGER NOT NULL,
    node_position INTEGER NOT NULL,
    node_hash BLOB NOT NULL,
    PRIMARY KEY (tree_size, node_position)
);

-- Internal Merkle tree nodes keyed by (level, position) for O(log n) operations
CREATE TABLE IF NOT EXISTS merkle_tree_nodes (
    level INTEGER NOT NULL,
    position INTEGER NOT NULL,
    node_hash BLOB NOT NULL,
    PRIMARY KEY (level, position)
);

-- Merkle frontier: compact representation of the tree state
CREATE TABLE IF NOT EXISTS merkle_frontier (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    tree_size INTEGER NOT NULL DEFAULT 0,
    frontier BLOB NOT NULL DEFAULT X''
);

-- Service configuration and state
CREATE TABLE IF NOT EXISTS service_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert initial state
INSERT OR IGNORE INTO service_state (key, value)
VALUES ('tree_size', '0');

-- Pending registrations for async operations
CREATE TABLE IF NOT EXISTS pending_registrations (
    operation_id TEXT PRIMARY KEY,
    statement_hash BLOB NOT NULL,
    cose_sign1 BLOB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);
