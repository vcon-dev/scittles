# Scittles

An IETF SCRAPI-compatible transparency service implementation using SQLite as the immutable storage backend.

Scittles implements the [SCITT (Supply Chain Integrity, Transparency and Trust)](https://datatracker.ietf.org/wg/scitt/about/) architecture, providing a distributed ledger service for registering and verifying cryptographically signed statements with Merkle tree inclusion proofs.

## Features

- **SCRAPI-Compatible REST API**: Full implementation of the SCRAPI transparency service endpoints
- **RFC 9162 Merkle Trees**: Cryptographic inclusion proofs with domain separation
- **COSE Sign1 Receipts**: ES256-signed receipts with verifiable data structure proofs
- **SQLite Backend**: Lightweight, append-only storage with async support
- **Zero External Dependencies**: No external databases or services required

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/vcon-dev/scittles.git
cd scittles

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e .

# For development
pip install -e ".[dev]"
```

### Running the Service

```bash
# Start the transparency service
python -m src.main

# Or using the entry point
scittles
```

The service starts on `http://localhost:8000` by default.

### Docker Deployment

Scittles can be run as a Docker container for easy deployment and isolation.

#### Quick Start with Docker Compose

```bash
# Build and start the service
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the service
docker-compose down
```

The service will be available at `http://localhost:8000`. The database is persisted in the `./data` directory on the host.

#### Building the Docker Image

```bash
# Build the image
docker build -t scittles:latest .

# Run the container
docker run -d \
  --name scittles \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  -e SCITT_SERVICE_URL=https://your-service-url.example \
  scittles:latest
```

#### Environment Variables

Configure the service using environment variables (prefix `SCITT_`):

**Core Configuration:**
- `SCITT_DB_PATH` - Database file path (default: `/app/data/transparency.db`)
- `SCITT_SERVICE_URL` - Public service URL (required for production)
- `SCITT_HOST` - Bind address (default: `0.0.0.0`)
- `SCITT_PORT` - Server port (default: `8000`)

**Observability Configuration:**
- `SCITT_LOG_LEVEL` - Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR` (default: `INFO`)
- `SCITT_LOG_FORMAT` - Log format: `json` or `text` (default: `json` in Docker)
- `SCITT_OTEL_ENABLED` - Enable OpenTelemetry (default: `true`)
- `SCITT_OTEL_SERVICE_NAME` - Service name for traces (default: `scittles`)
- `SCITT_OTEL_EXPORTER` - Comma-separated exporters: `console`, `otlp`, `prometheus` (default: `prometheus,console`)
- `SCITT_OTEL_ENDPOINT` - OTLP endpoint URL (e.g., `http://otel-collector:4317`)
- `SCITT_OTEL_HEADERS` - OTLP headers as comma-separated `key=value` pairs
- `SCITT_PROMETHEUS_PORT` - Prometheus port configuration (metrics served at `/metrics` on main port)

#### Prometheus Metrics

When the Prometheus exporter is enabled (default in Docker), metrics are available at:

```bash
curl http://localhost:8000/metrics
```

The metrics endpoint exposes HTTP, database, Merkle tree, receipt, and entry registration metrics compatible with Prometheus scraping.

#### Health Checks

The service includes a health check endpoint:

```bash
curl http://localhost:8000/.well-known/transparency-configuration
```

Docker Compose automatically configures health checks using this endpoint.

#### Volume Persistence

The database is stored in `./data/transparency.db` on the host, ensuring data persists across container restarts. Make sure to back up this directory in production.

For more detailed Docker documentation, see [docker/README.md](docker/README.md).

### Configuration

Configure via environment variables (prefix `SCITT_`):

| Variable | Default | Description |
|----------|---------|-------------|
| `SCITT_DATABASE_PATH` | `scittles.db` | SQLite database file path |
| `SCITT_SERVICE_URL` | `https://transparency.example` | Public service URL |
| `SCITT_HOST` | `0.0.0.0` | Server bind address |
| `SCITT_PORT` | `8000` | Server port |

## API Reference

### Service Discovery

```bash
GET /.well-known/transparency-configuration
```

Returns CBOR-encoded service configuration including registration and receipt endpoints.

### Register Signed Statement

```bash
POST /entries
Content-Type: application/cose

<COSE_Sign1 message>
```

Registers a COSE Sign1 signed statement. Returns:
- `201 Created`: Registration successful, receipt in response body
- `303 See Other`: Registration pending (async processing)
- `400 Bad Request`: Invalid statement or already registered

Response includes `Location` header with the entry URL.

### Retrieve Receipt

```bash
GET /entries/{entry_id}
```

Returns a fresh COSE receipt with the current Merkle tree state and inclusion proof.

### Retrieve Signed Statement

```bash
GET /signed-statements/{entry_id}
```

Returns the original COSE Sign1 signed statement.

## Architecture

```
scittles/
├── src/
│   ├── api/           # FastAPI REST endpoints
│   │   ├── endpoints.py
│   │   └── models.py
│   ├── core/          # Cryptographic operations
│   │   ├── merkle.py      # RFC 9162 Merkle tree
│   │   ├── receipts.py    # COSE receipt generation
│   │   └── verification.py
│   ├── storage/       # Persistence layer
│   │   ├── base.py        # Abstract interface
│   │   ├── sqlite_store.py
│   │   └── schema.sql
│   ├── config.py      # Configuration management
│   └── main.py        # Application entry point
├── examples/          # Client integration examples
│   ├── client_example.py
│   └── README.md
└── tests/             # Test suite
```

### Core Components

#### Merkle Tree (RFC 9162)

Implements binary Merkle trees with:
- Domain-separated hashing (0x00 for leaves, 0x01 for nodes)
- Inclusion proof generation and verification
- Support for incomplete trees (non-power-of-2 sizes)

#### Receipt Generator

Creates COSE Sign1 receipts containing:
- Verifiable Data Structure identifier (RFC 9162)
- Inclusion proofs in unprotected header
- Claims (issuer, subject) in protected header

#### Storage Backends

**SQLite** (default): Append-only log with entries table, Merkle node cache, and service state persistence.

**PostgreSQL**: Production backend using asyncpg for async database access. Configure via:

```bash
SCITT_STORAGE_BACKEND=postgres
SCITT_POSTGRES_URL=postgresql://user:pass@host:5432/dbname
```

#### Database Instrumentation

When OpenTelemetry is enabled, the asyncpg driver is auto-instrumented via `opentelemetry-instrumentation-asyncpg`. All PostgreSQL queries appear as `db.query` spans in traces, providing visibility into query latency and connection pool behavior. Install:

```bash
pip install opentelemetry-instrumentation-asyncpg
```

The instrumentor is activated automatically during OTEL initialization (`src/observability/otel.py`).

## Usage Examples

See the [`examples/`](examples/) directory for complete working examples demonstrating integration with the Scittles service.

### Quick Example

```python
import httpx
from pycose.messages import Sign1Message
from pycose.headers import Algorithm
from pycose.keys.ec2 import EC2Key
from pycose.keys.curves import P256

# Create a signed statement
key = EC2Key.generate_key(crv=P256)
msg = Sign1Message(
    phdr={Algorithm: -7},  # ES256
    payload=b"My artifact metadata"
)
msg.key = key
cose_bytes = msg.encode()

# Register with transparency service
async with httpx.AsyncClient() as client:
    response = await client.post(
        "http://localhost:8000/entries",
        content=cose_bytes,
        headers={"Content-Type": "application/cose"}
    )

    if response.status_code == 201:
        entry_id = response.headers["Location"].split("/")[-1]
        receipt = response.content
        print(f"Registered: {entry_id}")
```

### Running the Example Script

```bash
# Start the service (if not already running)
docker-compose up -d

# Run the example client
python3 examples/client_example.py
```

For more detailed examples and integration patterns, see [examples/README.md](examples/README.md).

### cURL Examples

```bash
# Get service configuration
curl http://localhost:8000/.well-known/transparency-configuration \
  -H "Accept: application/cbor" | python -c "import cbor2, sys; print(cbor2.loads(sys.stdin.buffer.read()))"

# Register a statement (assuming you have a COSE file)
curl -X POST http://localhost:8000/entries \
  -H "Content-Type: application/cose" \
  --data-binary @statement.cose

# Retrieve a receipt
curl http://localhost:8000/entries/<entry_id> \
  -H "Accept: application/cose" -o receipt.cose
```

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=term-missing

# Run specific test file
pytest tests/test_merkle.py -v
```

### Code Quality

```bash
# Format code
black src tests

# Lint
ruff check src tests

# Type checking
mypy src
```

## Standards Compliance

- **SCRAPI**: [draft-ietf-scitt-scrapi](https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/)
- **RFC 9162**: Certificate Transparency Version 2.0 (Merkle trees)
- **RFC 9052**: CBOR Object Signing and Encryption (COSE)
- **RFC 9290**: Concise Problem Details for CoAP APIs

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
