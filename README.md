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

#### SQLite Storage

Append-only log with:
- Entries table (statement hash, COSE message, metadata)
- Merkle node cache for efficient proof generation
- Service state persistence

## Usage Examples

### Python Client

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
