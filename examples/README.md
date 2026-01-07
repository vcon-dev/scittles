# Scittles Client Examples

This directory contains example scripts demonstrating how to integrate with the Scittles transparency service.

## Prerequisites

Install the required dependencies:

```bash
pip install httpx pycose cbor2
```

Or install from the project requirements:

```bash
pip install -r requirements.txt
```

## Examples

### client_example.py

A comprehensive example demonstrating the full workflow:

1. **Get service configuration** - Discover service endpoints
2. **Generate signing key** - Create a P-256 EC2 key for signing
3. **Create signed statement** - Sign artifact metadata as COSE Sign1
4. **Register statement** - Submit to transparency service
5. **Retrieve receipt** - Get the transparency receipt
6. **Retrieve statement** - Get the original signed statement
7. **Verify receipt** - Basic signature verification

#### Usage

Make sure the Scittles service is running:

```bash
# Using Docker
docker-compose up -d

# Or locally
python -m src.main
```

Then run the example:

```bash
python examples/client_example.py
```

#### Expected Output

```
======================================================================
Scittles Transparency Service Integration Example
======================================================================

Step 1: Getting service configuration...
  Service URL: https://transparency.example
  Registration endpoint: https://transparency.example/entries
  Receipt endpoint: https://transparency.example/entries/{entry_id}

Step 2: Generating signing key...
  Generated P-256 EC2 key

Step 3: Creating signed statement...
  Payload: {'hash': 'sha256:abc123...', 'name': 'example-package', 'timestamp': '2024-01-07T12:00:00Z', 'type': 'artifact', 'version': '1.0.0'}
  Created COSE Sign1 message (XXX bytes)

Step 4: Registering statement with transparency service...
  Success! Entry ID: abc123def456...
  Receipt size: XXX bytes

Step 5: Retrieving receipt...
  Retrieved receipt (XXX bytes)

Step 6: Retrieving original signed statement...
  Retrieved statement (XXX bytes)
  Statement matches original!

Step 7: Verifying receipt...
  Receipt signature is valid!

======================================================================
Example completed successfully!
======================================================================

Entry ID: abc123def456...
View receipt: http://localhost:8000/entries/abc123def456...
View statement: http://localhost:8000/signed-statements/abc123def456...
```

## Integration Patterns

### Basic Registration

```python
import httpx
from pycose.messages import Sign1Message
from pycose.keys.ec2 import EC2Key
from pycose.keys.curves import P256
from pycose.algorithms import Es256

# Create key and sign payload
key = EC2Key.generate_key(crv=P256)
msg = Sign1Message(phdr={Algorithm: Es256}, payload=b"Your payload")
msg.key = key
cose_sign1 = msg.encode()

# Register with service
async with httpx.AsyncClient() as client:
    response = await client.post(
        "http://localhost:8000/entries",
        content=cose_sign1,
        headers={"Content-Type": "application/cose"},
    )
    entry_id = response.headers["Location"].split("/")[-1]
    receipt = response.content
```

### Batch Registration

```python
async def register_multiple_statements(statements: list[bytes], base_url: str):
    """Register multiple statements."""
    async with httpx.AsyncClient() as client:
        results = []
        for statement in statements:
            response = await client.post(
                f"{base_url}/entries",
                content=statement,
                headers={"Content-Type": "application/cose"},
            )
            if response.status_code == 201:
                entry_id = response.headers["Location"].split("/")[-1]
                results.append((entry_id, response.content))
        return results
```

### Receipt Verification

```python
from pycose.messages import Sign1Message

def verify_receipt(receipt_bytes: bytes, service_key: EC2Key) -> bool:
    """Verify a receipt signature."""
    receipt_msg = Sign1Message.decode(receipt_bytes)
    receipt_msg.key = service_key
    return receipt_msg.verify_signature()
```

## API Endpoints

- `GET /.well-known/transparency-configuration` - Get service configuration (CBOR)
- `POST /entries` - Register a signed statement (COSE Sign1)
- `GET /entries/{entry_id}` - Get receipt for an entry (COSE Sign1)
- `GET /signed-statements/{entry_id}` - Get original signed statement (COSE Sign1)
- `GET /metrics` - Prometheus metrics endpoint

## Error Handling

The service returns errors in RFC 9290 Concise Problem Details format (CBOR):

```python
import cbor2

try:
    response = await client.post(...)
    response.raise_for_status()
except httpx.HTTPStatusError as e:
    error = cbor2.loads(e.response.content)
    # error is a dict with keys -1 (title) and -2 (detail)
    print(f"Error: {error.get(-1)} - {error.get(-2)}")
```

## See Also

- [SCRAPI Specification](https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/)
- [COSE Specification](https://datatracker.ietf.org/doc/html/rfc9052)
- [Main README](../README.md)

