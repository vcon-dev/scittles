#!/usr/bin/env python3
"""
Example client demonstrating integration with Scittles transparency service.

This script shows how to:
1. Create a COSE Sign1 signed statement
2. Register it with the transparency service
3. Retrieve the receipt
4. Retrieve the original signed statement
5. Verify the receipt (basic verification)
"""

import asyncio
import httpx
import json
from pathlib import Path
from typing import Optional

from pycose.messages import Sign1Message
from pycose.headers import Algorithm, KID
from pycose.keys.ec2 import EC2Key
from pycose.keys.curves import P256
from pycose.algorithms import Es256
import cbor2


class ScittlesClient:
    """Client for interacting with Scittles transparency service."""

    def __init__(self, base_url: str = "http://localhost:8000"):
        """
        Initialize the client.

        Args:
            base_url: Base URL of the Scittles service
        """
        self.base_url = base_url.rstrip("/")
        self.client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        """Async context manager entry."""
        self.client = httpx.AsyncClient(timeout=30.0)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.client:
            await self.client.aclose()

    async def get_configuration(self) -> dict:
        """
        Get the transparency service configuration.

        Returns:
            Dictionary containing service configuration
        """
        response = await self.client.get(
            f"{self.base_url}/.well-known/transparency-configuration",
            headers={"Accept": "application/cbor"},
        )
        response.raise_for_status()
        return cbor2.loads(response.content)

    async def register_statement(self, cose_sign1: bytes) -> tuple[str, bytes]:
        """
        Register a signed statement with the transparency service.

        Args:
            cose_sign1: COSE Sign1 encoded message

        Returns:
            Tuple of (entry_id, receipt_bytes)
        """
        response = await self.client.post(
            f"{self.base_url}/entries",
            content=cose_sign1,
            headers={"Content-Type": "application/cose"},
        )

        if response.status_code == 201:
            # Extract entry ID from Location header
            location = response.headers.get("Location", "")
            entry_id = location.split("/")[-1] if "/" in location else ""
            receipt = response.content
            return entry_id, receipt
        else:
            # Try to decode error response
            try:
                error = cbor2.loads(response.content)
                raise Exception(f"Registration failed: {error}")
            except:
                response.raise_for_status()
                raise

    async def get_receipt(self, entry_id: str) -> bytes:
        """
        Retrieve a receipt for a registered entry.

        Args:
            entry_id: Hex-encoded entry ID

        Returns:
            COSE Sign1 encoded receipt
        """
        response = await self.client.get(
            f"{self.base_url}/entries/{entry_id}",
            headers={"Accept": "application/cose"},
        )
        response.raise_for_status()
        return response.content

    async def get_signed_statement(self, entry_id: str) -> bytes:
        """
        Retrieve the original signed statement.

        Args:
            entry_id: Hex-encoded entry ID

        Returns:
            Original COSE Sign1 encoded statement
        """
        response = await self.client.get(
            f"{self.base_url}/signed-statements/{entry_id}",
            headers={"Accept": "application/cose"},
        )
        response.raise_for_status()
        return response.content


def create_signed_statement(payload: bytes, key: EC2Key) -> bytes:
    """
    Create a COSE Sign1 signed statement.

    Args:
        payload: The payload to sign
        key: EC2Key for signing

    Returns:
        COSE Sign1 encoded message
    """
    # Create Sign1 message
    msg = Sign1Message(
        phdr={Algorithm: Es256},  # ES256 algorithm
        payload=payload,
    )

    # Set the signing key
    msg.key = key

    # Encode the message
    return msg.encode()


async def main():
    """Main example function."""
    print("=" * 70)
    print("Scittles Transparency Service Integration Example")
    print("=" * 70)
    print()

    # Initialize client
    async with ScittlesClient("http://localhost:8000") as client:
        # Step 1: Get service configuration
        print("Step 1: Getting service configuration...")
        try:
            config = await client.get_configuration()
            print(f"  Service URL: {config.get('issuer')}")
            print(f"  Registration endpoint: {config.get('registration_endpoint')}")
            print(f"  Receipt endpoint: {config.get('receipt_endpoint')}")
            print()
        except Exception as e:
            print(f"  Error: {e}")
            return

        # Step 2: Generate a signing key
        print("Step 2: Generating signing key...")
        key = EC2Key.generate_key(crv=P256)
        print(f"  Generated P-256 EC2 key")
        print()

        # Step 3: Create a signed statement
        print("Step 3: Creating signed statement...")
        # Example payload - could be artifact metadata, SBOM, etc.
        # Include timestamp to ensure unique statements on each run
        import datetime
        payload_data = {
            "type": "artifact",
            "name": "example-package",
            "version": "1.0.0",
            "hash": "sha256:abc123...",
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        }
        payload = json.dumps(payload_data, sort_keys=True).encode("utf-8")
        print(f"  Payload: {payload_data}")
        
        cose_sign1 = create_signed_statement(payload, key)
        print(f"  Created COSE Sign1 message ({len(cose_sign1)} bytes)")
        print()

        # Step 4: Register the statement
        print("Step 4: Registering statement with transparency service...")
        entry_id = None
        receipt = None
        try:
            entry_id, receipt = await client.register_statement(cose_sign1)
            print(f"  Success! Entry ID: {entry_id}")
            print(f"  Receipt size: {len(receipt)} bytes")
            print()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 400:
                # Try to decode error - might be duplicate registration
                try:
                    error = cbor2.loads(e.response.content)
                    if "Already Registered" in str(error.get(-1, "")):
                        print(f"  Statement already registered (this is expected if running multiple times)")
                        # Calculate entry ID from statement hash (same as service does)
                        # For embedded payloads, hash the payload
                        import hashlib
                        msg = Sign1Message.decode(cose_sign1)
                        if msg.payload:
                            statement_hash = hashlib.sha256(msg.payload).digest()
                        else:
                            statement_hash = hashlib.sha256(cose_sign1).digest()
                        entry_id = statement_hash.hex()
                        print(f"  Entry ID: {entry_id}")
                        # Get existing receipt
                        receipt = await client.get_receipt(entry_id)
                        print(f"  Retrieved existing receipt ({len(receipt)} bytes)")
                        print()
                    else:
                        raise
                except:
                    raise
            else:
                raise

        if entry_id is None:
            print("  Failed to register or retrieve entry ID")
            return

        # Step 5: Retrieve the receipt
        print("Step 5: Retrieving receipt...")
        receipt_retrieved = await client.get_receipt(entry_id)
        print(f"  Retrieved receipt ({len(receipt_retrieved)} bytes)")
        if receipt == receipt_retrieved:
            print("  Receipt matches original (may differ if tree has grown)")
        print()

        # Step 6: Retrieve the original signed statement
        print("Step 6: Retrieving original signed statement...")
        statement_retrieved = await client.get_signed_statement(entry_id)
        print(f"  Retrieved statement ({len(statement_retrieved)} bytes)")
        if statement_retrieved == cose_sign1:
            print("  Statement matches original!")
        else:
            print("  Warning: Statement differs from original")
        print()

        # Step 7: Basic receipt verification
        print("Step 7: Verifying receipt...")
        try:
            receipt_msg = Sign1Message.decode(receipt)
            # Receipts use detached payload (empty payload)
            # The statement hash is embedded in the receipt claims
            receipt_msg.key = key  # Use same key for verification
            # Verify signature with empty payload (detached)
            receipt_msg.payload = b""
            if receipt_msg.verify_signature():
                print("  Receipt signature is valid!")
                print("  Note: Full receipt verification requires checking Merkle proof")
            else:
                print("  Warning: Receipt signature verification failed")
        except Exception as e:
            print(f"  Note: Receipt verification requires service public key")
            print(f"  Error details: {e}")
        print()

        print("=" * 70)
        print("Example completed successfully!")
        print("=" * 70)
        print()
        print(f"Entry ID: {entry_id}")
        print(f"View receipt: {client.base_url}/entries/{entry_id}")
        print(f"View statement: {client.base_url}/signed-statements/{entry_id}")


if __name__ == "__main__":
    asyncio.run(main())

