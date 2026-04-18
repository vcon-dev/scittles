import cbor2
import time
from pycose.messages import Sign1Message
from pycose.headers import Algorithm, KID
from pycose.algorithms import Es256
from pycose.keys.ec2 import EC2Key
from pycose.keys.curves import P256
from typing import Optional, List, Dict, Any
import hashlib
from opentelemetry import trace

from ..observability.logging import get_logger
from ..observability.metrics import get_metrics

logger = get_logger(__name__)
metrics = get_metrics()
tracer = trace.get_tracer(__name__)


class ReceiptGenerator:
    """
    Generates COSE-signed receipts with RFC 9162 inclusion proofs.
    """

    # Custom COSE header labels
    VDS_LABEL = 395  # Verifiable Data Structure
    PROOFS_LABEL = 396  # Proofs
    CLAIMS_LABEL = 15  # Claims

    # Proof types
    INCLUSION_PROOF_LABEL = -1

    def __init__(self, signing_key: EC2Key, service_id: str):
        """
        Initialize receipt generator.

        Args:
            signing_key: Private key for signing receipts
            service_id: Transparency service identifier (issuer)
        """
        self.signing_key = signing_key
        self.service_id = service_id

    @staticmethod
    def generate_signing_key() -> EC2Key:
        """Generate a new ES256 signing key."""
        return EC2Key.generate_key(crv=P256)

    def create_receipt(
        self,
        statement_hash: bytes,
        root_hash: bytes,
        leaf_index: int,
        tree_size: int,
        inclusion_proof: List[bytes],
        issuer: Optional[str] = None,
        subject: Optional[str] = None,
    ) -> bytes:
        """
        Create a COSE receipt with inclusion proof.

        Per draft-ietf-cose-merkle-tree-proofs, the detached payload is the
        Merkle root hash (not the statement hash). This forces verifiers to
        recompute the root from the inclusion proof before checking the signature,
        which authenticates the proof despite it living in the unprotected header.

        Args:
            statement_hash: Hash of the original signed statement (used as entry ID)
            root_hash: Merkle tree root hash at registration time (detached payload)
            leaf_index: Position in the tree
            tree_size: Size of the tree at time of proof
            inclusion_proof: List of sibling hashes for proof
            issuer: Original statement issuer
            subject: Original statement subject

        Returns:
            COSE_Sign1 receipt bytes
        """
        start_time = time.time()
        entry_id = statement_hash.hex()

        with tracer.start_as_current_span("receipt.create") as span:
            span.set_attribute("receipt.entry_id", entry_id)
            span.set_attribute("receipt.leaf_index", leaf_index)
            span.set_attribute("receipt.tree_size", tree_size)
            span.set_attribute("receipt.proof_length", len(inclusion_proof))
            if issuer:
                span.set_attribute("receipt.issuer", issuer)
            if subject:
                span.set_attribute("receipt.subject", subject)

            try:
                # Build protected header
                protected_header = {
                    Algorithm: Es256,  # ES256
                    KID: self.signing_key.kid if self.signing_key.kid else b"ts-key",
                }

                # Add verifiable data structure info
                protected_header[self.VDS_LABEL] = 1  # RFC 9162 SHA-256

                # Add claims
                claims = {
                    1: self.service_id,  # issuer (iss)
                }
                if issuer:
                    claims[1] = issuer
                if subject:
                    claims[2] = subject  # subject (sub)

                protected_header[self.CLAIMS_LABEL] = claims

                # Build unprotected header with proofs
                unprotected_header = {
                    self.PROOFS_LABEL: {
                        self.INCLUSION_PROOF_LABEL: [
                            cbor2.dumps([tree_size, leaf_index, inclusion_proof])
                        ]
                    }
                }

                # Create COSE Sign1 with detached payload (null)
                msg = Sign1Message(
                    phdr=protected_header,
                    uhdr=unprotected_header,
                    payload=None,  # Detached payload per SCITT spec
                )

                # Sign the message
                msg.key = self.signing_key

                # Encode with Merkle root as detached payload per spec.
                # Verifier recomputes root from the inclusion proof and checks
                # that the signature matches — this authenticates the proof.
                cose_bytes = msg.encode(detached_payload=root_hash)

                duration = time.time() - start_time
                metrics.receipt_generation_duration.record(duration)
                metrics.receipt_generation_count.add(1)

                logger.debug(
                    "receipt_created",
                    entry_id=entry_id,
                    leaf_index=leaf_index,
                    tree_size=tree_size,
                    duration_seconds=duration,
                )

                return cose_bytes

            except Exception as e:
                duration = time.time() - start_time
                metrics.receipt_error_count.add(1)
                span.record_exception(e)
                logger.exception(
                    "receipt_creation_failed",
                    entry_id=entry_id,
                    error=str(e),
                )
                raise

    @staticmethod
    def parse_receipt(receipt_bytes: bytes) -> Dict[str, Any]:
        """
        Parse a COSE receipt to extract metadata.

        Args:
            receipt_bytes: COSE_Sign1 receipt

        Returns:
            Dictionary with receipt metadata
        """
        msg = Sign1Message.decode(receipt_bytes)

        # Extract protected header
        protected = msg.phdr

        # Extract proofs from unprotected header
        unprotected = msg.uhdr
        proofs = unprotected.get(ReceiptGenerator.PROOFS_LABEL, {})
        inclusion_proofs_raw = proofs.get(ReceiptGenerator.INCLUSION_PROOF_LABEL, [])

        inclusion_proofs = []
        for proof_bytes in inclusion_proofs_raw:
            tree_size, leaf_index, proof_path = cbor2.loads(proof_bytes)
            inclusion_proofs.append(
                {"tree_size": tree_size, "leaf_index": leaf_index, "proof": proof_path}
            )

        # Extract claims
        claims = protected.get(ReceiptGenerator.CLAIMS_LABEL, {})

        return {
            "algorithm": protected.get(Algorithm),
            "kid": protected.get(KID),
            "vds": protected.get(ReceiptGenerator.VDS_LABEL),
            "claims": claims,
            "inclusion_proofs": inclusion_proofs,
            "payload": msg.payload,
        }


class StatementValidator:
    """
    Validates COSE Signed Statements.
    """

    @staticmethod
    def extract_statement_hash(cose_sign1: bytes) -> bytes:
        """
        Extract hash from a COSE Signed Statement.

        For statements with detached payloads, this reads the payload hash.
        For embedded payloads, this computes the hash.

        Args:
            cose_sign1: COSE_Sign1 message

        Returns:
            SHA-256 hash of the statement
        """
        msg = Sign1Message.decode(cose_sign1)

        # Check if payload is present or detached
        if msg.payload:
            # Embedded payload - hash it
            return hashlib.sha256(msg.payload).digest()
        else:
            # Detached payload - look for hash in protected header
            protected = msg.phdr

            # Custom header for payload hash (label 258)
            payload_hash = protected.get(258)
            if payload_hash:
                return payload_hash

            # Otherwise, hash the entire COSE structure
            return hashlib.sha256(cose_sign1).digest()

    @staticmethod
    def extract_metadata(cose_sign1: bytes) -> Dict[str, Any]:
        """
        Extract metadata from a COSE Signed Statement.

        Args:
            cose_sign1: COSE_Sign1 message

        Returns:
            Dictionary with issuer, subject, content_type, etc.
        """
        msg = Sign1Message.decode(cose_sign1)
        protected = msg.phdr

        # Extract common fields
        metadata = {
            "algorithm": protected.get(Algorithm),
            "kid": protected.get(KID),
        }

        # Check for SCITT-specific headers
        # Type header (16): "application/example+cose"
        content_type = protected.get(16)
        if content_type:
            metadata["content_type"] = content_type

        # Payload hash algorithm (258)
        payload_hash_alg = protected.get(258)
        if payload_hash_alg:
            metadata["payload_hash_alg"] = payload_hash_alg

        # Preimage content type (259)
        preimage_type = protected.get(259)
        if preimage_type:
            metadata["preimage_content_type"] = preimage_type

        # Payload location (260) - for detached payloads
        payload_location = protected.get(260)
        if payload_location:
            metadata["payload_location"] = payload_location

        return metadata
