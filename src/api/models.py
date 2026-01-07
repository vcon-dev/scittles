from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class TransparencyConfiguration(BaseModel):
    """Response for /.well-known/transparency-configuration"""

    issuer: str
    jwks_uri: Optional[str] = None
    registration_endpoint: str = "/entries"
    receipt_endpoint: str = "/entries/{entry_id}"


class RegistrationResponse(BaseModel):
    """Response for successful registration (201)"""

    entry_id: str
    location: str
    status: str = "registered"


class RegistrationPending(BaseModel):
    """Response for pending registration (303)"""

    location: str
    retry_after: Optional[int] = None


class ReceiptResponse(BaseModel):
    """Receipt metadata for clients"""

    entry_id: str
    statement_hash: str  # hex encoded
    leaf_index: int
    tree_size: int
    registered_at: datetime


class ErrorResponse(BaseModel):
    """CBOR Problem Details (RFC 9290) compatible error"""

    title: str = Field(..., description="Short error title")
    detail: str = Field(..., description="Detailed error message")
    instance: Optional[str] = None
