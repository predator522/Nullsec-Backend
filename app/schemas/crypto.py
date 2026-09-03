from pydantic import BaseModel, Field, field_validator
from app.schemas.common import ErrorDetail

# --- HASHING ---

class HashRequest(BaseModel):
    data: str = Field(..., description="String data to hash")
    algorithm: str = Field("sha256", description="Algorithm (md5, sha1, sha256, sha384, sha512)")

    @field_validator("algorithm")
    @classmethod
    def validate_algo(cls, val: str) -> str:
        algo = val.strip().lower()
        if algo not in ("md5", "sha1", "sha256", "sha384", "sha512"):
            raise ValueError("Algorithm must be md5, sha1, sha256, sha384, or sha512")
        return algo

class HashResponse(BaseModel):
    success: bool = Field(True)
    algorithm: str = Field(...)
    hash_result: str = Field(...)
    error: ErrorDetail | None = Field(None)


# --- BASE64 ---

class Base64Request(BaseModel):
    data: str = Field(..., description="Data to encode or decode")
    operation: str = Field("encode", description="Operation (encode or decode)")

    @field_validator("operation")
    @classmethod
    def validate_op(cls, val: str) -> str:
        op = val.strip().lower()
        if op not in ("encode", "decode"):
            raise ValueError("Operation must be encode or decode")
        return op

class Base64Response(BaseModel):
    success: bool = Field(True)
    operation: str = Field(...)
    result: str = Field(...)
    error: ErrorDetail | None = Field(None)


# --- URL ENCODING ---

class UrlRequest(BaseModel):
    data: str = Field(...)
    operation: str = Field("encode")

    @field_validator("operation")
    @classmethod
    def validate_url_op(cls, val: str) -> str:
        op = val.strip().lower()
        if op not in ("encode", "decode"):
            raise ValueError("Operation must be encode or decode")
        return op

class UrlResponse(BaseModel):
    success: bool = Field(True)
    operation: str = Field(...)
    result: str = Field(...)
    error: ErrorDetail | None = Field(None)


# --- HEX CONVERSION ---

class HexRequest(BaseModel):
    data: str = Field(...)
    operation: str = Field("encode")

    @field_validator("operation")
    @classmethod
    def validate_hex_op(cls, val: str) -> str:
        op = val.strip().lower()
        if op not in ("encode", "decode"):
            raise ValueError("Operation must be encode or decode")
        return op

class HexResponse(BaseModel):
    success: bool = Field(True)
    operation: str = Field(...)
    result: str = Field(...)
    error: ErrorDetail | None = Field(None)


# --- JWT DECODER ---

class JwtInspectRequest(BaseModel):
    token: str = Field(..., description="The JWT token string to safely decode")

class JwtAnalysis(BaseModel):
    header: dict = Field(default_factory=dict, description="Decoded JWT Header claims")
    payload: dict = Field(default_factory=dict, description="Decoded JWT Payload claims")
    signature_hex: str | None = Field(None, description="Extracted JWT signature segment")
    verification_disclaimer: str = Field(
        "DECODED — This inspection is local and does NOT prove token authenticity or cryptographic validity."
    )

class JwtInspectResponse(BaseModel):
    success: bool = Field(True)
    analysis: JwtAnalysis | None = Field(None)
    error: ErrorDetail | None = Field(None)
