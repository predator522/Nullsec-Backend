from pydantic import BaseModel, Field, field_validator
from app.utils.validation import validate_domain_or_ip, validate_port
from app.schemas.common import ErrorDetail

class TlsInspectRequest(BaseModel):
    target: str = Field(..., description="The public domain or IP address to inspect", examples=["example.com"])
    port: int = Field(443, description="Target port number (1-65535)")

    @field_validator("target")
    @classmethod
    def validate_tls_target(cls, val: str) -> str:
        return validate_domain_or_ip(val)

    @field_validator("port")
    @classmethod
    def validate_tls_port(cls, val: int) -> int:
        return validate_port(val)

class TlsCertificateInfo(BaseModel):
    subject: dict[str, str] = Field(default_factory=dict, description="Certificate Subject attributes")
    issuer: dict[str, str] = Field(default_factory=dict, description="Certificate Issuer attributes")
    valid_from: str | None = Field(None, description="Start date of certificate validity")
    valid_to: str | None = Field(None, description="Expiration date of certificate")
    is_expired: bool = Field(False, description="Whether the certificate is currently expired")
    serial_number: str | None = Field(None, description="Certificate serial number")
    sans: list[str] = Field(default_factory=list, description="Subject Alternative Names (SANs)")
    tls_version: str | None = Field(None, description="Negotiated TLS Protocol Version")

class TlsInspectResponse(BaseModel):
    success: bool = Field(True, description="Indicates if analysis succeeded")
    target: str = Field(..., description="The analyzed target")
    certificate: TlsCertificateInfo | None = Field(None, description="Inspected certificate metadata")
    error: ErrorDetail | None = Field(None, description="Detailed error information, if failed")
