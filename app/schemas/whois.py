from pydantic import BaseModel, Field, field_validator
from app.utils.validation import validate_domain_only
from app.schemas.common import ErrorDetail

class WhoisLookupRequest(BaseModel):
    domain: str = Field(..., description="The public domain name to query WHOIS info for", examples=["example.com"])

    @field_validator("domain")
    @classmethod
    def validate_whois_domain(cls, val: str) -> str:
        return validate_domain_only(val)

class WhoisRecord(BaseModel):
    domain: str = Field(..., description="The queried domain name")
    registrar: str | None = Field(None, description="Domain Registrar")
    creation_date: str | None = Field(None, description="Creation/Registration Date")
    expiration_date: str | None = Field(None, description="Expiration Date")
    name_servers: list[str] = Field(default_factory=list, description="Name Servers list")
    status: str | None = Field(None, description="Domain registry status")
    raw: str = Field(..., description="Raw WHOIS response content")

class WhoisLookupResponse(BaseModel):
    success: bool = Field(True, description="Indicates if query succeeded")
    domain: str = Field(..., description="The queried domain name")
    record: WhoisRecord | None = Field(None, description="The normalized WHOIS record")
    error: ErrorDetail | None = Field(None, description="Detailed error information, if failed")
