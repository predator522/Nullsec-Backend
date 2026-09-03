from pydantic import BaseModel, Field, field_validator
from app.utils.validation import validate_domain_only
from app.schemas.common import ErrorDetail

class DNSLookupRequest(BaseModel):
    domain: str = Field(..., description="The public domain name to query", examples=["example.com"])

    @field_validator("domain")
    @classmethod
    def validate_dns_domain(cls, val: str) -> str:
        return validate_domain_only(val)

class DNSRecords(BaseModel):
    A: list[str] = Field(default_factory=list, description="A IPv4 address records")
    AAAA: list[str] = Field(default_factory=list, description="AAAA IPv6 address records")
    MX: list[str] = Field(default_factory=list, description="Mail exchanger records")
    NS: list[str] = Field(default_factory=list, description="Name server records")
    TXT: list[str] = Field(default_factory=list, description="Text records")
    CNAME: list[str] = Field(default_factory=list, description="Canonical name records")
    SOA: list[str] = Field(default_factory=list, description="Start of Authority records")

class DNSLookupResponse(BaseModel):
    success: bool = Field(True, description="Indicates if the query was successful")
    domain: str = Field(..., description="The queried domain name")
    records: DNSRecords = Field(..., description="Grouped collection of DNS record results")
    error: ErrorDetail | None = Field(None, description="Detailed error information, if failed")
