from pydantic import BaseModel, Field, field_validator
from app.utils.validation import validate_domain_or_ip
from app.schemas.common import ErrorDetail

class IPAnalyzeRequest(BaseModel):
    target: str = Field(..., description="The public IP address or domain to analyze", examples=["8.8.8.8", "example.com"])

    @field_validator("target")
    @classmethod
    def validate_ip_target(cls, val: str) -> str:
        return validate_domain_or_ip(val)

class IPAnalysisResult(BaseModel):
    target: str = Field(..., description="The analyzed input")
    resolved_ip: str = Field(..., description="The resolved public IP address")
    ip_version: int = Field(..., description="IP protocol version (4 or 6)")
    asn: str | None = Field(None, description="Autonomous System Number (ASN)")
    isp: str | None = Field(None, description="Internet Service Provider (ISP)")
    country: str | None = Field(None, description="Country name")
    city: str | None = Field(None, description="City name")
    latitude: float | None = Field(None, description="Estimated latitude")
    longitude: float | None = Field(None, description="Estimated longitude")

class IPAnalyzeResponse(BaseModel):
    success: bool = Field(True, description="Indicates if query succeeded")
    target: str = Field(..., description="The analyzed target")
    analysis: IPAnalysisResult | None = Field(None, description="IP analysis information")
    error: ErrorDetail | None = Field(None, description="Detailed error information, if failed")
