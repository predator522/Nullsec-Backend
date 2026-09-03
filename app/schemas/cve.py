from pydantic import BaseModel, Field, field_validator
from app.utils.validation import validate_cve_id
from app.schemas.common import ErrorDetail

class CveLookupRequest(BaseModel):
    cve_id: str = Field(..., description="The standard CVE ID to query", examples=["CVE-2021-44228"])

    @field_validator("cve_id")
    @classmethod
    def validate_cve(cls, val: str) -> str:
        return validate_cve_id(val)

class CveRecord(BaseModel):
    cve_id: str = Field(..., description="Standard CVE Identifier")
    description: str | None = Field(None, description="Detailed vulnerability explanation")
    severity: str | None = Field(None, description="Severity rating (e.g. LOW, MEDIUM, HIGH, CRITICAL)")
    cvss_score: float | None = Field(None, description="CVSS base vulnerability score")
    references: list[str] = Field(default_factory=list, description="Reference list URLs")

class CveLookupResponse(BaseModel):
    success: bool = Field(True, description="Indicates if query succeeded")
    cve_id: str = Field(..., description="The queried CVE ID")
    record: CveRecord | None = Field(None, description="The returned CVE vulnerability data")
    error: ErrorDetail | None = Field(None, description="Detailed error information, if failed")
