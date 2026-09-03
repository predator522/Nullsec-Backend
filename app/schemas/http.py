from pydantic import BaseModel, Field, field_validator
from app.utils.validation import validate_url_safe
from app.schemas.common import ErrorDetail

# --- HTTP ANALYZER SCHEMAS ---

class HttpAnalyzeRequest(BaseModel):
    url: str = Field(..., description="The public HTTP or HTTPS URL to analyze", examples=["https://example.com"])

    @field_validator("url")
    @classmethod
    def validate_http_url(cls, val: str) -> str:
        return validate_url_safe(val)

class RedirectStep(BaseModel):
    url: str = Field(..., description="The URL of this redirect step")
    status_code: int = Field(..., description="The redirect status code")

class HttpAnalysisResult(BaseModel):
    url: str = Field(..., description="The requested URL")
    final_url: str = Field(..., description="The final target URL")
    status_code: int = Field(..., description="The HTTP status code of final response")
    response_time_ms: float = Field(..., description="Total time taken for request in milliseconds")
    http_version: str = Field(..., description="HTTP protocol version")
    content_type: str | None = Field(None, description="Response Content-Type")
    server: str | None = Field(None, description="Server technology signature")
    redirect_chain: list[RedirectStep] = Field(default_factory=list, description="Followed redirection route")
    headers: dict[str, str] = Field(default_factory=dict, description="Normalized response headers")

class HttpAnalyzeResponse(BaseModel):
    success: bool = Field(True, description="Indicates if query succeeded")
    url: str = Field(..., description="The requested url")
    result: HttpAnalysisResult | None = Field(None, description="HTTP analysis details")
    error: ErrorDetail | None = Field(None, description="Detailed error information, if failed")


# --- SECURITY HEADERS SCHEMAS ---

class HeaderFinding(BaseModel):
    header: str = Field(..., description="Name of the security header")
    status: str = Field(..., description="Status (e.g. PRESENT, MISSING, DEPRECATED, WEAK)")
    value: str | None = Field(None, description="Returned header value")
    severity: str = Field(..., description="Defensive rating (INFO, LOW, MEDIUM, HIGH)")
    description: str = Field(..., description="What this header does")
    recommendation: str = Field(..., description="Defensive guidance / fix action")

class HeaderAnalysisResult(BaseModel):
    url: str = Field(..., description="The analyzed URL")
    score: str = Field(..., description="Security score / rating (e.g., A, B, C, D, F)")
    findings: list[HeaderFinding] = Field(..., description="Security findings for headers")

class HeaderAnalyzeResponse(BaseModel):
    success: bool = Field(True)
    url: str = Field(...)
    result: HeaderAnalysisResult | None = Field(None)
    error: ErrorDetail | None = Field(None)


# --- COOKIE SCHEMAS ---

class CookieFinding(BaseModel):
    name: str = Field(..., description="Cookie name")
    domain: str | None = Field(None)
    path: str | None = Field(None)
    secure: bool = Field(..., description="Secure flag status")
    http_only: bool = Field(..., description="HttpOnly flag status")
    same_site: str | None = Field(None, description="SameSite configuration value")
    expires: str | None = Field(None, description="Expiration detail")
    issues: list[str] = Field(default_factory=list, description="List of defensive findings / weaknesses")

class CookieAnalysisResult(BaseModel):
    url: str = Field(...)
    cookies: list[CookieFinding] = Field(default_factory=list)

class CookieAnalyzeResponse(BaseModel):
    success: bool = Field(True)
    url: str = Field(...)
    result: CookieAnalysisResult | None = Field(None)
    error: ErrorDetail | None = Field(None)


# --- CORS SCHEMAS ---

class CorsCheckRequest(BaseModel):
    url: str = Field(..., description="The target URL to check CORS headers against")
    origin: str = Field("https://evil.attacker.com", description="Origin header to simulate during check")

    @field_validator("url")
    @classmethod
    def validate_cors_url(cls, val: str) -> str:
        return validate_url_safe(val)

class CorsAnalysisResult(BaseModel):
    url: str = Field(...)
    origin_tested: str = Field(...)
    allow_origin: str | None = Field(None)
    allow_credentials: str | None = Field(None)
    allow_methods: str | None = Field(None)
    is_vulnerable: bool = Field(False)
    findings: list[str] = Field(default_factory=list)

class CorsAnalyzeResponse(BaseModel):
    success: bool = Field(True)
    url: str = Field(...)
    result: CorsAnalysisResult | None = Field(None)
    error: ErrorDetail | None = Field(None)
