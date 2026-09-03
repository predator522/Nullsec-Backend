from pydantic import BaseModel, Field, field_validator
from app.utils.validation import validate_domain_only

ALLOWED_TOOLS = {"dns", "whois", "http", "headers", "tls", "cookies", "cors"}

class UnifiedAnalysisRequest(BaseModel):
    target: str = Field(..., description="Public domain authorized for passive analysis")
    include: list[str] = Field(default_factory=lambda: ["dns", "whois", "http", "headers", "tls", "cookies", "cors"])
    origin: str = "https://nullsec-kit.example"
    save_history: bool = True
    @field_validator("target")
    @classmethod
    def target_valid(cls, value: str) -> str: return validate_domain_only(value)
    @field_validator("include")
    @classmethod
    def tools_valid(cls, value: list[str]) -> list[str]:
        cleaned = list(dict.fromkeys(v.strip().lower() for v in value))
        unknown = [v for v in cleaned if v not in ALLOWED_TOOLS]
        if unknown: raise ValueError(f"Unsupported analysis modules: {', '.join(unknown)}")
        if not cleaned: raise ValueError("At least one analysis module is required.")
        return cleaned

class Finding(BaseModel):
    id: str; title: str; description: str; severity: str; category: str
    evidence: str | None = None; recommendation: str | None = None; source_tool: str

class UnifiedAnalysisResponse(BaseModel):
    success: bool = True
    scan_id: str; target: str; status: str; started_at: str; completed_at: str
    tools_requested: list[str]; tool_results: dict = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list); summary: dict = Field(default_factory=dict)
    history_saved: bool = False

class ScanHistoryItem(BaseModel):
    scan_id: str; target: str; status: str; started_at: str; completed_at: str
    tools_requested: list[str]; finding_count: int; severity_counts: dict

class ScanHistoryResponse(BaseModel):
    success: bool = True; scans: list[ScanHistoryItem] = Field(default_factory=list)
