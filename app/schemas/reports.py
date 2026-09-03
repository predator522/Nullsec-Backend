from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from app.schemas.common import ErrorDetail

class ReportCreateRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=253, description="Target system analyzed", examples=["example.com"])
    tool: str = Field(..., min_length=1, max_length=64, description="Source security module", examples=["dns"])
    findings: list[str] = Field(default_factory=list, max_length=200)
    metadata: dict = Field(default_factory=dict)

    @field_validator("target")
    @classmethod
    def clean_target(cls, value: str) -> str:
        return value.strip()

    @field_validator("tool")
    @classmethod
    def clean_tool(cls, value: str) -> str:
        return value.strip().lower()

class ReportModel(BaseModel):
    id: str = Field(..., description="The unique report identifier")
    created_at: str = Field(..., description="ISO creation timestamp")
    target: str = Field(..., description="Target system")
    tool: str = Field(..., description="Source tool")
    findings: list[str] = Field(default_factory=list, description="Key finding lists")
    metadata: dict = Field(default_factory=dict, description="Additional context/raw data")

class ReportSingleResponse(BaseModel):
    success: bool = Field(True)
    report: ReportModel | None = Field(None)
    error: ErrorDetail | None = Field(None)

class ReportListResponse(BaseModel):
    success: bool = Field(True)
    reports: list[ReportModel] = Field(default_factory=list)
    error: ErrorDetail | None = Field(None)

class ReportDeleteResponse(BaseModel):
    success: bool = Field(True)
    message: str = Field(...)
    error: ErrorDetail | None = Field(None)
