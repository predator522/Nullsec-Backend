from pydantic import BaseModel, Field, field_validator
from app.utils.validation import validate_domain_or_ip, validate_port

class ErrorDetail(BaseModel):
    code: str = Field(..., description="Unique error code identifier")
    message: str = Field(..., description="Descriptive error explanation")

class BaseResponse(BaseModel):
    success: bool = Field(True, description="Indicates if the API request was successful")
    error: ErrorDetail | None = Field(None, description="Error detail if success is False")

class TargetInput(BaseModel):
    target: str = Field(..., description="Target public domain or public IP address", examples=["example.com", "8.8.8.8"])

    @field_validator("target")
    @classmethod
    def validate_target(cls, val: str) -> str:
        return validate_domain_or_ip(val)

class PortInput(BaseModel):
    port: int = Field(..., description="Port number between 1 and 65535", examples=[443])

    @field_validator("port")
    @classmethod
    def validate_port_number(cls, val: int) -> int:
        return validate_port(val)
