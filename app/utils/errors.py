from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from app.core.exceptions import NullsecError
from app.utils.logging import log_error_safe, logger

def register_error_handlers(app: FastAPI):
    """Register global exception handlers on the FastAPI application."""
    
    @app.exception_handler(NullsecError)
    async def nullsec_exception_handler(request: Request, exc: NullsecError):
        log_error_safe(exc.code, exc.message, exc)
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "success": False,
                "error": {
                    "code": exc.code,
                    "message": exc.message
                }
            }
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        # Extract the details of validation failure and present a clean error
        errors = exc.errors()
        message = "Input validation failed."
        if errors:
            # Construct a clear, descriptive message based on the first error
            err = errors[0]
            loc = " -> ".join(str(l) for l in err.get("loc", []))
            msg = err.get("msg", "invalid input")
            message = f"Validation failed at '{loc}': {msg}"
            
        log_error_safe("VALIDATION_ERROR", message, exc)
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "error": {
                    "code": "INVALID_TARGET",
                    "message": message
                }
            }
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        log_error_safe("INTERNAL_ERROR", "An unexpected error occurred on the server.", exc)
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "An unexpected server error occurred. Please try again later."
                }
            }
        )
