class NullsecError(Exception):
    """Base exception for all NULLSEC KIT errors."""
    def __init__(self, code: str, message: str, status_code: int = 400):
        self.code = code
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

class ValidationError(NullsecError):
    """Raised when request validation fails (e.g. invalid target, port)."""
    def __init__(self, message: str = "The supplied target or parameter is invalid."):
        super().__init__(code="INVALID_TARGET", message=message, status_code=400)

class SSRFError(NullsecError):
    """Raised when an SSRF attempt is detected."""
    def __init__(self, message: str = "The requested target resolved to a private or restricted network."):
        super().__init__(code="SSRF_DETECTED", message=message, status_code=403)

class DNSError(NullsecError):
    """Raised when a DNS operation fails or returns no results."""
    def __init__(self, message: str = "DNS resolution failed."):
        super().__init__(code="DNS_ERROR", message=message, status_code=400)

class RateLimitError(NullsecError):
    """Raised when a client exceeds rate limits."""
    def __init__(self, message: str = "Rate limit exceeded. Please slow down."):
        super().__init__(code="RATE_LIMIT_EXCEEDED", message=message, status_code=429)

class DatabaseError(NullsecError):
    """Raised when there's an issue contacting MongoDB or Redis."""
    def __init__(self, message: str = "Database operation failed."):
        super().__init__(code="DATABASE_ERROR", message=message, status_code=500)

class ServiceUnavailableError(NullsecError):
    """Raised when a required external or persistence service is unavailable."""
    def __init__(self, message: str = "A required service is temporarily unavailable."):
        super().__init__(code="SERVICE_UNAVAILABLE", message=message, status_code=503)
