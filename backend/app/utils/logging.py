import logging
import sys
import time
from app.config.settings import settings

def setup_logger():
    """Set up structured application logging."""
    logger = logging.getLogger("nullsec_kit")
    logger.setLevel(settings.LOG_LEVEL)
    
    # Avoid duplicate handlers
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        # Use structured-like or clean-to-parse format
        formatter = logging.Formatter(
            '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
    return logger

logger = setup_logger()

def log_request_performance(method: str, path: str, status_code: int, duration_ms: float, client_host: str = ""):
    """Log structured HTTP request performance details."""
    logger.info(
        f"HTTP {method} {path} - Status: {status_code} - Duration: {duration_ms:.2f}ms - Client: {client_host}"
    )

def log_error_safe(error_code: str, message: str, exc: Exception = None):
    """Log an error safely without exposing raw trace internals to standard out unless in dev."""
    if settings.APP_ENV == "development" and exc:
        logger.exception(f"Error [{error_code}]: {message}")
    else:
        logger.error(f"Error [{error_code}]: {message}")
