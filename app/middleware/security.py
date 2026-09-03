from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
import time
from app.utils.logging import log_request_performance
from app.config.settings import settings

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.time()
        response = await call_next(request)
        duration = (time.time() - start) * 1000
        client_ip = request.client.host if request.client else "unknown"
        log_request_performance(request.method, request.url.path, response.status_code, duration, client_ip)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if settings.APP_ENV == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.url.path not in {"/docs", "/redoc", "/openapi.json"}:
            response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'"
        return response

def setup_security_middleware(app: FastAPI): app.add_middleware(SecurityHeadersMiddleware)
