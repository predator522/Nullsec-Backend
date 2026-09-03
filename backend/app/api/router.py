from fastapi import APIRouter
from app.api.routes import (
    health, dns, whois, ip, http_analysis,
    headers, cookies, cors, tls, crypto, cve, reports, analysis
)

api_router = APIRouter()

# Register sub-routers under api/v1
api_router.include_router(health.router, prefix="/health", tags=["Health"])
api_router.include_router(dns.router, prefix="/dns", tags=["DNS"])
api_router.include_router(whois.router, prefix="/whois", tags=["WHOIS"])
api_router.include_router(ip.router, prefix="/ip", tags=["IP Intelligence"])
api_router.include_router(http_analysis.router, prefix="/http", tags=["HTTP Analyzer"])
api_router.include_router(headers.router, prefix="/headers", tags=["Security Headers"])
api_router.include_router(cookies.router, prefix="/cookies", tags=["Cookie Analyzer"])
api_router.include_router(cors.router, prefix="/cors", tags=["CORS Checker"])
api_router.include_router(tls.router, prefix="/tls", tags=["TLS Inspector"])
api_router.include_router(crypto.router, prefix="/crypto", tags=["Cryptography Utilities"])
api_router.include_router(cve.router, prefix="/cve", tags=["CVE Lookup"])
api_router.include_router(reports.router, prefix="/reports", tags=["Reports"])
api_router.include_router(analysis.router, prefix="/analysis", tags=["Unified Analysis"])
