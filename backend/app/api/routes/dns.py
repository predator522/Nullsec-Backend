from fastapi import APIRouter, Depends
from app.schemas.dns import DNSLookupRequest, DNSLookupResponse
from app.services.dns.service import DNSService
from app.middleware.rate_limit import RateLimiter

router = APIRouter()

# Rate limit DNS lookups to e.g. 20 requests per minute
dns_rate_limiter = RateLimiter(limit=20, window_seconds=60)

@router.post("/lookup", response_model=DNSLookupResponse, dependencies=[Depends(dns_rate_limiter)])
async def dns_lookup(payload: DNSLookupRequest):
    """Perform a passive, secure DNS record analysis for a validated public domain.
    
    Checks A, AAAA, MX, NS, TXT, CNAME, and SOA records.
    Protects against internal/private infrastructure lookups (SSRF).
    """
    records = DNSService.lookup(payload.domain)
    return DNSLookupResponse(
        success=True,
        domain=payload.domain,
        records=records
    )
