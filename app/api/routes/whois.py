from fastapi import APIRouter, Depends
from app.schemas.whois import WhoisLookupRequest, WhoisLookupResponse
from app.services.whois.service import WhoisService
from app.middleware.rate_limit import RateLimiter

router = APIRouter()

# Rate limit WHOIS lookups to e.g. 15 requests per minute
whois_rate_limiter = RateLimiter(limit=15, window_seconds=60)

@router.post("/lookup", response_model=WhoisLookupResponse, dependencies=[Depends(whois_rate_limiter)])
async def whois_lookup(payload: WhoisLookupRequest):
    """Query publicly available domain registration (WHOIS) details for an authorized domain.
    
    Adheres strictly to passive security gathers.
    """
    record = WhoisService.lookup(payload.domain)
    return WhoisLookupResponse(
        success=True,
        domain=payload.domain,
        record=record
    )
