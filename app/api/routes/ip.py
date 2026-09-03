from fastapi import APIRouter, Depends
from app.schemas.ip import IPAnalyzeRequest, IPAnalyzeResponse
from app.services.ip.service import IPService
from app.middleware.rate_limit import RateLimiter

router = APIRouter()

# Rate limit IP lookups to 20 requests per minute
ip_rate_limiter = RateLimiter(limit=20, window_seconds=60)

@router.post("/analyze", response_model=IPAnalyzeResponse, dependencies=[Depends(ip_rate_limiter)])
async def ip_analyze(payload: IPAnalyzeRequest):
    """Examine public geographics and ASN internet routing properties of a public domain or IP."""
    result = await IPService.analyze(payload.target)
    return IPAnalyzeResponse(
        success=True,
        target=payload.target,
        analysis=result
    )
