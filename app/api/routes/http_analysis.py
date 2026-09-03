from fastapi import APIRouter, Depends
from app.schemas.http import HttpAnalyzeRequest, HttpAnalyzeResponse
from app.services.http.service import HttpService
from app.middleware.rate_limit import RateLimiter

router = APIRouter()

# Rate limit HTTP analysis to 20 requests per minute
http_rate_limiter = RateLimiter(limit=20, window_seconds=60)

@router.post("/analyze", response_model=HttpAnalyzeResponse, dependencies=[Depends(http_rate_limiter)])
async def http_analyze(payload: HttpAnalyzeRequest):
    """Inspect basic HTTP service details, trace redirects, and analyze technology headers securely."""
    result = await HttpService.analyze(payload.url)
    return HttpAnalyzeResponse(
        success=True,
        url=payload.url,
        result=result
    )
