from fastapi import APIRouter, Depends
from app.schemas.http import HttpAnalyzeRequest, HeaderAnalyzeResponse
from app.services.headers.service import HeadersService
from app.middleware.rate_limit import RateLimiter

router = APIRouter()

# Rate limit Headers checks to 25 requests per minute
headers_rate_limiter = RateLimiter(limit=25, window_seconds=60)

@router.post("/analyze", response_model=HeaderAnalyzeResponse, dependencies=[Depends(headers_rate_limiter)])
async def headers_analyze(payload: HttpAnalyzeRequest):
    """Scan and defensively audit the target server security response headers for web risks."""
    result = await HeadersService.analyze(payload.url)
    return HeaderAnalyzeResponse(
        success=True,
        url=payload.url,
        result=result
    )
