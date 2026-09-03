from fastapi import APIRouter, Depends
from app.schemas.http import HttpAnalyzeRequest, CookieAnalyzeResponse
from app.services.cookies.service import CookiesService
from app.middleware.rate_limit import RateLimiter

router = APIRouter()

# Rate limit Cookies checks to 25 requests per minute
cookies_rate_limiter = RateLimiter(limit=25, window_seconds=60)

@router.post("/analyze", response_model=CookieAnalyzeResponse, dependencies=[Depends(cookies_rate_limiter)])
async def cookies_analyze(payload: HttpAnalyzeRequest):
    """Scan and analyze cookie attributes and security flags of the target site."""
    result = await CookiesService.analyze(payload.url)
    return CookieAnalyzeResponse(
        success=True,
        url=payload.url,
        result=result
    )
