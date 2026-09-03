from fastapi import APIRouter, Depends
from app.schemas.http import CorsCheckRequest, CorsAnalyzeResponse
from app.services.cors.service import CorsService
from app.middleware.rate_limit import RateLimiter

router = APIRouter()

# Rate limit CORS checks to 25 requests per minute
cors_rate_limiter = RateLimiter(limit=25, window_seconds=60)

@router.post("/check", response_model=CorsAnalyzeResponse, dependencies=[Depends(cors_rate_limiter)])
async def cors_check(payload: CorsCheckRequest):
    """Audit server CORS policy configuration defensively by simulating cross-origin request profiles."""
    result = await CorsService.check(payload.url, payload.origin)
    return CorsAnalyzeResponse(
        success=True,
        url=payload.url,
        result=result
    )
