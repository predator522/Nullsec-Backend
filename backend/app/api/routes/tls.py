from fastapi import APIRouter, Depends
from app.schemas.tls import TlsInspectRequest, TlsInspectResponse
from app.services.tls.service import TlsService
from app.middleware.rate_limit import RateLimiter

router = APIRouter()

# Rate limit TLS inspections to 20 requests per minute
tls_rate_limiter = RateLimiter(limit=20, window_seconds=60)

@router.post("/inspect", response_model=TlsInspectResponse, dependencies=[Depends(tls_rate_limiter)])
async def tls_inspect(payload: TlsInspectRequest):
    """Examine public certificate characteristics and negotiated TLS protocol attributes defensively."""
    result = TlsService.inspect(payload.target, payload.port)
    return TlsInspectResponse(
        success=True,
        target=payload.target,
        certificate=result
    )
