from fastapi import APIRouter, Depends, Path
from app.schemas.cve import CveLookupResponse
from app.services.cve.service import CveService
from app.middleware.rate_limit import RateLimiter
from app.utils.validation import validate_cve_id

router = APIRouter()

# Rate limit CVE lookup checks to 30 requests per minute
cve_rate_limiter = RateLimiter(limit=30, window_seconds=60)

@router.get("/{cve_id}", response_model=CveLookupResponse, dependencies=[Depends(cve_rate_limiter)])
async def cve_lookup(cve_id: str = Path(..., description="The standard CVE ID (e.g. CVE-2021-44228)")):
    """Retrieve detailed description and severity ratings for a known public CVE software vulnerability."""
    # Syntactic check
    clean_cve = validate_cve_id(cve_id)
    result = await CveService.lookup(clean_cve)
    return CveLookupResponse(
        success=True,
        cve_id=clean_cve,
        record=result
    )
