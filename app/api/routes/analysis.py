from fastapi import APIRouter, Depends, Query
from app.schemas.analysis import UnifiedAnalysisRequest, UnifiedAnalysisResponse, ScanHistoryResponse
from app.services.analysis.service import AnalysisService
from app.middleware.rate_limit import RateLimiter

router = APIRouter()
analysis_rate_limiter = RateLimiter(limit=5, window_seconds=60)

@router.post("/run", response_model=UnifiedAnalysisResponse, dependencies=[Depends(analysis_rate_limiter)])
async def run_analysis(payload: UnifiedAnalysisRequest):
    return UnifiedAnalysisResponse(success=True, **(await AnalysisService.run(payload)))

@router.get("/history", response_model=ScanHistoryResponse, dependencies=[Depends(analysis_rate_limiter)])
async def scan_history(limit: int = Query(50, ge=1, le=100)):
    return ScanHistoryResponse(success=True, scans=await AnalysisService.history(limit))
