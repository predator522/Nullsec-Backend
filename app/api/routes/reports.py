from fastapi import APIRouter, Depends, Path, HTTPException
from app.schemas.reports import ReportCreateRequest, ReportSingleResponse, ReportListResponse, ReportDeleteResponse
from app.services.reports.service import ReportsService
from app.middleware.rate_limit import RateLimiter
from app.core.exceptions import DatabaseError

router = APIRouter()
reports_rate_limiter = RateLimiter(limit=30, window_seconds=60)

@router.post("", response_model=ReportSingleResponse, dependencies=[Depends(reports_rate_limiter)])
async def create_report(payload: ReportCreateRequest):
    try: return ReportSingleResponse(success=True, report=await ReportsService.create(payload))
    except DatabaseError as exc: raise HTTPException(503, str(exc))

@router.get("", response_model=ReportListResponse, dependencies=[Depends(reports_rate_limiter)])
async def list_reports():
    try: return ReportListResponse(success=True, reports=await ReportsService.get_all())
    except DatabaseError as exc: raise HTTPException(503, str(exc))

@router.get("/{report_id}", response_model=ReportSingleResponse, dependencies=[Depends(reports_rate_limiter)])
async def get_report_by_id(report_id: str = Path(...)):
    try: report = await ReportsService.get_one(report_id)
    except DatabaseError as exc: raise HTTPException(503, str(exc))
    if not report: raise HTTPException(404, "Report not found")
    return ReportSingleResponse(success=True, report=report)

@router.delete("/{report_id}", response_model=ReportDeleteResponse, dependencies=[Depends(reports_rate_limiter)])
async def delete_report(report_id: str = Path(...)):
    try: deleted = await ReportsService.delete(report_id)
    except DatabaseError as exc: raise HTTPException(503, str(exc))
    if not deleted: raise HTTPException(404, "Report not found")
    return ReportDeleteResponse(success=True, message="Report successfully deleted.")
