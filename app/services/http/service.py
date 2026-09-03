import time
from app.schemas.http import HttpAnalysisResult, RedirectStep
from app.services.http.client import safe_get
from app.utils.validation import validate_url_safe

class HttpService:
    @classmethod
    async def analyze(cls, url: str) -> HttpAnalysisResult:
        validated = validate_url_safe(url)
        start = time.perf_counter()
        response = await safe_get(validated)
        return HttpAnalysisResult(url=validated, final_url=str(response.url), status_code=response.status_code,
            response_time_ms=(time.perf_counter()-start)*1000, http_version=response.http_version,
            content_type=response.headers.get("content-type"), server=response.headers.get("server"),
            redirect_chain=[], headers=dict(response.headers))
