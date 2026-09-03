from __future__ import annotations
import uuid
from datetime import datetime, timezone
from app.schemas.analysis import UnifiedAnalysisRequest, Finding, ScanHistoryItem
from app.services.dns.service import DNSService
from app.services.whois.service import WhoisService
from app.services.http.service import HttpService
from app.services.headers.service import HeadersService
from app.services.tls.service import TlsService
from app.services.cookies.service import CookiesService
from app.services.cors.service import CorsService
from app.database.mongodb import get_mongodb, db_manager
from app.utils.logging import logger

class AnalysisService:
    @staticmethod
    def _now(): return datetime.now(timezone.utc).isoformat()

    @classmethod
    async def run(cls, request: UnifiedAnalysisRequest) -> dict:
        scan_id, started = str(uuid.uuid4()), cls._now()
        results, findings = {}, []
        url = f"https://{request.target}"
        for tool in request.include:
            try:
                if tool == "dns": result = DNSService.lookup(request.target)
                elif tool == "whois": result = WhoisService.lookup(request.target)
                elif tool == "http": result = await HttpService.analyze(url)
                elif tool == "headers": result = await HeadersService.analyze(url)
                elif tool == "tls": result = TlsService.inspect(request.target, 443)
                elif tool == "cookies": result = await CookiesService.analyze(url)
                elif tool == "cors": result = await CorsService.check(url, request.origin)
                results[tool] = result.model_dump() if hasattr(result, "model_dump") else result
                findings.extend(cls._findings_for(tool, result))
            except Exception as exc:
                logger.warning("Analysis module %s failed: %s", tool, exc)
                results[tool] = {"status": "error", "message": str(exc)}
        completed = cls._now()
        counts = {level: sum(1 for f in findings if f.severity == level) for level in ["INFO","LOW","MEDIUM","HIGH","CRITICAL"]}
        payload = {"scan_id":scan_id,"target":request.target,"status":"completed","started_at":started,"completed_at":completed,"tools_requested":request.include,"tool_results":results,"findings":findings,"summary":{"finding_count":len(findings),"severity_counts":counts}}
        if request.save_history and not db_manager.is_mock:
            try:
                db = get_mongodb()
                await db["scans"].insert_one({"_id": scan_id, **{k:(v.model_dump() if isinstance(v, Finding) else v) for k,v in payload.items()}, "findings":[f.model_dump() for f in findings]})
                payload["history_saved"] = True
            except Exception as exc: logger.error("Failed to save scan history %s: %s", scan_id, exc)
        else: payload["history_saved"] = False
        return payload

    @staticmethod
    def _findings_for(tool, result):
        out=[]
        if tool == "headers" and hasattr(result,"findings"):
            for i,item in enumerate(result.findings):
                if item.status in {"MISSING","WEAK","DEPRECATED","MISSING / WEAK"}:
                    out.append(Finding(id=f"{tool}-{i+1}",title=f"{item.header}: {item.status}",description=item.description,severity=item.severity,category="WEB / HEADERS",evidence=item.value,recommendation=item.recommendation,source_tool=tool))
        if tool == "cookies" and hasattr(result,"cookies"):
            for i,item in enumerate(result.cookies):
                for j,issue in enumerate(item.issues): out.append(Finding(id=f"{tool}-{i+1}-{j+1}",title=f"Cookie security issue: {item.name}",description=issue,severity="MEDIUM",category="WEB / COOKIES",evidence=item.name,recommendation="Review the cookie flags and session design.",source_tool=tool))
        if tool == "cors" and getattr(result,"is_vulnerable",False):
            out.append(Finding(id="cors-1",title="Potentially unsafe CORS policy",description="The tested origin was accepted with credentialed cross-origin access.",severity="HIGH",category="WEB / CORS",evidence=getattr(result,"allow_origin",None),recommendation="Restrict trusted origins and review credentialed cross-origin access.",source_tool=tool))
        return out

    @classmethod
    async def history(cls, limit: int = 50) -> list[ScanHistoryItem]:
        if db_manager.is_mock: return []
        db=get_mongodb(); cursor=db["scans"].find({}); items=await cursor.to_list(length=min(limit,100))
        items.sort(key=lambda x:x.get("completed_at", ""), reverse=True)
        return [ScanHistoryItem(scan_id=x.get("scan_id",x.get("_id","")),target=x.get("target",""),status=x.get("status",""),started_at=x.get("started_at",""),completed_at=x.get("completed_at",""),tools_requested=x.get("tools_requested",[]),finding_count=x.get("summary",{}).get("finding_count",len(x.get("findings",[]))),severity_counts=x.get("summary",{}).get("severity_counts",{})) for x in items]
