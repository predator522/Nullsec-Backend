import httpx
from app.schemas.cve import CveRecord
from app.core.exceptions import ServiceUnavailableError
from app.utils.logging import logger

class CveService:
    """Service to safely lookup public software vulnerability information from official sources."""

    @classmethod
    async def lookup(cls, cve_id: str) -> CveRecord:
        cve_id = cve_id.strip().upper()
        url = f"https://cve.circl.lu/api/cve/{cve_id}"
        try:
            async with httpx.AsyncClient(verify=True, timeout=8.0) as client:
                response = await client.get(url)
        except httpx.HTTPError as exc:
            logger.warning("CVE source unavailable for %s: %s", cve_id, exc)
            raise ServiceUnavailableError("CVE data source is temporarily unavailable.") from exc
        if response.status_code == 404:
            raise ServiceUnavailableError(f"No public CVE record was found for {cve_id}.")
        if response.status_code != 200:
            raise ServiceUnavailableError("CVE data source returned an unavailable response.")
        try:
            data = response.json()
            description = data.get("summary")
            score = data.get("cvss")
            cvss_score = float(score) if score not in (None, "") else None
            severity = "UNKNOWN"
            if cvss_score is not None:
                severity = "CRITICAL" if cvss_score >= 9 else "HIGH" if cvss_score >= 7 else "MEDIUM" if cvss_score >= 4 else "LOW"
            refs = data.get("references", [])
            if not isinstance(refs, list): refs = []
            if not description: raise ValueError("missing description")
            return CveRecord(cve_id=cve_id, description=description, severity=severity, cvss_score=cvss_score, references=[str(x) for x in refs[:10]])
        except (ValueError, TypeError, KeyError) as exc:
            logger.warning("Invalid CVE response for %s: %s", cve_id, exc)
            raise ServiceUnavailableError("CVE data source returned an invalid record.") from exc
