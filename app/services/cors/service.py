from app.schemas.http import CorsAnalysisResult
from app.core.exceptions import ValidationError
from app.services.http.client import safe_get

class CorsService:
    @classmethod
    async def check(cls, url: str, origin: str) -> CorsAnalysisResult:
        origin = origin.strip()
        if not origin.startswith(("http://", "https://")): origin = f"https://{origin}"
        if len(origin) > 2048 or any(c in origin for c in "\r\n"):
            raise ValidationError("Invalid CORS origin.")
        response = await safe_get(url, headers={"Origin": origin})
        h = response.headers
        allow_origin = h.get("access-control-allow-origin")
        allow_credentials = h.get("access-control-allow-credentials")
        allow_methods = h.get("access-control-allow-methods")
        findings, vulnerable = [], False
        if not allow_origin:
            findings.append("No Access-Control-Allow-Origin header was returned for the tested origin.")
        elif allow_origin == "*":
            findings.append("Wildcard Access-Control-Allow-Origin is broadly permissive for public responses.")
        elif allow_origin == origin:
            findings.append("The tested origin was reflected/allowed by the response.")
            if allow_credentials and allow_credentials.lower() == "true":
                vulnerable = True
                findings.append("Credentialed access is allowed for the tested origin; review whether this origin should be trusted.")
        else:
            findings.append(f"The server allowed a different origin: {allow_origin}")
        return CorsAnalysisResult(url=str(response.url), origin_tested=origin, allow_origin=allow_origin, allow_credentials=allow_credentials, allow_methods=allow_methods, is_vulnerable=vulnerable, findings=findings)
