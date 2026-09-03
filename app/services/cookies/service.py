from app.schemas.http import CookieAnalysisResult, CookieFinding
from app.core.exceptions import ValidationError
from app.services.http.client import safe_get
from app.utils.logging import logger

class CookiesService:
    """Service to defensively inspect security flags on target server HTTP cookies."""

    @classmethod
    async def analyze(cls, url: str) -> CookieAnalysisResult:
        """Fetch cookies set by the target URL and review their security attributes."""
        validated_url = url.strip()
        
        try:
            response = await safe_get(validated_url)
            # Read raw cookies from set-cookie headers
            raw_cookies = response.headers.get_list("set-cookie")
        except Exception as e:
            logger.warning(f"Failed to fetch cookies for {validated_url}: {e}")
            raise ValidationError(f"Could not fetch target page to analyze cookies: {str(e)}")
            
        cookie_findings = []
        
        # Parse set-cookie headers
        for raw in raw_cookies:
            parts = [p.strip() for p in raw.split(";")]
            if not parts:
                continue
                
            # First part is key=value
            name_val = parts[0].split("=", 1)
            name = name_val[0] if name_val else "Unknown"
            
            # Extract flags
            secure = False
            http_only = False
            same_site = None
            expires = None
            domain = None
            path = None
            
            for part in parts[1:]:
                part_lower = part.lower()
                if part_lower == "secure":
                    secure = True
                elif part_lower == "httponly":
                    http_only = True
                elif part_lower.startswith("samesite="):
                    same_site = part.split("=", 1)[1]
                elif part_lower.startswith("expires="):
                    expires = part.split("=", 1)[1]
                elif part_lower.startswith("domain="):
                    domain = part.split("=", 1)[1]
                elif part_lower.startswith("path="):
                    path = part.split("=", 1)[1]
                    
            # Audit issues
            issues = []
            if not secure:
                issues.append("Secure flag is missing. Cookie will be sent over unencrypted connections.")
            if not http_only:
                issues.append("HttpOnly flag is missing. Cookie is accessible to client-side scripts, elevating XSS risk.")
            if not same_site:
                issues.append("SameSite attribute is not defined, which may increase susceptibility to CSRF attacks.")
            elif same_site.lower() == "none" and not secure:
                issues.append("SameSite is set to 'None' but Secure flag is missing, causing browsers to block this cookie.")
                
            cookie_findings.append(
                CookieFinding(
                    name=name,
                    domain=domain,
                    path=path,
                    secure=secure,
                    http_only=http_only,
                    same_site=same_site,
                    expires=expires,
                    issues=issues
                )
            )
            
        return CookieAnalysisResult(
            url=validated_url,
            cookies=cookie_findings
        )
