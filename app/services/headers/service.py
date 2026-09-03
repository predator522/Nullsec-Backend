from app.schemas.http import HeaderAnalysisResult, HeaderFinding
from app.core.exceptions import ValidationError
from app.services.http.client import safe_get
from app.utils.logging import logger

class HeadersService:
    """Service to defensively audit web server security response headers."""

    @classmethod
    async def analyze(cls, url: str) -> HeaderAnalysisResult:
        """Fetch headers from the target and perform structured defensive analysis."""
        validated_url = url.strip()
        
        try:
            response = await safe_get(validated_url)
            headers = response.headers
        except Exception as e:
            logger.warning(f"Failed to fetch headers for {validated_url}: {e}")
            raise ValidationError(f"Could not connect to target URL: {str(e)}")
            
        findings = []
        points = 100
        
        # 1. Content-Security-Policy
        csp = headers.get("content-security-policy")
        if csp:
            findings.append(
                HeaderFinding(
                    header="Content-Security-Policy",
                    status="PRESENT",
                    value=csp,
                    severity="INFO",
                    description="Defines which dynamic resources are allowed to load, mitigating XSS risks.",
                    recommendation="Ensure the policy is strict and avoids 'unsafe-inline' or '*' where possible."
                )
            )
        else:
            points -= 25
            findings.append(
                HeaderFinding(
                    header="Content-Security-Policy",
                    status="MISSING",
                    value=None,
                    severity="HIGH",
                    description="Defines which dynamic resources are allowed to load, mitigating XSS risks.",
                    recommendation="Implement a robust Content Security Policy header (e.g., default-src 'self')."
                )
            )
            
        # 2. Strict-Transport-Security (HSTS)
        hsts = headers.get("strict-transport-security")
        if hsts:
            findings.append(
                HeaderFinding(
                    header="Strict-Transport-Security",
                    status="PRESENT",
                    value=hsts,
                    severity="INFO",
                    description="Forces browsers to use secure HTTPS connections exclusively.",
                    recommendation="Ensure max-age is set to at least 1 year (31536000 seconds) and includes subdomains."
                )
            )
        else:
            points -= 20
            findings.append(
                HeaderFinding(
                    header="Strict-Transport-Security",
                    status="MISSING",
                    value=None,
                    severity="MEDIUM",
                    description="Forces browsers to use secure HTTPS connections exclusively.",
                    recommendation="Add HSTS header 'max-age=31536000; includeSubDomains' to all secure responses."
                )
            )
            
        # 3. X-Frame-Options
        xfo = headers.get("x-frame-options")
        if xfo:
            findings.append(
                HeaderFinding(
                    header="X-Frame-Options",
                    status="PRESENT",
                    value=xfo,
                    severity="INFO",
                    description="Protects users against Clickjacking attacks by limiting framing.",
                    recommendation="Configure to DENY or SAMEORIGIN."
                )
            )
        else:
            points -= 15
            findings.append(
                HeaderFinding(
                    header="X-Frame-Options",
                    status="MISSING",
                    value=None,
                    severity="MEDIUM",
                    description="Protects users against Clickjacking attacks by limiting framing.",
                    recommendation="Add X-Frame-Options header with value 'DENY' or 'SAMEORIGIN'."
                )
            )
            
        # 4. X-Content-Type-Options
        xcto = headers.get("x-content-type-options")
        if xcto and "nosniff" in xcto.lower():
            findings.append(
                HeaderFinding(
                    header="X-Content-Type-Options",
                    status="PRESENT",
                    value=xcto,
                    severity="INFO",
                    description="Prevents browsers from MIME-sniffing response body away from declared content-type.",
                    recommendation="Keep configured to 'nosniff'."
                )
            )
        else:
            points -= 15
            findings.append(
                HeaderFinding(
                    header="X-Content-Type-Options",
                    status="MISSING / WEAK",
                    value=xcto,
                    severity="LOW",
                    description="Prevents browsers from MIME-sniffing response body away from declared content-type.",
                    recommendation="Add X-Content-Type-Options header with value 'nosniff'."
                )
            )
            
        # 5. Referrer-Policy
        ref = headers.get("referrer-policy")
        if ref:
            findings.append(
                HeaderFinding(
                    header="Referrer-Policy",
                    status="PRESENT",
                    value=ref,
                    severity="INFO",
                    description="Controls how much referrer information is sent along with requests.",
                    recommendation="Ensure a privacy-conscious policy is used, e.g., 'no-referrer' or 'strict-origin-when-cross-origin'."
                )
            )
        else:
            points -= 10
            findings.append(
                HeaderFinding(
                    header="Referrer-Policy",
                    status="MISSING",
                    value=None,
                    severity="LOW",
                    description="Controls how much referrer information is sent along with requests.",
                    recommendation="Configure Referrer-Policy to 'strict-origin-when-cross-origin'."
                )
            )
            
        # 6. Permissions-Policy
        perm = headers.get("permissions-policy") or headers.get("feature-policy")
        if perm:
            findings.append(
                HeaderFinding(
                    header="Permissions-Policy",
                    status="PRESENT",
                    value=perm,
                    severity="INFO",
                    description="Restricts browser feature usage (microphone, camera, geolocation) to specified hosts.",
                    recommendation="Audit active permissions directives to ensure only necessary features are allowed."
                )
            )
        else:
            points -= 15
            findings.append(
                HeaderFinding(
                    header="Permissions-Policy",
                    status="MISSING",
                    value=None,
                    severity="LOW",
                    description="Restricts browser feature usage (microphone, camera, geolocation) to specified hosts.",
                    recommendation="Implement Permissions-Policy to lock down sensitive browser API capabilities."
                )
            )
            
        # Calculate grade
        if points >= 90:
            score = "A"
        elif points >= 75:
            score = "B"
        elif points >= 60:
            score = "C"
        elif points >= 45:
            score = "D"
        else:
            score = "F"
            
        return HeaderAnalysisResult(
            url=validated_url,
            score=score,
            findings=findings
        )
