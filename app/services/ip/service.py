import socket
import httpx
import ipaddress
from app.schemas.ip import IPAnalysisResult
from app.core.exceptions import ValidationError, NullsecError
from app.utils.validation import check_ssrf_and_get_ip, is_valid_ip, is_private_ip
from app.utils.logging import logger

class IPService:
    """Service to handle secure IP intelligence, geolocation lookup, and ASN detection."""

    @classmethod
    async def analyze(cls, target: str) -> IPAnalysisResult:
        """Resolve target to public IP (if domain) and fetch public network metadata safely."""
        target = target.strip()
        
        # 1. Determine or resolve IP
        resolved_ip = ""
        if is_valid_ip(target):
            resolved_ip = target
        else:
            # Resolve domain
            resolved_ip = check_ssrf_and_get_ip(target)
            
        if not resolved_ip:
            raise ValidationError(f"Could not resolve or validate target: {target}")
            
        # Double check private range
        if is_private_ip(resolved_ip):
            raise ValidationError("Target resolved to a private or reserved network.")
            
        # 2. Determine IP version
        ip_obj = ipaddress.ip_address(resolved_ip)
        ip_version = ip_obj.version
        
        # 3. Query passive open geolocation API (ip-api.com) with 2.0s limit
        asn = None
        isp = None
        country = None
        city = None
        lat = None
        lon = None
        
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                # Query ip-api.com JSON endpoint (securely, passive query only)
                url = f"https://ipwho.is/{resolved_ip}"
                res = await client.get(url)
                if res.status_code == 200:
                    data = res.json()
                    if data.get("success") is True:
                        country = data.get("country")
                        city = data.get("city")
                        lat = data.get("lat")
                        lon = data.get("lon")
                        isp = data.get("connection", {}).get("isp")
                        asn = data.get("connection", {}).get("asn")
        except Exception as e:
            logger.warning(f"Failed to query IP geo-metadata for {resolved_ip}: {e}")
            # Fail gracefully, leave fields as None
            
        return IPAnalysisResult(
            target=target,
            resolved_ip=resolved_ip,
            ip_version=ip_version,
            asn=asn or "Unknown ASN",
            isp=isp or "Unknown ISP / Provider",
            country=country or "Unknown Country",
            city=city or "Unknown City",
            latitude=lat,
            longitude=lon
        )
