import ssl
import socket
from datetime import datetime, timezone
from app.schemas.tls import TlsCertificateInfo
from app.core.exceptions import ValidationError
from app.utils.validation import check_ssrf_and_get_ip, is_private_ip, is_valid_ip
from app.utils.logging import logger

class TlsService:
    """Service to safely inspect publicly presented TLS/SSL certificates and protocol metadata."""

    @classmethod
    def inspect(cls, target: str, port: int = 443) -> TlsCertificateInfo:
        """Connect to the target host and extract certificate details without bypassing validation."""
        target = target.strip()
        
        # 1. SSRF prevention checks
        resolved_ip = ""
        if is_valid_ip(target):
            resolved_ip = target
        else:
            resolved_ip = check_ssrf_and_get_ip(target)
            
        if is_private_ip(resolved_ip):
            raise ValidationError("Target resolved to a private or restricted network.")
            
        # 2. Open secure connection and grab certificate info
        context = ssl.create_default_context()
        # Set short connection timeouts (2.5s)
        try:
            with socket.create_connection((resolved_ip, port), timeout=2.5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
        except ssl.SSLError as e:
            logger.warning(f"SSL/TLS Handshake failure for {target}:{port}: {e}")
            raise ValidationError(f"TLS/SSL handshake failed: {str(e)}")
        except Exception as e:
            logger.warning(f"Connection failure for TLS inspection on {target}:{port}: {e}")
            raise ValidationError(f"Could not connect to target on port {port}: {str(e)}")
            
        if not cert:
            raise ValidationError("Target server did not present a public TLS certificate.")
            
        # 3. Parse certificate properties
        subject_dict = {}
        for item in cert.get("subject", []):
            for sub_item in item:
                subject_dict[sub_item[0]] = sub_item[1]
                
        issuer_dict = {}
        for item in cert.get("issuer", []):
            for sub_item in item:
                issuer_dict[sub_item[0]] = sub_item[1]
                
        # Handle certificate dates
        valid_from_raw = cert.get("notBefore")
        valid_to_raw = cert.get("notAfter")
        
        valid_from = None
        valid_to = None
        is_expired = False
        
        # Date string pattern: "Feb  8 12:00:00 2024 GMT"
        date_format = "%b %d %H:%M:%S %Y %Z"
        
        try:
            if valid_from_raw:
                dt_from = datetime.strptime(valid_from_raw, date_format).replace(tzinfo=timezone.utc)
                valid_from = dt_from.isoformat()
            if valid_to_raw:
                dt_to = datetime.strptime(valid_to_raw, date_format).replace(tzinfo=timezone.utc)
                valid_to = dt_to.isoformat()
                is_expired = datetime.now(timezone.utc) > dt_to
        except Exception as e:
            logger.warning(f"Failed parsing certificate dates: {e}")
            valid_from = valid_from_raw
            valid_to = valid_to_raw
            
        # Parse SANs
        sans = []
        for name_type, value in cert.get("subjectAltName", []):
            sans.append(f"{name_type}:{value}")
            
        return TlsCertificateInfo(
            subject=subject_dict,
            issuer=issuer_dict,
            valid_from=valid_from,
            valid_to=valid_to,
            is_expired=is_expired,
            serial_number=cert.get("serialNumber"),
            sans=sans[:20], # Return up to 20 SANs
            tls_version=tls_version
        )
