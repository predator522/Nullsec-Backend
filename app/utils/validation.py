import re, socket, ipaddress
from urllib.parse import urlparse
from app.config.settings import settings
from app.core.exceptions import ValidationError, SSRFError

DOMAIN_REGEX = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

def is_valid_domain(domain: str) -> bool:
    if not domain: return False
    d = domain.strip().lower().rstrip('.')
    if d in {"localhost", "loopback", "local"} or d.endswith((".local", ".internal", ".onion")): return False
    return bool(DOMAIN_REGEX.fullmatch(d))

def is_valid_ip(ip_str: str) -> bool:
    try: ipaddress.ip_address(ip_str.strip()); return True
    except ValueError: return False

def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        if any((ip.is_private, ip.is_loopback, ip.is_link_local, ip.is_multicast, ip.is_unspecified, ip.is_reserved)): return True
        return any(ip in ipaddress.ip_network(r, strict=False) for r in settings.BLOCKED_IP_RANGES)
    except ValueError: return True

def validate_domain_or_ip(target: str) -> str:
    target = target.strip()
    if is_valid_ip(target):
        if is_private_ip(target): raise ValidationError("Target is a private or restricted IP address.")
        return target
    if is_valid_domain(target): return target.rstrip('.').lower()
    raise ValidationError("Target must be a valid public domain or public IP address.")

def validate_domain_only(domain: str) -> str:
    domain = domain.strip().rstrip('.').lower()
    if not is_valid_domain(domain): raise ValidationError("Input must be a valid public domain name.")
    return domain

def validate_port(port: int) -> int:
    if 1 <= port <= 65535: return port
    raise ValidationError("Port must be between 1 and 65535.")

def validate_cve_id(cve_id: str) -> str:
    value = cve_id.strip().upper()
    if CVE_REGEX.fullmatch(value): return value
    raise ValidationError("Invalid CVE format. Must match CVE-YYYY-NNNN.")

def resolve_public_ips(hostname: str) -> list[str]:
    try: infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc: raise ValidationError(f"Could not resolve host: {hostname}") from exc
    ips = list(dict.fromkeys(info[4][0] for info in infos))
    if not ips: raise ValidationError(f"Could not resolve host: {hostname}")
    blocked = [ip for ip in ips if is_private_ip(ip)]
    if blocked: raise SSRFError(f"Target '{hostname}' resolved to a private or restricted network.")
    return ips

def check_ssrf_and_get_ip(hostname: str) -> str:
    return resolve_public_ips(hostname)[0]

def validate_url_safe(url: str) -> str:
    if not url or len(url) > 2048: raise ValidationError("URL is empty or too long.")
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https"): raise ValidationError("URL scheme must be HTTP or HTTPS.")
    if parsed.username or parsed.password: raise ValidationError("URLs containing embedded credentials are not allowed.")
    hostname = parsed.hostname
    if not hostname: raise ValidationError("URL must contain a valid hostname.")
    if is_valid_ip(hostname):
        if is_private_ip(hostname): raise SSRFError("URL hostname is private or restricted.")
    elif not is_valid_domain(hostname):
        raise ValidationError("URL host is not a valid public domain name.")
    return url.strip()
