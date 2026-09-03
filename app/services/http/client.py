import httpx
from urllib.parse import urljoin, urlparse
from app.utils.validation import validate_url_safe, resolve_public_ips
from app.core.exceptions import ValidationError, SSRFError

async def safe_get(url: str, headers: dict[str, str] | None = None, max_redirects: int = 5):
    current = validate_url_safe(url)
    async with httpx.AsyncClient(verify=True, timeout=httpx.Timeout(8.0, connect=4.0), follow_redirects=False) as client:
        for _ in range(max_redirects + 1):
            validate_url_safe(current)
            host = urlparse(current).hostname
            if not host: raise ValidationError("Invalid target URL.")
            resolve_public_ips(host)
            try:
                response = await client.get(current, headers=headers)
            except httpx.HTTPError as exc:
                raise ValidationError("HTTP connection failed or timed out.") from exc
            if response.is_redirect and response.headers.get("location"):
                current = urljoin(str(response.url), response.headers["location"])
                continue
            return response
    raise ValidationError("Maximum redirect limit exceeded.")
