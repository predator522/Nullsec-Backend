import time
from fastapi import Request
from app.config.settings import settings
from app.database.redis import get_redis
from app.core.exceptions import RateLimitError
from app.utils.logging import logger

class RateLimiter:
    """FastAPI Rate Limiting Dependency."""
    def __init__(self, limit: int = None, window_seconds: int = 60):
        self.limit = limit or settings.RATE_LIMIT_PER_MINUTE
        self.window_seconds = window_seconds

    async def __call__(self, request: Request):
        # Determine client identifier (use IP or proxy forward header)
        client_ip = request.client.host if request.client else "unknown"
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
            
        endpoint = request.url.path
        rate_key = f"rate_limit:{client_ip}:{endpoint}"
        
        redis_client = get_redis()
        
        try:
            current_count_str = redis_client.get(rate_key)
            if current_count_str is None:
                # Key doesn't exist, create it with expiry
                redis_client.setex(rate_key, self.window_seconds, "1")
                current_count = 1
            else:
                current_count = int(current_count_str)
                if current_count >= self.limit:
                    ttl = redis_client.ttl(rate_key)
                    ttl = max(0, ttl)
                    raise RateLimitError(
                        f"Rate limit of {self.limit} requests per {self.window_seconds}s exceeded. "
                        f"Please retry in {ttl} seconds."
                    )
                # Increment
                redis_client.incr(rate_key)
        except RateLimitError:
            raise
        except Exception as e:
            # If Redis or rate limit logic fails catastrophically, we fail open but log it so service is not disrupted
            logger.error(f"Rate limiter exception (failing open): {e}")
            pass
