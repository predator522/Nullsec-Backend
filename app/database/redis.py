import time
from app.config.settings import settings
from app.utils.logging import logger

class MockRedis:
    """A safe, in-memory mock for Redis when no live connection is available."""
    def __init__(self):
        self._store = {}
        self._expires = {}

    def get(self, key: str) -> str | None:
        self._cleanup(key)
        return self._store.get(key)

    def setex(self, key: str, seconds: int, value: str):
        self._store[key] = value
        self._expires[key] = time.time() + seconds

    def incr(self, key: str) -> int:
        self._cleanup(key)
        val = self._store.get(key, "0")
        try:
            int_val = int(val) + 1
        except ValueError:
            int_val = 1
        self._store[key] = str(int_val)
        return int_val

    def ttl(self, key: str) -> int:
        self._cleanup(key)
        if key not in self._store:
            return -2
        expiry = self._expires.get(key)
        if expiry is None:
            return -1
        remaining = int(expiry - time.time())
        return remaining if remaining > 0 else -2

    def _cleanup(self, key: str):
        if key in self._expires:
            if time.time() > self._expires[key]:
                self._store.pop(key, None)
                self._expires.pop(key, None)

class RedisManager:
    """Manages the lifecycle of Redis connection and operations."""
    def __init__(self):
        self.client = None
        self.is_mock = True

    def connect(self):
        if not settings.REDIS_URL:
            logger.warning("REDIS_URL not provided. Falling back to MockRedis.")
            self.client = MockRedis()
            self.is_mock = True
            return

        try:
            import redis
            # Connect synchronously or asynchronously depending on implementation.
            # Using standard redis-py with connection pool:
            self.client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True, socket_timeout=2.0)
            self.client.ping()
            self.is_mock = False
            logger.info("Successfully connected to Redis server.")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}. Falling back to MockRedis.")
            self.client = MockRedis()
            self.is_mock = True

    def get_client(self):
        if self.client is None:
            self.connect()
        return self.client

redis_manager = RedisManager()

def get_redis():
    """Dependency helper to retrieve the Redis client."""
    return redis_manager.get_client()
