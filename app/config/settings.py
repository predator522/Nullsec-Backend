import os
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseModel):
    APP_NAME: str = "NULLSEC KIT API"
    APP_ENV: str = os.getenv("APP_ENV", "development")
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    
    FRONTEND_URL: str = os.getenv("FRONTEND_URL", "http://localhost:3000")
    
    MONGODB_URI: str = os.getenv("MONGODB_URI", "")
    MONGODB_DATABASE: str = os.getenv("MONGODB_DATABASE", "nullsec_kit")
    
    REDIS_URL: str = os.getenv("REDIS_URL", "")
    
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "30"))
    
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    
    # SSRF Protection Safe Lists (allows specifying permitted domains if needed, but defaults to blocking internal IPs)
    BLOCKED_IP_RANGES: list = [
        "127.0.0.0/8",      # Loopback
        "10.0.0.0/8",       # Private network
        "172.16.0.0/12",    # Private network
        "192.168.0.0/16",   # Private network
        "169.254.0.0/16",   # Link-local / AWS metadata
        "0.0.0.0/8",        # Broadcast
        "::1/128",          # IPv6 loopback
        "fe80::/10",        # IPv6 link-local
        "fc00::/7"          # IPv6 unique local
    ]

settings = Settings()
