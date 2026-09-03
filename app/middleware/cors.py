from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config.settings import settings
from app.utils.logging import logger

def setup_cors_middleware(app: FastAPI):
    """Configures secure CORS rules for NULLSEC KIT backend."""
    origins = []
    
    # Configure frontend url
    if settings.FRONTEND_URL:
        # Accept comma-separated values in FRONTEND_URL
        url_list = [u.strip() for u in settings.FRONTEND_URL.split(",") if u.strip()]
        origins.extend(url_list)
        
    # Always allow common local addresses in development env
    if settings.APP_ENV == "development":
        local_defaults = ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5173"]
        for d in local_defaults:
            if d not in origins:
                origins.append(d)
                
    logger.info(f"CORS origins configured: {origins}")
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )
