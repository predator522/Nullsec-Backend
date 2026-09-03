from fastapi import FastAPI
from contextlib import asynccontextmanager
from app.config.settings import settings
from app.api.router import api_router
from app.middleware.cors import setup_cors_middleware
from app.middleware.security import setup_security_middleware
from app.utils.errors import register_error_handlers
from app.database.mongodb import db_manager
from app.database.redis import redis_manager
from app.utils.logging import logger

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle events management for startup and shutdown actions."""
    logger.info("Initializing NULLSEC KIT defensive backend...")
    
    # Pre-warm database connections (falls back to mock structures if offline)
    db_manager.connect()
    redis_manager.connect()
    
    yield
    
    logger.info("Shutting down NULLSEC KIT defensive backend.")

app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "NULLSEC KIT - A highly secured, passive defensive security toolkit and "
        "authorized-assessment API. Provides robust verification of DNS, headers, CORS, "
        "TLS and cryptography assets."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Set up middlewares
setup_cors_middleware(app)
setup_security_middleware(app)

# Register central error handling
register_error_handlers(app)

# Register main API routing structure
app.include_router(api_router, prefix="/api/v1")
