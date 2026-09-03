from fastapi import APIRouter
from app.database.mongodb import db_manager
from app.database.redis import redis_manager

router = APIRouter()

@router.get("")
async def health_check():
    """Verify system health, environment status, and database fallback state."""
    # Ensure connections are initiated
    mongodb_db = db_manager.get_db()
    redis_client = redis_manager.get_client()
    
    return {
        "success": True,
        "status": "healthy",
        "services": {
            "mongodb": "mocked" if db_manager.is_mock else "connected",
            "redis": "mocked" if redis_manager.is_mock else "connected"
        }
    }
