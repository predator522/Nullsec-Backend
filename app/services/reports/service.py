import uuid
from datetime import datetime, timezone
from app.schemas.reports import ReportModel, ReportCreateRequest
from app.database.mongodb import get_mongodb, db_manager
from app.core.exceptions import DatabaseError
from app.utils.logging import logger

class ReportsService:
    @classmethod
    async def create(cls, request: ReportCreateRequest) -> ReportModel:
        report_id = str(uuid.uuid4())
        report_data = {"_id": report_id, "id": report_id, "created_at": datetime.now(timezone.utc).isoformat(), "target": request.target, "tool": request.tool, "findings": request.findings, "metadata": request.metadata}
        try:
            db = get_mongodb()
            if db_manager.is_mock:
                raise DatabaseError("MongoDB is not configured; persistence is unavailable.")
            await db["reports"].insert_one(report_data)
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to persist report: {e}")
            raise DatabaseError("Report could not be persisted.")
        return ReportModel(**report_data)

    @classmethod
    async def get_all(cls) -> list[ReportModel]:
        try:
            from app.database.mongodb import db_manager
            if db_manager.is_mock:
                raise DatabaseError("MongoDB is not configured; persistence is unavailable.")
            db = get_mongodb()
            cursor = db["reports"].find({})
            items = await cursor.to_list(length=100)
            return [ReportModel(**({**item, "id": item.get("id", item.get("_id", "unknown"))})) for item in items]
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to query reports: {e}")
            raise DatabaseError("Reports could not be retrieved.")

    @classmethod
    async def get_one(cls, report_id: str) -> ReportModel | None:
        try:
            from app.database.mongodb import db_manager
            if db_manager.is_mock:
                raise DatabaseError("MongoDB is not configured; persistence is unavailable.")
            db = get_mongodb()
            item = await db["reports"].find_one({"_id": report_id})
            if not item:
                item = await db["reports"].find_one({"id": report_id})
            return ReportModel(**({**item, "id": item.get("id", item.get("_id", "unknown"))})) if item else None
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to fetch report {report_id}: {e}")
            raise DatabaseError("Report could not be retrieved.")

    @classmethod
    async def delete(cls, report_id: str) -> bool:
        try:
            from app.database.mongodb import db_manager
            if db_manager.is_mock:
                raise DatabaseError("MongoDB is not configured; persistence is unavailable.")
            db = get_mongodb()
            result = await db["reports"].delete_one({"_id": report_id})
            if result.deleted_count:
                return True
            result = await db["reports"].delete_one({"id": report_id})
            return bool(result.deleted_count)
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to delete report {report_id}: {e}")
            raise DatabaseError("Report could not be deleted.")
