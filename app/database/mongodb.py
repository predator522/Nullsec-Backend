import os
from app.config.settings import settings
from app.utils.logging import logger

class MockMongoDB:
    """A safe, in-memory mock for MongoDB when no live connection is available."""
    def __init__(self):
        self._data = {}

    def __getitem__(self, collection_name: str):
        if collection_name not in self._data:
            self._data[collection_name] = MockCollection(collection_name)
        return self._data[collection_name]

class MockCollection:
    def __init__(self, name: str):
        self.name = name
        self.store = []

    async def insert_one(self, document: dict):
        self.store.append(document)
        return type("InsertResult", (object,), {"inserted_id": document.get("_id", "mock_id")})()

    async def find_one(self, filter: dict):
        for doc in self.store:
            if all(doc.get(k) == v for k, v in filter.items()):
                return doc
        return None

    def find(self, filter: dict = None):
        filter = filter or {}
        results = []
        for doc in self.store:
            if all(doc.get(k) == v for k, v in filter.items()):
                results.append(doc)
        
        class AsyncCursor:
            def __init__(self, data):
                self.data = data
            def __aiter__(self):
                self._iter = iter(self.data)
                return self
            async def __anext__(self):
                try:
                    return next(self._iter)
                except StopIteration:
                    raise StopAsyncIteration
            async def to_list(self, length: int):
                return self.data[:length]
                
        return AsyncCursor(results)

    async def delete_one(self, filter: dict):
        for idx, doc in enumerate(self.store):
            if all(doc.get(k) == v for k, v in filter.items()):
                self.store.pop(idx)
                return type("DeleteResult", (object,), {"deleted_count": 1})()
        return type("DeleteResult", (object,), {"deleted_count": 0})()

class MongoDBManager:
    """Manages the lifecycle of MongoDB connection."""
    def __init__(self):
        self.client = None
        self.db = None
        self.is_mock = True

    def connect(self):
        if not settings.MONGODB_URI:
            logger.warning("MONGODB_URI not provided. Falling back to MockMongoDB.")
            self.db = MockMongoDB()
            self.is_mock = True
            return

        try:
            # We lazy import motor to avoid making it a strict dependency for simple test runs
            from motor.motor_asyncio import AsyncIOMotorClient
            self.client = AsyncIOMotorClient(settings.MONGODB_URI, serverSelectionTimeoutMS=2000)
            self.db = self.client[settings.MONGODB_DATABASE]
            self.is_mock = False
            logger.info("Successfully initiated MongoDB client connection.")
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}. Falling back to MockMongoDB.")
            self.db = MockMongoDB()
            self.is_mock = True

    def get_db(self):
        if self.db is None:
            self.connect()
        return self.db

db_manager = MongoDBManager()

def get_mongodb():
    """Dependency helper to retrieve the MongoDB database database client."""
    return db_manager.get_db()
