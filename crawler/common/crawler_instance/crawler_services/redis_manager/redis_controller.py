import pymongo
from typing import Any, Optional
from config import cfg

class redis_controller:
    """
    MongoDB Adapter that mimics redis_controller for legacy crawlers.
    Commands:
        1 = GET        args: [key, default] (optional timeout arg stripped)
        2 = SET        args: [key, value, expiry]
    """

    def __init__(self, host=None, port=None, db=None, password=None):
        try:
            self.client = pymongo.MongoClient(cfg.mongo_uri, serverSelectionTimeoutMS=5000)
            self.db = self.client[cfg.mongo_db]
            self.kv_collection = self.db["redis_kv_store"]
        except Exception as e:
            print(f"[MongoAdapter] Failed to connect: {e}")
            self.kv_collection = None

    def invoke_trigger(self, command: int, args) -> Any:
        if self.kv_collection is None:
            return None

        key = args[0]
        default_value = args[1] if len(args) > 1 else None
        expiry = args[2] if len(args) > 2 else None

        if command == 1:  # GET
            try:
                doc = self.kv_collection.find_one({"_id": key})
                if doc is None or "value" not in doc:
                    return default_value
                return doc["value"]
            except Exception:
                return default_value

        if command == 2:  # SET
            try:
                val = "" if default_value is None else str(default_value)
                self.kv_collection.update_one(
                    {"_id": key},
                    {"$set": {"value": val}},
                    upsert=True
                )
                return True
            except Exception:
                return None

        # 3 was APPEND list, which isn't used in invoke_trigger based on previous grep.
        return None
