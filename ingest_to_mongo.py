import json
import os
from mongo_persistence import persist_raw_documents
from crawler.crawler_services.log_manager.log_controller import log

def ingest():
    dump_file = "leak_data_dump.json"
    if not os.path.exists(dump_file):
        log.g().e(f"Dump file {dump_file} not found.")
        return

    log.g().i(f"Loading data from {dump_file}...")
    with open(dump_file, "r") as f:
        try:
            data = json.load(f)
        except Exception as e:
            log.g().e(f"Failed to parse JSON: {e}")
            return

    log.g().i(f"Found {len(data)} items to ingest.")
    
    # Group items by source_name for persist_raw_documents
    by_source = {}
    for item in data:
        # Infer source name from base_url or host
        base_url = item.get("base_url") or item.get("m_base_url") or "unknown"
        source = base_url.replace("https://", "").replace("http://", "").split("/")[0]
        if not source: source = "unknown"
        
        if source not in by_source:
            by_source[source] = []
        by_source[source].append(item)

    total_ingested = 0
    
    # Connect to MongoDB directly to populate redis_kv_store for the UI
    import pymongo
    from config import cfg
    try:
        client = pymongo.MongoClient(cfg.mongo_uri, serverSelectionTimeoutMS=5000)
        db = client[cfg.mongo_db]
        kv_col = db["redis_kv_store"]
    except Exception as e:
        log.g().e(f"Failed to connect to Mongo for redis_kv_store: {e}")
        kv_col = None

    for source, items in by_source.items():
        log.g().i(f"Ingesting {len(items)} items for source: {source}")
        res = persist_raw_documents("leak", source, items)
        total_ingested += res.get("raw_items", 0)
        
        # Also populate redis_kv_store for the UI
        if kv_col is not None:
            for item in items:
                dedupe_val = item.get("m_hash") or item.get("id") or item.get("url") or item.get("m_url") or str(item.get("collected_at", ""))
                doc_id = f"LEAK_ITEMS:{source}::{dedupe_val}"
                try:
                    upsert_doc = {"value": json.dumps(item, default=str)}
                    kv_col.update_one({"_id": doc_id}, {"$set": upsert_doc}, upsert=True)
                except Exception as e:
                    pass

    log.g().i(f"Successfully ingested {total_ingested} items into MongoDB.")

if __name__ == "__main__":
    ingest()
