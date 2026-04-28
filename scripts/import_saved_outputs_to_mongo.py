from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pymongo import MongoClient, UpdateOne


ROOT = Path(__file__).resolve().parents[1]
MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27022")
MONGO_DB = os.getenv("MONGO_DB", "darkpulse")


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return json.load(handle)


def serialise(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [serialise(v) for v in value]
    if isinstance(value, dict):
        return {str(k): serialise(v) for k, v in value.items()}
    return str(value)


def digest(value: Any) -> str:
    raw = json.dumps(serialise(value), sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def flatten(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    rows: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            rows.extend(flatten(child, f"{prefix}:{key}" if prefix else str(key)))
    elif isinstance(value, list):
        rows.append((f"{prefix}_count" if prefix else "count", len(value)))
        for index, child in enumerate(value):
            rows.extend(flatten(child, f"{prefix}:{index}" if prefix else str(index)))
    else:
        rows.append((prefix or "value", value))
    return rows


def first(data: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = data.get(key)
        if isinstance(value, list):
            value = value[0] if value else ""
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def item_list(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("data", "items", "results", "articles"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
    return []


def kv_raw_ops(source: str, path: Path, item_hash: str, item: Any) -> list[UpdateOne]:
    ops: list[UpdateOne] = []
    clean_source = source.upper().replace("-", "_")
    for field, value in flatten(serialise(item)):
        key = f"{clean_source}:saved:{path.stem}:{item_hash}:{field}"
        ops.append(UpdateOne(
            {"_id": key},
            {"$set": {
                "value": json.dumps(value, ensure_ascii=False, default=str) if isinstance(value, (dict, list)) else str(value),
                "source_file": str(path.relative_to(ROOT)),
                "restored_at": datetime.now(timezone.utc).isoformat(),
            }},
            upsert=True,
        ))
    return ops


def import_news(db) -> dict[str, int]:
    article_ops: list[UpdateOne] = []
    kv_ops: list[UpdateOne] = []
    for path in sorted((ROOT / "news_collector/scripts/output").glob("*.json")):
        try:
            payload = load_json(path)
        except Exception:
            continue
        source = path.stem.split("_output_", 1)[0]
        for item in item_list(payload):
            if not isinstance(item, dict):
                continue
            h = digest(item)
            aid = f"saved-news:{source}:{h}"
            doc = {
                "aid": aid,
                "title": first(item, "title", "m_title") or f"{source} saved item",
                "url": first(item, "url", "m_url", "seed_url"),
                "seed_url": first(item, "seed_url", "base_url", "m_base_url"),
                "source": source,
                "source_name": source,
                "author": first(item, "author", "m_author"),
                "description": first(item, "description", "m_description", "summary", "m_important_content"),
                "summary": first(item, "summary", "m_important_content", "description", "content")[:1000],
                "content": first(item, "content", "m_content", "description", "summary"),
                "date": first(item, "date", "m_leak_date", "published_at"),
                "date_raw": first(item, "date_raw"),
                "migrated_from": str(path.relative_to(ROOT)),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            article_ops.append(UpdateOne({"aid": aid}, {"$set": doc, "$setOnInsert": {"created_at": doc["updated_at"]}}, upsert=True))
            kv_ops.extend(kv_raw_ops(f"NEWS_{source}", path, h[:20], item))
    if article_ops:
        db.articles.bulk_write(article_ops, ordered=False)
    if kv_ops:
        db.redis_kv_store.bulk_write(kv_ops, ordered=False)
    return {"articles": len(article_ops), "kv_fields": len(kv_ops)}


def import_feed_json(db, patterns: list[str], prefix: str, collector_type: str) -> dict[str, int]:
    kv_ops: list[UpdateOne] = []
    item_collection_ops: list[UpdateOne] = []
    collection_name = f"{collector_type}_items"
    for pattern in patterns:
        for path in sorted(ROOT.glob(pattern)):
            try:
                payload = load_json(path)
            except Exception:
                continue
            source = path.stem
            for item in item_list(payload):
                if not isinstance(item, dict):
                    continue
                h = digest(item)
                title = first(item, "title", "m_title", "url", "m_url") or f"{source} saved item"
                url = first(item, "url", "m_url", "target", "domain")
                doc = {
                    "dedupe_key": f"saved:{collector_type}:{source}:{h}",
                    "collector_type": collector_type,
                    "source_name": source,
                    "document_role": "item",
                    "m_title": title,
                    "m_url": url,
                    "m_content": first(item, "content", "description", "m_content", "m_description"),
                    "m_description": first(item, "description", "m_description", "content"),
                    "m_leak_date": first(item, "date", "leak_date", "m_leak_date", "generated_on"),
                    "m_source": source,
                    "m_extra": item,
                    "migrated_from": str(path.relative_to(ROOT)),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
                item_collection_ops.append(UpdateOne({"dedupe_key": doc["dedupe_key"]}, {"$set": doc, "$setOnInsert": {"created_at": doc["updated_at"]}}, upsert=True))
                kv_key = f"{prefix}:{h[:20]}_{source}"
                kv_ops.append(UpdateOne({"_id": kv_key}, {"$set": {"value": json.dumps(doc, ensure_ascii=False, default=str)}}, upsert=True))
                kv_ops.extend(kv_raw_ops(f"RAW_{prefix}_{source}", path, h[:20], item))
    if item_collection_ops:
        db[collection_name].bulk_write(item_collection_ops, ordered=False)
    if kv_ops:
        db.redis_kv_store.bulk_write(kv_ops, ordered=False)
    return {"items": len(item_collection_ops), "kv_records": len(kv_ops)}


def import_trivy(db) -> dict[str, int]:
    return import_feed_json(db, ["api_collector/scripts/trivy_reports/*.json"], "API_ITEMS", "api")


def main() -> None:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client[MONGO_DB]
    result = {
        "news_outputs": import_news(db),
        "defacement_outputs": import_feed_json(db, ["openphish_output_*.json", "phishunt_output_*.json"], "DEFACEMENT_ITEMS", "defacement"),
        "leak_dump": import_feed_json(db, ["leak_data_dump.json"], "LEAK_ITEMS", "leak"),
        "trivy_reports": import_trivy(db),
    }
    total = sum(db.get_collection(name).count_documents({}) for name in db.list_collection_names())
    result["total_docs"] = total
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
