from __future__ import annotations

import hashlib
import json
from datetime import date, datetime, timezone
from typing import Any, Iterable

import pymongo

from config import cfg


RAW_COLLECTIONS: dict[str, tuple[str, str | None]] = {
    "news": ("news_items", "news_entities"),
    "exploit": ("exploit_items", "exploit_entities"),
    "leak": ("leak_items", "leak_entities"),
    "defacement": ("defacement_items", "defacement_entities"),
    "social": ("social_items", "social_entities"),
    "api": ("api_items", "api_entities"),
}

_mongo_client: pymongo.MongoClient | None = None


def get_db():
    global _mongo_client
    if _mongo_client is None:
        _mongo_client = pymongo.MongoClient(cfg.mongo_uri, serverSelectionTimeoutMS=5000)
    return _mongo_client[cfg.mongo_db]


def serialise_document(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, (list, tuple, set)):
        return [serialise_document(v) for v in value]
    if isinstance(value, dict):
        return {str(k): serialise_document(v) for k, v in value.items()}
    if hasattr(value, "to_dict"):
        return serialise_document(value.to_dict())
    if hasattr(value, "__dict__"):
        return serialise_document(
            {k: v for k, v in vars(value).items() if not k.startswith("_")}
        )
    return str(value)


def extract_model_documents(model: Any, parsed_data: Any = None) -> tuple[list[Any], list[Any]]:
    items = (
        getattr(model, "card_data", None)
        or getattr(model, "cards_data", None)
        or getattr(model, "apk_data", None)
        or []
    )
    entities = getattr(model, "entity_data", None) or []

    if not items and parsed_data:
        if isinstance(parsed_data, list):
            items = parsed_data
        elif isinstance(parsed_data, dict):
            for key in ("data", "items", "articles", "results"):
                candidate = parsed_data.get(key)
                if isinstance(candidate, list) and candidate:
                    items = candidate
                    break
            else:
                items = [parsed_data]
        else:
            items = [parsed_data]

    return list(items), list(entities)


def _doc_hash(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _dedupe_key(
    collector_type: str,
    source_name: str,
    payload: dict[str, Any],
    *,
    parent_key: str | None = None,
    position: int | None = None,
) -> str:
    preferred = [
        payload.get("m_hash"),
        payload.get("aid"),
        payload.get("id"),
        payload.get("m_message_id"),
        payload.get("m_package_id"),
        payload.get("m_url"),
        payload.get("url"),
        payload.get("m_app_url"),
        payload.get("m_message_sharable_link"),
        payload.get("m_title"),
        payload.get("title"),
        payload.get("m_name"),
        payload.get("name"),
    ]
    chosen = next((str(v).strip() for v in preferred if v), "")
    if not chosen:
        chosen = _doc_hash(payload)
    parts = [collector_type, source_name]
    if parent_key:
        parts.append(parent_key)
    parts.append(chosen)
    if position is not None:
        parts.append(str(position))
    return "::".join(parts)


def persist_raw_documents(
    collector_type: str,
    source_name: str,
    items: Iterable[Any],
    entities: Iterable[Any] | None = None,
) -> dict[str, int]:
    db = get_db()
    item_collection_name, entity_collection_name = RAW_COLLECTIONS[collector_type]
    item_collection = db[item_collection_name]
    entity_collection = db[entity_collection_name] if entity_collection_name else None

    item_count = 0
    entity_count = 0
    parent_keys: list[str] = []
    now = datetime.now(timezone.utc).isoformat()

    for item in items:
        payload = serialise_document(item)
        if not isinstance(payload, dict):
            continue

        dedupe_key = _dedupe_key(collector_type, source_name, payload)
        update_doc = {
            "$set": {
                **payload,
                "collector_type": collector_type,
                "source_name": source_name,
                "document_role": "item",
                "updated_at": now,
            },
            "$setOnInsert": {
                "dedupe_key": dedupe_key,
                "created_at": now,
            },
        }
        item_collection.update_one({"dedupe_key": dedupe_key}, update_doc, upsert=True)
        parent_keys.append(dedupe_key)
        item_count += 1

    if entity_collection is not None and entities:
        for idx, entity in enumerate(entities):
            payload = serialise_document(entity)
            if not isinstance(payload, dict):
                continue

            parent_key = parent_keys[idx] if idx < len(parent_keys) else None
            dedupe_key = _dedupe_key(
                collector_type,
                source_name,
                payload,
                parent_key=parent_key,
                position=idx,
            )
            update_doc = {
                "$set": {
                    **payload,
                    "collector_type": collector_type,
                    "source_name": source_name,
                    "document_role": "entity",
                    "parent_dedupe_key": parent_key,
                    "updated_at": now,
                },
                "$setOnInsert": {
                    "dedupe_key": dedupe_key,
                    "created_at": now,
                },
            }
            entity_collection.update_one({"dedupe_key": dedupe_key}, update_doc, upsert=True)
            entity_count += 1

    return {"raw_items": item_count, "raw_entities": entity_count}
