from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any

from pymongo import MongoClient, UpdateOne


MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27022")
MONGO_DB = os.getenv("MONGO_DB", "darkpulse")

NEWS_SOURCES = {
    "THN": "The Hacker News",
    "CSO": "CSO Cybercrime",
    "INFOSEC": "Infosecurity Magazine",
    "PORTSWIGGER": "PortSwigger",
    "HACKREAD": "HackRead",
    "THERECORD": "The Record",
    "KREBS": "KrebsOnSecurity",
    "BLEEPING": "BleepingComputer",
    "CERTPL": "CERT Polska",
    "CERTAT": "CERT.at",
    "CERTCN": "CERT China",
    "CERTEU": "CERT-EU",
    "CSA": "CSA Singapore",
    "ACN": "Australian Cyber Security Centre",
    "CERTPK": "CERT Pakistan",
    "CNCS": "CNCS",
    "TWEETFEED": "TweetFeed",
}

DEFACEMENT_SOURCES = {
    "DEFACER": "Defacer",
    "ZONEXSEC": "Zone-Xsec",
}

LEAK_SOURCES = {
    "PUBLIC": "Public Leak Source",
    "GENERIC": "Generic Leak Source",
}


def assign_nested(target: dict[str, Any], key: str, value: Any) -> None:
    parts = key.split(":")
    current = target
    for part in parts[:-1]:
        if part.isdigit():
            part = f"_{part}"
        current = current.setdefault(part, {})
    leaf = parts[-1]
    if leaf.isdigit():
        leaf = f"_{leaf}"
    current[leaf] = value


def flatten_arrays(data: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, dict):
            numeric = []
            other = {}
            for k, v in value.items():
                if k.startswith("_") and k[1:].isdigit():
                    numeric.append((int(k[1:]), v))
                else:
                    other[k] = v
            if numeric and not other:
                out[key] = [v for _, v in sorted(numeric)]
            else:
                out[key] = flatten_arrays(value)
        else:
            out[key] = value
    return out


def clean(value: Any) -> str:
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


def first(*values: Any) -> str:
    for value in values:
        if isinstance(value, list) and value:
            value = value[0]
        text = clean(value)
        if text:
            return text
    return ""


def recover() -> dict[str, int]:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client[MONGO_DB]
    kv = db["redis_kv_store"]
    articles = db["articles"]

    groups: dict[tuple[str, str], dict[str, Any]] = {}
    raw_re = re.compile(r"^([^:]+):raw:([^:]+):(.+)$")
    cursor = kv.find({"_id": {"$regex": r"^[^:]+:raw:[^:]+:"}}, {"_id": 1, "value": 1})
    for doc in cursor:
        match = raw_re.match(str(doc["_id"]))
        if not match:
            continue
        source, item_hash, field = match.groups()
        bucket = groups.setdefault((source, item_hash), {})
        assign_nested(bucket, field, doc.get("value", ""))

    now = datetime.now(timezone.utc).isoformat()
    article_ops: list[UpdateOne] = []
    kv_ops: list[UpdateOne] = []

    for (source, item_hash), raw_data in groups.items():
        data = flatten_arrays(raw_data)
        source_label = NEWS_SOURCES.get(source) or DEFACEMENT_SOURCES.get(source) or LEAK_SOURCES.get(source) or source
        detail = data.get("detail") if isinstance(data.get("detail"), dict) else {}

        title = first(
            data.get("title"),
            data.get("header"),
            detail.get("header") if isinstance(detail, dict) else "",
            detail.get("description") if isinstance(detail, dict) else "",
            data.get("description"),
            data.get("url"),
        )
        url = first(
            data.get("url"),
            data.get("source_url"),
            data.get("weblink"),
            detail.get("target") if isinstance(detail, dict) else "",
            detail.get("url") if isinstance(detail, dict) else "",
            detail.get("iframe_src") if isinstance(detail, dict) else "",
        )
        content = first(data.get("content"), detail.get("description") if isinstance(detail, dict) else "", data.get("description"), title)
        date_value = first(data.get("date"), data.get("leak_date"), data.get("scraped_at"), detail.get("date") if isinstance(detail, dict) else "")

        if source in NEWS_SOURCES:
            article_doc = {
                "aid": f"legacy:{source}:{item_hash}",
                "legacy_hash": item_hash,
                "legacy_source": source,
                "title": title or f"{source_label} item {item_hash[:8]}",
                "url": url,
                "seed_url": first(data.get("seed_url"), data.get("base_url")),
                "source": source_label,
                "source_name": source_label,
                "author": first(data.get("author")),
                "description": first(data.get("description"), content[:500]),
                "summary": content[:800],
                "content": content,
                "date": date_value,
                "date_raw": first(data.get("date_raw")),
                "network": first(data.get("network", {}).get("type") if isinstance(data.get("network"), dict) else data.get("network")),
                "categories": [{"label": "legacy", "score": 1.0}, {"label": source.lower(), "score": 0.8}],
                "migrated_from": "redis_kv_store_raw",
                "updated_at": now,
            }
            article_ops.append(UpdateOne({"aid": article_doc["aid"]}, {"$set": article_doc, "$setOnInsert": {"created_at": now}}, upsert=True))
        else:
            if source in DEFACEMENT_SOURCES:
                prefix = "DEFACEMENT_ITEMS"
                collector_type = "defacement"
            elif source in LEAK_SOURCES:
                prefix = "LEAK_ITEMS"
                collector_type = "leak"
            else:
                prefix = "API_ITEMS"
                collector_type = "api"
            item = {
                "m_title": title or f"{source_label} item {item_hash[:8]}",
                "m_url": url,
                "m_base_url": first(data.get("base_url")),
                "m_content": content,
                "m_description": first(data.get("description"), detail.get("description") if isinstance(detail, dict) else ""),
                "m_leak_date": date_value,
                "m_source": source_label,
                "source_name": source_label,
                "collector_type": collector_type,
                "m_network": first(data.get("network")),
                "m_attacker": first(detail.get("attacker") if isinstance(detail, dict) else ""),
                "m_team": first(detail.get("team") if isinstance(detail, dict) else ""),
                "m_web_server": first(detail.get("web_server") if isinstance(detail, dict) else ""),
                "m_mirror_links": [first(detail.get("iframe_src") if isinstance(detail, dict) else "")],
                "m_extra": data,
                "migrated_from": "redis_kv_store_raw",
            }
            key = f"{prefix}:legacy:{source}:{item_hash}"
            kv_ops.append(UpdateOne({"_id": key}, {"$set": {"value": json.dumps(item, ensure_ascii=False), "updated_at": now}, "$setOnInsert": {"created_at": now}}, upsert=True))

    article_result = articles.bulk_write(article_ops, ordered=False) if article_ops else None
    kv_result = kv.bulk_write(kv_ops, ordered=False) if kv_ops else None
    return {
        "raw_groups": len(groups),
        "article_upserts": len(article_ops),
        "kv_upserts": len(kv_ops),
        "article_modified": getattr(article_result, "modified_count", 0) if article_result else 0,
        "article_inserted": getattr(article_result, "upserted_count", 0) if article_result else 0,
        "kv_modified": getattr(kv_result, "modified_count", 0) if kv_result else 0,
        "kv_inserted": getattr(kv_result, "upserted_count", 0) if kv_result else 0,
    }


if __name__ == "__main__":
    print(json.dumps(recover(), indent=2))
