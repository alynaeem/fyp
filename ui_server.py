import asyncio
import base64
import os
import pathlib
import json
import re
import signal
import sys
import time
import traceback
import hashlib
import hmac
import secrets
import struct
from typing import Any, Dict, List, Optional
from urllib.parse import quote, unquote, urlencode, urlparse
from uuid import uuid4
from fastapi import FastAPI, Query, Request, HTTPException, Depends, WebSocket, WebSocketDisconnect
import bcrypt
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ReturnDocument

from config import cfg
from healing_system import get_healing_service
from logger import get_logger

log = get_logger(__name__)

# ── MongoDB Connection ──────────────────────────────────────────────────────────
client = AsyncIOMotorClient(cfg.mongo_uri, serverSelectionTimeoutMS=5000)
db = client[cfg.mongo_db]
articles_col = db["articles"]
news_items_col = db["news_items"]

# Users collection and auth setup
users_col = db["users"]
intelligence_runs_col = db["intelligence_runs"]
intelligence_notifications_col = db["dashboard_notifications"]
automation_state_col = db["automation_state"]


INTELLIGENCE_SCAN_SOURCES = {
    "news": {
        "label": "Security Feed Sites",
        "collector": "news",
        "collection_name": "articles",
        "env_overrides": {
            "MAX_PAGES": os.getenv("MANUAL_SCAN_NEWS_MAX_PAGES", "3"),
            "MAX_ARTICLES": os.getenv("MANUAL_SCAN_NEWS_MAX_ARTICLES", "60"),
        },
    },
    "leaks": {
        "label": "Ransomware Leak Sites",
        "collector": "leaks",
        "collection_name": "leak_items",
        "env_overrides": {
            "MAX_PAGES": os.getenv("MANUAL_SCAN_LEAKS_MAX_PAGES", "2"),
            "MAX_ARTICLES": os.getenv("MANUAL_SCAN_LEAKS_MAX_ARTICLES", "80"),
        },
    },
    "social": {
        "label": "Social and Channel Monitoring",
        "collector": "social",
        "collection_name": "social_items",
        "env_overrides": {
            "MAX_PAGES": os.getenv("MANUAL_SCAN_SOCIAL_MAX_PAGES", "2"),
            "MAX_ARTICLES": os.getenv("MANUAL_SCAN_SOCIAL_MAX_ARTICLES", "80"),
        },
    },
    "defacement": {
        "label": "Defacement Tracking",
        "collector": "defacement",
        "collection_name": "defacement_items",
        "env_overrides": {
            "MAX_PAGES": os.getenv("MANUAL_SCAN_DEFACEMENT_MAX_PAGES", "3"),
            "MAX_ARTICLES": os.getenv("MANUAL_SCAN_DEFACEMENT_MAX_ARTICLES", "120"),
        },
    },
}
DEFAULT_INTELLIGENCE_SCAN_ORDER = tuple(INTELLIGENCE_SCAN_SOURCES.keys())
RUNNING_SCAN_STATUSES = {"queued", "running", "cancelling"}
TERMINAL_SCAN_STATUSES = {
    "completed",
    "completed_no_new",
    "completed_with_errors",
    "failed",
    "cancelled",
}
SCAN_LOCK_ID = "intelligence_scan_lock"
SCAN_RECOVERY_GRACE_SECONDS = 10
SOURCE_HIGHLIGHT_LIMIT = 5
FEED_CACHE_TTL_SECONDS = 30
_FEED_ITEMS_CACHE: dict[tuple[str, bool], tuple[float, list[dict]]] = {}
_TRANSLATION_CACHE: dict[tuple[str, str], str] = {}
TRANSLATION_BATCH_LIMIT = 100
TRANSLATION_CHUNK_SIZE = 25
SEARCH_CANDIDATE_LIMIT = 400
_healing_monitor_task: asyncio.Task | None = None
_SEARCH_STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "for",
    "from",
    "in",
    "into",
    "is",
    "it",
    "of",
    "on",
    "or",
    "that",
    "the",
    "their",
    "this",
    "to",
    "vs",
    "v",
    "with",
}


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _channel_label() -> str:
    return (cfg.arya_notification_channel or "Dashboard Alert").strip() or "Dashboard Alert"


def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _seconds_since(value: Optional[str]) -> float:
    parsed = _parse_iso_datetime(value)
    if not parsed:
        return 0.0
    return max((datetime.now(timezone.utc) - parsed).total_seconds(), 0.0)


def _human_join(parts: list[str]) -> str:
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0]
    if len(parts) == 2:
        return " and ".join(parts)
    return ", ".join(parts[:-1]) + f", and {parts[-1]}"


def _cache_get_feed_items(key: tuple[str, bool]) -> Optional[list[dict]]:
    cached = _FEED_ITEMS_CACHE.get(key)
    if not cached:
        return None
    cached_at, items = cached
    if time.monotonic() - cached_at > FEED_CACHE_TTL_SECONDS:
        _FEED_ITEMS_CACHE.pop(key, None)
        return None
    return items


def _cache_set_feed_items(key: tuple[str, bool], items: list[dict]) -> list[dict]:
    _FEED_ITEMS_CACHE[key] = (time.monotonic(), items)
    return items


def _normalize_search_text(value: Any) -> str:
    if value is None:
        return ""
    text = unquote(str(value)).lower()
    text = re.sub(r"[_/\\|]+", " ", text)
    text = re.sub(r"[^\w\s\.\-:]+", " ", text, flags=re.UNICODE)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _flatten_search_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        parts: list[str] = []
        for key, nested in value.items():
            parts.append(str(key))
            parts.extend(_flatten_search_values(nested))
        return parts
    if isinstance(value, (list, tuple, set)):
        parts: list[str] = []
        for nested in value:
            parts.extend(_flatten_search_values(nested))
        return parts
    return [str(value)]


def _compose_search_blob(*values: Any) -> str:
    parts: list[str] = []
    for value in values:
        parts.extend(_flatten_search_values(value))
    return _normalize_search_text(" ".join(part for part in parts if part))[:8000]


def _query_search_terms(query: str) -> list[str]:
    normalized = _normalize_search_text(query)
    if not normalized:
        return []
    raw_terms = [token.strip(".-:") for token in normalized.split()]
    filtered: list[str] = []
    seen: set[str] = set()
    for term in raw_terms:
        if not term:
            continue
        if len(term) < 2 and not re.fullmatch(r"\d+", term):
            continue
        if term in _SEARCH_STOPWORDS:
            continue
        if term not in seen:
            filtered.append(term)
            seen.add(term)
    if filtered:
        return filtered
    return list(dict.fromkeys(token for token in raw_terms if token))


def _build_mongo_text_search(query: str, fields: list[str]) -> dict:
    normalized = _normalize_search_text(query)
    terms = _query_search_terms(query)[:5]
    branches: list[dict] = []

    if normalized:
        phrase_branch = {"$or": [{field: {"$regex": re.escape(normalized), "$options": "i"}} for field in fields]}
        branches.append(phrase_branch)

    if terms:
        token_branch = {
            "$and": [
                {"$or": [{field: {"$regex": re.escape(term), "$options": "i"}} for field in fields]}
                for term in terms
            ]
        }
        branches.append(token_branch)

        partial_branch = {
            "$or": [
                {field: {"$regex": re.escape(term), "$options": "i"}}
                for term in terms
                for field in fields
            ]
        }
        branches.append(partial_branch)

    if not branches:
        return {}
    if len(branches) == 1:
        return branches[0]
    return {"$or": branches}


def _clear_feed_cache() -> None:
    _FEED_ITEMS_CACHE.clear()


def _chunk_list(values: list[str], size: int) -> list[list[str]]:
    if size <= 0:
        return [values]
    return [values[index:index + size] for index in range(0, len(values), size)]


def _translate_with_deep_translator(texts: list[str], target_language: str, source_language: str = "auto") -> list[str]:
    from deep_translator import GoogleTranslator

    translator = GoogleTranslator(source=source_language or "auto", target=target_language)
    translated: list[str] = []
    for chunk in _chunk_list(texts, TRANSLATION_CHUNK_SIZE):
        batch_result = translator.translate_batch(chunk)
        if isinstance(batch_result, str):
            batch_result = [batch_result]
        translated.extend([str(item or "") for item in batch_result])
    return translated


def _translate_with_gemini(texts: list[str], target_language: str) -> list[str]:
    from google import genai
    from google.genai import types

    api_key = cfg.gemini_api_key or os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        raise RuntimeError("Gemini translation fallback is not configured")

    client = genai.Client(api_key=api_key)
    payload = json.dumps(texts, ensure_ascii=False)
    prompt = f"""
    Translate every string in the JSON array into {target_language}.
    Preserve URLs, malware family names, CVE IDs, IP addresses, usernames, and code snippets exactly as they appear.
    Return ONLY a JSON array of translated strings in the same order.
    Input: {payload}
    """

    response = client.models.generate_content(
        model="gemini-2.0-flash",
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0.1,
            response_mime_type="application/json",
        ),
    ).text
    parsed = json.loads(response or "[]")
    if not isinstance(parsed, list):
        raise ValueError("Gemini translation did not return a list")
    return [str(item or "") for item in parsed]


async def _count_source_documents(source_key: str) -> int:
    source_meta = INTELLIGENCE_SCAN_SOURCES[source_key]
    return await db[source_meta["collection_name"]].count_documents({})


def _notification_level(status: str) -> str:
    if status == "failed":
        return "error"
    if status in {"completed_with_errors", "cancelling", "cancelled"}:
        return "warning"
    if status in {"running", "queued"}:
        return "info"
    return "success"


def _build_notification_payload(
    *,
    job_id: str,
    status: str,
    triggered_by: str,
    started_at: str,
    completed_at: Optional[str] = None,
    source_results: Optional[list[dict[str, Any]]] = None,
    delivery: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    source_results = source_results or []
    delivery = delivery or {
        "channel_label": _channel_label(),
        "webhook_configured": bool(cfg.n8n_webhook_url),
        "webhook_delivered": False,
    }
    new_records_total = sum(max(int(item.get("new_records", 0)), 0) for item in source_results)
    ready_sources = [item for item in source_results if item.get("status") == "completed"]
    failed_sources = [item for item in source_results if item.get("status") == "failed"]
    source_breakdown = [f"{item['label']} {item.get('new_records', 0)}" for item in source_results]

    if status == "running":
        title = "Automated intelligence update is running"
        message = (
            "Scanning security feeds, ransomware leak sources, channel monitoring, "
            "and defacement tracking. MongoDB will refresh when the run completes."
        )
    elif status == "cancelling":
        title = "Stopping the automated intelligence update"
        message = "Stop requested. DarkPulse is shutting down active collectors and finalizing the latest counts."
    elif status == "cancelled":
        title = "Scan stopped by operator"
        if new_records_total > 0:
            message = (
                f"The scan was stopped after syncing {new_records_total} new records into MongoDB. "
                f"Arya channel: {delivery['channel_label']}."
            )
        else:
            message = "The scan was stopped before any new unique records were added to MongoDB."
    elif status == "completed_no_new":
        title = "Scan complete with no new intelligence"
        message = (
            f"No new unique records were added to MongoDB. Arya channel: {delivery['channel_label']}."
        )
    elif status == "completed_with_errors":
        failed_labels = _human_join([item["label"] for item in failed_sources]) or "one or more sources"
        if new_records_total > 0:
            message = (
                f"{new_records_total} new unique records were synced to MongoDB, "
                f"but {failed_labels} reported errors."
            )
        else:
            message = f"The scan finished with source errors and no new records were added. Affected sources: {failed_labels}."
        title = "Scan completed with partial source errors"
    elif status == "failed":
        title = "Automated intelligence update failed"
        message = "The background scan failed before MongoDB sync could complete."
    else:
        ready_labels = [f"{item['label']} {item.get('new_records', 0)}" for item in ready_sources if item.get("new_records", 0) > 0]
        title = f"Scan complete. {new_records_total} new records added"
        if ready_labels:
            message = (
                f"MongoDB was updated with new intelligence from {_human_join(ready_labels)}. "
                f"Arya channel: {delivery['channel_label']}."
            )
        else:
            message = f"MongoDB sync completed successfully. Arya channel: {delivery['channel_label']}."

    timestamp = completed_at or started_at
    return {
        "_id": job_id,
        "job_id": job_id,
        "status": status,
        "level": _notification_level(status),
        "title": title,
        "message": message,
        "triggered_by": triggered_by,
        "started_at": started_at,
        "completed_at": completed_at,
        "updated_at": timestamp,
        "new_records_total": new_records_total,
        "source_results": source_results,
        "source_breakdown": source_breakdown,
        "delivery": delivery,
    }


def _build_source_result(source_key: str, before_count: int) -> dict[str, Any]:
    source_meta = INTELLIGENCE_SCAN_SOURCES[source_key]
    return {
        "source": source_key,
        "label": source_meta["label"],
        "collector": source_meta["collector"],
        "status": "queued",
        "pid": None,
        "before_count": before_count,
        "current_count": before_count,
        "after_count": before_count,
        "new_records": 0,
        "started_at": None,
        "completed_at": None,
        "error": "",
        "highlights": [],
    }


def _clean_text(value: Any, *, fallback: str = "") -> str:
    if value is None:
        return fallback
    text = re.sub(r"\s+", " ", str(value)).strip()
    return text or fallback


def _humanize_source_name(value: Any, *, fallback: str = "") -> str:
    text = _clean_text(value)
    if not text:
        return fallback

    candidate = text
    if "://" in candidate:
        try:
            candidate = urlparse(candidate).hostname or candidate
        except Exception:
            candidate = text

    candidate = re.sub(r"^www\.", "", candidate, flags=re.IGNORECASE)
    domain_parts = [part for part in candidate.split(".") if part]
    common_tlds = {"com", "org", "net", "io", "co", "gov", "edu", "pk", "uk", "eu", "cn", "ru", "sg", "at", "pl"}
    if len(domain_parts) > 1 and all("/" not in part for part in domain_parts):
        trimmed = [part for part in domain_parts if part.lower() not in common_tlds]
        if trimmed:
            candidate = " ".join(trimmed)

    candidate = candidate.replace("_", " ").replace("-", " ")
    candidate = re.sub(r"\s+", " ", candidate).strip()
    return candidate.title() if candidate.islower() else candidate or fallback


def _build_source_highlight(title: Any, source_name: Any, url: Any = "") -> Optional[dict[str, str]]:
    clean_title = _clean_text(title)
    clean_source = _humanize_source_name(source_name)
    clean_url = _clean_text(url)
    if not clean_title:
        return None
    return {
        "title": clean_title[:180],
        "source_name": clean_source[:120] if clean_source else "",
        "url": clean_url[:400] if clean_url else "",
    }


def _extract_source_highlights_from_doc(source_key: str, doc: dict[str, Any]) -> list[dict[str, str]]:
    default_label = INTELLIGENCE_SCAN_SOURCES[source_key]["label"]

    if source_key == "news":
        highlight = _build_source_highlight(
            doc.get("title"),
            doc.get("source") or doc.get("seed_url") or doc.get("url") or default_label,
            doc.get("url") or doc.get("seed_url") or "",
        )
        return [highlight] if highlight else []

    if source_key == "leaks":
        highlight = _build_source_highlight(
            doc.get("title") or doc.get("important_content"),
            doc.get("source_name") or doc.get("team") or doc.get("base_url") or doc.get("url") or default_label,
            doc.get("url") or doc.get("base_url") or "",
        )
        return [highlight] if highlight else []

    if source_key == "defacement":
        highlight = _build_source_highlight(
            doc.get("m_title") or doc.get("title") or doc.get("m_url"),
            doc.get("source_name") or doc.get("m_base_url") or doc.get("m_source_url") or default_label,
            doc.get("m_url") or doc.get("m_source_url") or doc.get("m_base_url") or "",
        )
        return [highlight] if highlight else []

    if source_key == "social":
        base_source = _humanize_source_name(doc.get("source_name") or doc.get("source"), fallback=default_label)
        results: list[dict[str, str]] = []
        for nested in doc.get("items") or []:
            if not isinstance(nested, dict):
                highlight = _build_source_highlight(nested, base_source, "")
            else:
                highlight = _build_source_highlight(
                    nested.get("title") or nested.get("text") or nested.get("content") or nested.get("message") or nested.get("url"),
                    nested.get("source_name") or nested.get("source") or base_source,
                    nested.get("url") or nested.get("link") or nested.get("message_sharable_link") or "",
                )
            if highlight:
                results.append(highlight)

        if results:
            return results

        fallback_highlight = _build_source_highlight(doc.get("title") or base_source, base_source, doc.get("url") or "")
        return [fallback_highlight] if fallback_highlight else []

    return []


async def _fetch_source_highlights(source_key: str, limit: int) -> list[dict[str, str]]:
    safe_limit = max(min(int(limit or 0), SOURCE_HIGHLIGHT_LIMIT), 0)
    if safe_limit <= 0:
        return []

    collection_name = INTELLIGENCE_SCAN_SOURCES[source_key]["collection_name"]
    docs = await db[collection_name].find().sort([("$natural", -1)]).limit(max(safe_limit * 3, safe_limit)).to_list(length=max(safe_limit * 3, safe_limit))
    highlights: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for doc in docs:
        for highlight in _extract_source_highlights_from_doc(source_key, doc):
            dedupe_key = (
                highlight.get("title", "").strip().lower(),
                highlight.get("source_name", "").strip().lower(),
            )
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            highlights.append(highlight)
            if len(highlights) >= safe_limit:
                return highlights

    return highlights


async def _build_final_source_result(
    job_id: str,
    source_key: str,
    *,
    status: str,
    before_count: int,
    current_count: int,
    started_at: Optional[str],
    completed_at: str,
    error: str = "",
    pid: Optional[int] = None,
) -> dict[str, Any]:
    source_meta = INTELLIGENCE_SCAN_SOURCES[source_key]
    new_records = max(int(current_count) - int(before_count), 0)
    highlights = await _fetch_source_highlights(source_key, min(new_records, SOURCE_HIGHLIGHT_LIMIT))
    payload = {
        "source": source_key,
        "label": source_meta["label"],
        "collector": source_meta["collector"],
        "status": status,
        "pid": pid,
        "before_count": before_count,
        "current_count": current_count,
        "after_count": current_count,
        "new_records": new_records,
        "started_at": started_at,
        "completed_at": completed_at,
        "error": error,
        "highlights": highlights,
    }
    await _update_source_result(
        job_id,
        source_key,
        status=status,
        pid=pid,
        current_count=current_count,
        after_count=current_count,
        new_records=new_records,
        started_at=started_at,
        completed_at=completed_at,
        error=error,
        highlights=highlights,
    )
    return payload


async def _store_notification(notification: dict[str, Any]) -> None:
    await intelligence_notifications_col.replace_one(
        {"_id": notification["_id"]},
        notification,
        upsert=True,
    )


async def _emit_arya_event(event_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    delivery = {
        "channel_label": _channel_label(),
        "webhook_configured": bool(cfg.n8n_webhook_url),
        "webhook_delivered": False,
    }
    if not cfg.n8n_webhook_url:
        return delivery

    import aiohttp

    headers = {}
    if cfg.n8n_webhook_secret:
        headers["X-DarkPulse-Webhook-Secret"] = cfg.n8n_webhook_secret

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                cfg.n8n_webhook_url,
                json={"event": event_name, **payload},
                headers=headers,
                timeout=20,
            ) as resp:
                text = (await resp.text()).strip()
                delivery["webhook_status"] = resp.status
                delivery["webhook_delivered"] = resp.status < 300
                if not delivery["webhook_delivered"]:
                    delivery["webhook_error"] = text[:400] or f"HTTP {resp.status}"
    except Exception as exc:
        delivery["webhook_error"] = str(exc)

    return delivery


async def _fetch_run(job_id: str) -> Optional[dict[str, Any]]:
    return await intelligence_runs_col.find_one({"_id": job_id})


async def _fetch_latest_run() -> Optional[dict[str, Any]]:
    return await intelligence_runs_col.find_one(sort=[("started_at", -1)])


async def _fetch_latest_notification() -> Optional[dict[str, Any]]:
    return await intelligence_notifications_col.find_one(sort=[("updated_at", -1)])


async def _acquire_scan_lock(job_id: str, triggered_by: str, sources: list[str]) -> Optional[dict[str, Any]]:
    return await automation_state_col.find_one_and_update(
        {"_id": SCAN_LOCK_ID, "status": {"$nin": ["running", "cancelling"]}},
        {
            "$set": {
                "status": "running",
                "job_id": job_id,
                "triggered_by": triggered_by,
                "sources": sources,
                "updated_at": _utcnow_iso(),
            }
        },
        return_document=ReturnDocument.AFTER,
    )


async def _release_scan_lock(job_id: str, final_status: str) -> None:
    await automation_state_col.update_one(
        {"_id": SCAN_LOCK_ID, "job_id": job_id},
        {
            "$set": {
                "status": "idle",
                "job_id": None,
                "last_job_id": job_id,
                "last_status": final_status,
                "updated_at": _utcnow_iso(),
            }
        },
    )


async def _run_stop_requested(job_id: str) -> bool:
    run_doc = await _fetch_run(job_id)
    return bool(run_doc and run_doc.get("stop_requested"))


async def _update_source_result(job_id: str, source_key: str, **fields: Any) -> None:
    set_doc = {"updated_at": _utcnow_iso()}
    for key, value in fields.items():
        set_doc[f"source_results.$[entry].{key}"] = value
    await intelligence_runs_col.update_one(
        {"_id": job_id},
        {"$set": set_doc},
        array_filters=[{"entry.source": source_key}],
    )


def _kill_pid_group(pid: int, *, force: bool = False) -> bool:
    sig = signal.SIGKILL if force else signal.SIGTERM
    try:
        os.killpg(os.getpgid(pid), sig)
        return True
    except Exception:
        try:
            os.kill(pid, sig)
            return True
        except Exception:
            return False


def _pid_is_running(pid: Any) -> bool:
    try:
        pid_int = int(pid)
        if pid_int <= 0:
            return False
        os.kill(pid_int, 0)
        return True
    except Exception:
        return False


def _derive_run_status(source_results: list[dict[str, Any]], stop_requested: bool) -> tuple[str, int]:
    cancelled_sources = [item for item in source_results if item.get("status") == "cancelled"]
    failed_sources = [item for item in source_results if item.get("status") == "failed"]
    new_records_total = sum(max(int(item.get("new_records", 0)), 0) for item in source_results)

    if stop_requested or cancelled_sources:
        return "cancelled", new_records_total
    if failed_sources and new_records_total > 0:
        return "completed_with_errors", new_records_total
    if failed_sources:
        return "failed", new_records_total
    if new_records_total == 0:
        return "completed_no_new", new_records_total
    return "completed", new_records_total


async def _ensure_run_source_results(job_id: str, run_doc: dict[str, Any]) -> dict[str, Any]:
    if run_doc.get("source_results"):
        return run_doc

    sources = run_doc.get("sources") or list(DEFAULT_INTELLIGENCE_SCAN_ORDER)
    source_counts = await asyncio.gather(*[_count_source_documents(source) for source in sources])
    source_results = [
        _build_source_result(source_key, before_count)
        for source_key, before_count in zip(sources, source_counts)
    ]
    updated_at = _utcnow_iso()
    await intelligence_runs_col.update_one(
        {"_id": job_id},
        {"$set": {"source_results": source_results, "updated_at": updated_at}},
    )
    refreshed_run = dict(run_doc)
    refreshed_run["source_results"] = source_results
    refreshed_run["updated_at"] = updated_at
    return refreshed_run


async def _finalize_recovered_scan(job_id: str, run_doc: dict[str, Any], source_results: list[dict[str, Any]]) -> dict[str, Any]:
    completed_at = _utcnow_iso()
    stop_requested = bool(run_doc.get("stop_requested"))
    run_status, new_records_total = _derive_run_status(source_results, stop_requested)
    delivery = {
        "channel_label": _channel_label(),
        "webhook_configured": bool(cfg.n8n_webhook_url),
        "webhook_delivered": False,
        **(run_doc.get("delivery") or {}),
    }

    await intelligence_runs_col.update_one(
        {"_id": job_id},
        {
            "$set": {
                "status": run_status,
                "completed_at": completed_at,
                "updated_at": completed_at,
                "source_results": source_results,
                "new_records_total": new_records_total,
                "delivery": delivery,
            }
        },
    )
    _clear_feed_cache()
    notification = _build_notification_payload(
        job_id=job_id,
        status=run_status,
        triggered_by=run_doc.get("triggered_by", "dashboard"),
        started_at=run_doc.get("started_at", completed_at),
        completed_at=completed_at,
        source_results=source_results,
        delivery=delivery,
    )
    await _store_notification(notification)
    await _release_scan_lock(job_id, run_status)
    log.warning("Recovered stale intelligence scan %s with final status %s", job_id, run_status)
    return await _fetch_run(job_id) or {
        **run_doc,
        "status": run_status,
        "completed_at": completed_at,
        "updated_at": completed_at,
        "source_results": source_results,
        "new_records_total": new_records_total,
        "delivery": delivery,
    }


async def _reconcile_active_scan_state() -> tuple[dict[str, Any], Optional[dict[str, Any]]]:
    lock_doc = await automation_state_col.find_one({"_id": SCAN_LOCK_ID}) or {}
    if lock_doc.get("status") not in RUNNING_SCAN_STATUSES or not lock_doc.get("job_id"):
        return lock_doc, None

    job_id = lock_doc["job_id"]
    run_doc = await _fetch_run(job_id)
    if not run_doc:
        await automation_state_col.update_one(
            {"_id": SCAN_LOCK_ID, "job_id": job_id},
            {
                "$set": {
                    "status": "idle",
                    "job_id": None,
                    "last_job_id": job_id,
                    "last_status": "failed",
                    "updated_at": _utcnow_iso(),
                }
            },
        )
        return await automation_state_col.find_one({"_id": SCAN_LOCK_ID}) or {}, None

    if run_doc.get("status") in TERMINAL_SCAN_STATUSES:
        await _release_scan_lock(job_id, run_doc["status"])
        return await automation_state_col.find_one({"_id": SCAN_LOCK_ID}) or {}, None

    run_doc = await _ensure_run_source_results(job_id, run_doc)
    stop_requested = bool(run_doc.get("stop_requested")) or lock_doc.get("status") == "cancelling"
    run_age_seconds = _seconds_since(run_doc.get("started_at") or run_doc.get("updated_at"))
    has_live_source = False
    did_update_sources = False

    for source_result in run_doc.get("source_results", []):
        source_key = source_result.get("source")
        if source_key not in INTELLIGENCE_SCAN_SOURCES:
            continue

        before_count = int(source_result.get("before_count") or 0)
        current_count = await _count_source_documents(source_key)
        source_status = source_result.get("status") or "queued"
        pid = source_result.get("pid")
        pid_alive = _pid_is_running(pid) if pid else False

        if source_status in TERMINAL_SCAN_STATUSES:
            update_fields = {}
            if current_count != source_result.get("current_count"):
                update_fields["current_count"] = current_count
            if current_count != source_result.get("after_count"):
                update_fields["after_count"] = current_count
            new_records = max(current_count - before_count, 0)
            if new_records != source_result.get("new_records"):
                update_fields["new_records"] = new_records
            if update_fields:
                await _update_source_result(job_id, source_key, **update_fields)
                did_update_sources = True
            continue

        if pid_alive:
            has_live_source = True
            desired_status = "cancelling" if stop_requested else ("running" if source_status == "queued" else source_status)
            update_fields = {}
            if desired_status != source_status:
                update_fields["status"] = desired_status
            if current_count != source_result.get("current_count"):
                update_fields["current_count"] = current_count
            if current_count != source_result.get("after_count"):
                update_fields["after_count"] = current_count
            new_records = max(current_count - before_count, 0)
            if new_records != source_result.get("new_records"):
                update_fields["new_records"] = new_records
            if update_fields:
                await _update_source_result(job_id, source_key, **update_fields)
                did_update_sources = True
            continue

        if stop_requested:
            final_status = "cancelled"
            error_message = ""
        elif run_age_seconds >= SCAN_RECOVERY_GRACE_SECONDS:
            final_status = "failed" if source_status == "queued" else "completed"
            error_message = (
                "Collector never started after the API worker restarted."
                if source_status == "queued"
                else ""
            )
        else:
            continue

        await _update_source_result(
            job_id,
            source_key,
            status=final_status,
            completed_at=_utcnow_iso(),
            current_count=current_count,
            after_count=current_count,
            new_records=max(current_count - before_count, 0),
            pid=None,
            error=error_message,
            highlights=await _fetch_source_highlights(source_key, min(max(current_count - before_count, 0), SOURCE_HIGHLIGHT_LIMIT)),
        )
        did_update_sources = True

    if did_update_sources:
        run_doc = await _fetch_run(job_id) or run_doc

    pending_sources = [
        item for item in run_doc.get("source_results", [])
        if item.get("status") in RUNNING_SCAN_STATUSES
    ]
    if has_live_source:
        return lock_doc, run_doc
    if pending_sources and not stop_requested and run_age_seconds < SCAN_RECOVERY_GRACE_SECONDS:
        return lock_doc, run_doc

    if pending_sources:
        completed_at = _utcnow_iso()
        for source_result in pending_sources:
            source_key = source_result.get("source")
            if source_key not in INTELLIGENCE_SCAN_SOURCES:
                continue
            before_count = int(source_result.get("before_count") or 0)
            current_count = await _count_source_documents(source_key)
            final_status = "cancelled" if stop_requested else "failed"
            error_message = "" if stop_requested else "Collector is no longer running."
            await _update_source_result(
                job_id,
                source_key,
                status=final_status,
                completed_at=completed_at,
                current_count=current_count,
                after_count=current_count,
                new_records=max(current_count - before_count, 0),
                pid=None,
                error=error_message,
                highlights=await _fetch_source_highlights(source_key, min(max(current_count - before_count, 0), SOURCE_HIGHLIGHT_LIMIT)),
            )
        run_doc = await _fetch_run(job_id) or run_doc

    await _finalize_recovered_scan(job_id, run_doc, run_doc.get("source_results", []))
    return await automation_state_col.find_one({"_id": SCAN_LOCK_ID}) or {}, None


async def _run_source_scan(job_id: str, source_key: str) -> dict[str, Any]:
    source_meta = INTELLIGENCE_SCAN_SOURCES[source_key]
    run_doc = await _fetch_run(job_id)
    source_state = next(
        (item for item in (run_doc or {}).get("source_results", []) if item.get("source") == source_key),
        None,
    ) or _build_source_result(source_key, 0)
    before_count = int(source_state.get("before_count") or 0)
    current_count = before_count

    if await _run_stop_requested(job_id):
        completed_at = _utcnow_iso()
        await _update_source_result(
            job_id,
            source_key,
            status="cancelled",
            completed_at=completed_at,
            current_count=current_count,
            after_count=current_count,
            new_records=0,
            pid=None,
            highlights=[],
        )
        return {
            **source_state,
            "status": "cancelled",
            "completed_at": completed_at,
            "current_count": current_count,
            "after_count": current_count,
            "new_records": 0,
            "pid": None,
            "highlights": [],
        }

    started_at = _utcnow_iso()
    env = os.environ.copy()
    env.update({key: str(value) for key, value in source_meta.get("env_overrides", {}).items() if str(value).strip()})
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "orchestrator.py",
        "--once",
        "--collector",
        source_meta["collector"],
        cwd=str(_STATIC_DIR),
        env=env,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
        start_new_session=True,
    )
    await _update_source_result(
        job_id,
        source_key,
        status="running",
        pid=process.pid,
        started_at=started_at,
        current_count=current_count,
        after_count=current_count,
        new_records=0,
        error="",
    )

    stop_signal_sent = False
    stop_deadline = None
    returncode: Optional[int] = None

    while True:
        try:
            returncode = await asyncio.wait_for(process.wait(), timeout=1.0)
            break
        except asyncio.TimeoutError:
            current_count = await _count_source_documents(source_key)
            await _update_source_result(
                job_id,
                source_key,
                current_count=current_count,
                after_count=current_count,
                new_records=max(current_count - before_count, 0),
            )

            if await _run_stop_requested(job_id):
                if not stop_signal_sent:
                    _kill_pid_group(process.pid, force=False)
                    stop_signal_sent = True
                    stop_deadline = asyncio.get_running_loop().time() + 5
                    await _update_source_result(job_id, source_key, status="cancelling")
                elif stop_deadline and asyncio.get_running_loop().time() >= stop_deadline:
                    _kill_pid_group(process.pid, force=True)
            continue

    after_count = await _count_source_documents(source_key)
    stop_requested = await _run_stop_requested(job_id)
    completed_at = _utcnow_iso()

    if stop_requested or returncode in {-signal.SIGTERM, -signal.SIGKILL}:
        final_status = "cancelled"
        error_message = ""
    elif returncode == 0:
        final_status = "completed"
        error_message = ""
    else:
        final_status = "failed"
        error_message = f"Collector exited with code {returncode}"

    return await _build_final_source_result(
        job_id,
        source_key,
        status=final_status,
        before_count=before_count,
        current_count=after_count,
        started_at=started_at,
        completed_at=completed_at,
        error=error_message,
        pid=None,
    )


async def _execute_intelligence_update(job_id: str) -> None:
    run_doc = await _fetch_run(job_id)
    if not run_doc:
        return

    started_at = run_doc["started_at"]
    sources = run_doc.get("sources") or list(DEFAULT_INTELLIGENCE_SCAN_ORDER)
    triggered_by = run_doc.get("triggered_by", "dashboard")

    try:
        await intelligence_runs_col.update_one(
            {"_id": job_id},
            {"$set": {"status": "running", "updated_at": _utcnow_iso()}},
        )

        start_delivery = await _emit_arya_event(
            "scan_started",
            {
                "job_id": job_id,
                "triggered_by": triggered_by,
                "started_at": started_at,
                "sources": [
                    {
                        "source": source_key,
                        "label": INTELLIGENCE_SCAN_SOURCES[source_key]["label"],
                    }
                    for source_key in sources
                ],
            },
        )
        await intelligence_runs_col.update_one(
            {"_id": job_id},
            {"$set": {"delivery": {"start": start_delivery, "channel_label": _channel_label()}}},
        )

        source_results = await asyncio.gather(*[_run_source_scan(job_id, source) for source in sources])
        completed_at = _utcnow_iso()
        refreshed_run = await _fetch_run(job_id)
        if refreshed_run:
            source_results = refreshed_run.get("source_results", source_results)
        stop_requested = bool(refreshed_run and refreshed_run.get("stop_requested"))
        run_status, new_records_total = _derive_run_status(source_results, stop_requested)

        finish_delivery = await _emit_arya_event(
            "scan_completed",
            {
                "job_id": job_id,
                "triggered_by": triggered_by,
                "started_at": started_at,
                "completed_at": completed_at,
                "status": run_status,
                "new_records_total": new_records_total,
                "source_results": source_results,
            },
        )
        delivery = {
            "channel_label": _channel_label(),
            "webhook_configured": bool(cfg.n8n_webhook_url),
            "start": start_delivery,
            "finish": finish_delivery,
            "webhook_delivered": finish_delivery.get("webhook_delivered", False),
            "webhook_error": finish_delivery.get("webhook_error", ""),
        }

        update_doc = {
            "status": run_status,
            "completed_at": completed_at,
            "updated_at": completed_at,
            "source_results": source_results,
            "new_records_total": new_records_total,
            "delivery": delivery,
            "stop_requested": stop_requested,
        }
        await intelligence_runs_col.update_one({"_id": job_id}, {"$set": update_doc})
        _clear_feed_cache()

        notification = _build_notification_payload(
            job_id=job_id,
            status=run_status,
            triggered_by=triggered_by,
            started_at=started_at,
            completed_at=completed_at,
            source_results=source_results,
            delivery=delivery,
        )
        await _store_notification(notification)
    except Exception as exc:
        completed_at = _utcnow_iso()
        error_message = str(exc)
        await intelligence_runs_col.update_one(
            {"_id": job_id},
            {
                "$set": {
                    "status": "failed",
                    "completed_at": completed_at,
                    "updated_at": completed_at,
                    "error": error_message,
                    "delivery": {
                        "channel_label": _channel_label(),
                        "webhook_configured": bool(cfg.n8n_webhook_url),
                        "webhook_delivered": False,
                    },
                }
            },
        )
        _clear_feed_cache()
        notification = _build_notification_payload(
            job_id=job_id,
            status="failed",
            triggered_by=triggered_by,
            started_at=started_at,
            completed_at=completed_at,
            source_results=[],
            delivery={
                "channel_label": _channel_label(),
                "webhook_configured": bool(cfg.n8n_webhook_url),
                "webhook_delivered": False,
                "webhook_error": error_message,
            },
        )
        notification["message"] = f"{notification['message']} Error: {error_message}"
        await _store_notification(notification)
        log.error(f"Intelligence update job failed: {error_message}\n{traceback.format_exc()}")
    finally:
        final_run = await _fetch_run(job_id)
        final_status = final_run.get("status", "failed") if final_run else "failed"
        await _release_scan_lock(job_id, final_status)


SECRET_KEY = "a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
MFA_CHALLENGE_EXPIRE_MINUTES = 10
TWO_FACTOR_ISSUER = "DarkPulse Intelligence"
TWO_FACTOR_DIGITS = 6
TWO_FACTOR_PERIOD_SECONDS = 30
TWO_FACTOR_LOGIN_WINDOW = 4
TWO_FACTOR_SETUP_WINDOW = 4


def _totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _totp_secret_bytes(secret: str) -> bytes:
    normalized = (secret or "").strip().replace(" ", "").upper()
    padding = "=" * ((8 - len(normalized) % 8) % 8)
    return base64.b32decode(normalized + padding, casefold=True)


def _totp_token_for_time(secret: str, when: Optional[int] = None, digits: int = TWO_FACTOR_DIGITS, period: int = TWO_FACTOR_PERIOD_SECONDS) -> str:
    timestamp = int(when or time.time())
    counter = timestamp // period
    msg = struct.pack(">Q", counter)
    digest = hmac.new(_totp_secret_bytes(secret), msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    value = truncated % (10 ** digits)
    return f"{value:0{digits}d}"


def _verify_totp_token(secret: str, token: str, *, window: int = 1) -> bool:
    clean_token = re.sub(r"\s+", "", str(token or ""))
    if not re.fullmatch(rf"\d{{{TWO_FACTOR_DIGITS}}}", clean_token):
        return False
    now = int(time.time())
    for step_offset in range(-window, window + 1):
        if _totp_token_for_time(secret, now + (step_offset * TWO_FACTOR_PERIOD_SECONDS)) == clean_token:
            return True
    return False


def _two_factor_uri(username: str, secret: str) -> str:
    label = quote(f"{TWO_FACTOR_ISSUER}:{username}")
    query = urlencode({
        "secret": secret,
        "issuer": TWO_FACTOR_ISSUER,
        "algorithm": "SHA1",
        "digits": TWO_FACTOR_DIGITS,
        "period": TWO_FACTOR_PERIOD_SECONDS,
    })
    return f"otpauth://totp/{label}?{query}"


def _two_factor_qr_image_url(uri: str) -> str:
    return f"https://api.qrserver.com/v1/create-qr-code/?size=240x240&data={quote(uri, safe='')}"


def _two_factor_payload(user: dict) -> dict[str, Any]:
    enabled = bool(user.get("two_factor_enabled"))
    setup_pending = bool(user.get("two_factor_pending_secret")) and not enabled
    return {
        "enabled": enabled,
        "setup_pending": setup_pending,
        "required_on_login": enabled,
    }

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False

def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def create_access_token(data: dict, expires_delta: int = ACCESS_TOKEN_EXPIRE_MINUTES):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_delta)
    to_encode.setdefault("token_type", "access")
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Auth security scheme
security = HTTPBearer()

async def get_current_user(auth: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    token = auth.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("token_type", "access") != "access":
            raise credentials_exception
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = await users_col.find_one({"username": username})
    if user is None:
        raise credentials_exception
    return user

async def admin_required(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user




# ── Security Middleware ─────────────────────────────────────────────────────────
from fastapi import Header

async def verify_api_key(
    request: Request = None,
    websocket: WebSocket = None,
    x_api_key: str = Header(None, alias="X-API-Key")
):
    path = ""
    client = ""
    api_key_query = None
    
    if request:
        path = request.url.path
        client = request.client.host if request.client else ""
        api_key_query = request.query_params.get("api_key")
    elif websocket:
        path = websocket.url.path
        client = websocket.client.host if websocket.client else ""
        api_key_query = websocket.query_params.get("api_key")
        x_api_key = None # WebSockets don't natively send custom headers
        
    PUBLIC_PATHS = {
        "/",
        "/health",
        "/docs",
        "/openapi.json",
        "/auth/login",
        "/auth/login/verify-otp",
        "/auth/register",
        "/scan/repo",
    }
    
    if path in PUBLIC_PATHS:
        return
        
    if not cfg.api_key:
        return
        
    key_to_check = x_api_key or api_key_query
    
    if key_to_check != cfg.api_key:
        log.warning(f"Unauthorized request to {path} from {client}")
        raise HTTPException(status_code=403, detail="Invalid or missing API key")

app = FastAPI(
    title="Dark Pulse Local API",
    version="1.0",
    dependencies=[Depends(verify_api_key)],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=cfg.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Ensure default admin exists on startup
@app.on_event("startup")
async def create_default_admin():
    admin = await users_col.find_one({"username": "admin"})
    if not admin:
        hashed = get_password_hash("1qaz!QAZ")
        await users_col.insert_one({
            "username": "admin",
            "password": hashed,
            "email": "admin@example.com",
            "name": "Administrator",
            "status": "approved",
            "role": "admin",
            "two_factor_enabled": False,
        })
        log.info("Default admin user created.")

    await automation_state_col.update_one(
        {"_id": SCAN_LOCK_ID},
        {
            "$setOnInsert": {
                "status": "idle",
                "job_id": None,
                "updated_at": _utcnow_iso(),
            }
        },
        upsert=True,
    )


async def _run_healing_discovery() -> dict[str, Any]:
    return await asyncio.to_thread(get_healing_service().discover_targets)


async def _run_healing_monitor(*, limit: int | None = None, target_key: str | None = None) -> dict[str, Any]:
    return await asyncio.to_thread(get_healing_service().run_monitor, limit=limit, target_key=target_key)


async def _healing_monitor_loop() -> None:
    await asyncio.sleep(30)
    while True:
        try:
            await _run_healing_discovery()
            await _run_healing_monitor(limit=cfg.healing_monitor_target_limit or None)
        except Exception as exc:
            log.error(f"Healing monitor loop failed: {exc}", exc_info=True)
        await asyncio.sleep(max(cfg.healing_monitor_interval_minutes, 5) * 60)


@app.on_event("startup")
async def startup_healing_monitor():
    global _healing_monitor_task
    try:
        await _run_healing_discovery()
    except Exception as exc:
        log.error(f"Initial healing discovery failed: {exc}", exc_info=True)

    if cfg.healing_monitor_enabled and (_healing_monitor_task is None or _healing_monitor_task.done()):
        _healing_monitor_task = asyncio.create_task(_healing_monitor_loop())


@app.on_event("shutdown")
async def shutdown_healing_monitor():
    global _healing_monitor_task
    if _healing_monitor_task and not _healing_monitor_task.done():
        _healing_monitor_task.cancel()
        try:
            await _healing_monitor_task
        except asyncio.CancelledError:
            pass
    _healing_monitor_task = None


# ---------- Static file serving ----------
_STATIC_DIR = pathlib.Path(__file__).resolve().parent

# ---------- API endpoints ----------
@app.get("/")
def home():
    """Serve the frontend dashboard."""
    return FileResponse(_STATIC_DIR / "index.html", media_type="text/html")

@app.post("/api/trigger-smart-update")
async def trigger_smart_update(current_user: dict = Depends(get_current_user)):
    """Start a one-click intelligence update and emit Arya-ready notifications."""
    job_id = f"scan_{uuid4().hex[:12]}"
    sources = list(DEFAULT_INTELLIGENCE_SCAN_ORDER)
    triggered_by = current_user.get("username") or current_user.get("name") or "dashboard"

    lock = await _acquire_scan_lock(job_id, triggered_by, sources)
    if not lock:
        current_lock = await automation_state_col.find_one({"_id": SCAN_LOCK_ID})
        active_run = None
        if current_lock and current_lock.get("job_id"):
            active_run = await _fetch_run(current_lock["job_id"])
        return {
            "status": "busy",
            "message": "An intelligence update is already running.",
            "job": active_run,
        }

    started_at = _utcnow_iso()
    source_counts = await asyncio.gather(*[_count_source_documents(source) for source in sources])
    source_results = [
        _build_source_result(source_key, before_count)
        for source_key, before_count in zip(sources, source_counts)
    ]
    run_doc = {
        "_id": job_id,
        "job_id": job_id,
        "status": "queued",
        "triggered_by": triggered_by,
        "sources": sources,
        "started_at": started_at,
        "updated_at": started_at,
        "completed_at": None,
        "new_records_total": 0,
        "source_results": source_results,
        "stop_requested": False,
        "delivery": {
            "channel_label": _channel_label(),
            "webhook_configured": bool(cfg.n8n_webhook_url),
            "webhook_delivered": False,
        },
    }
    await intelligence_runs_col.replace_one({"_id": job_id}, run_doc, upsert=True)

    notification = _build_notification_payload(
        job_id=job_id,
        status="running",
        triggered_by=triggered_by,
        started_at=started_at,
        source_results=[],
        delivery=run_doc["delivery"],
    )
    await _store_notification(notification)

    asyncio.create_task(_execute_intelligence_update(job_id))
    delivery_mode = "Dashboard Alert"
    if cfg.n8n_webhook_url:
        delivery_mode = f"Dashboard Alert + {_channel_label()} via n8n"

    return {
        "status": "ok",
        "message": f"Automated intelligence update started. Arya delivery: {delivery_mode}.",
        "job": run_doc,
        "notification": notification,
    }


@app.post("/api/intelligence/stop")
async def stop_intelligence_update(current_user: dict = Depends(get_current_user)):
    lock_doc, _ = await _reconcile_active_scan_state()
    job_id = lock_doc.get("job_id")
    if not job_id:
        latest_run = await _fetch_latest_run()
        return {
            "status": "idle",
            "message": "No active scan is running right now.",
            "job": latest_run,
        }

    run_doc = await _fetch_run(job_id)
    if not run_doc or run_doc.get("status") not in RUNNING_SCAN_STATUSES:
        latest_run = await _fetch_latest_run()
        return {
            "status": "idle",
            "message": "No active scan is running right now.",
            "job": latest_run,
        }

    stopped_by = current_user.get("username") or current_user.get("name") or "operator"
    updated_at = _utcnow_iso()
    await intelligence_runs_col.update_one(
        {"_id": job_id},
        {
            "$set": {
                "status": "cancelling",
                "stop_requested": True,
                "stopped_by": stopped_by,
                "updated_at": updated_at,
            }
        },
    )
    await automation_state_col.update_one(
        {"_id": SCAN_LOCK_ID, "job_id": job_id},
        {"$set": {"status": "cancelling", "updated_at": updated_at}},
    )

    for source_result in run_doc.get("source_results", []):
        source_key = source_result.get("source")
        pid = source_result.get("pid")
        status = source_result.get("status")
        if status == "queued" and source_key:
            await _update_source_result(
                job_id,
                source_key,
                status="cancelled",
                completed_at=updated_at,
                pid=None,
            )
            continue
        if status in {"running", "cancelling"} and pid:
            _kill_pid_group(int(pid), force=False)
            if source_key:
                await _update_source_result(job_id, source_key, status="cancelling")

    _, active_run = await _reconcile_active_scan_state()
    latest_run = active_run or await _fetch_run(job_id)
    notification = _build_notification_payload(
        job_id=job_id,
        status=(latest_run or run_doc).get("status", "cancelling"),
        triggered_by=run_doc.get("triggered_by", stopped_by),
        started_at=run_doc.get("started_at", updated_at),
        source_results=(latest_run or run_doc).get("source_results", []),
        delivery=(latest_run or run_doc).get("delivery", {}),
    )
    await _store_notification(notification)

    return {
        "status": "ok",
        "message": "Stop requested. Running collectors are being shut down.",
        "job": latest_run,
        "notification": notification,
    }


@app.get("/api/intelligence/status")
async def intelligence_status():
    lock_doc, active_run = await _reconcile_active_scan_state()

    latest_run = await _fetch_latest_run()
    latest_notification = await _fetch_latest_notification()
    return {
        "active_run": active_run,
        "latest_run": latest_run,
        "latest_notification": latest_notification,
        "lock": {
            "status": lock_doc.get("status", "idle"),
            "job_id": lock_doc.get("job_id"),
            "updated_at": lock_doc.get("updated_at"),
        },
    }


@app.get("/healing/stats")
async def healing_stats(current_user: dict = Depends(get_current_user)):
    stats = await asyncio.to_thread(get_healing_service().get_stats)
    return {"status": "ok", "stats": stats}


@app.get("/healing/targets")
async def healing_targets(
    limit: int = Query(80, ge=1, le=300),
    current_user: dict = Depends(get_current_user),
):
    items = await asyncio.to_thread(get_healing_service().list_targets, limit=limit)
    return {"status": "ok", "count": len(items), "items": items}


@app.get("/healing/events")
async def healing_events(
    limit: int = Query(40, ge=1, le=200),
    target_key: str = Query(""),
    current_user: dict = Depends(get_current_user),
):
    items = await asyncio.to_thread(
        get_healing_service().list_events,
        limit=limit,
        target_key=target_key.strip() or None,
    )
    return {"status": "ok", "count": len(items), "items": items}


@app.post("/healing/discover", dependencies=[Depends(admin_required)])
async def healing_discover():
    result = await _run_healing_discovery()
    return {
        "status": "ok",
        "message": f"Discovered {result.get('discovered', 0)} monitor targets.",
        **result,
    }


@app.post("/healing/run", dependencies=[Depends(admin_required)])
async def healing_run(request: Request):
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    limit = int(body.get("limit") or cfg.healing_monitor_target_limit or 12)
    result = await _run_healing_monitor(limit=limit)
    return {
        "status": "ok",
        "message": f"Healing scan finished for {result.get('target_count', 0)} targets.",
        **result,
    }


@app.post("/healing/run/{target_key}", dependencies=[Depends(admin_required)])
async def healing_run_target(target_key: str):
    result = await _run_healing_monitor(target_key=target_key, limit=1)
    return {
        "status": "ok",
        "message": f"Healing check finished for {target_key}.",
        **result,
    }

@app.get("/style.css")
def serve_css():
    return FileResponse(_STATIC_DIR / "style.css", media_type="text/css")


@app.get("/app.js")
def serve_js():
    return FileResponse(_STATIC_DIR / "app.js", media_type="application/javascript")

@app.get("/health")
async def health():
    """Public health check — pings MongoDB."""
    try:
        await client.admin.command('ping')
        mongo_ok = True
    except Exception as e:
        mongo_ok = False
        log.error(f"MongoDB health check failed: {e}")
    return {
        "status": "ok" if mongo_ok else "degraded",
        "database": "mongodb connected" if mongo_ok else "unreachable",
    }


# ── Authentication Endpoints ────────────────────────────────────────────────
@app.post("/auth/login")
async def login(request: Request):
    body = await request.json()
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    
    user = await users_col.find_one({"username": username})
    if not user or not verify_password(password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    if user.get("status") != "approved":
        raise HTTPException(status_code=403, detail="Account pending approval")

    if user.get("two_factor_enabled"):
        challenge_token = create_access_token(
            data={
                "sub": user["username"],
                "role": user.get("role", "user"),
                "token_type": "mfa_challenge",
                "purpose": "otp_login",
            },
            expires_delta=MFA_CHALLENGE_EXPIRE_MINUTES,
        )
        return {
            "mfa_required": True,
            "challenge_type": "otp",
            "challenge_token": challenge_token,
            "username": user["username"],
        }

    pending_secret = user.get("two_factor_pending_secret")
    if pending_secret:
        otpauth_url = _two_factor_uri(user["username"], pending_secret)
        challenge_token = create_access_token(
            data={
                "sub": user["username"],
                "role": user.get("role", "user"),
                "token_type": "mfa_challenge",
                "purpose": "otp_setup",
            },
            expires_delta=MFA_CHALLENGE_EXPIRE_MINUTES,
        )
        return {
            "mfa_required": True,
            "setup_required": True,
            "challenge_type": "setup",
            "challenge_token": challenge_token,
            "username": user["username"],
            "qr_code_url": _two_factor_qr_image_url(otpauth_url),
            "otpauth_url": otpauth_url,
            "manual_secret": pending_secret,
            "issuer": TWO_FACTOR_ISSUER,
        }

    access_token = create_access_token(data={"sub": user["username"], "role": user.get("role", "user")})
    return {"access_token": access_token, "token_type": "bearer", "role": user.get("role", "user")}


@app.post("/auth/login/verify-otp")
async def verify_login_otp(request: Request):
    body = await request.json()
    challenge_token = (body.get("challenge_token") or "").strip()
    otp_code = re.sub(r"\s+", "", str(body.get("otp") or ""))

    if not challenge_token:
        raise HTTPException(status_code=400, detail="Challenge token is required")
    if not re.fullmatch(rf"\d{{{TWO_FACTOR_DIGITS}}}", otp_code):
        raise HTTPException(status_code=400, detail="Enter a valid 6-digit OTP code")

    try:
        payload = jwt.decode(challenge_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("token_type") != "mfa_challenge":
            raise HTTPException(status_code=401, detail="Invalid 2FA challenge")
    except JWTError:
        raise HTTPException(status_code=401, detail="2FA session expired. Sign in again.")

    username = payload.get("sub")
    purpose = payload.get("purpose")
    if not username or purpose not in {"otp_login", "otp_setup"}:
        raise HTTPException(status_code=401, detail="Invalid 2FA challenge")

    user = await users_col.find_one({"username": username})
    if not user or user.get("status") != "approved":
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    secret = user.get("two_factor_secret") if purpose == "otp_login" else user.get("two_factor_pending_secret")
    if not secret:
        raise HTTPException(status_code=400, detail="2FA setup is not available. Sign in again.")

    verify_window = TWO_FACTOR_SETUP_WINDOW if purpose == "otp_setup" else TWO_FACTOR_LOGIN_WINDOW
    if not _verify_totp_token(secret, otp_code, window=verify_window):
        raise HTTPException(
            status_code=401,
            detail="Invalid OTP code. If it just refreshed, try the newest code and make sure your authenticator time is synced.",
        )

    if purpose == "otp_setup":
        await users_col.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "two_factor_enabled": True,
                    "two_factor_secret": secret,
                    "two_factor_enabled_at": datetime.utcnow().isoformat(),
                },
                "$unset": {
                    "two_factor_pending_secret": "",
                    "two_factor_requested_at": "",
                },
            },
        )

    access_token = create_access_token(data={"sub": user["username"], "role": user.get("role", "user")})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": user.get("role", "user"),
    }


@app.post("/auth/register")
async def register(request: Request):
    body = await request.json()
    username = body.get("username", "").strip()
    password = body.get("password", "")
    email = body.get("email", "").strip()
    name = body.get("name", "").strip()
    
    if not username or not password or not email:
        raise HTTPException(status_code=400, detail="Username, password, and email are required")
        
    if " " in username:
        raise HTTPException(status_code=400, detail="Username cannot contain spaces")
        
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long")
        
    if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
        raise HTTPException(status_code=400, detail="Invalid email format")
        
    existing = await users_col.find_one({"$or": [{"username": username}, {"email": email}]})
    if existing:
        raise HTTPException(status_code=400, detail="Username or Email already registered")
        
    hashed = get_password_hash(password)
    user_doc = {
        "username": username,
        "password": hashed,
        "email": email,
        "name": name or username,
        "status": "pending",
        "role": "user",
        "created_at": datetime.utcnow().isoformat(),
        "two_factor_enabled": False,
    }
    await users_col.insert_one(user_doc)
    return {"status": "ok", "message": "Registration successful. Please wait for admin approval."}


@app.get("/auth/2fa/status")
async def two_factor_status(current_user: dict = Depends(get_current_user)):
    return _two_factor_payload(current_user)


@app.post("/auth/2fa/enable")
async def enable_two_factor(current_user: dict = Depends(get_current_user)):
    if current_user.get("two_factor_enabled"):
        return {
            "status": "ok",
            "message": "2FA is already enabled for this account.",
            **_two_factor_payload(current_user),
        }

    secret = _totp_secret()
    await users_col.update_one(
        {"_id": current_user["_id"]},
        {
            "$set": {
                "two_factor_enabled": False,
                "two_factor_pending_secret": secret,
                "two_factor_requested_at": datetime.utcnow().isoformat(),
            },
            "$unset": {"two_factor_secret": ""},
        },
    )
    return {
        "status": "ok",
        "message": "2FA setup started. Sign in again to scan the QR code and verify your OTP.",
        "enabled": False,
        "setup_pending": True,
    }


@app.post("/auth/2fa/disable")
async def disable_two_factor(current_user: dict = Depends(get_current_user)):
    await users_col.update_one(
        {"_id": current_user["_id"]},
        {
            "$set": {
                "two_factor_enabled": False,
                "two_factor_disabled_at": datetime.utcnow().isoformat(),
            },
            "$unset": {
                "two_factor_secret": "",
                "two_factor_pending_secret": "",
                "two_factor_enabled_at": "",
                "two_factor_requested_at": "",
            },
        },
    )
    return {
        "status": "ok",
        "message": "2FA disabled.",
        "enabled": False,
        "setup_pending": False,
    }


# ── Admin User Management ──────────────────────────────────────────────────
@app.get("/admin/users", dependencies=[Depends(admin_required)])
async def list_users():
    cursor = users_col.find({}, {"password": 0})
    users = await cursor.to_list(length=100)
    for user in users:
        if "_id" in user:
            user["_id"] = str(user["_id"])
    return {"users": users}


@app.post("/admin/users/{username}/approve", dependencies=[Depends(admin_required)])
async def approve_user(username: str):
    result = await users_col.update_one({"username": username}, {"$set": {"status": "approved"}})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "ok", "message": f"User {username} approved"}


@app.post("/admin/users/{username}/reject", dependencies=[Depends(admin_required)])
async def reject_user(username: str):
    result = await users_col.delete_one({"username": username})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "ok", "message": f"User {username} rejected/deleted"}


@app.post("/admin/users", dependencies=[Depends(admin_required)])
async def admin_create_user(request: Request):
    body = await request.json()
    username = body.get("username", "").strip()
    password = body.get("password", "")
    email = body.get("email", "").strip()
    name = body.get("name", "").strip()
    role = body.get("role", "user")
    
    if not username or not password or not email:
        raise HTTPException(status_code=400, detail="Username, password, and email are required")
        
    if " " in username:
        raise HTTPException(status_code=400, detail="Username cannot contain spaces")
        
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long")
        
    if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
        raise HTTPException(status_code=400, detail="Invalid email format")
        
    existing = await users_col.find_one({"$or": [{"username": username}, {"email": email}]})
    if existing:
        raise HTTPException(status_code=400, detail="Username or Email already exists")
        
    hashed = get_password_hash(password)
    user_doc = {
        "username": username,
        "password": hashed,
        "email": email,
        "name": name or username,
        "status": "approved",
        "role": role,
        "created_at": datetime.utcnow().isoformat(),
        "two_factor_enabled": False,
    }
    await users_col.insert_one(user_doc)
    return {"status": "ok", "message": "User created successfully"}

@app.get("/stats/map")
async def get_map_stats():
    """Return country impact data for leaks and defacement items."""
    leak_items = sorted(await _fetch_threat_items("leak"), key=_feed_sort_key, reverse=True)
    defacement_items = sorted(await _fetch_threat_items("defacement"), key=_feed_sort_key, reverse=True)

    bucket: Dict[str, Dict[str, Any]] = {}

    def _append_unique(values: list[str], value: str, limit: int = 4) -> None:
        clean_value = _clean_text(value)
        if not clean_value or clean_value in values or len(values) >= limit:
            return
        values.append(clean_value)

    def _append_example(entry: Dict[str, Any], item: dict[str, Any], max_examples: int = 6) -> None:
        if len(entry["examples"]) >= max_examples:
            return
        aid = _clean_text(item.get("aid"))
        if aid and any(example.get("aid") == aid for example in entry["examples"]):
            return
        entry["examples"].append({
            "aid": aid,
            "title": _clean_text(item.get("title"), fallback="Untitled"),
            "source": _humanize_source_name(item.get("source"), fallback=item.get("source_type", "intel")),
            "source_type": _clean_text(item.get("source_type"), fallback="intel"),
            "date": _clean_text(item.get("scraped_at") or item.get("date")),
        })

    def _touch(code: str) -> Dict[str, Any]:
        if code not in bucket:
            bucket[code] = {
                "code": code,
                "name": _COUNTRY_CODE_TO_NAME.get(code, code),
                "leak_count": 0,
                "defacement_count": 0,
                "total": 0,
                "examples": [],
                "leak_sources": [],
                "defacement_sources": [],
            }
        return bucket[code]

    for item in leak_items:
        for code in item.get("country_codes", []) or []:
            entry = _touch(code)
            entry["leak_count"] += 1
            entry["total"] += 1
            _append_unique(entry["leak_sources"], _humanize_source_name(item.get("source"), fallback="Leak Intel"))
            _append_example(entry, item)

    for item in defacement_items:
        for code in item.get("country_codes", []) or []:
            entry = _touch(code)
            entry["defacement_count"] += 1
            entry["total"] += 1
            _append_unique(entry["defacement_sources"], _humanize_source_name(item.get("source"), fallback="Defacement Intel"))
            _append_example(entry, item)

    countries = sorted(bucket.values(), key=lambda item: (-item["total"], item["name"]))
    return {
        "map_data": {item["code"]: item["total"] for item in countries},
        "countries": countries,
        "summary": {
            "affected_countries": len(countries),
            "leak_items_with_country": sum(1 for item in leak_items if item.get("country_codes")),
            "defacement_items_with_country": sum(1 for item in defacement_items if item.get("country_codes")),
            "updated_at": _utcnow_iso(),
        },
    }


# ── Collection holding raw crawl data (Redis-style KV) ──────────────────────
kv_col = db["redis_kv_store"]

_THREAT_PREFIXES = {
    "EXPLOIT_ITEMS": "exploit",
    "EXPLOIT_ENTITIES": None,
    "LEAK_ITEMS": "leak",
    "LEAK_ENTITIES": None,
    "DEFACEMENT_ITEMS": "defacement",
    "DEFACEMENT_ENTITIES": None,
    "SOCIAL_ITEMS": "social",
    "SOCIAL_ENTITIES": None,
    "API_ITEMS": "api",
    "API_ENTITIES": None,
}

_FEED_SOURCE_ALIASES = {
    "all": "all",
    "news": "news",
    "exploit": "exploit",
    "leak": "leak",
    "defacement": "defacement",
    "social": "social",
    "api": "api",
    "forums": "social",
    "marketplaces": "leak",
    "github": "api",
    "apk": "api",
}

_COUNTRY_CODE_TO_NAME = {
    "AE": "United Arab Emirates",
    "AR": "Argentina",
    "AT": "Austria",
    "AU": "Australia",
    "BD": "Bangladesh",
    "BE": "Belgium",
    "BR": "Brazil",
    "CA": "Canada",
    "CH": "Switzerland",
    "CL": "Chile",
    "CN": "China",
    "CO": "Colombia",
    "CZ": "Czech Republic",
    "DE": "Germany",
    "DK": "Denmark",
    "EG": "Egypt",
    "ES": "Spain",
    "FI": "Finland",
    "FR": "France",
    "GB": "United Kingdom",
    "GR": "Greece",
    "HU": "Hungary",
    "ID": "Indonesia",
    "IE": "Ireland",
    "IL": "Israel",
    "IN": "India",
    "IQ": "Iraq",
    "IR": "Iran",
    "IT": "Italy",
    "JP": "Japan",
    "KE": "Kenya",
    "KR": "South Korea",
    "LK": "Sri Lanka",
    "MX": "Mexico",
    "MY": "Malaysia",
    "NG": "Nigeria",
    "NL": "Netherlands",
    "NO": "Norway",
    "NZ": "New Zealand",
    "PH": "Philippines",
    "PK": "Pakistan",
    "PL": "Poland",
    "PT": "Portugal",
    "RO": "Romania",
    "RU": "Russia",
    "SA": "Saudi Arabia",
    "SE": "Sweden",
    "SG": "Singapore",
    "TH": "Thailand",
    "TR": "Turkey",
    "UA": "Ukraine",
    "US": "United States",
    "VN": "Vietnam",
    "ZA": "South Africa",
}

_COUNTRY_ALIASES = {
    "united states": "US",
    "u s": "US",
    "usa": "US",
    "united kingdom": "GB",
    "great britain": "GB",
    "uk": "GB",
    "england": "GB",
    "australia": "AU",
    "austria": "AT",
    "bangladesh": "BD",
    "belgium": "BE",
    "brazil": "BR",
    "canada": "CA",
    "switzerland": "CH",
    "chile": "CL",
    "china": "CN",
    "colombia": "CO",
    "czech republic": "CZ",
    "germany": "DE",
    "denmark": "DK",
    "egypt": "EG",
    "spain": "ES",
    "finland": "FI",
    "france": "FR",
    "greece": "GR",
    "hungary": "HU",
    "indonesia": "ID",
    "ireland": "IE",
    "israel": "IL",
    "india": "IN",
    "iraq": "IQ",
    "iran": "IR",
    "italy": "IT",
    "japan": "JP",
    "kenya": "KE",
    "south korea": "KR",
    "korea": "KR",
    "sri lanka": "LK",
    "mexico": "MX",
    "malaysia": "MY",
    "nigeria": "NG",
    "netherlands": "NL",
    "norway": "NO",
    "new zealand": "NZ",
    "philippines": "PH",
    "pakistan": "PK",
    "poland": "PL",
    "portugal": "PT",
    "romania": "RO",
    "russia": "RU",
    "saudi arabia": "SA",
    "sweden": "SE",
    "singapore": "SG",
    "thailand": "TH",
    "turkey": "TR",
    "ukraine": "UA",
    "vietnam": "VN",
    "south africa": "ZA",
}


def _canonical_source_type(source_type: str) -> str:
    normalized = (source_type or "all").strip().lower()
    return _FEED_SOURCE_ALIASES.get(normalized, normalized)


def _coerce_datetime_string(value: Any) -> str:
    if value in (None, "", []):
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (int, float)):
        timestamp = float(value)
        if timestamp > 1_000_000_000_000:
            timestamp /= 1000.0
        try:
            return datetime.utcfromtimestamp(timestamp).isoformat() + "Z"
        except Exception:
            return str(value)
    if isinstance(value, str):
        cleaned = value.strip()
        if cleaned.isdigit():
            return _coerce_datetime_string(int(cleaned))
        return cleaned
    return str(value)


def _coerce_scalar(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, list):
        values = [str(item) for item in value if item not in (None, "", [])]
        return ", ".join(values)
    if isinstance(value, dict):
        return str(value.get("type") or value.get("value") or "")
    return str(value)


def _coerce_list(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item not in (None, "", [])]
    return [str(value)]


_PLACEHOLDER_TITLES = {"", "(no title)", "untitled", "unknown"}
_PLACEHOLDER_DESCRIPTIONS = {"", "content not found.", "no description available.", "summary unavailable."}
_SOURCE_LABEL_ALIASES = {
    "thehackernews": "thehackernews.com",
    "_thehackernews": "thehackernews.com",
    "ransomware_live": "ransomware.live",
    "_ransomware_live": "ransomware.live",
    "tweetfeed": "tweetfeed.live",
    "_tweetfeed": "tweetfeed.live",
    "zone_xsec": "zone-xsec.com",
    "_zone_xsec": "zone-xsec.com",
}


def _clean_text_candidate(value: Any) -> str:
    return re.sub(r"\s+", " ", _coerce_scalar(value).strip())


def _meaningful_title(value: Any) -> str:
    text = _clean_text_candidate(value)
    return "" if text.lower() in _PLACEHOLDER_TITLES else text


def _meaningful_description(value: Any) -> str:
    text = _clean_text_candidate(value)
    return "" if text.lower() in _PLACEHOLDER_DESCRIPTIONS else text


def _excerpt_text(value: Any, limit: int = 400) -> str:
    text = _clean_text_candidate(value)
    if not text:
        return ""
    if len(text) <= limit:
        return text
    clipped = text[:limit].rsplit(" ", 1)[0].strip() or text[:limit].strip()
    if clipped.endswith(("...", "…")):
        return clipped
    return f"{clipped}..."


def _extract_hostname(value: Any) -> str:
    text = _clean_text_candidate(value)
    if not text:
        return ""
    try:
        parsed = urlparse(text)
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def _normalize_source_label(value: Any) -> str:
    text = _clean_text_candidate(value)
    if not text:
        return ""
    lowered = text.lower()
    if lowered in _SOURCE_LABEL_ALIASES:
        return _SOURCE_LABEL_ALIASES[lowered]
    if lowered.startswith("www."):
        return lowered
    if "." in lowered:
        return lowered
    return text.lstrip("_").replace("__", "_").replace("_", " ").strip()


def _title_from_url(value: Any) -> str:
    text = _clean_text_candidate(value)
    if not text:
        return ""
    try:
        parsed = urlparse(text)
        slug = unquote((parsed.path or "").rstrip("/").rsplit("/", 1)[-1])
        slug = re.sub(r"\.[A-Za-z0-9]+$", "", slug)
        slug = re.sub(r"^\d{4}-\d{2}-\d{2}-", "", slug)
        slug = slug.replace("-", " ").replace("_", " ").strip()
        if not slug:
            slug = parsed.hostname or ""
        parts = [part for part in slug.split() if part]
        if not parts:
            return ""
        return " ".join(part.upper() if part.isupper() else part.capitalize() for part in parts)
    except Exception:
        return ""


_IP_ADDRESS_RE = re.compile(
    r"(?<![\w:])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w:])"
)
_IMG_SRC_RE = re.compile(r"<img[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        if text in seen:
            continue
        seen.add(text)
        deduped.append(text)
    return deduped


def _flatten_strings(value: Any, limit: int = 128) -> list[str]:
    flattened: list[str] = []

    def visit(current: Any):
        if len(flattened) >= limit or current in (None, ""):
            return
        if isinstance(current, dict):
            for inner in current.values():
                visit(inner)
            return
        if isinstance(current, (list, tuple, set)):
            for inner in current:
                visit(inner)
            return
        text = str(current).strip()
        if text:
            flattened.append(text)

    visit(value)
    return flattened


def _extract_values(data: dict, *fields: str) -> list[str]:
    values: list[str] = []
    if not isinstance(data, dict):
        return values

    nested_sources = [data]
    for container_key in ("extra", "m_extra", "m_entity"):
        nested = data.get(container_key)
        if isinstance(nested, dict):
            nested_sources.append(nested)

    for field in fields:
        for source in nested_sources:
            if field not in source:
                continue
            values.extend(_flatten_strings(source.get(field)))

    return _dedupe_strings(values)


def _normalize_entities(value: Any) -> list[dict]:
    if not value:
        return []
    if isinstance(value, list):
        normalized = []
        for item in value:
            if isinstance(item, dict):
                normalized.append({
                    "label": str(item.get("label", "entity")),
                    "text": str(item.get("text", "")),
                    "score": item.get("score"),
                })
            else:
                normalized.append({"label": "entity", "text": str(item)})
        return normalized
    return []


def _extract_field(data: dict, *fields: str) -> str:
    for value in _extract_values(data, *fields):
        if value:
            return value
    return ""


def _merge_threat_payloads(item_data: dict, entity_data: Optional[dict]) -> dict:
    if not entity_data:
        return dict(item_data)

    merged = dict(item_data)
    for key, value in entity_data.items():
        if key in {"m_source", "m_collector_type"}:
            continue

        existing = merged.get(key)
        if existing in (None, "", [], {}):
            merged[key] = value
            continue

        if isinstance(existing, dict) and isinstance(value, dict):
            combined = dict(value)
            combined.update(existing)
            merged[key] = combined
            continue

        if isinstance(existing, (list, tuple, set)) or isinstance(value, (list, tuple, set)):
            merged[key] = _dedupe_strings(_flatten_strings(existing) + _flatten_strings(value))

    merged["m_entity"] = entity_data
    return merged


def _normalize_image_ref(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith("data:image/"):
        return text
    compact = "".join(text.split())
    if len(compact) > 120 and re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        return f"data:image/jpeg;base64,{compact}"
    if text.startswith(("http://", "https://")):
        return text
    return ""


def _extract_image_refs_from_html(value: Any) -> list[str]:
    refs: list[str] = []
    for html_blob in _flatten_strings(value, limit=32):
        refs.extend(match.strip() for match in _IMG_SRC_RE.findall(html_blob) if match.strip())
    return _dedupe_strings(refs)


def _extract_ip_addresses(data: dict) -> str:
    candidates: list[str] = []
    candidates.extend(
        _extract_values(
            data,
            "m_ip",
            "ip_address",
            "ip",
            "ips",
            "m_url",
            "url",
            "m_source_url",
            "source_url",
            "m_weblink",
            "weblink",
            "m_mirror_links",
            "mirror_links",
            "m_content",
            "content",
            "m_description",
            "description",
            "m_important_content",
            "important_content",
        )
    )
    candidates.extend(_flatten_strings(data.get("m_extra") or data.get("extra") or {}))

    found: list[str] = []
    for candidate in candidates:
        try:
            host = urlparse(candidate).hostname or ""
        except Exception:
            host = ""
        if host and _IP_ADDRESS_RE.fullmatch(host):
            found.append(host)
        found.extend(match.group(0) for match in _IP_ADDRESS_RE.finditer(candidate))

    return ", ".join(_dedupe_strings(found))


def _extract_screenshot_links(data: dict) -> list[str]:
    refs: list[str] = []
    refs.extend(
        _extract_values(
            data,
            "m_screenshot_links",
            "screenshot_links",
            "screenshots",
            "m_logo_or_images",
            "logo_or_images",
            "original_screenshot_url",
            "hero_image",
            "og_image",
            "m_screenshot_url",
            "screenshot_url",
            "image",
            "images",
        )
    )
    refs.extend(_extract_image_refs_from_html(_extract_values(data, "content_html", "m_ref_html")))
    normalized = [_normalize_image_ref(ref) for ref in refs]
    return _dedupe_strings([ref for ref in normalized if ref])


def _extract_primary_screenshot(data: dict) -> str:
    direct = _extract_field(data, "m_screenshot", "screenshot")
    normalized = _normalize_image_ref(direct)
    if normalized:
        return normalized
    links = _extract_screenshot_links(data)
    return links[0] if links else ""


def _extract_evidence_links(data: dict) -> list[str]:
    refs = _extract_values(
        data,
        "m_source_url",
        "source_url",
        "m_mirror_links",
        "mirror_links",
        "m_weblink",
        "weblink",
        "m_external_scanners",
        "external_scanners",
        "m_social_media_profiles",
        "social_media_profiles",
        "m_channel_url",
        "m_message_sharable_link",
    )
    return _dedupe_strings([ref for ref in refs if ref.startswith(("http://", "https://"))])


def _extract_network(data: dict) -> str:
    network = data.get("m_network", data.get("network"))
    if isinstance(network, dict):
        return _coerce_scalar(network.get("type")) or "clearnet"
    return _coerce_scalar(network) or "clearnet"


def _normalize_country_code(code: str) -> str:
    normalized = (code or "").strip().upper()
    if normalized == "UK":
        return "GB"
    return normalized if normalized in _COUNTRY_CODE_TO_NAME else ""


def _country_codes_from_hostname(hostname: str) -> list[str]:
    if not hostname:
        return []
    parts = [part for part in hostname.lower().split(".") if part]
    for part in reversed(parts):
        if len(part) == 2 and part.isalpha():
            code = _normalize_country_code(part)
            if code:
                return [code]
    return []


def _country_codes_from_text(text: str) -> list[str]:
    if not text:
        return []
    normalized = re.sub(r"[^a-z0-9]+", " ", text.lower())
    haystack = f" {normalized} "
    codes = []
    for alias, code in _COUNTRY_ALIASES.items():
        if f" {alias} " in haystack:
            codes.append(code)
    return sorted(set(codes))


def _infer_country_codes(item: dict, raw_data: dict) -> list[str]:
    codes: set[str] = set()

    explicit = [
        _extract_field(raw_data, "country", "m_country", "location", "m_location"),
        _extract_field(item, "source_country", "country", "country_name"),
    ]
    for value in explicit:
        if not value:
            continue
        code = _normalize_country_code(value)
        if code:
            codes.add(code)
        else:
            for inferred in _country_codes_from_text(value):
                codes.add(inferred)

    for candidate in [
        item.get("url"),
        item.get("seed_url"),
        _extract_field(raw_data, "url", "m_url", "base_url", "m_base_url"),
    ]:
        if not candidate:
            continue
        try:
            host = urlparse(candidate).hostname or ""
        except Exception:
            host = ""
        for inferred in _country_codes_from_hostname(host):
            codes.add(inferred)

    source_type = (item.get("source_type") or "").strip().lower()
    if source_type not in {"defacement", "social"}:
        text_blob = " ".join([
            _extract_field(raw_data, "title", "m_title", "description", "m_description"),
            _extract_field(raw_data, "content", "m_content", "important_content", "m_important_content"),
            item.get("title", ""),
            item.get("description", ""),
            item.get("summary", ""),
        ])
        for inferred in _country_codes_from_text(text_blob):
            codes.add(inferred)

    return sorted(codes)


def _feed_sort_key(item: dict) -> str:
    return (
        item.get("scraped_at")
        or item.get("date")
        or item.get("published_at")
        or item.get("created_at")
        or ""
    )


def _filter_feed_items(items: list[dict], query: str) -> list[dict]:
    needle = _normalize_search_text(query)
    if not needle:
        return items
    terms = _query_search_terms(query)

    scored: list[tuple[int, dict]] = []
    for item in items:
        title_blob = _compose_search_blob(
            item.get("title"),
            item.get("source"),
            item.get("source_label"),
            item.get("source_site"),
            item.get("author"),
            item.get("team"),
            item.get("attacker"),
            item.get("website"),
            item.get("website_host"),
        )
        summary_blob = _compose_search_blob(
            item.get("description"),
            item.get("summary"),
            item.get("ip_addresses"),
            item.get("web_server"),
            item.get("industry"),
            item.get("attack_date"),
            item.get("discovered_at"),
            item.get("country_names"),
        )
        haystack = _compose_search_blob(
            title_blob,
            summary_blob,
            item.get("url"),
            item.get("seed_url"),
            item.get("source_type"),
            item.get("network"),
            item.get("entities"),
            item.get("categories"),
            item.get("evidence_links"),
            item.get("screenshot_links"),
            item.get("mirror_links"),
            item.get("_search_blob"),
            item.get("raw"),
        )

        if not haystack:
            continue

        score = 0
        if needle in haystack:
            score += 120
        if needle in title_blob:
            score += 55
        if needle in summary_blob:
            score += 30

        matched_terms = [term for term in terms if term in haystack]
        unique_matches = list(dict.fromkeys(matched_terms))
        if unique_matches:
            score += len(unique_matches) * 22
            if len(terms) > 1 and len(unique_matches) == len(terms):
                score += 80
            elif len(terms) > 2 and len(unique_matches) >= max(2, len(terms) - 1):
                score += 38

            for term in unique_matches:
                if term in title_blob:
                    score += 18
                if term in summary_blob:
                    score += 10
        elif needle not in haystack:
            continue

        if score > 0:
            scored.append((score, item))

    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [item for _, item in scored]


def _public_feed_item(item: dict) -> dict:
    if "_search_blob" not in item:
        return item
    sanitized = dict(item)
    sanitized.pop("_search_blob", None)
    return sanitized


def _build_article_item(doc: dict, include_raw: bool = False) -> dict:
    raw_doc = dict(doc)
    item = dict(doc)
    item["aid"] = str(item.get("aid") or item.get("dedupe_key") or item.get("_id", ""))
    item.pop("_id", None)

    item["url"] = item.get("url") or _extract_field(raw_doc, "m_url", "url", "m_weblink", "weblink", "m_dumplink", "dumplink")
    item["seed_url"] = item.get("seed_url") or _extract_field(raw_doc, "seed_url", "m_base_url", "base_url", "m_source_url")

    fallback_title = _title_from_url(item["url"] or item["seed_url"])
    item["title"] = (
        _meaningful_title(item.get("title"))
        or _meaningful_title(_extract_field(raw_doc, "m_title", "title", "headline", "name"))
        or fallback_title
        or "Untitled"
    )

    item["description"] = (
        _meaningful_description(item.get("description"))
        or _meaningful_description(_extract_field(raw_doc, "description", "m_description", "m_important_content", "important_content"))
        or _excerpt_text(_extract_field(raw_doc, "summary", "m_important_content", "important_content", "m_content", "content"))
        or f"Intelligence captured from {_extract_hostname(item['url'] or item['seed_url']) or 'the monitored source'}."
    )
    item["summary"] = (
        _meaningful_description(item.get("summary"))
        or _excerpt_text(_extract_field(raw_doc, "summary", "m_important_content", "important_content", "m_content", "content"))
        or item["description"]
    )[:400]

    categories = item.get("categories", [])
    if not categories:
        categories = [{"label": label, "score": 0.8} for label in _extract_values(raw_doc, "m_content_type", "content_type")]
        item["categories"] = categories
    if categories:
        categories_sorted = sorted(categories, key=lambda x: x.get("score", 0), reverse=True)
        item["top_tag"] = categories_sorted[0].get("label", "")
    else:
        item["top_tag"] = ""

    item["source_type"] = (item.get("source_type") or "news").lower()
    item["author"] = item.get("author") or item.get("writer") or _extract_field(raw_doc, "m_author", "author", "writer")
    item["source_site"] = (
        _extract_hostname(item["url"])
        or _extract_hostname(item["seed_url"])
        or _extract_hostname(_extract_field(raw_doc, "m_base_url", "base_url", "source_url"))
    )
    item["source_label"] = (
        _normalize_source_label(item.get("source_name"))
        or _normalize_source_label(_extract_field(raw_doc, "source_name", "m_source", "m_scrap_file"))
        or item["source_site"]
        or "news"
    )
    item["source"] = (
        _normalize_source_label(item.get("source"))
        or item["source_site"]
        or item["source_label"]
    )
    item["scraped_at"] = _coerce_datetime_string(item.get("scraped_at") or item.get("date"))
    item["date"] = _coerce_datetime_string(item.get("date") or item.get("scraped_at"))
    item["published_at"] = item["date"]
    item["entities"] = _normalize_entities(item.get("entities") or raw_doc.get("entities") or raw_doc.get("m_entities"))
    item["network"] = item.get("network", {}).get("type") if isinstance(item.get("network"), dict) else item.get("network", "clearnet")
    item["ip_addresses"] = _extract_ip_addresses(raw_doc)
    item["attacker"] = _extract_field(raw_doc, "m_attacker", "attacker")
    item["team"] = _extract_field(raw_doc, "m_team", "team", "m_sender_name", "m_username")
    item["web_server"] = _extract_field(raw_doc, "m_web_server", "web_server")
    item["screenshot"] = _extract_primary_screenshot(raw_doc)
    item["screenshot_links"] = _extract_screenshot_links(raw_doc)
    item["evidence_links"] = _extract_evidence_links(raw_doc)
    item["website"] = _extract_field(raw_doc, "website", "domain")
    item["website_host"] = _extract_hostname(item["website"])
    item["country_codes"] = _infer_country_codes(item, raw_doc)
    item["country_names"] = [_COUNTRY_CODE_TO_NAME[code] for code in item["country_codes"]]
    item["_search_blob"] = _compose_search_blob(
        item["title"],
        item["description"],
        item["summary"],
        item["url"],
        item["seed_url"],
        item["source"],
        item["source_label"],
        item["source_site"],
        item["author"],
        item["network"],
        item["ip_addresses"],
        item["attacker"],
        item["team"],
        item["web_server"],
        item["website"],
        item["website_host"],
        item["country_names"],
        item["entities"],
        item["categories"],
        item["evidence_links"],
        item["screenshot_links"],
        _extract_field(raw_doc, "summary", "m_important_content", "important_content", "m_content", "content", "body", "text"),
    )
    if include_raw:
        if "_id" in raw_doc:
            raw_doc["_id"] = str(raw_doc["_id"])
        item["raw"] = raw_doc
    return item


def _build_threat_item(key: str, data: dict, include_raw: bool = False) -> dict | None:
    source_cat = "threat"
    for prefix, category in _THREAT_PREFIXES.items():
        if key.startswith(prefix):
            if category is None:
                return None
            source_cat = category
            break

    title = _extract_field(
        data,
        "m_title",
        "title",
        "m_name",
        "m_company_name",
        "m_app_name",
        "m_important_content",
        "important_content",
    )
    raw_url = _extract_field(
        data,
        "m_url",
        "url",
        "m_app_url",
        "m_message_sharable_link",
        "m_channel_url",
        "m_weblink",
        "weblink",
    )
    if not raw_url:
        evidence_links = _extract_evidence_links(data)
        raw_url = evidence_links[0] if evidence_links else ""
    if not raw_url:
        links = (
            data.get("m_weblink")
            or data.get("weblink")
            or data.get("links")
            or data.get("m_links")
            or []
        )
        raw_url = _coerce_list(links)[0] if _coerce_list(links) else ""

    if not title and raw_url:
        title = _title_from_url(raw_url) or _extract_hostname(raw_url) or raw_url
    if not title:
        title = "Untitled"

    content = _extract_field(
        data,
        "m_content",
        "content",
        "m_description",
        "description",
        "m_important_content",
        "important_content",
        "m_ref_html",
    )
    source_name = _extract_field(data, "source_name", "m_source", "m_scrap_file", "m_platform", "m_sender_name") or source_cat
    source_label = _normalize_source_label(source_name) or source_cat
    network = _extract_network(data)
    date_value = _coerce_datetime_string(_extract_field(data, "m_leak_date", "leak_date", "m_message_date", "m_exploit_year", "m_latest_date", "m_date"))
    seed_url = _extract_field(data, "m_base_url", "base_url", "m_source_url", "m_channel_url")
    website = _extract_field(data, "website", "m_website", "m_domain", "domain", "m_target_domain", "target_domain")
    website_host = _extract_hostname(website)
    source_site = _extract_hostname(seed_url) or _extract_hostname(_extract_field(data, "m_source_url", "source_url")) or _extract_hostname(raw_url)
    discovered_at = _coerce_datetime_string(_extract_field(data, "discovered_at", "m_discovered_at"))
    attack_date = _coerce_datetime_string(_extract_field(data, "attack_date", "m_attack_date"))
    industry = _extract_field(data, "industry", "m_industry", "sector", "m_sector")
    collected_at = _coerce_datetime_string(_extract_field(data, "collected_at", "m_collected_at", "updated_at"))
    author = _extract_field(data, "m_actor", "m_sender_name", "m_author", "author", "m_username")
    ip_addresses = _extract_ip_addresses(data)
    attacker = _extract_field(data, "m_attacker", "attacker")
    team = _extract_field(data, "m_team", "team", "m_username")
    web_server = _extract_field(data, "m_web_server", "web_server")
    screenshot = _extract_primary_screenshot(data)
    screenshot_links = _extract_screenshot_links(data)
    evidence_links = _extract_evidence_links(data)
    mirror_links = _extract_values(data, "m_mirror_links", "mirror_links")

    content_types = _extract_values(data, "m_ioc_type", "content_type", "m_content_type", "m_section", "m_sections")
    categories = [{"label": source_cat, "score": 1.0}]
    for label in content_types:
        if label and label != source_cat:
            categories.append({"label": label, "score": 0.75})

    summary_text = (
        _meaningful_description(_extract_field(data, "m_description", "description", "m_important_content", "important_content"))
        or _excerpt_text(content)
        or title
    )
    description_parts = [summary_text] if summary_text else []
    summary_lower = summary_text.lower()
    if ip_addresses and ip_addresses.lower() not in summary_lower:
        description_parts.append(f"IP: {ip_addresses}")
    if attacker and attacker.lower() not in summary_lower:
        description_parts.append(f"Attacker: {attacker}")
    if team and team.lower() not in summary_lower:
        description_parts.append(f"Team: {team}")
    if website_host and website_host.lower() not in summary_lower:
        description_parts.append(f"Website: {website_host}")
    if web_server and web_server.lower() not in summary_lower:
        description_parts.append(f"Server: {web_server}")
    if content_types:
        type_text = ", ".join(content_types)
        if type_text.lower() not in summary_lower:
            description_parts.append(f"Type: {type_text}")
    description = " | ".join(part for part in description_parts if part) or title

    item = {
        "aid": key,
        "title": title,
        "description": description[:800],
        "url": raw_url,
        "seed_url": seed_url,
        "source": source_site or source_label or source_cat,
        "source_label": source_label,
        "source_site": source_site,
        "source_type": source_cat,
        "author": author or attacker or team,
        "date": date_value,
        "scraped_at": date_value,
        "published_at": date_value,
        "network": network,
        "top_tag": source_cat,
        "categories": categories,
        "summary": (_excerpt_text(content) or _excerpt_text(description) or title)[:400],
        "entities": _normalize_entities(data.get("entities") or data.get("m_entities")),
        "ip_addresses": ip_addresses,
        "attacker": attacker,
        "team": team,
        "web_server": web_server,
        "screenshot": screenshot,
        "screenshot_links": screenshot_links,
        "mirror_links": mirror_links,
        "evidence_links": evidence_links,
        "website": website,
        "website_host": website_host,
        "industry": industry,
        "discovered_at": discovered_at,
        "attack_date": attack_date,
        "collected_at": collected_at,
        "extra": data.get("extra") or data.get("m_extra") or {},
    }
    item["country_codes"] = _infer_country_codes(item, data)
    item["country_names"] = [_COUNTRY_CODE_TO_NAME[code] for code in item["country_codes"]]
    item["_search_blob"] = _compose_search_blob(
        item["title"],
        item["description"],
        item["summary"],
        item["url"],
        item["seed_url"],
        item["source"],
        item["source_label"],
        item["source_site"],
        item["author"],
        item["network"],
        item["ip_addresses"],
        item["attacker"],
        item["team"],
        item["web_server"],
        item["website"],
        item["website_host"],
        item["industry"],
        item["discovered_at"],
        item["attack_date"],
        item["collected_at"],
        item["country_names"],
        item["entities"],
        item["categories"],
        item["evidence_links"],
        item["screenshot_links"],
        item["mirror_links"],
        content,
        data.get("m_ref_html"),
        data.get("extra") or data.get("m_extra"),
    )
    if include_raw:
        item["raw"] = data
    return item


def _parse_kv_item(doc: dict, include_raw: bool = False, entity_doc: dict | None = None) -> dict | None:
    raw = doc.get("value", "")
    if not raw or not isinstance(raw, str):
        return None
    try:
        data = json.loads(raw)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None

    entity_data: dict | None = None
    if entity_doc:
        entity_raw = entity_doc.get("value", "")
        if isinstance(entity_raw, str) and entity_raw:
            try:
                loaded = json.loads(entity_raw)
                if isinstance(loaded, dict):
                    entity_data = loaded
            except Exception:
                entity_data = None

    merged = _merge_threat_payloads(data, entity_data)
    return _build_threat_item(str(doc.get("_id", "")), merged, include_raw=include_raw)


def _news_merge_key(item: dict) -> str:
    return str(item.get("url") or item.get("aid") or item.get("seed_url") or "")


def _news_item_score(item: dict) -> int:
    score = 0
    if _meaningful_title(item.get("title")):
        score += 5
    if _meaningful_description(item.get("description")):
        score += 4
    if _meaningful_description(item.get("summary")):
        score += 2
    if _clean_text_candidate(item.get("author")):
        score += 1
    if _clean_text_candidate(item.get("source")):
        score += 1
    if item.get("screenshot"):
        score += 1
    if item.get("entities"):
        score += 1
    return score


async def _fetch_news_items(include_raw: bool = False) -> list[dict]:
    cache_key = ("news", include_raw)
    if not include_raw:
        cached = _cache_get_feed_items(cache_key)
        if cached is not None:
            return cached

    processed_docs = await articles_col.find({}).to_list(length=None)
    raw_docs = await news_items_col.find({}).to_list(length=None) if include_raw else []

    merged: dict[str, dict] = {}
    for doc in processed_docs + raw_docs:
        item = _build_article_item(doc, include_raw=include_raw)
        key = _news_merge_key(item)
        if not key:
            continue
        existing = merged.get(key)
        if not existing or _news_item_score(item) >= _news_item_score(existing):
            merged[key] = item

    items = list(merged.values())
    return _cache_set_feed_items(cache_key, items) if not include_raw else items


async def _fetch_news_page(limit: int, offset: int) -> tuple[int, list[dict]]:
    total = await articles_col.count_documents({})
    cursor = (
        articles_col.find({})
        .sort([
            ("scraped_at", -1),
            ("date", -1),
            ("published_at", -1),
            ("_id", -1),
        ])
        .skip(offset)
        .limit(limit)
    )
    docs = await cursor.to_list(length=limit)
    return total, [_build_article_item(doc, include_raw=False) for doc in docs]


async def _search_news_items(query: str, include_raw: bool = False, limit: int = SEARCH_CANDIDATE_LIMIT) -> list[dict]:
    search_filter = _build_mongo_text_search(
        query,
        [
            "title",
            "description",
            "summary",
            "content",
            "url",
            "seed_url",
            "source",
            "source_name",
            "author",
            "writer",
        ],
    )
    if not search_filter:
        return []

    cursor = (
        articles_col.find(search_filter)
        .sort([
            ("scraped_at", -1),
            ("date", -1),
            ("published_at", -1),
            ("_id", -1),
        ])
        .limit(limit)
    )
    docs = await cursor.to_list(length=limit)
    return [_build_article_item(doc, include_raw=include_raw) for doc in docs]


async def _find_news_doc(aid: str) -> dict | None:
    queries = [{"_id": aid}, {"aid": aid}, {"dedupe_key": aid}]
    for collection in (articles_col, news_items_col):
        for query in queries:
            doc = await collection.find_one(query)
            if doc:
                return doc
    return None


async def _search_threat_items(query: str, source_type: str = "", include_raw: bool = False, limit: int = SEARCH_CANDIDATE_LIMIT) -> list[dict]:
    prefixes = [prefix for prefix, category in _THREAT_PREFIXES.items() if category is not None]
    if source_type:
        prefixes = [prefix for prefix, category in _THREAT_PREFIXES.items() if category == source_type]
        if not prefixes:
            return []

    regex_pattern = "^(" + "|".join(prefixes) + "):"
    search_filter = _build_mongo_text_search(query, ["value", "_id"])
    query_doc: dict[str, Any] = {"_id": {"$regex": regex_pattern}}
    if search_filter:
        query_doc = {"$and": [query_doc, search_filter]}

    docs = await kv_col.find(query_doc).sort([("_id", -1)]).limit(limit).to_list(length=limit)
    suffixes = []
    for doc in docs:
        doc_id = str(doc.get("_id", ""))
        suffixes.append(doc_id.split(":", 1)[1] if ":" in doc_id else doc_id)

    entity_docs: list[dict] = []
    if suffixes:
        entity_ids = []
        for prefix in prefixes:
            entity_prefix = prefix.replace("_ITEMS", "_ENTITIES")
            entity_ids.extend([f"{entity_prefix}:{suffix}" for suffix in suffixes])
        entity_docs = await kv_col.find({"_id": {"$in": entity_ids}}).to_list(length=None)

    entity_map: dict[str, dict] = {}
    for entity_doc in entity_docs:
        entity_id = str(entity_doc.get("_id", ""))
        if ":" not in entity_id:
            continue
        entity_map[entity_id.split(":", 1)[1]] = entity_doc

    items = []
    for doc in docs:
        doc_id = str(doc.get("_id", ""))
        suffix = doc_id.split(":", 1)[1] if ":" in doc_id else doc_id
        parsed = _parse_kv_item(doc, include_raw=include_raw, entity_doc=entity_map.get(suffix))
        if parsed:
            items.append(parsed)
    return items


async def _fetch_threat_items(source_type: str = "", include_raw: bool = False) -> list[dict]:
    cache_key = (f"threat:{source_type or 'all'}", include_raw)
    if not include_raw:
        cached = _cache_get_feed_items(cache_key)
        if cached is not None:
            return cached

    prefixes = [prefix for prefix, category in _THREAT_PREFIXES.items() if category is not None]
    if source_type:
        prefixes = [prefix for prefix, category in _THREAT_PREFIXES.items() if category == source_type]
        if not prefixes:
            return []

    entity_prefixes = [prefix.replace("_ITEMS", "_ENTITIES") for prefix in prefixes]
    regex_pattern = "^(" + "|".join(prefixes) + "):"
    entity_regex_pattern = "^(" + "|".join(entity_prefixes) + "):"

    docs = await kv_col.find({"_id": {"$regex": regex_pattern}}).to_list(length=None)
    entity_docs = await kv_col.find({"_id": {"$regex": entity_regex_pattern}}).to_list(length=None)
    entity_map: dict[str, dict] = {}
    for entity_doc in entity_docs:
        entity_id = str(entity_doc.get("_id", ""))
        if ":" not in entity_id:
            continue
        entity_map[entity_id.split(":", 1)[1]] = entity_doc

    items = []
    for doc in docs:
        doc_id = str(doc.get("_id", ""))
        suffix = doc_id.split(":", 1)[1] if ":" in doc_id else doc_id
        parsed = _parse_kv_item(doc, include_raw=include_raw, entity_doc=entity_map.get(suffix))
        if parsed:
            items.append(parsed)
    return _cache_set_feed_items(cache_key, items) if not include_raw else items


@app.get("/news")
async def list_news(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    q: str = Query(""),
    include_raw: bool = Query(False),
):
    if not q and not include_raw:
        total, items = await _fetch_news_page(limit, offset)
        payload = {
            "total": total,
            "offset": offset,
            "limit": limit,
            "items": [_public_feed_item(item) for item in items],
        }
        payload["news"] = payload["items"]
        return payload

    if q:
        items = await _search_news_items(q, include_raw=include_raw)
        items = sorted(items, key=_feed_sort_key, reverse=True)
        items = _filter_feed_items(items, q)
    else:
        items = await _fetch_news_items(include_raw=include_raw)
        items = sorted(items, key=_feed_sort_key, reverse=True)
    payload = {
        "total": len(items),
        "offset": offset,
        "limit": limit,
        "items": [_public_feed_item(item) for item in items[offset:offset + limit]],
    }
    payload["news"] = payload["items"]
    return payload


@app.get("/news/{aid}")
async def get_news(aid: str):
    doc = await _find_news_doc(aid)
    if not doc:
        raise HTTPException(status_code=404, detail="Article not found")
    item = _build_article_item(doc, include_raw=True)
    public_item = _public_feed_item(item)
    return {"article": public_item, **public_item}


@app.get("/feed")
async def list_feed(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    source_type: str = Query("all"),
    q: str = Query(""),
    include_raw: bool = Query(False),
):
    canonical = _canonical_source_type(source_type)

    if canonical == "news":
        if not q and not include_raw:
            total, items = await _fetch_news_page(limit, offset)
            return {
                "total": total,
                "offset": offset,
                "limit": limit,
                "items": [_public_feed_item(item) for item in items],
            }
        if q:
            items = await _search_news_items(q, include_raw=include_raw)
        else:
            items = await _fetch_news_items(include_raw=include_raw)
    elif canonical in {"exploit", "leak", "defacement", "social", "api"}:
        if q:
            items = await _search_threat_items(q, canonical, include_raw=include_raw)
        else:
            items = await _fetch_threat_items(canonical, include_raw=include_raw)
    else:
        if q:
            news_items, threat_items = await asyncio.gather(
                _search_news_items(q, include_raw=include_raw),
                _search_threat_items(q, include_raw=include_raw),
            )
        else:
            news_items, threat_items = await asyncio.gather(
                _fetch_news_items(include_raw=include_raw),
                _fetch_threat_items(include_raw=include_raw),
            )
        items = news_items + threat_items

    items = sorted(items, key=_feed_sort_key, reverse=True)
    if q:
        items = _filter_feed_items(items, q)
    return {
        "total": len(items),
        "offset": offset,
        "limit": limit,
        "items": [_public_feed_item(item) for item in items[offset:offset + limit]],
    }


@app.get("/feed/{aid:path}")
async def get_feed_item(aid: str):
    if any(aid.startswith(f"{prefix}:") for prefix in _THREAT_PREFIXES):
        doc = await kv_col.find_one({"_id": aid})
        entity_doc = None
        if aid.startswith(("EXPLOIT_ITEMS:", "LEAK_ITEMS:", "DEFACEMENT_ITEMS:", "SOCIAL_ITEMS:", "API_ITEMS:")):
            entity_doc = await kv_col.find_one({"_id": aid.replace("_ITEMS:", "_ENTITIES:", 1)})
        parsed = _parse_kv_item(doc, include_raw=True, entity_doc=entity_doc) if doc else None
        if not parsed:
            raise HTTPException(status_code=404, detail="Threat item not found")
        return _public_feed_item(parsed)

    doc = await _find_news_doc(aid)
    if not doc:
        raise HTTPException(status_code=404, detail="Feed item not found")
    return _public_feed_item(_build_article_item(doc, include_raw=True))


@app.get("/threats")
async def list_threats(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    source_type: str = Query("", description="Filter: exploit, social, leak, etc."),
):
    """Return non-news threat intel entries (exploits, leaks, social, etc.)
    from the redis_kv_store collection, formatted like articles for the frontend."""

    items = await _fetch_threat_items(_canonical_source_type(source_type))
    items = sorted(items, key=_feed_sort_key, reverse=True)
    total = len(items)
    return {"total": total, "offset": offset, "limit": limit, "items": items[offset:offset + limit]}


@app.get("/stats")
async def stats():
    """Return counts per collector type for the dashboard stats bar."""
    result = {
        "news": await articles_col.count_documents({}),
    }
    for pfx, cat in _THREAT_PREFIXES.items():
        if cat is None:
            continue
        regex = f"^{pfx}:"
        count = await kv_col.count_documents({"_id": {"$regex": regex}})
        result[cat] = result.get(cat, 0) + count
    result["total"] = sum(result.values())
    return {"counts": result, **result}


# ── PakDB Phone Lookup ──────────────────────────────────────────────────────
pakdb_col = db["pakdb_lookups"]


@app.post("/pakdb/lookup")
async def pakdb_lookup(request: Request):
    """Run a PakDB phone number lookup via the Playwright + Tor scraper.
    Accepts JSON body: {"number": "03001234567"}
    Returns structured results or an error."""
    import asyncio
    from datetime import datetime, timezone

    body = await request.json()
    number = str(body.get("number", "")).strip()
    if not number:
        raise HTTPException(status_code=400, detail="Phone number is required")

    # Validate: must look like a Pakistani phone number
    import re
    cleaned = re.sub(r"\D+", "", number)
    if len(cleaned) < 10 or len(cleaned) > 13:
        raise HTTPException(status_code=400, detail="Invalid phone number format")

    log.info(f"PakDB lookup requested for: {number}")

    try:
        from api_collector.scripts._pakdb import _pakdb

        scraper = _pakdb()
        loop = asyncio.get_running_loop()

        # Run the Playwright scraper in a thread pool (it's blocking)
        result = await loop.run_in_executor(
            None,
            lambda: asyncio.run(scraper.parse_leak_data(query={"number": number}, context=None))
        )

        cards = list(getattr(result, "cards_data", []) or []) if result else []

        items = []
        for card in cards:
            extra = getattr(card, "m_extra", {}) or {}
            item = {
                "name": extra.get("name") or getattr(card, "m_app_name", ""),
                "cnic": extra.get("cnic", ""),
                "mobile": extra.get("mobile", ""),
                "address": extra.get("address", ""),
            }
            items.append(item)

        # Persist to MongoDB for history
        doc = {
            "query": number,
            "results": items,
            "count": len(items),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await pakdb_col.insert_one(doc)

        log.info(f"PakDB lookup complete: {len(items)} results for {number}")
        return {"status": "ok", "query": number, "count": len(items), "results": items}

    except Exception as e:
        log.error(f"PakDB lookup failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Lookup failed: {str(e)}")


@app.get("/pakdb/history")
async def pakdb_history(limit: int = Query(50, ge=1, le=200)):
    """Return recent PakDB lookups from history WITH full results."""
    cursor = pakdb_col.find({}).sort("timestamp", -1).limit(limit)
    docs = await cursor.to_list(length=limit)
    for d in docs:
        d["_id"] = str(d["_id"])
    return {"items": docs}


@app.delete("/pakdb/history/{item_id}")
async def pakdb_delete_history(item_id: str):
    """Delete a single PakDB lookup from history."""
    from bson import ObjectId
    try:
        result = await pakdb_col.delete_one({"_id": ObjectId(item_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Not found")
    return {"status": "deleted", "id": item_id}


@app.delete("/pakdb/history")
async def pakdb_clear_history():
    """Clear all PakDB lookup history."""
    result = await pakdb_col.delete_many({})
    return {"status": "cleared", "deleted": result.deleted_count}


@app.get("/pakdb/search")
async def pakdb_search_cnic(q: str = Query(..., min_length=1)):
    """Search PakDB history by CNIC or phone number."""
    # Search in the results array for matching CNIC or mobile
    query = {
        "$or": [
            {"results.cnic": {"$regex": q, "$options": "i"}},
            {"results.mobile": {"$regex": q, "$options": "i"}},
            {"results.name": {"$regex": q, "$options": "i"}},
            {"query": {"$regex": q, "$options": "i"}},
        ]
    }
    cursor = pakdb_col.find(query).sort("timestamp", -1).limit(50)
    docs = await cursor.to_list(length=50)
    for d in docs:
        d["_id"] = str(d["_id"])
    return {"items": docs, "query": q}


# ═══════════════════════════════════════════════════════════════════════════════
# GITHUB TRIVY SCANNER
# ═══════════════════════════════════════════════════════════════════════════════
github_col = db["github_scans"]


@app.post("/github/scan")
async def github_scan(request: Request):
    """Clone a GitHub repo and run Trivy vulnerability + secret scanning."""
    import asyncio
    from datetime import datetime, timezone

    body = await request.json()
    repo_url = str(body.get("repo_url", "")).strip()
    if not repo_url or "github.com" not in repo_url:
        raise HTTPException(status_code=400, detail="Valid GitHub repo URL is required")

    log.info(f"GitHub Trivy scan requested for: {repo_url}")

    try:
        from api_collector.scripts.github_trivy_checker import github_trivy_checker
        import os

        scanner = github_trivy_checker()
        loop = asyncio.get_running_loop()

        query = {
            "github": repo_url,
            "git_token": os.getenv("GITHUB_TOKEN", ""),
            "timeout": 900,
            "print_details": False,
            "max_vulns_print": 50,
            "max_secrets_print": 20,
            "keep_workdir": False,
        }

        result = await loop.run_in_executor(
            None,
            lambda: asyncio.run(scanner.parse_leak_data(query=query, context=None))
        )

        raw = getattr(result, "raw_data", {}) or {}

        # Extract summary from DarkpulseSummary in raw data
        raw_summary = raw.get("DarkpulseSummary") or {}
        summary = {
            "grade": raw_summary.get("grade") or "F",
            "risk_score": raw_summary.get("risk_score") or 85,
            "total_vulns": raw_summary.get("counts", {}).get("CRITICAL", 0) + raw_summary.get("counts", {}).get("HIGH", 0) + raw_summary.get("counts", {}).get("MEDIUM", 0),
            "total_secrets": raw_summary.get("counts", {}).get("SECRETS", 0),
            "critical": raw_summary.get("counts", {}).get("CRITICAL", 0),
            "high": raw_summary.get("counts", {}).get("HIGH", 0),
            "medium": raw_summary.get("counts", {}).get("MEDIUM", 0),
            "low": raw_summary.get("counts", {}).get("LOW", 0),
            "scanned_by": "Orion Intelligence",
            "host": "github.com",
            "port": "443",
            "tls_status": "Ssl Enabled"
        }

        # Add actual findings from Trivy JSON Results
        vulnerabilities = []
        secrets = []
        misconfigs = []

        for r in (raw.get("Results") or []):
            target = r.get("Target", "Source")
            
            # Helper to extract code snippet
            def get_snippet(finding):
                code = finding.get("Code", {})
                lines = code.get("Lines", [])
                if lines:
                    return "\n".join([f"{l.get('Number', '')}: {l.get('Content', '')}" for l in lines])
                return finding.get("Match") or ""

            # 1. Vulnerabilities
            for v in (r.get("Vulnerabilities") or []):
                vulnerabilities.append({
                    "id": v.get("VulnerabilityID", "VULN"),
                    "title": v.get("Title") or v.get("PkgName") or "Security Vulnerability",
                    "description": v.get("Description") or "No detailed description available.",
                    "severity": v.get("Severity", "CRITICAL"),
                    "confidence": "Medium Confidence",
                    "pkg": v.get("PkgName", ""),
                    "version": v.get("InstalledVersion", ""),
                    "snippet": get_snippet(v),
                    "target": target
                })

            # 2. Secrets
            for s in (r.get("Secrets") or []):
                secrets.append({
                    "id": s.get("RuleID", "SECRET"),
                    "title": s.get("Title") or "Potential Secret Leak",
                    "description": s.get("Message") or f"Match found in {target}",
                    "severity": s.get("Severity", "CRITICAL"),
                    "confidence": "High Confidence",
                    "rule": s.get("RuleID", ""),
                    "snippet": get_snippet(s),
                    "target": target
                })

            # 3. Misconfigurations
            for m in (r.get("Misconfigurations") or []):
                misconfigs.append({
                    "id": m.get("ID", "MISCONFIG"),
                    "title": m.get("Title") or "Security Misconfiguration",
                    "description": m.get("Message") or m.get("Description") or "Policy violation detected.",
                    "severity": m.get("Severity", "HIGH"),
                    "confidence": "High Confidence",
                    "snippet": get_snippet(m),
                    "target": target
                })

        findings = vulnerabilities + secrets + misconfigs

        doc = {
            "query": repo_url,
            "results": {
                "vulnerabilities": vulnerabilities,
                "secrets": secrets,
                "misconfigs": misconfigs
            },
            "summary": summary,
            "count": len(findings),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await github_col.insert_one(doc)

        log.info(f"GitHub scan complete: {len(findings)} findings for {repo_url}")
        return {
            "status": "ok", 
            "query": repo_url, 
            "count": len(findings), 
            "vulnerabilities": vulnerabilities, 
            "secrets": secrets, 
            "misconfigs": misconfigs,
            "summary": summary
        }

    except Exception as e:
        log.error(f"GitHub scan failed: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

apk_col = db["apk_scans"]


async def _collect_apk_scan_results(playstore_url: str, proxy_url: Optional[str] = None, attempts: int = 2):
    from api_collector.scripts._apk_mod import _apk_mod
    from playwright.async_api import async_playwright

    last_error = ""
    best_results = []

    for attempt in range(1, max(1, attempts) + 1):
        try:
            scraper = _apk_mod()
            async with async_playwright() as p:
                browser_kwargs = {
                    "headless": True,
                    "args": ["--no-sandbox", "--disable-dev-shm-usage"],
                }
                if proxy_url:
                    browser_kwargs["proxy"] = {"server": proxy_url}

                browser = await p.chromium.launch(**browser_kwargs)
                context = await browser.new_context(ignore_https_errors=True)
                try:
                    result = await scraper.parse_leak_data(
                        query={"playstore": playstore_url}, context=context
                    )
                finally:
                    await browser.close()

            cards = list(getattr(result, "cards_data", []) or []) if result else []
            results = []
            for card in cards:
                results.append({
                    "app_name": getattr(card, "m_app_name", ""),
                    "package_id": getattr(card, "m_package_id", ""),
                    "url": getattr(card, "m_app_url", ""),
                    "network": getattr(card, "m_network", "clearnet"),
                    "source": getattr(card, "m_source", ""),
                    "publisher": getattr(card, "m_publisher", ""),
                    "description": getattr(card, "m_description", ""),
                    "version": getattr(card, "m_version", ""),
                    "content_type": getattr(card, "m_content_type", ["apk"])[0] if getattr(card, "m_content_type", []) else "apk",
                    "download_link": getattr(card, "m_download_link", [""])[0] if getattr(card, "m_download_link", []) else "",
                    "apk_size": getattr(card, "m_apk_size", "not available"),
                    "latest_date": getattr(card, "m_latest_date", ""),
                    "mod_features": getattr(card, "m_mod_features", "")
                })

            if results:
                if attempt > 1:
                    log.info(f"APK scan recovered on retry {attempt} for {playstore_url} with {len(results)} item(s)")
                return results

            best_results = results
            log.warning(f"APK scan attempt {attempt} returned 0 items for {playstore_url}")
        except Exception as exc:
            last_error = str(exc)
            log.warning(f"APK scan attempt {attempt} failed for {playstore_url}: {exc}")

    if last_error:
        raise RuntimeError(last_error)
    return best_results


@app.post("/apk/scan")
async def apk_scan(request: Request):
    """Search APK mirror sites for a Play Store app."""
    from datetime import datetime, timezone

    body = await request.json()
    playstore_url = str(body.get("playstore_url", "")).strip()
    if not playstore_url or "play.google.com" not in playstore_url:
        raise HTTPException(status_code=400, detail="Valid Play Store URL is required")

    log.info(f"APK scan requested for: {playstore_url}")

    try:
        results = await _collect_apk_scan_results(playstore_url, attempts=2)

        doc = {
            "query": playstore_url,
            "results": results,
            "count": len(results),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await apk_col.insert_one(doc)

        log.info(f"APK scan complete: {len(results)} items for {playstore_url}")
        return {"status": "ok", "query": playstore_url, "count": len(results), "results": results}

    except Exception as e:
        log.error(f"APK scan failed: {e}", exc_info=True)
        return {"status": "error", "message": f"Scan failed: {str(e)}"}


@app.get("/apk/history")
async def apk_history(limit: int = Query(50, ge=1, le=200)):
    cursor = apk_col.find({}).sort("timestamp", -1).limit(limit)
    docs = await cursor.to_list(length=limit)
    for d in docs:
        d["_id"] = str(d["_id"])
    return {"items": docs}


@app.delete("/apk/history/{item_id}")
async def apk_delete_history(item_id: str):
    from bson import ObjectId
    try:
        result = await apk_col.delete_one({"_id": ObjectId(item_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Not found")
    return {"status": "deleted", "id": item_id}


# ═══════════════════════════════════════════════════════════════════════════════
# PC GAME MOD SCANNER
# ═══════════════════════════════════════════════════════════════════════════════
pcgame_col = db["pcgame_scans"]


@app.post("/pcgame/scan")
async def pcgame_scan(request: Request):
    """Search Steam and PCGamingWiki for a game."""
    import asyncio
    from datetime import datetime, timezone

    body = await request.json()
    game_name = str(body.get("game_name", "")).strip()
    if not game_name:
        raise HTTPException(status_code=400, detail="Game name is required")

    log.info(f"PC Game scan requested for: {game_name}")

    try:
        from api_collector.scripts._pcgame_mod import _pcgame_mod

        scanner = _pcgame_mod()
        loop = asyncio.get_running_loop()

        result = await loop.run_in_executor(
            None,
            lambda: asyncio.run(scanner.parse_leak_data(query={"name": game_name}, context=None))
        )

        cards = list(getattr(result, "cards_data", []) or []) if result else []

        items = []
        for card in cards:
            extra = getattr(card, "m_extra", {}) or {}
            
            content_type_arr = getattr(card, "m_content_type", []) or []
            if not isinstance(content_type_arr, list):
                content_type_arr = [content_type_arr]
                
            item = {
                "app_name": getattr(card, "m_app_name", "") or getattr(card, "m_name", "") or "not available",
                "package_id": getattr(card, "m_package_id", "") or "not available",
                "app_url": getattr(card, "m_app_url", "") or "not available",
                "network": getattr(card, "m_network", "") or "clearnet",
                "version": getattr(card, "m_version", "") or "not available",
                "content_type": ", ".join(content_type_arr) if content_type_arr else "pc_game",
                "download_link": getattr(card, "m_download_link", "") or "[]",
                "apk_size": getattr(card, "m_apk_size", "") or "not available",
                "latest_date": getattr(card, "m_latest_date", "") or "not available",
                "mod_features": getattr(card, "m_mod_features", "") or "not available",
                
                # Including existing legacy fields just in case they are used elsewhere
                "name": getattr(card, "m_app_name", "") or getattr(card, "m_name", ""),
                "url": getattr(card, "m_app_url", "") or "",
                "source": (extra.get("source", "") if isinstance(extra, dict) else ""),
                "score": (extra.get("score", "") if isinstance(extra, dict) else ""),
                "pcgamingwiki": (extra.get("pcgamingwiki", "") if isinstance(extra, dict) else ""),
                "description": getattr(card, "m_description", "") or "",
            }
            items.append(item)

        doc = {
            "query": game_name,
            "results": items,
            "count": len(items),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await pcgame_col.insert_one(doc)

        log.info(f"PC Game scan complete: {len(items)} items for {game_name}")
        return {"status": "ok", "query": game_name, "count": len(items), "results": items}

    except Exception as e:
        log.error(f"PC Game scan failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@app.get("/pcgame/history")
async def pcgame_history(limit: int = Query(50, ge=1, le=200)):
    cursor = pcgame_col.find({}).sort("timestamp", -1).limit(limit)
    docs = await cursor.to_list(length=limit)
    for d in docs:
        d["_id"] = str(d["_id"])
    return {"items": docs}


@app.delete("/pcgame/history/{item_id}")
async def pcgame_delete_history(item_id: str):
    from bson import ObjectId
    try:
        result = await pcgame_col.delete_one({"_id": ObjectId(item_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Not found")
    return {"status": "deleted", "id": item_id}


# ── DarkPulse 2.0 Streaming Engine ──────────────────────────────────────────────
@app.websocket("/live-feed")
async def live_feed(websocket: WebSocket):
    await websocket.accept()
    log.info("Client connected to /live-feed WebSocket")
    try:
        last_id = None
        while True:
            query = {}
            if last_id:
                query = {"_id": {"$gt": last_id}}
            
            # Phase 2: Stream from intel_feed (Analyzed data)
            cursor = db["intel_feed"].find(query).sort("_id", 1).limit(20)
            items = await cursor.to_list(length=20)
            
            for item in items:
                last_id = item["_id"]
                
                # Normalize _id and raw_id for JSON serialization
                item["_id"] = str(item["_id"])
                if "raw_id" in item:
                    item["raw_id"] = str(item["raw_id"])
                if "raw_payload" in item and "_id" in item["raw_payload"]:
                    item["raw_payload"]["_id"] = str(item["raw_payload"]["_id"])
                    
                await websocket.send_json(item)
                
            await asyncio.sleep(2)
            
    except WebSocketDisconnect:
        log.info("Client disconnected from /live-feed WebSocket")
    except Exception as e:
        log.error(f"WebSocket error: {e}")


from pydantic import BaseModel

class PlaystoreRequest(BaseModel):
    url: str

class NLQRequest(BaseModel):
    query: str


class TranslateRequest(BaseModel):
    texts: list[str]
    target_language: str
    source_language: str = "auto"

@app.post("/search/nlq")
async def search_nlq(req: NLQRequest, request: Request):
    """
    Natural Language Query endpoint. Translates human text into a MongoDB
    aggregation pipeline using Gemini 1.5 Flash, executes it against intel_feed,
    and returns the resulting documents.
    """
    try:
        from google import genai
        from google.genai import types
        import os
        import json
        
        api_key = os.environ.get("GEMINI_API_KEY", "")
        if not api_key:
            log.warning("GEMINI_API_KEY not configured. Returning mock pipeline for NLQ.")
            # Extract basic keyword from query for crude mock filtering
            keyword = req.query.split()[-1] if req.query else "breach"
            # Improved mock to check more fields
            pipeline = [
                {"$match": {"$or": [
                    {"title": {"$regex": f"(?i){keyword}"}},
                    {"ai_summary": {"$regex": f"(?i){keyword}"}},
                    {"content": {"$regex": f"(?i){keyword}"}},
                    {"description": {"$regex": f"(?i){keyword}"}},
                    {"entities.text": {"$regex": f"(?i){keyword}"}}
                ]}},
                {"$sort": {"_id": -1}},
                {"$limit": 50}
            ]
        else:
            client = genai.Client(api_key=api_key)
            
            prompt = f"""
            You are a MongoDB translation engine for a Threat Intelligence dashboard.
            Translate the user's natural language query into a raw MongoDB aggregation pipeline JSON array.
            
            The collection is named `intel_feed`. 
            Schema fields:
            - _id (ObjectId)
            - source_type (string: 'news', 'exploit', 'leak', 'defacement', 'social', 'api')
            - title (string)
            - url (string)
            - date (string YYYY-MM-DD)
            - impact_score (int 0-100)
            - threat_actors (list of strings)
            - ai_summary (string)
            - content (string)
            - description (string)
            - entities (list of objects with 'label' and 'text', e.g. {{'label': 'ORG', 'text': 'Microsoft'}})
            - network (string: 'clearnet', 'tor', 'i2p')
            
            User Query: "{req.query}"
            
            Return ONLY a JSON array representing the aggregation pipeline. No markdown, no explanations. 
            Example result: 
            [{{"$match": {{"$or": [{{"title": {{"$regex": "(?i)rockstar"}}}}, {{"content": {{"$regex": "(?i)rockstar"}}}} ]}}}}, {{"$sort": {{"impact_score": -1}}}}, {{"$limit": 20}}]
            """
            
            loop = asyncio.get_running_loop()
            def call_gemini():
                return client.models.generate_content(
                    model='gemini-2.0-flash',
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        temperature=0.0,
            response_mime_type="application/json"
                    )
                ).text
                
            pipeline_json = await loop.run_in_executor(None, call_gemini)
            
            try:
                pipeline = json.loads(pipeline_json)
            except json.JSONDecodeError:
                log.error(f"Failed to parse Gemini pipeline: {pipeline_json}")
                raise HTTPException(status_code=500, detail="AI failed to generate a valid MongoDB query.")
            
        # Execute the pipeline
        cursor = db["intel_feed"].aggregate(pipeline)
        docs = await cursor.to_list(length=100)
        
        for d in docs:
            d["_id"] = str(d["_id"])
            if "raw_id" in d:
                d["raw_id"] = str(d["raw_id"])
            if "raw_payload" in d and "_id" in d["raw_payload"]:
                d["raw_payload"]["_id"] = str(d["raw_payload"]["_id"])
                
        return {"query": req.query, "count": len(docs), "results": docs, "pipeline": pipeline}
        
    except HTTPException:
        raise
    except ImportError:
        raise HTTPException(status_code=500, detail="google-genai SDK not installed.")
    except Exception as e:
        log.error(f"NLQ search failed: {e}")
        raise HTTPException(status_code=500, detail=f"Search failed: {e}")


@app.post("/translate/text")
async def translate_text(req: TranslateRequest):
    target_language = (req.target_language or "").strip()
    source_language = (req.source_language or "auto").strip() or "auto"
    texts = [str(text or "") for text in (req.texts or [])]

    if not target_language:
        raise HTTPException(status_code=400, detail="Target language is required")
    if len(texts) > TRANSLATION_BATCH_LIMIT:
        raise HTTPException(status_code=400, detail=f"Too many text items. Limit is {TRANSLATION_BATCH_LIMIT}.")

    clean_texts = [re.sub(r"\s+", " ", text).strip() for text in texts]
    if not any(clean_texts):
        return {
            "status": "ok",
            "target_language": target_language,
            "translations": clean_texts,
            "provider": "noop",
        }

    if target_language.lower() == "en":
        return {
            "status": "ok",
            "target_language": target_language,
            "translations": clean_texts,
            "provider": "noop",
        }

    missing_texts: list[str] = []
    for text in clean_texts:
        key = (target_language, text)
        if text and key not in _TRANSLATION_CACHE and text not in missing_texts:
            missing_texts.append(text)

    provider = "cache"
    if missing_texts:
        loop = asyncio.get_running_loop()
        try:
            translated_missing = await loop.run_in_executor(
                None,
                _translate_with_deep_translator,
                missing_texts,
                target_language,
                source_language,
            )
            provider = "deep_translator"
        except Exception as translate_err:
            log.warning(f"deep_translator failed for {target_language}: {translate_err}")
            try:
                translated_missing = await loop.run_in_executor(
                    None,
                    _translate_with_gemini,
                    missing_texts,
                    target_language,
                )
                provider = "gemini"
            except Exception as gemini_err:
                log.error(f"Translation failed for {target_language}: {gemini_err}")
                raise HTTPException(status_code=502, detail=f"Translation failed: {gemini_err}")

        if len(translated_missing) != len(missing_texts):
            raise HTTPException(status_code=502, detail="Translation provider returned an unexpected number of items.")

        for original, translated in zip(missing_texts, translated_missing):
            _TRANSLATION_CACHE[(target_language, original)] = translated or original

    translations = [
        _TRANSLATION_CACHE.get((target_language, text), text)
        if text else ""
        for text in clean_texts
    ]

    return {
        "status": "ok",
        "target_language": target_language,
        "translations": translations,
        "provider": provider,
    }


@app.get("/graph/{leak_id}")
async def get_mission_graph(leak_id: str):
    """
    Generates nodes and edges for the 'Mission Graph' UI.
    Maps out the leak, its source, threat actors, and known breaches.
    """
    from bson import ObjectId
    try:
        doc = await db["intel_feed"].find_one({"_id": ObjectId(leak_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid leak ID format.")
        
    if not doc:
        raise HTTPException(status_code=404, detail="Leak not found in intel_feed.")
        
    nodes = []
    edges = []
    
    # 1. Primary Node (The Leak)
    doc_id = str(doc["_id"])
    title = doc.get("title", "Unknown Leak")
    nodes.append({
        "data": {"id": doc_id, "label": title[:30] + "...", "type": "leak", "color": "#e11d48", "size": 30}
    })
    
    # 2. Source Node
    source = doc.get("source_type", "Unknown Source")
    source_id = f"source_{source}"
    nodes.append({
        "data": {"id": source_id, "label": source, "type": "source", "color": "#00d4ff"}
    })
    edges.append({"data": {"source": doc_id, "target": source_id, "label": "Found on"}})
    
    # 3. Threat Actors and their correlation data
    actors = doc.get("threat_actors", [])
    for actor_profile in actors:
        if isinstance(actor_profile, str):
            continue  # Older data format, ignore or handle strings if you want
            
        actor_name = actor_profile.get("actor", "Unknown Actor")
        actor_id = f"actor_{actor_name}"
        risk = actor_profile.get("risk_level", "Unknown")
        color = "#ccff00" if risk != "Critical" else "#e11d48"
        
        nodes.append({
            "data": {"id": actor_id, "label": f"Actor: {actor_name}", "type": "actor", "color": color}
        })
        edges.append({"data": {"source": doc_id, "target": actor_id, "label": "Involved"}})
        
        # Aliases
        for alias in actor_profile.get("aliases", []):
            alias_id = f"alias_{alias}"
            nodes.append({
                "data": {"id": alias_id, "label": alias, "type": "alias", "color": "#a855f7"}
            })
            edges.append({"data": {"source": actor_id, "target": alias_id, "label": "Alias"}})
            
        # Known Breaches
        for breach in actor_profile.get("known_breaches", []):
            breach_id = f"breach_{hash(breach)}"
            # Avoid duplicate breach nodes if multiple actors share it
            if not any(n["data"]["id"] == breach_id for n in nodes):
                nodes.append({
                    "data": {"id": breach_id, "label": breach, "type": "breach", "color": "#f59e0b"}
                })
            edges.append({"data": {"source": actor_id, "target": breach_id, "label": "Present In"}})
            
    return {"nodes": nodes, "edges": edges}


# --- SEO Checker ---
def calculate_seo_grade(score: float) -> str:
    """Map 0-1 score to A, B, C, D, F grades."""
    if score is None: return "N/A"
    if score >= 0.9: return "A"
    if score >= 0.8: return "B"
    if score >= 0.7: return "C"
    if score >= 0.5: return "D"
    return "F"


def _normalize_ai_bullets(text: str) -> str:
    lines: list[str] = []
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        line = re.sub(r"^[-*•]\s*", "", line)
        line = re.sub(r"^\d+[.)]\s*", "", line)
        if line:
            lines.append(f"- {line}")
    return "\n".join(lines[:6])


def _build_seo_fallback_suggestions(url: str, audits: dict[str, dict[str, Any]]) -> str:
    failing = []
    for audit_id, audit in (audits or {}).items():
        score = audit.get("score")
        if score == 1:
            continue
        failing.append({
            "id": audit_id,
            "title": str(audit.get("title") or audit_id).strip(),
            "description": str(audit.get("description") or "").strip(),
            "score": score,
        })

    def _sort_key(item: dict[str, Any]) -> tuple[int, float, str]:
        score = item.get("score")
        if isinstance(score, (int, float)):
            return (0, float(score), item["title"])
        return (1, 2.0, item["title"])

    failing.sort(key=_sort_key)

    suggestions: list[str] = []

    def _push(text: str) -> None:
        clean_text = text.strip()
        if clean_text and clean_text not in suggestions and len(suggestions) < 4:
            suggestions.append(clean_text)

    for item in failing:
        title = item["title"].lower()
        description = re.sub(r"\s+", " ", item["description"]).strip()
        short_desc = description[:160].rstrip(".")

        if "title" in title:
            _push("Write a unique, descriptive page title for each important page and align it closely with the main search intent.")
        elif "meta description" in title:
            _push("Add a clear meta description that explains the page value in plain language and encourages clicks from search results.")
        elif "crawl" in title or "index" in title or "robots" in title or "http status" in title:
            _push("Make sure important pages return HTTP 200, are not blocked by robots or noindex directives, and can be crawled consistently.")
        elif "link" in title:
            _push("Improve internal anchor text so links describe the destination clearly instead of using generic phrases.")
        elif "image" in title or "alt" in title:
            _push("Add meaningful alt text to important images so search engines and accessibility tools understand the page content better.")
        elif "mobile" in title or "viewport" in title:
            _push("Review the mobile layout and viewport settings so the page remains readable and usable on smaller screens.")
        elif "canonical" in title:
            _push("Set canonical URLs on indexable pages to reduce duplicate-content confusion and consolidate ranking signals.")
        elif "structured data" in title or "schema" in title:
            _push("Add valid structured data where appropriate so search engines can understand page entities and rich result opportunities.")
        elif short_desc:
            _push(f"Address '{item['title']}' first. {short_desc}.")
        else:
            _push(f"Address '{item['title']}' as a priority SEO issue on {urlparse(url).hostname or url}.")

    if not suggestions:
        suggestions = [
            "Keep page titles and meta descriptions unique across key pages.",
            "Check crawlability, status codes, and indexability for important landing pages.",
            "Strengthen internal links and content clarity so pages map cleanly to search intent.",
        ]

    return "\n".join(f"- {suggestion}" for suggestion in suggestions[:4])


def _safe_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 1.0
    return max(0.0, min(1.0, numerator / denominator))


def _local_seo_audit(url: str) -> dict[str, Any]:
    import requests
    from bs4 import BeautifulSoup

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/123.0 Safari/537.36"
        )
    }
    response = requests.get(url, timeout=30, headers=headers, allow_redirects=True)
    response.raise_for_status()

    final_url = response.url or url
    soup = BeautifulSoup(response.text or "", "lxml")

    def _text(value: Any) -> str:
        return re.sub(r"\s+", " ", str(value or "")).strip()

    title_text = _text(soup.title.string if soup.title else "")
    meta_description = _text((soup.find("meta", attrs={"name": re.compile("^description$", re.I)}) or {}).get("content"))
    robots_meta = _text((soup.find("meta", attrs={"name": re.compile("^robots$", re.I)}) or {}).get("content"))
    x_robots = _text(response.headers.get("X-Robots-Tag"))
    canonical = _text((soup.find("link", attrs={"rel": re.compile("canonical", re.I)}) or {}).get("href"))
    viewport = _text((soup.find("meta", attrs={"name": re.compile("^viewport$", re.I)}) or {}).get("content"))
    lang = _text(getattr(soup.html, "attrs", {}).get("lang") if soup.html else "")

    h1_tags = [tag for tag in soup.find_all("h1") if _text(tag.get_text(" ", strip=True))]
    image_tags = soup.find_all("img")
    images_with_alt = sum(1 for img in image_tags if _text(img.get("alt")))
    anchor_tags = soup.find_all("a")
    descriptive_links = sum(
        1 for link in anchor_tags
        if _text(link.get_text(" ", strip=True)).lower() not in {"", "click here", "read more", "learn more", "here", "more"}
    )

    audits: dict[str, dict[str, Any]] = {}

    def _add_audit(audit_id: str, score: float, title: str, description: str) -> None:
        audits[audit_id] = {
            "score": round(max(0.0, min(1.0, float(score))), 2),
            "title": title,
            "description": description,
        }

    _add_audit(
        "document-title",
        1.0 if 10 <= len(title_text) <= 65 else (0.5 if title_text else 0.0),
        "Document has a descriptive title",
        "A strong SEO title should exist and usually stay within a readable search-result length."
    )
    _add_audit(
        "meta-description",
        1.0 if 50 <= len(meta_description) <= 170 else (0.5 if meta_description else 0.0),
        "Meta description is present",
        "Pages should have a concise meta description that explains value clearly in search results."
    )
    _add_audit(
        "http-status-code",
        1.0 if response.status_code == 200 else 0.0,
        "Page returns a successful status code",
        f"The scanned page returned HTTP {response.status_code}. Important landing pages should normally respond with HTTP 200."
    )
    _add_audit(
        "is-crawlable",
        0.0 if ("noindex" in robots_meta.lower() or "noindex" in x_robots.lower()) else 1.0,
        "Page is indexable by search engines",
        "Robots directives should not accidentally block indexation of pages intended for search visibility."
    )
    _add_audit(
        "viewport",
        1.0 if viewport else 0.0,
        "Mobile viewport is configured",
        "Responsive pages should define a viewport meta tag so they render correctly on mobile devices."
    )
    _add_audit(
        "html-lang",
        1.0 if lang else 0.0,
        "Document language is declared",
        "The root html element should declare a language to help search engines and accessibility tooling interpret content."
    )
    _add_audit(
        "canonical",
        1.0 if canonical else 0.0,
        "Canonical URL is declared",
        "Canonical tags help consolidate duplicate signals and clarify which URL should rank."
    )
    _add_audit(
        "single-h1",
        1.0 if len(h1_tags) == 1 else (0.5 if len(h1_tags) > 1 else 0.0),
        "Primary H1 heading is defined",
        "Pages generally perform best with one clear H1 that matches the main topic and search intent."
    )
    _add_audit(
        "image-alt",
        _safe_ratio(images_with_alt, len(image_tags)),
        "Images include alt text",
        "Important images should include meaningful alt text so search engines and assistive technologies understand them."
    )
    _add_audit(
        "link-text",
        _safe_ratio(descriptive_links, len(anchor_tags)),
        "Links use descriptive anchor text",
        "Anchor text should describe the destination instead of relying on generic phrases like 'click here'."
    )

    valid_scores = [audit["score"] for audit in audits.values() if isinstance(audit.get("score"), (int, float))]
    seo_score = round(sum(valid_scores) / len(valid_scores), 2) if valid_scores else 0.0

    return {
        "url": final_url,
        "seoScore": seo_score,
        "audits": audits,
        "provider": "local_fallback",
    }

@app.get("/seo/analyze")
async def analyze_seo(url: str):
    """
    Analyzes a website URL using Google PageSpeed Insights (SEO category).
    Returns structured audit data and a calculated grade.
    """
    try:
        from api_collector.scripts.seo_checker import pagespeed_seo
        import time
        import asyncio
        
        # Ensure URL has protocol
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            
        log.info(f"SEO analysis requested for: {url}")
        
        loop = asyncio.get_running_loop()
        pagespeed_key = cfg.pagespeed_api_key or os.environ.get("PAGESPEED_API_KEY", "")
        data = await loop.run_in_executor(None, pagespeed_seo, url, pagespeed_key)
        scan_source = "pagespeed"
        scan_message = ""
        
        if "error" in data:
            error_message = str(data.get("error") or "")
            response_preview = str(data.get("response") or "")
            quota_hit = (
                "429" in error_message
                or "quota" in response_preview.lower()
                or "rate limit" in response_preview.lower()
                or "daily limit" in response_preview.lower()
            )
            if quota_hit:
                log.warning(f"SEO PageSpeed quota unavailable for {url}; using local fallback audit.")
                data = await loop.run_in_executor(None, _local_seo_audit, url)
                scan_source = "local_fallback"
                scan_message = "Google PageSpeed quota is unavailable right now, so DarkPulse used a local SEO fallback audit."
            else:
                log.error(f"SEO analysis failed for {url}: {data['error']}")
                return {"status": "error", "message": data["error"]}
        
        audits = data.get("audits", {})
        score = data.get("seoScore", 0)
        grade = calculate_seo_grade(score)
        ai_suggestions = ""
        ai_status = "fallback"
        ai_message = ""
        failing_audits = [
            audit.get("title")
            for audit in audits.values()
            if audit.get("score") != 1 and audit.get("title")
        ]

        gemini_key = cfg.gemini_api_key or os.environ.get("GEMINI_API_KEY", "")
        if gemini_key and failing_audits:
            try:
                from google import genai
                from google.genai import types
                
                client = genai.Client(api_key=gemini_key)
                
                # Prepare findings for AI
                audits_text = ", ".join(failing_audits[:10]) # Limit to top 10 for prompt efficiency
                
                prompt = f"""
                You are a senior SEO expert and web performance consultant.
                Based on the following SEO audit findings for the website {url}:
                Findings: {audits_text}
                
                Provide 3-4 professional, actionable, and concise bullet points for improvement.
                Focus on high-impact changes. Keep the tone professional but accessible.
                Do not use markdown formatting like bold or headers; just return a plain text list of bullet points starting with '-'.
                """
                
                def call_gemini():
                    return client.models.generate_content(
                        model='gemini-2.0-flash',
                        contents=prompt,
                        config=types.GenerateContentConfig(temperature=0.7)
                    ).text
                
                ai_raw = await loop.run_in_executor(None, call_gemini)
                ai_suggestions = _normalize_ai_bullets(ai_raw)
                if not ai_suggestions:
                    ai_suggestions = _build_seo_fallback_suggestions(url, audits)
                    ai_status = "fallback_format"
                    ai_message = "Gemini returned an empty response format, so DarkPulse generated recommendations from the audit findings."
                else:
                    ai_status = "gemini"
                    ai_message = "Recommendations generated by Gemini."
            except Exception as ai_err:
                log.warning(f"AI Suggestions failed: {ai_err}")
                ai_suggestions = _build_seo_fallback_suggestions(url, audits)
                error_text = str(ai_err)
                if "RESOURCE_EXHAUSTED" in error_text or "429" in error_text:
                    ai_status = "fallback_quota"
                    ai_message = "Gemini quota is exhausted right now, so DarkPulse generated recommendations from the audit findings."
                else:
                    ai_status = "fallback_error"
                    ai_message = "Gemini is temporarily unavailable, so DarkPulse generated recommendations from the audit findings."
        elif failing_audits:
            ai_suggestions = _build_seo_fallback_suggestions(url, audits)
            ai_status = "fallback_no_key"
            ai_message = "GEMINI_API_KEY is not configured, so DarkPulse generated recommendations from the audit findings."
        else:
            ai_suggestions = "- Core SEO checks passed for this scan.\n- Keep monitoring titles, crawlability, and metadata after future content changes."
            ai_status = "no_findings"
            ai_message = "No major failing SEO audits were detected in this run."

        return {
            "status": "ok",
            "url": data.get("url"),
            "score": score,
            "grade": grade,
            "audits": audits,
            "ai_suggestions": ai_suggestions.strip(),
            "ai_status": ai_status,
            "ai_message": ai_message,
            "scan_source": scan_source,
            "scan_message": scan_message,
            "timestamp": time.strftime("%B %d, %Y")
        }
    except Exception as e:
        log.error(f"SEO analysis exception: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/playstore/scan")
async def playstore_scan(req: PlaystoreRequest):
    """
    Search Playstore URL for cracked/modded versions using _apk_mod.
    """
    try:
        import time

        log.info(f"Playstore scan requested for: {req.url}")

        results = await _collect_apk_scan_results(
            req.url,
            proxy_url=cfg.tor_proxy_url or None,
            attempts=2,
        )

        return {
            "status": "ok",
            "query": req.url,
            "count": len(results),
            "results": results,
            "timestamp": time.strftime("%B %d, %Y")
        }

    except Exception as e:
        log.error(f"Playstore scan failed: {e}")
        return {"status": "error", "message": f"Scan failed: {str(e)}"}
@app.post("/scan/repo")
async def scan_repo(request: Request):
    """
    Scans a GitHub repository for vulnerabilities using Trivy.
    """
    try:
        from api_collector.scripts.github_trivy_checker import github_trivy_checker
        import time
        import asyncio

        body = await request.json()
        repo_url = body.get("url", "").strip()
        git_token = body.get("token", "").strip() or body.get("git_token", "").strip()
        
        if not repo_url:
            raise HTTPException(status_code=400, detail="Repository URL is required")

        log.info(f"Repository scan requested for: {repo_url} (Token provided: {'Yes' if git_token else 'No'})")
        
        scanner = github_trivy_checker()
        
        # run the scan
        scan_query = {"github": repo_url}
        if git_token:
            scan_query["git_token"] = git_token

        result = await scanner.parse_leak_data(query=scan_query, context=None)
        
        # The result of parse_leak_data is an apk_data_model
        raw_data = getattr(result, "raw_data", {}) or {}
        
        # Check for internal scanner errors
        if "error" in raw_data:
            err_msg = raw_data.get("error")
            log.error(f"Scanner internal error: {err_msg}")
            return {"status": "error", "message": f"Scan failed: {err_msg}"}

        # Flatten Results from Trivy (Targets -> Findings)
        vulnerabilities = []
        secrets = []
        misconfigs = []
        
        raw_results = raw_data.get("Results", []) or []
        for target in raw_results:
            target_name = target.get("Target", "unknown")
            
            # 1. Processing Vulnerabilities
            for v in target.get("Vulnerabilities", []) or []:
                vulnerabilities.append({
                    "id": v.get("VulnerabilityID", "VULN"),
                    "title": f"{v.get('PkgName', 'Pkg')}: {v.get('Title', 'Vulnerability')}",
                    "description": v.get("Description", "No description provided."),
                    "severity": (v.get("Severity") or "UNKNOWN").upper(),
                    "confidence": "High",
                    "snippet": f"Package: {v.get('PkgName')} \nInstalled: {v.get('InstalledVersion')} \nFixed: {v.get('FixedVersion') or 'N/A'}\nTarget: {target_name}",
                    "type": "vulnerability"
                })
            
            # 2. Processing Secrets
            for s in target.get("Secrets", []) or []:
                secrets.append({
                    "id": s.get("RuleID", "SECRET"),
                    "title": s.get("Title", "Exposed Secret"),
                    "description": f"Exposed credentials or keys found in {target_name}",
                    "severity": (s.get("Severity") or "CRITICAL").upper(),
                    "confidence": "Confirmed",
                    "snippet": f"File: {target_name}\nLines: {s.get('StartLine')}-{s.get('EndLine')}\nMatch: {s.get('Match', '')}",
                    "type": "secret"
                })

            # 3. Processing Misconfigs (if any)
            for m in target.get("Misconfigurations", []) or []:
                misconfigs.append({
                    "id": m.get("ID", "CONF"),
                    "title": m.get("Title", "Configuration Issue"),
                    "description": m.get("Description", "No description provided."),
                    "severity": (m.get("Severity") or "MEDIUM").upper(),
                    "confidence": "High",
                    "snippet": f"Cause: {m.get('Message', 'N/A')}\nResolution: {m.get('Resolution', 'N/A')}",
                    "type": "misconfig"
                })

        summary_data = raw_data.get("DarkpulseSummary", {}) or {}
        repo_path = (urlparse(repo_url).path or "").strip("/")
        
        # Prepare final response formatted for the UI
        return {
            "status": "ok",
            "query": repo_url,
            "summary": {
                "grade": summary_data.get("grade", "A"),
                "risk_score": summary_data.get("risk_score", 0),
                "counts": summary_data.get("counts", {}),
                "posture_label": summary_data.get("posture_label", "Scan"),
                "scan_status": summary_data.get("scan_status", "complete"),
                "note": summary_data.get("note", "Repository analysis complete."),
                "coverage": summary_data.get("coverage", {}),
                "recommendations": summary_data.get("recommendations", []),
                "host": urlparse(repo_url).hostname or "github.com",
                "repo_name": repo_path or (urlparse(repo_url).hostname or "github.com"),
                "port": "443",
                "scanned_by": "DarkPulse / Trivy"
            },
            "vulnerabilities": vulnerabilities,
            "secrets": secrets,
            "misconfigs": misconfigs,
            "results": vulnerabilities + secrets + misconfigs, # fallback
            "timestamp": time.strftime("%B %d, %Y")
        }

    except Exception as e:
        log.error(f"Repository scan failed: {e}", exc_info=True)
        return {"status": "error", "message": f"Scan failed: {str(e)}"}
