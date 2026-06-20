import asyncio
import base64
import math
import os
import pathlib
import json
import re
import signal
import socket
import sys
import time
import traceback
import hashlib
import hmac
import secrets
import struct
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse, urljoin
from uuid import uuid4
from fastapi import FastAPI, Query, Request, HTTPException, Depends, WebSocket, WebSocketDisconnect, UploadFile, File
import bcrypt
from datetime import date, datetime, timedelta, timezone
from jose import JWTError, jwt
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ReturnDocument

from config import cfg
from healing.routes import build_healing_router
from healing_system import get_healing_service
from logger import get_logger

log = get_logger(__name__)

# ── MongoDB Connection ──────────────────────────────────────────────────────────
client = AsyncIOMotorClient(cfg.mongo_uri, serverSelectionTimeoutMS=5000)
db = client[cfg.mongo_db]
articles_col = db["articles"]
news_items_col = db["news_items"]
leak_items_col = db["leak_items"]
collector_source_status_col = db["collector_source_status"]

# Users collection and auth setup
users_col = db["users"]
password_reset_requests_col = db["password_reset_requests"]
intelligence_runs_col = db["intelligence_runs"]
intelligence_notifications_col = db["dashboard_notifications"]
automation_state_col = db["automation_state"]
credential_exposures_col = db["credential_exposures"]
credential_datasets_col = db["credential_datasets"]
confidential_analysis_col = db["confidential_analysis_findings"]
_LEAK_SOURCE_SCRIPT_DIR = pathlib.Path(__file__).resolve().parent / "leak_collector" / "scripts" / "leak"
_FEED_SCREENSHOT_DIR = pathlib.Path(__file__).resolve().parent / "data" / "feed_screenshots"
_FEED_SCREENSHOT_SEMAPHORE = asyncio.Semaphore(2)


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
        "label": "Compromised Monitoring",
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
SMART_UPDATE_SCAN_MODE = "fast_headless_incremental"
SMART_UPDATE_SOURCE_TIMEOUT_SECONDS = int(os.getenv("SMART_UPDATE_SOURCE_TIMEOUT_SECONDS", "360"))
SMART_UPDATE_BASE_ENV = {
    "DARKPULSE_FAST_SCAN": "1",
    "DARKPULSE_INCREMENTAL_SCAN": "1",
    "DARKPULSE_HEADLESS": "1",
    "HEADLESS": "1",
    "PLAYWRIGHT_HEADLESS": "1",
    "PWDEBUG": "0",
    "CI": "1",
}
FEED_CACHE_TTL_SECONDS = 30
_FEED_ITEMS_CACHE: dict[tuple[str, bool], tuple[float, list[dict]]] = {}
FEED_PAGE_CACHE_TTL_SECONDS = 180
_FEED_PAGE_CACHE: dict[tuple[Any, ...], tuple[float, dict]] = {}
MAP_STATS_CACHE_TTL_SECONDS = 120
_MAP_STATS_CACHE: tuple[float, dict] | None = None
_MAP_STATS_INFLIGHT: asyncio.Task | None = None
STATS_CACHE_TTL_SECONDS = 60
_STATS_CACHE: tuple[float, dict] | None = None
SEMANTIC_SEARCH_CACHE_TTL_SECONDS = 90
_SEMANTIC_SEARCH_CACHE: dict[tuple[str, int], tuple[float, dict]] = {}
_TRANSLATION_CACHE: dict[tuple[str, str], str] = {}
TRANSLATION_BATCH_LIMIT = 100
TRANSLATION_CHUNK_SIZE = 25
SEARCH_CANDIDATE_LIMIT = 400
_healing_monitor_task: asyncio.Task | None = None
_map_stats_warmup_task: asyncio.Task | None = None
_feed_warmup_task: asyncio.Task | None = None
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
_LEAK_SOURCE_STATUS_ORDER = {
    "ingested": 0,
    "running": 1,
    "unreachable": 2,
    "error": 3,
    "import_error": 4,
    "empty": 5,
    "not_run": 6,
}
_NEWS_FEED_PROJECTION = {
    "content": 0,
    "content_html": 0,
    "raw": 0,
    "raw_text_snippet": 0,
    "embedding": 0,
}
_THREAT_FEED_PROJECTION = {
    "value.content": 0,
    "value.content_html": 0,
    "value.raw": 0,
    "value.raw_text_snippet": 0,
    "value.embedding": 0,
    "value.m_content": 0,
    "value.m_ref_html": 0,
    "value.ref_html": 0,
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


def _cache_get_feed_page(key: tuple[Any, ...]) -> Optional[dict]:
    cached = _FEED_PAGE_CACHE.get(key)
    if not cached:
        return None
    cached_at, payload = cached
    if time.monotonic() - cached_at > FEED_PAGE_CACHE_TTL_SECONDS:
        _FEED_PAGE_CACHE.pop(key, None)
        return None
    return payload


def _cache_set_feed_page(key: tuple[Any, ...], payload: dict) -> dict:
    _FEED_PAGE_CACHE[key] = (time.monotonic(), payload)
    return payload


def _cache_get_map_stats() -> Optional[dict]:
    cached = _MAP_STATS_CACHE
    if not cached:
        return None
    cached_at, payload = cached
    if time.monotonic() - cached_at > MAP_STATS_CACHE_TTL_SECONDS:
        return None
    return payload


def _cache_set_map_stats(payload: dict) -> dict:
    global _MAP_STATS_CACHE
    _MAP_STATS_CACHE = (time.monotonic(), payload)
    return payload


def _cache_get_stats() -> Optional[dict]:
    cached = _STATS_CACHE
    if not cached:
        return None
    cached_at, payload = cached
    if time.monotonic() - cached_at > STATS_CACHE_TTL_SECONDS:
        return None
    return payload


def _cache_set_stats(payload: dict) -> dict:
    global _STATS_CACHE
    _STATS_CACHE = (time.monotonic(), payload)
    return payload


def _cache_get_semantic_search(key: tuple[str, int]) -> Optional[dict]:
    cached = _SEMANTIC_SEARCH_CACHE.get(key)
    if not cached:
        return None
    cached_at, payload = cached
    if time.monotonic() - cached_at > SEMANTIC_SEARCH_CACHE_TTL_SECONDS:
        _SEMANTIC_SEARCH_CACHE.pop(key, None)
        return None
    return payload


def _cache_set_semantic_search(key: tuple[str, int], payload: dict) -> dict:
    _SEMANTIC_SEARCH_CACHE[key] = (time.monotonic(), payload)
    return payload


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
    global _MAP_STATS_CACHE, _STATS_CACHE
    _FEED_ITEMS_CACHE.clear()
    _FEED_PAGE_CACHE.clear()
    _MAP_STATS_CACHE = None
    _STATS_CACHE = None
    _SEMANTIC_SEARCH_CACHE.clear()


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


