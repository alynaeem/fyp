import asyncio
import pathlib
import json
from typing import Any, Dict, List
from fastapi import FastAPI, Query, Request, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from motor.motor_asyncio import AsyncIOMotorClient

from config import cfg
from logger import get_logger

log = get_logger(__name__)

# ── MongoDB Connection ──────────────────────────────────────────────────────────
client = AsyncIOMotorClient(cfg.mongo_uri, serverSelectionTimeoutMS=5000)
db = client[cfg.mongo_db]
articles_col = db["articles"]

# ── Security Middleware ─────────────────────────────────────────────────────────
from fastapi import Header

PUBLIC_PATHS = {"/", "/health", "/docs", "/openapi.json"}

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
        
    if path in PUBLIC_PATHS:
        return
        
    if not cfg.api_key:
        return
        
    key_to_check = x_api_key or api_key_query
    
    if key_to_check != cfg.api_key:
        log.warning(f"Unauthorized request to {path} from {client}")
        raise HTTPException(status_code=403, detail="Invalid or missing API key")

app = FastAPI(
    title="DarkPulse Local API",
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


# ---------- Static file serving ----------
_STATIC_DIR = pathlib.Path(__file__).resolve().parent

# ---------- API endpoints ----------
@app.get("/")
def home():
    """Serve the frontend dashboard."""
    return FileResponse(_STATIC_DIR / "index.html", media_type="text/html")

@app.get("/app.js")
def serve_js():
    return FileResponse(_STATIC_DIR / "app.js", media_type="application/javascript",
                        headers={"Cache-Control": "no-cache, no-store, must-revalidate"})

@app.get("/style.css")
def serve_css():
    return FileResponse(_STATIC_DIR / "style.css", media_type="text/css",
                        headers={"Cache-Control": "no-cache, no-store, must-revalidate"})

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

@app.get("/news")
async def list_news(limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    # Standard MongoDB pagination
    cursor = articles_col.find({}).sort("scraped_at", -1).skip(offset).limit(limit)
    items = await cursor.to_list(length=limit)
    
    total = await articles_col.count_documents({})
    
    # ensure top_tag is included for UI compatibility
    for it in items:
        if "_id" in it:
            it["aid"] = str(it["_id"])
            del it["_id"]
            
        categories = it.get("categories", [])
        if categories:
            categories_sorted = sorted(categories, key=lambda x: x.get("score", 0), reverse=True)
            it["top_tag"] = categories_sorted[0].get("label", "")
        else:
            it["top_tag"] = ""

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": items,
    }

@app.get("/news/{aid}")
async def get_news(aid: str):
    doc = await articles_col.find_one({"_id": aid})
    if not doc:
        doc = await articles_col.find_one({"aid": aid})
        if not doc:
            raise HTTPException(status_code=404, detail="Article not found")
            
    doc["aid"] = str(doc.get("_id", aid))
    if "_id" in doc:
        del doc["_id"]
        
    categories = doc.get("categories", [])
    if categories:
        categories_sorted = sorted(categories, key=lambda x: x.get("score", 0), reverse=True)
        doc["top_tag"] = categories_sorted[0].get("label", "")
    else:
        doc["top_tag"] = ""
        
    return doc


# ── Collection holding raw crawl data (Redis-style KV) ──────────────────────
kv_col = db["redis_kv_store"]

# Prefixes that hold JSON item data (not news, not indexes/hashes)
_NEWS_PREFIXES = {"THN", "BLEEPING", "CSO", "HACKREAD", "INFOSEC", "KREBS", "PORTSWIGGER", "THERECORD"}

_THREAT_PREFIXES = {
    "EXPLOIT_ITEMS":      "exploit",
    "EXPLOIT_ENTITIES":   None,       # skip entity docs (duplicates)
    "LEAK_ITEMS":         "leak",
    "LEAK_ENTITIES":      None,
    "DEFACEMENT_ITEMS":   "defacement",
    "DEFACEMENT_ENTITIES": None,
    "SOCIAL_ITEMS":       "social",
    "SOCIAL_ENTITIES":    None,
    "API_ITEMS":          "api",
    "API_ENTITIES":       None,
}


def _parse_kv_item(doc) -> dict | None:
    """Turn a redis_kv_store document whose value is a JSON-encoded dict into a
    card-friendly article-like dict the frontend can render."""
    import json as _json
    raw = doc.get("value", "")
    if not raw or not isinstance(raw, str):
        return None
    try:
        data = _json.loads(raw)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None

    key = str(doc.get("_id", ""))

    # Determine source category from key prefix
    source_cat = "threat"
    for pfx, cat in _THREAT_PREFIXES.items():
        if key.startswith(pfx):
            if cat is None:  # skip entity-only prefixes
                return None
            source_cat = cat
            break

    # ── Helper: try multiple field names, return first non-empty ──────────
    def _first(*fields):
        for f in fields:
            v = data.get(f)
            if v:
                return str(v) if not isinstance(v, str) else v
        return ""

    # ── Title ─────────────────────────────────────────────────────────────
    title = _first("m_title", "title", "m_important_content", "important_content",
                    "m_name", "m_app_name")
    # Defacement fallback: use the target URL as the title
    if not title:
        raw_url = _first("m_url", "url")
        if raw_url:
            try:
                from urllib.parse import urlparse
                title = urlparse(raw_url).hostname or raw_url
            except Exception:
                title = raw_url
    if not title:
        title = "Untitled"

    # ── URL / link ────────────────────────────────────────────────────────
    url = _first("m_url", "url", "m_app_url", "m_message_sharable_link", "m_channel_url")
    if not url:
        links = data.get("m_weblink") or data.get("weblink") or []
        if links and isinstance(links, list):
            url = links[0]

    # ── Content / description ─────────────────────────────────────────────
    content = _first("m_content", "content", "m_description", "description",
                      "m_important_content", "important_content")

    # ── Source name ───────────────────────────────────────────────────────
    source_name = _first("m_source", "m_scrap_file", "m_team", "m_actor",
                         "m_platform", "m_sender_name")
    if not source_name:
        source_name = source_cat

    # ── Network ───────────────────────────────────────────────────────────
    network = _first("m_network", "network") or "clearnet"

    # ── Date ──────────────────────────────────────────────────────────────
    date_str = _first("m_leak_date", "leak_date", "m_message_date",
                       "m_exploit_year", "m_latest_date", "m_date")

    # ── Build description from multiple fields ────────────────────────────
    desc_parts = []
    if content:
        desc_parts.append(content[:400])
    pkg = data.get("m_package_id", "")
    if pkg:
        desc_parts.append(f"Package: {pkg}")
    ver = data.get("m_version", "")
    if ver:
        desc_parts.append(f"Version: {ver}")
    mod = data.get("m_mod_features", "")
    if mod:
        desc_parts.append(f"Mod: {mod}")
    # Defacement extras
    web_server = data.get("m_web_server")
    if web_server and isinstance(web_server, list):
        desc_parts.append(f"Server: {', '.join(web_server)}")
    ioc_type = data.get("m_ioc_type") or data.get("content_type")
    if ioc_type and isinstance(ioc_type, list):
        desc_parts.append(f"Type: {', '.join(ioc_type)}")
    description = " | ".join(desc_parts) if desc_parts else title

    # ── Author (for social, exploits) ─────────────────────────────────────
    author = _first("m_actor", "m_sender_name", "m_author", "author")

    return {
        "aid": key,
        "title": title,
        "description": description[:500],
        "url": url,
        "seed_url": _first("m_base_url", "base_url", "m_source_url"),
        "source": source_name,
        "source_type": source_cat,
        "author": author,
        "date": date_str,
        "scraped_at": date_str,
        "network": network,
        "top_tag": source_cat,
        "categories": [{"label": source_cat, "score": 1.0}],
        "summary": description[:300],
        "entities": {},
    }


@app.get("/threats")
async def list_threats(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    source_type: str = Query("", description="Filter: exploit, social, leak, etc."),
):
    """Return non-news threat intel entries (exploits, leaks, social, etc.)
    from the redis_kv_store collection, formatted like articles for the frontend."""

    # Build list of prefixes to scan
    prefixes = [p for p, cat in _THREAT_PREFIXES.items() if cat is not None]
    if source_type:
        prefixes = [p for p, cat in _THREAT_PREFIXES.items() if cat == source_type]
        if not prefixes:
            return {"total": 0, "offset": offset, "limit": limit, "items": []}

    regex_pattern = "^(" + "|".join(prefixes) + "):"
    query = {"_id": {"$regex": regex_pattern}}
    total = await kv_col.count_documents(query)
    cursor = kv_col.find(query).skip(offset).limit(limit)
    docs = await cursor.to_list(length=limit)

    items = []
    for doc in docs:
        parsed = _parse_kv_item(doc)
        if parsed:
            items.append(parsed)

    return {"total": total, "offset": offset, "limit": limit, "items": items}


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
    return result


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

        cards = list(getattr(result, "cards_data", []) or []) if result else []
        raw = getattr(result, "raw_data", {}) or {}

        items = []
        for card in cards:
            extra = getattr(card, "m_extra", {}) or {}
            item = {
                "name": getattr(card, "m_app_name", "") or getattr(card, "m_name", ""),
                "package_id": getattr(card, "m_package_id", ""),
                "version": getattr(card, "m_version", ""),
                "description": getattr(card, "m_description", "") or "",
                "url": getattr(card, "m_app_url", "") or "",
                "extra": extra if isinstance(extra, dict) else {},
            }
            items.append(item)

        # Extract summary from raw data
        summary = {
            "grade": raw.get("grade", ""),
            "risk_score": raw.get("risk_score", ""),
            "total_vulns": raw.get("total_vulns", 0),
            "total_secrets": raw.get("total_secrets", 0),
            "critical": raw.get("critical", 0),
            "high": raw.get("high", 0),
            "medium": raw.get("medium", 0),
            "low": raw.get("low", 0),
        }

        doc = {
            "query": repo_url,
            "results": items,
            "summary": summary,
            "count": len(items),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await github_col.insert_one(doc)

        log.info(f"GitHub scan complete: {len(items)} items for {repo_url}")
        return {"status": "ok", "query": repo_url, "count": len(items), "results": items, "summary": summary}

    except Exception as e:
        log.error(f"GitHub scan failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@app.get("/github/history")
async def github_history(limit: int = Query(50, ge=1, le=200)):
    cursor = github_col.find({}).sort("timestamp", -1).limit(limit)
    docs = await cursor.to_list(length=limit)
    for d in docs:
        d["_id"] = str(d["_id"])
    return {"items": docs}


@app.delete("/github/history/{item_id}")
async def github_delete_history(item_id: str):
    from bson import ObjectId
    try:
        result = await github_col.delete_one({"_id": ObjectId(item_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Not found")
    return {"status": "deleted", "id": item_id}


# ═══════════════════════════════════════════════════════════════════════════════
# APK MOD SCANNER
# ═══════════════════════════════════════════════════════════════════════════════
apk_col = db["apk_scans"]


@app.post("/apk/scan")
async def apk_scan(request: Request):
    """Search APK mirror sites for a Play Store app."""
    import asyncio
    from datetime import datetime, timezone

    body = await request.json()
    playstore_url = str(body.get("playstore_url", "")).strip()
    if not playstore_url or "play.google.com" not in playstore_url:
        raise HTTPException(status_code=400, detail="Valid Play Store URL is required")

    log.info(f"APK scan requested for: {playstore_url}")

    try:
        from api_collector.scripts._apk_mod import _apk_mod
        from playwright.async_api import async_playwright

        scanner = _apk_mod()
        loop = asyncio.get_running_loop()

        async def _run_apk():
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                try:
                    return await scanner.parse_leak_data(
                        query={"playstore": playstore_url}, context=context
                    )
                finally:
                    await browser.close()

        result = await loop.run_in_executor(
            None, lambda: asyncio.run(_run_apk())
        )

        cards = list(getattr(result, "cards_data", []) or []) if result else []

        items = []
        for card in cards:
            extra = getattr(card, "m_extra", {}) or {}
            item = {
                "app_name": getattr(card, "m_app_name", ""),
                "package_id": getattr(card, "m_package_id", ""),
                "version": getattr(card, "m_version", ""),
                "latest_date": getattr(card, "m_latest_date", ""),
                "download_links": getattr(card, "m_download_link", []) or [],
                "app_url": getattr(card, "m_app_url", ""),
                "mod_features": getattr(card, "m_mod_features", ""),
                "source": (extra.get("source", "") if isinstance(extra, dict) else ""),
            }
            items.append(item)

        doc = {
            "query": playstore_url,
            "results": items,
            "count": len(items),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await apk_col.insert_one(doc)

        log.info(f"APK scan complete: {len(items)} items for {playstore_url}")
        return {"status": "ok", "query": playstore_url, "count": len(items), "results": items}

    except Exception as e:
        log.error(f"APK scan failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


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
            item = {
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

class NLQRequest(BaseModel):
    query: str

@app.post("/search/nlq")
async def search_nlq(req: NLQRequest, request: Request):
    """
    Natural Language Query endpoint. Translates human text into a MongoDB
    aggregation pipeline using Gemini 3 Flash, executes it against intel_feed,
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
            pipeline = [
                {"$match": {"$or": [
                    {"title": {"$regex": f"(?i){keyword}"}},
                    {"ai_summary": {"$regex": f"(?i){keyword}"}}
                ]}},
                {"$sort": {"_id": -1}},
                {"$limit": 20}
            ]
        else:
            client = genai.Client(api_key=api_key)
            
            prompt = f"""
            You are a MongoDB translation engine for a Threat Intelligence dashboard.
            Translate the user's natural language query into a raw MongoDB aggregation pipeline JSON array.
            
            The collection is named `intel_feed`. 
            Schema fields:
            - _id (ObjectId)
            - source_type (string, e.g., 'news', 'exploit', 'leak', 'defacement', 'social', 'api')
            - title (string)
            - url (string)
            - date (string YYYY-MM-DD or ISO)
            - impact_score (int 0-100)
            - is_fake (bool)
            - threat_actors (list of strings)
            - ai_summary (string)
            
            User Query: "{req.query}"
            
            Return ONLY a JSON array representing the aggregation pipeline. No markdown formatting, no explanations. Just valid JSON like:
            [{{"$match": {{"title": {{"$regex": "(?i)rockstar"}}}}}}, {{"$sort": {{"impact_score": -1}}}}, {{"$limit": 20}}]
            """
            
            loop = asyncio.get_running_loop()
            def call_gemini():
                response = client.models.generate_content(
                    model='gemini-2.5-flash',
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        temperature=0.0,
                        response_mime_type="application/json"
                    )
                )
                return response.text
                
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
