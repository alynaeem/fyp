import pathlib
from typing import Any, Dict, List
from fastapi import FastAPI, Query, Request, HTTPException, Depends
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
_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
PUBLIC_PATHS = {"/", "/health", "/docs", "/openapi.json"}

async def verify_api_key(request: Request, api_key: str = Depends(_API_KEY_HEADER)):
    if request.url.path in PUBLIC_PATHS:
        return
    if not cfg.api_key:
        return
    if api_key != cfg.api_key:
        log.warning(f"Unauthorized request to {request.url.path} from {request.client}")
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

    title = (data.get("m_title") or data.get("m_important_content") or data.get("m_name") or "Untitled")
    content = data.get("m_content", "")
    url = data.get("m_url") or ""
    if not url:
        links = data.get("m_weblink", [])
        if links and isinstance(links, list):
            url = links[0]
    source_name = data.get("m_source") or data.get("m_scrap_file") or data.get("m_team") or source_cat
    network = data.get("m_network", "clearnet")

    return {
        "aid": key,
        "title": title,
        "description": content[:500] if content else title,
        "url": url,
        "seed_url": data.get("m_base_url", ""),
        "source": source_name,
        "source_type": source_cat,
        "scraped_at": data.get("m_leak_date") or data.get("m_exploit_year") or "",
        "network": network,
        "top_tag": source_cat,
        "categories": [{"label": source_cat, "score": 1.0}],
        "summary": content[:300] if content else "",
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