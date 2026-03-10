from typing import Any, Dict, List
from fastapi import FastAPI, Query, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
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


# ---------- API endpoints ----------
@app.get("/")
def home():
    return {
        "ok": True,
        "message": "DarkPulse Local API is running",
        "endpoints": ["/news", "/news/{aid}", "/health"],
        "auth_required": bool(cfg.api_key),
    }

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
async def list_news(limit: int = Query(20, ge=1, le=200), offset: int = Query(0, ge=0)):
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
