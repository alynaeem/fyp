import asyncio
import pathlib
import json
import re
from typing import Any, Dict, List
from urllib.parse import urlparse
from fastapi import FastAPI, Query, Request, HTTPException, Depends, WebSocket, WebSocketDisconnect
import bcrypt
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
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

# Users collection and auth setup
users_col = db["users"]


SECRET_KEY = "a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

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
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Auth security scheme
security = HTTPBearer()

async def get_current_user(auth: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    token = auth.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
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
        
    PUBLIC_PATHS = {"/", "/health", "/docs", "/openapi.json", "/auth/login", "/auth/register"}
    
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
        })
        log.info("Default admin user created.")


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


# ── Authentication Endpoints ────────────────────────────────────────────────
@app.post("/auth/login")
async def login(request: Request):
    body = await request.json()
    username = body.get("username")
    password = body.get("password")
    
    user = await users_col.find_one({"username": username})
    if not user or not verify_password(password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    if user.get("status") != "approved":
        raise HTTPException(status_code=403, detail="Account pending approval")
    
    access_token = create_access_token(data={"sub": user["username"], "role": user.get("role", "user")})
    return {"access_token": access_token, "token_type": "bearer", "role": user.get("role", "user")}


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
        "created_at": datetime.utcnow().isoformat()
    }
    await users_col.insert_one(user_doc)
    return {"status": "ok", "message": "Registration successful. Please wait for admin approval."}


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
        "created_at": datetime.utcnow().isoformat()
    }
    await users_col.insert_one(user_doc)
    return {"status": "ok", "message": "User created successfully"}

@app.get("/stats/map")
async def get_map_stats():
    """Return country impact data for leaks and defacement items."""
    leak_items = await _fetch_threat_items("leak")
    defacement_items = await _fetch_threat_items("defacement")

    bucket: Dict[str, Dict[str, Any]] = {}

    def _touch(code: str) -> Dict[str, Any]:
        if code not in bucket:
            bucket[code] = {
                "code": code,
                "name": _COUNTRY_CODE_TO_NAME.get(code, code),
                "leak_count": 0,
                "defacement_count": 0,
                "total": 0,
                "examples": [],
            }
        return bucket[code]

    for item in leak_items:
        for code in item.get("country_codes", []) or []:
            entry = _touch(code)
            entry["leak_count"] += 1
            entry["total"] += 1
            if len(entry["examples"]) < 4:
                entry["examples"].append({
                    "aid": item["aid"],
                    "title": item["title"],
                    "source_type": item["source_type"],
                })

    for item in defacement_items:
        for code in item.get("country_codes", []) or []:
            entry = _touch(code)
            entry["defacement_count"] += 1
            entry["total"] += 1
            if len(entry["examples"]) < 4:
                entry["examples"].append({
                    "aid": item["aid"],
                    "title": item["title"],
                    "source_type": item["source_type"],
                })

    countries = sorted(bucket.values(), key=lambda item: (-item["total"], item["name"]))
    return {
        "map_data": {item["code"]: item["total"] for item in countries},
        "countries": countries,
        "summary": {
            "affected_countries": len(countries),
            "leak_items_with_country": sum(1 for item in leak_items if item.get("country_codes")),
            "defacement_items_with_country": sum(1 for item in defacement_items if item.get("country_codes")),
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
    for field in fields:
        if field not in data:
            continue
        value = data.get(field)
        scalar = _coerce_scalar(value)
        if scalar:
            return scalar
    return ""


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
    needle = (query or "").strip().lower()
    if not needle:
        return items

    filtered = []
    for item in items:
        haystack = " ".join([
            str(item.get("title", "")),
            str(item.get("description", "")),
            str(item.get("summary", "")),
            str(item.get("source", "")),
            str(item.get("source_type", "")),
            str(item.get("author", "")),
            str(item.get("ip_addresses", "")),
            str(item.get("attacker", "")),
            str(item.get("team", "")),
            str(item.get("web_server", "")),
            " ".join(item.get("country_names", []) or []),
            json.dumps(item.get("raw", {}), ensure_ascii=False, default=str),
        ]).lower()
        if needle in haystack:
            filtered.append(item)
    return filtered


def _build_article_item(doc: dict, include_raw: bool = False) -> dict:
    raw_doc = dict(doc)
    item = dict(doc)
    item["aid"] = str(item.get("_id", item.get("aid", "")))
    item.pop("_id", None)

    categories = item.get("categories", [])
    if categories:
        categories_sorted = sorted(categories, key=lambda x: x.get("score", 0), reverse=True)
        item["top_tag"] = categories_sorted[0].get("label", "")
    else:
        item["top_tag"] = ""

    item["source_type"] = (item.get("source_type") or "news").lower()
    item["author"] = item.get("author") or item.get("writer") or ""
    item["scraped_at"] = _coerce_datetime_string(item.get("scraped_at") or item.get("date"))
    item["date"] = _coerce_datetime_string(item.get("date") or item.get("scraped_at"))
    item["entities"] = _normalize_entities(item.get("entities"))
    item["network"] = item.get("network", {}).get("type") if isinstance(item.get("network"), dict) else item.get("network", "clearnet")
    item["ip_addresses"] = ""
    item["attacker"] = ""
    item["team"] = ""
    item["web_server"] = ""
    item["country_codes"] = _infer_country_codes(item, raw_doc)
    item["country_names"] = [_COUNTRY_CODE_TO_NAME[code] for code in item["country_codes"]]
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

    title = _extract_field(data, "m_title", "title", "m_important_content", "important_content", "m_name", "m_app_name")
    raw_url = _extract_field(data, "m_url", "url", "m_app_url", "m_message_sharable_link", "m_channel_url")
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
        try:
            title = urlparse(raw_url).hostname or raw_url
        except Exception:
            title = raw_url
    if not title:
        title = "Untitled"

    content = _extract_field(data, "m_content", "content", "m_description", "description", "m_important_content", "important_content")
    source_name = _extract_field(data, "m_source", "m_scrap_file", "m_team", "m_actor", "m_platform", "m_sender_name") or source_cat
    network = _extract_network(data)
    date_value = _coerce_datetime_string(_extract_field(data, "m_leak_date", "leak_date", "m_message_date", "m_exploit_year", "m_latest_date", "m_date"))
    seed_url = _extract_field(data, "m_base_url", "base_url", "m_source_url")
    author = _extract_field(data, "m_actor", "m_sender_name", "m_author", "author")
    ip_addresses = _extract_field(data, "m_ip", "ip_address", "ip")
    attacker = _extract_field(data, "m_attacker", "attacker")
    team = _extract_field(data, "m_team", "team")
    web_server = _coerce_scalar(data.get("m_web_server") or data.get("web_server"))

    content_types = _coerce_list(data.get("m_ioc_type") or data.get("content_type"))
    categories = [{"label": source_cat, "score": 1.0}]
    for label in content_types:
        if label and label != source_cat:
            categories.append({"label": label, "score": 0.75})

    description_parts = [content[:400]] if content else []
    if ip_addresses:
        description_parts.append(f"IP: {ip_addresses}")
    if attacker:
        description_parts.append(f"Attacker: {attacker}")
    if team:
        description_parts.append(f"Team: {team}")
    if web_server:
        description_parts.append(f"Server: {web_server}")
    if content_types:
        description_parts.append(f"Type: {', '.join(content_types)}")
    description = " | ".join(part for part in description_parts if part) or title

    item = {
        "aid": key,
        "title": title,
        "description": description[:800],
        "url": raw_url,
        "seed_url": seed_url,
        "source": source_name,
        "source_type": source_cat,
        "author": author or attacker,
        "date": date_value,
        "scraped_at": date_value,
        "network": network,
        "top_tag": source_cat,
        "categories": categories,
        "summary": (content or description)[:400],
        "entities": _normalize_entities(data.get("entities") or data.get("m_entities")),
        "ip_addresses": ip_addresses,
        "attacker": attacker,
        "team": team,
        "web_server": web_server,
    }
    item["country_codes"] = _infer_country_codes(item, data)
    item["country_names"] = [_COUNTRY_CODE_TO_NAME[code] for code in item["country_codes"]]
    if include_raw:
        item["raw"] = data
    return item


def _parse_kv_item(doc: dict, include_raw: bool = False) -> dict | None:
    raw = doc.get("value", "")
    if not raw or not isinstance(raw, str):
        return None
    try:
        data = json.loads(raw)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    return _build_threat_item(str(doc.get("_id", "")), data, include_raw=include_raw)


async def _fetch_news_items(include_raw: bool = False) -> list[dict]:
    docs = await articles_col.find({}).to_list(length=None)
    return [_build_article_item(doc, include_raw=include_raw) for doc in docs]


async def _fetch_threat_items(source_type: str = "", include_raw: bool = False) -> list[dict]:
    prefixes = [prefix for prefix, category in _THREAT_PREFIXES.items() if category is not None]
    if source_type:
        prefixes = [prefix for prefix, category in _THREAT_PREFIXES.items() if category == source_type]
        if not prefixes:
            return []

    regex_pattern = "^(" + "|".join(prefixes) + "):"
    docs = await kv_col.find({"_id": {"$regex": regex_pattern}}).to_list(length=None)
    items = []
    for doc in docs:
        parsed = _parse_kv_item(doc, include_raw=include_raw)
        if parsed:
            items.append(parsed)
    return items


@app.get("/news")
async def list_news(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    q: str = Query(""),
    include_raw: bool = Query(False),
):
    items = await _fetch_news_items(include_raw=include_raw)
    items = sorted(items, key=_feed_sort_key, reverse=True)
    items = _filter_feed_items(items, q)
    payload = {
        "total": len(items),
        "offset": offset,
        "limit": limit,
        "items": items[offset:offset + limit],
    }
    payload["news"] = payload["items"]
    return payload


@app.get("/news/{aid}")
async def get_news(aid: str):
    doc = await articles_col.find_one({"_id": aid})
    if not doc:
        doc = await articles_col.find_one({"aid": aid})
        if not doc:
            raise HTTPException(status_code=404, detail="Article not found")
    item = _build_article_item(doc, include_raw=True)
    return {"article": item, **item}


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
        items = await _fetch_news_items(include_raw=include_raw)
    elif canonical in {"exploit", "leak", "defacement", "social", "api"}:
        items = await _fetch_threat_items(canonical, include_raw=include_raw)
    else:
        news_items = await _fetch_news_items(include_raw=include_raw)
        threat_items = await _fetch_threat_items(include_raw=include_raw)
        items = news_items + threat_items

    items = sorted(items, key=_feed_sort_key, reverse=True)
    items = _filter_feed_items(items, q)
    return {
        "total": len(items),
        "offset": offset,
        "limit": limit,
        "items": items[offset:offset + limit],
    }


@app.get("/feed/{aid}")
async def get_feed_item(aid: str):
    if any(aid.startswith(f"{prefix}:") for prefix in _THREAT_PREFIXES):
        doc = await kv_col.find_one({"_id": aid})
        parsed = _parse_kv_item(doc, include_raw=True) if doc else None
        if not parsed:
            raise HTTPException(status_code=404, detail="Threat item not found")
        return parsed

    doc = await articles_col.find_one({"_id": aid})
    if not doc:
        doc = await articles_col.find_one({"aid": aid})
        if not doc:
            raise HTTPException(status_code=404, detail="Feed item not found")
    return _build_article_item(doc, include_raw=True)


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
                    model='gemini-1.5-flash',
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

