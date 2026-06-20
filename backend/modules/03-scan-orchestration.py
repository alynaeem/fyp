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
                "scan_mode": SMART_UPDATE_SCAN_MODE,
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
            "scan_mode": SMART_UPDATE_SCAN_MODE,
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


SECRET_KEY = cfg.jwt_secret.strip() or secrets.token_urlsafe(48)
if not cfg.jwt_secret.strip():
    log.warning("JWT_SECRET is not configured. A temporary startup-only JWT secret was generated.")
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

app.include_router(build_healing_router(get_current_user, admin_required))


# Ensure default admin exists on startup
@app.on_event("startup")
async def create_default_admin():
    initial_username = cfg.initial_admin_username.strip()
    initial_password = cfg.initial_admin_password
    if initial_username and initial_password:
        admin = await users_col.find_one({"username": initial_username})
        if not admin:
            hashed = get_password_hash(initial_password)
            await users_col.insert_one({
                "username": initial_username,
                "password": hashed,
                "email": cfg.initial_admin_email.strip() or "admin@example.com",
                "name": cfg.initial_admin_name.strip() or initial_username,
                "status": "approved",
                "role": "admin",
                "two_factor_enabled": False,
            })
            log.info("Initial admin user created from environment configuration.")
    elif not await users_col.find_one({"role": "admin"}):
        log.warning(
            "No admin user exists and INITIAL_ADMIN_USERNAME/INITIAL_ADMIN_PASSWORD are not configured. "
            "Create an admin through a trusted local setup path before production use."
        )

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
    await _ensure_intelligence_indexes()


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


async def _warm_map_stats_cache() -> None:
    await asyncio.sleep(1)
    try:
        await get_map_stats()
        log.info("Map stats cache warmed on startup.")
    except Exception as exc:
        log.error(f"Map stats warmup failed: {exc}", exc_info=True)


@app.on_event("startup")
async def startup_warm_map_stats():
    global _map_stats_warmup_task
    if _map_stats_warmup_task is None or _map_stats_warmup_task.done():
        _map_stats_warmup_task = asyncio.create_task(_warm_map_stats_cache())


async def _warm_feed_cache() -> None:
    await asyncio.sleep(30.0)
    try:
        await stats()
        warm_tasks = []
        for source_key in ("all", "news", "leak", "defacement", "exploit", "social", "api"):
            cache_key = ("feed", source_key, 30, 0, "", "", "", "", False)
            if source_key == "all":
                async def warm_all(key=cache_key):
                    total, items = await _fetch_combined_feed_page(30, 0)
                    _cache_set_feed_page(key, {
                        "total": total,
                        "offset": 0,
                        "limit": 30,
                        "items": [_public_feed_item(item) for item in items],
                    })
                warm_tasks.append(warm_all())
            elif source_key == "news":
                async def warm_news(key=cache_key):
                    total, items = await _fetch_news_page(30, 0)
                    _cache_set_feed_page(key, {
                        "total": total,
                        "offset": 0,
                        "limit": 30,
                        "items": [_public_feed_item(item) for item in items],
                    })
                warm_tasks.append(warm_news())
            else:
                async def warm_threat(source=source_key, key=cache_key):
                    total, items = await _fetch_threat_page(source, 30, 0)
                    _cache_set_feed_page(key, {
                        "total": total,
                        "offset": 0,
                        "limit": 30,
                        "items": [_public_feed_item(item) for item in items],
                    })
                warm_tasks.append(warm_threat())
        await asyncio.gather(*warm_tasks)
        log.info("Page-level feed and stats cache warmed on startup.")
    except Exception as exc:
        log.error(f"Feed cache warmup failed: {exc}", exc_info=True)


@app.on_event("startup")
async def startup_warm_feed_cache():
    global _feed_warmup_task
    if _feed_warmup_task is None or _feed_warmup_task.done():
        _feed_warmup_task = asyncio.create_task(_warm_feed_cache())


@app.on_event("shutdown")
async def shutdown_healing_monitor():
    global _healing_monitor_task, _map_stats_warmup_task, _feed_warmup_task
    if _healing_monitor_task and not _healing_monitor_task.done():
        _healing_monitor_task.cancel()
        try:
            await _healing_monitor_task
        except asyncio.CancelledError:
            pass
    _healing_monitor_task = None
    if _map_stats_warmup_task and not _map_stats_warmup_task.done():
        _map_stats_warmup_task.cancel()
        try:
            await _map_stats_warmup_task
        except asyncio.CancelledError:
            pass
    _map_stats_warmup_task = None
    if _feed_warmup_task and not _feed_warmup_task.done():
        _feed_warmup_task.cancel()
        try:
            await _feed_warmup_task
        except asyncio.CancelledError:
            pass
    _feed_warmup_task = None


