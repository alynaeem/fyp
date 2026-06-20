def _leak_status_host(value: str) -> str:
    if not value:
        return ""
    try:
        return urlparse(value).netloc or value
    except Exception:
        return value


def _leak_status_sort_key(item: dict[str, Any]) -> tuple[int, int, str]:
    status = str(item.get("status") or "not_run").lower()
    mongo_docs = int(item.get("mongo_document_count") or 0)
    script_file = str(item.get("script_file") or "")
    return (_LEAK_SOURCE_STATUS_ORDER.get(status, 99), -mongo_docs, script_file)


async def _build_leak_source_status_payload() -> dict[str, Any]:
    script_paths = sorted(
        path
        for path in _LEAK_SOURCE_SCRIPT_DIR.glob("_*.py")
        if path.name != "__init__.py"
    )
    status_docs = await collector_source_status_col.find({"collector_type": "leak"}).to_list(length=None)
    status_by_module = {
        str(doc.get("module_stem") or ""): doc
        for doc in status_docs
        if doc.get("module_stem")
    }

    mongo_counts_rows = await leak_items_col.aggregate([
        {"$group": {"_id": "$source_name", "count": {"$sum": 1}}},
    ]).to_list(length=None)
    mongo_counts = {
        str(row.get("_id") or ""): int(row.get("count") or 0)
        for row in mongo_counts_rows
        if row.get("_id")
    }

    items: list[dict[str, Any]] = []
    status_counts: dict[str, int] = {}
    total_mongo_documents = 0
    with_data = 0

    for script_path in script_paths:
        module_stem = script_path.stem
        status_doc = status_by_module.get(module_stem, {})
        source_name = (
            status_doc.get("source_name")
            or module_stem.lstrip("_")
        )
        mongo_document_count = int(mongo_counts.get(str(source_name), 0))
        status = str(status_doc.get("status") or "").lower() or ("ingested" if mongo_document_count else "not_run")
        if mongo_document_count > 0 and status in {"empty", "not_run"}:
            status = "ingested"

        item = {
            "module_stem": module_stem,
            "script_file": script_path.name,
            "source_name": source_name,
            "status": status,
            "source_kind": status_doc.get("source_kind") or "leak_site",
            "auto_discovered": bool(status_doc.get("auto_discovered")),
            "target_url": status_doc.get("target_url") or "",
            "target_host": status_doc.get("target_host") or _leak_status_host(str(status_doc.get("target_url") or "")),
            "parse_count": int(status_doc.get("parse_count") or 0),
            "raw_items": int(status_doc.get("raw_items") or 0),
            "raw_entities": int(status_doc.get("raw_entities") or 0),
            "mongo_document_count": mongo_document_count,
            "last_run_at": status_doc.get("last_run_at"),
            "last_success_at": status_doc.get("last_success_at"),
            "last_error": status_doc.get("last_error") or "",
            "updated_at": status_doc.get("updated_at"),
        }
        items.append(item)
        status_counts[status] = status_counts.get(status, 0) + 1
        total_mongo_documents += mongo_document_count
        if mongo_document_count > 0:
            with_data += 1

    items.sort(key=_leak_status_sort_key)

    return {
        "summary": {
            "total_scripts": len(items),
            "with_data": with_data,
            "without_data": max(len(items) - with_data, 0),
            "total_mongo_documents": total_mongo_documents,
            "status_counts": status_counts,
        },
        "items": items,
    }


# ---------- Static file serving ----------
_STATIC_DIR = pathlib.Path(__file__).resolve().parent
_ASSETS_DIR = _STATIC_DIR / "assets"
_PARTIALS_DIR = _STATIC_DIR / "partials"
_JS_DIR = _STATIC_DIR / "js"
if _ASSETS_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(_ASSETS_DIR)), name="assets")
if _PARTIALS_DIR.exists():
    app.mount("/partials", StaticFiles(directory=str(_PARTIALS_DIR)), name="partials")
if _JS_DIR.exists():
    app.mount("/js", StaticFiles(directory=str(_JS_DIR)), name="js")

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
        "scan_mode": SMART_UPDATE_SCAN_MODE,
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
        "message": f"Fast headless background sync started. Old cached records remain visible; new unique records will be upserted. Arya delivery: {delivery_mode}.",
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
    if (
        not active_run
        and latest_notification
        and latest_notification.get("status") in RUNNING_SCAN_STATUSES
    ):
        resolved_status = (
            latest_run.get("status")
            if latest_run and latest_run.get("status") not in RUNNING_SCAN_STATUSES
            else "completed_no_new"
        )
        latest_notification = {
            **latest_notification,
            "status": resolved_status,
            "title": "No active scan is running",
            "message": "The previous scan is no longer active. Press Scan Now to start a fresh hidden background sync.",
            "completed_at": (latest_run or {}).get("completed_at") or latest_notification.get("completed_at"),
        }
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

@app.post("/api/ai/query")
async def ai_query(request: Request):
    """Non-streaming fallback — collects the full LLM answer then returns JSON."""
    body = await request.json()
    query = str(body.get("query", "")).strip()
    if not query:
        raise HTTPException(status_code=400, detail="Query is required")

    collection = str(body.get("collection") or "redis_kv_store").strip() or "redis_kv_store"
    try:
        limit = min(max(int(body.get("limit") or 8), 1), 15)
    except (TypeError, ValueError):
        limit = 8
    try:
        max_context_words = min(max(int(body.get("max_context_words") or 1800), 300), 2500)
    except (TypeError, ValueError):
        max_context_words = 1800

    try:
        from ollama_mongo_intelligence import stream_query_from_mongo

        loop = asyncio.get_running_loop()

        def _run_sync():
            answer_parts = []
            meta = None
            for item in stream_query_from_mongo(
                query,
                collection_name=collection,
                limit=limit,
                max_context_words=max_context_words,
            ):
                if isinstance(item, dict):
                    meta = item
                else:
                    answer_parts.append(item)
            return meta, "".join(answer_parts)

        meta, answer = await loop.run_in_executor(None, _run_sync)

        if meta and meta.get("status") == "error":
            raise HTTPException(status_code=500, detail=meta.get("message", "MongoDB error"))
        if meta and meta.get("status") == "empty":
            return {
                "status": "ok",
                "query": query,
                "collection": collection,
                "count": 0,
                "context_word_count": 0,
                "answer": meta.get("message", "No matching data found."),
                "documents": [],
            }

        return {
            "status": "ok",
            "query": query,
            "collection": meta.get("collection", collection) if meta else collection,
            "count": meta.get("count", 0) if meta else 0,
            "context_word_count": meta.get("context_word_count", 0) if meta else 0,
            "answer": answer,
            "documents": meta.get("documents", []) if meta else [],
        }
    except HTTPException:
        raise
    except Exception as exc:
        log.error(f"AI query failed: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"AI query failed: {exc}")


@app.post("/api/ai/stream")
async def ai_stream(request: Request):
    """SSE streaming endpoint — sends LLM tokens to the browser as they arrive."""
    body = await request.json()
    query = str(body.get("query", "")).strip()
    if not query:
        raise HTTPException(status_code=400, detail="Query is required")

    collection = str(body.get("collection") or "redis_kv_store").strip() or "redis_kv_store"
    try:
        limit = min(max(int(body.get("limit") or 8), 1), 15)
    except (TypeError, ValueError):
        limit = 8
    try:
        max_context_words = min(max(int(body.get("max_context_words") or 1800), 300), 2500)
    except (TypeError, ValueError):
        max_context_words = 1800

    async def _sse_generator():
        import queue
        import threading
        from ollama_mongo_intelligence import stream_query_from_mongo

        q: queue.Queue = queue.Queue()
        _SENTINEL = object()

        def _produce():
            try:
                for item in stream_query_from_mongo(
                    query,
                    collection_name=collection,
                    limit=limit,
                    max_context_words=max_context_words,
                ):
                    q.put(item)
            except Exception as exc:
                q.put({"status": "error", "message": str(exc)})
            finally:
                q.put(_SENTINEL)

        thread = threading.Thread(target=_produce, daemon=True)
        thread.start()

        while True:
            try:
                item = await asyncio.get_running_loop().run_in_executor(
                    None, lambda: q.get(timeout=0.05)
                )
            except queue.Empty:
                continue

            if item is _SENTINEL:
                break

            if isinstance(item, dict):
                yield f"event: meta\ndata: {json.dumps(item, default=str)}\n\n"
            else:
                yield f"event: chunk\ndata: {json.dumps(item)}\n\n"

        yield "event: done\ndata: {}\n\n"

    return StreamingResponse(
        _sse_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.get("/leaks/source-status")
async def leak_source_status(current_user: dict = Depends(get_current_user)):
    payload = await _build_leak_source_status_payload()
    return {"status": "ok", **payload}


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


