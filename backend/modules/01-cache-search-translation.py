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
        title = "Fast background intelligence sync is running"
        message = (
            "Cached dashboard records stay visible while headless collectors check for new dated intelligence and upsert it into MongoDB."
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
        "scan_mode": SMART_UPDATE_SCAN_MODE,
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
        "scan_mode": SMART_UPDATE_SCAN_MODE,
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


async def _fetch_source_highlights(source_key: str, limit: int, *, since: str | None = None) -> list[dict[str, str]]:
    safe_limit = max(min(int(limit or 0), SOURCE_HIGHLIGHT_LIMIT), 0)
    if safe_limit <= 0:
        return []

    collection_name = INTELLIGENCE_SCAN_SOURCES[source_key]["collection_name"]
    query: dict[str, Any] = {}
    if since:
        # Raw collector docs use ISO strings for created_at. Filtering here makes
        # the run summary show records inserted during this scan, not stale cache.
        query["$or"] = [
            {"created_at": {"$gte": since}},
            {"updated_at": {"$gte": since}},
            {"synced_at": {"$gte": since}},
        ]
    docs = await db[collection_name].find(query).sort([("created_at", -1), ("updated_at", -1), ("_id", -1)]).limit(max(safe_limit * 3, safe_limit)).to_list(length=max(safe_limit * 3, safe_limit))
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
    highlights = await _fetch_source_highlights(source_key, min(new_records, SOURCE_HIGHLIGHT_LIMIT), since=started_at)
    payload = {
        "source": source_key,
        "label": source_meta["label"],
        "collector": source_meta["collector"],
        "status": status,
        "scan_mode": SMART_UPDATE_SCAN_MODE,
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


async def _ensure_intelligence_indexes() -> None:
    index_jobs = [
        intelligence_runs_col.create_index([("started_at", -1)]),
        intelligence_notifications_col.create_index([("updated_at", -1)]),
        automation_state_col.create_index([("updated_at", -1)]),
    ]
    for source_meta in INTELLIGENCE_SCAN_SOURCES.values():
        collection = db[source_meta["collection_name"]]
        index_jobs.extend([
            collection.create_index([("dedupe_key", 1)]),
            collection.create_index([("created_at", -1)]),
            collection.create_index([("updated_at", -1)]),
        ])
    await asyncio.gather(*index_jobs, return_exceptions=True)


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


