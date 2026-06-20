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
    env.update(SMART_UPDATE_BASE_ENV)
    env.update({
        "DARKPULSE_SCAN_JOB_ID": job_id,
        "DARKPULSE_SCAN_SOURCE": source_key,
        "DARKPULSE_SCAN_STARTED_AT": started_at,
        "SMART_UPDATE_SCAN_MODE": SMART_UPDATE_SCAN_MODE,
    })
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
            if SMART_UPDATE_SOURCE_TIMEOUT_SECONDS > 0 and _seconds_since(started_at) >= SMART_UPDATE_SOURCE_TIMEOUT_SECONDS:
                _kill_pid_group(process.pid, force=False)
                stop_signal_sent = True
                stop_deadline = asyncio.get_running_loop().time() + 5
                await _update_source_result(
                    job_id,
                    source_key,
                    status="cancelling",
                    error=f"Fast headless scan timeout after {SMART_UPDATE_SOURCE_TIMEOUT_SECONDS} seconds.",
                )
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


