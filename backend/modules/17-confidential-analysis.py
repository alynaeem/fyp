@app.post("/scan/repo", dependencies=[Depends(get_current_user)])
async def scan_repo(request: Request):
    """
    Scans a GitHub repository for vulnerabilities using Trivy.
    """
    try:
        from api_collector.scripts.github_trivy_checker import github_trivy_checker
        import time

        body = await request.json()
        repo_url = str(body.get("url", "")).strip()
        git_token = (
            str(body.get("token", "")).strip()
            or str(body.get("git_token", "")).strip()
            or cfg.github_token
            or os.environ.get("GITHUB_TOKEN", "")
        ).strip()
        
        if not repo_url:
            raise HTTPException(status_code=400, detail="Repository URL is required")

        parsed_repo = _parse_github_repo_url(repo_url)
        if not parsed_repo:
            return {"status": "error", "message": "Please enter a valid GitHub repository URL."}

        owner, repo, normalized_repo_url = parsed_repo
        log.info("Repository scan requested for URL=%s owner=%s repo=%s", repo_url, owner, repo)

        if not git_token:
            log.warning("Repository scan cannot start: GITHUB_TOKEN is missing")
            return {
                "status": "error",
                "message": "GitHub token is missing. Please set GITHUB_TOKEN in .env and restart the server.",
            }

        cached_scan = await github_col.find_one(
            {
                "scanner": "scan_repo",
                "query": normalized_repo_url,
                "created_at": {"$gte": datetime.now(timezone.utc) - timedelta(hours=6)},
            },
            sort=[("created_at", -1)],
        )
        if cached_scan and isinstance(cached_scan.get("response"), dict):
            cached_response = dict(cached_scan["response"])
            cached_response["cached"] = True
            cached_summary = dict(cached_response.get("summary") or {})
            cached_summary["scan_status"] = "cached"
            cached_summary["note"] = (
                cached_summary.get("note")
                or "Repository analysis loaded from the recent local scan cache."
            )
            recs, ai_status, ai_message = await _build_repo_ai_recommendations(
                cached_summary.get("repo_name") or f"{owner}/{repo}",
                cached_summary,
                list(cached_response.get("vulnerabilities") or []),
                list(cached_response.get("secrets") or []),
                list(cached_response.get("misconfigs") or []),
            )
            cached_summary["recommendations"] = recs
            cached_summary["ai_status"] = ai_status
            cached_summary["ai_message"] = ai_message
            cached_response["summary"] = cached_summary
            log.info("Repository scan cache hit for %s/%s", owner, repo)
            return cached_response

        try:
            github_meta = await asyncio.wait_for(
                _inspect_github_repository(owner, repo, git_token),
                timeout=45,
            )
        except asyncio.TimeoutError:
            log.error("GitHub API validation timed out for %s/%s", owner, repo)
            return {"status": "error", "message": "GitHub API request timed out. Try again later."}
        except ValueError as exc:
            log.error("GitHub API validation failed for %s/%s: %s", owner, repo, exc)
            return {"status": "error", "message": str(exc)}
        
        scanner = github_trivy_checker()
        
        # run the scan
        scan_query = {
            "github": normalized_repo_url,
            "git_token": git_token,
            "timeout": 180,
            "print_details": False,
            "keep_workdir": False,
        }

        try:
            loop = asyncio.get_running_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: asyncio.run(scanner.parse_leak_data(query=scan_query, context=None)),
                ),
                timeout=210,
            )
        except asyncio.TimeoutError:
            log.error("Repository scan timed out for %s/%s", owner, repo)
            return {
                "status": "error",
                "message": "Repository scan timed out. Try a smaller repository or run again later.",
            }
        
        # The result of parse_leak_data is an apk_data_model
        raw_data = getattr(result, "raw_data", {}) or {}
        
        # Check for internal scanner errors
        if "error" in raw_data:
            err_msg = raw_data.get("error")
            if err_msg == "git clone failed":
                stderr = str(raw_data.get("stderr") or "")
                stderr_lower = stderr.lower()
                if "authentication failed" in stderr_lower or "bad credentials" in stderr_lower:
                    err_msg = "GitHub token is invalid or expired. Please update GITHUB_TOKEN in .env and restart the server."
                elif "could not read Username" in stderr or "Repository not found" in stderr:
                    err_msg = "Repository is private or not accessible with the current token."
            log.error("Scanner internal error for %s/%s: %s", owner, repo, err_msg)
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
        repo_path = f"{owner}/{repo}"
        coverage = summary_data.get("coverage", {}) or {}
        coverage["github_api"] = {
            "default_branch": github_meta.get("default_branch"),
            "discovered_files": github_meta.get("discovered_files", []),
            "open_issues_count": github_meta.get("open_issues_count", 0),
            "language": github_meta.get("language"),
        }
        summary_data["coverage"] = coverage
        repo_recommendations, repo_ai_status, repo_ai_message = await _build_repo_ai_recommendations(
            repo_path,
            summary_data,
            vulnerabilities,
            secrets,
            misconfigs,
        )
        
        # Prepare final response formatted for the UI
        log.info(
            "Repository scan completed for %s/%s: vulns=%s secrets=%s misconfigs=%s grade=%s",
            owner,
            repo,
            len(vulnerabilities),
            len(secrets),
            len(misconfigs),
            summary_data.get("grade", "A"),
        )
        response_payload = {
            "status": "ok",
            "query": normalized_repo_url,
            "repository": github_meta,
            "summary": {
                "grade": summary_data.get("grade", "A"),
                "risk_score": summary_data.get("risk_score", 0),
                "counts": summary_data.get("counts", {}),
                "posture_label": summary_data.get("posture_label", "Scan"),
                "scan_status": summary_data.get("scan_status", "complete"),
                "note": summary_data.get("note", "Repository analysis complete."),
                "coverage": summary_data.get("coverage", {}),
                "recommendations": repo_recommendations,
                "ai_status": repo_ai_status,
                "ai_message": repo_ai_message,
                "host": "github.com",
                "repo_name": repo_path,
                "port": "443",
                "scanned_by": "DarkPulse / Trivy"
            },
            "vulnerabilities": vulnerabilities,
            "secrets": secrets,
            "misconfigs": misconfigs,
            "results": vulnerabilities + secrets + misconfigs, # fallback
            "timestamp": time.strftime("%B %d, %Y")
        }
        await github_col.insert_one({
            "scanner": "scan_repo",
            "query": normalized_repo_url,
            "owner": owner,
            "repo": repo,
            "created_at": datetime.now(timezone.utc),
            "response": response_payload,
        })
        return response_payload

    except Exception as e:
        log.error(f"Repository scan failed: {e}", exc_info=True)
        return {"status": "error", "message": f"Scan failed: {str(e)}"}


async def _sync_credential_datasets(force: bool = False) -> dict[str, Any]:
    from api_collector.stealer_log_scan import (
        CREDENTIAL_DOCUMENT_SCHEMA_VERSION,
        build_documents_from_file,
        discover_credential_files,
    )

    dataset_paths = await asyncio.to_thread(discover_credential_files)
    dataset_path_strings = {str(path.resolve()) for path in dataset_paths}
    datasets: list[dict[str, Any]] = []
    synced_files = 0
    synced_records = 0

    if dataset_path_strings:
        stale_meta_cursor = credential_datasets_col.find({"path": {"$nin": list(dataset_path_strings)}})
        stale_meta = await stale_meta_cursor.to_list(length=None)
        stale_paths = [item.get("path") for item in stale_meta if item.get("path")]
        if stale_paths:
            await credential_datasets_col.delete_many({"path": {"$in": stale_paths}})
            await credential_exposures_col.delete_many({"dataset_path": {"$in": stale_paths}})
    else:
        await credential_datasets_col.delete_many({})
        await credential_exposures_col.delete_many({})

    for path in dataset_paths:
        resolved_path = str(path.resolve())
        stat = path.stat()
        existing = await credential_datasets_col.find_one({"path": resolved_path})

        should_sync = force or not existing
        if existing and not force:
            stale_redacted_docs = await credential_exposures_col.count_documents({
                "dataset_path": resolved_path,
                "$or": [
                    {"password": {"$regex": r"\[redacted_", "$options": "i"}},
                    {"raw_trace": {"$regex": r"\[redacted_", "$options": "i"}},
                    {"credential_identifier": {"$regex": r"\[redacted_", "$options": "i"}},
                    {"email_username": {"$regex": r"\[redacted_", "$options": "i"}},
                ],
            })
            should_sync = (
                existing.get("mtime_ns") != stat.st_mtime_ns
                or existing.get("size_bytes") != stat.st_size
                or existing.get("schema_version") != CREDENTIAL_DOCUMENT_SCHEMA_VERSION
                or stale_redacted_docs > 0
            )

        if should_sync:
            docs = await asyncio.to_thread(build_documents_from_file, path)
            await credential_exposures_col.delete_many({"dataset_path": resolved_path})
            if docs:
                await credential_exposures_col.insert_many(docs, ordered=False)
            synced_files += 1
            synced_records += len(docs)
            await credential_datasets_col.update_one(
                {"path": resolved_path},
                {"$set": {
                    "name": path.name,
                    "path": resolved_path,
                    "size_bytes": stat.st_size,
                    "mtime_ns": stat.st_mtime_ns,
                    "schema_version": CREDENTIAL_DOCUMENT_SCHEMA_VERSION,
                    "modified_at": datetime.utcfromtimestamp(stat.st_mtime).isoformat() + "Z",
                    "records_count": len(docs),
                    "synced_at": datetime.utcnow().isoformat() + "Z",
                }},
                upsert=True,
            )

        meta = await credential_datasets_col.find_one({"path": resolved_path}) or {}
        datasets.append({
            "name": meta.get("name", path.name),
            "path": resolved_path,
            "size_bytes": meta.get("size_bytes", stat.st_size),
            "modified_at": meta.get("modified_at", datetime.utcfromtimestamp(stat.st_mtime).isoformat() + "Z"),
            "records_count": meta.get("records_count", 0),
            "synced_at": meta.get("synced_at", ""),
        })

    datasets.sort(key=lambda item: item.get("name", "").lower())
    return {
        "datasets": datasets,
        "files_loaded": len(datasets),
        "synced_files": synced_files,
        "synced_records": synced_records,
    }


@app.on_event("startup")
async def startup_sync_credential_checker() -> None:
    try:
        await collector_source_status_col.create_index("module_stem", unique=True)
        await collector_source_status_col.create_index("source_name")
        await collector_source_status_col.create_index("status")
        await credential_datasets_col.create_index("path", unique=True)
        await credential_exposures_col.create_index("ingest_key", unique=True)
        await credential_exposures_col.create_index("dataset_path")

        summary = await _sync_credential_datasets(force=False)
        if summary.get("files_loaded", 0):
            log.info(
                "Credential checker startup sync loaded %s file(s) and %s new record(s).",
                summary.get("files_loaded", 0),
                summary.get("synced_records", 0),
            )
        else:
            log.info("Credential checker startup sync found no saved dataset files.")
    except Exception as exc:
        log.error(f"Credential checker startup sync failed: {exc}", exc_info=True)


@app.post("/credentials/search")
async def credential_checker_search(request: Request):
    """Search Mongo-backed credential exposure records hydrated from local datasets."""
    body = await request.json()
    query = str(body.get("query", "")).strip()
    limit = body.get("limit", 30)
    page = body.get("page", 1)

    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 30

    try:
        page = int(page)
    except (TypeError, ValueError):
        page = 1

    limit = max(1, min(limit, 100))
    page = max(1, page)

    if not query:
        raise HTTPException(status_code=400, detail="Search query is required")

    log.info(f"Credential checker search requested for: {query}")

    try:
        sync_summary = await _sync_credential_datasets(force=False)
        datasets = sync_summary.get("datasets", [])
        if not datasets:
            return {
                "status": "ok",
                "query": query,
                "count": 0,
                "results": [],
                "elapsed_ms": 0,
                "hosts_count": 0,
                "files_loaded": 0,
                "aggregated_count": 0,
                "datasets": [],
                "page": page,
                "per_page": limit,
                "total_pages": 0,
                "message": "No stealer-log JSON files are saved on disk yet. Upload them in Credential Checker or place them inside data/credential_checker so they can sync into Mongo.",
            }

        start = time.perf_counter()
        terms = [term for term in re.split(r"\s+", query.lower()) if term]
        mongo_query = {
            "$and": [
                {"search_blob": {"$regex": re.escape(term), "$options": "i"}}
                for term in terms
            ]
        }
        count = await credential_exposures_col.count_documents(mongo_query)
        projection = {
            "_id": 0,
            "domain_host": 1,
            "credential_identifier": 1,
            "date": 1,
            "source_domain": 1,
            "channel": 1,
            "year": 1,
            "file_type": 1,
            "email_username": 1,
            "domain": 1,
            "ip": 1,
            "password": 1,
            "password_present": 1,
            "metadata_tags": 1,
            "raw_trace": 1,
            "source_file": 1,
        }
        total_pages = math.ceil(count / limit) if count else 0
        if total_pages:
            page = min(page, total_pages)
        skip = (page - 1) * limit

        cursor = credential_exposures_col.find(mongo_query, projection).sort("date", -1).skip(skip).limit(limit)
        docs = await cursor.to_list(length=limit)

        hosts = {doc.get("domain_host") for doc in docs if doc.get("domain_host") and doc.get("domain_host") != "-"}
        result = {
            "status": "ok",
            "query": query,
            "count": count,
            "results": docs,
            "elapsed_ms": int((time.perf_counter() - start) * 1000),
            "hosts_count": len(hosts),
            "files_loaded": sync_summary.get("files_loaded", len(datasets)),
            "aggregated_count": len(datasets),
            "datasets": [item.get("name", "") for item in datasets],
            "page": page,
            "per_page": limit,
            "total_pages": total_pages,
            "message": (
                f"{count} redacted credential exposure result(s) found."
                if count
                else f"No matching exposure records were found for {query}."
            ),
        }
        log.info(
            "Credential checker complete: %s match(es) across %s file(s) for %s",
            result.get("count", 0),
            result.get("files_loaded", 0),
            query,
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        log.error(f"Credential checker failed: {exc}", exc_info=True)
        return {"status": "error", "message": f"Scan failed: {str(exc)}"}


