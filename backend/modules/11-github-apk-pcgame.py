async def _call_authorized_pakdb_provider(number: str, normalized_number: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    import requests

    provider_url = (cfg.pakdb_provider_api_url or os.environ.get("PAKDB_PROVIDER_API_URL", "")).strip()
    provider_key = (cfg.pakdb_provider_api_key or os.environ.get("PAKDB_PROVIDER_API_KEY", "")).strip()
    provider_name = urlparse(provider_url).netloc or "authorized-provider"

    log.info(
        "PakDB provider selected=%s configured_url=%s configured_key=%s",
        provider_name,
        bool(provider_url),
        bool(provider_key),
    )

    if not provider_url:
        raise ValueError("PakDB lookup source is not configured. Please connect an authorized data source API.")
    if not provider_key:
        raise PermissionError("PakDB data source API key is missing. Please set PAKDB_PROVIDER_API_KEY in .env.")

    def request_provider() -> tuple[int, Any]:
        response = requests.post(
            provider_url,
            json={"number": normalized_number, "mobile": normalized_number, "input": number},
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {provider_key}",
                "X-API-Key": provider_key,
                "User-Agent": "DarkPulse-PakDB-Provider",
            },
            timeout=20,
        )
        try:
            payload = response.json()
        except ValueError:
            payload = {"message": response.text.strip()}
        return response.status_code, payload

    status_code, payload = await asyncio.to_thread(request_provider)
    log.info("PakDB provider response status=%s provider=%s", status_code, provider_name)

    if status_code in (401, 403):
        raise PermissionError("PakDB data source rejected the request. Please check data source API settings.")
    if status_code in (408, 429, 500, 502, 503, 504):
        raise ConnectionError("PakDB lookup failed. Please check data source API settings.")
    if status_code >= 400:
        raise RuntimeError("PakDB lookup failed. Please check data source API settings.")

    records = _extract_pakdb_records(payload)
    metadata = {
        "provider": provider_name,
        "provider_status": status_code,
        "raw_count": len(records),
    }
    return records, metadata


@app.post("/pakdb/launch-tor")
async def pakdb_launch_tor(request: Request):
    """Open the configured lookup website in the local Tor Browser for manual verification."""

    body = await request.json()
    number = str(body.get("number", "")).strip()
    if not number:
        raise HTTPException(status_code=400, detail="Phone number is required before opening the lookup site.")

    normalized_number = _normalize_pakdb_number(number)
    if not re.fullmatch(r"923\d{9}", normalized_number):
        raise HTTPException(status_code=400, detail="Invalid phone number. Use 923xxxxxxxxx, +923xxxxxxxxx, or 03xxxxxxxxx.")

    tor_browser_path = (cfg.tor_browser_path or os.environ.get("TOR_BROWSER_PATH", "")).strip()
    if not tor_browser_path:
        raise HTTPException(status_code=400, detail="TOR_BROWSER_PATH is not configured in .env.")

    executable = pathlib.Path(tor_browser_path).expanduser()
    if not executable.exists():
        raise HTTPException(status_code=400, detail=f"Tor Browser path does not exist: {executable}")
    if not executable.is_file():
        raise HTTPException(status_code=400, detail=f"Tor Browser path is not a file: {executable}")
    if not os.access(str(executable), os.X_OK):
        raise HTTPException(status_code=400, detail=f"Tor Browser path is not executable: {executable}")

    lookup_url = _build_manual_lookup_url(number, normalized_number)
    try:
        await asyncio.create_subprocess_exec(
            str(executable),
            lookup_url,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except Exception as exc:
        log.error("Could not launch Tor Browser for PakDB lookup: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Could not launch Tor Browser: {exc}")

    return {
        "status": "ok",
        "lookup_url": lookup_url,
        "query": normalized_number,
        "message": "Tor Browser opened. Complete Cloudflare/CAPTCHA/login/search manually, then paste the result into DarkPulse.",
    }


@app.post("/pakdb/import")
async def pakdb_import_manual_result(request: Request):
    """Import user-pasted manual lookup output without bypassing external controls."""

    body = await request.json()
    number = str(body.get("number", "")).strip()
    raw_result = str(body.get("raw_result", "")).strip()
    if not raw_result:
        raise HTTPException(status_code=400, detail="Paste result text, HTML, or JSON before importing.")

    normalized_number = _normalize_pakdb_number(number)
    items = _parse_manual_pakdb_import(raw_result)
    if not items:
        raise HTTPException(status_code=400, detail="Could not parse any records from the pasted result.")

    doc = {
        "query": normalized_number,
        "input": number,
        "provider": "manual-tor-import",
        "status": "ok",
        "message": "",
        "results": items,
        "count": len(items),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    await pakdb_col.insert_one(doc)
    return {
        "status": "ok",
        "message": f"Imported {len(items)} pasted result(s).",
        "query": normalized_number,
        "provider": "manual-tor-import",
        "count": len(items),
        "results": items,
        "timestamp": doc["timestamp"],
    }


@app.post("/pakdb/lookup")
async def pakdb_lookup(request: Request):
    """Run a PakDB lookup through an authorized data source API only."""

    body = await request.json()
    number = str(body.get("number", "")).strip()
    if not number:
        return _pakdb_error_response("Phone number is required")

    normalized_number = _normalize_pakdb_number(number)
    log.info("PakDB lookup received input=%s normalized=%s", number, normalized_number)
    if not re.fullmatch(r"923\d{9}", normalized_number):
        log.warning("PakDB lookup invalid phone number: input=%s normalized=%s", number, normalized_number)
        return _pakdb_error_response("Invalid phone number. Use 923xxxxxxxxx, +923xxxxxxxxx, or 03xxxxxxxxx.", number, normalized_number)

    provider = "unconfigured"
    items: list[dict[str, Any]] = []
    message = ""
    status = "ok"

    try:
        items, metadata = await asyncio.wait_for(
            _call_authorized_pakdb_provider(number, normalized_number),
            timeout=25,
        )
        provider = metadata.get("provider", "authorized-provider")
        message = "No matching record found from the configured authorized data source." if not items else ""
    except asyncio.TimeoutError:
        status = "error"
        message = "PakDB lookup failed. Please check data source API settings."
        log.error("PakDB provider timeout for normalized=%s provider=%s", normalized_number, provider)
    except (ValueError, PermissionError, ConnectionError, RuntimeError) as exc:
        status = "error"
        message = str(exc)
        log.error("PakDB lookup error reason=%s normalized=%s", message, normalized_number)
    except Exception as exc:
        status = "error"
        message = "PakDB lookup failed. Please check data source API settings."
        log.error("PakDB lookup failed unexpectedly for %s: %s", normalized_number, exc, exc_info=True)

    doc = {
        "query": normalized_number,
        "input": number,
        "provider": provider,
        "status": status,
        "message": message,
        "results": items,
        "count": len(items),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    await pakdb_col.insert_one(doc)

    log.info("PakDB lookup complete status=%s provider=%s count=%s normalized=%s", status, provider, len(items), normalized_number)
    return {
        "status": status,
        "message": message,
        "query": normalized_number,
        "provider": provider,
        "count": len(items),
        "results": items,
        "timestamp": doc["timestamp"],
    }


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

        raw = getattr(result, "raw_data", {}) or {}

        # Extract summary from DarkpulseSummary in raw data
        raw_summary = raw.get("DarkpulseSummary") or {}
        summary = {
            "grade": raw_summary.get("grade") or "F",
            "risk_score": raw_summary.get("risk_score") or 85,
            "total_vulns": raw_summary.get("counts", {}).get("CRITICAL", 0) + raw_summary.get("counts", {}).get("HIGH", 0) + raw_summary.get("counts", {}).get("MEDIUM", 0),
            "total_secrets": raw_summary.get("counts", {}).get("SECRETS", 0),
            "critical": raw_summary.get("counts", {}).get("CRITICAL", 0),
            "high": raw_summary.get("counts", {}).get("HIGH", 0),
            "medium": raw_summary.get("counts", {}).get("MEDIUM", 0),
            "low": raw_summary.get("counts", {}).get("LOW", 0),
            "scanned_by": "Orion Intelligence",
            "host": "github.com",
            "port": "443",
            "tls_status": "Ssl Enabled"
        }

        # Add actual findings from Trivy JSON Results
        vulnerabilities = []
        secrets = []
        misconfigs = []

        for r in (raw.get("Results") or []):
            target = r.get("Target", "Source")
            
            # Helper to extract code snippet
            def get_snippet(finding):
                code = finding.get("Code", {})
                lines = code.get("Lines", [])
                if lines:
                    return "\n".join([f"{l.get('Number', '')}: {l.get('Content', '')}" for l in lines])
                return finding.get("Match") or ""

            # 1. Vulnerabilities
            for v in (r.get("Vulnerabilities") or []):
                vulnerabilities.append({
                    "id": v.get("VulnerabilityID", "VULN"),
                    "title": v.get("Title") or v.get("PkgName") or "Security Vulnerability",
                    "description": v.get("Description") or "No detailed description available.",
                    "severity": v.get("Severity", "CRITICAL"),
                    "confidence": "Medium Confidence",
                    "pkg": v.get("PkgName", ""),
                    "version": v.get("InstalledVersion", ""),
                    "snippet": get_snippet(v),
                    "target": target
                })

            # 2. Secrets
            for s in (r.get("Secrets") or []):
                secrets.append({
                    "id": s.get("RuleID", "SECRET"),
                    "title": s.get("Title") or "Potential Secret Leak",
                    "description": s.get("Message") or f"Match found in {target}",
                    "severity": s.get("Severity", "CRITICAL"),
                    "confidence": "High Confidence",
                    "rule": s.get("RuleID", ""),
                    "snippet": get_snippet(s),
                    "target": target
                })

            # 3. Misconfigurations
            for m in (r.get("Misconfigurations") or []):
                misconfigs.append({
                    "id": m.get("ID", "MISCONFIG"),
                    "title": m.get("Title") or "Security Misconfiguration",
                    "description": m.get("Message") or m.get("Description") or "Policy violation detected.",
                    "severity": m.get("Severity", "HIGH"),
                    "confidence": "High Confidence",
                    "snippet": get_snippet(m),
                    "target": target
                })

        findings = vulnerabilities + secrets + misconfigs

        doc = {
            "query": repo_url,
            "results": {
                "vulnerabilities": vulnerabilities,
                "secrets": secrets,
                "misconfigs": misconfigs
            },
            "summary": summary,
            "count": len(findings),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await github_col.insert_one(doc)

        log.info(f"GitHub scan complete: {len(findings)} findings for {repo_url}")
        return {
            "status": "ok", 
            "query": repo_url, 
            "count": len(findings), 
            "vulnerabilities": vulnerabilities, 
            "secrets": secrets, 
            "misconfigs": misconfigs,
            "summary": summary
        }

    except Exception as e:
        log.error(f"GitHub scan failed: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

apk_col = db["apk_scans"]

APK_SUSPICIOUS_KEYWORDS = (
    "mod apk",
    "cracked apk",
    "hacked apk",
    "unlimited money",
    "unlimited gems",
    "premium unlocked",
    "free download apk",
    "apk mod",
    "apk hack",
    "modified version",
    "hack apk",
)

APK_SUSPICIOUS_DOMAINS = {
    "apkpure.com",
    "happymod.com",
    "apkcombo.com",
    "apkdone.com",
    "modyolo.com",
    "liteapks.com",
    "rexdl.com",
    "apkmody.com",
    "moddroid.com",
    "apksoul.net",
    "apkmodhere.com",
    "getmodsapk.com",
    "9mod.com",
    "an1.com",
}


def _extract_playstore_package_id(playstore_url: str) -> str:
    from urllib.parse import parse_qs

    text = str(playstore_url or "").strip()
    parsed = urlparse(text if "://" in text else f"https://{text}")
    package_id = parse_qs(parsed.query).get("id", [""])[0].strip()
    if package_id:
        return package_id
    if re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", text):
        return text
    return ""


def _humanize_android_package(package_id: str) -> str:
    tail = (package_id or "").split(".")[-1].strip()
    known = {
        "clashofclans": "Clash of Clans",
        "clashroyale": "Clash Royale",
        "subwaysurf": "Subway Surf",
        "subwaysurfers": "Subway Surfers",
        "candycrushsaga": "Candy Crush Saga",
        "freefiremax": "Free Fire Max",
    }
    key = re.sub(r"[^a-z0-9]+", "", tail.lower())
    if key in known:
        return known[key]
    tail = re.sub(r"([a-z])([A-Z])", r"\1 \2", tail).replace("_", " ").replace("-", " ")
    return " ".join(part.capitalize() for part in re.findall(r"[A-Za-z0-9]+", tail)) or package_id


