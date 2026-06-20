@app.get("/feed")
async def list_feed(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    source_type: str = Query("all"),
    q: str = Query(""),
    topic: str = Query(""),
    start_date: str = Query(""),
    end_date: str = Query(""),
    network: str = Query(""),
    include_raw: bool = Query(False),
):
    canonical = _canonical_source_type(source_type)
    fast_cache_key = (
        "feed",
        canonical,
        limit,
        offset,
        q.strip().lower(),
        topic.strip().lower(),
        start_date.strip(),
        end_date.strip(),
        network.strip().lower(),
        bool(include_raw),
    )
    if not include_raw:
        cached_page = _cache_get_feed_page(fast_cache_key)
        if cached_page is not None:
            return cached_page

    if canonical == "news":
        if not q and not include_raw and not topic and not start_date and not end_date and not network:
            total, items = await _fetch_news_page(limit, offset)
            return _cache_set_feed_page(fast_cache_key, {
                "total": total,
                "offset": offset,
                "limit": limit,
                "items": [_public_feed_item(item) for item in items],
            })
        if q:
            items = await _search_news_items(q, include_raw=include_raw)
        else:
            items = await _fetch_news_items(include_raw=include_raw)
    elif canonical in {"exploit", "leak", "defacement", "social", "api"}:
        if not q and not include_raw and not topic and not start_date and not end_date and not network:
            total, items = await _fetch_threat_page(canonical, limit, offset)
            return _cache_set_feed_page(fast_cache_key, {
                "total": total,
                "offset": offset,
                "limit": limit,
                "items": [_public_feed_item(item) for item in items],
            })
        if q:
            items = await _search_threat_items(q, canonical, include_raw=include_raw)
        else:
            items = await _fetch_threat_items(canonical, include_raw=include_raw)
    else:
        if not q and not include_raw and not topic and not start_date and not end_date and not network:
            total, items = await _fetch_combined_feed_page(limit, offset)
            return _cache_set_feed_page(fast_cache_key, {
                "total": total,
                "offset": offset,
                "limit": limit,
                "items": [_public_feed_item(item) for item in items],
            })
        if q:
            news_items, threat_items = await asyncio.gather(
                _search_news_items(q, include_raw=include_raw),
                _search_threat_items(q, include_raw=include_raw),
            )
        else:
            news_items, threat_items = await asyncio.gather(
                _fetch_news_items(include_raw=include_raw),
                _fetch_threat_items(include_raw=include_raw),
            )
        items = news_items + threat_items

    items = sorted(items, key=_feed_sort_key, reverse=True)
    if q:
        items = _filter_feed_items(items, q)
    items = _apply_feed_filters(items, topic=topic, start_date=start_date, end_date=end_date, network=network)
    return _cache_set_feed_page(fast_cache_key, {
        "total": len(items),
        "offset": offset,
        "limit": limit,
        "items": [_public_feed_item(item) for item in items[offset:offset + limit]],
    })


async def _find_feed_item_for_screenshot(aid: str) -> dict:
    if any(aid.startswith(f"{prefix}:") for prefix in _THREAT_PREFIXES):
        doc = await kv_col.find_one({"_id": aid})
        entity_doc = None
        if aid.startswith(("EXPLOIT_ITEMS:", "LEAK_ITEMS:", "DEFACEMENT_ITEMS:", "SOCIAL_ITEMS:", "API_ITEMS:")):
            entity_doc = await kv_col.find_one({"_id": aid.replace("_ITEMS:", "_ENTITIES:", 1)})
        parsed = _parse_kv_item(doc, include_raw=False, entity_doc=entity_doc) if doc else None
        if parsed:
            return parsed

    doc = await _find_news_doc(aid)
    if doc:
        return _build_article_item(doc, include_raw=False)

    raise HTTPException(status_code=404, detail="Feed item not found")


def _feed_screenshot_cache_path(aid: str, url: str) -> pathlib.Path:
    digest = hashlib.sha256(f"{aid}\n{url}".encode("utf-8", errors="ignore")).hexdigest()
    return _FEED_SCREENSHOT_DIR / f"{digest}.jpg"


def _chromium_host_resolver_rule(url: str) -> str:
    host = urlparse(url or "").hostname
    if not host:
        return ""
    try:
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        return ""
    for family, _, _, _, sockaddr in addresses:
        if family == socket.AF_INET and sockaddr and sockaddr[0]:
            return f"MAP {host} {sockaddr[0]},EXCLUDE localhost"
    return ""


def _capture_feed_screenshot(url: str, output_path: pathlib.Path) -> None:
    from playwright.sync_api import sync_playwright

    output_path.parent.mkdir(parents=True, exist_ok=True)
    launch_args = ["--no-sandbox", "--disable-dev-shm-usage"]
    resolver_rule = _chromium_host_resolver_rule(url)
    if resolver_rule:
        launch_args.append(f"--host-resolver-rules={resolver_rule}")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=launch_args)
        context = browser.new_context(
            viewport={"width": 1280, "height": 720},
            device_scale_factor=1,
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
            ),
        )
        page = context.new_page()
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=20000)
            page.wait_for_timeout(1200)
            page.screenshot(path=str(output_path), type="jpeg", quality=72, full_page=False)
        finally:
            context.close()
            browser.close()


def _response_from_embedded_image(value: Any) -> Response | None:
    text = str(value or "").strip()
    if not text:
        return None
    media_type = "image/jpeg"
    if text.startswith("data:image/"):
        header, _, payload = text.partition(",")
        if not payload:
            return None
        media_type = (header.split(";", 1)[0].replace("data:", "") or media_type).strip()
        text = payload.strip()
    if len(text) < 2000 or not re.fullmatch(r"[A-Za-z0-9+/=\s]+", text):
        return None
    try:
        image_bytes = base64.b64decode(re.sub(r"\s+", "", text), validate=False)
    except Exception:
        return None
    if len(image_bytes) < 1024:
        return None
    if image_bytes.startswith(b"\x89PNG"):
        media_type = "image/png"
    elif image_bytes.startswith(b"GIF"):
        media_type = "image/gif"
    elif image_bytes.startswith(b"\xff\xd8"):
        media_type = "image/jpeg"
    return Response(content=image_bytes, media_type=media_type)


@app.get("/feed-screenshot")
async def get_feed_screenshot(aid: str = Query(...)):
    item = await _find_feed_item_for_screenshot(aid)
    embedded_refs = [item.get("screenshot")]
    if isinstance(item.get("screenshot_links"), list):
        embedded_refs.extend(item.get("screenshot_links") or [])
    for ref in embedded_refs:
        response = _response_from_embedded_image(ref)
        if response is not None:
            return response

    url = _unwrap_redirect_url(first_non_empty := _extract_field(item, "url", "website", "seed_url")) or first_non_empty
    parsed = urlparse(url or "")
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=404, detail="No screenshot-capable URL for this item")

    cache_path = _feed_screenshot_cache_path(aid, url)
    if not cache_path.exists() or cache_path.stat().st_size < 1024:
        async with _FEED_SCREENSHOT_SEMAPHORE:
            if not cache_path.exists() or cache_path.stat().st_size < 1024:
                loop = asyncio.get_running_loop()
                try:
                    await loop.run_in_executor(None, _capture_feed_screenshot, url, cache_path)
                except Exception as exc:
                    log.warning("Feed screenshot capture failed aid=%s url=%s error=%s", aid, url, exc)
                    raise HTTPException(status_code=404, detail="Screenshot capture failed") from exc

    return FileResponse(cache_path, media_type="image/jpeg")


@app.get("/feed/{aid:path}")
async def get_feed_item(aid: str):
    if any(aid.startswith(f"{prefix}:") for prefix in _THREAT_PREFIXES):
        doc = await kv_col.find_one({"_id": aid})
        entity_doc = None
        if aid.startswith(("EXPLOIT_ITEMS:", "LEAK_ITEMS:", "DEFACEMENT_ITEMS:", "SOCIAL_ITEMS:", "API_ITEMS:")):
            entity_doc = await kv_col.find_one({"_id": aid.replace("_ITEMS:", "_ENTITIES:", 1)})
        parsed = _parse_kv_item(doc, include_raw=True, entity_doc=entity_doc) if doc else None
        if not parsed:
            raise HTTPException(status_code=404, detail="Threat item not found")
        return _public_feed_item(parsed)

    doc = await _find_news_doc(aid)
    if not doc:
        raise HTTPException(status_code=404, detail="Feed item not found")
    return _public_feed_item(_build_article_item(doc, include_raw=True))


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
    """Return live MongoDB-backed counts for every dashboard count card."""
    cached = _cache_get_stats()
    if cached is not None:
        return cached

    threat_prefixes = [(pfx, cat) for pfx, cat in _THREAT_PREFIXES.items() if cat is not None]
    count_tasks = [articles_col.count_documents({})] + [
        kv_col.count_documents({"_id": {"$regex": f"^{pfx}:"}})
        for pfx, _cat in threat_prefixes
    ] + [
        kv_col.count_documents({"_id": {"$regex": pattern}})
        for pattern, _cat in _LEGACY_STATS_PATTERNS
    ] + [
        credential_exposures_col.count_documents({}),
        credential_datasets_col.count_documents({}),
        confidential_analysis_col.count_documents({}),
    ]
    counts = await asyncio.gather(*count_tasks)

    result = {
        "news": counts[0],
    }
    for (pfx, cat), count in zip(threat_prefixes, counts[1:]):
        result[cat] = result.get(cat, 0) + count
    legacy_counts = counts[1 + len(threat_prefixes):]
    legacy_result: dict[str, int] = {}
    for (_pattern, cat), count in zip(_LEGACY_STATS_PATTERNS, legacy_counts):
        legacy_result[cat] = legacy_result.get(cat, 0) + count
    for cat, count in legacy_result.items():
        result[cat] = max(result.get(cat, 0), count)
    extra_offset = 1 + len(threat_prefixes) + len(_LEGACY_STATS_PATTERNS)
    result["credentials"] = counts[extra_offset]
    result["credential_datasets"] = counts[extra_offset + 1]
    result["confidential"] = counts[extra_offset + 2]

    try:
        map_payload = await get_map_stats()
        map_summary = map_payload.get("summary", {}) if isinstance(map_payload, dict) else {}
    except Exception:
        map_summary = {}
    result["affected_countries"] = int(map_summary.get("affected_countries") or 0)
    result["leak_coverage"] = int(map_summary.get("leak_items_with_country") or 0)
    result["defacement_coverage"] = int(map_summary.get("defacement_items_with_country") or 0)

    category_total = sum(result.values())
    display_total = sum(
        int(result.get(key, 0) or 0)
        for key in ("news", "leak", "defacement", "exploit", "social", "api")
    ) or category_total
    try:
        stored_counts = await asyncio.gather(
            *[db[collection_name].count_documents({}) for collection_name in _STORED_RECORD_COLLECTIONS]
        )
        stored_total = sum(int(count or 0) for count in stored_counts)
    except Exception:
        stored_total = display_total
    result["display_total"] = display_total
    result["stored_total"] = stored_total
    result["records_to_100k"] = max(100000 - stored_total, 0)
    # Dashboard Total must match the primary stream cards visible in the UI.
    # Raw Mongo volume is still returned as stored_total for diagnostics.
    result["total"] = display_total
    return _cache_set_stats({"counts": result, **result})


# ── PakDB Phone Lookup ──────────────────────────────────────────────────────
pakdb_col = db["pakdb_lookups"]


def _normalize_pakdb_number(number: str) -> str:
    cleaned = re.sub(r"\D+", "", number or "")
    if cleaned.startswith("0092"):
        cleaned = "92" + cleaned[4:]
    elif cleaned.startswith("0"):
        cleaned = "92" + cleaned[1:]
    elif cleaned.startswith("3"):
        cleaned = "92" + cleaned
    return cleaned


def _build_manual_lookup_url(number: str, normalized_number: str) -> str:
    lookup_url = (cfg.lookup_site_url or os.environ.get("LOOKUP_SITE_URL", "") or "https://pakistandatabase.com/index.php").strip()
    value = normalized_number or number
    if "{number}" in lookup_url:
        return lookup_url.replace("{number}", quote(value))
    parsed = urlparse(lookup_url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query.setdefault("number", [value])
    rebuilt_query = urlencode(query, doseq=True)
    return parsed._replace(query=rebuilt_query).geturl()


def _normalize_imported_pakdb_record(record: dict[str, Any]) -> dict[str, str]:
    aliases = {
        "mobile": ("mobile", "phone", "number", "sim", "cell", "msisdn"),
        "name": ("name", "full name", "fullname", "customer", "owner"),
        "cnic": ("cnic", "nic", "id", "identity", "national id"),
        "address": ("address", "addr", "location"),
    }
    lowered = {str(key).strip().lower(): str(value).strip() for key, value in record.items() if str(value).strip()}
    clean: dict[str, str] = {}
    for target, names in aliases.items():
        for key in names:
            if key in lowered:
                clean[target] = lowered[key]
                break
    for key, value in lowered.items():
        if key not in clean and key not in {"", "-"}:
            clean.setdefault(key.replace(" ", "_"), value)
    if "mobile" not in clean:
        blob = " ".join(lowered.values())
        match = re.search(r"(?:\+?92|0)?3\d{9}", blob)
        if match:
            clean["mobile"] = _normalize_pakdb_number(match.group(0))
    if "cnic" not in clean:
        blob = " ".join(lowered.values())
        match = re.search(r"\b\d{5}-?\d{7}-?\d\b", blob)
        if match:
            clean["cnic"] = match.group(0)
    return clean


def _parse_manual_pakdb_import(raw_text: str) -> list[dict[str, str]]:
    text = (raw_text or "").strip()
    if not text:
        return []

    try:
        payload = json.loads(text)
    except ValueError:
        payload = None
    if payload is not None:
        return [
            record for record in (
                _normalize_imported_pakdb_record(item)
                for item in _extract_pakdb_records(payload)
            )
            if record
        ]

    records: list[dict[str, str]] = []
    if "<" in text and ">" in text:
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(text, "lxml")
            for table in soup.find_all("table"):
                headers = [cell.get_text(" ", strip=True) for cell in table.find_all("th")]
                for row in table.find_all("tr"):
                    cells = [cell.get_text(" ", strip=True) for cell in row.find_all("td")]
                    if not cells:
                        continue
                    if headers and len(headers) >= len(cells):
                        mapped = dict(zip(headers, cells))
                    elif len(cells) >= 4:
                        mapped = {"mobile": cells[0], "name": cells[1], "cnic": cells[2], "address": cells[3]}
                    else:
                        mapped = {f"field_{idx + 1}": value for idx, value in enumerate(cells)}
                    record = _normalize_imported_pakdb_record(mapped)
                    if record:
                        records.append(record)
            if records:
                return records
        except Exception as exc:
            log.warning("Manual PakDB HTML import parse failed: %s", exc)

    lines = [line.strip(" \t|") for line in text.splitlines() if line.strip(" \t|")]
    for line in lines:
        mobile = re.search(r"(?:\+?92|0)?3\d{9}", line)
        cnic = re.search(r"\b\d{5}-?\d{7}-?\d\b", line)
        if not mobile and not cnic:
            continue
        record = _normalize_imported_pakdb_record({
            "mobile": mobile.group(0) if mobile else "",
            "cnic": cnic.group(0) if cnic else "",
            "address": line,
        })
        if record:
            records.append(record)
    return records


def _pakdb_error_response(message: str, number: str = "", normalized_number: str = "", provider: str = "unconfigured") -> dict[str, Any]:
    return {
        "status": "error",
        "message": message,
        "query": normalized_number,
        "input": number,
        "provider": provider,
        "count": 0,
        "results": [],
    }


def _extract_pakdb_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict):
        records = None
        for key in ("results", "items", "records", "data", "matches"):
            value = payload.get(key)
            if isinstance(value, list):
                records = value
                break
        if records is None:
            records = [payload] if payload else []
    else:
        records = []

    allowed_records: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        clean: dict[str, Any] = {}
        for key, value in record.items():
            if value is None or isinstance(value, (dict, list)):
                continue
            clean[str(key)] = str(value)
        if clean:
            allowed_records.append(clean)
    return allowed_records


