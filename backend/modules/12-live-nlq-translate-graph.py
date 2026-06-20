def _resolve_playstore_title(playstore_url: str, package_id: str) -> tuple[str, str]:
    import requests
    from bs4 import BeautifulSoup

    normalized_url = playstore_url if playstore_url.startswith(("http://", "https://")) else (
        f"https://play.google.com/store/apps/details?id={package_id}"
    )
    fallback = _humanize_android_package(package_id)
    try:
        response = requests.get(
            normalized_url,
            timeout=12,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123 Safari/537.36"},
        )
        response.raise_for_status()
        soup = BeautifulSoup(response.text or "", "lxml")
        candidates = []
        for selector, attr in [
            ('meta[property="og:title"]', "content"),
            ('meta[name="twitter:title"]', "content"),
            ("title", ""),
            ("h1", ""),
        ]:
            node = soup.select_one(selector)
            if not node:
                continue
            value = node.get(attr, "") if attr else node.get_text(" ", strip=True)
            value = re.sub(r"\s*-\s*Apps on Google Play\s*$", "", str(value or ""), flags=re.I).strip()
            if value and "google play" not in value.lower():
                candidates.append(value)
        if candidates:
            return candidates[0], normalized_url
    except Exception as exc:
        log.warning("Playstore title resolution failed for %s: %s", normalized_url, exc)
    return fallback, normalized_url


def _build_apk_search_queries(app_name: str, package_id: str) -> list[str]:
    variants = [
        f"{app_name} mod apk",
        f"{app_name} cracked apk",
        f"{app_name} unlimited gems apk",
        f"{package_id} mod apk",
        f"{package_id} cracked",
        f"{app_name} hack apk",
        f"{app_name} apk mod download",
    ]
    seen: set[str] = set()
    queries: list[str] = []
    for query in variants:
        clean_query = re.sub(r"\s+", " ", query).strip()
        if clean_query and clean_query.lower() not in seen:
            seen.add(clean_query.lower())
            queries.append(clean_query)
    return queries


def _apk_slug(value: str) -> str:
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", str(value or "").lower())).strip("-")


def _source_domain(url: str) -> str:
    return urlparse(url or "").netloc.lower().replace("www.", "")


def _matched_apk_keyword(*values: str) -> str:
    haystack = " ".join(str(value or "") for value in values).lower()
    for keyword in APK_SUSPICIOUS_KEYWORDS:
        if keyword in haystack:
            return keyword
    if "mod" in haystack and "apk" in haystack:
        return "mod apk"
    if "hack" in haystack and "apk" in haystack:
        return "hack apk"
    return ""


def _risk_for_apk_result(domain: str, keyword: str, title: str, snippet: str) -> str:
    haystack = f"{title} {snippet}".lower()
    if any(term in haystack for term in ("unlimited gems", "unlimited money", "premium unlocked", "hack apk", "hacked apk", "cracked apk")):
        return "high"
    if domain in APK_SUSPICIOUS_DOMAINS or keyword in {"mod apk", "apk mod", "modified version"}:
        return "medium"
    return "low"


def _dedupe_apk_results(results: list[dict[str, Any]], limit: int = 25) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in results:
        url = str(item.get("url") or "").strip()
        key = re.sub(r"[?#].*$", "", url).rstrip("/").lower() or str(item.get("title") or "").lower()
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(item)
        if len(deduped) >= limit:
            break
    return deduped


def _decode_bing_url(raw_url: str) -> str:
    from urllib.parse import parse_qs

    parsed = urlparse(raw_url or "")
    if "bing.com" not in parsed.netloc:
        return raw_url
    encoded = parse_qs(parsed.query).get("u", [""])[0]
    if encoded.startswith("a1"):
        try:
            payload = encoded[2:]
            padding = "=" * (-len(payload) % 4)
            return base64.urlsafe_b64decode((payload + padding).encode()).decode("utf-8", "ignore")
        except Exception:
            return raw_url
    return raw_url


async def _search_apk_local_intelligence(app_name: str, package_id: str, queries: list[str]) -> list[dict[str, Any]]:
    regexes = [
        re.compile(re.escape(app_name), re.I),
        re.compile(re.escape(package_id), re.I),
        re.compile(r"mod\s+apk|apk\s+mod|cracked\s+apk|hack(?:ed)?\s+apk|unlimited\s+gems|premium\s+unlocked", re.I),
    ]
    mongo_query = {
        "$and": [
            {"$or": [{"value": regexes[0]}, {"value": regexes[1]}, {"_id": regexes[1]}]},
            {"value": regexes[2]},
        ]
    }
    docs = await kv_col.find(mongo_query, {"_id": 1, "value": 1}).limit(20).to_list(length=20)
    results: list[dict[str, Any]] = []
    for doc in docs:
        text = re.sub(r"\s+", " ", str(doc.get("value") or "")).strip()
        url_match = re.search(r"https?://[^\s\"'<>]+", text)
        url = url_match.group(0) if url_match else ""
        keyword = _matched_apk_keyword(text, str(doc.get("_id") or ""))
        if not keyword:
            continue
        domain = _source_domain(url) if url else "local intelligence"
        title = text[:90] or str(doc.get("_id"))
        results.append({
            "title": title,
            "url": url,
            "sourceDomain": domain,
            "matchedKeyword": keyword,
            "riskLevel": _risk_for_apk_result(domain, keyword, title, text),
            "snippet": text[:260] or f"Local intelligence record {doc.get('_id')}",
            "package_id": package_id,
            "app_name": app_name,
            "source": "local-intel",
            "network": "mongodb",
        })
    return results


def _search_apk_web(app_name: str, package_id: str, queries: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    import requests
    from bs4 import BeautifulSoup

    errors: list[str] = []
    results: list[dict[str, Any]] = []
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
    })

    for query in queries[:5]:
        try:
            response = session.get("https://www.bing.com/search", params={"q": query}, timeout=12)
            response.raise_for_status()
            soup = BeautifulSoup(response.text or "", "lxml")
            for node in soup.select("li.b_algo")[:8]:
                anchor = node.select_one("h2 a")
                if not anchor:
                    continue
                title = anchor.get_text(" ", strip=True)
                url = _decode_bing_url(anchor.get("href") or "")
                snippet_node = node.select_one(".b_caption p")
                snippet = snippet_node.get_text(" ", strip=True) if snippet_node else ""
                domain = _source_domain(url)
                keyword = _matched_apk_keyword(title, url, snippet, query)
                if not keyword:
                    continue
                if domain not in APK_SUSPICIOUS_DOMAINS and "apk" not in f"{title} {url} {snippet}".lower():
                    continue
                results.append({
                    "title": title,
                    "url": url,
                    "sourceDomain": domain,
                    "matchedKeyword": keyword,
                    "riskLevel": _risk_for_apk_result(domain, keyword, title, snippet),
                    "snippet": snippet or f"Search result matched query: {query}",
                    "package_id": package_id,
                    "app_name": app_name,
                    "source": domain or "web-search",
                    "network": "clearnet",
                })
        except Exception as exc:
            errors.append(f"Bing search failed for '{query}': {exc}")
    return results, errors


def _known_apk_mirror_candidates(app_name: str, package_id: str) -> list[dict[str, Any]]:
    slug = _apk_slug(app_name)
    package_slug = _apk_slug(package_id)
    candidates = [
        ("HappyMod", f"https://www.happymod.com/{slug}-mod/{package_id}/", "mod apk"),
        ("APKCombo", f"https://apkcombo.com/{slug}/{package_id}/", "free download apk"),
        ("APKPure", f"https://apkpure.com/{slug}/{package_id}", "free download apk"),
        ("MODYOLO", f"https://modyolo.com/{slug}.html", "mod apk"),
        ("LiteAPKs", f"https://liteapks.com/{slug}.html", "apk mod"),
        ("APKDone", f"https://apkdone.com/{slug}-mod/", "mod apk"),
        ("RevDL/RexDL", f"https://rexdl.com/android/{slug}-apk.html/", "apk mod"),
    ]
    results = []
    for source, url, keyword in candidates:
        domain = _source_domain(url)
        title = f"{app_name} {keyword}"
        results.append({
            "title": title,
            "url": url,
            "sourceDomain": domain,
            "matchedKeyword": keyword,
            "riskLevel": _risk_for_apk_result(domain, keyword, title, source),
            "snippet": (
                f"Known third-party APK mirror pattern for package {package_id}. "
                "Open the page to verify availability and treat downloads as suspicious."
            ),
            "package_id": package_id,
            "app_name": app_name,
            "source": source,
            "network": "clearnet",
        })
    if package_slug and package_slug != slug:
        results.append({
            "title": f"{package_id} mod apk",
            "url": f"https://apkcombo.com/{package_slug}/{package_id}/",
            "sourceDomain": "apkcombo.com",
            "matchedKeyword": "mod apk",
            "riskLevel": "medium",
            "snippet": f"Package-ID based APK mirror candidate for {package_id}.",
            "package_id": package_id,
            "app_name": app_name,
            "source": "APKCombo",
            "network": "clearnet",
        })
    return results


async def _collect_apk_reference_results(playstore_url: str) -> dict[str, Any]:
    package_id = _extract_playstore_package_id(playstore_url)
    if not package_id:
        raise HTTPException(status_code=400, detail="Play Store URL must include an id= Android package parameter")

    app_name, normalized_url = await asyncio.to_thread(_resolve_playstore_title, playstore_url, package_id)
    queries = _build_apk_search_queries(app_name, package_id)
    log.info("APK reference scan parsed package=%s app=%s queries=%s", package_id, app_name, queries)

    local_results = await _search_apk_local_intelligence(app_name, package_id, queries)
    web_results, search_errors = await asyncio.to_thread(_search_apk_web, app_name, package_id, queries)
    candidate_results = _known_apk_mirror_candidates(app_name, package_id)
    results = _dedupe_apk_results(local_results + web_results + candidate_results)

    return {
        "package_id": package_id,
        "app_name": app_name,
        "playstore_url": normalized_url,
        "queries": queries,
        "results": results,
        "search_errors": search_errors,
        "sources": {
            "local_intelligence": len(local_results),
            "web_search": len(web_results),
            "known_mirror_candidates": len(candidate_results),
        },
    }


async def _collect_apk_scan_results(playstore_url: str, proxy_url: Optional[str] = None, attempts: int = 2):
    import asyncio

    from api_collector.scripts._apk_mod import _apk_mod
    from playwright.async_api import async_playwright

    last_error = ""
    best_results = []

    for attempt in range(1, max(1, attempts) + 1):
        try:
            scraper = _apk_mod()
            async with async_playwright() as p:
                browser_kwargs = {
                    "headless": True,
                    "args": ["--no-sandbox", "--disable-dev-shm-usage"],
                }
                if proxy_url:
                    browser_kwargs["proxy"] = {"server": proxy_url}

                browser = await p.chromium.launch(**browser_kwargs)
                context = await browser.new_context(ignore_https_errors=True)
                try:
                    result = await asyncio.wait_for(
                        scraper.parse_leak_data(query={"playstore": playstore_url}, context=context),
                        timeout=25,
                    )
                finally:
                    await browser.close()

            cards = list(getattr(result, "cards_data", []) or []) if result else []
            results = []
            for card in cards:
                results.append({
                    "app_name": getattr(card, "m_app_name", ""),
                    "package_id": getattr(card, "m_package_id", ""),
                    "url": getattr(card, "m_app_url", ""),
                    "network": getattr(card, "m_network", "clearnet"),
                    "source": getattr(card, "m_source", ""),
                    "publisher": getattr(card, "m_publisher", ""),
                    "description": getattr(card, "m_description", ""),
                    "version": getattr(card, "m_version", ""),
                    "content_type": getattr(card, "m_content_type", ["apk"])[0] if getattr(card, "m_content_type", []) else "apk",
                    "download_link": getattr(card, "m_download_link", [""])[0] if getattr(card, "m_download_link", []) else "",
                    "apk_size": getattr(card, "m_apk_size", "not available"),
                    "latest_date": getattr(card, "m_latest_date", ""),
                    "mod_features": getattr(card, "m_mod_features", "")
                })

            if results:
                if attempt > 1:
                    log.info(f"APK scan recovered on retry {attempt} for {playstore_url} with {len(results)} item(s)")
                return results

            best_results = results
            log.warning(f"APK scan attempt {attempt} returned 0 items for {playstore_url}")
        except Exception as exc:
            last_error = str(exc)
            log.warning(f"APK scan attempt {attempt} failed for {playstore_url}: {exc}")

    if last_error:
        raise RuntimeError(last_error)
    return best_results


@app.post("/apk/scan")
async def apk_scan(request: Request):
    """Search APK mirror sites for a Play Store app."""
    from datetime import datetime, timezone

    body = await request.json()
    playstore_url = str(body.get("playstore_url", "")).strip()
    if not playstore_url or "play.google.com" not in playstore_url:
        raise HTTPException(status_code=400, detail="Valid Play Store URL is required")

    log.info(f"APK scan requested for: {playstore_url}")

    try:
        scan = await _collect_apk_reference_results(playstore_url)
        results = scan["results"]

        doc = {
            "query": playstore_url,
            "playstore_url": scan["playstore_url"],
            "package_id": scan["package_id"],
            "app_name": scan["app_name"],
            "queries": scan["queries"],
            "sources": scan["sources"],
            "search_errors": scan["search_errors"],
            "results": results,
            "count": len(results),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await apk_col.insert_one(doc)

        log.info(
            "APK scan complete: %s items for package=%s app=%s sources=%s errors=%s",
            len(results),
            scan["package_id"],
            scan["app_name"],
            scan["sources"],
            len(scan["search_errors"]),
        )
        message = (
            f"Searched {scan['package_id']} ({scan['app_name']}) across web and intelligence sources."
            if results else
            f"No cracked/modded references found for {scan['package_id']} ({scan['app_name']})."
        )
        return {
            "status": "ok",
            "query": playstore_url,
            "playstore_url": scan["playstore_url"],
            "package_id": scan["package_id"],
            "app_name": scan["app_name"],
            "queries": scan["queries"],
            "sources": scan["sources"],
            "search_errors": scan["search_errors"],
            "count": len(results),
            "results": results,
            "message": message,
        }

    except Exception as e:
        log.error(f"APK scan failed: {e}", exc_info=True)
        return {"status": "error", "message": f"Scan failed: {str(e)}"}


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


