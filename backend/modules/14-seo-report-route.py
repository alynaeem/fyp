def _build_seo_fallback_suggestions(url: str, audits: dict[str, dict[str, Any]]) -> str:
    failing = []
    for audit_id, audit in (audits or {}).items():
        score = audit.get("score")
        if score == 1:
            continue
        recommendation = str(audit.get("recommendation") or "").strip()
        if recommendation:
            failing.append({
                "id": audit_id,
                "title": str(audit.get("title") or audit_id).strip(),
                "description": str(audit.get("description") or "").strip(),
                "score": score,
                "recommendation": recommendation,
            })
            continue
        failing.append({
            "id": audit_id,
            "title": str(audit.get("title") or audit_id).strip(),
            "description": str(audit.get("description") or "").strip(),
            "score": score,
        })

    def _sort_key(item: dict[str, Any]) -> tuple[int, float, str]:
        score = item.get("score")
        if isinstance(score, (int, float)):
            return (0, float(score), item["title"])
        return (1, 2.0, item["title"])

    failing.sort(key=_sort_key)

    suggestions: list[str] = []

    def _push(text: str) -> None:
        clean_text = text.strip()
        if clean_text and clean_text not in suggestions and len(suggestions) < 4:
            suggestions.append(clean_text)

    for item in failing:
        if item.get("recommendation"):
            _push(item["recommendation"])
            continue
        title = item["title"].lower()
        description = re.sub(r"\s+", " ", item["description"]).strip()
        short_desc = description[:160].rstrip(".")

        if "title" in title:
            _push("Write a unique, descriptive page title for each important page and align it closely with the main search intent.")
        elif "meta description" in title:
            _push("Add a clear meta description that explains the page value in plain language and encourages clicks from search results.")
        elif "crawl" in title or "index" in title or "robots" in title or "http status" in title:
            _push("Make sure important pages return HTTP 200, are not blocked by robots or noindex directives, and can be crawled consistently.")
        elif "link" in title:
            _push("Improve internal anchor text so links describe the destination clearly instead of using generic phrases.")
        elif "image" in title or "alt" in title:
            _push("Add meaningful alt text to important images so search engines and accessibility tools understand the page content better.")
        elif "mobile" in title or "viewport" in title:
            _push("Review the mobile layout and viewport settings so the page remains readable and usable on smaller screens.")
        elif "canonical" in title:
            _push("Set canonical URLs on indexable pages to reduce duplicate-content confusion and consolidate ranking signals.")
        elif "structured data" in title or "schema" in title:
            _push("Add valid structured data where appropriate so search engines can understand page entities and rich result opportunities.")
        elif short_desc:
            _push(f"Address '{item['title']}' first. {short_desc}.")
        else:
            _push(f"Address '{item['title']}' as a priority SEO issue on {urlparse(url).hostname or url}.")

    if not suggestions:
        suggestions = [
            "Keep page titles and meta descriptions unique across key pages.",
            "Check crawlability, status codes, and indexability for important landing pages.",
            "Strengthen internal links and content clarity so pages map cleanly to search intent.",
        ]

    return "\n".join(f"- {suggestion}" for suggestion in suggestions[:4])


def _safe_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 1.0
    return max(0.0, min(1.0, numerator / denominator))


def _score_length(value: str, good_min: int, good_max: int, warn_min: int = 1, warn_max: int | None = None) -> float:
    length = len(value or "")
    if good_min <= length <= good_max:
        return 1.0
    if length >= warn_min and (warn_max is None or length <= warn_max):
        return 0.65
    return 0.0


def _normalize_seo_host(hostname: str | None) -> str:
    host = (hostname or "").strip().lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def _same_requested_host(requested_host: str | None, final_host: str | None) -> bool:
    requested = _normalize_seo_host(requested_host)
    final = _normalize_seo_host(final_host)
    return bool(requested and final and requested == final)


def _validate_seo_target(url: str) -> tuple[str, str]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise SEOScanError(
            "Please enter a valid website URL or domain, for example https://example.com.",
            kind="invalid_url",
        )
    hostname = parsed.hostname
    if not hostname:
        raise SEOScanError("The URL does not contain a valid hostname.", kind="invalid_url")
    try:
        socket.getaddrinfo(hostname, 443 if parsed.scheme == "https" else 80, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise SEOScanError(
            f"Domain '{hostname}' could not be resolved. Check the spelling or try the full live URL.",
            kind="dns_error",
            details={"host": hostname},
        )
    except OSError as exc:
        raise SEOScanError(
            f"Could not validate DNS for '{hostname}': {exc}",
            kind="dns_error",
            details={"host": hostname},
        )
    return url, hostname


def _friendly_request_error(url: str, exc: Exception) -> SEOScanError:
    import requests

    host = urlparse(url).hostname or url
    if isinstance(exc, requests.exceptions.Timeout):
        return SEOScanError(
            f"Timed out while connecting to '{host}'. The site may be slow or blocking automated checks.",
            kind="timeout",
            details={"host": host},
        )
    if isinstance(exc, requests.exceptions.SSLError):
        return SEOScanError(
            f"Could not complete the HTTPS/TLS handshake for '{host}'. Check the SSL certificate or try http:// if this is an internal site.",
            kind="ssl_error",
            details={"host": host},
        )
    if isinstance(exc, requests.exceptions.TooManyRedirects):
        return SEOScanError(
            f"'{host}' has too many redirects. Fix the redirect loop before running an SEO audit.",
            kind="redirect_loop",
            details={"host": host},
        )
    if isinstance(exc, requests.exceptions.ConnectionError):
        return SEOScanError(
            f"Could not connect to '{host}'. The domain may be offline, blocked, or refusing scanner requests.",
            kind="connection_error",
            details={"host": host},
        )
    if isinstance(exc, requests.exceptions.HTTPError):
        response = getattr(exc, "response", None)
        status_code = getattr(response, "status_code", None)
        return SEOScanError(
            f"'{host}' returned HTTP {status_code or 'error'}, so a reliable SEO report could not be generated.",
            kind="http_error",
            details={"host": host, "status_code": status_code},
        )
    return SEOScanError(
        f"SEO scan failed for '{host}': {exc}",
        kind="scan_error",
        details={"host": host},
    )


_SEO_HTTP_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/123.0 Safari/537.36"
    )
}
_ACCESS_LIMIT_PATTERNS = (
    "please wait while we verify",
    "enable javascript",
    "log in to continue",
    "login to continue",
    "authentication required",
    "sign up",
    "create account",
    "checkpoint",
    "captcha",
)
_BOT_PROTECTION_PATTERNS = (
    "captcha",
    "cloudflare",
    "cf-challenge",
    "checking your browser",
    "automated access",
    "unusual traffic",
    "rate limited",
    "too many requests",
)
_GENERIC_LINK_TEXT = {"", "click here", "read more", "learn more", "here", "more", "link"}


def _clean_seo_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _seo_status(score: float, *, confidence: str = "high", needs_review: bool = False) -> str:
    if needs_review:
        return "needs_review"
    if score >= 0.85:
        return "pass"
    if confidence == "low":
        return "needs_review"
    if score >= 0.55:
        return "warning"
    return "fail"


def _scan_confidence_grade(level: str) -> str:
    return {"high": "High", "medium": "Medium", "low": "Low"}.get(level, "Medium")


def _is_brand_like_short_title(title: str, hostname: str) -> bool:
    title_clean = re.sub(r"[^a-z0-9]+", "", (title or "").lower())
    host_part = (_normalize_seo_host(hostname).split(".")[0] or "").lower()
    return bool(title_clean and host_part and (title_clean == host_part or title_clean in host_part or host_part in title_clean))


def _json_ld_parse_errors(values: list[str]) -> list[str]:
    errors: list[str] = []
    for index, raw_value in enumerate(values, start=1):
        try:
            json.loads(raw_value)
        except Exception as exc:
            errors.append(f"JSON-LD block {index}: {str(exc)[:120]}")
    return errors


def _extract_seo_dom_snapshot(html: str, base_url: str, *, source: str) -> dict[str, Any]:
    import requests
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html or "", "lxml")
    title = _clean_seo_text(soup.title.string if soup.title else "")
    meta_description = _clean_seo_text((soup.find("meta", attrs={"name": re.compile("^description$", re.I)}) or {}).get("content"))
    robots_meta = _clean_seo_text((soup.find("meta", attrs={"name": re.compile("^robots$", re.I)}) or {}).get("content"))
    canonical_tags = [
        _clean_seo_text(tag.get("href"))
        for tag in soup.find_all("link", attrs={"rel": re.compile("canonical", re.I)})
        if _clean_seo_text(tag.get("href"))
    ]
    canonical_abs = [urljoin(base_url, item) for item in canonical_tags]
    viewport = _clean_seo_text((soup.find("meta", attrs={"name": re.compile("^viewport$", re.I)}) or {}).get("content"))
    lang = _clean_seo_text(getattr(soup.html, "attrs", {}).get("lang") if soup.html else "")
    body_text = _clean_seo_text(soup.body.get_text(" ", strip=True) if soup.body else "")
    h1_texts = [_clean_seo_text(tag.get_text(" ", strip=True)) for tag in soup.find_all("h1")]
    h1_texts = [item for item in h1_texts if item]
    image_tags = soup.find_all("img")
    informative_images = [
        img for img in image_tags
        if str(img.get("role") or "").lower() != "presentation"
        and str(img.get("aria-hidden") or "").lower() != "true"
    ]
    images_with_alt = sum(1 for img in informative_images if _clean_seo_text(img.get("alt")))
    anchor_tags = soup.find_all("a")
    descriptive_links = sum(
        1 for link in anchor_tags
        if _clean_seo_text(link.get_text(" ", strip=True)).lower() not in _GENERIC_LINK_TEXT
    )
    og_tags = soup.find_all("meta", attrs={"property": re.compile(r"^og:", re.I)})
    twitter_tags = soup.find_all("meta", attrs={"name": re.compile(r"^twitter:", re.I)})
    json_ld_values = [
        str(tag.string or tag.get_text() or "").strip()
        for tag in soup.find_all("script", attrs={"type": re.compile(r"ld\+json", re.I)})
        if str(tag.string or tag.get_text() or "").strip()
    ]
    html_lower = (html or "").lower()
    app_root_present = bool(
        soup.find(id=re.compile(r"^(app|root|__next|mount)$", re.I))
        or soup.find(attrs={"data-reactroot": True})
        or soup.find(attrs={"ng-version": True})
    )
    access_limited = any(pattern in html_lower or pattern in body_text.lower() for pattern in _ACCESS_LIMIT_PATTERNS)
    bot_protection = any(pattern in html_lower or pattern in body_text.lower() for pattern in _BOT_PROTECTION_PATTERNS)
    script_count = len(soup.find_all("script"))

    return {
        "source": source,
        "title": title,
        "metaDescription": meta_description,
        "robotsMeta": robots_meta,
        "canonical": canonical_abs[0] if canonical_abs else "",
        "canonicalTags": canonical_abs,
        "viewport": viewport,
        "lang": lang,
        "h1Count": len(h1_texts),
        "h1Text": h1_texts[:5],
        "bodyTextLength": len(body_text),
        "imageCount": len(image_tags),
        "informativeImageCount": len(informative_images),
        "imagesWithAlt": images_with_alt,
        "linkCount": len(anchor_tags),
        "descriptiveLinkCount": descriptive_links,
        "openGraphCount": len(og_tags),
        "twitterCardCount": len(twitter_tags),
        "jsonLdCount": len(json_ld_values),
        "jsonLdParseErrors": _json_ld_parse_errors(json_ld_values),
        "scriptCount": script_count,
        "htmlSize": len(html or ""),
        "appRootPresent": app_root_present,
        "accessLimitedSignals": access_limited,
        "botProtectionLikely": bot_protection,
        "htmlPreview": (html or "")[:500],
    }


def _rendered_seo_scan(url: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
    except Exception as exc:
        return None, {"kind": "playwright_unavailable", "message": f"Rendered DOM scan unavailable: {exc}"}

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            context = browser.new_context(
                user_agent=_SEO_HTTP_HEADERS["User-Agent"],
                viewport={"width": 1365, "height": 900},
                ignore_https_errors=True,
            )
            page = context.new_page()
            response_status = None
            try:
                response = page.goto(url, wait_until="domcontentloaded", timeout=15000)
                response_status = response.status if response else None
                try:
                    page.wait_for_load_state("networkidle", timeout=5000)
                except PlaywrightTimeoutError:
                    pass
                html = page.content()
                snapshot = _extract_seo_dom_snapshot(html, page.url or url, source="rendered_dom")
                snapshot["url"] = page.url or url
                snapshot["statusCode"] = response_status
                return snapshot, None
            finally:
                context.close()
                browser.close()
    except Exception as exc:
        return None, {"kind": exc.__class__.__name__, "message": f"Rendered DOM scan failed: {str(exc)[:240]}"}


def _fetch_robots_status(session: Any, final_url: str, hostname: str) -> dict[str, Any]:
    robots_url = f"{urlparse(final_url).scheme}://{hostname}/robots.txt"
    try:
        response = session.get(robots_url, timeout=8, headers=_SEO_HTTP_HEADERS, allow_redirects=True)
        text = response.text or ""
        body_lower = text.lower()
        if response.status_code == 200:
            score = 0.0 if re.search(r"(?im)^disallow:\s*/\s*$", body_lower) else 1.0
            status = "pass" if score == 1.0 else "fail"
            message = f"robots.txt returned HTTP 200 with {len(text)} characters."
        elif response.status_code == 403:
            score, status = 0.55, "warning"
            message = "robots.txt returned HTTP 403; crawler policy could not be fully verified."
        elif response.status_code == 404:
            score, status = 0.65, "warning"
            message = "robots.txt returned HTTP 404; no robots policy was found."
        elif response.status_code == 429:
            score, status = 0.55, "warning"
            message = "robots.txt returned HTTP 429; rate limited during scan."
        else:
            score, status = 0.65, "warning"
            message = f"robots.txt returned HTTP {response.status_code}."
        return {"url": robots_url, "statusCode": response.status_code, "score": score, "status": status, "message": message}
    except Exception as exc:
        return {"url": robots_url, "statusCode": None, "score": 0.55, "status": "warning", "message": f"robots.txt check failed: {str(exc)[:120]}"}


def _compute_crawler_visibility(raw: dict[str, Any], rendered: dict[str, Any] | None, rendered_error: dict[str, Any] | None) -> dict[str, Any]:
    raw_body = int(raw.get("bodyTextLength") or 0)
    raw_scripts = int(raw.get("scriptCount") or 0)
    rendered_body = int(rendered.get("bodyTextLength") or 0) if rendered else None
    rendered_scripts = int(rendered.get("scriptCount") or 0) if rendered else 0
    text_for_detection = " ".join([
        str(raw.get("htmlPreview") or ""),
        str((rendered or {}).get("htmlPreview") or ""),
    ]).lower()
    js_heavy = raw_scripts >= 20 or (raw_scripts >= 5 and raw_body < 250) or bool(raw.get("appRootPresent")) or bool((rendered or {}).get("appRootPresent"))
    access_limited = bool(raw.get("accessLimitedSignals") or (rendered or {}).get("accessLimitedSignals") or (raw_body < 30 and raw_scripts >= 5))
    bot_protection = bool(raw.get("botProtectionLikely") or (rendered or {}).get("botProtectionLikely") or raw.get("statusCode") in {403, 429})
    login_wall = any(pattern in text_for_detection for pattern in ("login", "log in", "sign up", "create account", "authentication required"))
    rendered_available = rendered is not None
    rendered_meaningful = rendered_available and (
        (rendered_body or 0) >= 80
        or ((rendered_body or 0) >= 20 and int((rendered or {}).get("h1Count") or 0) > 0 and raw_scripts < 5)
    )

    if rendered_meaningful and not bot_protection:
        level = "high"
        reason = "Rendered DOM scan completed and visible text/content was available."
    elif rendered_available and (rendered_body or 0) > 0:
        level = "medium"
        reason = "Rendered DOM scan completed but returned limited visible content."
    else:
        level = "low"
        if rendered_error:
            reason = rendered_error.get("message") or "Rendered DOM scan failed or was blocked."
        else:
            reason = "Only limited crawler-visible initial HTML was available."

    return {
        "level": level,
        "reason": reason,
        "signals": {
            "bodyTextLength": raw_body,
            "scriptCount": raw_scripts,
            "renderedBodyTextLength": rendered_body,
            "renderedScriptCount": rendered_scripts,
            "accessLimitedSignals": access_limited,
            "botProtectionLikely": bot_protection,
            "loginWallLikely": login_wall,
            "jsHeavyLikely": js_heavy,
            "renderedScanAvailable": rendered_available,
        },
    }


def _preferred_dom(raw: dict[str, Any], rendered: dict[str, Any] | None, field: str) -> tuple[Any, str, str]:
    rendered_value = (rendered or {}).get(field)
    raw_value = raw.get(field)
    if rendered is not None and rendered_value not in (None, "", [], {}):
        return rendered_value, "rendered_dom", "high"
    if raw_value not in (None, "", [], {}):
        return raw_value, "raw_html", "medium" if rendered is None else "high"
    return raw_value, "combined" if rendered is not None else "raw_html", "high" if rendered is not None else "low"


