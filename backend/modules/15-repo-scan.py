def _make_audit(
    audits: dict[str, dict[str, Any]],
    audit_id: str,
    *,
    score: float,
    title: str,
    description: str,
    weight: int,
    evidence: str,
    recommendation: str = "",
    confidence: str = "high",
    evidence_source: str = "combined",
    status: str | None = None,
    note: str = "",
) -> None:
    bounded = round(max(0.0, min(1.0, float(score))), 2)
    audits[audit_id] = {
        "id": audit_id,
        "score": bounded,
        "title": title,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "weight": weight,
        "status": status or _seo_status(bounded, confidence=confidence),
        "confidence": confidence,
        "evidenceSource": evidence_source,
        "note": note,
    }


def _build_dual_mode_seo_report(
    *,
    url: str,
    final_url: str,
    requested_host: str,
    response: Any,
    raw: dict[str, Any],
    rendered: dict[str, Any] | None,
    rendered_error: dict[str, Any] | None,
    robots: dict[str, Any],
) -> dict[str, Any]:
    hostname = urlparse(final_url).hostname or requested_host
    visibility = _compute_crawler_visibility(raw, rendered, rendered_error)
    low_visibility = visibility["level"] == "low"
    limited_visibility = visibility["level"] != "high"
    audits: dict[str, dict[str, Any]] = {}
    rendered_available = rendered is not None

    def limited_note(issue: str) -> str:
        return (
            f"{issue} was not verified in a high-confidence rendered DOM. "
            "Validate with Google Search Console URL Inspection or PageSpeed Insights."
        )

    title, title_source, title_conf = _preferred_dom(raw, rendered, "title")
    title_score = _score_length(str(title or ""), 10, 65, warn_min=1, warn_max=85)
    if title_score < 0.85 and _is_brand_like_short_title(str(title or ""), hostname):
        title_score = 0.75
        title_note = "A longer descriptive title may help non-brand search intent, but short brand titles can be acceptable for major brand homepages."
    else:
        title_note = ""
    _make_audit(
        audits,
        "document-title",
        score=title_score,
        title="Document has a descriptive title",
        description="A strong SEO title should exist and usually stay within a readable search-result length.",
        weight=12,
        evidence=f"Title length: {len(str(title or ''))}. Title: {str(title or 'not found')[:90]}.",
        recommendation="Consider a 10-65 character title aligned with the page's primary search intent." if title_score < 0.85 else "",
        confidence=title_conf,
        evidence_source=title_source,
        note=title_note,
        status="warning" if title_note else None,
    )

    meta_description, meta_source, meta_conf = _preferred_dom(raw, rendered, "metaDescription")
    meta_score = _score_length(str(meta_description or ""), 50, 170, warn_min=1, warn_max=220)
    meta_status = None
    meta_note = "Google may generate snippets from page content, but a meta description is still recommended."
    if not meta_description and low_visibility and not rendered_available:
        meta_score, meta_status, meta_conf, meta_source = 0.55, "needs_review", "low", "raw_html"
        meta_note = limited_note("Meta description")
    _make_audit(
        audits,
        "meta-description",
        score=meta_score,
        title="Meta description is present",
        description="Pages should have a concise meta description that explains value clearly in search results.",
        weight=10,
        evidence=f"Raw length: {len(str(raw.get('metaDescription') or ''))}; rendered length: {len(str((rendered or {}).get('metaDescription') or '')) if rendered_available else 'not available'}.",
        recommendation="Add a unique 50-170 character meta description focused on the page value and target audience." if meta_score < 0.85 else "",
        confidence=meta_conf,
        evidence_source=meta_source,
        status=meta_status,
        note=meta_note if meta_score < 0.85 else "",
    )

    redirects = len(response.history or [])
    _make_audit(
        audits,
        "http-status-code",
        score=1.0 if response.status_code == 200 else 0.0,
        title="Page returns a successful status code",
        description=f"The scanned page returned HTTP {response.status_code}. Important landing pages should normally respond with HTTP 200.",
        weight=14,
        evidence=f"Final URL: {final_url}. Redirect hops: {redirects}.",
        recommendation="Fix the page response so the canonical landing URL returns HTTP 200." if response.status_code != 200 else "",
        confidence="high",
        evidence_source="http_headers",
    )

    robots_meta_raw = str(raw.get("robotsMeta") or "")
    robots_meta_rendered = str((rendered or {}).get("robotsMeta") or "")
    x_robots = str(raw.get("xRobotsTag") or "")
    noindex = "noindex" in robots_meta_raw.lower() or "noindex" in robots_meta_rendered.lower() or "noindex" in x_robots.lower()
    _make_audit(
        audits,
        "is-crawlable",
        score=0.0 if noindex else 1.0,
        title="Page is indexable by search engines",
        description="Robots directives should not accidentally block indexation of pages intended for search visibility.",
        weight=14,
        evidence=f"Raw meta robots: {robots_meta_raw or 'none'}; rendered meta robots: {robots_meta_rendered or 'none'}; X-Robots-Tag: {x_robots or 'none'}.",
        recommendation="Remove noindex directives from pages that should appear in search results." if noindex else "",
        confidence="high",
        evidence_source="combined",
    )

    for audit_id, field, title, description, weight, recommendation in [
        ("viewport", "viewport", "Mobile viewport is configured", "Responsive pages should define a viewport meta tag so they render correctly on mobile devices.", 8, 'Add <meta name="viewport" content="width=device-width, initial-scale=1"> for reliable mobile rendering.'),
        ("html-lang", "lang", "Document language is declared", "The root html element should declare a language to help search engines and accessibility tooling interpret content.", 5, 'Set the root html language, for example <html lang="en">, to improve accessibility and interpretation.'),
    ]:
        value, source, confidence = _preferred_dom(raw, rendered, field)
        missing_low = not value and low_visibility and not rendered_available
        _make_audit(
            audits,
            audit_id,
            score=0.55 if missing_low else (1.0 if value else 0.0),
            title=title,
            description=description,
            weight=weight,
            evidence=f"Raw: {raw.get(field) or 'not found'}; rendered: {(rendered or {}).get(field) or ('not available' if not rendered_available else 'not found')}.",
            recommendation=recommendation if not value else "",
            confidence="low" if missing_low else confidence,
            evidence_source=source,
            status="needs_review" if missing_low else None,
            note=limited_note(title) if missing_low else "",
        )

    raw_canonicals = raw.get("canonicalTags") or []
    rendered_canonicals = (rendered or {}).get("canonicalTags") or []
    canonical, canonical_source, canonical_conf = _preferred_dom(raw, rendered, "canonical")
    multiple_canonical = len(raw_canonicals) > 1 or len(rendered_canonicals) > 1
    canonical_mismatch = bool(raw_canonicals and rendered_canonicals and raw_canonicals[0] != rendered_canonicals[0])
    canonical_score = 1.0 if canonical and not multiple_canonical and not canonical_mismatch else (0.55 if canonical else 0.0)
    canonical_status = None
    canonical_note = ""
    if not canonical and low_visibility:
        canonical_score, canonical_status, canonical_conf, canonical_source = 0.55, "needs_review", "low", "raw_html"
        canonical_note = limited_note("Canonical tag")
    _make_audit(
        audits,
        "canonical",
        score=canonical_score,
        title="Canonical URL is declared",
        description="Canonical tags help consolidate duplicate signals and clarify which URL should rank.",
        weight=8,
        evidence=f"Raw canonicals: {raw_canonicals or 'none'}; rendered canonicals: {rendered_canonicals or ('not available' if not rendered_available else 'none')}.",
        recommendation="Declare one canonical URL pointing to the preferred HTTPS version of this page." if canonical_score < 0.85 else "",
        confidence=canonical_conf,
        evidence_source=canonical_source if not (raw_canonicals and rendered_canonicals) else "combined",
        status=canonical_status,
        note=canonical_note or ("Multiple or mismatched canonical tags were detected." if multiple_canonical or canonical_mismatch else ""),
    )

    h1_count = int((rendered or raw).get("h1Count") or 0)
    h1_source = "rendered_dom" if rendered_available else "raw_html"
    h1_conf = "high" if rendered_available and visibility["level"] == "high" else ("medium" if rendered_available else "low")
    h1_score = 1.0 if h1_count == 1 else (0.65 if 2 <= h1_count <= 3 else 0.0)
    h1_status = None
    h1_note = ""
    if h1_count == 0 and limited_visibility:
        h1_score, h1_status, h1_note = 0.55, "needs_review", limited_note("H1")
    _make_audit(
        audits,
        "single-h1",
        score=h1_score,
        title="Primary H1 heading is defined",
        description="Pages generally perform best with one clear H1 that matches the main topic and search intent.",
        weight=7,
        evidence=f"Raw H1 count: {raw.get('h1Count')}; rendered H1 count: {(rendered or {}).get('h1Count') if rendered_available else 'not available'}.",
        recommendation="Use one visible H1 that clearly describes the page topic." if h1_score < 0.85 else "",
        confidence=h1_conf,
        evidence_source=h1_source,
        status=h1_status,
        note=h1_note,
    )

    img_source_data = rendered if rendered_available else raw
    image_count = int(img_source_data.get("informativeImageCount") or img_source_data.get("imageCount") or 0)
    images_with_alt = int(img_source_data.get("imagesWithAlt") or 0)
    image_score = _safe_ratio(images_with_alt, image_count) if image_count else 0.55
    image_status = "not_applicable" if image_count == 0 and visibility["level"] != "low" else None
    image_note = ""
    if limited_visibility and image_count <= 2:
        image_status, image_score, image_note = "needs_review", 0.55, limited_note("Image alt coverage")
    _make_audit(
        audits,
        "image-alt",
        score=image_score,
        title="Images include alt text",
        description="Important images should include meaningful alt text so search engines and assistive technologies understand them.",
        weight=5,
        evidence=f"Raw images with alt: {raw.get('imagesWithAlt')}/{raw.get('informativeImageCount')}; rendered: {(rendered or {}).get('imagesWithAlt')}/{(rendered or {}).get('informativeImageCount') if rendered_available else 'not available'}.",
        recommendation="Add concise, meaningful alt text to informative images; decorative images can use empty alt text." if image_score < 0.85 and image_count else "",
        confidence="low" if image_status == "needs_review" else ("high" if rendered_available and visibility["level"] == "high" else "medium"),
        evidence_source="rendered_dom" if rendered_available else "raw_html",
        status=image_status,
        note=image_note,
    )

    link_data = rendered if rendered_available else raw
    link_count = int(link_data.get("linkCount") or 0)
    descriptive_links = int(link_data.get("descriptiveLinkCount") or 0)
    if link_count == 0:
        link_score = 0.55
        link_status = "needs_review" if limited_visibility else "not_applicable"
        link_note = "No links were available in the inspected DOM; this rule cannot be confirmed from the current scan."
    else:
        link_score = _safe_ratio(descriptive_links, link_count)
        link_status = None
        link_note = ""
    _make_audit(
        audits,
        "link-text",
        score=link_score,
        title="Links use descriptive anchor text",
        description="Anchor text should describe the destination instead of relying on generic phrases like 'click here'.",
        weight=5,
        evidence=f"Raw descriptive links: {raw.get('descriptiveLinkCount')}/{raw.get('linkCount')}; rendered: {(rendered or {}).get('descriptiveLinkCount')}/{(rendered or {}).get('linkCount') if rendered_available else 'not available'}.",
        recommendation="Replace vague link labels with destination-specific anchor text." if link_count and link_score < 0.85 else "",
        confidence="low" if link_status == "needs_review" else ("high" if rendered_available and visibility["level"] == "high" else "medium"),
        evidence_source="rendered_dom" if rendered_available else "raw_html",
        status=link_status,
        note=link_note,
    )

    for audit_id, raw_field, rendered_field, title, description, weight, recommendation in [
        ("social-metadata", "openGraphCount", "openGraphCount", "Social preview metadata is configured", "Open Graph or Twitter Card tags improve link previews and click-through quality when pages are shared.", 4, "Add Open Graph and Twitter Card metadata for the title, description, image, and canonical URL."),
        ("structured-data", "jsonLdCount", "jsonLdCount", "Structured data is present", "JSON-LD schema helps search engines understand page entities and can unlock richer search presentation.", 4, "Add relevant JSON-LD schema such as Organization, WebSite, Article, BreadcrumbList, or LocalBusiness where appropriate."),
    ]:
        raw_count = int(raw.get(raw_field) or 0)
        rendered_count = int((rendered or {}).get(rendered_field) or 0)
        count = rendered_count if rendered_available else raw_count
        source = "rendered_dom" if rendered_available else "raw_html"
        confidence = "high" if rendered_available and visibility["level"] == "high" else ("low" if low_visibility else "medium")
        score = 1.0 if count else (0.55 if limited_visibility else 0.45)
        status = "needs_review" if limited_visibility and not count else None
        note = limited_note(title) if status == "needs_review" else ""
        if audit_id == "structured-data" and (raw.get("jsonLdParseErrors") or (rendered or {}).get("jsonLdParseErrors")):
            score, status, note = 0.55, "warning", "JSON-LD was found but at least one block could not be parsed."
        _make_audit(
            audits,
            audit_id,
            score=score,
            title=title,
            description=description,
            weight=weight,
            evidence=f"Raw count: {raw_count}; rendered count: {rendered_count if rendered_available else 'not available'}.",
            recommendation=recommendation if score < 0.85 else "",
            confidence=confidence,
            evidence_source=source,
            status=status,
            note=note,
        )

    _make_audit(
        audits,
        "robots-txt",
        score=float(robots.get("score", 0.55)),
        title="robots.txt is reachable and not broadly blocking",
        description="A clear robots.txt file helps crawlers understand which areas can be accessed.",
        weight=5,
        evidence=str(robots.get("message") or "robots.txt was not checked."),
        recommendation="Review robots.txt so it is reachable and does not accidentally block important public pages." if robots.get("status") != "pass" else "",
        confidence="high" if robots.get("statusCode") == 200 else "medium",
        evidence_source="robots_txt",
        status=str(robots.get("status") or "warning"),
    )

    content_bytes = len(response.content or b"")
    _make_audit(
        audits,
        "response-weight",
        score=1.0 if content_bytes <= 1_500_000 else (0.65 if content_bytes <= 3_000_000 else 0.35),
        title="Initial HTML response is reasonably sized",
        description="Very large HTML responses can slow down crawling and first render.",
        weight=4,
        evidence=f"Downloaded HTML size: {round(content_bytes / 1024, 1)} KB. Compression header: {response.headers.get('Content-Encoding') or 'none observed'}.",
        recommendation="Reduce initial HTML payload and move non-critical data/scripts out of the first response." if content_bytes > 1_500_000 else "",
        confidence="high",
        evidence_source="http_headers",
    )
    _make_audit(
        audits,
        "redirects",
        score=1.0 if redirects <= 1 else (0.7 if redirects <= 3 else 0.35),
        title="Redirect chain is short",
        description="Short redirect chains preserve crawl efficiency and reduce latency.",
        weight=4,
        evidence=f"Redirect hops before final URL: {redirects}.",
        recommendation="Point internal and canonical links directly to the final HTTPS URL to avoid extra redirect hops." if redirects > 1 else "",
        confidence="high",
        evidence_source="http_headers",
    )

    _make_audit(
        audits,
        "crawler-visibility",
        score={"high": 1.0, "medium": 0.7, "low": 0.4}[visibility["level"]],
        title="Crawler visibility confidence",
        description="Shows how much reliable page content DarkPulse could inspect.",
        weight=0,
        evidence=visibility["reason"],
        recommendation="Validate with Google Search Console URL Inspection or PageSpeed Insights." if visibility["level"] != "high" else "",
        confidence="high",
        evidence_source="combined",
        status="pass" if visibility["level"] == "high" else "warning",
        note="This is a scan-confidence finding, not a direct SEO defect.",
    )

    weighted_total = sum(float(audit["score"]) * int(audit["weight"]) for audit in audits.values() if int(audit.get("weight") or 0) > 0)
    total_weight = sum(int(audit["weight"]) for audit in audits.values() if int(audit.get("weight") or 0) > 0)
    seo_score = round(weighted_total / total_weight, 2) if total_weight else 0.0
    if visibility["level"] == "low":
        seo_score = round(max(seo_score, 0.72), 2)

    return {
        "url": final_url,
        "requestedUrl": url,
        "seoScore": seo_score,
        "seoHealthScore": seo_score,
        "seoHealthGrade": calculate_seo_grade(seo_score),
        "scanConfidenceGrade": _scan_confidence_grade(visibility["level"]),
        "scanModeUsed": "raw_html+rendered_dom" if rendered_available else "raw_html",
        "rawScanAvailable": True,
        "renderedScanAvailable": rendered_available,
        "crawlerVisibility": visibility,
        "audits": audits,
        "provider": "dual_mode_local",
        "confidence": "normal" if visibility["level"] == "high" else "limited_html",
        "rawScan": raw,
        "renderedScan": rendered,
        "renderedScanError": rendered_error,
        "technical": {
            "status_code": response.status_code,
            "redirects": redirects,
            "content_bytes": content_bytes,
            "compressed": bool(response.headers.get("Content-Encoding")),
            "body_text_length": raw.get("bodyTextLength"),
            "rendered_body_text_length": (rendered or {}).get("bodyTextLength"),
            "js_heavy": visibility["signals"]["jsHeavyLikely"],
            "access_limited": visibility["signals"]["accessLimitedSignals"],
            "bot_protection_likely": visibility["signals"]["botProtectionLikely"],
            "response_headers": dict(response.headers),
            "redirect_chain": [item.url for item in response.history] + [final_url],
        },
    }


def _local_seo_audit(url: str) -> dict[str, Any]:
    import requests

    url, requested_host = _validate_seo_target(url)
    session = requests.Session()
    try:
        response = session.get(url, timeout=30, headers=_SEO_HTTP_HEADERS, allow_redirects=True)
        response.raise_for_status()
    except requests.exceptions.RequestException as exc:
        raise _friendly_request_error(url, exc) from exc

    final_url = response.url or url
    final_host = urlparse(final_url).hostname
    if not _same_requested_host(requested_host, final_host):
        raise SEOScanError(
            (
                f"'{requested_host}' redirects to a different domain "
                f"'{final_host or final_url}'. No SEO report was generated for the requested host."
            ),
            kind="cross_domain_redirect",
            details={
                "requested_host": requested_host,
                "final_host": final_host,
                "final_url": final_url,
                "redirect_chain": [item.url for item in response.history] + [final_url],
            },
        )

    raw = _extract_seo_dom_snapshot(response.text or "", final_url, source="raw_html")
    raw["url"] = final_url
    raw["statusCode"] = response.status_code
    raw["xRobotsTag"] = _clean_seo_text(response.headers.get("X-Robots-Tag"))
    raw["responseHeaders"] = dict(response.headers)
    raw["compression"] = response.headers.get("Content-Encoding") or ""
    raw["initialHtmlBytes"] = len(response.content or b"")

    rendered, rendered_error = _rendered_seo_scan(final_url)
    if rendered is not None:
        rendered_host = urlparse(rendered.get("url") or final_url).hostname
        if rendered_host and not _same_requested_host(requested_host, rendered_host):
            rendered_error = {
                "kind": "cross_domain_redirect",
                "message": f"Rendered browser ended on a different host: {rendered_host}.",
            }
            rendered = None

    hostname = urlparse(final_url).hostname or requested_host
    robots = _fetch_robots_status(session, final_url, hostname)
    return _build_dual_mode_seo_report(
        url=url,
        final_url=final_url,
        requested_host=requested_host,
        response=response,
        raw=raw,
        rendered=rendered,
        rendered_error=rendered_error,
        robots=robots,
    )

