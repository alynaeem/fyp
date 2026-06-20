def _flatten_strings(value: Any, limit: int = 128) -> list[str]:
    flattened: list[str] = []

    def visit(current: Any):
        if len(flattened) >= limit or current in (None, ""):
            return
        if isinstance(current, dict):
            for inner in current.values():
                visit(inner)
            return
        if isinstance(current, (list, tuple, set)):
            for inner in current:
                visit(inner)
            return
        text = str(current).strip()
        if text:
            flattened.append(text)

    visit(value)
    return flattened


def _extract_values(data: dict, *fields: str) -> list[str]:
    values: list[str] = []
    if not isinstance(data, dict):
        return values

    nested_sources = [data]
    for container_key in ("extra", "m_extra", "m_entity"):
        nested = data.get(container_key)
        if isinstance(nested, dict):
            nested_sources.append(nested)

    for field in fields:
        for source in nested_sources:
            if field not in source:
                continue
            values.extend(_flatten_strings(source.get(field)))

    return _dedupe_strings(values)


def _normalize_entities(value: Any) -> list[dict]:
    if not value:
        return []
    if isinstance(value, list):
        normalized = []
        for item in value:
            if isinstance(item, dict):
                normalized.append({
                    "label": str(item.get("label", "entity")),
                    "text": str(item.get("text", "")),
                    "score": item.get("score"),
                })
            else:
                normalized.append({"label": "entity", "text": str(item)})
        return normalized
    return []


def _extract_field(data: dict, *fields: str) -> str:
    for value in _extract_values(data, *fields):
        if value:
            return value
    return ""


_BLOCKED_ARTICLE_TITLES = {"403 error", "403 forbidden", "access denied"}
_LOW_QUALITY_ARTICLE_TITLES = {"infosecurity news"}
_BLOCKED_ARTICLE_PHRASES = (
    "this website uses a security service to protect against malicious bots",
    "this page is displayed while the website verifies you are not a bot",
    "request could not be satisfied",
)


def _is_blocked_article_doc(doc: dict) -> bool:
    title = _clean_text_candidate(_extract_field(doc, "title", "m_title", "headline", "name")).lower()
    url = _clean_text_candidate(_extract_field(doc, "url", "m_url", "weblink", "m_weblink")).lower()
    description = _clean_text_candidate(
        _extract_field(doc, "description", "m_description", "summary", "m_important_content", "important_content")
    ).lower()
    content = _clean_text_candidate(_extract_field(doc, "content", "m_content")).lower()
    status_raw = _extract_field(doc, "http_status", "status_code")

    try:
        http_status = int(float(status_raw)) if status_raw else 0
    except (TypeError, ValueError):
        http_status = 0

    if http_status and http_status >= 400:
        return True
    if title in _BLOCKED_ARTICLE_TITLES or description in _BLOCKED_ARTICLE_TITLES:
        return True
    if any(phrase in description or phrase in content for phrase in _BLOCKED_ARTICLE_PHRASES):
        return True
    if title in _LOW_QUALITY_ARTICLE_TITLES and re.search(r"/news/(page-\d+/?)?$", url):
        return True
    if title in _LOW_QUALITY_ARTICLE_TITLES and len(description) < 80:
        return True
    return False


def _visible_news_query(extra_filter: Optional[dict] = None) -> dict:
    blocked_title_pattern = r"^\s*(403\s+error|403\s+forbidden|access\s+denied)\s*$"
    low_quality_title_pattern = r"^\s*infosecurity\s+news\s*$"
    bot_check_pattern = r"(security service to protect against malicious bots|verifies you are not a bot|request could not be satisfied)"
    visibility_filter = {
        "$and": [
            {
                "$nor": [
                    {"title": {"$regex": blocked_title_pattern, "$options": "i"}},
                    {"m_title": {"$regex": blocked_title_pattern, "$options": "i"}},
                    {"description": {"$regex": blocked_title_pattern, "$options": "i"}},
                    {"m_description": {"$regex": blocked_title_pattern, "$options": "i"}},
                    {"description": {"$regex": bot_check_pattern, "$options": "i"}},
                    {"m_description": {"$regex": bot_check_pattern, "$options": "i"}},
                    {"content": {"$regex": bot_check_pattern, "$options": "i"}},
                    {"m_content": {"$regex": bot_check_pattern, "$options": "i"}},
                    {
                        "$and": [
                            {"title": {"$regex": low_quality_title_pattern, "$options": "i"}},
                            {"url": {"$regex": r"/news/(page-\d+/?)?$", "$options": "i"}},
                        ]
                    },
                ]
            },
            {"http_status": {"$nin": [403, "403", 401, "401", 429, "429"]}},
            {"m_extra.http_status": {"$nin": [403, "403", 401, "401", 429, "429"]}},
        ]
    }
    if not extra_filter:
        return visibility_filter
    return {"$and": [visibility_filter, extra_filter]}


def _merge_threat_payloads(item_data: dict, entity_data: Optional[dict]) -> dict:
    if not entity_data:
        return dict(item_data)

    merged = dict(item_data)
    for key, value in entity_data.items():
        if key in {"m_source", "m_collector_type"}:
            continue

        existing = merged.get(key)
        if existing in (None, "", [], {}):
            merged[key] = value
            continue

        if isinstance(existing, dict) and isinstance(value, dict):
            combined = dict(value)
            combined.update(existing)
            merged[key] = combined
            continue

        if isinstance(existing, (list, tuple, set)) or isinstance(value, (list, tuple, set)):
            merged[key] = _dedupe_strings(_flatten_strings(existing) + _flatten_strings(value))

    merged["m_entity"] = entity_data
    return merged


def _normalize_image_ref(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith("data:image/"):
        return text
    compact = "".join(text.split())
    if len(compact) > 120 and re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        return f"data:image/jpeg;base64,{compact}"
    if text.startswith(("http://", "https://")):
        return text
    return ""


def _extract_image_refs_from_html(value: Any) -> list[str]:
    refs: list[str] = []
    for html_blob in _flatten_strings(value, limit=32):
        refs.extend(match.strip() for match in _IMG_SRC_RE.findall(html_blob) if match.strip())
    return _dedupe_strings(refs)


def _extract_ip_addresses(data: dict) -> str:
    candidates: list[str] = []
    candidates.extend(
        _extract_values(
            data,
            "m_ip",
            "ip_address",
            "ip",
            "ips",
            "m_url",
            "url",
            "m_source_url",
            "source_url",
            "m_weblink",
            "weblink",
            "m_mirror_links",
            "mirror_links",
            "m_content",
            "content",
            "m_description",
            "description",
            "m_important_content",
            "important_content",
        )
    )
    candidates.extend(_flatten_strings(data.get("m_extra") or data.get("extra") or {}))

    found: list[str] = []
    for candidate in candidates:
        try:
            host = urlparse(candidate).hostname or ""
        except Exception:
            host = ""
        if host and _IP_ADDRESS_RE.fullmatch(host):
            found.append(host)
        found.extend(match.group(0) for match in _IP_ADDRESS_RE.finditer(candidate))

    return ", ".join(_dedupe_strings(found))


def _extract_screenshot_links(data: dict) -> list[str]:
    refs: list[str] = []
    refs.extend(
        _extract_values(
            data,
            "m_screenshot_links",
            "screenshot_links",
            "screenshots",
            "m_logo_or_images",
            "logo_or_images",
            "original_screenshot_url",
            "hero_image",
            "og_image",
            "m_screenshot_url",
            "screenshot_url",
            "image",
            "images",
        )
    )
    refs.extend(_extract_image_refs_from_html(_extract_values(data, "content_html", "m_ref_html")))
    normalized = [_normalize_image_ref(ref) for ref in refs]
    return _dedupe_strings([ref for ref in normalized if ref])


def _extract_primary_screenshot(data: dict) -> str:
    direct = _extract_field(data, "m_screenshot", "screenshot")
    normalized = _normalize_image_ref(direct)
    if normalized:
        return normalized
    links = _extract_screenshot_links(data)
    return links[0] if links else ""


def _extract_evidence_links(data: dict) -> list[str]:
    refs = _extract_values(
        data,
        "m_source_url",
        "source_url",
        "m_mirror_links",
        "mirror_links",
        "m_weblink",
        "weblink",
        "m_external_scanners",
        "external_scanners",
        "m_social_media_profiles",
        "social_media_profiles",
        "m_channel_url",
        "m_message_sharable_link",
    )
    return _dedupe_strings([ref for ref in refs if ref.startswith(("http://", "https://"))])


def _extract_network(data: dict) -> str:
    network = data.get("m_network", data.get("network"))
    if isinstance(network, dict):
        return _coerce_scalar(network.get("type")) or "clearnet"
    return _coerce_scalar(network) or "clearnet"


def _normalize_country_code(code: str) -> str:
    normalized = (code or "").strip().upper()
    if normalized == "UK":
        return "GB"
    return normalized if normalized in _COUNTRY_CODE_TO_NAME else ""


def _country_codes_from_hostname(hostname: str) -> list[str]:
    if not hostname:
        return []
    parts = [part for part in hostname.lower().split(".") if part]
    for part in reversed(parts):
        if len(part) == 2 and part.isalpha():
            code = _normalize_country_code(part)
            if code:
                return [code]
    return []


def _country_codes_from_text(text: str) -> list[str]:
    if not text:
        return []
    normalized = re.sub(r"[^a-z0-9]+", " ", text.lower())
    haystack = f" {normalized} "
    codes = []
    for alias, code in _COUNTRY_ALIASES.items():
        if f" {alias} " in haystack:
            codes.append(code)
    return sorted(set(codes))


def _infer_country_codes(item: dict, raw_data: dict) -> list[str]:
    codes: set[str] = set()

    explicit = [
        _extract_field(raw_data, "country", "m_country", "location", "m_location"),
        _extract_field(item, "source_country", "country", "country_name"),
    ]
    for value in explicit:
        if not value:
            continue
        code = _normalize_country_code(value)
        if code:
            codes.add(code)
        else:
            for inferred in _country_codes_from_text(value):
                codes.add(inferred)

    for candidate in [
        item.get("url"),
        item.get("seed_url"),
        _extract_field(raw_data, "url", "m_url", "base_url", "m_base_url"),
    ]:
        if not candidate:
            continue
        try:
            host = urlparse(candidate).hostname or ""
        except Exception:
            host = ""
        for inferred in _country_codes_from_hostname(host):
            codes.add(inferred)

    source_type = (item.get("source_type") or "").strip().lower()
    if source_type not in {"defacement", "social"}:
        text_blob = " ".join([
            _extract_field(raw_data, "title", "m_title", "description", "m_description"),
            _extract_field(raw_data, "content", "m_content", "important_content", "m_important_content"),
            item.get("title", ""),
            item.get("description", ""),
            item.get("summary", ""),
        ])
        for inferred in _country_codes_from_text(text_blob):
            codes.add(inferred)

    return sorted(codes)


def _feed_sort_key(item: dict) -> tuple[str, str, str]:
    return (
        str(
            item.get("scraped_at")
            or item.get("date")
            or item.get("published_at")
            or item.get("created_at")
            or ""
        ),
        str(item.get("source_type") or ""),
        str(item.get("aid") or item.get("url") or item.get("title") or ""),
    )


def _feed_date_sort_key(item: dict) -> str:
    return (
        item.get("scraped_at")
        or item.get("date")
        or item.get("published_at")
        or item.get("created_at")
        or ""
    )


def _filter_feed_items(items: list[dict], query: str) -> list[dict]:
    needle = _normalize_search_text(query)
    if not needle:
        return items
    terms = _query_search_terms(query)

    scored: list[tuple[int, dict]] = []
    for item in items:
        title_blob = _compose_search_blob(
            item.get("title"),
            item.get("source"),
            item.get("source_label"),
            item.get("source_site"),
            item.get("author"),
            item.get("team"),
            item.get("attacker"),
            item.get("website"),
            item.get("website_host"),
        )
        summary_blob = _compose_search_blob(
            item.get("description"),
            item.get("summary"),
            item.get("ip_addresses"),
            item.get("web_server"),
            item.get("industry"),
            item.get("attack_date"),
            item.get("discovered_at"),
            item.get("country_names"),
        )
        haystack = _compose_search_blob(
            title_blob,
            summary_blob,
            item.get("url"),
            item.get("seed_url"),
            item.get("source_type"),
            item.get("network"),
            item.get("entities"),
            item.get("categories"),
            item.get("evidence_links"),
            item.get("screenshot_links"),
            item.get("mirror_links"),
            item.get("_search_blob"),
            item.get("raw"),
        )

        if not haystack:
            continue

        score = 0
        if needle in haystack:
            score += 120
        if needle in title_blob:
            score += 55
        if needle in summary_blob:
            score += 30

        matched_terms = [term for term in terms if term in haystack]
        unique_matches = list(dict.fromkeys(matched_terms))
        if unique_matches:
            score += len(unique_matches) * 22
            if len(terms) > 1 and len(unique_matches) == len(terms):
                score += 80
            elif len(terms) > 2 and len(unique_matches) >= max(2, len(terms) - 1):
                score += 38

            for term in unique_matches:
                if term in title_blob:
                    score += 18
                if term in summary_blob:
                    score += 10
        elif needle not in haystack:
            continue

        if score > 0:
            scored.append((score, item))

    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [item for _, item in scored]


