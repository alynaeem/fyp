async def _build_map_stats_payload() -> dict:
    leak_items, defacement_items = await asyncio.gather(
        _fetch_threat_items("leak"),
        _fetch_threat_items("defacement"),
    )
    leak_items = sorted(leak_items, key=_feed_sort_key, reverse=True)
    defacement_items = sorted(defacement_items, key=_feed_sort_key, reverse=True)

    bucket: Dict[str, Dict[str, Any]] = {}

    def _append_unique(values: list[str], value: str, limit: int = 4) -> None:
        clean_value = _clean_text(value)
        if not clean_value or clean_value in values or len(values) >= limit:
            return
        values.append(clean_value)

    def _append_example(entry: Dict[str, Any], item: dict[str, Any], max_examples: int = 6) -> None:
        if len(entry["examples"]) >= max_examples:
            return
        aid = _clean_text(item.get("aid"))
        if aid and any(example.get("aid") == aid for example in entry["examples"]):
            return
        entry["examples"].append({
            "aid": aid,
            "title": _clean_text(item.get("title"), fallback="Untitled"),
            "source": _humanize_source_name(item.get("source"), fallback=item.get("source_type", "intel")),
            "source_type": _clean_text(item.get("source_type"), fallback="intel"),
            "date": _clean_text(item.get("scraped_at") or item.get("date")),
        })

    def _touch(code: str) -> Dict[str, Any]:
        if code not in bucket:
            bucket[code] = {
                "code": code,
                "name": _COUNTRY_CODE_TO_NAME.get(code, code),
                "leak_count": 0,
                "defacement_count": 0,
                "total": 0,
                "examples": [],
                "leak_sources": [],
                "defacement_sources": [],
            }
        return bucket[code]

    for item in leak_items:
        for code in item.get("country_codes", []) or []:
            entry = _touch(code)
            entry["leak_count"] += 1
            entry["total"] += 1
            _append_unique(entry["leak_sources"], _humanize_source_name(item.get("source"), fallback="Leak Intel"))
            _append_example(entry, item)

    for item in defacement_items:
        for code in item.get("country_codes", []) or []:
            entry = _touch(code)
            entry["defacement_count"] += 1
            entry["total"] += 1
            _append_unique(entry["defacement_sources"], _humanize_source_name(item.get("source"), fallback="Compromised Intel"))
            _append_example(entry, item)

    countries = sorted(bucket.values(), key=lambda item: (-item["total"], item["name"]))
    return {
        "map_data": {item["code"]: item["total"] for item in countries},
        "countries": countries,
        "summary": {
            "affected_countries": len(countries),
            "leak_items_with_country": sum(1 for item in leak_items if item.get("country_codes")),
            "defacement_items_with_country": sum(1 for item in defacement_items if item.get("country_codes")),
            "updated_at": _utcnow_iso(),
        },
    }


@app.get("/stats/map")
async def get_map_stats():
    """Return country impact data for leaks and defacement items."""
    global _MAP_STATS_INFLIGHT
    cached = _cache_get_map_stats()
    if cached is not None:
        return cached
    if _MAP_STATS_INFLIGHT and not _MAP_STATS_INFLIGHT.done():
        return await _MAP_STATS_INFLIGHT
    _MAP_STATS_INFLIGHT = asyncio.create_task(_build_map_stats_payload())
    try:
        payload = await _MAP_STATS_INFLIGHT
        return _cache_set_map_stats(payload)
    finally:
        if _MAP_STATS_INFLIGHT and _MAP_STATS_INFLIGHT.done():
            _MAP_STATS_INFLIGHT = None


# ── Collection holding raw crawl data (Redis-style KV) ──────────────────────
kv_col = db["redis_kv_store"]

_THREAT_PREFIXES = {
    "EXPLOIT_ITEMS": "exploit",
    "EXPLOIT_ENTITIES": None,
    "LEAK_ITEMS": "leak",
    "LEAK_ENTITIES": None,
    "DEFACEMENT_ITEMS": "defacement",
    "DEFACEMENT_ENTITIES": None,
    "SOCIAL_ITEMS": "social",
    "SOCIAL_ENTITIES": None,
    "API_ITEMS": "api",
    "API_ENTITIES": None,
}

_LEGACY_STATS_PATTERNS = (
    (r"^HACKREAD:", "news"),
    (r"^BLEEPING:", "news"),
    (r"^KREBS:", "news"),
    (r"^THERECORD:", "news"),
    (r"^ACN:", "news"),
    (r"^THN:", "news"),
    (r"^CSO:", "news"),
    (r"^CERTPL:", "exploit"),
    (r"^CERTAT:", "exploit"),
    (r"^CERTCN:", "exploit"),
    (r"^CERTPK:", "exploit"),
    (r"^CERTEU:", "exploit"),
    (r"^CSA:", "exploit"),
    (r"^PORTSWIGGER:", "exploit"),
    (r"^DEFACER:", "defacement"),
    (r"^RAW_LEAK_ITEMS", "leak"),
)

_STORED_RECORD_COLLECTIONS = (
    "agent_state",
    "api_items",
    "articles",
    "automation_state",
    "clean_intel",
    "collector_source_status",
    "credential_datasets",
    "credential_exposures",
    "dashboard_notifications",
    "defacement_entities",
    "defacement_items",
    "exploit_entities",
    "exploit_items",
    "github_scans",
    "healing_events",
    "healing_repairs",
    "healing_runtime",
    "healing_snapshots",
    "healing_targets",
    "intelligence_runs",
    "leak_entities",
    "leak_items",
    "news_entities",
    "news_items",
    "pakdb_lookups",
    "pcgame_scans",
    "redis_kv_store",
    "social_entities",
    "social_items",
)

_FEED_SOURCE_ALIASES = {
    "all": "all",
    "news": "news",
    "exploit": "exploit",
    "leak": "leak",
    "defacement": "defacement",
    "social": "social",
    "api": "api",
    "forums": "social",
    "marketplaces": "leak",
    "github": "api",
    "apk": "api",
}

_COUNTRY_CODE_TO_NAME = {
    "AE": "United Arab Emirates",
    "AR": "Argentina",
    "AT": "Austria",
    "AU": "Australia",
    "BD": "Bangladesh",
    "BE": "Belgium",
    "BR": "Brazil",
    "CA": "Canada",
    "CH": "Switzerland",
    "CL": "Chile",
    "CN": "China",
    "CO": "Colombia",
    "CZ": "Czech Republic",
    "DE": "Germany",
    "DK": "Denmark",
    "EG": "Egypt",
    "ES": "Spain",
    "FI": "Finland",
    "FR": "France",
    "GB": "United Kingdom",
    "GR": "Greece",
    "HU": "Hungary",
    "ID": "Indonesia",
    "IE": "Ireland",
    "IL": "Israel",
    "IN": "India",
    "IQ": "Iraq",
    "IR": "Iran",
    "IT": "Italy",
    "JP": "Japan",
    "KE": "Kenya",
    "KR": "South Korea",
    "LK": "Sri Lanka",
    "MX": "Mexico",
    "MY": "Malaysia",
    "NG": "Nigeria",
    "NL": "Netherlands",
    "NO": "Norway",
    "NZ": "New Zealand",
    "PH": "Philippines",
    "PK": "Pakistan",
    "PL": "Poland",
    "PT": "Portugal",
    "RO": "Romania",
    "RU": "Russia",
    "SA": "Saudi Arabia",
    "SE": "Sweden",
    "SG": "Singapore",
    "TH": "Thailand",
    "TR": "Turkey",
    "UA": "Ukraine",
    "US": "United States",
    "VN": "Vietnam",
    "ZA": "South Africa",
}

_COUNTRY_ALIASES = {
    "united states": "US",
    "u s": "US",
    "usa": "US",
    "united kingdom": "GB",
    "great britain": "GB",
    "uk": "GB",
    "england": "GB",
    "australia": "AU",
    "austria": "AT",
    "bangladesh": "BD",
    "belgium": "BE",
    "brazil": "BR",
    "canada": "CA",
    "switzerland": "CH",
    "chile": "CL",
    "china": "CN",
    "colombia": "CO",
    "czech republic": "CZ",
    "germany": "DE",
    "denmark": "DK",
    "egypt": "EG",
    "spain": "ES",
    "finland": "FI",
    "france": "FR",
    "greece": "GR",
    "hungary": "HU",
    "indonesia": "ID",
    "ireland": "IE",
    "israel": "IL",
    "india": "IN",
    "iraq": "IQ",
    "iran": "IR",
    "italy": "IT",
    "japan": "JP",
    "kenya": "KE",
    "south korea": "KR",
    "korea": "KR",
    "sri lanka": "LK",
    "mexico": "MX",
    "malaysia": "MY",
    "nigeria": "NG",
    "netherlands": "NL",
    "norway": "NO",
    "new zealand": "NZ",
    "philippines": "PH",
    "pakistan": "PK",
    "poland": "PL",
    "portugal": "PT",
    "romania": "RO",
    "russia": "RU",
    "saudi arabia": "SA",
    "sweden": "SE",
    "singapore": "SG",
    "thailand": "TH",
    "turkey": "TR",
    "ukraine": "UA",
    "vietnam": "VN",
    "south africa": "ZA",
}


def _canonical_source_type(source_type: str) -> str:
    normalized = (source_type or "all").strip().lower()
    return _FEED_SOURCE_ALIASES.get(normalized, normalized)


def _coerce_datetime_string(value: Any) -> str:
    if value in (None, "", []):
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (int, float)):
        timestamp = float(value)
        if timestamp > 1_000_000_000_000:
            timestamp /= 1000.0
        try:
            return datetime.utcfromtimestamp(timestamp).isoformat() + "Z"
        except Exception:
            return str(value)
    if isinstance(value, str):
        cleaned = value.strip()
        if cleaned.isdigit():
            return _coerce_datetime_string(int(cleaned))
        return cleaned
    return str(value)


def _coerce_scalar(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, list):
        values = [str(item) for item in value if item not in (None, "", [])]
        return ", ".join(values)
    if isinstance(value, dict):
        return str(value.get("type") or value.get("value") or "")
    return str(value)


def _coerce_list(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item not in (None, "", [])]
    return [str(value)]


_PLACEHOLDER_TITLES = {"", "(no title)", "untitled", "unknown"}
_PLACEHOLDER_DESCRIPTIONS = {"", "content not found.", "no description available.", "summary unavailable."}
_SOURCE_LABEL_ALIASES = {
    "thehackernews": "thehackernews.com",
    "_thehackernews": "thehackernews.com",
    "ransomware_live": "ransomware.live",
    "_ransomware_live": "ransomware.live",
    "tweetfeed": "tweetfeed.live",
    "_tweetfeed": "tweetfeed.live",
    "zone_xsec": "zone-xsec.com",
    "_zone_xsec": "zone-xsec.com",
}


def _clean_text_candidate(value: Any) -> str:
    return re.sub(r"\s+", " ", _coerce_scalar(value).strip())


def _meaningful_title(value: Any) -> str:
    text = _clean_text_candidate(value)
    return "" if text.lower() in _PLACEHOLDER_TITLES else text


def _meaningful_description(value: Any) -> str:
    text = _clean_text_candidate(value)
    return "" if text.lower() in _PLACEHOLDER_DESCRIPTIONS else text


def _excerpt_text(value: Any, limit: int = 400) -> str:
    text = _clean_text_candidate(value)
    if not text:
        return ""
    if len(text) <= limit:
        return text
    clipped = text[:limit].rsplit(" ", 1)[0].strip() or text[:limit].strip()
    if clipped.endswith(("...", "…")):
        return clipped
    return f"{clipped}..."


def _extract_hostname(value: Any) -> str:
    text = _clean_text_candidate(value)
    if not text:
        return ""
    try:
        parsed = urlparse(text)
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def _normalize_source_label(value: Any) -> str:
    text = _clean_text_candidate(value)
    if not text:
        return ""
    lowered = text.lower()
    if lowered in _SOURCE_LABEL_ALIASES:
        return _SOURCE_LABEL_ALIASES[lowered]
    if lowered.startswith("www."):
        return lowered
    if "." in lowered:
        return lowered
    return text.lstrip("_").replace("__", "_").replace("_", " ").strip()


def _title_from_url(value: Any) -> str:
    text = _clean_text_candidate(value)
    if not text:
        return ""
    try:
        parsed = urlparse(text)
        slug = unquote((parsed.path or "").rstrip("/").rsplit("/", 1)[-1])
        slug = re.sub(r"\.[A-Za-z0-9]+$", "", slug)
        slug = re.sub(r"^\d{4}-\d{2}-\d{2}-", "", slug)
        slug = slug.replace("-", " ").replace("_", " ").strip()
        if not slug:
            slug = parsed.hostname or ""
        parts = [part for part in slug.split() if part]
        if not parts:
            return ""
        return " ".join(part.upper() if part.isupper() else part.capitalize() for part in parts)
    except Exception:
        return ""


def _unwrap_redirect_url(value: Any) -> str:
    text = _clean_text_candidate(value)
    if not text:
        return ""
    try:
        parsed = urlparse(text)
        params = parse_qs(parsed.query)
        for key in ("q", "url", "u", "target"):
            for candidate in params.get(key, []):
                candidate = unquote(str(candidate or "").strip())
                if candidate.startswith(("http://", "https://")):
                    return candidate
    except Exception:
        return text
    return text


_IP_ADDRESS_RE = re.compile(
    r"(?<![\w:])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w:])"
)
_IMG_SRC_RE = re.compile(r"<img[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        if text in seen:
            continue
        seen.add(text)
        deduped.append(text)
    return deduped


