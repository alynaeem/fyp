def _parse_kv_item(doc: dict, include_raw: bool = False, entity_doc: dict | None = None) -> dict | None:
    raw = doc.get("value", "")
    if not raw or not isinstance(raw, str):
        return None
    try:
        data = json.loads(raw)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None

    entity_data: dict | None = None
    if entity_doc:
        entity_raw = entity_doc.get("value", "")
        if isinstance(entity_raw, str) and entity_raw:
            try:
                loaded = json.loads(entity_raw)
                if isinstance(loaded, dict):
                    entity_data = loaded
            except Exception:
                entity_data = None

    merged = _merge_threat_payloads(data, entity_data)
    return _build_threat_item(str(doc.get("_id", "")), merged, include_raw=include_raw)


def _news_merge_key(item: dict) -> str:
    return str(item.get("url") or item.get("aid") or item.get("seed_url") or "")


def _news_item_score(item: dict) -> int:
    score = 0
    if _meaningful_title(item.get("title")):
        score += 5
    if _meaningful_description(item.get("description")):
        score += 4
    if _meaningful_description(item.get("summary")):
        score += 2
    if _clean_text_candidate(item.get("author")):
        score += 1
    if _clean_text_candidate(item.get("source")):
        score += 1
    if item.get("screenshot"):
        score += 1
    if item.get("entities"):
        score += 1
    return score


async def _fetch_news_items(include_raw: bool = False) -> list[dict]:
    cache_key = ("news", include_raw)
    if not include_raw:
        cached = _cache_get_feed_items(cache_key)
        if cached is not None:
            return cached

    processed_docs = await articles_col.find(_visible_news_query()).to_list(length=None)
    raw_docs = await news_items_col.find(_visible_news_query()).to_list(length=None) if include_raw else []

    merged: dict[str, dict] = {}
    for doc in processed_docs + raw_docs:
        if _is_blocked_article_doc(doc):
            continue
        item = _build_article_item(doc, include_raw=include_raw)
        key = _news_merge_key(item)
        if not key:
            continue
        existing = merged.get(key)
        if not existing or _news_item_score(item) >= _news_item_score(existing):
            merged[key] = item

    items = sorted(merged.values(), key=_feed_sort_key, reverse=True)
    return _cache_set_feed_items(cache_key, items) if not include_raw else items


async def _fetch_news_page(limit: int, offset: int) -> tuple[int, list[dict]]:
    try:
        total_future = asyncio.ensure_future(articles_col.estimated_document_count())
    except Exception:
        total_future = asyncio.ensure_future(articles_col.count_documents({}))
    safe_limit = max(min(int(limit or 30), 500), 1)
    safe_offset = max(int(offset or 0), 0)
    candidates: list[dict] = []
    seen_keys: set[str] = set()
    scanned = 0
    batch_limit = min(max(safe_limit * 6, 180), 300)
    max_scan = max((safe_offset + safe_limit) * 24, 8000)
    while scanned < max_scan:
        docs = await (
            articles_col.find({}, _NEWS_FEED_PROJECTION)
            .sort([("$natural", -1)])
            .skip(scanned)
            .limit(batch_limit)
            .to_list(length=batch_limit)
        )
        if not docs:
            break
        scanned += len(docs)
        for doc in docs:
            if _is_blocked_article_doc(doc):
                continue
            item = _build_article_item(doc, include_raw=False)
            dedupe_key = _news_merge_key(item).strip().lower()
            if not dedupe_key or dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)
            candidates.append(item)
    items = sorted(candidates, key=_feed_sort_key, reverse=True)[safe_offset:safe_offset + safe_limit]
    total = await total_future
    return total, items


async def _search_news_items(query: str, include_raw: bool = False, limit: int = SEARCH_CANDIDATE_LIMIT) -> list[dict]:
    search_filter = _build_mongo_text_search(
        query,
        [
            "title",
            "description",
            "summary",
            "content",
            "url",
            "seed_url",
            "source",
            "source_name",
            "author",
            "writer",
        ],
    )
    if not search_filter:
        return []

    cursor = (
        articles_col.find(_visible_news_query(search_filter))
        .sort([
            ("scraped_at", -1),
            ("date", -1),
            ("published_at", -1),
            ("_id", -1),
        ])
        .limit(limit)
    )
    docs = await cursor.to_list(length=limit)
    return [_build_article_item(doc, include_raw=include_raw) for doc in docs if not _is_blocked_article_doc(doc)]


async def _find_news_doc(aid: str) -> dict | None:
    queries = [{"_id": aid}, {"aid": aid}, {"dedupe_key": aid}]
    for collection in (articles_col, news_items_col):
        for query in queries:
            doc = await collection.find_one(query)
            if doc:
                return doc
    return None


async def _search_threat_items(query: str, source_type: str = "", include_raw: bool = False, limit: int = SEARCH_CANDIDATE_LIMIT) -> list[dict]:
    prefixes = [prefix for prefix, category in _THREAT_PREFIXES.items() if category is not None]
    if source_type:
        prefixes = [prefix for prefix, category in _THREAT_PREFIXES.items() if category == source_type]
        if not prefixes:
            return []

    regex_pattern = "^(" + "|".join(prefixes) + "):"
    search_filter = _build_mongo_text_search(query, ["value", "_id"])
    query_doc: dict[str, Any] = {"_id": {"$regex": regex_pattern}}
    if search_filter:
        query_doc = {"$and": [query_doc, search_filter]}

    docs = await kv_col.find(query_doc).sort([("_id", -1)]).limit(limit).to_list(length=limit)
    suffixes = []
    for doc in docs:
        doc_id = str(doc.get("_id", ""))
        suffixes.append(doc_id.split(":", 1)[1] if ":" in doc_id else doc_id)

    entity_docs: list[dict] = []
    if suffixes:
        entity_ids = []
        for prefix in prefixes:
            entity_prefix = prefix.replace("_ITEMS", "_ENTITIES")
            entity_ids.extend([f"{entity_prefix}:{suffix}" for suffix in suffixes])
        entity_docs = await kv_col.find({"_id": {"$in": entity_ids}}).to_list(length=None)

    entity_map: dict[str, dict] = {}
    for entity_doc in entity_docs:
        entity_id = str(entity_doc.get("_id", ""))
        if ":" not in entity_id:
            continue
        entity_map[entity_id.split(":", 1)[1]] = entity_doc

    items = []
    for doc in docs:
        doc_id = str(doc.get("_id", ""))
        suffix = doc_id.split(":", 1)[1] if ":" in doc_id else doc_id
        parsed = _parse_kv_item(doc, include_raw=include_raw, entity_doc=entity_map.get(suffix))
        if parsed:
            items.append(parsed)
    return items


async def _count_threat_items(source_type: str = "") -> int:
    prefixes = [prefix for prefix, category in _THREAT_PREFIXES.items() if category is not None]
    if source_type:
        prefixes = [prefix for prefix, category in _THREAT_PREFIXES.items() if category == source_type]
        if not prefixes:
            return 0
    regex_pattern = "^(" + "|".join(prefixes) + "):"
    return await kv_col.count_documents({"_id": {"$regex": regex_pattern}})


async def _fetch_threat_items(source_type: str = "", include_raw: bool = False) -> list[dict]:
    cache_key = (f"threat:{source_type or 'all'}", include_raw)
    if not include_raw:
        cached = _cache_get_feed_items(cache_key)
        if cached is not None:
            return cached

    prefixes = [prefix for prefix, category in _THREAT_PREFIXES.items() if category is not None]
    if source_type:
        prefixes = [prefix for prefix, category in _THREAT_PREFIXES.items() if category == source_type]
        if not prefixes:
            return []

    entity_prefixes = [prefix.replace("_ITEMS", "_ENTITIES") for prefix in prefixes]
    regex_pattern = "^(" + "|".join(prefixes) + "):"
    entity_regex_pattern = "^(" + "|".join(entity_prefixes) + "):"

    docs = await kv_col.find({"_id": {"$regex": regex_pattern}}).to_list(length=None)
    entity_docs = await kv_col.find({"_id": {"$regex": entity_regex_pattern}}).to_list(length=None)
    entity_map: dict[str, dict] = {}
    for entity_doc in entity_docs:
        entity_id = str(entity_doc.get("_id", ""))
        if ":" not in entity_id:
            continue
        entity_map[entity_id.split(":", 1)[1]] = entity_doc

    items = []
    for doc in docs:
        doc_id = str(doc.get("_id", ""))
        suffix = doc_id.split(":", 1)[1] if ":" in doc_id else doc_id
        parsed = _parse_kv_item(doc, include_raw=include_raw, entity_doc=entity_map.get(suffix))
        if parsed:
            items.append(parsed)
    items = sorted(items, key=_feed_sort_key, reverse=True)
    return _cache_set_feed_items(cache_key, items) if not include_raw else items


async def _fetch_threat_page(source_type: str, limit: int, offset: int, *, include_total: bool = True) -> tuple[int, list[dict]]:
    prefixes = [prefix for prefix, category in _THREAT_PREFIXES.items() if category == source_type]
    if not prefixes:
        return 0, []

    regex_pattern = "^(" + "|".join(prefixes) + "):"
    query_doc = {"_id": {"$regex": regex_pattern}}
    total_task = asyncio.ensure_future(kv_col.count_documents(query_doc)) if include_total else None
    docs = await (
        kv_col.find(query_doc, _THREAT_FEED_PROJECTION)
        .sort([("_id", -1)])
        .skip(offset)
        .limit(limit)
        .to_list(length=limit)
    )

    suffixes = []
    for doc in docs:
        doc_id = str(doc.get("_id", ""))
        suffixes.append(doc_id.split(":", 1)[1] if ":" in doc_id else doc_id)

    entity_map: dict[str, dict] = {}
    if suffixes:
        entity_ids = []
        for prefix in prefixes:
            entity_prefix = prefix.replace("_ITEMS", "_ENTITIES")
            entity_ids.extend([f"{entity_prefix}:{suffix}" for suffix in suffixes])
        entity_docs = await kv_col.find({"_id": {"$in": entity_ids}}, _THREAT_FEED_PROJECTION).to_list(length=None)
        for entity_doc in entity_docs:
            entity_id = str(entity_doc.get("_id", ""))
            if ":" in entity_id:
                entity_map[entity_id.split(":", 1)[1]] = entity_doc

    items = []
    for doc in docs:
        doc_id = str(doc.get("_id", ""))
        suffix = doc_id.split(":", 1)[1] if ":" in doc_id else doc_id
        parsed = _parse_kv_item(doc, include_raw=False, entity_doc=entity_map.get(suffix))
        if parsed:
            items.append(parsed)

    items = sorted(items, key=_feed_sort_key, reverse=True)
    total = await total_task if total_task else 0
    return total, items


def _cached_feed_total() -> int:
    cached_stats = _cache_get_stats()
    if not cached_stats:
        return 0
    counts = cached_stats.get("counts") if isinstance(cached_stats.get("counts"), dict) else cached_stats
    try:
        return int(counts.get("display_total") or counts.get("total") or 0)
    except Exception:
        return 0


async def _feed_total_from_stats() -> int:
    total = _cached_feed_total()
    if total:
        return total
    try:
        stats_payload = await stats()
        counts = stats_payload.get("counts") if isinstance(stats_payload.get("counts"), dict) else stats_payload
        return int(counts.get("display_total") or counts.get("total") or 0)
    except Exception:
        return 0


async def _fetch_combined_feed_page(limit: int, offset: int) -> tuple[int, list[dict]]:
    safe_limit = max(min(int(limit or 30), 500), 1)
    safe_offset = max(int(offset or 0), 0)
    source_types = ("leak", "defacement", "exploit", "social", "api")

    # Keep the dashboard path page-sized. The older all-feed route built every
    # item first, which made the first paint wait on tens of thousands of docs.
    if safe_offset <= 900:
        candidate_limit = 1000
        source_offset = 0
        slice_offset = safe_offset
    else:
        candidate_limit = min(max(safe_limit, 30), 80)
        source_offset = max((safe_offset // (len(source_types) + 1)) - safe_limit, 0)
        slice_offset = 0

    results = await asyncio.gather(
        _fetch_news_page(candidate_limit, source_offset),
        *[
            _fetch_threat_page(source_type, candidate_limit, source_offset, include_total=False)
            for source_type in source_types
        ],
    )

    candidates: list[dict] = []
    for _source_total, source_items in results:
        candidates.extend(source_items)

    candidates = sorted(candidates, key=_feed_sort_key, reverse=True)
    total = await _feed_total_from_stats()
    total = total or max(len(candidates), safe_offset + len(candidates))
    return total, candidates[slice_offset:slice_offset + safe_limit]


async def _fetch_combined_feed_items(include_raw: bool = False) -> list[dict]:
    cache_key = ("feed:all", include_raw)
    if not include_raw:
        cached = _cache_get_feed_items(cache_key)
        if cached is not None:
            return cached

    news_items, threat_items = await asyncio.gather(
        _fetch_news_items(include_raw=include_raw),
        _fetch_threat_items(include_raw=include_raw),
    )
    items = sorted(news_items + threat_items, key=_feed_sort_key, reverse=True)
    return _cache_set_feed_items(cache_key, items) if not include_raw else items


@app.get("/news")
async def list_news(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    q: str = Query(""),
    include_raw: bool = Query(False),
):
    if not q and not include_raw:
        total, items = await _fetch_news_page(limit, offset)
        payload = {
            "total": total,
            "offset": offset,
            "limit": limit,
            "items": [_public_feed_item(item) for item in items],
        }
        payload["news"] = payload["items"]
        return payload

    if q:
        items = await _search_news_items(q, include_raw=include_raw)
        items = sorted(items, key=_feed_sort_key, reverse=True)
        items = _filter_feed_items(items, q)
    else:
        items = await _fetch_news_items(include_raw=include_raw)
        items = sorted(items, key=_feed_sort_key, reverse=True)
    payload = {
        "total": len(items),
        "offset": offset,
        "limit": limit,
        "items": [_public_feed_item(item) for item in items[offset:offset + limit]],
    }
    payload["news"] = payload["items"]
    return payload


@app.get("/news/{aid}")
async def get_news(aid: str):
    doc = await _find_news_doc(aid)
    if not doc:
        raise HTTPException(status_code=404, detail="Article not found")
    item = _build_article_item(doc, include_raw=True)
    public_item = _public_feed_item(item)
    return {"article": public_item, **public_item}


@app.get("/search/semantic")
async def semantic_search(
    q: str = Query(..., min_length=2),
    limit: int = Query(8, ge=1, le=30),
):
    query = (q or "").strip()
    cache_key = (query.lower(), limit)
    cached = _cache_get_semantic_search(cache_key)
    if cached is not None:
        return cached
    news_items, threat_items = await asyncio.gather(
        _search_news_items(query, include_raw=False, limit=max(limit * 4, 40)),
        _search_threat_items(query, include_raw=False, limit=max(limit * 6, 60)),
    )
    ranked_items = sorted(
        _filter_feed_items(news_items + threat_items, query),
        key=_feed_sort_key,
        reverse=True,
    )

    source_counts: dict[str, int] = {}
    for item in ranked_items[:120]:
        source_key = _canonical_source_type(item.get("source_type") or "all")
        source_counts[source_key] = source_counts.get(source_key, 0) + 1

    suggested_view = "all"
    if source_counts:
        dominant_source, dominant_count = max(source_counts.items(), key=lambda pair: pair[1])
        total_matches = sum(source_counts.values())
        if dominant_source != "all" and dominant_count >= 3 and dominant_count / max(total_matches, 1) >= 0.45:
            suggested_view = dominant_source

    return _cache_set_semantic_search(cache_key, {
        "status": "ok",
        "query": query,
        "total": len(ranked_items),
        "matched_terms": _query_search_terms(query),
        "suggested_view": suggested_view,
        "source_counts": source_counts,
        "top_matches": [_public_feed_item(item) for item in ranked_items[:limit]],
    })


