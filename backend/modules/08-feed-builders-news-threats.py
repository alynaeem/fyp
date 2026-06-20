def _parse_feed_filter_date(value: str) -> date | None:
    text = (value or "").strip()
    if not text:
        return None
    try:
        if re.match(r"^\d{4}-\d{2}-\d{2}$", text):
            return datetime.strptime(text, "%Y-%m-%d").date()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text).date()
    except Exception:
        return None


def _item_effective_date(item: dict) -> date | None:
    for field in ("date", "scraped_at", "published_at", "attack_date", "discovered_at", "collected_at", "created_at"):
        parsed = _parse_feed_filter_date(str(item.get(field) or ""))
        if parsed:
            return parsed
    return None


def _apply_feed_filters(
    items: list[dict],
    topic: str = "",
    start_date: str = "",
    end_date: str = "",
    network: str = "",
) -> list[dict]:
    normalized_topic = _normalize_search_text(topic)
    start_bound = _parse_feed_filter_date(start_date)
    end_bound = _parse_feed_filter_date(end_date)
    normalized_network = (network or "").strip().lower()

    if not normalized_topic and not start_bound and not end_bound and not normalized_network:
        return items

    filtered: list[dict] = []
    for item in items:
        if normalized_network:
            item_network = str(item.get("network") or "").strip().lower()
            item_url_blob = " ".join(
                str(item.get(field) or "")
                for field in ("url", "link", "source_url", "weblink", "m_url", "app_url")
            ).lower()
            is_onion = item_network in {"onion", "tor", "darkweb", "dark_web"} or ".onion" in item_url_blob
            if normalized_network == "onion" and not is_onion:
                continue
            if normalized_network == "clearnet" and is_onion:
                continue

        if normalized_topic:
            haystack = _compose_search_blob(
                item.get("title"),
                item.get("description"),
                item.get("summary"),
                item.get("top_tag"),
                item.get("source_type"),
                item.get("categories"),
                item.get("entities"),
                item.get("attacker"),
                item.get("team"),
                item.get("source"),
            )
            if normalized_topic not in haystack:
                continue

        effective_date = _item_effective_date(item)
        if start_bound and (not effective_date or effective_date < start_bound):
            continue
        if end_bound and (not effective_date or effective_date > end_bound):
            continue

        filtered.append(item)

    return filtered


def _build_ai_summary(item: dict) -> str:
    source_label = (
        _clean_text(item.get("source_label"))
        or _clean_text(item.get("source_site"))
        or _clean_text(item.get("source"))
        or "the monitored source"
    )
    source_type = (_clean_text(item.get("source_type")) or "intelligence").replace("_", " ")
    topic_labels = [
        _clean_text(category.get("label"))
        for category in (item.get("categories") or [])
        if isinstance(category, dict) and _clean_text(category.get("label"))
    ]
    topic_labels = list(dict.fromkeys(topic_labels))
    entity_labels = [
        _clean_text(entity.get("text"))
        for entity in (item.get("entities") or [])
        if isinstance(entity, dict) and _clean_text(entity.get("text"))
    ]
    entity_labels = list(dict.fromkeys(entity_labels))
    geography = ", ".join((item.get("country_names") or [])[:2])
    base_summary = (
        _meaningful_description(item.get("summary"))
        or _meaningful_description(item.get("description"))
        or _clean_text(item.get("title"))
        or "No summary is available for this record."
    )
    base_summary = _excerpt_text(base_summary) or base_summary
    if base_summary and not re.search(r"[.!?]$", base_summary):
        base_summary = f"{base_summary}."

    if topic_labels:
        topic_line = f"This {source_type} item from {source_label} focuses on {', '.join(topic_labels[:3])}."
    else:
        topic_line = f"This {source_type} item from {source_label} highlights the reported activity."

    context_bits = []
    if entity_labels:
        context_bits.append(f"Key entities include {', '.join(entity_labels[:3])}")
    if geography:
        context_bits.append(f"geography points to {geography}")
    if _clean_text(item.get('attacker')):
        context_bits.append(f"the named attacker is {_clean_text(item.get('attacker'))}")
    elif _clean_text(item.get('team')):
        context_bits.append(f"the named team is {_clean_text(item.get('team'))}")

    context_line = ""
    if context_bits:
        context_line = " " + context_bits[0][0].upper() + context_bits[0][1:]
        if len(context_bits) > 1:
            context_line += "; " + "; ".join(context_bits[1:])
        context_line += "."

    return f"{topic_line} {base_summary}{context_line}".strip()


def _public_feed_item(item: dict) -> dict:
    sanitized = dict(item)
    for key in (
        "_search_blob",
        "content",
        "raw_text_snippet",
        "embedding",
        "raw",
        "content_html",
        "m_content",
        "m_ref_html",
        "ref_html",
    ):
        sanitized.pop(key, None)
    aid = str(sanitized.get("aid") or "")
    for image_key in ("screenshot", "hero_image", "og_image"):
        value = str(sanitized.get(image_key) or "")
        if aid and len(value) > 2000 and not value.startswith(("http://", "https://", "/")):
            sanitized[image_key] = f"/feed-screenshot?aid={quote(aid)}"
    screenshot_links = sanitized.get("screenshot_links")
    if aid and isinstance(screenshot_links, list):
        sanitized["screenshot_links"] = [
            f"/feed-screenshot?aid={quote(aid)}" if len(str(link or "")) > 2000 and not str(link).startswith(("http://", "https://", "/")) else link
            for link in screenshot_links[:4]
        ]
    return sanitized


def _build_article_item(doc: dict, include_raw: bool = False) -> dict:
    raw_doc = dict(doc)
    item = dict(doc)
    item["aid"] = str(item.get("aid") or item.get("dedupe_key") or item.get("_id", ""))
    item.pop("_id", None)

    item["url"] = item.get("url") or _extract_field(raw_doc, "m_url", "url", "m_weblink", "weblink", "m_dumplink", "dumplink")
    item["seed_url"] = item.get("seed_url") or _extract_field(raw_doc, "seed_url", "m_base_url", "base_url", "m_source_url")

    fallback_title = _title_from_url(item["url"] or item["seed_url"])
    item["title"] = (
        _meaningful_title(item.get("title"))
        or _meaningful_title(_extract_field(raw_doc, "m_title", "title", "headline", "name"))
        or fallback_title
        or "Untitled"
    )

    item["description"] = (
        _meaningful_description(item.get("description"))
        or _meaningful_description(_extract_field(raw_doc, "description", "m_description", "m_important_content", "important_content"))
        or _excerpt_text(_extract_field(raw_doc, "summary", "m_important_content", "important_content", "m_content", "content"))
        or f"Intelligence captured from {_extract_hostname(item['url'] or item['seed_url']) or 'the monitored source'}."
    )
    item["summary"] = (
        _meaningful_description(item.get("summary"))
        or _excerpt_text(_extract_field(raw_doc, "summary", "m_important_content", "important_content", "m_content", "content"))
        or item["description"]
    )[:900]

    categories = item.get("categories", [])
    if not categories:
        categories = [{"label": label, "score": 0.8} for label in _extract_values(raw_doc, "m_content_type", "content_type")]
        item["categories"] = categories
    if categories:
        categories_sorted = sorted(categories, key=lambda x: x.get("score", 0), reverse=True)
        item["top_tag"] = categories_sorted[0].get("label", "")
    else:
        item["top_tag"] = ""

    item["source_type"] = (item.get("source_type") or "news").lower()
    item["author"] = item.get("author") or item.get("writer") or _extract_field(raw_doc, "m_author", "author", "writer")
    item["source_site"] = (
        _extract_hostname(item["url"])
        or _extract_hostname(item["seed_url"])
        or _extract_hostname(_extract_field(raw_doc, "m_base_url", "base_url", "source_url"))
    )
    item["source_label"] = (
        _normalize_source_label(item.get("source_name"))
        or _normalize_source_label(_extract_field(raw_doc, "source_name", "m_source", "m_scrap_file"))
        or item["source_site"]
        or "news"
    )
    item["source"] = (
        _normalize_source_label(item.get("source"))
        or item["source_site"]
        or item["source_label"]
    )
    item["scraped_at"] = _coerce_datetime_string(item.get("scraped_at") or item.get("date"))
    item["date"] = _coerce_datetime_string(item.get("date") or item.get("scraped_at"))
    item["published_at"] = item["date"]
    item["entities"] = _normalize_entities(item.get("entities") or raw_doc.get("entities") or raw_doc.get("m_entities"))
    item["network"] = item.get("network", {}).get("type") if isinstance(item.get("network"), dict) else item.get("network", "clearnet")
    item["ip_addresses"] = _extract_ip_addresses(raw_doc)
    item["attacker"] = _extract_field(raw_doc, "m_attacker", "attacker")
    item["team"] = _extract_field(raw_doc, "m_team", "team", "m_sender_name", "m_username")
    item["web_server"] = _extract_field(raw_doc, "m_web_server", "web_server")
    item["screenshot"] = _extract_primary_screenshot(raw_doc)
    item["screenshot_links"] = _extract_screenshot_links(raw_doc)
    item["evidence_links"] = _extract_evidence_links(raw_doc)
    item["website"] = _extract_field(raw_doc, "website", "domain")
    item["website_host"] = _extract_hostname(item["website"])
    item["country_codes"] = _infer_country_codes(item, raw_doc)
    item["country_names"] = [_COUNTRY_CODE_TO_NAME[code] for code in item["country_codes"]]
    item["ai_summary"] = _build_ai_summary(item)
    item["_search_blob"] = _compose_search_blob(
        item["title"],
        item["description"],
        item["summary"],
        item["url"],
        item["seed_url"],
        item["source"],
        item["source_label"],
        item["source_site"],
        item["author"],
        item["network"],
        item["ip_addresses"],
        item["attacker"],
        item["team"],
        item["web_server"],
        item["website"],
        item["website_host"],
        item["country_names"],
        item["entities"],
        item["categories"],
        item["evidence_links"],
        item["screenshot_links"],
        _extract_field(raw_doc, "summary", "m_important_content", "important_content", "m_content", "content", "body", "text"),
    )
    if include_raw:
        if "_id" in raw_doc:
            raw_doc["_id"] = str(raw_doc["_id"])
        item["raw"] = raw_doc
    return item


def _build_threat_item(key: str, data: dict, include_raw: bool = False) -> dict | None:
    source_cat = "threat"
    for prefix, category in _THREAT_PREFIXES.items():
        if key.startswith(prefix):
            if category is None:
                return None
            source_cat = category
            break

    title = _extract_field(
        data,
        "m_title",
        "title",
        "m_name",
        "m_company_name",
        "m_app_name",
        "m_important_content",
        "important_content",
    )
    raw_url = _extract_field(
        data,
        "m_url",
        "url",
        "m_app_url",
        "m_message_sharable_link",
        "m_channel_url",
        "m_weblink",
        "weblink",
    )
    if not raw_url:
        evidence_links = _extract_evidence_links(data)
        raw_url = evidence_links[0] if evidence_links else ""
    if not raw_url:
        links = (
            data.get("m_weblink")
            or data.get("weblink")
            or data.get("links")
            or data.get("m_links")
            or []
        )
        raw_url = _coerce_list(links)[0] if _coerce_list(links) else ""

    raw_url = _unwrap_redirect_url(raw_url) or raw_url
    if raw_url and _clean_text_candidate(title).lower() in {"", "url", "website", "target", "untitled", "unknown"}:
        title = _title_from_url(raw_url) or _extract_hostname(raw_url) or raw_url
    if not title and raw_url:
        title = _title_from_url(raw_url) or _extract_hostname(raw_url) or raw_url
    if not title:
        title = "Untitled"

    content = _extract_field(
        data,
        "m_content",
        "content",
        "m_description",
        "description",
        "m_important_content",
        "important_content",
        "m_ref_html",
    )
    source_name = _extract_field(data, "source_name", "m_source", "m_scrap_file", "m_platform", "m_sender_name") or source_cat
    source_label = _normalize_source_label(source_name) or source_cat
    network = _extract_network(data)
    date_value = _coerce_datetime_string(_extract_field(data, "m_leak_date", "leak_date", "m_message_date", "m_exploit_year", "m_latest_date", "m_date"))
    seed_url = _extract_field(data, "m_base_url", "base_url", "m_source_url", "m_channel_url")
    website = _extract_field(data, "website", "m_website", "m_domain", "domain", "m_target_domain", "target_domain")
    website_host = _extract_hostname(website)
    source_site = _extract_hostname(seed_url) or _extract_hostname(_extract_field(data, "m_source_url", "source_url")) or _extract_hostname(raw_url)
    discovered_at = _coerce_datetime_string(_extract_field(data, "discovered_at", "m_discovered_at"))
    attack_date = _coerce_datetime_string(_extract_field(data, "attack_date", "m_attack_date"))
    industry = _extract_field(data, "industry", "m_industry", "sector", "m_sector")
    collected_at = _coerce_datetime_string(_extract_field(data, "collected_at", "m_collected_at", "updated_at"))
    author = _extract_field(data, "m_actor", "m_sender_name", "m_author", "author", "m_username")
    ip_addresses = _extract_ip_addresses(data)
    attacker = _extract_field(data, "m_attacker", "attacker")
    team = _extract_field(data, "m_team", "team", "m_username")
    web_server = _extract_field(data, "m_web_server", "web_server")
    screenshot = _extract_primary_screenshot(data)
    screenshot_links = _extract_screenshot_links(data)
    evidence_links = _extract_evidence_links(data)
    mirror_links = _extract_values(data, "m_mirror_links", "mirror_links")

    content_types = _extract_values(data, "m_ioc_type", "content_type", "m_content_type", "m_section", "m_sections")
    categories = [{"label": source_cat, "score": 1.0}]
    for label in content_types:
        if label and label != source_cat:
            categories.append({"label": label, "score": 0.75})

    summary_text = (
        _meaningful_description(_extract_field(data, "m_description", "description", "m_important_content", "important_content"))
        or _excerpt_text(content)
        or title
    )
    description_parts = [summary_text] if summary_text else []
    summary_lower = summary_text.lower()
    if ip_addresses and ip_addresses.lower() not in summary_lower:
        description_parts.append(f"IP: {ip_addresses}")
    if attacker and attacker.lower() not in summary_lower:
        description_parts.append(f"Attacker: {attacker}")
    if team and team.lower() not in summary_lower:
        description_parts.append(f"Team: {team}")
    if website_host and website_host.lower() not in summary_lower:
        description_parts.append(f"Website: {website_host}")
    if web_server and web_server.lower() not in summary_lower:
        description_parts.append(f"Server: {web_server}")
    if content_types:
        type_text = ", ".join(content_types)
        if type_text.lower() not in summary_lower:
            description_parts.append(f"Type: {type_text}")
    description = " | ".join(part for part in description_parts if part) or title

    item = {
        "aid": key,
        "title": title,
        "description": description[:800],
        "url": raw_url,
        "seed_url": seed_url,
        "source": source_site or source_label or source_cat,
        "source_label": source_label,
        "source_site": source_site,
        "source_type": source_cat,
        "author": author or attacker or team,
        "date": date_value,
        "scraped_at": date_value,
        "published_at": date_value,
        "network": network,
        "top_tag": source_cat,
        "categories": categories,
        "summary": (_excerpt_text(content) or _excerpt_text(description) or title)[:400],
        "entities": _normalize_entities(data.get("entities") or data.get("m_entities")),
        "ip_addresses": ip_addresses,
        "attacker": attacker,
        "team": team,
        "web_server": web_server,
        "screenshot": screenshot,
        "screenshot_links": screenshot_links,
        "mirror_links": mirror_links,
        "evidence_links": evidence_links,
        "website": website,
        "website_host": website_host,
        "industry": industry,
        "discovered_at": discovered_at,
        "attack_date": attack_date,
        "collected_at": collected_at,
        "extra": data.get("extra") or data.get("m_extra") or {},
    }
    item["country_codes"] = _infer_country_codes(item, data)
    item["country_names"] = [_COUNTRY_CODE_TO_NAME[code] for code in item["country_codes"]]
    item["ai_summary"] = _build_ai_summary(item)
    item["_search_blob"] = _compose_search_blob(
        item["title"],
        item["description"],
        item["summary"],
        item["url"],
        item["seed_url"],
        item["source"],
        item["source_label"],
        item["source_site"],
        item["author"],
        item["network"],
        item["ip_addresses"],
        item["attacker"],
        item["team"],
        item["web_server"],
        item["website"],
        item["website_host"],
        item["industry"],
        item["discovered_at"],
        item["attack_date"],
        item["collected_at"],
        item["country_names"],
        item["entities"],
        item["categories"],
        item["evidence_links"],
        item["screenshot_links"],
        item["mirror_links"],
        content,
        data.get("m_ref_html"),
        data.get("extra") or data.get("m_extra"),
    )
    if include_raw:
        item["raw"] = data
    return item


