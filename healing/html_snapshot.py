from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup


SNAPSHOT_ROOT = Path("data/healing/snapshots")
SUMMARY_HEADING_LIMIT = 12
SUMMARY_CLASS_LIMIT = 50
SUMMARY_ID_LIMIT = 25
SUMMARY_TAG_LIMIT = 30
SUMMARY_ANCHOR_LIMIT = 20
SUMMARY_BLOCK_LIMIT = 20


def empty_summary() -> dict[str, Any]:
    return {
        "title": "",
        "headings": [],
        "text_anchors": [],
        "tag_counts": {},
        "class_tokens": {},
        "id_tokens": {},
        "repeated_blocks": {},
        "forms": 0,
        "links": 0,
        "images": 0,
        "scripts": 0,
        "text_length": 0,
    }


def summarize_html(html: str) -> dict[str, Any]:
    if not html:
        return empty_summary()

    soup = BeautifulSoup(html, "html.parser")
    tag_counts = Counter(node.name for node in soup.find_all(True))
    class_counts: Counter[str] = Counter()
    id_counts: Counter[str] = Counter()
    block_counts: Counter[str] = Counter()

    for node in soup.find_all(True):
        classes = [str(cls) for cls in node.get("class") or [] if cls][:2]
        for cls in classes:
            class_counts[cls] += 1
        node_id = node.get("id")
        if node_id:
            id_counts[str(node_id)] += 1
        if node.name in {"article", "section", "div", "li", "tr"}:
            signature = node.name
            if classes:
                signature = f"{signature}." + ".".join(classes)
            block_counts[signature] += 1

    headings: list[str] = []
    for selector in ("h1", "h2", "h3"):
        for node in soup.select(selector):
            text = node.get_text(" ", strip=True)
            if text and text not in headings:
                headings.append(text)
            if len(headings) >= SUMMARY_HEADING_LIMIT:
                break
        if len(headings) >= SUMMARY_HEADING_LIMIT:
            break

    anchors: list[str] = []
    for selector in ("a", "button", "label"):
        for node in soup.select(selector):
            text = node.get_text(" ", strip=True)
            if text and text not in anchors:
                anchors.append(text[:120])
            if len(anchors) >= SUMMARY_ANCHOR_LIMIT:
                break
        if len(anchors) >= SUMMARY_ANCHOR_LIMIT:
            break

    title = ""
    if soup.title and soup.title.get_text(strip=True):
        title = soup.title.get_text(" ", strip=True)
    body_text = soup.get_text(" ", strip=True)
    return {
        "title": title,
        "headings": headings[:SUMMARY_HEADING_LIMIT],
        "text_anchors": anchors[:SUMMARY_ANCHOR_LIMIT],
        "tag_counts": dict(tag_counts.most_common(SUMMARY_TAG_LIMIT)),
        "class_tokens": dict(class_counts.most_common(SUMMARY_CLASS_LIMIT)),
        "id_tokens": dict(id_counts.most_common(SUMMARY_ID_LIMIT)),
        "repeated_blocks": {
            key: value for key, value in block_counts.most_common(SUMMARY_BLOCK_LIMIT) if value > 1
        },
        "forms": len(soup.find_all("form")),
        "links": len(soup.find_all("a")),
        "images": len(soup.find_all("img")),
        "scripts": len(soup.find_all("script")),
        "text_length": len(body_text),
    }


def fingerprint_summary(summary: dict[str, Any]) -> str:
    payload = json.dumps(summary, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def persist_snapshot_file(script_doc: dict[str, Any], html: str, *, label: str = "snapshot") -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    script_dir = SNAPSHOT_ROOT / str(script_doc.get("collector_name", "misc")) / str(
        script_doc.get("script_name", "unknown")
    )
    script_dir.mkdir(parents=True, exist_ok=True)
    path = script_dir / f"{timestamp}_{label}.html"
    path.write_text(html or "", encoding="utf-8", errors="ignore")
    return str(path)


def read_snapshot_text(path: str) -> str:
    if not path:
        return ""
    snapshot_path = Path(path)
    if not snapshot_path.exists():
        return ""
    try:
        return snapshot_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""
