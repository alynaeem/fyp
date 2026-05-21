from __future__ import annotations

import difflib
import re
from typing import Any

from .models import DriftResult


def _summary_tokens(summary: dict[str, Any]) -> set[str]:
    tokens: set[str] = set()
    for bucket_name in ("tag_counts", "class_tokens", "id_tokens", "repeated_blocks"):
        for key in (summary.get(bucket_name) or {}).keys():
            tokens.add(str(key))
    for heading in summary.get("headings") or []:
        for token in re.findall(r"[a-zA-Z0-9_\-]{3,}", str(heading).lower()):
            tokens.add(token)
    for anchor in summary.get("text_anchors") or []:
        for token in re.findall(r"[a-zA-Z0-9_\-]{3,}", str(anchor).lower()):
            tokens.add(token)
    return tokens


def compare_snapshots(
    baseline_summary: dict[str, Any] | None,
    current_summary: dict[str, Any] | None,
    *,
    baseline_hash: str = "",
    current_hash: str = "",
) -> DriftResult:
    baseline_summary = baseline_summary or {}
    current_summary = current_summary or {}
    if not baseline_summary:
        return DriftResult(
            html_change_status="no_change",
            structure_similarity=1.0,
            html_changed=False,
            diff_summary=["Initial baseline captured."],
            changed_components=[],
            diff_excerpt="",
        )

    html_changed = bool(baseline_hash and current_hash and baseline_hash != current_hash)
    baseline_tokens = _summary_tokens(baseline_summary)
    current_tokens = _summary_tokens(current_summary)
    if not baseline_tokens and not current_tokens:
        similarity = 1.0
    else:
        overlap = len(baseline_tokens & current_tokens)
        similarity = overlap / max(len(baseline_tokens | current_tokens), 1)

    changed_components: list[str] = []
    diff_summary: list[str] = []
    if baseline_summary.get("title") != current_summary.get("title"):
        changed_components.append("title")
        diff_summary.append("Page title changed.")
    for key in ("forms", "links", "images", "scripts", "text_length"):
        if baseline_summary.get(key) != current_summary.get(key):
            changed_components.append(key)
            diff_summary.append(f"{key.replace('_', ' ').title()} changed.")
    if (baseline_summary.get("headings") or [])[:5] != (current_summary.get("headings") or [])[:5]:
        changed_components.append("headings")
        diff_summary.append("Important headings changed.")
    if (baseline_summary.get("repeated_blocks") or {}) != (current_summary.get("repeated_blocks") or {}):
        changed_components.append("repeated_blocks")
        diff_summary.append("Repeated card/container structure changed.")
    if not diff_summary and html_changed:
        diff_summary.append("HTML hash changed.")

    if not html_changed and similarity >= 0.98:
        change_status = "no_change"
    elif similarity >= 0.8 and len(changed_components) <= 3:
        change_status = "minor_change"
    else:
        change_status = "major_change"

    baseline_lines = [
        f"title: {baseline_summary.get('title', '')}",
        *[f"h: {item}" for item in (baseline_summary.get("headings") or [])[:6]],
        *[f"a: {item}" for item in (baseline_summary.get("text_anchors") or [])[:6]],
    ]
    current_lines = [
        f"title: {current_summary.get('title', '')}",
        *[f"h: {item}" for item in (current_summary.get("headings") or [])[:6]],
        *[f"a: {item}" for item in (current_summary.get("text_anchors") or [])[:6]],
    ]
    diff_excerpt = "\n".join(
        difflib.unified_diff(baseline_lines, current_lines, fromfile="baseline", tofile="latest", lineterm="")
    )[:4000]

    return DriftResult(
        html_change_status=change_status,
        structure_similarity=round(similarity, 3),
        html_changed=html_changed or change_status != "no_change",
        diff_summary=diff_summary[:10],
        changed_components=changed_components[:10],
        diff_excerpt=diff_excerpt,
    )
