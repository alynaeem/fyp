from __future__ import annotations

import difflib
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup

from .models import RepairPreview


def _selector_from_element(element: Any) -> str:
    if not element or not getattr(element, "name", None):
        return ""
    attrs = getattr(element, "attrs", {})
    element_id = attrs.get("id")
    if element_id:
        return f"#{element_id}"
    classes = [str(cls) for cls in attrs.get("class", []) if cls][:3]
    if classes:
        return f"{element.name}." + ".".join(classes)
    return str(element.name)


def _suggest_replacement(previous_match: dict[str, Any] | None, soup: BeautifulSoup) -> dict[str, Any] | None:
    if not previous_match:
        return None

    tag = previous_match.get("tag") or None
    previous_classes = set(previous_match.get("classes") or [])
    previous_text = str(previous_match.get("text") or "").strip().lower()
    candidates = soup.find_all(tag) if tag else soup.find_all(True)
    best_score = 0.0
    best = None

    for element in candidates[:2500]:
        attrs = getattr(element, "attrs", {})
        classes = set(str(cls) for cls in attrs.get("class", []) if cls)
        text = element.get_text(" ", strip=True).lower()[:180]
        class_overlap = (
            len(previous_classes & classes) / max(len(previous_classes | classes), 1)
            if previous_classes
            else 0.0
        )
        text_score = (
            difflib.SequenceMatcher(None, previous_text[:120], text[:120]).ratio()
            if previous_text and text
            else 0.0
        )
        score = 0.55 * class_overlap + 0.45 * text_score
        if previous_match.get("id") and attrs.get("id") == previous_match.get("id"):
            score += 0.3
        if score > best_score:
            best_score = score
            best = element

    if not best or best_score < 0.45:
        return None
    suggestion = _selector_from_element(best)
    if not suggestion:
        return None
    return {
        "suggested_selector": suggestion,
        "confidence": round(min(best_score, 0.99), 2),
        "reason": "Matched by tag, class overlap, and nearby text similarity.",
    }


def generate_repair_preview(
    script_doc: dict[str, Any],
    source_path: Path,
    latest_html: str,
    baseline_selector_results: list[dict[str, Any]],
    current_selector_results: list[dict[str, Any]],
) -> RepairPreview:
    if not latest_html:
        return RepairPreview(
            repair_candidate_exists=False,
            repair_confidence=0.0,
            preview_message="No HTML was captured for repair analysis.",
        )

    current_index = {
        str(item.get("selector") or ""): item for item in (current_selector_results or [])
    }
    broken: list[dict[str, Any]] = []
    suggestions: list[dict[str, Any]] = []
    soup = BeautifulSoup(latest_html, "html.parser")

    for previous in baseline_selector_results or []:
        selector = str(previous.get("selector") or "").strip()
        if not selector:
            continue
        previous_count = int(previous.get("match_count") or 0)
        current_count = int((current_index.get(selector) or {}).get("match_count") or 0)
        if previous_count > 0 and current_count == 0:
            broken.append({"selector": selector, "previous_match": previous.get("first_match")})
            suggestion = _suggest_replacement(previous.get("first_match"), soup)
            if suggestion:
                suggestions.append({"old_selector": selector, **suggestion})

    changed_mappings: list[dict[str, Any]] = []
    patched_source = ""
    candidate_exists = False
    preview_message = "No confident repair candidate was generated."

    try:
        source_text = source_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        source_text = ""

    if source_text and suggestions:
        patched_source = source_text
        for item in suggestions:
            old_selector = str(item.get("old_selector") or "")
            new_selector = str(item.get("suggested_selector") or "")
            # Keep repair previews conservative: only patch exact selector strings we can see in source.
            if old_selector and new_selector and old_selector in patched_source:
                patched_source = patched_source.replace(old_selector, new_selector, 1)
                changed_mappings.append(
                    {
                        "old_selector": old_selector,
                        "new_selector": new_selector,
                        "confidence": item.get("confidence"),
                    }
                )
        candidate_exists = patched_source != source_text and bool(changed_mappings)
        if candidate_exists:
            preview_message = "A patch preview was generated from exact selector string replacements."

    confidence = max((float(item.get("confidence") or 0.0) for item in suggestions), default=0.0)
    return RepairPreview(
        repair_candidate_exists=candidate_exists,
        repair_confidence=round(confidence, 2),
        failed_selectors=broken,
        suggested_selectors=suggestions,
        changed_selector_mappings=changed_mappings,
        preview_message=preview_message,
    )
