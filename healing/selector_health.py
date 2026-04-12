from __future__ import annotations

from typing import Any

from bs4 import BeautifulSoup

from .models import SelectorHealthResult


def _element_signature(element: Any) -> dict[str, Any] | None:
    if not element:
        return None
    text = element.get_text(" ", strip=True) if hasattr(element, "get_text") else ""
    attrs = getattr(element, "attrs", {}) if hasattr(element, "attrs") else {}
    classes = [str(cls) for cls in attrs.get("class", [])][:6]
    return {
        "tag": getattr(element, "name", ""),
        "id": attrs.get("id") or "",
        "classes": classes,
        "text": text[:180],
    }


def evaluate_selector_health(html: str, selector_hints: list[dict[str, Any]]) -> SelectorHealthResult:
    if not selector_hints:
        return SelectorHealthResult(
            selector_health_score=None,
            total_selectors=0,
            matched_selectors=0,
            failed_selectors=[],
            results=[],
        )
    if not html:
        return SelectorHealthResult(
            selector_health_score=0.0,
            total_selectors=len(selector_hints),
            matched_selectors=0,
            failed_selectors=[{"selector": item.get("selector"), "reason": "empty_html"} for item in selector_hints],
            results=[],
        )

    soup = BeautifulSoup(html, "html.parser")
    results: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    matched = 0

    for hint in selector_hints:
        selector = str(hint.get("selector") or "").strip()
        method = str(hint.get("method") or "css")
        if not selector:
            continue
        matches: list[Any] = []
        error = ""
        try:
            if method == "tag":
                matches = soup.find_all(selector)
            else:
                matches = soup.select(selector)
        except Exception as exc:
            error = str(exc)
            matches = []

        if matches:
            matched += 1
        else:
            failed.append({"selector": selector, "method": method, "reason": error or "no_match"})

        results.append(
            {
                "selector": selector,
                "method": method,
                "match_count": len(matches),
                "first_match": _element_signature(matches[0] if matches else None),
                "error": error,
            }
        )

    total = max(len(results), 1)
    score = round((matched / total) * 100, 1)
    return SelectorHealthResult(
        selector_health_score=score,
        total_selectors=len(results),
        matched_selectors=matched,
        failed_selectors=failed,
        results=results,
    )
