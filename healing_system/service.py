from __future__ import annotations

import difflib
import hashlib
import json
import re
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from config import cfg
from logger import get_logger
from mongo_persistence import get_db

log = get_logger("healing_system")

SCRIPT_ROOTS: tuple[tuple[str, str], ...] = (
    ("news", "news_collector/scripts"),
    ("leak", "leak_collector/scripts"),
    ("defacement", "defacement_collector/scripts"),
    ("exploit", "exploit_collector/scripts"),
    ("social", "social_collector/scripts"),
    ("api", "api_collector/scripts"),
)

SELECTOR_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "css",
        re.compile(
            r"""(?:select_one|select|query_selector|query_selector_all)\(\s*['"]([^'"]{2,220})['"]"""
        ),
    ),
    (
        "tag",
        re.compile(
            r"""find(?:_all)?\(\s*['"]([a-zA-Z][a-zA-Z0-9:_\-]{0,80})['"]"""
        ),
    ),
)
URL_PATTERN = re.compile(r"""https?://[^\s'"<>]+""")
SKIP_FILE_NAMES = {"__init__.py", "main.py", "apimain.py", "apkmain.py", "gitmain.py"}
SNAPSHOT_DIR = Path("data/html_snapshots")
MAX_HTML_BYTES = 1_500_000
SUMMARY_HEADING_LIMIT = 10
SUMMARY_CLASS_LIMIT = 40
SUMMARY_ID_LIMIT = 20
SUMMARY_TAG_LIMIT = 25
EVENT_HISTORY_LIMIT = 100
FETCH_TIMEOUT_SECONDS = 20


class HealingMonitorService:
    def __init__(self) -> None:
        self.db = get_db()
        self.targets = self.db["healing_targets"]
        self.snapshots = self.db["healing_snapshots"]
        self.events = self.db["healing_events"]
        self.runtime = self.db["healing_runtime"]
        SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        try:
            self.targets.create_index("target_key", unique=True)
            self.targets.create_index([("collector_type", 1), ("script_name", 1)])
            self.targets.create_index([("status", 1), ("collector_type", 1)])
            self.snapshots.create_index([("target_key", 1), ("captured_at", -1)])
            self.events.create_index([("target_key", 1), ("created_at", -1)])
            self.events.create_index([("created_at", -1)])
            self.runtime.create_index("_id", unique=True)
        except Exception as exc:
            log.warning(f"Could not ensure healing indexes: {exc}")

    def discover_targets(self) -> dict[str, Any]:
        discovered: list[dict[str, Any]] = []
        seen: set[str] = set()
        now = self._now_iso()

        for collector_type, root in SCRIPT_ROOTS:
            base = Path(root)
            if not base.exists():
                continue

            for path in sorted(base.rglob("*.py")):
                if path.name in SKIP_FILE_NAMES or path.name.startswith("test_") or path.name.startswith("_example"):
                    continue
                target = self._build_target_definition(path, collector_type)
                if not target or target["target_key"] in seen:
                    continue
                seen.add(target["target_key"])
                discovered.append(target)

        for target in discovered:
            self.targets.update_one(
                {"target_key": target["target_key"]},
                {
                    "$set": {
                        **target,
                        "active": True,
                        "updated_at": now,
                    },
                    "$setOnInsert": {
                        "discovered_at": now,
                        "status": "discovered",
                        "last_checked_at": None,
                        "last_changed_at": None,
                        "last_fix_status": "not_run",
                        "change_count": 0,
                        "auto_fix_count": 0,
                        "needs_review_count": 0,
                        "selector_broken_count": 0,
                        "selector_fix_count": 0,
                        "structure_similarity": 1.0,
                        "html_changed": False,
                        "last_error": "",
                        "last_summary_changes": [],
                        "last_selector_suggestions": [],
                        "latest_snapshot_path": "",
                    },
                },
                upsert=True,
            )

        self.runtime.update_one(
            {"_id": "healing_registry"},
            {
                "$set": {
                    "last_discovered_at": now,
                    "target_count": len(discovered),
                    "updated_at": now,
                }
            },
            upsert=True,
        )

        return {
            "status": "ok",
            "discovered": len(discovered),
            "updated_at": now,
        }

    def run_monitor(self, *, limit: int | None = None, target_key: str | None = None) -> dict[str, Any]:
        started_at = self._now_iso()
        query: dict[str, Any] = {"active": {"$ne": False}, "target_url": {"$exists": True, "$ne": ""}}
        if target_key:
            query["target_key"] = target_key

        cursor = self.targets.find(query).sort([("last_checked_at", 1), ("target_key", 1)])
        if limit:
            cursor = cursor.limit(int(limit))

        results: list[dict[str, Any]] = []
        counters: Counter[str] = Counter()
        for target in cursor:
            result = self.run_target_check(target)
            results.append(result)
            counters[result.get("status") or "unknown"] += 1

        completed_at = self._now_iso()
        summary = {
            "status": "ok",
            "started_at": started_at,
            "completed_at": completed_at,
            "target_count": len(results),
            "status_counts": dict(counters),
            "results": results[:50],
        }
        self.runtime.update_one(
            {"_id": "healing_monitor"},
            {
                "$set": {
                    "last_run_at": completed_at,
                    "last_summary": summary,
                    "updated_at": completed_at,
                }
            },
            upsert=True,
        )
        return summary

    def run_target_check(self, target: dict[str, Any] | str) -> dict[str, Any]:
        target_doc = self.targets.find_one({"target_key": target}) if isinstance(target, str) else target
        if not target_doc:
            return {"status": "missing", "target_key": str(target)}

        target_key = target_doc["target_key"]
        started_at = time.time()
        fetch_result = self._fetch_target_html(target_doc)
        previous = self.snapshots.find_one({"target_key": target_key}, sort=[("captured_at", -1)])
        html = fetch_result.get("html") or ""

        selector_health = self._evaluate_selectors(html, target_doc.get("selector_hints") or [])
        dom_summary = self._summarize_html(html) if html else self._empty_summary()
        snapshot_path = self._persist_snapshot_file(target_doc, html)
        snapshot_doc = {
            "target_key": target_key,
            "script_name": target_doc.get("script_name"),
            "collector_type": target_doc.get("collector_type"),
            "target_url": target_doc.get("target_url"),
            "captured_at": self._now_iso(),
            "duration_ms": int((time.time() - started_at) * 1000),
            "fetch_strategy": fetch_result.get("strategy"),
            "status_code": fetch_result.get("status_code"),
            "final_url": fetch_result.get("final_url") or target_doc.get("target_url"),
            "reachable": bool(fetch_result.get("reachable")),
            "error": fetch_result.get("error") or "",
            "html_sha256": self._sha(html),
            "html_size": len(html.encode("utf-8", errors="ignore")),
            "dom_fingerprint": self._fingerprint(dom_summary),
            "summary": dom_summary,
            "selector_health": selector_health,
            "snapshot_path": snapshot_path,
        }
        snapshot_insert = self.snapshots.insert_one(snapshot_doc)
        snapshot_doc["_id"] = snapshot_insert.inserted_id

        diff_result = self._compare_snapshots(previous, snapshot_doc)
        repair = self._repair_broken_selectors(previous, snapshot_doc, html)
        status = self._derive_status(snapshot_doc, diff_result, repair)
        auto_fix_count = len(
            [item for item in repair["suggestions"] if float(item.get("confidence") or 0) >= 0.65]
        )
        needs_review = bool(repair["broken_selectors"]) and auto_fix_count == 0

        event_doc = {
            "target_key": target_key,
            "script_name": target_doc.get("script_name"),
            "collector_type": target_doc.get("collector_type"),
            "target_url": target_doc.get("target_url"),
            "created_at": self._now_iso(),
            "status": status,
            "html_changed": diff_result["html_changed"],
            "structure_similarity": diff_result["structure_similarity"],
            "summary_changes": diff_result["summary_changes"],
            "broken_selectors": repair["broken_selectors"],
            "selector_suggestions": repair["suggestions"],
            "auto_fix_count": auto_fix_count,
            "needs_review": needs_review,
            "snapshot_id": str(snapshot_insert.inserted_id),
            "error": snapshot_doc.get("error") or "",
        }
        self.events.insert_one(event_doc)
        self._prune_events(target_key)

        target_update = {
            "status": status,
            "last_checked_at": snapshot_doc["captured_at"],
            "last_error": snapshot_doc.get("error") or "",
            "last_fix_status": "auto_fixed" if auto_fix_count else "needs_review" if needs_review else "healthy",
            "latest_snapshot_path": snapshot_path,
            "html_changed": diff_result["html_changed"],
            "selector_broken_count": len(repair["broken_selectors"]),
            "selector_fix_count": auto_fix_count,
            "structure_similarity": diff_result["structure_similarity"],
            "last_summary_changes": diff_result["summary_changes"],
            "last_selector_suggestions": repair["suggestions"][:5],
            "updated_at": self._now_iso(),
        }
        inc_doc: dict[str, int] = {}
        if diff_result["html_changed"]:
            target_update["last_changed_at"] = snapshot_doc["captured_at"]
            inc_doc["change_count"] = 1
        if auto_fix_count:
            inc_doc["auto_fix_count"] = auto_fix_count
        if needs_review:
            inc_doc["needs_review_count"] = 1

        update_doc: dict[str, Any] = {"$set": target_update}
        if inc_doc:
            update_doc["$inc"] = inc_doc
        self.targets.update_one({"target_key": target_key}, update_doc)

        return {
            "target_key": target_key,
            "script_name": target_doc.get("script_name"),
            "collector_type": target_doc.get("collector_type"),
            "status": status,
            "html_changed": diff_result["html_changed"],
            "structure_similarity": diff_result["structure_similarity"],
            "broken_selector_count": len(repair["broken_selectors"]),
            "auto_fix_count": auto_fix_count,
            "error": snapshot_doc.get("error") or "",
        }

    def get_stats(self) -> dict[str, Any]:
        breakdown = self._build_discovery_breakdown()
        total_targets = self.targets.count_documents({"active": {"$ne": False}})
        changed = self.targets.count_documents({"active": {"$ne": False}, "html_changed": True})
        auto_fixed = self.targets.count_documents({"active": {"$ne": False}, "selector_fix_count": {"$gt": 0}})
        needs_review = self.targets.count_documents({"active": {"$ne": False}, "last_fix_status": "needs_review"})
        healthy = self.targets.count_documents({"active": {"$ne": False}, "status": "healthy"})
        unreachable = self.targets.count_documents({"active": {"$ne": False}, "status": "unreachable"})
        latest_runtime = self.runtime.find_one({"_id": "healing_monitor"}) or {}
        latest_registry = self.runtime.find_one({"_id": "healing_registry"}) or {}
        recent_event = self.events.find_one({}, sort=[("created_at", -1)]) or {}
        return {
            "total_targets": total_targets,
            "html_changed": changed,
            "auto_fixed": auto_fixed,
            "needs_review": needs_review,
            "healthy": healthy,
            "unreachable": unreachable,
            "last_run_at": latest_runtime.get("last_run_at"),
            "last_discovered_at": latest_registry.get("last_discovered_at"),
            "last_event_status": recent_event.get("status"),
            "last_event_target": recent_event.get("script_name"),
            "discovery_breakdown": breakdown,
        }

    def list_targets(self, *, limit: int = 100) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        cursor = self.targets.find({"active": {"$ne": False}}, {"_id": 0}).sort(
            [("status", 1), ("collector_type", 1), ("script_name", 1)]
        ).limit(int(limit))
        for doc in cursor:
            items.append(doc)
        return items

    def list_events(self, *, limit: int = 50, target_key: str | None = None) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        query = {"target_key": target_key} if target_key else {}
        cursor = self.events.find(query, {"_id": 0}).sort("created_at", -1).limit(int(limit))
        for doc in cursor:
            items.append(doc)
        return items

    def _build_target_definition(self, path: Path, collector_type: str) -> dict[str, Any] | None:
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as exc:
            log.warning(f"Could not read healing target source {path}: {exc}")
            return None

        urls = self._extract_urls(source)
        if not urls:
            return None

        target_url = self._pick_primary_url(urls)
        if not target_url:
            return None

        rel_path = path.as_posix().lstrip("./")
        script_name = path.stem
        fetch_strategy = self._infer_fetch_strategy(source)
        selector_hints = self._extract_selector_hints(source)
        domain = urlparse(target_url).netloc or target_url
        return {
            "target_key": self._safe_key(rel_path),
            "script_name": script_name,
            "collector_type": collector_type,
            "file_path": rel_path,
            "target_url": target_url,
            "target_domain": domain,
            "additional_urls": [url for url in urls if url != target_url][:10],
            "selector_hints": selector_hints[:40],
            "fetch_strategy": fetch_strategy,
        }

    def _build_discovery_breakdown(self) -> dict[str, Any]:
        total_python_files = 0
        skipped_files: list[str] = []
        utility_files: list[str] = []
        discovered_files: list[str] = []

        for collector_type, root in SCRIPT_ROOTS:
            base = Path(root)
            if not base.exists():
                continue

            for path in sorted(base.rglob("*.py")):
                total_python_files += 1
                rel_path = path.as_posix().lstrip("./")

                if path.name in SKIP_FILE_NAMES or path.name.startswith("test_") or path.name.startswith("_example"):
                    skipped_files.append(rel_path)
                    continue

                target = self._build_target_definition(path, collector_type)
                if not target:
                    utility_files.append(rel_path)
                    continue

                discovered_files.append(rel_path)

        return {
            "roots": [root for _, root in SCRIPT_ROOTS],
            "root_count": len(SCRIPT_ROOTS),
            "total_python_files": total_python_files,
            "skipped_file_count": len(skipped_files),
            "utility_file_count": len(utility_files),
            "discovered_target_count": len(discovered_files),
            "default_run_limit": int(cfg.healing_monitor_target_limit or 12),
            "skipped_files": skipped_files[:20],
            "utility_files": utility_files[:20],
        }

    def _extract_urls(self, source: str) -> list[str]:
        urls: list[str] = []
        for match in URL_PATTERN.findall(source):
            cleaned = match.rstrip("\"' ,)")
            if cleaned not in urls:
                urls.append(cleaned)
        return urls

    def _pick_primary_url(self, urls: Iterable[str]) -> str:
        scored: list[tuple[int, str]] = []
        priority_fragments = (
            "ransomware.live",
            "thehackernews",
            "bleepingcomputer",
            "hackread",
            "zone-xsec",
            "tweetfeed",
            "cisa.gov",
            "exploit-db.com",
        )
        for url in urls:
            score = 0
            lowered = url.lower()
            if "/support/" not in lowered and "/contact" not in lowered and "/privacy" not in lowered:
                score += 2
            if any(fragment in lowered for fragment in priority_fragments):
                score += 3
            if lowered.count("/") <= 4:
                score += 1
            if any(fragment in lowered for fragment in ("/archive", "/api", "/feed", "/rss")):
                score -= 1
            scored.append((score, url))
        scored.sort(key=lambda item: (item[0], -len(item[1])), reverse=True)
        return scored[0][1] if scored else ""

    def _infer_fetch_strategy(self, source: str) -> str:
        lowered = source.lower()
        if "playwright" in lowered or "query_selector" in lowered or "page.goto" in lowered:
            return "playwright"
        return "requests"

    def _extract_selector_hints(self, source: str) -> list[dict[str, Any]]:
        selectors: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for selector_type, pattern in SELECTOR_PATTERNS:
            for match in pattern.finditer(source):
                selector = (match.group(1) or "").strip()
                if not selector or len(selector) < 2:
                    continue
                key = (selector, selector_type)
                if key in seen:
                    continue
                seen.add(key)
                selectors.append({"selector": selector, "method": selector_type})
        return selectors

    def _fetch_target_html(self, target: dict[str, Any]) -> dict[str, Any]:
        url = target.get("target_url")
        strategy = target.get("fetch_strategy") or "requests"
        if not url:
            return {"reachable": False, "error": "No target URL", "strategy": strategy, "html": ""}

        if strategy == "playwright":
            try:
                return self._fetch_with_playwright(url)
            except Exception as exc:
                log.warning(f"Playwright fetch failed for {target.get('script_name')}: {exc}")
        return self._fetch_with_requests(url)

    def _fetch_with_requests(self, url: str) -> dict[str, Any]:
        started = time.time()
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0 Safari/537.36"
            ),
            "Accept-Language": "en-US,en;q=0.9",
        }
        try:
            response = requests.get(
                url,
                timeout=FETCH_TIMEOUT_SECONDS,
                headers=headers,
                proxies=cfg.requests_proxies,
                allow_redirects=True,
            )
            text = (response.text or "")[:MAX_HTML_BYTES]
            return {
                "reachable": response.ok,
                "status_code": response.status_code,
                "final_url": response.url,
                "html": text,
                "strategy": "requests",
                "duration_ms": int((time.time() - started) * 1000),
                "error": "" if response.ok else f"HTTP {response.status_code}",
            }
        except Exception as exc:
            return {
                "reachable": False,
                "error": str(exc),
                "strategy": "requests",
                "duration_ms": int((time.time() - started) * 1000),
                "html": "",
                "status_code": None,
                "final_url": url,
            }

    def _fetch_with_playwright(self, url: str) -> dict[str, Any]:
        from playwright.sync_api import sync_playwright

        started = time.time()
        with sync_playwright() as playwright:
            browser_args: dict[str, Any] = {
                "headless": True,
                "args": ["--no-sandbox", "--disable-dev-shm-usage"],
            }
            if cfg.proxy:
                browser_args["proxy"] = cfg.proxy
            browser = playwright.chromium.launch(**browser_args)
            page = browser.new_page(ignore_https_errors=True)
            try:
                response = page.goto(url, wait_until="domcontentloaded", timeout=25_000)
                page.wait_for_timeout(1200)
                html = page.content()[:MAX_HTML_BYTES]
                return {
                    "reachable": bool(response) and response.ok,
                    "status_code": response.status if response else 200,
                    "final_url": page.url,
                    "html": html,
                    "strategy": "playwright",
                    "duration_ms": int((time.time() - started) * 1000),
                    "error": "" if not response or response.ok else f"HTTP {response.status}",
                }
            finally:
                browser.close()

    def _summarize_html(self, html: str) -> dict[str, Any]:
        soup = BeautifulSoup(html or "", "html.parser")
        tag_counts = Counter(node.name for node in soup.find_all(True))
        class_counts: Counter[str] = Counter()
        id_counts: Counter[str] = Counter()

        for node in soup.find_all(True):
            for cls in node.get("class") or []:
                if cls:
                    class_counts[str(cls)] += 1
            node_id = node.get("id")
            if node_id:
                id_counts[str(node_id)] += 1

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

        title = ""
        if soup.title and soup.title.get_text(strip=True):
            title = soup.title.get_text(" ", strip=True)
        body_text = soup.get_text(" ", strip=True)
        return {
            "title": title,
            "headings": headings[:SUMMARY_HEADING_LIMIT],
            "tag_counts": dict(tag_counts.most_common(SUMMARY_TAG_LIMIT)),
            "class_tokens": dict(class_counts.most_common(SUMMARY_CLASS_LIMIT)),
            "id_tokens": dict(id_counts.most_common(SUMMARY_ID_LIMIT)),
            "forms": len(soup.find_all("form")),
            "links": len(soup.find_all("a")),
            "images": len(soup.find_all("img")),
            "scripts": len(soup.find_all("script")),
            "text_length": len(body_text),
        }

    def _empty_summary(self) -> dict[str, Any]:
        return {
            "title": "",
            "headings": [],
            "tag_counts": {},
            "class_tokens": {},
            "id_tokens": {},
            "forms": 0,
            "links": 0,
            "images": 0,
            "scripts": 0,
            "text_length": 0,
        }

    def _fingerprint(self, summary: dict[str, Any]) -> str:
        payload = json.dumps(summary, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _evaluate_selectors(self, html: str, selector_hints: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not html:
            return []
        soup = BeautifulSoup(html, "html.parser")
        results: list[dict[str, Any]] = []

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

            first = matches[0] if matches else None
            results.append(
                {
                    "selector": selector,
                    "method": method,
                    "match_count": len(matches),
                    "first_match": self._element_signature(first),
                    "error": error,
                }
            )
        return results

    def _element_signature(self, element: Any) -> dict[str, Any] | None:
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

    def _compare_snapshots(self, previous: dict[str, Any] | None, current: dict[str, Any]) -> dict[str, Any]:
        if not previous:
            return {
                "html_changed": False,
                "structure_similarity": 1.0,
                "summary_changes": ["Initial snapshot captured"],
            }

        html_changed = previous.get("html_sha256") != current.get("html_sha256")
        prev_tokens = self._summary_tokens(previous.get("summary") or {})
        curr_tokens = self._summary_tokens(current.get("summary") or {})
        if not prev_tokens and not curr_tokens:
            similarity = 1.0
        else:
            overlap = len(prev_tokens & curr_tokens)
            similarity = overlap / max(len(prev_tokens | curr_tokens), 1)

        changes: list[str] = []
        previous_summary = previous.get("summary") or {}
        current_summary = current.get("summary") or {}
        if previous_summary.get("title") != current_summary.get("title"):
            changes.append("Page title changed")
        for key in ("forms", "links", "images", "scripts"):
            if previous_summary.get(key) != current_summary.get(key):
                changes.append(f"{key.title()} count changed")
        if not changes and html_changed:
            changes.append("HTML hash changed")

        return {
            "html_changed": html_changed,
            "structure_similarity": round(similarity, 3),
            "summary_changes": changes[:8],
        }

    def _summary_tokens(self, summary: dict[str, Any]) -> set[str]:
        tokens: set[str] = set()
        for bucket_name in ("tag_counts", "class_tokens", "id_tokens"):
            for key in (summary.get(bucket_name) or {}).keys():
                tokens.add(str(key))
        for heading in summary.get("headings") or []:
            for token in re.findall(r"[a-zA-Z0-9_\-]{3,}", str(heading).lower()):
                tokens.add(token)
        return tokens

    def _repair_broken_selectors(
        self,
        previous: dict[str, Any] | None,
        current: dict[str, Any],
        html: str,
    ) -> dict[str, Any]:
        if not previous or not html:
            return {"broken_selectors": [], "suggestions": []}

        previous_health = previous.get("selector_health") or []
        current_health = {item.get("selector"): item for item in current.get("selector_health") or []}
        soup = BeautifulSoup(html, "html.parser")
        broken: list[dict[str, Any]] = []
        suggestions: list[dict[str, Any]] = []

        for prev in previous_health:
            selector = prev.get("selector")
            prev_count = int(prev.get("match_count") or 0)
            curr_count = int((current_health.get(selector) or {}).get("match_count") or 0)
            if prev_count > 0 and curr_count == 0:
                broken.append(
                    {
                        "selector": selector,
                        "previous_match": prev.get("first_match"),
                    }
                )
                candidate = self._suggest_replacement(prev.get("first_match"), soup)
                if candidate:
                    suggestions.append({"old_selector": selector, **candidate})

        return {"broken_selectors": broken, "suggestions": suggestions}

    def _suggest_replacement(self, previous_match: dict[str, Any] | None, soup: BeautifulSoup) -> dict[str, Any] | None:
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
        suggestion = self._selector_from_element(best)
        if not suggestion:
            return None
        return {
            "suggested_selector": suggestion,
            "confidence": round(min(best_score, 0.99), 2),
            "reason": "Matched by tag, class overlap, and nearby text similarity.",
        }

    def _selector_from_element(self, element: Any) -> str:
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

    def _derive_status(self, snapshot: dict[str, Any], diff_result: dict[str, Any], repair: dict[str, Any]) -> str:
        if not snapshot.get("reachable"):
            return "unreachable"
        if snapshot.get("error"):
            return "error"
        if repair.get("broken_selectors"):
            return "auto_fixed" if repair.get("suggestions") else "needs_review"
        if diff_result.get("html_changed"):
            return "changed"
        return "healthy"

    def _persist_snapshot_file(self, target: dict[str, Any], html: str) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        script_dir = SNAPSHOT_DIR / str(target.get("collector_type", "misc")) / str(
            target.get("script_name", "unknown")
        )
        script_dir.mkdir(parents=True, exist_ok=True)
        path = script_dir / f"{timestamp}.html"
        path.write_text(html or "", encoding="utf-8", errors="ignore")
        return str(path)

    def _prune_events(self, target_key: str) -> None:
        extra = list(
            self.events.find({"target_key": target_key}, {"_id": 1})
            .sort("created_at", -1)
            .skip(EVENT_HISTORY_LIMIT)
        )
        if extra:
            self.events.delete_many({"_id": {"$in": [doc["_id"] for doc in extra]}})

    def _sha(self, value: str) -> str:
        return hashlib.sha256((value or "").encode("utf-8", errors="ignore")).hexdigest()

    def _safe_key(self, value: str) -> str:
        return re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("_").lower()

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()


_SERVICE: HealingMonitorService | None = None


def get_healing_service() -> HealingMonitorService:
    global _SERVICE
    if _SERVICE is None:
        _SERVICE = HealingMonitorService()
    return _SERVICE
