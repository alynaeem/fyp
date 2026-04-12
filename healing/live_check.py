from __future__ import annotations

import time
from typing import Any

import requests

from config import cfg
from .models import LiveCheckResult

try:
    from playwright.sync_api import sync_playwright  # type: ignore
except Exception:  # pragma: no cover
    sync_playwright = None  # type: ignore


FETCH_TIMEOUT_SECONDS = 20
MAX_HTML_BYTES = 1_500_000


def _classify_error(message: str) -> str:
    lowered = str(message or "").lower()
    if "timed out" in lowered or "timeout" in lowered:
        return "timeout"
    if "name or service not known" in lowered or "name resolution" in lowered or "dns" in lowered:
        return "dns_failure"
    if "connection refused" in lowered or "connection reset" in lowered or "socks" in lowered or "proxy" in lowered:
        return "connection_error"
    return "unreachable"


def _status_from_code(status_code: int | None) -> tuple[str, bool]:
    if status_code is None:
        return "unknown", False
    if 200 <= status_code < 300:
        return "live", True
    if 300 <= status_code < 400:
        return "redirect", True
    if status_code in {401, 403, 429}:
        return "blocked", True
    if 400 <= status_code < 500:
        return "client_error", True
    if status_code >= 500:
        return "server_error", True
    return "unknown", False


def check_target_live(target_url: str, fetch_strategy: str = "requests") -> LiveCheckResult:
    if not target_url:
        return LiveCheckResult(
            live_status="missing_target",
            is_live=False,
            reachable=False,
            error="No target URL configured.",
            fetch_strategy=fetch_strategy or "requests",
        )

    if fetch_strategy == "playwright":
        result = _check_with_playwright(target_url)
        if result.reachable or not sync_playwright:
            return result
        fallback = _check_with_requests(target_url)
        if fallback.reachable or fallback.status_code is not None:
            return fallback
        return result
    return _check_with_requests(target_url)


def _check_with_requests(target_url: str) -> LiveCheckResult:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0 Safari/537.36"
        ),
        "Accept-Language": "en-US,en;q=0.9",
    }
    started = time.time()
    try:
        response = requests.get(
            target_url,
            timeout=FETCH_TIMEOUT_SECONDS,
            headers=headers,
            proxies=cfg.requests_proxies,
            allow_redirects=True,
        )
        html = (response.text or "")[:MAX_HTML_BYTES]
        live_status, is_live = _status_from_code(response.status_code)
        return LiveCheckResult(
            live_status=live_status,
            is_live=is_live,
            reachable=True,
            status_code=response.status_code,
            response_time_ms=int((time.time() - started) * 1000),
            final_url=response.url,
            html=html,
            fetch_strategy="requests",
            error="" if response.ok else f"HTTP {response.status_code}",
        )
    except Exception as exc:
        return LiveCheckResult(
            live_status=_classify_error(str(exc)),
            is_live=False,
            reachable=False,
            status_code=None,
            response_time_ms=int((time.time() - started) * 1000),
            final_url=target_url,
            html="",
            fetch_strategy="requests",
            error=str(exc),
        )


def _check_with_playwright(target_url: str) -> LiveCheckResult:
    if sync_playwright is None:
        return LiveCheckResult(
            live_status="playwright_unavailable",
            is_live=False,
            reachable=False,
            final_url=target_url,
            fetch_strategy="playwright",
            error="Playwright is not available in this environment.",
        )

    started = time.time()
    try:
        with sync_playwright() as playwright:
            launch_kwargs: dict[str, Any] = {
                "headless": True,
                "args": ["--no-sandbox", "--disable-dev-shm-usage"],
            }
            if cfg.proxy:
                launch_kwargs["proxy"] = cfg.proxy
            browser = playwright.chromium.launch(**launch_kwargs)
            page = browser.new_page(ignore_https_errors=True)
            try:
                response = page.goto(target_url, wait_until="domcontentloaded", timeout=25_000)
                page.wait_for_timeout(1200)
                html = page.content()[:MAX_HTML_BYTES]
                status_code = response.status if response else 200
                live_status, is_live = _status_from_code(status_code)
                return LiveCheckResult(
                    live_status=live_status,
                    is_live=is_live,
                    reachable=True,
                    status_code=status_code,
                    response_time_ms=int((time.time() - started) * 1000),
                    final_url=page.url,
                    html=html,
                    fetch_strategy="playwright",
                    error="" if not response or response.ok else f"HTTP {status_code}",
                )
            finally:
                try:
                    browser.close()
                except Exception:
                    pass
    except Exception as exc:
        return LiveCheckResult(
            live_status=_classify_error(str(exc)),
            is_live=False,
            reachable=False,
            status_code=None,
            response_time_ms=int((time.time() - started) * 1000),
            final_url=target_url,
            html="",
            fetch_strategy="playwright",
            error=str(exc),
        )
