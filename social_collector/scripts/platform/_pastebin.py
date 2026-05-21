from __future__ import annotations

import inspect
import re
from abc import ABC
from collections import OrderedDict
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

try:
    from playwright.sync_api import Page  # type: ignore
except Exception:
    Page = None  # type: ignore

from crawler.common.crawler_instance.local_interface_model.leak.leak_extractor_interface import (
    leak_extractor_interface,
)
from crawler.common.crawler_instance.local_shared_model.data_model.entity_model import (
    entity_model,
)
from crawler.common.crawler_instance.local_shared_model.data_model.social_model import (
    social_model,
)
from crawler.common.crawler_instance.local_shared_model.rule_model import (
    RuleModel,
    FetchProxy,
    FetchConfig,
    ThreatType,
)
from crawler.common.crawler_instance.crawler_services.redis_manager.redis_controller import (
    redis_controller,
)
from crawler.common.crawler_instance.crawler_services.shared.helper_method import (
    helper_method,
)
from crawler.common.crawler_instance.crawler_services.log_manager.log_controller import (
    log,
)


class _pastebin(leak_extractor_interface, ABC):
    """
    Pastebin extractor.

    ✅ Works with Playwright Page (if provided)
    ✅ Works WITHOUT Playwright by falling back to requests+BeautifulSoup
    ✅ Handles varying entity_model constructor signatures (e.g. requires m_team)
    """

    needs_seed_fetch = False

    _PASTE_ID_RE = re.compile(r"^/[A-Za-z0-9]{4,12}$")

    def __init__(self, callback=None):
        self.callback = callback

        self._card_data: List[social_model] = []
        self._entity_data: List[entity_model] = []

        self.soup = None
        self.m_seed_url = ""
        self._initialized = None
        self._redis_instance = redis_controller()
        self._is_crawled = False
        self._title_seen = OrderedDict()

        # Framework may set these
        self.page: Optional[Any] = None
        self._page: Optional[Any] = None
        self._request_page: Optional[Any] = None
        self.request_page: Optional[Any] = None
        self.playwright_page: Optional[Any] = None

        # requests session (fallback)
        self._session = requests.Session()
        self._session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "close",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
            }
        )

    def init_callback(self, callback=None):
        self.callback = callback

    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return self.m_seed_url

    @property
    def base_url(self) -> str:
        return "https://pastebin.com"

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_fetch_proxy=FetchProxy.NONE,
            m_fetch_config=FetchConfig.PLAYRIGHT,
            m_resoource_block=False,
            m_threat_type=ThreatType.PASTEBIN,
        )

    @property
    def card_data(self) -> List[social_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def contact_page(self) -> str:
        return "https://pastebin.com/contact"

    # -------------------------
    # Page injection helpers
    # -------------------------
    def attach_page(self, page: Any) -> None:
        self._request_page = page
        self.page = page
        self._page = page
        self.request_page = page
        self.playwright_page = page

    def set_page(self, page: Any) -> None:
        self.attach_page(page)

    def _detect_page_object(self) -> Optional[Any]:
        for name in (
            "_request_page",
            "page",
            "_page",
            "request_page",
            "playwright_page",
            "m_page",
            "browser_page",
            "pw_page",
        ):
            obj = getattr(self, name, None)
            if obj is not None:
                return obj
        return None

    # -------------------------
    # Data append
    # -------------------------
    def append_leak_data(self, leak: social_model, entity: entity_model):
        self._card_data.append(leak)
        self._entity_data.append(entity)

        if self.callback:
            try:
                if self.callback():
                    self._card_data.clear()
                    self._entity_data.clear()
            except Exception:
                pass

    # -------------------------
    # Utils
    # -------------------------
    def _parse_date_text(self, raw: str):
        try:
            raw_date = (raw or "").strip()
            if not raw_date:
                return None
            clean_date = re.sub(r"(\d+)(st|nd|rd|th)", r"\1", raw_date, flags=re.IGNORECASE)
            clean_date = re.sub(r"\(.*?\)", "", clean_date).strip()
            clean_date = clean_date.title()
            month = clean_date.split()[0] if clean_date else ""
            fmt = "%b %d, %Y" if len(month) <= 3 else "%B %d, %Y"
            return datetime.strptime(clean_date, fmt).date()
        except Exception:
            return None

    def _extract_entities_from_text(self, text: str):
        cleaned = (text or "").replace("\xa0", " ")
        cleaned = re.sub(r"[ \t]+", " ", cleaned).strip()

        email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        ip_pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
        domain_pattern = r"\b(?:https?://[^\s@]+|www\.[^\s@]+)"

        emails = sorted(set(re.findall(email_pattern, cleaned)))
        ips = sorted(set(re.findall(ip_pattern, cleaned)))
        domains = sorted(set(re.findall(domain_pattern, cleaned)))
        return emails, ips, domains

    def _is_bot_block_html(self, html: str) -> bool:
        h = (html or "").lower()
        return any(
            kw in h
            for kw in (
                "cloudflare",
                "attention required",
                "verify you are human",
                "captcha",
                "access denied",
                "please enable cookies",
                "ddos protection",
            )
        )

    def _make_entity_model(
        self,
        *,
        m_scrap_file: str,
        m_username: List[str],
        m_ip: List[str],
        m_email: List[str],
        m_weblink: List[str],
    ) -> entity_model:
        """
        Create entity_model across different deployments where constructor args differ.
        Your current environment requires m_team, so we supply it when needed.
        """
        # Base candidates
        payload: Dict[str, Any] = {
            "m_scrap_file": m_scrap_file,
            "m_username": m_username,
            "m_ip": m_ip,
            "m_email": m_email,
            "m_weblink": m_weblink,
        }

        # Introspect __init__ params
        try:
            sig = inspect.signature(entity_model.__init__)
            params = sig.parameters

            # If m_team is required (or present), provide a safe default
            if "m_team" in params:
                # Choose empty list as safest (teams are usually list-like)
                payload["m_team"] = []

            # Some deployments might require other fields; add safe defaults if required and missing.
            # Only add if parameter exists and is required (no default) and not already provided.
            for name, p in params.items():
                if name in ("self",):
                    continue
                if name in payload:
                    continue
                if p.default is not inspect._empty:
                    continue  # optional, skip
                # Required but unknown: provide safe empty defaults by type-hint guess
                # Fallback rules:
                # - list-like -> []
                # - str -> ""
                # - int/float -> 0
                # - bool -> False
                ann = p.annotation
                if ann in (list, List):
                    payload[name] = []
                elif ann is str:
                    payload[name] = ""
                elif ann is int:
                    payload[name] = 0
                elif ann is float:
                    payload[name] = 0.0
                elif ann is bool:
                    payload[name] = False
                else:
                    # safest generic
                    payload[name] = None

        except Exception:
            # If signature introspection fails, last resort: try m_team
            payload.setdefault("m_team", [])

        return entity_model(**payload)

    # -------------------------
    # REQUIRED by interface
    # -------------------------
    def parse_leak_data(self, page: Any) -> None:
        if page is not None and hasattr(page, "goto") and hasattr(page, "locator"):
            try:
                self._parse_with_playwright(page)
                return
            except Exception as ex:
                log.g().e(f"[pastebin] Playwright parse failed, fallback to requests: {ex}")

        self._parse_with_requests()

    # -------------------------
    # Playwright path
    # -------------------------
    def _parse_with_playwright(self, page: Any) -> None:
        url_lists: List[str] = []

        try:
            if not str(getattr(page, "url", "")).startswith(self.base_url):
                page.goto(f"{self.base_url}/archive", wait_until="domcontentloaded", timeout=30000)
        except Exception:
            pass

        try:
            links = page.locator("a[href]")
            count = links.count()
        except Exception:
            links = None
            count = 0

        for i in range(count):
            try:
                href = links.nth(i).get_attribute("href")  # type: ignore
            except Exception:
                href = None
            if not href:
                continue
            href = href.strip()
            if not self._PASTE_ID_RE.fullmatch(href):
                continue
            if href in ("/archive", "/trends", "/pro", "/login", "/signup"):
                continue
            url_lists.append(urljoin(self.base_url, href))

        url_lists = list(dict.fromkeys(url_lists))
        if self._is_crawled and url_lists:
            url_lists = url_lists[:2]

        for url in url_lists:
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=30000)
            except Exception:
                continue

            title = ""
            username = ""
            date = None

            try:
                title = page.locator("div.info-top").inner_text().strip()
            except Exception:
                title = ""

            try:
                username = page.locator("div.username a, div.username").first.inner_text().strip()
            except Exception:
                username = ""

            try:
                raw_date = page.locator("div.date").inner_text().strip()
                date = self._parse_date_text(raw_date)
            except Exception:
                date = None

            source_text = ""
            for sel in (
                "div#paste_code",
                "textarea#paste_code",
                ".post-view",
                ".post-view ol",
                "div.source",
                "pre",
            ):
                try:
                    loc = page.locator(sel)
                    if loc.count() > 0:
                        t = loc.first.inner_text(timeout=5000)
                        if t and t.strip():
                            source_text = t
                            break
                except Exception:
                    continue

            emails, ips, domains = self._extract_entities_from_text(source_text)

            content_type = ["leak"]
            try:
                if helper_method.is_code(source_text or ""):
                    content_type.append("code")
            except Exception:
                pass

            card = social_model(
                m_title=title,
                m_channel_url=str(getattr(page, "url", url)),
                m_message_sharable_link=str(getattr(page, "url", url)),
                m_content=(source_text or "").replace("\xa0", " ").strip(),
                m_network=helper_method.get_network_type(self.base_url),
                m_content_type=content_type,
                m_platform="pastebin",
                m_message_date=date,
            )

            ent = self._make_entity_model(
                m_scrap_file=self.__class__.__name__,
                m_username=[username] if username else [],
                m_ip=ips,
                m_email=emails,
                m_weblink=domains,
            )

            self.append_leak_data(card, ent)

    # -------------------------
    # Requests fallback
    # -------------------------
    def _get_html(self, url: str, timeout: int = 30) -> str:
        resp = self._session.get(url, timeout=timeout, allow_redirects=True)
        return resp.text or ""

    def _extract_paste_links_from_archive_html(self, html: str) -> List[str]:
        soup = BeautifulSoup(html, "lxml")
        links: List[str] = []
        for a in soup.select("a[href]"):
            href = (a.get("href") or "").strip()
            if not href:
                continue
            if not self._PASTE_ID_RE.fullmatch(href):
                continue
            if href in ("/archive", "/trends", "/pro", "/login", "/signup"):
                continue
            links.append(urljoin(self.base_url, href))
        return list(dict.fromkeys(links))

    def _parse_with_requests(self) -> None:
        archive_candidates = [
            f"{self.base_url}/archive",
            f"{self.base_url}/archive?limit=100",
        ]

        archive_html = ""
        used_archive_url = ""

        for u in archive_candidates:
            try:
                archive_html = self._get_html(u, timeout=30)
                used_archive_url = u
                if archive_html and len(archive_html) > 500:
                    break
            except Exception:
                continue

        if not archive_html:
            log.g().e("[pastebin][requests] archive fetch failed: empty html")
            return

        if self._is_bot_block_html(archive_html):
            log.g().e("[pastebin][requests] archive looks bot-block/captcha. Consider Playwright integration.")

        url_lists = self._extract_paste_links_from_archive_html(archive_html)

        if not url_lists:
            snippet = (archive_html[:300] or "").replace("\n", " ").replace("\r", " ")
            log.g().e(
                f"[pastebin][requests] 0 links extracted. archive_url={used_archive_url} html_snippet={snippet}"
            )
            return

        if self._is_crawled and url_lists:
            url_lists = url_lists[:2]

        for url in url_lists:
            try:
                p_html = self._get_html(url, timeout=30)
            except Exception:
                continue

            if not p_html or len(p_html) < 200:
                continue
            if self._is_bot_block_html(p_html):
                continue

            ps = BeautifulSoup(p_html, "lxml")

            title = ""
            username = ""
            date = None

            try:
                info_top = ps.select_one("div.info-top")
                title = info_top.get_text(strip=True) if info_top else ""
            except Exception:
                title = ""

            try:
                u = ps.select_one("div.username a") or ps.select_one("div.username")
                username = u.get_text(strip=True) if u else ""
            except Exception:
                username = ""

            try:
                d = ps.select_one("div.date")
                date = self._parse_date_text(d.get_text(strip=True) if d else "")
            except Exception:
                date = None

            source_text = ""
            for sel in (
                "div#paste_code",
                "textarea#paste_code",
                "div.post-view",
                "pre",
            ):
                el = ps.select_one(sel)
                if el:
                    t = el.get_text("\n", strip=True)
                    if t:
                        source_text = t
                        break

            emails, ips, domains = self._extract_entities_from_text(source_text)

            content_type = ["leak"]
            try:
                if helper_method.is_code(source_text or ""):
                    content_type.append("code")
            except Exception:
                pass

            card = social_model(
                m_title=title,
                m_channel_url=url,
                m_message_sharable_link=url,
                m_content=(source_text or "").replace("\xa0", " ").strip(),
                m_network=helper_method.get_network_type(self.base_url),
                m_content_type=content_type,
                m_platform="pastebin",
                m_message_date=date,
            )

            ent = self._make_entity_model(
                m_scrap_file=self.__class__.__name__,
                m_username=[username] if username else [],
                m_ip=ips,
                m_email=emails,
                m_weblink=domains,
            )

            self.append_leak_data(card, ent)

    # -------------------------
    # run()
    # -------------------------
    def run(self, page: Optional[Any] = None) -> List[Dict[str, Any]]:
        try:
            self._card_data.clear()
            self._entity_data.clear()

            if page is not None:
                self.attach_page(page)

            detected = self._detect_page_object()
            self.parse_leak_data(detected)

            out: List[Dict[str, Any]] = []
            for c, e in zip(self._card_data, self._entity_data):
                out.append(
                    {
                        "leak": c.to_dict() if hasattr(c, "to_dict") else c.__dict__,
                        "entity": e.to_dict() if hasattr(e, "to_dict") else e.__dict__,
                    }
                )
            return out

        except Exception as ex:
            log.g().e(f"SCRIPT ERROR (run) {ex} | {self.__class__.__name__}")
            raise
