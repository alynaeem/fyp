from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
from abc import ABC
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from playwright.sync_api import sync_playwright

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
from crawler.common.crawler_instance.crawler_services.redis_manager.redis_enums import (
    REDIS_COMMANDS,
    CUSTOM_SCRIPT_REDIS_KEYS,
)
from crawler.common.crawler_instance.crawler_services.log_manager.log_controller import log



class _ownzyou(leak_extractor_interface, ABC):
    _instance = None

    NAV_TIMEOUT_MS = 120_000

    MAX_LIST_PAGES_FIRST_RUN = 5
    MAX_LIST_PAGES_NEXT_RUN = 30

    THREAD_LIMIT_FIRST_RUN = 120
    THREAD_LIMIT_NEXT_RUN = 80

    MAX_POSTS_PER_THREAD = 20
    MAX_CONTENT_CHARS = 4000
    MAX_OUT_LINKS = 200

    needs_seed_fetch = False

    def __init__(self, callback=None):
        self.callback = callback
        self._card_data: List[social_model] = []
        self._entity_data: List[entity_model] = []
        self._redis = redis_controller()
        self._is_crawled = False

        self.page = None
        self._page = None
        self.seed_page = None
        self._request_page = None

    def __new__(cls, callback=None):
        if cls._instance is None:
            cls._instance = super(_ownzyou, cls).__new__(cls)
        return cls._instance

    # ---------------- META ----------------
    @property
    def seed_url(self) -> str:
        return "https://ownzyou.com/forum/"

    @property
    def base_url(self) -> str:
        u = urlparse(self.seed_url)
        return f"{u.scheme}://{u.netloc}"

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_fetch_proxy=FetchProxy.NONE,
            m_fetch_config=FetchConfig.PLAYRIGHT,
            m_threat_type=ThreatType.FORUM,
        )

    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def card_data(self):
        return self._card_data

    @property
    def entity_data(self):
        return self._entity_data

    def contact_page(self) -> str:
        return "https://ownzyou.com/forum/misc/contact"

    # ---------------- REDIS ----------------
    def invoke_db(self, command: int, key: str, default_value, expiry: int = None):
        return self._redis.invoke_trigger(
            int(command),
            [key + self.__class__.__name__, default_value, expiry],
        )

    def _data_hash(self, s: str) -> str:
        return hashlib.sha1((s or "").encode("utf-8")).hexdigest()

    def _last_seen_key(self, section_hash: str) -> str:
        return f"{CUSTOM_SCRIPT_REDIS_KEYS.GENERIC}ownzyou:last_seen:{section_hash}:"

    def _redis_get_last_seen(self, section_hash: str) -> datetime:
        val = self.invoke_db(
            REDIS_COMMANDS.GET,
            self._last_seen_key(section_hash),
            "",
        )
        if val:
            try:
                return datetime.fromisoformat(val.replace("Z", "+00:00")).astimezone(timezone.utc)
            except Exception:
                pass
        return datetime.now(timezone.utc) - timedelta(days=500)

    def _redis_set_last_seen(self, section_hash: str, dt: datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        self.invoke_db(
            REDIS_COMMANDS.SET,
            self._last_seen_key(section_hash),
            dt.isoformat(),
        )

    # ---------------- ENTITY SAFE ----------------
    def _safe_entity(self, **kwargs) -> entity_model:
        sig = inspect.signature(entity_model.__init__)
        allowed = set(sig.parameters.keys())
        allowed.discard("self")

        data = {k: v for k, v in kwargs.items() if k in allowed}

        if "m_scrap_file" not in data:
            data["m_scrap_file"] = self.__class__.__name__
        if "m_username" not in data:
            data["m_username"] = ["unknown"]

        return entity_model(**data)

    # ---------------- UTILS ----------------
    @staticmethod
    def _clean(s: str) -> str:
        return re.sub(r"\s+", " ", (s or "")).strip()

    @staticmethod
    def _parse_dt(dt_attr: str) -> Optional[datetime]:
        if not dt_attr:
            return None
        try:
            return datetime.fromisoformat(dt_attr.replace("Z", "+00:00")).astimezone(timezone.utc)
        except Exception:
            return None

    def _get_page(self):
        for attr in ("_request_page", "seed_page", "page", "_page"):
            p = getattr(self, attr, None)
            if p is not None and hasattr(p, "goto"):
                return p
        return None

    def _detect_proxy(self) -> Optional[str]:
        for k in ("DARKPULSE_SOCKS_PROXY", "TOR_SOCKS_PROXY", "ALL_PROXY", "HTTPS_PROXY"):
            v = (os.environ.get(k) or "").strip()
            if v:
                if v.startswith("socks5h://"):
                    v = "socks5://" + v[len("socks5h://") :]
                return v
        return "socks5://127.0.0.1:9150"

    # ---------------- CATEGORIES ----------------
    def _collect_categories(self, page) -> List[str]:
        page.goto(self.seed_url, wait_until="domcontentloaded", timeout=self.NAV_TIMEOUT_MS)
        urls = []
        for a in page.query_selector_all("h3.node-title a"):
            href = a.get_attribute("href")
            if href:
                urls.append(urljoin(self.seed_url, href))
        return urls

    # ---------------- THREAD LIST ----------------
    def _collect_threads(self, page, section_url: str, max_pages: int) -> List[Dict[str, Any]]:
        section_hash = self._data_hash(section_url)
        last_seen = self._redis_get_last_seen(section_hash)

        out = []
        newest = None

        for pn in range(1, max_pages + 1):
            url = section_url if pn == 1 else f"{section_url}?page={pn}"
            page.goto(url, wait_until="domcontentloaded", timeout=self.NAV_TIMEOUT_MS)

            items = page.query_selector_all("div.structItem--thread")
            if not items:
                break

            for it in items:
                a = it.query_selector("div.structItem-title a")
                t = it.query_selector("time.structItem-latestDate")
                if not a or not t:
                    continue

                thread_url = urljoin(url, a.get_attribute("href"))
                title = self._clean(a.inner_text())

                dt = self._parse_dt(t.get_attribute("datetime"))
                if not dt or dt <= last_seen:
                    continue

                out.append({"url": thread_url, "title": title, "dt": dt})
                if newest is None or dt > newest:
                    newest = dt

        if newest:
            self._redis_set_last_seen(section_hash, newest)

        return out

    # ---------------- THREAD PARSE ----------------
    def _parse_thread(self, page, t: Dict[str, Any]):
        page.goto(t["url"], wait_until="domcontentloaded", timeout=self.NAV_TIMEOUT_MS)

        posts = page.locator("div.message-content")
        count = posts.count()

        content_parts = []
        users = []

        for i in range(min(count, self.MAX_POSTS_PER_THREAD)):
            txt = self._clean(posts.nth(i).inner_text())
            if txt:
                content_parts.append(txt)

        for u in page.query_selector_all("a.username"):
            name = self._clean(u.inner_text())
            if name and name not in users:
                users.append(name)

        content = "\n\n".join(content_parts)[: self.MAX_CONTENT_CHARS]

        card = social_model(
            m_title=t["title"],
            m_channel_url=self.seed_url,
            m_message_sharable_link=t["url"],
            m_weblink=[t["url"]],
            m_content=content,
            m_content_type=["forum"],
            m_network="clearnet",
            m_message_date=t["dt"].date() if isinstance(t["dt"], datetime) else None,
            m_message_id=t["url"],
            m_platform="forum",
            m_source="ownzyou_forum",
            m_post_comments_count=str(count),
        )

        ent = self._safe_entity(
            m_username=users or ["unknown"],
            m_weblink=[t["url"]],
        )

        self.append_leak_data(card, ent)

    # ---------------- INTERFACE ----------------
    def parse_leak_data(self, page_obj):
        if page_obj is not None and hasattr(page_obj, "goto"):
            self._request_page = page_obj

    # ---------------- RUN ----------------
    def run(self):
        self._card_data.clear()
        self._entity_data.clear()

        max_pages = self.MAX_LIST_PAGES_NEXT_RUN if self.is_crawled else self.MAX_LIST_PAGES_FIRST_RUN
        thread_limit = self.THREAD_LIMIT_NEXT_RUN if self.is_crawled else self.THREAD_LIMIT_FIRST_RUN

        injected = self._get_page()

        if injected:
            page = injected
            cats = self._collect_categories(page)
            threads = []
            for c in cats:
                threads.extend(self._collect_threads(page, c, max_pages))
            threads = sorted(threads, key=lambda x: x["dt"], reverse=True)[:thread_limit]
            for t in threads:
                self._parse_thread(page, t)
        else:
            proxy = self._detect_proxy()
            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=True,
                    proxy={"server": proxy},
                    args=["--no-sandbox", "--disable-gpu"],
                )
                ctx = browser.new_context(ignore_https_errors=True)
                page = ctx.new_page()

                cats = self._collect_categories(page)
                threads = []
                for c in cats:
                    threads.extend(self._collect_threads(page, c, max_pages))
                threads = sorted(threads, key=lambda x: x["dt"], reverse=True)[:thread_limit]
                for t in threads:
                    self._parse_thread(page, t)

                ctx.close()
                browser.close()

        self._is_crawled = True

        return [
            {
                "social": c.to_dict() if hasattr(c, "to_dict") else c.__dict__,
                "entity": e.to_dict() if hasattr(e, "to_dict") else e.__dict__,
            }
            for c, e in zip(self._card_data, self._entity_data)
        ]
