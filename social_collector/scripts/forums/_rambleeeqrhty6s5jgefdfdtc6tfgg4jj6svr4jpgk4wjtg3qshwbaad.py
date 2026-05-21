from __future__ import annotations

import inspect
import json
import re
import hashlib
from abc import ABC
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
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
    REDIS_KEYS,
)
from crawler.common.crawler_instance.crawler_services.log_manager.log_controller import log


class _rambleeeqrhty6s5jgefdfdtc6tfgg4jj6svr4jpgk4wjtg3qshwbaad(leak_extractor_interface, ABC):
    _instance = None
    needs_seed_fetch = True

    NAV_TIMEOUT_MS = 120_000

    MAX_DAYS_FIRST_RUN = 500
    MAX_DAYS_NEXT_RUN = 30

    MAX_PAGE_FIRST_RUN = 5
    MAX_PAGE_NEXT_RUN = 2

    COMMENTS_HEAD = 10
    COMMENTS_TAIL = 10

    SECTIONS = [
        "/f/Privacy",
        "/f/FreeSpeech",
        "/f/Security",
    ]

    def __init__(self, callback=None):
        self.callback = callback
        self._card_data: List[social_model] = []
        self._entity_data: List[entity_model] = []
        self._redis_instance = redis_controller()
        self._is_crawled = False

        self.page = None
        self._page = None
        self.seed_page = None
        self._request_page = None

        self._seed_response = None
        self._seed_html = ""

    def __new__(cls, callback=None):
        if cls._instance is None:
            cls._instance = super(
                _rambleeeqrhty6s5jgefdfdtc6tfgg4jj6svr4jpgk4wjtg3qshwbaad, cls
            ).__new__(cls)
        return cls._instance

    # -------------------------
    # ✅ HASH (no helper_method)
    # -------------------------
    @staticmethod
    def _generate_data_hash(text: str) -> str:
        """
        Generates deterministic hash for Redis keys
        """
        if text is None:
            text = ""
        b = text.encode("utf-8", errors="ignore")
        return hashlib.md5(b).hexdigest()

    @property
    def seed_url(self) -> str:
        return "http://rambleeeqrhty6s5jgefdfdtc6tfgg4jj6svr4jpgk4wjtg3qshwbaad.onion/forums"

    @property
    def base_url(self) -> str:
        u = urlparse(self.seed_url)
        return f"{u.scheme}://{u.netloc}"

    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_fetch_proxy=FetchProxy.TOR,
            m_resoource_block=False,
            m_fetch_config=FetchConfig.REQUESTS,
            m_threat_type=ThreatType.FORUM,
        )

    @property
    def card_data(self) -> List[social_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def contact_page(self) -> str:
        return self.base_url

    def _print_jsonl(self, payload: Dict[str, Any]):
        print(json.dumps(payload, ensure_ascii=False, default=str), flush=True)

    def invoke_db(self, command, key: str, default_value, expiry: int = None):
        try:
            cmd_value = command.value if hasattr(command, "value") else int(command)
        except Exception:
            cmd_value = command
        namespaced_key = f"{key}{self.__class__.__name__}"
        return self._redis_instance.invoke_trigger(cmd_value, [namespaced_key, default_value, expiry])

    @staticmethod
    def _dt_to_iso_z(dt: datetime) -> str:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _iso_to_dt(s: str) -> Optional[datetime]:
        if not s:
            return None
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            m = re.fullmatch(r"(\d{4})(\d{2})(\d{2})", s.strip())
            if m:
                try:
                    return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=timezone.utc)
                except Exception:
                    return None
        return None

    # -------------------------
    # ✅ DATE PARSER (no helper_method)
    # -------------------------
    @staticmethod
    def _parse_date(raw: str, now: Optional[datetime] = None) -> Optional[datetime]:
        """
        Robust date parser for forum timestamps.
        Returns timezone-aware datetime (UTC) or None.
        Handles:
          - ISO 8601: 2026-02-13T03:18:31Z / +00:00
          - "YYYY-MM-DD HH:MM:SS"
          - "YYYY-MM-DD"
          - "Feb 13, 2026" / "13 Feb 2026" / similar
          - relative: "today", "yesterday", "2 days ago", "3 hours ago", "15 min ago"
        """
        if not raw:
            return None

        s = str(raw).strip()
        if not s:
            return None

        if now is None:
            now = datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        low = s.lower()

        # Relative keywords
        if low in {"today"}:
            return now
        if low in {"yesterday"}:
            return now - timedelta(days=1)

        # Relative: "2 days ago", "3 hours ago", "15 minutes ago"
        rel = re.search(r"(\d+)\s*(sec|secs|second|seconds|min|mins|minute|minutes|hour|hours|day|days|week|weeks)\s*ago", low)
        if rel:
            n = int(rel.group(1))
            unit = rel.group(2)
            if unit.startswith("sec"):
                return now - timedelta(seconds=n)
            if unit.startswith("min"):
                return now - timedelta(minutes=n)
            if unit.startswith("hour"):
                return now - timedelta(hours=n)
            if unit.startswith("day"):
                return now - timedelta(days=n)
            if unit.startswith("week"):
                return now - timedelta(weeks=n)

        # ISO 8601
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass

        # Common formats
        fmts = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%d",
            "%d-%m-%Y",
            "%d/%m/%Y",
            "%Y/%m/%d",
            "%b %d, %Y",
            "%B %d, %Y",
            "%d %b %Y",
            "%d %B %Y",
            "%b %d %Y",
            "%B %d %Y",
        ]
        for f in fmts:
            try:
                dt = datetime.strptime(s, f)
                dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except Exception:
                continue

        # Fallback: extract something like YYYY-MM-DD anywhere in string
        m = re.search(r"(\d{4})[-/](\d{2})[-/](\d{2})", s)
        if m:
            try:
                y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
                return datetime(y, mo, d, tzinfo=timezone.utc)
            except Exception:
                return None

        return None

    def _safe_entity(self, **kwargs) -> entity_model:
        sig = inspect.signature(entity_model.__init__)
        params = sig.parameters

        allowed = set(params.keys())
        allowed.discard("self")

        filtered = {k: v for k, v in kwargs.items() if k in allowed}

        for name, p in params.items():
            if name == "self":
                continue
            is_required = (p.default is inspect._empty) and (
                p.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
            )
            if is_required and name not in filtered:
                if name == "m_scrap_file":
                    filtered[name] = self.__class__.__name__
                elif name in ("m_username",):
                    filtered[name] = ["unknown"]
                else:
                    filtered[name] = "unknown"

        if "m_scrap_file" not in filtered:
            filtered["m_scrap_file"] = self.__class__.__name__

        return entity_model(**filtered)

    def _get_tor_proxy_server(self) -> str:
        return "socks5://127.0.0.1:9150"

    @staticmethod
    def _clean(s: str) -> str:
        return re.sub(r"\s+", " ", (s or "")).strip()

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

    def parse_leak_data(self, page_obj):
        seed_html = ""
        try:
            if hasattr(page_obj, "_seed_response") and page_obj._seed_response is not None:
                seed_html = page_obj._seed_response.text or ""
        except Exception:
            seed_html = ""

        self._print_jsonl(
            {
                "source": "ramble_forum",
                "type": "debug",
                "seed_url": self.seed_url,
                "html_length": len(seed_html),
                "has_seed_html": bool(seed_html),
                "note": "Actual forum crawl happens in run() via Playwright.",
            }
        )

    def _crawl_section(self, nav_page, section_url: str, max_days: int, max_page: int):
        max_date = datetime.now(timezone.utc) - timedelta(days=max_days)

        redis_key = self._generate_data_hash(section_url) + str(REDIS_KEYS.S_URL_TIMEOUT)

        last_seen_raw = self.invoke_db(REDIS_COMMANDS.S_GET_STRING, redis_key, "")
        last_seen_dt = self._iso_to_dt(last_seen_raw) if last_seen_raw else None
        if last_seen_dt is None:
            last_seen_dt = datetime.now(timezone.utc) - timedelta(days=max_days)

        self._print_jsonl(
            {
                "source": "ramble_forum",
                "type": "debug",
                "section": section_url,
                "max_days": max_days,
                "max_page": max_page,
                "last_seen": self._dt_to_iso_z(last_seen_dt),
            }
        )

        current_url = section_url
        page_count = 0
        latest_dt_seen: Optional[datetime] = None

        while current_url and page_count < max_page:
            page_count += 1

            nav_page.goto(current_url, timeout=self.NAV_TIMEOUT_MS, wait_until="domcontentloaded")
            try:
                nav_page.wait_for_load_state("networkidle")
            except Exception:
                pass

            post_rows = nav_page.query_selector_all("div.submission__row") or []
            if not post_rows:
                break

            next_href = ""
            try:
                next_li = nav_page.query_selector("li.next")
                next_link = next_li.query_selector('a[rel="next"]') if next_li else None
                if next_link:
                    next_href = (next_link.get_attribute("href") or "").strip()
            except Exception:
                next_href = ""

            valid_threads: List[Dict[str, Any]] = []

            for post in post_rows:
                atag = post.query_selector('h1.submission__title a.submission__link')
                if not atag:
                    continue

                title = self._clean(atag.inner_text() or "")
                href = (atag.get_attribute("href") or "").strip()
                if not href:
                    continue

                date_el = post.query_selector("time.submission__timestamp")
                raw_dt = (date_el.get_attribute("datetime") or "").strip() if date_el else ""

                # ✅ FIX: no helper_method usage
                thread_dt = self._parse_date(raw_dt)

                if isinstance(thread_dt, datetime) and thread_dt.tzinfo is None:
                    thread_dt = thread_dt.replace(tzinfo=timezone.utc)

                if not isinstance(thread_dt, datetime):
                    continue

                if thread_dt < max_date:
                    continue

                if thread_dt.date() <= last_seen_dt.date():
                    continue

                thread_url = urljoin(current_url, href)
                valid_threads.append(
                    {
                        "thread_url": thread_url,
                        "title": title,
                        "raw_dt": raw_dt,
                        "thread_dt": thread_dt,
                    }
                )

            if not valid_threads:
                break

            page_latest = max(valid_threads, key=lambda x: x["thread_dt"])["thread_dt"]
            if latest_dt_seen is None or page_latest > latest_dt_seen:
                latest_dt_seen = page_latest

            for t in valid_threads:
                self._crawl_thread(nav_page, t["thread_url"], t["title"], t["raw_dt"])

            if next_href:
                current_url = urljoin(current_url, next_href)
            else:
                break

        if latest_dt_seen is not None:
            self.invoke_db(
                REDIS_COMMANDS.S_SET_STRING,
                redis_key,
                self._dt_to_iso_z(latest_dt_seen),
            )

    # -------------------------
    # ✅ SAFE social_model builder
    # -------------------------
    def _safe_social(self, **kwargs) -> social_model:
        sig = inspect.signature(social_model.__init__)
        params = sig.parameters

        allowed = set(params.keys())
        allowed.discard("self")

        filtered = {k: v for k, v in kwargs.items() if k in allowed}

        for name, p in params.items():
            if name == "self":
                continue
            is_required = (p.default is inspect._empty) and (
                p.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
            )
            if is_required and name not in filtered:
                if name == "m_scrap_file":
                    filtered[name] = self.__class__.__name__
                elif name in ("m_title", "m_description", "m_content"):
                    filtered[name] = ""
                elif name in ("m_url", "m_post_url", "m_thread_url"):
                    filtered[name] = ""
                elif name in ("m_username", "m_author", "m_user"):
                    filtered[name] = "unknown"
                elif name in ("m_source",):
                    filtered[name] = "ramble_forum"
                else:
                    filtered[name] = "unknown"

        if "m_scrap_file" in allowed and "m_scrap_file" not in filtered:
            filtered["m_scrap_file"] = self.__class__.__name__

        return social_model(**filtered)

    # -------------------------
    # ✅ Thread crawler
    # -------------------------
    def _crawl_thread(self, nav_page, thread_url: str, thread_title: str, thread_raw_dt: str):
        try:
            nav_page.goto(thread_url, timeout=self.NAV_TIMEOUT_MS, wait_until="domcontentloaded")
            try:
                nav_page.wait_for_load_state("networkidle")
            except Exception:
                pass

            title = thread_title or ""
            try:
                h = nav_page.query_selector("h1")
                if h:
                    title2 = self._clean(h.inner_text() or "")
                    if title2:
                        title = title2
            except Exception:
                pass

            created_dt: Optional[datetime] = None
            try:
                time_el = nav_page.query_selector("time")
                dt_attr = (time_el.get_attribute("datetime") or "").strip() if time_el else ""
                if dt_attr:
                    created_dt = self._parse_date(dt_attr)
                elif thread_raw_dt:
                    created_dt = self._parse_date(thread_raw_dt)
            except Exception:
                created_dt = None

            if isinstance(created_dt, datetime) and created_dt.tzinfo is None:
                created_dt = created_dt.replace(tzinfo=timezone.utc)

            created_iso = self._dt_to_iso_z(created_dt) if isinstance(created_dt, datetime) else ""

            author = "unknown"
            try:
                a = nav_page.query_selector('[class*="author"], [class*="user"], a[href*="/u/"], a[href*="/user/"]')
                if a:
                    author2 = self._clean(a.inner_text() or "")
                    if author2:
                        author = author2
            except Exception:
                pass

            body = ""
            try:
                candidates = [
                    "div.post__body",
                    "div.post-body",
                    "div.submission__body",
                    "article",
                    "div.content",
                    "div.markdown",
                ]
                for sel in candidates:
                    el = nav_page.query_selector(sel)
                    if el:
                        txt = self._clean(el.inner_text() or "")
                        if txt and len(txt) > len(body):
                            body = txt
            except Exception:
                pass

            comments: List[str] = []
            try:
                comment_nodes = nav_page.query_selector_all(
                    "div.comment, div.comment__body, li.comment, article.comment, div[data-comment]"
                ) or []
                for n in comment_nodes:
                    try:
                        t = self._clean(n.inner_text() or "")
                        if t:
                            comments.append(t)
                    except Exception:
                        continue
            except Exception:
                comments = []

            if comments and len(comments) > (self.COMMENTS_HEAD + self.COMMENTS_TAIL):
                comments = comments[: self.COMMENTS_HEAD] + comments[-self.COMMENTS_TAIL :]

            leak = self._safe_social(
                m_source="ramble_forum",
                m_title=title,
                m_url=thread_url,
                m_post_url=thread_url,
                m_thread_url=thread_url,
                m_username=author,
                m_author=author,
                m_description=body,
                m_content=body,
                m_created_at=created_iso,
                m_time=created_iso,
                m_comments=comments,
                m_scrap_file=self.__class__.__name__,
            )

            entity = self._safe_entity(
                m_scrap_file=self.__class__.__name__,
                m_username=[author] if author else ["unknown"],
                m_source="ramble_forum",
                m_url=thread_url,
            )

            self.append_leak_data(leak, entity)

            self._print_jsonl(
                {
                    "source": "ramble_forum",
                    "type": "thread",
                    "url": thread_url,
                    "title": title,
                    "author": author,
                    "created_at": created_iso,
                    "comments_count": len(comments),
                    "body_len": len(body),
                }
            )

        except Exception as e:
            self._print_jsonl(
                {
                    "source": "ramble_forum",
                    "type": "error",
                    "stage": "crawl_thread",
                    "url": thread_url,
                    "error": repr(e),
                }
            )

    # -------------------------
    # ✅ REQUIRED by RequestParser
    # -------------------------
    def run(self) -> Dict[str, Any]:
        """
        Entry point expected by RequestParser: self.model.run()
        """
        if self._is_crawled:
            return {
                "status": "already_crawled",
                "items": len(self._card_data),
                "entities": len(self._entity_data),
                "source": "ramble_forum",
            }

        proxy_server = self._get_tor_proxy_server()

        is_next_run = False
        try:
            for sec in self.SECTIONS:
                section_abs = urljoin(self.base_url, sec)
                redis_key = self._generate_data_hash(section_abs) + str(REDIS_KEYS.S_URL_TIMEOUT)
                last_seen_raw = self.invoke_db(REDIS_COMMANDS.S_GET_STRING, redis_key, "")
                if last_seen_raw:
                    is_next_run = True
                    break
        except Exception:
            is_next_run = False

        max_days = self.MAX_DAYS_NEXT_RUN if is_next_run else self.MAX_DAYS_FIRST_RUN
        max_page = self.MAX_PAGE_NEXT_RUN if is_next_run else self.MAX_PAGE_FIRST_RUN

        with sync_playwright() as p:
            browser = p.firefox.launch(
                headless=True,
                proxy={"server": proxy_server},
            )
            context = browser.new_context()
            page = context.new_page()
            self._page = page

            try:
                page.goto(self.seed_url, timeout=self.NAV_TIMEOUT_MS, wait_until="domcontentloaded")
                try:
                    page.wait_for_load_state("networkidle")
                except Exception:
                    pass

                for sec in self.SECTIONS:
                    section_abs = urljoin(self.base_url, sec)
                    self._crawl_section(page, section_abs, max_days=max_days, max_page=max_page)

                self._is_crawled = True

                return {
                    "status": "success",
                    "source": "ramble_forum",
                    "items": len(self._card_data),
                    "entities": len(self._entity_data),
                    "mode": "next_run" if is_next_run else "first_run",
                    "max_days": max_days,
                    "max_page": max_page,
                }

            finally:
                try:
                    context.close()
                except Exception:
                    pass
                try:
                    browser.close()
                except Exception:
                    pass
