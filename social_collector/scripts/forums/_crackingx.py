from __future__ import annotations

import hashlib
import inspect
import json
import re
from abc import ABC
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse
import os
from pathlib import Path
from datetime import timezone
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
from crawler.common.crawler_instance.crawler_services.shared.helper_method import (
    helper_method,
)
from crawler.common.crawler_instance.crawler_services.log_manager.log_controller import log


class _crackingx(leak_extractor_interface, ABC):
    _instance = None

    NAV_TIMEOUT_MS = 120_000
    MAX_SECTION_PAGES_FIRST_RUN = 5
    MAX_SECTION_PAGES_NEXT_RUN = 200

    THREAD_LIMIT_FIRST_RUN = 200
    THREAD_LIMIT_NEXT_RUN = 120

    MAX_TEXT_BLOCKS = 20
    MAX_USERS = 5
    MAX_TAGS = 80
    MAX_OUT_LINKS = 200

    # ✅ clearnet: RequestParser seed_fetch needed nahi
    needs_seed_fetch = False

    def __init__(self, callback=None):
        self.callback = callback
        self._card_data: List[social_model] = []
        self._entity_data: List[entity_model] = []
        self._redis_instance = redis_controller()
        self._is_crawled = False
        # -------------------------
        # JSONL File output
        # -------------------------
        base_dir = os.getenv("DARKPULSE_EXPORT_DIR", "data/exports")
        Path(base_dir).mkdir(parents=True, exist_ok=True)

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        script_name = self.__class__.__name__
        self._jsonl_path = str(Path(base_dir) / f"{script_name}_{ts}.jsonl")
        # may be injected by framework
        self.page = None
        self._page = None
        self.seed_page = None
        self._request_page = None

    def __new__(cls, callback=None):
        if cls._instance is None:
            cls._instance = super(_crackingx, cls).__new__(cls)
        return cls._instance

    # -------------------------
    # META
    # -------------------------
    @property
    def seed_url(self) -> str:
        return "https://crackingx.com"

    @property
    def base_url(self) -> str:
        u = urlparse(self.seed_url)
        return f"{u.scheme}://{u.netloc}"

    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def rule_config(self) -> RuleModel:
        # ✅ clearnet
        return RuleModel(
            m_fetch_proxy=FetchProxy.NONE,
            m_fetch_config=FetchConfig.PLAYRIGHT,
            m_threat_type=ThreatType.FORUM,
        )

    @property
    def card_data(self) -> List[social_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def contact_page(self) -> str:
        return "https://crackingx.com/misc/contact"

    # -------------------------
    # JSONL debug
    # -------------------------
    def _print_jsonl(self, payload: Dict[str, Any]):
        line = json.dumps(payload, ensure_ascii=False, default=str)

        # 1) Console
        print(line, flush=True)

        # 2) File (JSONL append)
        try:
            with open(self._jsonl_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
        except Exception as ex:
            # File write fail ho to crawling rukni nahi chahiye
            log.g().e(f"[onion] JSONL file write failed: {ex} | path={getattr(self, '_jsonl_path', '')}")
    # -------------------------
    # Redis helpers (ONLY GET/SET/DELETE exist)
    # -------------------------
    def invoke_db(self, command: int, key: str, default_value, expiry: int = None):
        namespaced_key = f"{key}{self.__class__.__name__}"
        return self._redis_instance.invoke_trigger(int(command), [namespaced_key, default_value, expiry])

    def _redis_get(self, key: str, default: str = "") -> str:
        try:
            return self.invoke_db(REDIS_COMMANDS.GET, key, default) or default
        except Exception:
            return default

    def _redis_set(self, key: str, value: str, expiry: int = None):
        try:
            self.invoke_db(REDIS_COMMANDS.SET, key, value, expiry)
        except Exception:
            pass

    def _last_seen_key(self, section_hash: str) -> str:
        # store under GENERIC namespace
        return f"{CUSTOM_SCRIPT_REDIS_KEYS.GENERIC}crackingx:last_seen:{section_hash}:"

    def _redis_get_last_seen_dt(self, section_hash: str) -> Optional[datetime]:
        val = self._redis_get(self._last_seen_key(section_hash), "")
        if not val:
            return None
        try:
            return datetime.fromisoformat(str(val).replace("Z", "+00:00")).astimezone(timezone.utc)
        except Exception:
            return None

    def _redis_set_last_seen_dt(self, section_hash: str, dt_utc: datetime):
        if dt_utc.tzinfo is None:
            dt_utc = dt_utc.replace(tzinfo=timezone.utc)
        self._redis_set(self._last_seen_key(section_hash), dt_utc.astimezone(timezone.utc).isoformat())

    # -------------------------
    # Safe entity_model
    # -------------------------
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
                else:
                    filtered[name] = "unknown"

        if "m_scrap_file" not in filtered:
            filtered["m_scrap_file"] = self.__class__.__name__

        return entity_model(**filtered)

    # -------------------------
    # Utils
    # -------------------------
    @staticmethod
    def _clean(s: str) -> str:
        return re.sub(r"\s+", " ", (s or "")).strip()

    @staticmethod
    def _parse_time_attr(dt_attr: str) -> Optional[datetime]:
        if not dt_attr:
            return None
        try:
            return datetime.fromisoformat(dt_attr.replace("Z", "+00:00")).astimezone(timezone.utc)
        except Exception:
            try:
                return datetime.strptime(dt_attr, "%Y-%m-%dT%H:%M:%S%z").astimezone(timezone.utc)
            except Exception:
                return None

    @staticmethod
    def _data_hash(s: str) -> str:
        return hashlib.sha1((s or "").encode("utf-8", errors="ignore")).hexdigest()

    def _category_mapping(self) -> Dict[str, List[str]]:
        return {
            "cracking": [
                "https://crackingx.com/forums/9/",
                "https://crackingx.com/forums/5/",
                "https://crackingx.com/forums/2/",
                "https://crackingx.com/forums/17/",
                "https://crackingx.com/forums/11/",
            ],
            "Marketplace": [
                "https://crackingx.com/forums/premium_section/",
                "https://crackingx.com/forums/14/",
                "https://crackingx.com/forums/13/",
                "https://crackingx.com/forums/16/",
            ],
            "Money": [
                "https://crackingx.com/forums/4/",
                "https://crackingx.com/forums/19/",
            ],
        }

    # -------------------------
    # Section -> thread URLs
    # -------------------------
    def _collect_threads_from_section(self, page, section_url: str, max_pages: int) -> List[Dict[str, Any]]:
        section_hash = self._data_hash(section_url)

        last_seen = self._redis_get_last_seen_dt(section_hash)
        if last_seen is None:
            max_days = 500 if not self.is_crawled else 30
            last_seen = datetime.now(timezone.utc) - timedelta(days=max_days)

        results: List[Dict[str, Any]] = []
        next_url = section_url
        page_num = 1

        while next_url and page_num <= max_pages:
            page.goto(next_url, wait_until="domcontentloaded", timeout=self.NAV_TIMEOUT_MS)

            items = page.query_selector_all(".structItem")
            if not items:
                break

            for item in items:
                title_el = item.query_selector("a[href^='/threads/']") or item.query_selector(
                    ".structItem-title a[href*='/threads/']"
                )
                if not title_el:
                    continue

                href = (title_el.get_attribute("href") or "").strip()
                title = (title_el.inner_text() or "").strip()
                if not href:
                    continue

                time_el = item.query_selector("time.structItem-latestDate.u-dt") or item.query_selector("time.u-dt")
                if not time_el:
                    continue

                dt_attr = (time_el.get_attribute("datetime") or "").strip()
                dt_utc = self._parse_time_attr(dt_attr)
                if not dt_utc:
                    continue

                if dt_utc <= last_seen:
                    continue

                full = urljoin(self.base_url, href)
                results.append({"url": full, "title": title, "dt_utc": dt_utc})

            # next page
            nurl = None
            try:
                loc = page.locator("a.pageNav-jump--next").last
                if loc.count() > 0:
                    v = loc.get_attribute("href")
                    if v:
                        nurl = urljoin(page.url, v)
            except Exception:
                nurl = None

            next_url = nurl
            page_num += 1

        if results:
            newest = max(results, key=lambda x: x["dt_utc"])["dt_utc"]
            self._redis_set_last_seen_dt(section_hash, newest)

        return results

    # -------------------------
    # Thread extraction
    # -------------------------
    def _extract_thread_fields(self, page, thread_url: str) -> Dict[str, Any]:
        page.goto(thread_url, wait_until="domcontentloaded", timeout=self.NAV_TIMEOUT_MS)

        thread_dt_utc: Optional[datetime] = None
        tloc = page.locator("time.u-dt").first
        if tloc.count() > 0:
            dt_attr = (tloc.get_attribute("datetime") or "").strip()
            thread_dt_utc = self._parse_time_attr(dt_attr)

        wrappers = page.locator("div.bbWrapper")
        wrapper_count = wrappers.count()

        max_days = 5 if self.is_crawled else 500
        if wrapper_count < 10:
            if not thread_dt_utc:
                return {}
            if (datetime.now(timezone.utc) - thread_dt_utc).days > max_days:
                return {}

        n = min(wrappers.count(), self.MAX_TEXT_BLOCKS)
        blocks: List[str] = []
        for i in range(n):
            try:
                txt = wrappers.nth(i).inner_text() or ""
            except Exception:
                txt = ""
            txt = re.sub(r"\n+", "\n", txt).strip()
            if txt:
                blocks.append(txt[:1000])
        content = "\n".join(blocks).strip()

        usernames: List[str] = []
        seen_u = set()
        for el in page.query_selector_all("a.username")[: self.MAX_USERS]:
            u = (el.inner_text() or "").strip()
            if u and u not in seen_u:
                seen_u.add(u)
                usernames.append(u)

        hashtags: List[str] = []
        seen_t = set()
        for el in page.query_selector_all("a.tagItem")[: self.MAX_TAGS]:
            t = (el.inner_text() or "").strip()
            if t and t not in seen_t:
                seen_t.add(t)
                hashtags.append(t)

        out_links: List[str] = []
        seen_l = set()
        for a in page.query_selector_all("div.bbWrapper a[href]"):
            href = (a.get_attribute("href") or "").strip()
            if not href:
                continue
            full = urljoin(thread_url, href)
            if not full.startswith(("http://", "https://")):
                continue
            if full in seen_l:
                continue
            seen_l.add(full)
            out_links.append(full)
            if len(out_links) >= self.MAX_OUT_LINKS:
                break

        return {
            "thread_dt_utc": thread_dt_utc,
            "wrapper_count": wrapper_count,
            "content": content,
            "usernames": usernames,
            "hashtags": hashtags,
            "out_links": out_links,
        }

    # -------------------------
    # Append
    # -------------------------
    def append_leak_data(self, leak: social_model, entity: entity_model):
        self._card_data.append(leak)
        self._entity_data.append(entity)
        if self.callback and self.callback():
            self._card_data.clear()
            self._entity_data.clear()

    # -------------------------
    # Interface-required
    # -------------------------
    def parse_leak_data(self, page_obj):
        self._print_jsonl({"source": "crackingx", "type": "debug", "export_jsonl_path": getattr(self, "_jsonl_path", ""),"seed_url": self.seed_url})

    # -------------------------
    # RUN
    # -------------------------
    def run(self):
        try:
            self._card_data.clear()
            self._entity_data.clear()

            max_pages = self.MAX_SECTION_PAGES_NEXT_RUN if self.is_crawled else self.MAX_SECTION_PAGES_FIRST_RUN
            thread_limit = self.THREAD_LIMIT_NEXT_RUN if self.is_crawled else self.THREAD_LIMIT_FIRST_RUN

            mapping = self._category_mapping()
            all_threads: List[Dict[str, Any]] = []

            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
                )
                context = browser.new_context(
                    user_agent=(
                        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/120 Safari/537.36"
                    ),
                    viewport={"width": 1280, "height": 720},
                    locale="en-US",
                    ignore_https_errors=True,
                )
                page = context.new_page()

                # collect threads
                for category, section_urls in mapping.items():
                    for section_url in section_urls:
                        try:
                            threads = self._collect_threads_from_section(page, section_url, max_pages=max_pages)
                            for t in threads:
                                t["category"] = category
                            all_threads.extend(threads)
                        except Exception as ex:
                            log.g().e(f"[crackingx] collect_threads error {ex} | {section_url}")

                all_threads.sort(
                    key=lambda x: x.get("dt_utc") or datetime(1970, 1, 1, tzinfo=timezone.utc),
                    reverse=True,
                )
                all_threads = all_threads[:thread_limit]

                self._print_jsonl(
                    {"source": "crackingx", "type": "debug", "threads_to_parse": len(all_threads), "sample": [t["url"] for t in all_threads[:20]]}
                )

                for t in all_threads:
                    thread_url = t["url"]
                    thread_title = t.get("title") or ""
                    category = t.get("category") or "unknown"

                    try:
                        fields = self._extract_thread_fields(page, thread_url)
                        if not fields:
                            continue

                        dt_utc = fields.get("thread_dt_utc")
                        msg_date: Optional[date] = dt_utc.date() if isinstance(dt_utc, datetime) else None

                        card = social_model(
                            m_title=thread_title,
                            m_channel_url=thread_url,
                            m_content=(fields.get("content") or "")[:4000],
                            m_network=helper_method.get_network_type(self.base_url),
                            m_message_date=msg_date,
                            m_content_type=["leaks", category],
                            m_platform="forum",
                            m_message_sharable_link=thread_url,
                            m_post_comments_count=str(fields.get("wrapper_count") or 0),
                        )

                        ent = self._safe_entity(
                            m_scrap_file=self.__class__.__name__,
                            m_author=fields.get("usernames") or [],
                            m_hashtags=fields.get("hashtags") or [],
                        )

                        self.append_leak_data(card, ent)

                    except Exception as ex:
                        log.g().e(f"[crackingx] thread parse error {ex} | {thread_url}")

                context.close()
                browser.close()

            self._is_crawled = True

            return [
                {
                    "social": c.to_dict() if hasattr(c, "to_dict") else c.__dict__,
                    "entity": e.to_dict() if hasattr(e, "to_dict") else e.__dict__,
                }
                for c, e in zip(self._card_data, self._entity_data)
            ]

        except Exception as ex:
            log.g().e(f"SCRIPT ERROR (run) {ex} | {self.__class__.__name__}")
            raise
