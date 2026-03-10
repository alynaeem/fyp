from __future__ import annotations

import hashlib
import inspect
import json
import re
from abc import ABC
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
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


class _csrin(leak_extractor_interface, ABC):
    _instance = None

    needs_seed_fetch = True

    NAV_TIMEOUT_MS = 120_000
    SEED_MAX_URLS = 80

    THREADS_LIMIT_FIRST_RUN = 80
    THREADS_LIMIT_NEXT_RUN = 30

    POSTS_EXTRACT_LIMIT = 12
    USERS_EXTRACT_LIMIT = 20

    MAX_DAYS_FIRST_RUN = 365
    MAX_DAYS_NEXT_RUN = 365

    def __init__(self, callback=None):
        self.callback = callback
        self._card_data: List[social_model] = []
        self._entity_data: List[entity_model] = []
        self._redis_instance = redis_controller()
        self._is_crawled = False

        # RequestParser may set one of these
        self.page = None
        self._page = None
        self.seed_page = None
        self._request_page = None

        # RequestParser seed fetch attaches these
        self._seed_response = None
        self._seed_html = ""

    def __new__(cls, callback=None):
        if cls._instance is None:
            cls._instance = super(_csrin, cls).__new__(cls)
        return cls._instance

    # -------------------------
    # META
    # -------------------------
    @property
    def seed_url(self) -> str:
        return "https://cs.rin.ru/forum/viewforum.php?f=10"

    @property
    def base_url(self) -> str:
        u = urlparse(self.seed_url)
        return f"{u.scheme}://{u.netloc}/forum/"

    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_fetch_proxy=FetchProxy.NONE,
            m_fetch_config=FetchConfig.REQUESTS,
            m_threat_type=ThreatType.SOCIAL,
        )

    @property
    def card_data(self) -> List[social_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def contact_page(self) -> str:
        return "https://cs.rin.ru/forum/chat.php"

    # -------------------------
    # Printing (JSONL)
    # -------------------------
    def _print_jsonl(self, payload: Dict[str, Any]):
        print(json.dumps(payload, ensure_ascii=False, default=str), flush=True)

    # -------------------------
    # Redis helpers
    # -------------------------
    def invoke_db(self, command, key: str, default_value, expiry: int = None):
        try:
            cmd_value = command.value if hasattr(command, "value") else int(command)
        except Exception:
            cmd_value = command
        namespaced_key = f"{key}{self.__class__.__name__}"
        return self._redis_instance.invoke_trigger(cmd_value, [namespaced_key, default_value, expiry])

    def _redis_cmd(self, name: str):
        return getattr(REDIS_COMMANDS, name, None)

    def _redis_key(self, name: str, default: str) -> str:
        key_enum = getattr(CUSTOM_SCRIPT_REDIS_KEYS, name, None)
        if key_enum is not None and hasattr(key_enum, "value"):
            return str(key_enum.value)
        return default

    def _redis_save_json(self, key: str, payload: Dict[str, Any], expiry: int = 60 * 60 * 24 * 7):
        data = json.dumps(payload, ensure_ascii=False, default=str)

        rpush_cmd = self._redis_cmd("RPUSH")
        lpush_cmd = self._redis_cmd("LPUSH")
        set_cmd = self._redis_cmd("SET")

        if rpush_cmd is not None:
            self.invoke_db(rpush_cmd, key, data, expiry=expiry)
            return
        if lpush_cmd is not None:
            self.invoke_db(lpush_cmd, key, data, expiry=expiry)
            return
        if set_cmd is not None:
            uniq = payload.get("m_hash") or payload.get("hash") or str(datetime.utcnow().timestamp())
            self.invoke_db(set_cmd, f"{key}:{uniq}", data, expiry=expiry)
            return

        log.g().e(f"[csrin] Redis save skipped (no RPUSH/LPUSH/SET) | key={key}")

    # -------------------------
    # SAFE HASH (fix for your error)
    # -------------------------
    def _data_hash(self, s: str) -> str:
        """
        Your environment does NOT have helper_method.generate_data_hash().
        So we safely try multiple possibilities, else sha256 fallback.
        """
        try:
            fn = getattr(helper_method, "generate_data_hash", None)
            if callable(fn):
                return str(fn(s))
        except Exception:
            pass

        try:
            fn = getattr(helper_method, "generate_hash", None)
            if callable(fn):
                return str(fn(s))
        except Exception:
            pass

        return hashlib.sha256((s or "").encode("utf-8", errors="ignore")).hexdigest()

    # -------------------------
    # Safe model creators
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
                elif name in ("m_username",):
                    filtered[name] = ["unknown"]
                else:
                    filtered[name] = "unknown"

        if "m_scrap_file" not in filtered:
            filtered["m_scrap_file"] = self.__class__.__name__

        return entity_model(**filtered)

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
            if not is_required or name in filtered:
                continue

            if name in ("m_channel_url",):
                filtered[name] = self.seed_url
            elif name in ("m_message_sharable_link", "m_message_id"):
                filtered[name] = kwargs.get("m_message_sharable_link") or kwargs.get("m_message_id") or self.seed_url
            elif name in ("m_title",):
                filtered[name] = kwargs.get("m_title") or ""
            elif name in ("m_content",):
                filtered[name] = kwargs.get("m_content") or ""
            elif name in ("m_network",):
                filtered[name] = helper_method.get_network_type(self.base_url)
            elif name in ("m_message_date",):
                filtered[name] = datetime.utcnow().date()
            elif name in ("m_platform",):
                filtered[name] = "forum"
            else:
                filtered[name] = "unknown"

        return social_model(**filtered)

    # -------------------------
    # Utils
    # -------------------------
    @staticmethod
    def _clean(s: str) -> str:
        return re.sub(r"\s+", " ", (s or "")).strip()

    def _parse_date_any(self, s: str) -> Optional[datetime]:
        if not s:
            return None
        s = (s or "").strip()

        try:
            dt = helper_method.parse_date(s)
            if dt and isinstance(dt, datetime):
                if dt.tzinfo is None:
                    return dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
        except Exception:
            pass

        fmts = [
            "%a %b %d, %Y %I:%M %p",
            "%b %d, %Y %I:%M %p",
            "%d %b %Y, %H:%M",
            "%Y-%m-%d %H:%M",
            "%Y/%m/%d %H:%M",
        ]
        for f in fmts:
            try:
                dt = datetime.strptime(s, f)
                return dt.replace(tzinfo=timezone.utc)
            except Exception:
                pass

        m = re.search(r"(\d{4})-(\d{2})-(\d{2})", s)
        if m:
            try:
                return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=timezone.utc)
            except Exception:
                return None

        return None

    @staticmethod
    def _date_to_str(d: Optional[date]) -> str:
        if not d:
            return ""
        return d.strftime("%Y%m%d")

    def _get_seed_html(self, page_obj) -> str:
        try:
            if hasattr(page_obj, "_seed_response") and page_obj._seed_response is not None:
                return page_obj._seed_response.text or ""
        except Exception:
            pass

        try:
            if hasattr(self, "_seed_response") and self._seed_response is not None:
                return self._seed_response.text or ""
        except Exception:
            pass

        html = getattr(self, "_seed_html", "") or ""
        if html:
            return html

        try:
            if hasattr(page_obj, "content"):
                return page_obj.content() or ""
        except Exception:
            pass

        return ""

    # -------------------------
    # Seed parsing -> thread URLs
    # -------------------------
    def _collect_threads_from_seed(self, html: str) -> List[Dict[str, Any]]:
        soup = BeautifulSoup(html, "lxml")
        threads: List[Dict[str, Any]] = []
        seen = set()

        for a in soup.select("a.topictitle"):
            href = (a.get("href") or "").strip()
            if not href:
                continue

            thread_url = urljoin(self.seed_url, href)
            title = self._clean(a.get_text(" ", strip=True))

            if thread_url not in seen:
                seen.add(thread_url)
                threads.append({"url": thread_url, "title": title, "seed_dt": None})

        return threads[: self.SEED_MAX_URLS]

    # -------------------------
    # REQUIRED by interface
    # -------------------------
    def parse_leak_data(self, page_obj):
        seed_html = self._get_seed_html(page_obj)
        self._print_jsonl(
            {
                "source": "csrin_forum",
                "type": "debug",
                "seed_url": self.seed_url,
                "html_length": len(seed_html),
                "has_seed_html": bool(seed_html),
            }
        )
        if not seed_html:
            log.g().e("[csrin] Seed HTML empty. Ensure RequestParser(seed_fetch=True) OR use run() fallback.")
            return

        threads = self._collect_threads_from_seed(seed_html)
        self._print_jsonl(
            {
                "source": "csrin_forum",
                "type": "debug",
                "threads_found": len(threads),
                "sample_threads": threads[:30],
            }
        )

    # -------------------------
    # Thread page extraction
    # -------------------------
    def _extract_thread_fields(self, thread_html: str, thread_url: str, fallback_title: str = "") -> Dict[str, Any]:
        soup = BeautifulSoup(thread_html, "lxml")

        t = soup.select_one("h2.topic-title") or soup.select_one("h2") or soup.select_one("title")
        title = self._clean(t.get_text(" ", strip=True)) if t else self._clean(fallback_title)

        post_bodies = soup.select("div.postbody")
        post_count = len(post_bodies)

        content_parts: List[str] = []
        for b in post_bodies[: self.POSTS_EXTRACT_LIMIT]:
            txt = self._clean(b.get_text(" ", strip=True))
            if txt:
                content_parts.append(txt)
        content = "\n\n".join(content_parts).strip()

        usernames: List[str] = []
        for u in soup.select("b.postauthor"):
            name = self._clean(u.get_text(" ", strip=True))
            if name and name not in usernames:
                usernames.append(name)
            if len(usernames) >= self.USERS_EXTRACT_LIMIT:
                break

        post_dt: Optional[datetime] = None
        page_text = self._clean(soup.get_text(" ", strip=True))
        low = page_text.lower()
        if "posted:" in low:
            seg = page_text[low.find("posted:") :][:220]
            post_dt = self._parse_date_any(seg)

        if not post_dt:
            time_el = soup.select_one("time")
            if time_el:
                post_dt = self._parse_date_any(self._clean(time_el.get("datetime") or time_el.get_text(" ", strip=True)))

        if post_dt and post_dt.tzinfo is None:
            post_dt = post_dt.replace(tzinfo=timezone.utc)
        if post_dt:
            post_dt = post_dt.astimezone(timezone.utc)

        return {
            "title": title,
            "content": content,
            "usernames": usernames,
            "post_dt": post_dt,
            "post_count": post_count,
        }

    # -------------------------
    # Last-seen logic (Redis) - FIXED
    # -------------------------
    def _get_last_seen_date(self) -> date:
        key_timeout = self._redis_key("S_URL_TIMEOUT", "S_URL_TIMEOUT")
        redis_key = self._data_hash(self.seed_url) + str(key_timeout)

        get_cmd = getattr(REDIS_COMMANDS, "S_GET_STRING", None) or self._redis_cmd("GET")

        last_seen_str = self.invoke_db(get_cmd, redis_key, "")
        if last_seen_str:
            try:
                return datetime.strptime(str(last_seen_str), "%Y%m%d").date()
            except Exception:
                pass

        max_days = self.MAX_DAYS_NEXT_RUN if self.is_crawled else self.MAX_DAYS_FIRST_RUN
        return (datetime.now(timezone.utc) - timedelta(days=max_days)).date()

    def _set_last_seen_date(self, d: date):
        key_timeout = self._redis_key("S_URL_TIMEOUT", "S_URL_TIMEOUT")
        redis_key = self._data_hash(self.seed_url) + str(key_timeout)

        set_cmd = getattr(REDIS_COMMANDS, "S_SET_STRING", None) or self._redis_cmd("SET")
        self.invoke_db(set_cmd, redis_key, self._date_to_str(d))

    # -------------------------
    # Parse threads with Playwright
    # -------------------------
    def _parse_threads_with_nav_page(self, nav_page, threads: List[Dict[str, Any]]):
        redis_items = self._redis_key("SOCIAL_ITEMS", "SOCIAL_ITEMS")
        redis_entities = self._redis_key("SOCIAL_ENTITIES", "SOCIAL_ENTITIES")

        limit = self.THREADS_LIMIT_NEXT_RUN if self.is_crawled else self.THREADS_LIMIT_FIRST_RUN

        max_days = self.MAX_DAYS_NEXT_RUN if self.is_crawled else self.MAX_DAYS_FIRST_RUN
        min_dt = datetime.now(timezone.utc) - timedelta(days=max_days)

        last_seen = self._get_last_seen_date()
        latest_seen: Optional[date] = None
        processed = 0

        for th in threads[:limit]:
            thread_url = th.get("url") or ""
            fallback_title = th.get("title") or ""

            if not thread_url:
                continue

            try:
                nav_page.goto(thread_url, wait_until="domcontentloaded", timeout=self.NAV_TIMEOUT_MS)
                nav_page.wait_for_load_state("networkidle")

                html = nav_page.content() or ""
                if not html:
                    continue

                data = self._extract_thread_fields(html, thread_url, fallback_title=fallback_title)

                post_dt = data.get("post_dt") or datetime.now(timezone.utc)
                if isinstance(post_dt, datetime) and post_dt.tzinfo is None:
                    post_dt = post_dt.replace(tzinfo=timezone.utc)
                if isinstance(post_dt, datetime):
                    post_dt = post_dt.astimezone(timezone.utc)

                if post_dt < min_dt:
                    continue
                if post_dt.date() <= last_seen:
                    continue

                if latest_seen is None or post_dt.date() > latest_seen:
                    latest_seen = post_dt.date()

                card = self._safe_social(
                    m_title=data.get("title") or fallback_title,
                    m_channel_url=self.seed_url,
                    m_content=(data.get("content") or "")[:4000],
                    m_network=helper_method.get_network_type(self.base_url),
                    m_message_date=post_dt.date(),
                    m_content_type=["forum"],
                    m_platform="forum",
                    m_message_sharable_link=thread_url,
                    m_post_comments_count=str(data.get("post_count") or "0"),
                    m_weblink=[thread_url],
                    m_message_id=thread_url,
                    m_source="csrin_forum",
                    m_raw={
                        "url": thread_url,
                        "usernames": data.get("usernames") or [],
                        "post_count": data.get("post_count") or 0,
                    },
                )

                if hasattr(card, "compute_hash"):
                    try:
                        card.compute_hash()
                    except Exception:
                        pass

                ent = self._safe_entity(
                    m_scrap_file=self.__class__.__name__,
                    m_username=(data.get("usernames") or ["unknown"]),
                    m_weblink=[thread_url],
                    m_extra={
                        "source": "csrin_forum",
                        "hash": getattr(card, "m_hash", ""),
                        "seed": self.seed_url,
                    },
                )

                card_payload = card.to_dict() if hasattr(card, "to_dict") else card.__dict__
                ent_payload = ent.to_dict() if hasattr(ent, "to_dict") else ent.__dict__

                self._print_jsonl({"source": "csrin_forum", "type": "record", "social": card_payload, "entity": ent_payload})

                self._redis_save_json(redis_items, card_payload)
                self._redis_save_json(redis_entities, ent_payload)

                self._card_data.append(card)
                self._entity_data.append(ent)
                processed += 1

                if self.callback:
                    try:
                        if self.callback():
                            self._card_data.clear()
                            self._entity_data.clear()
                    except Exception:
                        pass

            except Exception as ex:
                log.g().e(f"[csrin] thread parse error {ex} | {self.__class__.__name__}")

        if latest_seen:
            try:
                self._set_last_seen_date(latest_seen)
            except Exception:
                pass

        self._is_crawled = True
        self._print_jsonl(
            {
                "source": "csrin_forum",
                "type": "debug",
                "processed": processed,
                "latest_seen": str(latest_seen) if latest_seen else "",
                "last_seen_cutoff": str(last_seen),
            }
        )

    # -------------------------
    # RUN
    # -------------------------
    def run(self):
        try:
            self._card_data.clear()
            self._entity_data.clear()

            # try RequestParser injected object
            page_obj = (
                getattr(self, "_request_page", None)
                or getattr(self, "seed_page", None)
                or getattr(self, "_page", None)
                or getattr(self, "page", None)
            )

            seed_html = ""
            if page_obj is not None:
                seed_html = self._get_seed_html(page_obj)

            # fallback if RequestParser failed seed_fetch
            if not seed_html:
                self._print_jsonl(
                    {
                        "source": "csrin_forum",
                        "type": "debug",
                        "msg": "RequestParser seed_fetch missing/failed; using Playwright fallback for seed fetch.",
                    }
                )
                with sync_playwright() as p:
                    browser = p.chromium.launch(
                        headless=True,
                        args=[
                            "--no-sandbox",
                            "--disable-dev-shm-usage",
                            "--disable-gpu",
                        ],
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
                    seed_page = context.new_page()
                    seed_page.goto(self.seed_url, wait_until="domcontentloaded", timeout=self.NAV_TIMEOUT_MS)
                    seed_page.wait_for_load_state("networkidle")
                    seed_html = seed_page.content() or ""
                    context.close()
                    browser.close()

            if not seed_html:
                raise RuntimeError("[csrin] Seed HTML still empty. Network/proxy issue persists.")

            threads = self._collect_threads_from_seed(seed_html)
            self._print_jsonl(
                {
                    "source": "csrin_forum",
                    "type": "debug",
                    "threads_found": len(threads),
                    "sample_threads": threads[:30],
                }
            )

            if not threads:
                log.g().e("[csrin] No threads found (selectors mismatch).")
                return []

            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                    ],
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
                nav_page = context.new_page()

                try:
                    nav_page.add_init_script("Object.defineProperty(navigator, 'webdriver', { get: () => undefined });")
                except Exception:
                    pass

                self._parse_threads_with_nav_page(nav_page, threads)

                context.close()
                browser.close()

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
