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


class _hacksnation(leak_extractor_interface, ABC):
    _instance = None

    NAV_TIMEOUT_MS = 120_000

    MAX_LIST_PAGES_FIRST_RUN = 5
    MAX_LIST_PAGES_NEXT_RUN = 50

    THREAD_LIMIT_FIRST_RUN = 120
    THREAD_LIMIT_NEXT_RUN = 80

    MAX_POSTS_PER_THREAD = 30
    MAX_CONTENT_CHARS = 4000
    MAX_OUT_LINKS = 200

    # clearnet => no RequestParser seed_fetch dependency
    needs_seed_fetch = False

    FORBIDDEN_KEYWORDS = [
        "porn", "onlyfans", "sex", "horny", "pornography", "adult",
        "escort", "camgirl", "cam boy", "nudes", "nude", "xxx", "fetish", "bdsm",
        "pornhub", "stripchat", "livejasmin", "snapchat", "chaturbate", "leak",
        "incest", "taboo", "hardcore", "erotica", "sexcam", "adultwork",
        "escortservice", "hooker", "prostitute", "anal", "oral", "cum", "blowjob",
        "handjob", "dildo", "vibrator", "orgy", "gangbang", "deepfake", "onlyfansleak",
        "fansly", "amateur", "spank", "lust", "suck", "slut", "whore", "milf", "teen",
        "lolita", "hentai", "futa", "sextape", "sex tape",
    ]

    def __init__(self, callback=None):
        self.callback = callback
        self._card_data: List[social_model] = []
        self._entity_data: List[entity_model] = []
        self._redis_instance = redis_controller()
        self._is_crawled = False

        # framework may inject these
        self.page = None
        self._page = None
        self.seed_page = None
        self._request_page = None

    def __new__(cls, callback=None):
        if cls._instance is None:
            cls._instance = super(_hacksnation, cls).__new__(cls)
        return cls._instance

    # -------------------------
    # META
    # -------------------------
    @property
    def seed_url(self) -> str:
        return "https://hacksnation.com/t/cracked"

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
        return "https://hacksnation.com/contact-us"

    # -------------------------
    # JSONL debug
    # -------------------------
    def _print_jsonl(self, payload: Dict[str, Any]):
        print(json.dumps(payload, ensure_ascii=False, default=str), flush=True)

    # -------------------------
    # Redis helpers
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

    def _data_hash(self, s: str) -> str:
        return hashlib.sha1((s or "").encode("utf-8", errors="ignore")).hexdigest()

    def _last_seen_key(self, section_hash: str) -> str:
        return f"{CUSTOM_SCRIPT_REDIS_KEYS.GENERIC}hacksnation:last_seen:{section_hash}:"

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
                elif name in ("m_username", "m_author"):
                    filtered[name] = ["unknown"]
                else:
                    filtered[name] = "unknown"

        if "m_scrap_file" not in filtered:
            filtered["m_scrap_file"] = self.__class__.__name__

        return entity_model(**filtered)

    # -------------------------
    # Utils (no helper_method)
    # -------------------------
    @staticmethod
    def _clean(s: str) -> str:
        return re.sub(r"\s+", " ", (s or "")).strip()

    @staticmethod
    def _clean_multiline(s: str) -> str:
        s = (s or "").replace("\r", "\n")
        s = re.sub(r"\n{3,}", "\n\n", s)
        return s.strip()

    @staticmethod
    def _network_type(url: str) -> str:
        try:
            host = urlparse(url).netloc.lower()
            if host.endswith(".onion"):
                return "onion"
        except Exception:
            pass
        return "clearnet"

    @staticmethod
    def _parse_time_attr(dt_attr: str) -> Optional[datetime]:
        if not dt_attr:
            return None
        dt_attr = dt_attr.strip()
        try:
            return datetime.fromisoformat(dt_attr.replace("Z", "+00:00")).astimezone(timezone.utc)
        except Exception:
            pass
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
            try:
                d = datetime.strptime(dt_attr, fmt)
                if d.tzinfo is None:
                    d = d.replace(tzinfo=timezone.utc)
                return d.astimezone(timezone.utc)
            except Exception:
                continue
        return None

    def _has_forbidden(self, text: str) -> bool:
        low = (text or "").lower()
        return any(k in low for k in self.FORBIDDEN_KEYWORDS)

    # -------------------------
    # IMPORTANT: use injected page if available
    # -------------------------
    def _get_injected_page(self):
        for attr in ("_request_page", "seed_page", "page", "_page"):
            obj = getattr(self, attr, None)
            if obj is not None and hasattr(obj, "goto"):
                return obj
        return None

    def _detect_proxy_server(self) -> Optional[str]:
        """
        Playwright needs proxy too, otherwise DNS fails (ERR_NAME_NOT_RESOLVED).
        Priority:
          1) DARKPULSE_SOCKS_PROXY / TOR_SOCKS_PROXY
          2) ALL_PROXY / HTTPS_PROXY / HTTP_PROXY
          3) fallback socks5://127.0.0.1:9150 if user is running Tor Browser
        """
        keys = [
            "DARKPULSE_SOCKS_PROXY",
            "TOR_SOCKS_PROXY",
            "ALL_PROXY",
            "HTTPS_PROXY",
            "HTTP_PROXY",
        ]
        for k in keys:
            v = (os.environ.get(k) or "").strip()
            if v:
                # normalize socks5h -> socks5 for playwright compatibility
                if v.startswith("socks5h://"):
                    v = "socks5://" + v[len("socks5h://") :]
                return v

        # default (because your logs show Tor Browser running at 9150)
        return "socks5://127.0.0.1:9150"

    # -------------------------
    # Listing
    # -------------------------
    def _listing_page_url(self, base: str, page_num: int) -> str:
        if page_num <= 1:
            return base
        if "?" in base:
            return f"{base}&page={page_num}"
        return f"{base}?page={page_num}"

    def _collect_threads(self, page, list_url: str, max_pages: int) -> List[Dict[str, Any]]:
        section_hash = self._data_hash(list_url)

        last_seen = self._redis_get_last_seen_dt(section_hash)
        if last_seen is None:
            last_seen = datetime.now(timezone.utc) - timedelta(days=500)

        out: List[Dict[str, Any]] = []
        newest_dt: Optional[datetime] = None

        seen_urls = set()
        no_new_pages_in_row = 0

        for pn in range(1, max_pages + 1):
            url = self._listing_page_url(list_url, pn)
            page.goto(url, wait_until="domcontentloaded", timeout=self.NAV_TIMEOUT_MS)

            items = page.query_selector_all(".DiscussionListItem")
            if not items:
                break

            added_this_page = 0

            for it in items:
                a = it.query_selector("a.DiscussionListItem-main")
                if not a:
                    continue

                href = (a.get_attribute("href") or "").strip()
                if not href:
                    continue
                thread_url = urljoin(page.url, href)
                if thread_url in seen_urls:
                    continue

                blob = self._clean(it.inner_text() or "")
                title = ""
                try:
                    title_el = it.query_selector(".DiscussionListItem-title")
                    if title_el:
                        title = self._clean(title_el.inner_text() or "")
                except Exception:
                    title = ""

                if self._has_forbidden(blob) or self._has_forbidden(title):
                    continue

                t = it.query_selector("time")
                dt_attr = (t.get_attribute("datetime") or "").strip() if t else ""
                dt_utc = self._parse_time_attr(dt_attr)
                if not dt_utc:
                    continue

                if dt_utc <= last_seen:
                    continue

                seen_urls.add(thread_url)
                out.append(
                    {
                        "url": thread_url,
                        "title": title or "Post",
                        "dt_utc": dt_utc,
                        "list_url": list_url,
                    }
                )
                added_this_page += 1

                if newest_dt is None or dt_utc > newest_dt:
                    newest_dt = dt_utc

            if added_this_page == 0:
                no_new_pages_in_row += 1
            else:
                no_new_pages_in_row = 0

            if no_new_pages_in_row >= 2:
                break

        if newest_dt is not None:
            self._redis_set_last_seen_dt(section_hash, newest_dt)

        return out

    # -------------------------
    # Thread extraction
    # -------------------------
    def _extract_posts(self, page) -> Tuple[str, List[str], List[str], int]:
        results: List[Tuple[str, str]] = []
        codes_all: List[str] = []

        articles = page.locator("article.CommentPost")
        count = articles.count()

        if count == 0:
            articles = page.locator("article")
            count = articles.count()

        comment_count = int(count)
        take_n = min(comment_count, self.MAX_POSTS_PER_THREAD)

        for i in range(take_n):
            art = articles.nth(i)

            user = ""
            try:
                uel = art.locator(".PostUser-name .username").first
                if uel.count() > 0:
                    user = (uel.inner_text() or "").strip()
            except Exception:
                user = ""

            text = ""
            try:
                body = art.locator(".Post-body").first
                if body.count() == 0:
                    body = art.locator(".content").first

                paragraphs = [t.strip() for t in body.locator("p").all_text_contents()] if body.count() > 0 else []
                codes = [t.strip() for t in body.locator("code").all_text_contents()] if body.count() > 0 else []

                codes_all.extend([c for c in codes if c])

                parts = [p for p in paragraphs if p]
                if parts:
                    text = "\n".join(parts)
                else:
                    text = (body.inner_text() or "").strip() if body.count() > 0 else ""
            except Exception:
                text = ""

            text = self._clean_multiline(text)
            if text:
                results.append((user, text))

        content = "\n\n".join([r[1] for r in results]).strip()
        content = re.sub(r"\n{3,}", "\n\n", content)

        users: List[str] = []
        seen = set()
        for u, _ in results:
            if u and u not in seen:
                seen.add(u)
                users.append(u)

        return content, users, codes_all, comment_count

    def _collect_out_links(self, page, thread_url: str) -> List[str]:
        out_links: List[str] = []
        seen = set()
        for a in page.query_selector_all("a[href]"):
            href = (a.get_attribute("href") or "").strip()
            if not href:
                continue
            full = urljoin(thread_url, href)
            if not full.startswith(("http://", "https://")):
                continue
            if full in seen:
                continue
            seen.add(full)
            out_links.append(full)
            if len(out_links) >= self.MAX_OUT_LINKS:
                break
        return out_links

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
        # if framework passes a page, store it for run()
        try:
            if page_obj is not None and hasattr(page_obj, "goto"):
                self._request_page = page_obj
        except Exception:
            pass

        self._print_jsonl({"source": "hacksnation", "type": "debug", "seed_url": self.seed_url})

    # -------------------------
    # RUN
    # -------------------------
    def run(self):
        try:
            self._card_data.clear()
            self._entity_data.clear()

            max_pages = self.MAX_LIST_PAGES_NEXT_RUN if self.is_crawled else self.MAX_LIST_PAGES_FIRST_RUN
            thread_limit = self.THREAD_LIMIT_NEXT_RUN if self.is_crawled else self.THREAD_LIMIT_FIRST_RUN

            injected_page = self._get_injected_page()

            # ✅ If RequestParser injected a Playwright page, use it (it already knows proxies/cookies/etc.)
            if injected_page is not None:
                page = injected_page

                threads = self._collect_threads(page, self.seed_url, max_pages=max_pages)
                threads.sort(
                    key=lambda x: x.get("dt_utc") or datetime(1970, 1, 1, tzinfo=timezone.utc),
                    reverse=True,
                )
                threads = threads[:thread_limit]

                self._print_jsonl(
                    {
                        "source": "hacksnation",
                        "type": "debug",
                        "mode": "injected_page",
                        "threads_to_parse": len(threads),
                        "sample": [t["url"] for t in threads[:20]],
                    }
                )

                for t in threads:
                    self._parse_one_thread(page, t)

                self._is_crawled = True

                return [
                    {
                        "social": c.to_dict() if hasattr(c, "to_dict") else c.__dict__,
                        "entity": e.to_dict() if hasattr(e, "to_dict") else e.__dict__,
                    }
                    for c, e in zip(self._card_data, self._entity_data)
                ]

            # ✅ No injected page => fully self-contained Playwright with proxy
            proxy_server = self._detect_proxy_server()

            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=True,
                    proxy={"server": proxy_server} if proxy_server else None,
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

                threads = self._collect_threads(page, self.seed_url, max_pages=max_pages)
                threads.sort(
                    key=lambda x: x.get("dt_utc") or datetime(1970, 1, 1, tzinfo=timezone.utc),
                    reverse=True,
                )
                threads = threads[:thread_limit]

                self._print_jsonl(
                    {
                        "source": "hacksnation",
                        "type": "debug",
                        "mode": "self_playwright",
                        "proxy": proxy_server,
                        "threads_to_parse": len(threads),
                        "sample": [t["url"] for t in threads[:20]],
                    }
                )

                for t in threads:
                    self._parse_one_thread(page, t)

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

    # -------------------------
    # Single thread parse
    # -------------------------
    def _parse_one_thread(self, page, t: Dict[str, Any]):
        thread_url = t.get("url") or ""
        title = t.get("title") or "Post"
        dt_utc = t.get("dt_utc")

        try:
            page.goto(thread_url, wait_until="domcontentloaded", timeout=self.NAV_TIMEOUT_MS)
            try:
                page.wait_for_load_state("networkidle", timeout=self.NAV_TIMEOUT_MS)
            except Exception:
                pass

            content, usernames, codes_all, comment_count = self._extract_posts(page)

            if self._has_forbidden(title) or self._has_forbidden(content):
                return

            code_snippet: List[str] = []
            for c in codes_all:
                c = (c or "").strip()
                if c:
                    code_snippet.append(c[:2000])
            if code_snippet:
                code_snippet = code_snippet[:5]

            out_links = self._collect_out_links(page, thread_url)

            msg_date: Optional[date] = dt_utc.date() if isinstance(dt_utc, datetime) else None

            card = social_model(
                m_title=title,
                m_channel_url=self.seed_url,
                m_message_sharable_link=thread_url,
                m_weblink=[thread_url],
                m_content=(content[: self.MAX_CONTENT_CHARS] if content else ""),
                m_content_type=["forum"],
                m_network=self._network_type(self.base_url),
                m_message_date=msg_date,
                m_message_id=thread_url,
                m_platform="forum",
                m_source="hacksnation_forum",
                m_raw={
                    "url": thread_url,
                    "section": self.seed_url,
                    "usernames": usernames,
                    "out_links": out_links,
                },
                m_post_comments_count=str(comment_count or 0),
            )

            ent = self._safe_entity(
                m_scrap_file=self.__class__.__name__,
                m_username=(usernames if usernames else ["unknown"]),
                m_weblink=[thread_url],
                m_code_snippet=code_snippet,
                m_extra={"source": "hacksnation_forum", "seed": self.seed_url},
            )

            self.append_leak_data(card, ent)

            self._print_jsonl(
                {
                    "source": "hacksnation",
                    "type": "record",
                    "social": (card.to_dict() if hasattr(card, "to_dict") else card.__dict__),
                    "entity": (ent.to_dict() if hasattr(ent, "to_dict") else ent.__dict__),
                }
            )

        except Exception as ex:
            log.g().e(f"[hacksnation] thread parse error {ex} | {thread_url}")
