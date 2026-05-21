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


class _quartertothree(leak_extractor_interface, ABC):
    _instance = None

    NAV_TIMEOUT_MS = 120_000

    MAX_LIST_PAGES_FIRST_RUN = 5
    MAX_LIST_PAGES_NEXT_RUN = 3  # discourse infinite scroll-ish, so keep low

    THREAD_LIMIT_FIRST_RUN = 150
    THREAD_LIMIT_NEXT_RUN = 80

    MAX_POSTS_PER_THREAD = 20
    MAX_CONTENT_CHARS = 4000
    MAX_OUT_LINKS = 200

    needs_seed_fetch = False

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
            cls._instance = super(_quartertothree, cls).__new__(cls)
        return cls._instance

    # -------------------------
    # META
    # -------------------------
    @property
    def base_url(self) -> str:
        return "https://forum.quartertothree.com"

    @property
    def seed_url(self) -> str:
        return "https://forum.quartertothree.com/c/games/7"

    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def developer_signature(self) -> str:
        return "Syed Ibrahim : owEBbgKR/ZANAwAKAZ6k986TaqHrAcsnYgBogoHBVmVyaWZpZWQgZGV2ZWxvcGVyOiBTeWVkIElicmFoaW0KiQIzBAABCgAdFiEE0cDJTTL9lGNCNy3mnqT3zpNqoesFAmiCgcEACgkQnqT3zpNqoeu+UxAAvORjme5u4ZXhva6MkNXPwRHrKLbhZrBBYHgkDra+reoSSRQnMQTlEGWEhRiBi3wGo4MyC2xwhCjRW1raFddBnv03LA59ro978LafPwpEO6cQYxnpqI8nDh6TIEbcJi2GLPIOc4xZm79GvxVZ6b9t5zoaNdSUPv/AwidjXGU4ACIkDo9LQW0RLiVUq8wvhPJRcvvwpmKGwLc9XRWSG95Vv172cv6KCh14EAW90sXSaDc4nIP9sr13j3YN1XGmQwTtmQo8ynmZpZ3JydmUud79ZnB+CfXZXKRehDlSfnTQH5TezsZCpshv5KbtuYwVsqgp/zDSMSZwGtgeaeD3M/yYgRdxbu0yt9RQ74yiwiqzBWa6yEkkECAkAb9QwRXGIqX3oWLFMadiBkCFMaILl+NH4phAVB4lual3H7bZEBgNasOjNm+SYqf/8FJrhBCSjVkLpkpQ71oEBUX06vX+tj2hXW42ZjWm4Lx9qHPh5JYyp9Th5DhnYONVvK96DQHxjYIpqbDTigVCS/rN6PFHolJHOFFivnzYqGeWZEzoI9U+2JhmuDwStKBMNWE+NWJHyyNsOFqEZ1Murl5sBpJEMeC4J4Vn//lPvQAo24hAULJAmOT9CjT00DdnXRdyl602fv0HfwzPf78NQ3LUuabyTLMQUgDKm8Gg8LlenlraOovjXgw==s7Wx"

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_fetch_proxy=FetchProxy.NONE,
            m_fetch_config=FetchConfig.PLAYRIGHT,
            m_threat_type=ThreatType.SOCIAL,
        )

    @property
    def card_data(self) -> List[social_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def contact_page(self) -> str:
        return "https://www.quartertothree.com/fp/about/"

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
        return f"{CUSTOM_SCRIPT_REDIS_KEYS.GENERIC}quartertothree:last_seen:{section_hash}:"

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
    def _parse_iso(dt_str: str) -> Optional[datetime]:
        if not dt_str:
            return None
        try:
            return datetime.fromisoformat(dt_str.replace("Z", "+00:00")).astimezone(timezone.utc)
        except Exception:
            return None

    def _get_injected_page(self):
        for attr in ("_request_page", "seed_page", "page", "_page"):
            obj = getattr(self, attr, None)
            if obj is not None and hasattr(obj, "goto"):
                return obj
        return None

    def _detect_proxy_server(self) -> Optional[str]:
        keys = ["DARKPULSE_SOCKS_PROXY", "TOR_SOCKS_PROXY", "ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY"]
        for k in keys:
            v = (os.environ.get(k) or "").strip()
            if v:
                if v.startswith("socks5h://"):
                    v = "socks5://" + v[len("socks5h://") :]
                return v
        return "socks5://127.0.0.1:9150"

    # -------------------------
    # Discourse: list parsing
    # -------------------------
    def _extract_topic_rows(self, page) -> List[Any]:
        return page.query_selector_all("tbody.topic-list-body tr.topic-list-item")

    def _scroll_for_more(self, page, prev_count: int, max_wait_attempts: int = 10) -> int:
        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        for _ in range(max_wait_attempts):
            page.wait_for_timeout(1000)
            rows = self._extract_topic_rows(page)
            if len(rows) > prev_count:
                return len(rows)
        return prev_count

    def _collect_threads_from_list(self, page, list_url: str, max_threads: int) -> List[Dict[str, Any]]:
        section_hash = self._data_hash(list_url)

        last_seen = self._redis_get_last_seen_dt(section_hash)
        if last_seen is None:
            last_seen = datetime.now(timezone.utc) - timedelta(days=365)

        page.goto(list_url, wait_until="domcontentloaded", timeout=self.NAV_TIMEOUT_MS)
        page.wait_for_timeout(1500)

        threads: List[Dict[str, Any]] = []
        seen = set()

        idx = 0
        guard_rounds = 0

        while len(threads) < max_threads:
            rows = self._extract_topic_rows(page)
            if not rows:
                break

            if idx >= len(rows):
                if guard_rounds >= self.MAX_LIST_PAGES_NEXT_RUN:
                    break
                guard_rounds += 1
                prev = len(rows)
                newc = self._scroll_for_more(page, prev)
                if newc <= prev:
                    break
                continue

            row = rows[idx]
            idx += 1

            a = row.query_selector("a.title.raw-link.raw-topic-link")
            if not a:
                continue

            href = (a.get_attribute("href") or "").strip()
            if not href:
                continue

            thread_url = urljoin(self.base_url, href)
            if thread_url in seen:
                continue
            seen.add(thread_url)

            title = self._clean(a.inner_text() or "") or "Post"

            # Use Discourse topic JSON to get exact last_posted_at
            topic_id = None
            m = re.search(r"/t/[^/]+/(\d+)", href)
            if m:
                try:
                    topic_id = int(m.group(1))
                except Exception:
                    topic_id = None

            last_dt = None
            if topic_id is not None:
                try:
                    # /t/<slug>/<id>.json works
                    json_url = f"{thread_url}.json" if not thread_url.endswith(".json") else thread_url
                    resp = page.request.get(json_url, timeout=self.NAV_TIMEOUT_MS)
                    if resp.ok:
                        data = resp.json()
                        # prefer last_posted_at, else created_at
                        last_dt = self._parse_iso((data.get("last_posted_at") or "")[:30])
                        if last_dt is None:
                            last_dt = self._parse_iso((data.get("created_at") or "")[:30])
                except Exception:
                    last_dt = None

            # Fallback: activity title (may be local time string)
            if last_dt is None:
                activity_td = row.query_selector("td.activity.num.topic-list-data.age")
                title_attr = (activity_td.get_attribute("title") or "") if activity_td else ""
                # Example: "Latest: February 12, 2026 8:21pm"
                mt = re.search(r"Latest:\s*(.+)$", title_attr)
                if mt:
                    txt = mt.group(1).strip()
                    # try: "February 12, 2026"
                    md = re.search(r"([A-Za-z]+ \d{1,2}, \d{4})", txt)
                    if md:
                        try:
                            last_dt = datetime.strptime(md.group(1), "%B %d, %Y").replace(tzinfo=timezone.utc)
                        except Exception:
                            last_dt = None

            if not last_dt:
                continue

            if last_dt <= last_seen:
                continue

            threads.append({"url": thread_url, "title": title, "dt_utc": last_dt})

        # update last seen (newest)
        if threads:
            newest = max(threads, key=lambda x: x["dt_utc"])["dt_utc"]
            self._redis_set_last_seen_dt(section_hash, newest)

        return threads

    # -------------------------
    # Thread extraction
    # -------------------------
    def _extract_thread(self, page, thread_url: str) -> Dict[str, Any]:
        page.goto(thread_url, wait_until="domcontentloaded", timeout=self.NAV_TIMEOUT_MS)
        page.wait_for_timeout(1000)

        cooked = page.locator("div.cooked")
        total_posts = cooked.count()

        take_first = min(10, total_posts)
        pieces: List[str] = []

        for i in range(take_first):
            try:
                txt = cooked.nth(i).inner_text() or ""
            except Exception:
                txt = ""
            txt = self._clean_multiline(txt)
            if txt:
                pieces.append(txt)

        # try add last 10 if huge thread (discourse jump to bottom)
        if total_posts > 20:
            try:
                # click timeline "now-date" to go near bottom
                bottom = page.locator("div.timeline-date-wrapper a.now-date").first
                if bottom.count() > 0:
                    bottom.click()
                    page.wait_for_timeout(1500)
                    cooked2 = page.locator("div.cooked")
                    total2 = cooked2.count()
                    start = max(0, total2 - 10)
                    for i in range(start, total2):
                        txt = self._clean_multiline(cooked2.nth(i).inner_text() or "")
                        if txt:
                            pieces.append(txt)
                    total_posts = max(total_posts, total2)
            except Exception:
                pass

        content = "\n\n".join(pieces)
        content = self._clean(content)  # flatten
        content = content[: self.MAX_CONTENT_CHARS]

        usernames: List[str] = []
        seen_u = set()
        for el in page.query_selector_all("div.names.trigger-user-card span.first.username a"):
            u = self._clean(el.inner_text() or "")
            if u and u not in seen_u:
                seen_u.add(u)
                usernames.append(u)
            if len(usernames) >= 15:
                break

        out_links: List[str] = []
        seen_l = set()
        for a in page.query_selector_all("div.cooked a[href]"):
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
            "content": content,
            "usernames": usernames,
            "out_links": out_links,
            "post_count": int(total_posts),
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
        try:
            if page_obj is not None and hasattr(page_obj, "goto"):
                self._request_page = page_obj
        except Exception:
            pass

        self._print_jsonl({"source": "quartertothree", "type": "debug", "seed_url": self.seed_url})

    # -------------------------
    # RUN
    # -------------------------
    def run(self):
        try:
            self._card_data.clear()
            self._entity_data.clear()

            max_threads = self.THREAD_LIMIT_NEXT_RUN if self.is_crawled else self.THREAD_LIMIT_FIRST_RUN
            injected_page = self._get_injected_page()

            def do_work(page):
                threads = self._collect_threads_from_list(page, self.seed_url, max_threads=max_threads)
                threads.sort(
                    key=lambda x: x.get("dt_utc") or datetime(1970, 1, 1, tzinfo=timezone.utc),
                    reverse=True,
                )
                threads = threads[:max_threads]

                self._print_jsonl(
                    {
                        "source": "quartertothree",
                        "type": "debug",
                        "threads_to_parse": len(threads),
                        "sample": [t["url"] for t in threads[:10]],
                    }
                )

                for t in threads:
                    try:
                        fields = self._extract_thread(page, t["url"])
                        if not fields:
                            continue

                        msg_date: Optional[date] = t["dt_utc"].date() if isinstance(t["dt_utc"], datetime) else None

                        card = social_model(
                            m_title=t.get("title") or "Post",
                            m_channel_url=t["url"],
                            m_message_sharable_link=t["url"],
                            m_weblink=[t["url"]],
                            m_content=(fields.get("content") or "")[: self.MAX_CONTENT_CHARS],
                            m_content_type=["forum"],
                            m_network=self._network_type(self.base_url),
                            m_message_date=msg_date,
                            m_message_id=t["url"],
                            m_platform="forum",
                            m_source="quartertothree_forum",
                            m_raw={
                                "url": t["url"],
                                "section": self.seed_url,
                                "usernames": fields.get("usernames") or [],
                                "out_links": fields.get("out_links") or [],
                            },
                            m_post_comments_count=str(fields.get("post_count") or 0),
                        )

                        ent = self._safe_entity(
                            m_scrap_file=self.__class__.__name__,
                            m_username=(fields.get("usernames") or ["unknown"]),
                            m_weblink=[t["url"]],
                            m_extra={"source": "quartertothree_forum", "seed": self.seed_url},
                        )

                        self.append_leak_data(card, ent)

                        self._print_jsonl(
                            {
                                "source": "quartertothree",
                                "type": "record",
                                "social": (card.to_dict() if hasattr(card, "to_dict") else card.__dict__),
                                "entity": (ent.to_dict() if hasattr(ent, "to_dict") else ent.__dict__),
                            }
                        )
                    except Exception as ex:
                        log.g().e(f"[quartertothree] thread parse error {ex} | {t.get('url')}")

            # injected page path
            if injected_page is not None:
                do_work(injected_page)
                self._is_crawled = True
                return [
                    {
                        "social": c.to_dict() if hasattr(c, "to_dict") else c.__dict__,
                        "entity": e.to_dict() if hasattr(e, "to_dict") else e.__dict__,
                    }
                    for c, e in zip(self._card_data, self._entity_data)
                ]

            # self playwright path
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

                do_work(page)

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
