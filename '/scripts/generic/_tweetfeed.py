import ipaddress
import re
import hashlib
import requests
from abc import ABC
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from playwright.sync_api import sync_playwright

from crawler.common.constants.constant import RAW_PATH_CONSTANTS
from crawler.common.crawler_instance.local_interface_model.leak.leak_extractor_interface import (
    leak_extractor_interface,
)
from crawler.common.crawler_instance.local_shared_model.data_model.defacement_model import (
    defacement_model,
)
from crawler.common.crawler_instance.local_shared_model.data_model.entity_model import (
    entity_model,
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

from crawler.common.dev_signature import developer_signature


class _tweetfeed(leak_extractor_interface, ABC):
    """
    Tweetfeed.live crawler (THN-style structure, but NO NLP printing).
    Prints ONLY row metadata:
      - date, twitter user/profile
      - IOC value, extracted IP
      - tags
      - tweet link + scanner link
      - content length
    Stores:
      - defacement_model (card)
      - entity_model (entity)
      - raw keys in redis (no JSON) + raw index
    """

    _instance = None

    # ---------------- Singleton ----------------
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_tweetfeed, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, developer_name: str = "Anonymous", developer_note: str = ""):
        if getattr(self, "_initialized", False):
            return
        self._initialized = True

        self._card_data: List[defacement_model] = []
        self._entity_data: List[entity_model] = []

        self._redis = redis_controller()
        self._is_crawled = False
        self.callback = None

        self._developer_name = developer_name
        self._developer_note = developer_note

        # crawl controls
        self._max_pages: int = 90
        self._max_rows: Optional[int] = None  # None = unlimited
        self._proxy: dict = {}
        self._chromium_exe = None  # optional local chromium path

        # redis indices (pipe-delimited, not json)
        self._raw_index_key = "TWEETFEED:raw_index"

        print("[TWEETFEED] Initialized ✅ (pure Redis, no JSON)")

    # ---------------- hooks/config ----------------
    def init_callback(self, callback=None):
        self.callback = callback
        print("[TWEETFEED] Callback set")

    def set_proxy(self, proxy: dict):
        self._proxy = proxy or {}
        print(f"[TWEETFEED] Proxy configured: {self._proxy}")

    def set_limits(self, max_pages: Optional[int] = None, max_rows: Optional[int] = None):
        if max_pages is not None and max_pages >= 1:
            self._max_pages = int(max_pages)
        if max_rows is not None and max_rows >= 1:
            self._max_rows = int(max_rows)
        print(f"[TWEETFEED] Limits → pages={self._max_pages}, rows={self._max_rows or '∞'}")

    # ---------------- required interface props ----------------
    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "https://tweetfeed.live/"

    @property
    def base_url(self) -> str:
        return "https://tweetfeed.live/"

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_fetch_proxy=FetchProxy.NONE,
            m_fetch_config=FetchConfig.PLAYRIGHT,
            m_resoource_block=False,
            m_threat_type=ThreatType.DEFACEMENT,
        )

    @property
    def card_data(self) -> List[defacement_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def developer_signature(self) -> str:
        return developer_signature(self._developer_name, self._developer_note)

    def contact_page(self) -> str:
        return "https://tweetfeed.live/about.html"

    # ---------------- minimal redis helpers (NO JSON) ----------------
    def _redis_get(self, key: str, default: str = "") -> str:
        try:
            val = self._redis.invoke_trigger(1, [key, default, None])
            if val is None:
                return default
            return str(val)
        except Exception:
            return default

    def _redis_set(self, key: str, value: object, expiry: Optional[int] = None):
        v = "" if value is None else str(value)
        self._redis.invoke_trigger(2, [key, v, expiry])

    def _append_index(self, index_key: str, item_id: str):
        cur = self._redis_get(index_key, "")
        parts = [p for p in cur.split("|") if p] if cur else []
        if item_id not in parts:
            parts.append(item_id)
            self._redis_set(index_key, "|".join(parts), expiry=None)

    # keep original invoke_db style for helper_method.extract_refhtml compatibility
    def invoke_db(self, command: int, key: str, default_value, expiry: int = None):
        return self._redis.invoke_trigger(command, [key + self.__class__.__name__, default_value, expiry])

    # ---------------- utility helpers ----------------
    @staticmethod
    def _sha1(text: str) -> str:
        return hashlib.sha1(text.encode("utf-8")).hexdigest()

    @staticmethod
    def _date_to_string(d) -> str:
        if d is None:
            return ""
        if isinstance(d, datetime):
            return d.strftime("%Y-%m-%d")
        return str(d)

    @staticmethod
    def extract_ip(value: str) -> Optional[str]:
        value = (value or "").strip()
        match = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", value)
        if match:
            try:
                ipaddress.ip_address(match.group())
                return match.group()
            except ValueError:
                return None
        return None

    @staticmethod
    def is_domain_or_url(value: str) -> bool:
        value = (value or "").strip().lower()
        if not value:
            return False
        if value.startswith(("http://", "https://")):
            return True
        return bool(re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", value))

    def _check_link_activity(self, url: str, timeout: int = 10) -> str:
        try:
            r = requests.head(url, timeout=timeout, allow_redirects=True)
            if 200 <= r.status_code < 300:
                return "ACTIVE"
            return f"INACTIVE ({r.status_code})"
        except Exception:
            return "UNREACHABLE"

    # ✅ stable AID
    def _make_aid(self, card: defacement_model, ent: entity_model) -> str:
        seed = "|".join(
            [
                str(card.m_url or ""),
                str(self._date_to_string(card.m_leak_date)),
                str(getattr(ent, "m_team", "") or ""),
                ",".join(card.m_source_url or []),
            ]
        )
        return self._sha1(seed)

    # ---------------- storage (raw per-field keys, no JSON) ----------------
    def _store_raw_card(self, aid: str, card: defacement_model, ent: entity_model) -> str:
        base = f"TWEETFEED:raw:{aid}"

        # card scalar fields
        self._redis_set(f"{base}:url", card.m_url or "")
        self._redis_set(f"{base}:base_url", card.m_base_url or "")
        self._redis_set(f"{base}:network:type", card.m_network or "")
        self._redis_set(f"{base}:leak_date", self._date_to_string(card.m_leak_date))
        self._redis_set(f"{base}:content", card.m_content or "")
        self._redis_set(f"{base}:scraped_at", int(datetime.now(timezone.utc).timestamp()))
        self._redis_set(f"{base}:seed_url", self.seed_url)
        self._redis_set(f"{base}:rendered", "1")

        # lists (no json)
        srcs = card.m_source_url or []
        self._redis_set(f"{base}:source_url_count", len(srcs))
        for i, u in enumerate(srcs):
            self._redis_set(f"{base}:source_url:{i}", u)

        iocs = card.m_ioc_type or []
        self._redis_set(f"{base}:ioc_type_count", len(iocs))
        for i, t in enumerate(iocs):
            self._redis_set(f"{base}:ioc_type:{i}", t)

        # entity fields (guarded if your entity_model is minimal)
        ent_base = f"{base}:entity"
        self._redis_set(f"{ent_base}:scrap_file", getattr(ent, "m_scrap_file", "") or "")
        self._redis_set(f"{ent_base}:team", getattr(ent, "m_team", "") or "")

        ips = getattr(ent, "m_ip", []) or []
        self._redis_set(f"{ent_base}:ip_count", len(ips))
        for i, x in enumerate(ips):
            self._redis_set(f"{ent_base}:ip:{i}", x)

        weblinks = getattr(ent, "m_weblink", []) or []
        self._redis_set(f"{ent_base}:weblink_count", len(weblinks))
        for i, x in enumerate(weblinks):
            self._redis_set(f"{ent_base}:weblink:{i}", x)

        profiles = getattr(ent, "m_social_media_profiles", []) or []
        self._redis_set(f"{ent_base}:social_media_profiles_count", len(profiles))
        for i, x in enumerate(profiles):
            self._redis_set(f"{ent_base}:social_media_profile:{i}", x)

        scanners = getattr(ent, "m_external_scanners", []) or []
        self._redis_set(f"{ent_base}:external_scanners_count", len(scanners))
        for i, x in enumerate(scanners):
            self._redis_set(f"{ent_base}:external_scanner:{i}", x)

        self._append_index(self._raw_index_key, aid)
        return aid

    # ---------------- browser helpers ----------------
    def _launch_browser(self, p, use_proxy: bool) -> Tuple[object, object]:
        launch_kwargs = {"headless": False}
        if self._chromium_exe:
            launch_kwargs["executable_path"] = self._chromium_exe

        if use_proxy and (self._proxy or {}).get("server"):
            launch_kwargs["proxy"] = {"server": self._proxy["server"]}
            print(f"[TWEETFEED] Launching Chromium WITH proxy: {self._proxy['server']}")
        else:
            print("[TWEETFEED] Launching Chromium WITHOUT proxy")

        browser = p.chromium.launch(**launch_kwargs)
        context = browser.new_context()
        return browser, context

    # ---------------- pipeline core ----------------
    def run(self) -> dict:
        print("[TWEETFEED] run() → Playwright crawl")
        return self.parse_leak_data()

    def append_leak_data(self, leak: defacement_model, ent: entity_model):
        self._card_data.append(leak)
        self._entity_data.append(ent)
        if self.callback:
            try:
                if self.callback():
                    self._card_data.clear()
                    self._entity_data.clear()
            except Exception:
                pass

    def parse_leak_data(self) -> dict:
        collected = 0
        visited_rows = 0

        max_pages = 30 if self.is_crawled else self._max_pages

        with sync_playwright() as p:
            # open seed with proxy fallback
            try:
                browser, context = self._launch_browser(p, use_proxy=True)
                page = context.new_page()
                print(f"[TWEETFEED] Opening seed (proxy): {self.seed_url}")
                page.goto(self.seed_url, timeout=60000, wait_until="load")
            except Exception as ex:
                print(f"[TWEETFEED] Proxy navigation failed: {ex}. Retrying without proxy …")
                try:
                    context.close()
                except Exception:
                    pass
                try:
                    browser.close()
                except Exception:
                    pass
                browser, context = self._launch_browser(p, use_proxy=False)
                page = context.new_page()
                print(f"[TWEETFEED] Opening seed (no proxy): {self.seed_url}")
                page.goto(self.seed_url, timeout=60000, wait_until="load")

            page.wait_for_load_state("networkidle")

            current_page_no = 1
            while current_page_no <= max_pages:
                try:
                    page.wait_for_selector("table tbody tr", timeout=20000)
                except Exception as ex:
                    log.g().e(f"[TWEETFEED] table rows not found: {ex}")
                    break

                rows = page.locator("table tbody tr")
                row_count = rows.count()
                print(f"[TWEETFEED] Page {current_page_no}: rows={row_count}")

                for i in range(row_count):
                    if self._max_rows and visited_rows >= self._max_rows:
                        print("[TWEETFEED] Max rows reached, stopping.")
                        break

                    visited_rows += 1
                    try:
                        row = rows.nth(i)

                        raw_date = row.locator("td.sorting_1.d-none.d-lg-table-cell").inner_text(timeout=4000)
                        leak_date = None
                        try:
                            leak_date = datetime.strptime(raw_date.strip(), "%Y-%m-%d %H:%M:%S").date()
                        except Exception:
                            leak_date = None

                        user_url = row.locator("a.twitterUser").get_attribute("href")
                        user_text = row.locator("a.twitterUser").inner_text(timeout=4000)

                        value_text = row.locator("span[style*='text-overflow']").inner_text(timeout=4000)
                        val = (value_text or "").strip()

                        tags_text = row.locator("td.d-none.d-lg-table-cell.tableTags").inner_text(timeout=4000)
                        types = (tags_text or "").split("#")
                        filtered = [s.strip() for s in types if len(s.strip()) >= 2]
                        if "databases" not in filtered:
                            filtered.append("databases")

                        original_tweet_link = row.locator("td.d-none.d-lg-table-cell a").first.get_attribute("href")
                        search_in_virus_tool_link = row.locator("td.d-none.d-lg-table-cell a").nth(1).get_attribute("href")

                        ip_val = self.extract_ip(val)

                        # content extraction (only if value is URL/domain or IP)
                        content = ""
                        if self.is_domain_or_url(val) or ip_val:
                            content = helper_method.extract_refhtml(
                                val,
                                self.invoke_db,
                                REDIS_COMMANDS,
                                CUSTOM_SCRIPT_REDIS_KEYS,
                                RAW_PATH_CONSTANTS,
                                page,
                            )

                        card = defacement_model(
                            m_url=val,
                            m_content=content,
                            m_base_url=self.base_url,
                            m_source_url=[original_tweet_link] if original_tweet_link else [],
                            m_ioc_type=filtered,
                            m_network=helper_method.get_network_type(self.base_url),
                            m_leak_date=leak_date,
                        )

                        # entity_model (works with extended model; minimal model still ok if you remove optional fields)
                        ent = entity_model(
                            m_scrap_file=self.__class__.__name__,
                            m_team=(user_text or "").strip(),
                            m_ip=[ip_val] if ip_val else [],
                            m_weblink=[val] if (not ip_val and self.is_domain_or_url(val)) else [],
                            m_social_media_profiles=[user_url] if user_url else [],
                            m_external_scanners=[search_in_virus_tool_link] if search_in_virus_tool_link else [],
                        )

                        self.append_leak_data(card, ent)

                        aid = self._make_aid(card, ent)
                        self._store_raw_card(aid, card, ent)
                        collected += 1

                        # ✅ PRINT ONLY THE REQUIRED DATA
                        print("\n-------------------- TWEETFEED ROW --------------------")
                        print(f"AID: {aid}")
                        print(f"Date: {leak_date}")
                        print(f"Twitter User: {(user_text or '').strip()}")
                        print(f"Twitter Profile: {user_url or ''}")
                        print(f"IOC Value: {val}")
                        print(f"Extracted IP: {ip_val or ''}")
                        print(f"Tags: {', '.join(filtered)}")
                        print(f"Tweet Link: {original_tweet_link or ''}")
                        print(f"Scanner Link: {search_in_virus_tool_link or ''}")
                        print(f"Content Len: {len(content or '')}")
                        print("-------------------------------------------------------\n")

                    except Exception as ex:
                        log.g().e(f"[TWEETFEED] SCRIPT ERROR {ex} {_tweetfeed.__name__}")

                if self._max_rows and visited_rows >= self._max_rows:
                    break

                # pagination
                try:
                    next_btn_li = page.locator("li#dataTable_next")
                    if next_btn_li.count() and "disabled" not in (next_btn_li.get_attribute("class") or ""):
                        next_btn = next_btn_li.locator("a.page-link")
                        next_btn.scroll_into_view_if_needed()
                        next_btn.click()
                        page.wait_for_timeout(1000)
                        current_page_no += 1
                    else:
                        break
                except Exception:
                    break

            # close browser
            try:
                page.close()
            except Exception:
                pass
            try:
                context.close()
            except Exception:
                pass
            try:
                browser.close()
            except Exception:
                pass

        self._is_crawled = True
        print(f"[TWEETFEED] ✅ Done. Collected={collected}")
        return {
            "seed_url": self.seed_url,
            "items_collected": collected,
            "developer_signature": self.developer_signature(),
        }