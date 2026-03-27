import re
import hashlib
from abc import ABC
from datetime import datetime, timezone
from typing import List, Optional, Dict, Tuple, Set
from urllib.parse import urljoin

from playwright.sync_api import Page, sync_playwright

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


class _zone_xsec(leak_extractor_interface, ABC):
    """
    Zone-XSEC Archive crawler (pure Redis, no JSON) — same style as DEFACER.

    IMPORTANT: Framework RequestParser calls model.run() with NO args.
    So run() must create Playwright page and pass it to parse_leak_data(page).

    User requirements:
    - keep the same page query style: /archive/page={n}
    - print all important queries/data
    - crawl up to 5 pages
    - use Playwright browser launch so you can observe behavior
    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_zone_xsec, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, developer_name: str = "Anonymous", developer_note: str = "", callback=None):
        if getattr(self, "_initialized", False):
            return
        self._initialized = True

        self.callback = callback
        self._card_data: List[defacement_model] = []
        self._entity_data: List[entity_model] = []

        self._redis = redis_controller()
        self._is_crawled = False

        self._developer_name = developer_name
        self._developer_note = developer_note

        # crawl controls (USER: 5 pages)
        self._max_pages: int = 5
        self._max_rows: Optional[int] = None
        self._listing_timeout_ms: int = 60000
        self._detail_timeout_ms: int = 60000

        # Playwright controls
        self._proxy: dict = {}     # set by set_proxy()
        self._headless: bool = False  # USER: want to see browser
        self._chromium_exe = None  # optional

        # raw index
        self._raw_index_key = "ZONEXSEC:raw_index"

        print("[ZONEXSEC] Initialized ✅ (pure Redis, no JSON)")

    # ---------------- hooks/config ----------------
    def init_callback(self, callback=None):
        self.callback = callback
        print("[ZONEXSEC] Callback set")

    def set_limits(self, max_pages: Optional[int] = None, max_rows: Optional[int] = None):
        if max_pages is not None and max_pages >= 1:
            self._max_pages = int(max_pages)
        if max_rows is not None and max_rows >= 1:
            self._max_rows = int(max_rows)
        print(f"[ZONEXSEC] Limits → pages={self._max_pages}, rows={self._max_rows or '∞'}")

    def set_proxy(self, proxy: dict):
        self._proxy = proxy or {}
        print(f"[ZONEXSEC] Proxy configured: {self._proxy}")

    def set_headless(self, headless: bool):
        self._headless = bool(headless)
        print(f"[ZONEXSEC] Headless: {self._headless}")

    # ---------------- required interface props ----------------
    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "https://zone-xsec.com/archive"

    @property
    def base_url(self) -> str:
        return "https://zone-xsec.com"

    @property
    def developer_signature(self) -> str:
        return f"{self._developer_name}:{self._developer_note}"

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_fetch_proxy=FetchProxy.NONE,
            m_fetch_config=FetchConfig.PLAYWRIGHT,
            m_threat_type=ThreatType.DEFACEMENT,
        )

    @property
    def card_data(self) -> List[defacement_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def contact_page(self) -> str:
        return "https://zone-xsec.com/contact"

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

    def invoke_db(self, command: int, key: str, default_value, expiry: int = None):
        # keep same behavior: key + classname
        return self._redis.invoke_trigger(command, [key + self.__class__.__name__, default_value, expiry])

    # ---------------- utility helpers ----------------
    @staticmethod
    def _sha1(text: str) -> str:
        return hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()

    def _make_aid(self, target_url: str, mirror_url: str, saved_on: str) -> str:
        seed = "|".join([target_url or "", mirror_url or "", saved_on or "", self.seed_url])
        return self._sha1(seed)

    @staticmethod
    def _safe_strip(x: str) -> str:
        return re.sub(r"\s+", " ", (x or "").strip())

    @staticmethod
    def _safe_text(page: Page, selector: str) -> str:
        try:
            el = page.query_selector(selector)
            if not el:
                return ""
            return (el.inner_text() or "").strip()
        except Exception:
            return ""

    @staticmethod
    def _safe_attr(page: Page, selector: str, attr: str) -> str:
        try:
            el = page.query_selector(selector)
            if not el:
                return ""
            return (el.get_attribute(attr) or "").strip()
        except Exception:
            return ""

    @staticmethod
    def _parse_zone_date(s: str) -> Tuple[Optional[datetime], Optional[object]]:
        """
        Zone-X sometimes shows 'Saved on' like: '2024-01-15 13:22:11' or '2024-01-15'
        We try common formats; return (datetime_obj, date_obj).
        """
        s = (s or "").strip()
        if not s:
            return None, None

        # keep only first two tokens if label noise exists
        s = re.sub(r"^[A-Za-z ]+:\s*", "", s).strip()

        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(s, fmt)
                return dt, dt.date()
            except Exception:
                pass

        # fallback: try first token as YYYY-MM-DD
        tok = s.split()[0] if s.split() else ""
        try:
            dt = datetime.strptime(tok, "%Y-%m-%d")
            return dt, dt.date()
        except Exception:
            return None, None

    # ---------------- browser helpers ----------------
    def _launch_browser(self, p, use_proxy: bool):
        launch_kwargs = {"headless": self._headless}
        if self._chromium_exe:
            launch_kwargs["executable_path"] = self._chromium_exe

        if use_proxy and (self._proxy or {}).get("server"):
            launch_kwargs["proxy"] = {"server": self._proxy["server"]}
            print(f"[ZONEXSEC] Launching Chromium WITH proxy: {self._proxy['server']}")
        else:
            print("[ZONEXSEC] Launching Chromium WITHOUT proxy")

        browser = p.chromium.launch(**launch_kwargs)
        context = browser.new_context()

        # safer timeouts
        context.set_default_timeout(max(self._listing_timeout_ms, self._detail_timeout_ms))
        context.set_default_navigation_timeout(max(self._listing_timeout_ms, self._detail_timeout_ms))

        return browser, context

    # ---------------- framework entrypoint ----------------
    def run(self) -> dict:
        """
        RequestParser calls run() with no args.
        We create Playwright page here and call parse_leak_data(page).
        """
        print("[ZONEXSEC] run() → Playwright crawl")
        return self._run_playwright()

    def _run_playwright(self) -> dict:
        with sync_playwright() as p:
            browser = None
            context = None
            page = None

            # try with proxy then without (USOM style)
            try:
                browser, context = self._launch_browser(p, use_proxy=True)
                page = context.new_page()
                page.goto(self.seed_url, wait_until="domcontentloaded", timeout=self._listing_timeout_ms)
            except Exception as ex:
                print(f"[ZONEXSEC] Proxy navigation failed: {ex}. Retrying without proxy …")
                try:
                    if page:
                        page.close()
                except Exception:
                    pass
                try:
                    if context:
                        context.close()
                except Exception:
                    pass
                try:
                    if browser:
                        browser.close()
                except Exception:
                    pass

                browser, context = self._launch_browser(p, use_proxy=False)
                page = context.new_page()
                page.goto(self.seed_url, wait_until="domcontentloaded", timeout=self._listing_timeout_ms)

            try:
                result = self.parse_leak_data(page)
                return result
            finally:
                try:
                    if page:
                        page.close()
                except Exception:
                    pass
                try:
                    if context:
                        context.close()
                except Exception:
                    pass
                try:
                    if browser:
                        browser.close()
                except Exception:
                    pass

    # ---------------- storage ----------------
    def _store_raw_card(self, aid: str, card: defacement_model, ent: entity_model, fields: Dict[str, str]) -> str:
        base = f"ZONEXSEC:raw:{aid}"
        ent_base = f"{base}:entity"

        self._redis_set(f"{base}:url", card.m_url or "")
        self._redis_set(f"{base}:base_url", card.m_base_url or "")
        self._redis_set(f"{base}:network:type", card.m_network or "")
        self._redis_set(f"{base}:leak_date", str(card.m_leak_date or ""))
        self._redis_set(f"{base}:content", card.m_content or "")
        self._redis_set(f"{base}:scraped_at", int(datetime.now(timezone.utc).timestamp()))
        self._redis_set(f"{base}:seed_url", self.seed_url)
        self._redis_set(f"{base}:rendered", "1")

        srcs = getattr(card, "m_source_url", []) or []
        self._redis_set(f"{base}:source_url_count", len(srcs))
        for i, u in enumerate(srcs):
            self._redis_set(f"{base}:source_url:{i}", u)

        iocs = getattr(card, "m_ioc_type", []) or []
        self._redis_set(f"{base}:ioc_type_count", len(iocs))
        for i, t in enumerate(iocs):
            self._redis_set(f"{base}:ioc_type:{i}", t)

        mirrors = getattr(card, "m_mirror_links", []) or []
        self._redis_set(f"{base}:mirror_links_count", len(mirrors))
        for i, u in enumerate(mirrors):
            self._redis_set(f"{base}:mirror_link:{i}", u)

        servers = getattr(card, "m_web_server", []) or []
        self._redis_set(f"{base}:web_server_count", len(servers))
        for i, s in enumerate(servers):
            self._redis_set(f"{base}:web_server:{i}", s)

        self._redis_set(f"{ent_base}:scrap_file", getattr(ent, "m_scrap_file", "") or "")
        self._redis_set(f"{ent_base}:team", getattr(ent, "m_team", "") or "")
        self._redis_set(f"{ent_base}:vulnerability", getattr(ent, "m_vulnerability", "") or "")
        self._redis_set(f"{ent_base}:exploit_year", getattr(ent, "m_exploit_year", "") or "")

        ips = getattr(ent, "m_ip", []) or []
        self._redis_set(f"{ent_base}:ip_count", len(ips))
        for i, x in enumerate(ips):
            self._redis_set(f"{ent_base}:ip:{i}", x)

        attackers = getattr(ent, "m_attacker", []) or []
        self._redis_set(f"{ent_base}:attacker_count", len(attackers))
        for i, x in enumerate(attackers):
            self._redis_set(f"{ent_base}:attacker:{i}", x)

        weblinks = getattr(ent, "m_weblink", []) or []
        self._redis_set(f"{ent_base}:weblink_count", len(weblinks))
        for i, x in enumerate(weblinks):
            self._redis_set(f"{ent_base}:weblink:{i}", x)

        isps = getattr(ent, "m_isp", []) or []
        self._redis_set(f"{ent_base}:isp_count", len(isps))
        for i, x in enumerate(isps):
            self._redis_set(f"{ent_base}:isp:{i}", x)

        for k, v in (fields or {}).items():
            self._redis_set(f"{base}:detail:{k}", v)

        self._append_index(self._raw_index_key, aid)
        return aid

    # ---------------- output ----------------
    def append_leak_data(self, leak: defacement_model, entity: entity_model):
        self._card_data.append(leak)
        self._entity_data.append(entity)
        if self.callback:
            try:
                if self.callback():
                    self._card_data.clear()
                    self._entity_data.clear()
            except Exception:
                pass

    # ---------------- listing helpers ----------------
    def _archive_page_url(self, page_no: int) -> str:
        # USER: keep same query style
        return f"{self.seed_url}/page={page_no}"

    def _collect_show_mirror_links_from_listing(self, page: Page) -> List[str]:
        """
        From archive listing, collect all "Show Mirror" links.
        """
        page.wait_for_selector("a[title='Show Mirror']", timeout=self._listing_timeout_ms)

        links: List[str] = []
        for a in page.query_selector_all("a[title='Show Mirror']"):
            href = (a.get_attribute("href") or "").strip()
            if not href:
                continue
            links.append(urljoin(self.base_url, href))
        return links

    # ---------------- detail helpers ----------------
    def _extract_detail_fields(self, mirror_page: Page, fallback_url: str) -> Dict[str, str]:
        """
        Extracts important fields from a Zone-X mirror detail page.
        """
        # This is what your old script expected:
        mirror_page.wait_for_selector(".panel.panel-danger", timeout=self._detail_timeout_ms)

        # Target URL (sometimes in span#url)
        url_span = mirror_page.query_selector("span#url")
        extracted_url = self._safe_strip(url_span.inner_text() if url_span else "") or fallback_url

        # These selectors are taken from your original script; we keep them but make them safe.
        ip = self._safe_strip(self._safe_text(mirror_page, "p:has(strong):has-text('IP') strong"))
        defacer = self._safe_strip(self._safe_text(mirror_page, "p:has(strong):has-text('Defacer') strong"))
        location = self._safe_strip(self._safe_text(mirror_page, "p:has(strong):has-text('Location') strong"))
        web_server = self._safe_strip(self._safe_text(mirror_page, "p:has(strong):has-text('Web Server') strong"))
        saved_on = self._safe_strip(self._safe_text(mirror_page, "p:has(strong):has-text('Saved on') strong"))
        team = self._safe_strip(self._safe_text(mirror_page, "p:has(strong):has-text('Team') strong"))

        # Mirror iframe
        iframe = mirror_page.query_selector("iframe")
        iframe_src = self._safe_strip(iframe.get_attribute("src") if iframe else "")

        return {
            "target_url": extracted_url,
            "ip": ip,
            "defacer": defacer,
            "location": location,
            "web_server": web_server,
            "saved_on": saved_on,
            "team": team,
            "iframe_src": iframe_src,
        }

    # ---------------- main parse ----------------
    def parse_leak_data(self, page: Page):
        collected = 0
        visited = 0
        consecutive_errors = 0

        context = page.context
        max_pages = 1 if self.is_crawled else self._max_pages

        # -------- PHASE 1: collect all mirror URLs --------
        seen: Set[str] = set()
        mirror_urls: List[str] = []

        current_page = 1
        while current_page <= max_pages:
            try:
                page_url = self._archive_page_url(current_page)
                print(f"[ZONEXSEC] Listing open: {page_url}")

                page.goto(page_url, wait_until="domcontentloaded", timeout=self._listing_timeout_ms)
                page.wait_for_selector("a[title='Show Mirror']", timeout=self._listing_timeout_ms)

                links = self._collect_show_mirror_links_from_listing(page)

                new_count = 0
                for u in links:
                    u = (u or "").strip()
                    if not u or u in seen:
                        continue
                    seen.add(u)
                    mirror_urls.append(u)
                    new_count += 1

                print(
                    f"[ZONEXSEC] Page {current_page}/{max_pages}: links={len(links)} "
                    f"new={new_count} total_unique={len(mirror_urls)}"
                )

                consecutive_errors = 0
                current_page += 1

            except Exception as ex:
                log.g().e(f"[ZONEXSEC] Archive page error {current_page}: {ex}")
                consecutive_errors += 1
                if consecutive_errors >= 5:
                    log.g().e("[ZONEXSEC] Too many consecutive listing errors. Stopping listing phase.")
                    break
                current_page += 1

        print(f"[ZONEXSEC] ✅ Listing collection done: total_show_urls={len(mirror_urls)}")

        # -------- PHASE 2: visit each mirror/detail and extract --------
        for idx, mirror_url in enumerate(mirror_urls, start=1):
            if self._max_rows and visited >= self._max_rows:
                print("[ZONEXSEC] Max rows reached, stopping detail phase.")
                break

            visited += 1
            mirror_page = None

            try:
                print(f"[ZONEXSEC] Detail open ({idx}/{len(mirror_urls)}): {mirror_url}")

                mirror_page = context.new_page()
                mirror_page.goto(mirror_url, wait_until="domcontentloaded", timeout=self._detail_timeout_ms)

                fields = self._extract_detail_fields(mirror_page, fallback_url=mirror_url)
                dt_obj, date_obj = self._parse_zone_date(fields.get("saved_on", ""))

                # IMPORTANT: keep helper_method.extract_refhtml usage (same as your script)
                content = helper_method.extract_refhtml(
                    fields.get("ip", ""),
                    self.invoke_db,
                    REDIS_COMMANDS,
                    CUSTOM_SCRIPT_REDIS_KEYS,
                    RAW_PATH_CONSTANTS,
                    mirror_page,
                )

                target_url = fields.get("target_url", "") or mirror_url

                card = defacement_model(
                    m_web_server=[fields.get("web_server")] if fields.get("web_server") else [],
                    m_source_url=[mirror_url],
                    m_content=content or "",
                    m_base_url=self.base_url,
                    m_url=target_url,
                    m_ioc_type=["hacked"],
                    m_mirror_links=[fields.get("iframe_src")] if fields.get("iframe_src") else [],
                    m_network=helper_method.get_network_type(self.base_url),
                    m_leak_date=date_obj,
                )

                ent = entity_model(
                    m_scrap_file=self.__class__.__name__,
                    m_ip=[fields.get("ip")] if fields.get("ip") else [],
                    m_location=[fields.get("location")] if fields.get("location") else [],
                    m_team=fields.get("team") or "",
                    m_attacker=[fields.get("defacer")] if fields.get("defacer") else [],
                    m_weblink=[target_url] if target_url else [],
                )

                self.append_leak_data(card, ent)

                aid = self._make_aid(target_url, mirror_url, fields.get("saved_on", ""))

                store_fields = dict(fields)
                store_fields["mirror_url"] = mirror_url
                store_fields["content_len"] = str(len(content or ""))
                store_fields["saved_on_dt"] = dt_obj.isoformat() if dt_obj else ""

                self._store_raw_card(aid, card, ent, store_fields)
                collected += 1

                # USER: print queries and data (full verbose output)
                print("\n---------------------- ZONEXSEC SHOW ----------------------")
                print(f"#{idx}/{len(mirror_urls)}")
                print(f"AID: {aid}")
                print(f"Listing Page Style: {self.seed_url}/page={{n}} (max_pages={max_pages})")
                print(f"Mirror URL: {mirror_url}")
                print(f"Target URL: {target_url}")
                print(f"Saved On: {fields.get('saved_on','')}")
                print(f"IP: {fields.get('ip','')}")
                print(f"Defacer: {fields.get('defacer','')}")
                print(f"Team: {fields.get('team','')}")
                print(f"Location: {fields.get('location','')}")
                print(f"Web Server: {fields.get('web_server','')}")
                print(f"Iframe Mirror: {fields.get('iframe_src','')}")
                print(f"Tags: {', '.join(getattr(card, 'm_ioc_type', []) or [])}")
                print(f"Content Len: {len(content or '')}")
                print("-----------------------------------------------------------\n")

            except Exception as ex:
                log.g().e(f"[ZONEXSEC] Mirror error {mirror_url}: {ex}")

            finally:
                if mirror_page:
                    try:
                        mirror_page.close()
                    except Exception:
                        pass

        self._is_crawled = True
        print(f"[ZONEXSEC] ✅ Done. Collected={collected}")

        return {
            "seed_url": self.seed_url,
            "items_collected": collected,
            "developer_signature": self.developer_signature,
            "max_pages": max_pages,
        }
