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


class _defacer(leak_extractor_interface, ABC):
    """
    DEFACER Archive crawler (pure Redis, no JSON) — USOM style.

    IMPORTANT: Framework RequestParser calls model.run() with NO args.
    So run() must create Playwright page and pass it to parse_leak_data(page).
    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_defacer, cls).__new__(cls)
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

        # crawl controls
        self._max_pages: int = 2
        self._max_rows: Optional[int] = None
        self._listing_timeout_ms: int = 60000
        self._detail_timeout_ms: int = 60000

        # Playwright controls
        self._proxy: dict = {}     # set by set_proxy()
        self._headless: bool = True
        self._chromium_exe = None  # optional

        # raw index
        self._raw_index_key = "DEFACER:raw_index"

        print("[DEFACER] Initialized ✅ (pure Redis, no JSON)")

    # ---------------- hooks/config ----------------
    def init_callback(self, callback=None):
        self.callback = callback
        print("[DEFACER] Callback set")

    def set_limits(self, max_pages: Optional[int] = None, max_rows: Optional[int] = None):
        if max_pages is not None and max_pages >= 1:
            self._max_pages = int(max_pages)
        if max_rows is not None and max_rows >= 1:
            self._max_rows = int(max_rows)
        print(f"[DEFACER] Limits → pages={self._max_pages}, rows={self._max_rows or '∞'}")

    def set_proxy(self, proxy: dict):
        self._proxy = proxy or {}
        print(f"[DEFACER] Proxy configured: {self._proxy}")

    def set_headless(self, headless: bool):
        self._headless = bool(headless)
        print(f"[DEFACER] Headless: {self._headless}")

    # ---------------- required interface props ----------------
    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "https://defacer.net/archive/"

    @property
    def base_url(self) -> str:
        return "https://defacer.net"

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
        return self.base_url

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
        return self._redis.invoke_trigger(command, [key + self.__class__.__name__, default_value, expiry])

    # ---------------- utility helpers ----------------
    @staticmethod
    def _sha1(text: str) -> str:
        return hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()

    def _make_aid(self, target_url: str, mirror_url: str, recorded_on: str) -> str:
        seed = "|".join([target_url or "", mirror_url or "", recorded_on or "", self.seed_url])
        return self._sha1(seed)

    @staticmethod
    def _safe_strip(x: str) -> str:
        return re.sub(r"\s+", " ", (x or "").strip())

    @staticmethod
    def _parse_defacer_datetime(s: str) -> Tuple[Optional[datetime], Optional[object]]:
        s = (s or "").strip()
        if not s:
            return None, None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
            try:
                dt = datetime.strptime(s, fmt)
                return dt, dt.date()
            except Exception:
                pass
        return None, None

    # ---------------- browser helpers ----------------
    def _launch_browser(self, p, use_proxy: bool):
        launch_kwargs = {"headless": self._headless}
        if self._chromium_exe:
            launch_kwargs["executable_path"] = self._chromium_exe

        if use_proxy and (self._proxy or {}).get("server"):
            launch_kwargs["proxy"] = {"server": self._proxy["server"]}
            print(f"[DEFACER] Launching Chromium WITH proxy: {self._proxy['server']}")
        else:
            print("[DEFACER] Launching Chromium WITHOUT proxy")

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
        print("[DEFACER] run() → Playwright crawl")
        return self._run_playwright()

    def _run_playwright(self) -> dict:
        with sync_playwright() as p:
            browser = None
            context = None
            page = None

            # try with proxy then without (same as USOM)
            try:
                browser, context = self._launch_browser(p, use_proxy=True)
                page = context.new_page()
                page.goto(self.seed_url, wait_until="domcontentloaded", timeout=self._listing_timeout_ms)
            except Exception as ex:
                print(f"[DEFACER] Proxy navigation failed: {ex}. Retrying without proxy …")
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
                # now call actual parser
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
        base = f"DEFACER:raw:{aid}"
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
        if page_no <= 1:
            return self.seed_url
        return f"{self.seed_url}{page_no}"

    def _collect_mirror_links_from_listing(self, page: Page) -> List[str]:
        page.wait_for_selector("table tbody tr", timeout=self._listing_timeout_ms)
        rows = page.query_selector_all("table tbody tr")

        links: List[str] = []
        for row in rows:
            a = row.query_selector("td.center a")
            if not a:
                continue
            href = (a.get_attribute("href") or "").strip()
            if not href:
                continue
            links.append(urljoin(self.base_url, href))
        return links

    # ---------------- detail helpers ----------------
    def _extract_detail_fields(self, mirror_page: Page) -> Dict[str, str]:
        mirror_page.wait_for_selector(".card.bg-dark", timeout=self._detail_timeout_ms)

        header_elem = mirror_page.query_selector(".card-header.bg-info")
        header = self._safe_strip(header_elem.inner_text() if header_elem else "")

        target_url = ""
        if "Defacement Detail of" in header:
            target_url = self._safe_strip(header.split("Defacement Detail of", 1)[-1])

        desc_elem = mirror_page.query_selector(".card-body p")
        description = self._safe_strip(desc_elem.inner_text() if desc_elem else "")

        rec_elem = mirror_page.query_selector("p:has(strong:has-text('Recorded On')) strong")
        recorded_on = ""
        if rec_elem:
            recorded_on = self._safe_strip(rec_elem.inner_text())
            if ":" in recorded_on:
                recorded_on = self._safe_strip(recorded_on.split(":", 1)[-1])

        ip_elem = mirror_page.query_selector("strong:has-text('IP') a")
        ip = self._safe_strip(ip_elem.inner_text() if ip_elem else "")

        att_elem = mirror_page.query_selector("p:has(strong:has-text('Attacker')) a")
        attacker = self._safe_strip(att_elem.inner_text() if att_elem else "")

        team_elem = mirror_page.query_selector("p:has(strong:has-text('Team')) a")
        team = self._safe_strip(team_elem.inner_text() if team_elem else "")

        srv_elem = mirror_page.query_selector("p:has(strong:has-text('Server')) strong")
        server = ""
        if srv_elem:
            server = self._safe_strip(srv_elem.inner_text())
            if ":" in server:
                server = self._safe_strip(server.split(":", 1)[-1])

        poc_elem = mirror_page.query_selector("p:has(strong:has-text('PoC')) strong")
        poc = ""
        if poc_elem:
            poc = self._safe_strip(poc_elem.inner_text())
            if ":" in poc:
                poc = self._safe_strip(poc.split(":", 1)[-1])

        isp_elem = mirror_page.query_selector("p:has(strong:has-text('ISP Provider')) strong")
        isp = ""
        if isp_elem:
            isp = self._safe_strip(isp_elem.inner_text())
            if ":" in isp:
                isp = self._safe_strip(isp.split(":", 1)[-1])

        iframe = mirror_page.query_selector("iframe")
        iframe_src = ""
        if iframe:
            iframe_src = self._safe_strip(iframe.get_attribute("src") or "")

        return {
            "header": header,
            "target_url": target_url,
            "description": description,
            "recorded_on": recorded_on,
            "ip": ip,
            "attacker": attacker,
            "team": team,
            "server": server,
            "poc": poc,
            "isp": isp,
            "iframe_src": iframe_src,
        }

    # ---------------- main parse ----------------
    def parse_leak_data(self, page: Page):
        collected = 0
        visited = 0
        consecutive_errors = 0

        context = page.context
        max_pages = 2 if self.is_crawled else self._max_pages

        # -------- PHASE 1: collect all mirror URLs --------
        seen: Set[str] = set()
        mirror_urls: List[str] = []

        current_page = 1
        while current_page <= max_pages:
            try:
                page_url = self._archive_page_url(current_page)
                print(f"[DEFACER] Listing open: {page_url}")

                page.goto(page_url, wait_until="domcontentloaded", timeout=self._listing_timeout_ms)
                page.wait_for_selector("table tbody tr", timeout=self._listing_timeout_ms)

                links = self._collect_mirror_links_from_listing(page)

                new_count = 0
                for u in links:
                    u = (u or "").strip()
                    if not u or u in seen:
                        continue
                    seen.add(u)
                    mirror_urls.append(u)
                    new_count += 1

                print(f"[DEFACER] Page {current_page}/{max_pages}: links={len(links)} new={new_count} total_unique={len(mirror_urls)}")

                consecutive_errors = 0
                current_page += 1

            except Exception as ex:
                log.g().e(f"[DEFACER] Archive page error {current_page}: {ex}")
                consecutive_errors += 1
                if consecutive_errors >= 5:
                    log.g().e("[DEFACER] Too many consecutive listing errors. Stopping listing phase.")
                    break
                current_page += 1

        print(f"[DEFACER] ✅ Listing collection done: total_show_urls={len(mirror_urls)}")

        # -------- PHASE 2: visit each mirror/detail and extract --------
        for idx, mirror_url in enumerate(mirror_urls, start=1):
            if self._max_rows and visited >= self._max_rows:
                print("[DEFACER] Max rows reached, stopping detail phase.")
                break

            visited += 1
            mirror_page = None

            try:
                mirror_page = context.new_page()
                mirror_page.goto(mirror_url, wait_until="domcontentloaded", timeout=self._detail_timeout_ms)

                fields = self._extract_detail_fields(mirror_page)
                dt_obj, date_obj = self._parse_defacer_datetime(fields.get("recorded_on", ""))

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
                    m_web_server=[fields.get("server")] if fields.get("server") else [],
                    m_source_url=[mirror_url],
                    m_content=content or "",
                    m_base_url=self.base_url,
                    m_url=target_url,
                    m_ioc_type=["hacked", "defacer"],
                    m_mirror_links=[fields.get("iframe_src")] if fields.get("iframe_src") else [],
                    m_network=helper_method.get_network_type(self.base_url),
                    m_leak_date=date_obj,
                )

                ent = entity_model(
                    m_scrap_file=self.__class__.__name__,
                    m_ip=[fields.get("ip")] if fields.get("ip") else [],
                    m_team=fields.get("team") or "",
                    m_attacker=[fields.get("attacker")] if fields.get("attacker") else [],
                    m_weblink=[target_url] if target_url else [],
                    m_vulnerability=fields.get("poc") or "",
                    m_isp=[fields.get("isp")] if fields.get("isp") else [],
                    m_exploit_year=fields.get("description") or "",
                )

                self.append_leak_data(card, ent)

                aid = self._make_aid(target_url, mirror_url, fields.get("recorded_on", ""))

                store_fields = dict(fields)
                store_fields["mirror_url"] = mirror_url
                store_fields["content_len"] = str(len(content or ""))
                store_fields["recorded_on_dt"] = dt_obj.isoformat() if dt_obj else ""

                self._store_raw_card(aid, card, ent, store_fields)
                collected += 1

                print("\n---------------------- DEFACER SHOW -----------------------")
                print(f"#{idx}/{len(mirror_urls)}")
                print(f"AID: {aid}")
                print(f"Mirror URL: {mirror_url}")
                print(f"Target URL: {target_url}")
                print(f"Recorded On: {fields.get('recorded_on','')}")
                print(f"IP: {fields.get('ip','')}")
                print(f"Attacker: {fields.get('attacker','')}")
                print(f"Team: {fields.get('team','')}")
                print(f"Server: {fields.get('server','')}")
                print(f"PoC: {fields.get('poc','')}")
                print(f"ISP: {fields.get('isp','')}")
                print(f"Iframe Mirror: {fields.get('iframe_src','')}")
                print(f"Description: {fields.get('description','')}")
                print(f"Tags: {', '.join(getattr(card, 'm_ioc_type', []) or [])}")
                print(f"Content Len: {len(content or '')}")
                print("-----------------------------------------------------------\n")

            except Exception as ex:
                log.g().e(f"[DEFACER] Mirror error {mirror_url}: {ex}")

            finally:
                if mirror_page:
                    try:
                        mirror_page.close()
                    except Exception:
                        pass

        self._is_crawled = True
        print(f"[DEFACER] ✅ Done. Collected={collected}")

        return {
            "seed_url": self.seed_url,
            "items_collected": collected,
            "developer_signature": self.developer_signature,
        }
