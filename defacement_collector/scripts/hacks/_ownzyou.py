import re
import hashlib
from abc import ABC
from datetime import datetime
from typing import List, Optional, Dict, Set
from urllib.parse import urljoin

from playwright.sync_api import Page, sync_playwright

# ✅ EXACT imports (same as your new framework version)
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


class _ownzyou(leak_extractor_interface, ABC):
    """
    OWNZYOU crawler — uses OLD-style 'Next' pagination logic (click next + wait change),
    but with correct DataTables selectors (#onhold_next etc).

    Flow:
      PHASE-1: visit first N pages and collect all /zone/... links (dedupe)
      PHASE-2: open each zone link one-by-one and extract fields + print
    """

    _instance = None

    # ---------------- Singleton ----------------
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_ownzyou, cls).__new__(cls)
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

        # limits
        self._max_pages: int = 5
        self._max_rows: Optional[int] = None

        # timeouts
        self._listing_timeout_ms: int = 90000
        self._detail_timeout_ms: int = 90000

        # retries
        self._goto_retries: int = 3

        # playwright options
        self._headless: bool = True

        print("[OWNZYOU] Initialized ✅")

    # ---------------- required interface props ----------------
    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "https://ownzyou.com"

    @property
    def base_url(self) -> str:
        return "https://ownzyou.com/"

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_fetch_proxy=FetchProxy.NONE,
            m_fetch_config=FetchConfig.PLAYRIGHT,
            m_threat_type=ThreatType.DEFACEMENT,
            m_resoource_block=False,
        )

    @property
    def developer_signature(self) -> str:
        return developer_signature(self._developer_name, self._developer_note)

    @property
    def card_data(self) -> List[defacement_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def contact_page(self) -> str:
        return "https://ownzyou.com/contact"

    # keep invoke_db style
    def invoke_db(self, command: int, key: str, default_value, expiry: int = None):
        return self._redis.invoke_trigger(command, [key + self.__class__.__name__, default_value, expiry])

    # ---------------- output (framework) ----------------
    def run(self) -> dict:
        print("[OWNZYOU] run() → Playwright crawl")

        if self._is_crawled:
            return {
                "seed_url": self.seed_url,
                "items_collected": len(self._card_data),
                "developer_signature": self.developer_signature,
            }

        p = None
        browser = None
        context = None
        page = None

        try:
            p = sync_playwright().start()
            browser = p.chromium.launch(headless=self._headless)
            context = browser.new_context(ignore_https_errors=True)

            try:
                context.set_default_timeout(max(self._listing_timeout_ms, self._detail_timeout_ms))
                context.set_default_navigation_timeout(max(self._listing_timeout_ms, self._detail_timeout_ms))
            except Exception:
                pass

            page = context.new_page()
            result = self.parse_leak_data(page)

            if isinstance(result, dict):
                result.setdefault("developer_signature", self.developer_signature)
            return result

        except Exception as ex:
            log.g().e(f"[OWNZYOU] run() fatal error: {ex}")
            return {
                "seed_url": self.seed_url,
                "items_collected": 0,
                "developer_signature": self.developer_signature,
                "error": str(ex),
            }

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
            try:
                if p:
                    p.stop()
            except Exception:
                pass

    # ---------------- data append ----------------
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

    # ---------------- utils ----------------
    @staticmethod
    def _safe_strip(x: str) -> str:
        return re.sub(r"\s+", " ", (x or "").strip())

    @staticmethod
    def safe_find(page: Page, selector: str, attr: str = None) -> str:
        try:
            element = page.query_selector(selector)
            if not element:
                return ""
            if attr:
                return (element.get_attribute(attr) or "").strip()
            return (element.inner_text() or "").strip()
        except Exception:
            return ""

    @staticmethod
    def _parse_report_date(report_date_str: str):
        s = (report_date_str or "").strip()
        if not s:
            return None
        for fmt in ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M"):
            try:
                return datetime.strptime(s, fmt).date()
            except Exception:
                pass
        return None

    @staticmethod
    def _sha1(text: str) -> str:
        return hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()

    def _make_aid(self, detail_url: str, ip: str, report_date: str) -> str:
        seed = "|".join([detail_url or "", ip or "", report_date or "", self.seed_url])
        return self._sha1(seed)

    def _goto_with_retry(self, p: Page, url: str, timeout_ms: int):
        last_ex = None
        for attempt in range(1, self._goto_retries + 1):
            try:
                p.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                return
            except Exception as ex1:
                last_ex = ex1
                try:
                    p.goto(url, wait_until="networkidle", timeout=timeout_ms)
                    return
                except Exception as ex2:
                    last_ex = ex2
                    try:
                        p.wait_for_timeout(700 * attempt)
                    except Exception:
                        pass
        raise last_ex

    # ---------------- listing helpers ----------------
    def _first_row_text(self, page: Page) -> str:
        try:
            row = page.query_selector("table tbody tr")
            return (row.inner_text() or "").strip() if row else ""
        except Exception:
            return ""

    def _collect_detail_links(self, page: Page) -> List[str]:
        page.wait_for_selector("table tbody tr", timeout=self._listing_timeout_ms)
        links: List[str] = []
        for a in page.query_selector_all("table tbody tr td a.btn.btn-outline-primary"):
            href = (a.get_attribute("href") or "").strip()
            if href:
                links.append(urljoin(self.base_url, href))
        return links

    def _find_next_button(self, page: Page):
        """
        OLD-style: try multiple selectors. Added DataTables next selector first.
        """
        return (
            page.query_selector("#onhold_next a.page-link") or
            page.query_selector("li.paginate_button.page-item.next a.page-link") or
            page.query_selector("ul.pagination li.next a") or
            page.query_selector("ul.pagination li a:has-text('Next')") or
            page.query_selector("a.page-link[rel='next']") or
            page.query_selector("a[rel='next']")
        )

    def _is_next_disabled(self, page: Page) -> bool:
        """
        DataTables: <li id="onhold_next" class="... disabled">
        """
        try:
            li = page.query_selector("#onhold_next")
            if not li:
                return False
            cls = (li.get_attribute("class") or "").lower()
            return "disabled" in cls
        except Exception:
            return False

    def _click_next_and_wait(self, page: Page) -> bool:
        """
        Mimics your old logic:
          - capture first row text
          - click next
          - wait networkidle
          - wait first-row changed
        """
        if self._is_next_disabled(page):
            return False

        next_button = self._find_next_button(page)
        if not next_button:
            return False

        prev_text = self._first_row_text(page)

        try:
            next_button.click()
        except Exception:
            try:
                page.locator("#onhold_next a.page-link").first.click(timeout=15000, force=True)
            except Exception:
                return False

        # wait page settle
        try:
            page.wait_for_load_state("networkidle", timeout=60000)
        except Exception:
            pass

        # wait table updated
        try:
            page.wait_for_function(
                """(prev) => {
                    const row = document.querySelector("table tbody tr");
                    if (!row) return false;
                    const now = (row.innerText || "").trim();
                    return now && now !== prev;
                }""",
                prev_text,
                timeout=25000,
            )
        except Exception:
            # fallback: sometimes first row text stays same; still allow progress
            pass

        return True

    # ---------------- detail helpers ----------------
    def _extract_detail_fields(self, detail_page: Page) -> Dict[str, str]:
        detail_page.wait_for_selector("#attacker_name", timeout=self._detail_timeout_ms)
        detail_page.wait_for_selector("#remote_zone_url", timeout=self._detail_timeout_ms)
        detail_page.wait_for_selector("#zone_ip", timeout=self._detail_timeout_ms)
        detail_page.wait_for_selector("#report_date", timeout=self._detail_timeout_ms)

        reporter = self.safe_find(detail_page, "#attacker_name") or self.safe_find(
            detail_page, "p:has(i.fa-user-secret) strong"
        )
        web_url = self.safe_find(detail_page, "#remote_zone_url", "href")
        ip = self.safe_find(detail_page, "#zone_ip")
        total_report = self.safe_find(detail_page, "#total_report")
        report_date = self.safe_find(detail_page, "#report_date")
        location = self.safe_find(detail_page, "#zone_location")
        mode = self.safe_find(detail_page, "#mirror_path_full")
        web_server = self.safe_find(detail_page, "#zone_web_server")

        iframe_src = ""
        iframe = detail_page.query_selector("iframe#mirror_path")
        if iframe:
            src = (iframe.get_attribute("src") or "").strip()
            if src:
                iframe_src = urljoin(self.base_url, src)

        return {
            "reporter": self._safe_strip(reporter),
            "web_url": self._safe_strip(web_url),
            "ip": self._safe_strip(ip),
            "total_report": self._safe_strip(total_report),
            "report_date": self._safe_strip(report_date),
            "location": self._safe_strip(location),
            "mode": self._safe_strip(mode),
            "web_server": self._safe_strip(web_server),
            "iframe_src": self._safe_strip(iframe_src),
        }

    # ---------------- MAIN ----------------
    def parse_leak_data(self, page: Page):
        # how many listing pages to read
        max_pages = 2 if self.is_crawled else self._max_pages

        # ---------------- load seed ----------------
        try:
            self._goto_with_retry(page, self.seed_url, timeout_ms=self._listing_timeout_ms)
        except Exception as ex:
            log.g().e(f"[OWNZYOU] seed goto warning: {ex}")

        # ensure listing table exists
        try:
            page.wait_for_selector("table tbody tr", timeout=self._listing_timeout_ms)
        except Exception as ex:
            log.g().e(f"[OWNZYOU] listing table not found: {ex}")

        # ---------------- PHASE 1: collect ALL links from N pages ----------------
        seen: Set[str] = set()
        detail_urls: List[str] = []

        current_page = 1
        while current_page <= max_pages:
            try:
                page.wait_for_load_state("domcontentloaded")
                page.wait_for_selector("table tbody tr", timeout=self._listing_timeout_ms)

                links = self._collect_detail_links(page)
                new_count = 0
                for u in links:
                    if u not in seen:
                        seen.add(u)
                        detail_urls.append(u)
                        new_count += 1

                first_link = links[0] if links else ""
                print(
                    f"[OWNZYOU] Listing page {current_page}/{max_pages}: "
                    f"links={len(links)} new={new_count} total_unique={len(detail_urls)} | first={first_link}"
                )

                if current_page >= max_pages:
                    break

                moved = self._click_next_and_wait(page)
                if not moved:
                    log.g().i("[OWNZYOU] No next button found / next disabled — pagination finished.")
                    break

                current_page += 1

            except Exception as ex:
                log.g().e(f"[OWNZYOU] Archive page error {current_page}: {ex}")
                break

        print(f"[OWNZYOU] ✅ Listing collection done: total_detail_urls={len(detail_urls)}")

        # ---------------- PHASE 2: open each detail one-by-one ----------------
        collected = 0
        visited = 0

        for idx, detail_url in enumerate(detail_urls, start=1):
            if self._max_rows and visited >= self._max_rows:
                print("[OWNZYOU] Max rows reached, stopping detail phase.")
                break

            visited += 1
            detail_page = None

            try:
                detail_page = page.context.new_page()
                self._goto_with_retry(detail_page, detail_url, timeout_ms=self._detail_timeout_ms)
                try:
                    detail_page.wait_for_load_state("networkidle", timeout=30000)
                except Exception:
                    pass

                fields = self._extract_detail_fields(detail_page)
                date_obj = self._parse_report_date(fields.get("report_date", ""))

                content = helper_method.extract_refhtml(
                    fields.get("ip", ""),
                    self.invoke_db,
                    REDIS_COMMANDS,
                    CUSTOM_SCRIPT_REDIS_KEYS,
                    RAW_PATH_CONSTANTS,
                    detail_page,
                )

                card = defacement_model(
                    m_web_server=[fields.get("web_server")] if fields.get("web_server") else [],
                    m_source_url=[detail_url],
                    m_content=content or "",
                    m_base_url=self.base_url,
                    m_url=fields.get("web_url") or detail_url,
                    m_ioc_type=["hacked", "ownzyou"],
                    m_mirror_links=[fields.get("iframe_src")] if fields.get("iframe_src") else [],
                    m_network=helper_method.get_network_type(self.base_url),
                    m_leak_date=date_obj,
                )

                ent = entity_model(
                    m_scrap_file=self.__class__.__name__,
                    m_team="",
                    m_ip=[fields.get("ip")] if fields.get("ip") else [],
                    m_attacker=[fields.get("reporter")] if fields.get("reporter") else [],
                    m_weblink=[fields.get("web_url")] if fields.get("web_url") else [],
                    m_vulnerability=fields.get("mode") or "",
                    m_location=fields.get("location") or "",
                    m_name="ownzyou",
                    m_total_report=fields.get("total_report") or "",
                )

                self.append_leak_data(card, ent)

                aid = self._make_aid(detail_url, fields.get("ip", ""), fields.get("report_date", ""))
                collected += 1

                print("\n---------------------- OWNZYOU SHOW -----------------------")
                print(f"#{idx}/{len(detail_urls)}")
                print(f"AID: {aid}")
                print(f"Detail URL: {detail_url}")
                print(f"Web URL: {fields.get('web_url','')}")
                print(f"Reporter: {fields.get('reporter','')}")
                print(f"IP: {fields.get('ip','')}")
                print(f"Total Report: {fields.get('total_report','')}")
                print(f"Report Date: {fields.get('report_date','')}")
                print(f"Location: {fields.get('location','')}")
                print(f"Mode: {fields.get('mode','')}")
                print(f"Web Server: {fields.get('web_server','')}")
                print(f"Iframe Mirror: {fields.get('iframe_src','')}")
                print(f"Tags: {', '.join(getattr(card, 'm_ioc_type', []) or [])}")
                print(f"Content Len: {len(content or '')}")
                print("----------------------------------------------------------\n")

            except Exception as ex:
                log.g().e(f"[OWNZYOU] Detail error {detail_url}: {ex}")

            finally:
                if detail_page:
                    try:
                        detail_page.close()
                    except Exception:
                        pass

        self._is_crawled = True
        print(f"[OWNZYOU] ✅ Done. Collected={collected}")

        return {
            "seed_url": self.seed_url,
            "items_collected": collected,
            "developer_signature": self.developer_signature,
        }
