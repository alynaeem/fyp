import re
import hashlib
from abc import ABC
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict

from bs4 import BeautifulSoup
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


class _usom(leak_extractor_interface, ABC):
    """
    USOM Address crawler (pure Redis, no JSON).

    Flow:
      1) Open seed listing: https://www.usom.gov.tr/en/address/
      2) Collect all "Show" links from table rows (dedupe)
      3) For each Show link, open detail in NEW page/tab
      4) Extract:
         - Title/IOC
         - Category (text-danger)
         - Criticality (score)
         - dt/dd map: Description, Connection Type, Date, Source, ...
         - page_text (clean)
      5) Print after each show
      6) Store raw keys in Redis (no JSON) + index key
      7) Create defacement_model + entity_model
    """

    _instance = None

    # ---------------- Singleton ----------------
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_usom, cls).__new__(cls)
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
        self._max_pages: int = 5
        self._max_rows: Optional[int] = None  # None = unlimited
        self._proxy: dict = {}
        self._chromium_exe = None  # optional local chromium path
        self._headless: bool = False

        # redis indices (pipe-delimited, not json)
        self._raw_index_key = "USOM:raw_index"

        print("[USOM] Initialized ✅ (pure Redis, no JSON)")

    # ---------------- hooks/config ----------------
    def init_callback(self, callback=None):
        self.callback = callback
        print("[USOM] Callback set")

    def set_proxy(self, proxy: dict):
        self._proxy = proxy or {}
        print(f"[USOM] Proxy configured: {self._proxy}")

    def set_headless(self, headless: bool):
        self._headless = bool(headless)
        print(f"[USOM] Headless: {self._headless}")

    def set_limits(self, max_pages: Optional[int] = None, max_rows: Optional[int] = None):
        if max_pages is not None and max_pages >= 1:
            self._max_pages = int(max_pages)
        if max_rows is not None and max_rows >= 1:
            self._max_rows = int(max_rows)
        print(f"[USOM] Limits → pages={self._max_pages}, rows={self._max_rows or '∞'}")

    # ---------------- required interface props ----------------
    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "https://www.usom.gov.tr/en/address/"

    @property
    def base_url(self) -> str:
        return "https://www.usom.gov.tr/"

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
        return "https://www.usom.gov.tr/en/"

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

    # keep original invoke_db style (if you use helper_method.extract_refhtml anywhere)
    def invoke_db(self, command: int, key: str, default_value, expiry: int = None):
        return self._redis.invoke_trigger(command, [key + self.__class__.__name__, default_value, expiry])

    # ---------------- utility helpers ----------------
    @staticmethod
    def _sha1(text: str) -> str:
        return hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()

    @staticmethod
    def _abs_url(path_or_url: str) -> str:
        if not path_or_url:
            return ""
        if path_or_url.startswith(("http://", "https://")):
            return path_or_url
        if not path_or_url.startswith("/"):
            path_or_url = "/" + path_or_url
        return "https://www.usom.gov.tr" + path_or_url

    @staticmethod
    def _clean_text(html: str) -> str:
        soup = BeautifulSoup(html, "lxml")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        text = soup.get_text("\n", strip=True)
        text = re.sub(r"\n{3,}", "\n\n", text).strip()
        return text

    @staticmethod
    def _extract_dt_dd_map(soup: BeautifulSoup) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for dl in soup.find_all("dl"):
            for dt in dl.find_all("dt"):
                dd = dt.find_next_sibling("dd")
                if not dd:
                    continue
                k = re.sub(r"\s+", " ", dt.get_text(" ", strip=True)).strip().rstrip(":")
                v = re.sub(r"\s+", " ", dd.get_text(" ", strip=True)).strip()
                if k:
                    out[k] = v
        return out

    @staticmethod
    def _parse_usom_date_to_dateobj(date_str: str):
        """
        USOM detail date example: "2/8/2026, 06:10 PM"
        We'll try a couple formats, otherwise return None.
        """
        s = (date_str or "").strip()
        if not s:
            return None
        # try common formats
        for fmt in ("%m/%d/%Y, %I:%M %p", "%m/%d/%Y, %H:%M", "%d/%m/%Y, %I:%M %p", "%d/%m/%Y, %H:%M"):
            try:
                return datetime.strptime(s, fmt).date()
            except Exception:
                pass
        return None

    def _make_aid(self, ioc: str, show_url: str, leak_date: str) -> str:
        seed = "|".join([str(ioc or ""), str(show_url or ""), str(leak_date or ""), self.seed_url])
        return self._sha1(seed)

    # ---------------- storage (raw per-field keys, no JSON) ----------------
    def _store_raw_card(
        self,
        aid: str,
        card: defacement_model,
        ent: entity_model,
        detail_fields: Dict[str, str],
        show_url: str,
    ) -> str:
        base = f"USOM:raw:{aid}"

        # card scalar fields
        self._redis_set(f"{base}:url", card.m_url or "")
        self._redis_set(f"{base}:base_url", card.m_base_url or "")
        self._redis_set(f"{base}:network:type", card.m_network or "")
        self._redis_set(f"{base}:leak_date", str(card.m_leak_date or ""))
        self._redis_set(f"{base}:content", card.m_content or "")
        self._redis_set(f"{base}:scraped_at", int(datetime.now(timezone.utc).timestamp()))
        self._redis_set(f"{base}:seed_url", self.seed_url)
        self._redis_set(f"{base}:show_url", show_url or "")
        self._redis_set(f"{base}:rendered", "1")

        # source_url list (no json)
        srcs = card.m_source_url or []
        self._redis_set(f"{base}:source_url_count", len(srcs))
        for i, u in enumerate(srcs):
            self._redis_set(f"{base}:source_url:{i}", u)

        # ioc_type list (no json)
        iocs = card.m_ioc_type or []
        self._redis_set(f"{base}:ioc_type_count", len(iocs))
        for i, t in enumerate(iocs):
            self._redis_set(f"{base}:ioc_type:{i}", t)

        # entity fields
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

        # detail fields (NO JSON) → store as individual keys
        # important fields
        self._redis_set(f"{base}:detail:title", detail_fields.get("title", ""))
        self._redis_set(f"{base}:detail:category", detail_fields.get("category", ""))
        self._redis_set(f"{base}:detail:criticality", detail_fields.get("criticality", ""))
        self._redis_set(f"{base}:detail:description", detail_fields.get("description", ""))
        self._redis_set(f"{base}:detail:connection_type", detail_fields.get("connection_type", ""))
        self._redis_set(f"{base}:detail:date_raw", detail_fields.get("date_raw", ""))
        self._redis_set(f"{base}:detail:source", detail_fields.get("source", ""))

        # kv map flattened (pipe-safe store as newline lines)
        kv_lines = detail_fields.get("kv_text", "")
        self._redis_set(f"{base}:detail:kv_text", kv_lines)

        # cleaned full text
        self._redis_set(f"{base}:detail:page_text", detail_fields.get("page_text", ""))

        # index
        self._append_index(self._raw_index_key, aid)
        return aid

    # ---------------- browser helpers ----------------
    def _launch_browser(self, p, use_proxy: bool) -> Tuple[object, object]:
        launch_kwargs = {"headless": self._headless}
        if self._chromium_exe:
            launch_kwargs["executable_path"] = self._chromium_exe

        if use_proxy and (self._proxy or {}).get("server"):
            launch_kwargs["proxy"] = {"server": self._proxy["server"]}
            print(f"[USOM] Launching Chromium WITH proxy: {self._proxy['server']}")
        else:
            print("[USOM] Launching Chromium WITHOUT proxy")

        browser = p.chromium.launch(**launch_kwargs)
        context = browser.new_context()
        return browser, context

    # ---------------- pipeline core ----------------
    def run(self) -> dict:
        print("[USOM] run() → Playwright crawl")
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

    # ---------------- USOM parsing helpers ----------------
    def _collect_show_rows(self, page) -> List[Dict[str, str]]:
        """
        From listing page HTML: find each row show link + ioc guess.
        Returns list of dicts: {"ioc":..., "show_path":..., "show_url":...}
        """
        html = page.content()
        soup = BeautifulSoup(html, "lxml")

        table = soup.find("table")
        if not table:
            return []

        out: List[Dict[str, str]] = []
        for tr in table.find_all("tr"):
            a = tr.select_one("a.btn.btn-primary[href]")
            if not a:
                continue
            show_path = (a.get("href") or "").strip()
            if not show_path:
                continue
            show_url = self._abs_url(show_path)

            # IOC guess from non-button td
            ioc_guess = ""
            tds = tr.find_all("td")
            for td in tds:
                if td.select_one("a.btn.btn-primary"):
                    continue
                txt = re.sub(r"\s+", " ", td.get_text(" ", strip=True)).strip()
                if not txt:
                    continue
                if "." in txt or "http" in txt:
                    ioc_guess = txt
                    break
            if not ioc_guess and tds:
                ioc_guess = re.sub(r"\s+", " ", tds[0].get_text(" ", strip=True)).strip()

            out.append(
                {
                    "ioc": ioc_guess,
                    "show_path": show_path,
                    "show_url": show_url,
                }
            )

        return out

    def _click_next_listing(self, page) -> bool:
        """
        Try multiple selectors for Next.
        Return True if moved to next page.
        """
        next_candidates = [
            "a[rel='next']",
            "li.page-item.next a",
            "a[aria-label='Sonraki']",
            "button[aria-label='Sonraki']",
            "a:has-text('Next')",
            "button:has-text('Sonraki')",
            "a:has-text('›')",
            "a:has-text('»')",
        ]

        for sel in next_candidates:
            try:
                loc = page.locator(sel)
                if loc.count() == 0:
                    continue
                el = loc.first
                cls = (el.get_attribute("class") or "").lower()
                aria_disabled = (el.get_attribute("aria-disabled") or "").lower()
                if "disabled" in cls or aria_disabled == "true":
                    continue
                el.scroll_into_view_if_needed()
                el.click(timeout=15000)
                page.wait_for_load_state("domcontentloaded", timeout=60000)
                page.wait_for_timeout(800)
                return True
            except Exception:
                continue
        return False

    def _extract_detail(self, detail_page) -> Dict[str, str]:
        """
        Extract detail fields from /en/address/<id> page.
        """
        html = detail_page.content()
        soup = BeautifulSoup(html, "lxml")

        title_el = soup.select_one("h1.title")
        title = title_el.get_text(" ", strip=True) if title_el else ""

        category_el = soup.select_one("span.text-danger")
        category = category_el.get_text(" ", strip=True) if category_el else ""

        crit_el = soup.select_one("div.card.score h6")
        criticality = crit_el.get_text(" ", strip=True) if crit_el else ""
        criticality = re.sub(r"\s+", " ", criticality).strip()

        kv = self._extract_dt_dd_map(soup)

        # normalize common keys
        description = kv.get("Description", "")
        connection_type = kv.get("Connection Type", "")
        date_raw = kv.get("Date", "")
        source = kv.get("Source", "")

        kv_text = ""
        if kv:
            kv_text = "\n".join([f"{k}: {v}" for k, v in kv.items()])

        page_text = self._clean_text(html)

        return {
            "title": title,
            "category": category,
            "criticality": criticality,
            "description": description,
            "connection_type": connection_type,
            "date_raw": date_raw,
            "source": source,
            "kv_text": kv_text,
            "page_text": page_text,
        }

    # ---------------- main parse ----------------
    def parse_leak_data(self) -> dict:
        collected = 0
        visited_rows = 0

        max_pages = 15 if self.is_crawled else self._max_pages

        with sync_playwright() as p:
            # open seed with proxy fallback
            try:
                browser, context = self._launch_browser(p, use_proxy=True)
                page = context.new_page()
                print(f"[USOM] Opening seed (proxy): {self.seed_url}")
                page.goto(self.seed_url, timeout=60000, wait_until="domcontentloaded")
            except Exception as ex:
                print(f"[USOM] Proxy navigation failed: {ex}. Retrying without proxy …")
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
                print(f"[USOM] Opening seed (no proxy): {self.seed_url}")
                page.goto(self.seed_url, timeout=60000, wait_until="domcontentloaded")

            page.wait_for_load_state("networkidle")

            # -------- paginate listing and collect show urls --------
            all_items: List[Dict[str, str]] = []
            seen_show = set()

            current_page_no = 1
            while current_page_no <= max_pages:
                try:
                    page.wait_for_selector("table", timeout=20000)
                except Exception as ex:
                    log.g().e(f"[USOM] table not found: {ex}")
                    break

                rows = self._collect_show_rows(page)
                # dedupe
                new_count = 0
                for r in rows:
                    su = r.get("show_url") or ""
                    if su and su not in seen_show:
                        seen_show.add(su)
                        all_items.append(r)
                        new_count += 1

                print(f"[USOM] Page {current_page_no}: rows={len(rows)} (new={new_count}, total_unique={len(all_items)})")

                moved = self._click_next_listing(page)
                if not moved:
                    break

                current_page_no += 1

            # -------- open each show (NEW page) and extract --------
            for idx, item in enumerate(all_items, start=1):
                if self._max_rows and visited_rows >= self._max_rows:
                    print("[USOM] Max rows reached, stopping.")
                    break

                visited_rows += 1

                ioc_from_list = (item.get("ioc") or "").strip()
                show_url = (item.get("show_url") or "").strip()
                if not show_url:
                    continue

                detail_page = context.new_page()
                try:
                    detail_page.goto(show_url, timeout=60000, wait_until="domcontentloaded")
                    detail_page.wait_for_load_state("networkidle")

                    fields = self._extract_detail(detail_page)

                    # decide final ioc/title
                    title = (fields.get("title") or "").strip()
                    ioc_value = title or ioc_from_list or show_url

                    # leak_date from detail date
                    leak_date = self._parse_usom_date_to_dateobj(fields.get("date_raw", ""))

                    # tags / ioc types
                    tags = ["defacement", "usom"]
                    if fields.get("category"):
                        tags.append(fields["category"])

                    # build models
                    card = defacement_model(
                        m_url=ioc_value,
                        m_content=fields.get("page_text", "") or "",
                        m_base_url=self.base_url,
                        m_source_url=[show_url],
                        m_ioc_type=tags,
                        m_network=helper_method.get_network_type(self.base_url),
                        m_leak_date=leak_date,
                    )

                    # entity: keep it simple
                    ent = entity_model(
                        m_scrap_file=self.__class__.__name__,
                        m_team=(fields.get("source") or "").strip(),
                        m_ip=[],
                        m_weblink=[ioc_value] if ioc_value else [],
                        m_social_media_profiles=[],
                        m_external_scanners=[show_url],
                    )

                    self.append_leak_data(card, ent)

                    # AID
                    aid = self._make_aid(ioc_value, show_url, str(leak_date or ""))

                    # store raw (no json)
                    self._store_raw_card(aid, card, ent, fields, show_url)
                    collected += 1

                    # ✅ PRINT after each show (like you asked)
                    print("\n---------------------- USOM SHOW -----------------------")
                    print(f"#{idx}/{len(all_items)}")
                    print(f"AID: {aid}")
                    print(f"IOC/Title: {ioc_value}")
                    print(f"Show: {show_url}")
                    print(f"Category: {fields.get('category','')}")
                    print(f"Criticality: {fields.get('criticality','')}")
                    print(f"Description: {fields.get('description','')}")
                    print(f"Connection Type: {fields.get('connection_type','')}")
                    print(f"Date: {fields.get('date_raw','')}")
                    print(f"Source: {fields.get('source','')}")
                    print(f"Tags: {', '.join(tags)}")
                    print(f"Content Len: {len(fields.get('page_text','') or '')}")
                    print("--------------------------------------------------------\n")

                except Exception as ex:
                    log.g().e(f"[USOM] SCRIPT ERROR {ex} {_usom.__name__}")
                finally:
                    try:
                        detail_page.close()
                    except Exception:
                        pass

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
        print(f"[USOM] ✅ Done. Collected={collected}")
        return {
            "seed_url": self.seed_url,
            "items_collected": collected,
            "developer_signature": self.developer_signature(),
        }