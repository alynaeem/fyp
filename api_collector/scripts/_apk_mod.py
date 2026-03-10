import re
from datetime import datetime
from abc import ABC
from typing import List, Dict, Optional
from difflib import SequenceMatcher
from urllib.parse import urljoin
from playwright.async_api import BrowserContext

from crawler.common.crawler_instance.local_interface_model.api.api_apk_model import apk_data_model
from crawler.common.crawler_instance.local_interface_model.api.api_collector_interface import api_collector_interface
from crawler.common.crawler_instance.local_shared_model.data_model.apk_model import apk_model
from crawler.common.crawler_instance.local_shared_model.data_model.entity_model import entity_model
from crawler.common.crawler_instance.local_shared_model import RuleModel, FetchProxy, FetchConfig, ThreatType


class _apk_mod(api_collector_interface, ABC):
    """
    Playstore URL -> get app name -> search multiple APK sites -> extract metadata -> return apk_data_model
    NOTE: Implements required api_collector_interface abstract methods so it can be instantiated.
    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_apk_mod, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if getattr(self, "_initialized", False):
            return
        self._initialized = True

        self._apk_data: List[apk_model] = []
        self._entity_data: List[entity_model] = []
        self._is_crawled: bool = False
        self._last_query: Dict = {}

        self._proxy: Dict = {}
        self._max_pages: int = 1
        self._max_items: Optional[int] = 10
        self.callback = None

    # =============================
    # Required interface properties
    # =============================

    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "playstore://apk-mod-search"

    @property
    def base_url(self) -> str:
        return "https://www.example.com/"

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_fetch_proxy=FetchProxy.NONE,
            m_resoource_block=True,
            m_javascript=False,
            m_fetch_config=FetchConfig.PLAYRIGHT,
            m_threat_type=ThreatType.API,
        )

    @property
    def apk_data(self) -> List[apk_model]:
        return self._apk_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    # =============================
    # Required interface methods
    # =============================

    def init_callback(self, callback=None):
        self.callback = callback

    def set_proxy(self, proxy: dict):
        self._proxy = proxy or {}

    def set_limits(self, max_pages: Optional[int] = None, max_items: Optional[int] = None):
        if max_pages is not None and int(max_pages) >= 1:
            self._max_pages = int(max_pages)
        if max_items is not None and int(max_items) >= 1:
            self._max_items = int(max_items)

    def reset_cache(self):
        self._apk_data.clear()
        self._entity_data.clear()
        self._is_crawled = False
        self._last_query = {}

    def developer_signature(self) -> str:
        return "Muhammad Abdullah"

    def contact_page(self) -> str:
        return "https://github.com/contact"

    def run(self) -> dict:
        """
        Sync wrapper (optional). Your framework might call this.
        """
        q = self._last_query or {}
        try:
            # Can't create BrowserContext here because framework usually provides it.
            # So return minimal info.
            return {
                "seed_url": self.seed_url,
                "items_collected": len(self._apk_data),
                "developer_signature": self.developer_signature(),
                "note": "Use parse_leak_data(query, context) with Playwright context.",
                "last_query": q,
            }
        except Exception as e:
            return {"seed_url": self.seed_url, "items_collected": 0, "error": str(e)}

    # =============================
    # Scraper config
    # =============================

    APK_SITES = [
        {
            "name": "9mod",
            "base_url": "https://9mod.com",
            "search": "https://9mod.com/?s={apk_name}",
            "selectors": {
                "results": "a.link-title",
                "result_title": "h2.body-2",
                "details_title": "h1",
                "last_update": "span.date-news",
                "content": "div.body-2.blockreadmore.body-content.readmore-section.readmore-collapsed",
                "pkg_anchor": "a.body-2.text-truncate",
                "pkg_id": "a.body-2.text-truncate",
                "publisher": "span.body-2 a[rel='tag']",
                "size": "div.info-block.scora:has(span.gray:has-text('Size')) >> span.body-2:not(.gray)",
                "version": "div.info-block.scora:has(span.gray:has-text('Version')) >> span.body-2:not(.gray)",
                "mod": "span.body-2 p",
                "download": "a.download-button",
            },
        },
        {
            "name": "getmodsapk",
            "base_url": "https://getmodsapk.com",
            "search": "https://getmodsapk.com/search?query={apk_name}",
            "selectors": {
                "results": "a.bg-white",
                "result_title": "h3.font-semibold",
                "details_title": "h1.text-2xl",
                "version": "div.info-grid-card-custom:nth-of-type(2) p.text-sm.md\\:text-xl.font-bold",
                "last_update": "div.flex.items-center.dark\\:text-gray-300",
                "publisher": "div.info-grid-card-custom:nth-of-type(4) p.text-sm.md\\:text-xl.font-bold",
                "size": "div.info-grid-card-custom:nth-of-type(7) p.text-sm.md\\:text-xl.font-bold",
                "pkg_anchor": "div.info-grid-card-custom:nth-of-type(8) a",
                "mod": "div.pl-8.pb-3.prose ul",
                "content": "div.post-content.text-gray-900",
                "download": "a[href*='/download']",
            },
        },
        {
            "name": "apkpure",
            "base_url": "https://apkpure.com",
            "search": "https://apkpure.com/search?q={apk_name}",
            "selectors": {
                "results": "a[data-dt-recid]",
                "result_title": "p.p1",
                "details_title": "h1",
                "version": "span.version.one-line",
                "last_update": "li:has-text('Update date') div.head",
                "pkg_anchor": "div.additional-item:has-text('Available on') a.value.ga",
                "publisher": "a.developer.one-line",
                "download": "a.btn.normal-download-btn.da.dt-main-download-btn",
                "size": "a.btn.normal-download-btn.da.dt-main-download-btn",
                "content": "div.show-more",
            },
        },
        {
            "name": "filecr",
            "base_url": "https://filecr.com",
            "search": "https://filecr.com/search/?q={apk_name}",
            "selectors": {
                "results": "a.card_title__az7G7",
                "result_title": "a.card_title__az7G7",
                "details_title": 'div.info_item__0IxQW:has-text("File name") span.info_data__N609l',
                "publisher": 'div.info_item__0IxQW:has-text("Created by") span.info_data__N609l a',
                "pkg_anchor": 'div.info_item__0IxQW:has-text("Google Play") span.info_data__N609l a',
                "version": 'div.info_item__0IxQW:has-text("Version") span.info_data__N609l',
                "last_update": 'div.info_item__0IxQW:has-text("Release Date") span.info_data__N609l',
                "mod": "span.info_data__N609l.info_green__1WTdc",
                "size": "div.download-size",
                "content": "article.article",
            },
        },
        {
            "name": "apkcombo",
            "base_url": "https://apkcombo.com",
            "search": "https://apkcombo.com/search/{apk_name}/",
            "selectors": {
                "results": "a.l_item",
                "result_title": "span.name",
                "details_title": "h1 a[title]",
                # NOTE: these look like XPath, but your code uses query_selector (CSS).
                # Keep them if you later switch to page.query_selector("xpath=...").
                "publisher": "div.item:has-text('Developer') div.value",
                "version": "div.item:has-text('Version') div.value",
                "last_update": "div.item:has-text('Update') div.value",
                "pkg_anchor": "div.item:has-text('Google Play ID') div.value a.is-link",
                "pkg_id": "div.item:has-text('Google Play ID') div.value a.is-link",
                "download": "a.button.is-success.is-fullwidth",
                "size": "span.fsize span",
                "content": "div.text-description.ton",
            },
        },
    ]

    # =============================
    # Core scraping logic
    # =============================

    def append_apk_data(self, apk: apk_model):
        self._apk_data.append(apk)

    @staticmethod
    def similarity(a: str, b: str) -> float:
        def clean(text: str) -> str:
            text = text.lower()
            text = re.sub(r"\bv?\d+(\.\d+)*\b", "", text)
            text = re.sub(r"\bmod( apk)?\b", "", text)
            text = re.sub(r"[^a-z0-9\s]", "", text)
            return text.strip()

        a_clean = clean(a)
        b_clean = clean(b)

        if a_clean == b_clean:
            return 1.0
        if a_clean and a_clean in b_clean:
            return 0.95

        return SequenceMatcher(None, a_clean, b_clean).ratio()

    @staticmethod
    async def search_site(page, site, app_name: str):
        search_url = site["search"].format(apk_name=app_name.replace(" ", "+").lower())
        await page.goto(search_url, timeout=60000)

        results = await page.query_selector_all(site["selectors"]["results"])
        collected = []

        for r in results[:5]:
            sel_title = site["selectors"].get("result_title")
            if sel_title:
                title_el = await r.query_selector(sel_title)
                title = await title_el.inner_text() if title_el else await r.inner_text()
            else:
                title = await r.inner_text()

            href = await r.get_attribute("href")
            if href:
                collected.append((title.strip(), href))

        return collected

    @staticmethod
    def parse_date(date_str: str) -> Optional[str]:
        if not date_str:
            return None
        match = re.search(r"([A-Za-z]{3,9} \d{1,2}, \d{4})", date_str)
        if not match:
            return None
        date_str = match.group(1)

        formats = ["%B %d, %Y", "%d %B %Y", "%b %d, %Y", "%Y-%m-%d"]
        for fmt in formats:
            try:
                dt = datetime.strptime(date_str.strip(), fmt)
                return dt.strftime("%Y-%m-%d")
            except ValueError:
                continue
        return None

    async def extract_metadata(self, page, site, href: str) -> Dict:
        full_url = urljoin(site["base_url"], href)
        await page.goto(full_url, timeout=60000)
        meta: Dict = {}

        for key, selector in site["selectors"].items():
            if key in ["results", "result_title"]:
                continue
            try:
                el = await page.query_selector(selector)
                if not el:
                    continue

                if key in ["pkg_anchor", "download", "pkg_id"]:
                    dwnld_href = await el.get_attribute("href")
                    if dwnld_href:
                        meta[key] = urljoin(site["base_url"], dwnld_href)
                elif key == "last_update":
                    raw_date = await el.inner_text()
                    meta[key] = self.parse_date(raw_date)
                else:
                    meta[key] = (await el.inner_text()).strip()

            except Exception:
                continue

        meta["url"] = full_url

        # pkg_id fallback
        m_pkg_id = meta.get("pkg_id")
        if not m_pkg_id or not str(m_pkg_id).strip():
            url = meta.get("pkg_anchor", "") or ""
            match = re.search(r"[?&]id=([^&]+)", url)
            m_pkg_id = match.group(1).strip() if match and match.group(1) else None
        meta["pkg_id"] = m_pkg_id

        return meta

    async def parse_leak_data(self, query: Dict, context: BrowserContext):
        """
        query = {"playstore": "<playstore url or package id>"}
        """
        self._last_query = dict(query or {})
        self._is_crawled = False

        await context.route(
            "**/*",
            lambda route: route.abort()
            if route.request.resource_type in {
                "image", "media", "font", "stylesheet", "texttrack", "video", "audio"
            }
            else route.continue_()
        )

        page = await context.new_page()

        # parse playstore input
        v = str((query or {}).get("playstore", "")).strip()
        if not v:
            return apk_data_model(base_url=self.base_url, content_type=["cracked"])

        if v.startswith("http://") or v.startswith("https://") or "play.google.com" in v:
            url = v
            m = re.search(r"id=([a-zA-Z0-9._-]+)", v)
            pkg_name = m.group(1) if m else ""
        elif re.match(r"^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)+$", v):
            pkg_name = v
            url = f"https://play.google.com/store/apps/details?id={v}"
        else:
            return apk_data_model(base_url=self.base_url, content_type=["cracked"])

        await page.goto(url, timeout=60000)
        app_name = await page.inner_text("h1 span[itemprop='name']", timeout=60000)

        all_best_results = []
        for site in self.APK_SITES:
            try:
                collected = await self.search_site(page, site, app_name)

                best_site_result = None
                best_site_score = 0.0

                for title, href in collected:
                    score = self.similarity(app_name, title)
                    if score > best_site_score:
                        best_site_score = score
                        best_site_result = (site, title, href, score)

                if best_site_result:
                    all_best_results.append(best_site_result)

            except Exception:
                continue

        found_cards: List[apk_model] = []
        for site, title, href, score in all_best_results[: (self._max_items or 10)]:
            try:
                meta = await self.extract_metadata(page, site, href)
            except Exception:
                continue

            card_data = apk_model()

            setattr(card_data, "m_app_name", meta.get("details_title", title))
            setattr(card_data, "m_app_url", meta.get("url") or "")
            setattr(card_data, "m_package_id", meta.get("pkg_id") or pkg_name)
            setattr(card_data, "m_mod_features", meta.get("mod") or "")
            setattr(card_data, "m_network", "clearnet")
            setattr(card_data, "m_version", meta.get("version") or "")
            setattr(card_data, "m_download_link", [meta.get("download")] if meta.get("download") else [])
            setattr(card_data, "m_content_type", ["apk"])
            setattr(card_data, "m_latest_date", str(meta.get("last_update") or ""))

            found_cards.append(card_data)
            self.append_apk_data(card_data)

        model = apk_data_model()
        setattr(model, "base_url", self.base_url)
        setattr(model, "content_type", ["cracked"])
        setattr(model, "cards_data", found_cards)
        return model

