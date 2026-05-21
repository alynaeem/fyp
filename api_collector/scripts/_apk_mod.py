import re
from datetime import datetime
from abc import ABC
from typing import List, Dict, Optional
from difflib import SequenceMatcher
from urllib.parse import urljoin, urlparse, parse_qs, quote_plus, unquote
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
                "results": "a.block.p-2.relative",
                "result_title": "h3",
                "details_title": "h1",
                "last_update": "span.date-news",
                "content": "div.body-content",
                "pkg_anchor": "a[href*='play.google.com']",
                "pkg_id": "a[href*='play.google.com']",
                "publisher": "span.body-2 a[rel='tag']",
                "size": "div.info-block:has-text('Size') span.body-2",
                "version": "div.info-block:has-text('Version') span.body-2",
                "mod": "div.body-content p",
                "download": "a.download-button",
            },
        },
        {
            "name": "getmodsapk",
            "base_url": "https://getmodsapk.com",
            "search": "https://getmodsapk.com/search?query={apk_name}",
            "selectors": {
                "results": "a.bg-white",
                "result_title": "h3",
                "details_title": "h1",
                "version": "div.info-grid-card-custom:nth-of-type(2) p.font-bold",
                "last_update": "div.flex.items-center.dark\\:text-gray-300",
                "publisher": "div.info-grid-card-custom:nth-of-type(4) p.font-bold",
                "size": "div.info-grid-card-custom:nth-of-type(7) p.font-bold",
                "pkg_anchor": "div.info-grid-card-custom:nth-of-type(8) a",
                "mod": "div.pl-8.pb-3.prose ul",
                "content": "div.post-content",
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
            return re.sub(r"\s+", " ", text).strip()

        a_clean = clean(a)
        b_clean = clean(b)
        a_flat = a_clean.replace(" ", "")
        b_flat = b_clean.replace(" ", "")

        if a_clean == b_clean or (a_flat and a_flat == b_flat):
            return 1.0
        if a_flat and a_flat in b_flat:
            return 0.98

        return max(
            SequenceMatcher(None, a_clean, b_clean).ratio(),
            SequenceMatcher(None, a_flat, b_flat).ratio(),
        )

    @staticmethod
    def _normalize_lookup_text(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "", (value or "").lower())

    @staticmethod
    def _same_site_url(site_base_url: str, candidate_url: str) -> bool:
        site_host = urlparse(site_base_url or "").netloc.lower().replace("www.", "")
        candidate_host = urlparse(candidate_url or "").netloc.lower().replace("www.", "")
        if not site_host or not candidate_host:
            return True
        return candidate_host == site_host or candidate_host.endswith(f".{site_host}")

    @staticmethod
    def _parse_playstore_input(value: str) -> tuple[str, str]:
        text = str(value or "").strip()
        if not text:
            return "", ""

        if text.startswith("http://") or text.startswith("https://") or "play.google.com" in text:
            parsed = urlparse(text)
            pkg_name = parse_qs(parsed.query).get("id", [""])[0].strip()
            return text, pkg_name

        if re.match(r"^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)+$", text):
            return f"https://play.google.com/store/apps/details?id={text}", text

        return "", ""

    @staticmethod
    def _humanize_package_name(pkg_name: str) -> str:
        if not pkg_name:
            return ""
        last = pkg_name.split(".")[-1].strip()
        if not last:
            return ""
        last = re.sub(r"([a-z])([A-Z])", r"\1 \2", last)
        last = last.replace("_", " ").replace("-", " ")
        common_compounds = {
            "clashofclans": "Clash of Clans",
            "subwaysurf": "Subway Surf",
            "subwaysurfers": "Subway Surfers",
            "candycrushsaga": "Candy Crush Saga",
            "freefiremax": "Free Fire Max",
        }
        lowered = last.replace(" ", "").lower()
        if lowered in common_compounds:
            return common_compounds[lowered]
        return " ".join(part.capitalize() for part in last.split())

    async def _first_text(self, page, selectors: List[str]) -> str:
        for selector in selectors:
            try:
                el = await page.query_selector(selector)
                if not el:
                    continue
                text = (await el.inner_text()).strip()
                if text:
                    return text
            except Exception:
                continue
        return ""

    async def _first_attr(self, page, selectors: List[str], attr: str) -> str:
        for selector in selectors:
            try:
                el = await page.query_selector(selector)
                if not el:
                    continue
                value = (await el.get_attribute(attr) or "").strip()
                if value:
                    return value
            except Exception:
                continue
        return ""

    async def _extract_playstore_app_name(self, page, pkg_name: str, fallback_value: str) -> str:
        title_text = ""
        try:
            title_text = (await page.title()).strip()
        except Exception:
            title_text = ""

        if title_text:
            title_text = re.sub(r"\s*-\s*Apps on Google Play\s*$", "", title_text, flags=re.I).strip()
            if title_text and "google play" not in title_text.lower():
                return title_text

        meta_title = await self._first_attr(
            page,
            [
                'meta[property="og:title"]',
                'meta[name="twitter:title"]',
                'meta[itemprop="name"]',
            ],
            "content",
        )
        if meta_title:
            meta_title = re.sub(r"\s*-\s*Apps on Google Play\s*$", "", meta_title, flags=re.I).strip()
            if meta_title and "google play" not in meta_title.lower():
                return meta_title

        heading = await self._first_text(
            page,
            [
                "h1 span",
                'h1[itemprop="name"]',
                '[itemprop="name"] span',
                "h1",
            ],
        )
        if heading:
            return heading

        try:
            html = await page.content()
        except Exception:
            html = ""

        if html:
            patterns = [
                r'"name":"([^"]+)"',
                r"<title>(.*?)</title>",
            ]
            for pattern in patterns:
                match = re.search(pattern, html, re.I | re.S)
                if not match:
                    continue
                candidate = unquote(match.group(1)).strip()
                candidate = re.sub(r"\s*-\s*Apps on Google Play\s*$", "", candidate, flags=re.I).strip()
                if candidate and "google play" not in candidate.lower():
                    return candidate

        return self._humanize_package_name(pkg_name) or fallback_value

    def _build_query_variants(self, app_name: str, pkg_name: str) -> List[str]:
        variants: List[str] = []

        def add(value: str):
            text = str(value or "").strip()
            if not text:
                return
            if text not in variants:
                variants.append(text)

        humanized_pkg = self._humanize_package_name(pkg_name)
        pkg_tail = pkg_name.split(".")[-1].strip() if pkg_name else ""

        add(app_name)
        add(humanized_pkg)
        add(pkg_tail)
        add(pkg_name)

        if humanized_pkg:
            add(f"{humanized_pkg} apk")
            add(f"{humanized_pkg} mod")
            add(f"{humanized_pkg} mod apk")

        return variants

    async def _collect_generic_anchor_matches(self, page, site, needles: List[str]) -> List[tuple[str, str]]:
        anchors = await page.query_selector_all("a[href]")
        collected: List[tuple[str, str]] = []
        seen = set()

        for anchor in anchors[:250]:
            try:
                href = (await anchor.get_attribute("href") or "").strip()
                if not href:
                    continue
                title = (await anchor.inner_text()).strip()
                if not title:
                    continue
                full_href = urljoin(site["base_url"], href)
                if not self._same_site_url(site["base_url"], full_href):
                    continue
                haystack = self._normalize_lookup_text(f"{title} {full_href}")
                if needles and not any(needle and needle in haystack for needle in needles):
                    continue
                if full_href in seen:
                    continue
                seen.add(full_href)
                collected.append((title, href))
            except Exception:
                continue

        return collected

    @staticmethod
    async def search_site(page, site, queries: List[str], pkg_name: str = ""):
        collected = []
        seen = set()
        result_selectors = site["selectors"].get("results") or []
        if isinstance(result_selectors, str):
            result_selectors = [result_selectors]
        title_selectors = site["selectors"].get("result_title") or []
        if isinstance(title_selectors, str):
            title_selectors = [title_selectors]

        needles = [
            _apk_mod._normalize_lookup_text(query)
            for query in [pkg_name, *(queries or [])]
            if str(query or "").strip()
        ]

        for query in queries or []:
            search_url = site["search"].format(apk_name=quote_plus(query))
            try:
                await page.goto(search_url, timeout=60000, wait_until="domcontentloaded")
                await page.wait_for_timeout(2500)
            except Exception:
                continue

            results = []
            for selector in result_selectors:
                try:
                    results = await page.query_selector_all(selector)
                except Exception:
                    results = []
                if results:
                    break

            if not results:
                generic_matches = await _apk_mod._collect_generic_anchor_matches(_apk_mod, page, site, needles)
                for title, href in generic_matches:
                    full_href = urljoin(site["base_url"], href)
                    if full_href in seen:
                        continue
                    seen.add(full_href)
                    collected.append((title.strip(), href))
                if collected:
                    break
                continue

            for r in results[:8]:
                title = ""
                for sel_title in title_selectors:
                    try:
                        title_el = await r.query_selector(sel_title)
                        if title_el:
                            title = (await title_el.inner_text()).strip()
                            if title:
                                break
                    except Exception:
                        continue
                if not title:
                    try:
                        title = (await r.inner_text()).strip()
                    except Exception:
                        title = ""

                href = ""
                try:
                    href = (await r.get_attribute("href") or "").strip()
                except Exception:
                    href = ""
                if not href:
                    try:
                        nested_anchor = await r.query_selector("a[href]")
                        href = (await nested_anchor.get_attribute("href") or "").strip() if nested_anchor else ""
                    except Exception:
                        href = ""

                if not href:
                    continue

                full_href = urljoin(site["base_url"], href)
                if not _apk_mod._same_site_url(site["base_url"], full_href):
                    continue
                haystack = _apk_mod._normalize_lookup_text(f"{title} {full_href}")
                if needles and not any(needle and needle in haystack for needle in needles):
                    continue
                if full_href in seen:
                    continue
                seen.add(full_href)
                collected.append((title.strip() or full_href, href))

            if collected:
                break

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
        await page.goto(full_url, timeout=60000, wait_until="domcontentloaded")
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

        if not meta.get("details_title"):
            try:
                page_title = (await page.title()).strip()
            except Exception:
                page_title = ""
            if page_title:
                meta["details_title"] = re.sub(r"\s*(MOD APK|APK|Download).*$", "", page_title, flags=re.I).strip() or page_title

        if not meta.get("content"):
            for selector in ["article", "main", ".entry-content", ".post-content", "body"]:
                try:
                    el = await page.query_selector(selector)
                    if not el:
                        continue
                    text = (await el.inner_text()).strip()
                    if text:
                        meta["content"] = text[:2000]
                        break
                except Exception:
                    continue

        if not meta.get("download"):
            for selector in [
                "a[href*='download']",
                "a[class*='download']",
                "a[href$='.apk']",
                "a[href$='.xapk']",
            ]:
                try:
                    el = await page.query_selector(selector)
                    if not el:
                        continue
                    href_value = (await el.get_attribute("href") or "").strip()
                    if href_value:
                        meta["download"] = urljoin(site["base_url"], href_value)
                        break
                except Exception:
                    continue

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

        url, pkg_name = self._parse_playstore_input(v)
        if not url:
            return apk_data_model(base_url=self.base_url, content_type=["cracked"])

        app_name = self._humanize_package_name(pkg_name) or v
        try:
            await page.goto(url, timeout=60000, wait_until="domcontentloaded")
            await page.wait_for_timeout(1500)
            extracted_name = await self._extract_playstore_app_name(page, pkg_name, v)
            if extracted_name:
                app_name = extracted_name
        except Exception:
            try:
                await page.close()
            except Exception:
                pass
            page = await context.new_page()

        query_variants = self._build_query_variants(app_name, pkg_name)

        all_best_results = []
        for site in self.APK_SITES:
            try:
                collected = await self.search_site(page, site, query_variants, pkg_name=pkg_name)

                best_site_result = None
                best_site_score = 0.0

                for title, href in collected:
                    score = max(self.similarity(candidate, title) for candidate in query_variants if candidate)
                    if pkg_name and pkg_name.lower() in href.lower():
                        score = max(score, 0.99)
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
            setattr(card_data, "m_apk_size", meta.get("size") or "")
            setattr(card_data, "m_source", site["name"])
            setattr(card_data, "m_publisher", meta.get("publisher") or "")
            setattr(card_data, "m_description", meta.get("content") or "")

            found_cards.append(card_data)
            self.append_apk_data(card_data)

        model = apk_data_model()
        setattr(model, "base_url", self.base_url)
        setattr(model, "content_type", ["cracked"])
        setattr(model, "cards_data", found_cards)
        return model
