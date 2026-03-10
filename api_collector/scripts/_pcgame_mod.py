import re
import asyncio
from abc import ABC
from typing import List, Dict, Optional, Tuple
from urllib.parse import quote_plus, urljoin

import requests
from bs4 import BeautifulSoup
from playwright.sync_api import BrowserContext  # keeping signature

from crawler.common.crawler_instance.local_interface_model.api.api_apk_model import apk_data_model
from crawler.common.crawler_instance.local_interface_model.api.api_collector_interface import api_collector_interface
from crawler.common.crawler_instance.local_shared_model.data_model.apk_model import apk_model
from crawler.common.crawler_instance.local_shared_model.data_model.entity_model import entity_model
from crawler.common.crawler_instance.local_shared_model import RuleModel, FetchProxy, FetchConfig, ThreatType


class _pcgame_mod(api_collector_interface, ABC):
    _instance = None

    PC_GAME_SITES = [
        {
            "name": "steam",
            "base_url": "https://store.steampowered.com",
            "search": "https://store.steampowered.com/search/?term={game}",
            "result_selector": "a.search_result_row[href]",
            "title_selector": "span.title",
        },
        {
            "name": "pcgamingwiki_search",
            "base_url": "https://www.pcgamingwiki.com",
            "search": "https://www.pcgamingwiki.com/w/index.php?search={game}&title=Special%3ASearch&fulltext=1",
            "result_selector": "div.mw-search-result-heading a[href], ul.mw-search-results li a[href]",
            "title_selector": None,
        },
        {
            "name": "pcgamingwiki_direct",
            "base_url": "https://www.pcgamingwiki.com",
            "type": "wiki_direct",
            "search": "https://www.pcgamingwiki.com/wiki/{slug}",
        },
    ]

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_pcgame_mod, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, developer_name: str = "Muhammad Abdullah", developer_note: str = ""):
        if getattr(self, "_initialized", False):
            return
        self._initialized = True

        self._developer_name = developer_name
        self._developer_note = developer_note

        self._apk_data: List[apk_model] = []
        self._entity_data: List[entity_model] = []
        self._is_crawled: bool = False

        self._proxy: Dict = {}
        self._max_items: Optional[int] = 100
        self._per_site_limit: int = 20   # ✅ so 1 site doesn't consume all results
        self._detail_timeout: int = 25

        self._last_query: Dict = {}
        self.callback = None

        self._session = requests.Session()
        self._session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                              "(KHTML, like Gecko) Chrome/120 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }
        )

        print("[API] _pcgame_mod Initialized ✅ (Steam + PCGamingWiki)")

    # ---------------- interface required ----------------
    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "pcgame://legal-search"

    @property
    def base_url(self) -> str:
        return "https://store.steampowered.com/"

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_threat_type=ThreatType.API,
            m_fetch_proxy=FetchProxy.NONE,
            m_fetch_config=FetchConfig.REQUESTS,
            m_resoource_block=False,
        )

    @property
    def apk_data(self) -> List[apk_model]:
        return self._apk_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def init_callback(self, callback=None):
        self.callback = callback
        print("[API] Callback set")

    def set_proxy(self, proxy: dict):
        self._proxy = proxy or {}
        print(f"[API] Proxy configured: {self._proxy}")

        server = (self._proxy or {}).get("server")
        if server and not str(server).lower().startswith("socks"):
            self._session.proxies.update({"http": server, "https": server})

    def set_limits(self, max_pages: Optional[int] = None, max_items: Optional[int] = None):
        if max_items is not None and max_items >= 1:
            self._max_items = int(max_items)
        print(f"[API] Limits → items={self._max_items or '∞'}")

    def reset_cache(self):
        self._apk_data.clear()
        self._entity_data.clear()
        self._is_crawled = False
        self._last_query = {}
        print("[API] Reset cache ✅")

    def developer_signature(self) -> str:
        return f"{self._developer_name}:{self._developer_note}".strip(":")

    def contact_page(self) -> str:
        return "https://store.steampowered.com/about/"

    # ---------------- helpers ----------------
    @staticmethod
    def _slugify_pkg(url: str) -> str:
        return re.sub(r"[^a-zA-Z0-9\-_\.]", "-", url or "")[:200]

    @staticmethod
    def _page_title(html: str) -> str:
        try:
            soup = BeautifulSoup(html, "html.parser")
            t = soup.select_one("title")
            return t.get_text(" ", strip=True) if t else ""
        except Exception:
            return ""

    def _get_html(self, url: str, timeout: int = 25) -> str:
        try:
            r = self._session.get(url, timeout=timeout, allow_redirects=True)
            r.encoding = r.apparent_encoding or r.encoding
            return r.text or ""
        except Exception:
            return ""

    def _pcgw_slug(self, name: str) -> str:
        n = (name or "").strip().lower()
        aliases = {
            "gta v": "Grand_Theft_Auto_V",
            "gta 5": "Grand_Theft_Auto_V",
            "grand theft auto v": "Grand_Theft_Auto_V",
        }
        if n in aliases:
            return aliases[n]
        cleaned = re.sub(r"\s+", " ", (name or "").strip())
        return cleaned.replace(" ", "_")

    def _build_search_url(self, site: Dict, game_name: str) -> str:
        tpl = site.get("search", "")
        if "{slug}" in tpl:
            return tpl.format(slug=self._pcgw_slug(game_name), game=quote_plus(game_name))
        return tpl.format(game=quote_plus(game_name))

    def _search_site(self, site: Dict, game_name: str) -> List[Tuple[str, str]]:
        search_url = self._build_search_url(site, game_name)
        html = self._get_html(search_url)
        if not html:
            print(f"[API] [{site['name']}] ❌ empty HTML")
            return []

        # PCGW may return Cloudflare page
        pt = self._page_title(html)
        if "Just a moment" in pt:
            print(f"[API] [{site['name']}] ⚠ Cloudflare page detected: title='{pt}' len={len(html)}")
            return []

        soup = BeautifulSoup(html, "html.parser")
        results: List[Tuple[str, str]] = []
        seen = set()

        sel = site.get("result_selector")
        if not sel:
            return []

        for a in soup.select(sel):
            href = (a.get("href") or "").strip()
            if not href:
                continue

            if href.startswith("/"):
                href = urljoin(site["base_url"], href)

            title_sel = site.get("title_selector")
            if title_sel:
                t_el = a.select_one(title_sel)
                title = t_el.get_text(" ", strip=True) if t_el else ""
            else:
                title = a.get_text(" ", strip=True)

            title = (title or "").strip()
            if not title:
                continue

            key = (title.lower(), href)
            if key in seen:
                continue
            seen.add(key)

            results.append((title, href))
            if len(results) >= self._per_site_limit:
                break

        return results

    # ---------------- DETAIL EXTRACTION ----------------
    def _extract_steam_details(self, url: str) -> Dict:
        """
        Steam app page se details nikalta hai
        """
        html = self._get_html(url, timeout=self._detail_timeout)
        if not html:
            return {}

        soup = BeautifulSoup(html, "html.parser")

        def txt(sel: str) -> str:
            el = soup.select_one(sel)
            return el.get_text(" ", strip=True) if el else ""

        name = txt("#appHubAppName") or txt("h1")
        short_desc = ""
        mdesc = soup.select_one("meta[name='description']")
        if mdesc and mdesc.get("content"):
            short_desc = str(mdesc.get("content")).strip()

        release_date = txt(".release_date .date")
        dev = ", ".join([a.get_text(" ", strip=True) for a in soup.select("#developers_list a") if a.get_text(strip=True)])
        pub = ""
        # publisher block (best effort)
        dev_rows = soup.select(".dev_row")
        for row in dev_rows:
            label = row.select_one(".subtitle")
            if label and "publisher" in label.get_text(" ", strip=True).lower():
                pub = ", ".join([a.get_text(" ", strip=True) for a in row.select("a") if a.get_text(strip=True)])
                break

        genres = [a.get_text(" ", strip=True) for a in soup.select("a[href*='genre']") if a.get_text(strip=True)]
        tags = [a.get_text(" ", strip=True) for a in soup.select("a.app_tag") if a.get_text(strip=True)]

        # requirements
        req_min = txt(".game_page_autocollapse.sys_req .sysreq_contents .game_area_sys_req_leftCol")
        req_rec = txt(".game_page_autocollapse.sys_req .sysreq_contents .game_area_sys_req_rightCol")

        # images
        screenshots = []
        for img in soup.select("img[src]"):
            src = (img.get("src") or "").strip()
            if src and ("steamuserimages" in src or "akamai" in src or "cloudfront" in src):
                if src.lower().endswith((".jpg", ".jpeg", ".png", ".webp")) and src not in screenshots:
                    screenshots.append(src)
            if len(screenshots) >= 10:
                break

        game_type = "game"
        # Steam sometimes labels "dlc", "music", etc in breadcrumbs / type in scripts; best-effort:
        if "/dlc/" in url:
            game_type = "dlc"

        return {
            "name": name,
            "type": game_type,
            "description": short_desc,
            "release_date": release_date,
            "developer": dev,
            "publisher": pub,
            "genres": list(dict.fromkeys(genres))[:10],
            "tags": list(dict.fromkeys(tags))[:20],
            "requirements_min": req_min,
            "requirements_rec": req_rec,
            "screenshots": screenshots[:10],
        }

    def _extract_pcgamingwiki_details(self, url: str) -> Dict:
        """
        PCGamingWiki page se basic details (best effort)
        """
        html = self._get_html(url, timeout=self._detail_timeout)
        if not html:
            return {}

        pt = self._page_title(html)
        if "Just a moment" in pt:
            return {"blocked": True, "title": pt}

        soup = BeautifulSoup(html, "html.parser")

        title = ""
        h1 = soup.select_one("#firstHeading")
        if h1:
            title = h1.get_text(" ", strip=True)

        intro = ""
        p = soup.select_one("#mw-content-text p")
        if p:
            intro = p.get_text(" ", strip=True)

        return {
            "title": title,
            "intro": intro[:600],
        }

    def _print_dict(self, label: str, d: Dict):
        print("\n" + "-" * 85)
        print(f"[DETAIL] {label}")
        for k, v in d.items():
            if v is None or v == "" or v == [] or v == {}:
                continue
            if isinstance(v, str) and len(v) > 900:
                v = v[:900] + " ... (trimmed)"
            print(f"  - {k}: {v}")
        print("-" * 85 + "\n")

    # ---------------- REQUIRED by your runner ----------------
    async def parse_leak_data(self, query: Dict, context: BrowserContext):
        if not isinstance(query, dict):
            return None

        name = (query.get("name") or "").strip()
        if not name:
            return None

        self._last_query = dict(query)
        self._apk_data.clear()
        self._entity_data.clear()
        self._is_crawled = False

        print(f"[API] Searching '{name}' on {len(self.PC_GAME_SITES)} sites ...")

        total_added = 0
        seen_urls = set()

        for site in self.PC_GAME_SITES:
            site_name = site["name"]
            search_url = self._build_search_url(site, name)
            print(f"[API] [{site_name}] search: {search_url}")

            # direct wiki mode -> build direct url and treat as 1 candidate
            if site.get("type") == "wiki_direct":
                direct_url = search_url
                items = [(self._pcgw_slug(name).replace("_", " "), direct_url)]
            else:
                items = self._search_site(site, name)

            print(f"[API] [{site_name}] found: {len(items)}")

            for title, url in items:
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                # ✅ DETAIL FETCH
                details = {}
                if site_name == "steam":
                    details = self._extract_steam_details(url)
                    self._print_dict(f"STEAM DETAILS for: {title}", details)
                elif "pcgamingwiki" in site_name:
                    details = self._extract_pcgamingwiki_details(url)
                    self._print_dict(f"PCGW DETAILS for: {title}", details)

                # ✅ CARD BUILD
                card = apk_model()
                setattr(card, "m_app_name", details.get("name") or details.get("title") or title)
                setattr(card, "m_app_url", url)
                setattr(card, "m_package_id", self._slugify_pkg(url))
                setattr(card, "m_mod_features", "")
                setattr(card, "m_network", "clearnet")
                setattr(card, "m_version", "")
                setattr(card, "m_content_type", ["pc_game"])

                # best effort dates
                setattr(card, "m_latest_date", details.get("release_date") or "")

                # description
                setattr(card, "m_description", details.get("description") or details.get("intro") or "")

                # extra: store everything
                extra = {"source": site_name, "search_url": search_url, "details": details}
                setattr(card, "m_extra", extra)

                self._apk_data.append(card)
                total_added += 1

                print(f"[API] ✅ Added: {getattr(card, 'm_app_name', '')[:80]} | {url} | source={site_name}")

                if self._max_items and total_added >= self._max_items:
                    break

            if self._max_items and total_added >= self._max_items:
                break

        model = apk_data_model()
        setattr(model, "base_url", self.base_url)
        setattr(model, "content_type", ["pc_game"])
        setattr(model, "cards_data", self.apk_data)

        self._is_crawled = True
        print(f"[API] Done ✅ Total items={len(self._apk_data)}")
        return model

    def run(self) -> dict:
        q = self._last_query or {"name": "GTA V"}
        try:
            result = asyncio.run(self.parse_leak_data(query=q, context=None))
            count = len(getattr(result, "cards_data", []) or []) if result else 0
        except Exception as e:
            print("[API] run() failed:", e)
            count = 0

        return {"seed_url": self.seed_url, "items_collected": count, "developer_signature": self.developer_signature()}
