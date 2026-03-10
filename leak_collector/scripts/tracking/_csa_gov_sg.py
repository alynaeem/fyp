import re
import json
import hashlib
import requests

from abc import ABC
from datetime import datetime, timezone
from typing import List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

from crawler.common.crawler_instance.local_interface_model.leak.leak_extractor_interface import leak_extractor_interface
from crawler.common.crawler_instance.local_shared_model.data_model import entity_model
from crawler.common.crawler_instance.local_shared_model.data_model import leak_model
from crawler.common.crawler_instance.local_shared_model import RuleModel, FetchProxy, FetchConfig, ThreatType
from crawler.common.crawler_instance.crawler_services.redis_manager.redis_controller import redis_controller
from crawler.common.crawler_instance.crawler_services.shared.helper_method import helper_method


class _csa_gov_sg(leak_extractor_interface, ABC):
    _instance = None

    # ---------------- singleton ----------------
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_csa_gov_sg, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, developer_name: str = "Anonymous", developer_note: str = ""):
        if getattr(self, "_initialized", False):
            return
        self._initialized = True

        self._card_data: List[leak_model] = []
        self._entity_data: List[entity_model] = []

        self._redis = redis_controller()
        self._is_crawled = False

        self._proxy: dict = {}
        self.callback = None

        self._developer_name = developer_name
        self._developer_note = developer_note

        # crawling limits
        self._max_pages: int = 20
        self._max_articles: Optional[int] = None

        # first crawl rules (best-effort; CSA content is often recent)
        self._first_crawl_min_year = 2023
        self._next_crawl_min_year = 2024

        # Redis master indexes (pipe-delimited strings, NOT JSON)
        self._raw_index_key = "CSA:raw_index"
        self._json_index_key = "CSA:json_index"

        # keep your fixed signature exactly as provided (old script)
        self._fixed_signature = (
            "Muhammad Marij Younas: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9UyN"
        )

        print("[CSA.GOV.SG] Initialized ✅ (requests + Redis indexing)")

    # ---------------- interface hooks ----------------
    def init_callback(self, callback=None):
        self.callback = callback
        print("[CSA.GOV.SG] Callback set")

    def set_proxy(self, proxy: dict):
        self._proxy = proxy or {}
        print(f"[CSA.GOV.SG] Proxy configured: {self._proxy}")

    def set_limits(self, max_pages: Optional[int] = None, max_articles: Optional[int] = None):
        if max_pages is not None and max_pages >= 1:
            self._max_pages = int(max_pages)
        if max_articles is not None and max_articles >= 1:
            self._max_articles = int(max_articles)
        print(f"[CSA.GOV.SG] Limits → pages={self._max_pages}, articles={self._max_articles or '∞'}")

    def reset_cache(self):
        # keep a small marker key, but do not depend on it
        self._redis_set("CSA:last_crawl", "", 60)

    # ---------------- required properties ----------------
    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "https://www.csa.gov.sg/alerts-and-advisories/"

    @property
    def base_url(self) -> str:
        return "https://www.csa.gov.sg/"

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_fetch_proxy=FetchProxy.NONE,
            m_fetch_config=FetchConfig.REQUESTS,
            m_threat_type=ThreatType.TRACKING,
            m_resoource_block=False,
        )

    @property
    def card_data(self) -> List[leak_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    @property
    def developer_signature(self) -> str:
        return self._fixed_signature

    def contact_page(self) -> str:
        return "https://www.csa.gov.sg/contact-us/"

    # ---------------- Redis helpers ----------------
    def _redis_get(self, key: str, default: str = "") -> str:
        try:
            val = self._redis.invoke_trigger(1, [key, default, None])
            if val is None:
                return default
            return str(val)
        except Exception:
            return default

    def _redis_set(self, key: str, value: object, expiry: Optional[int] = None):
        val = "" if value is None else str(value)
        self._redis.invoke_trigger(2, [key, val, expiry])

    def _append_index(self, index_key: str, item_id: str):
        cur = self._redis_get(index_key, "")
        parts = [p for p in cur.split("|") if p] if cur else []
        if item_id not in parts:
            parts.append(item_id)
            self._redis_set(index_key, "|".join(parts), expiry=None)

    @staticmethod
    def _sha1(text: str) -> str:
        return hashlib.sha1(text.encode("utf-8")).hexdigest()

    @staticmethod
    def _date_to_string(d) -> str:
        if d is None:
            return ""
        if isinstance(d, datetime):
            return d.strftime("%Y-%m-%d")
        try:
            return d.strftime("%Y-%m-%d")
        except Exception:
            return str(d)

    # ---------------- HTTP session ----------------
    def _make_requests_session(self, use_proxy: bool = True) -> requests.Session:
        s = requests.Session()
        s.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Referer": self.base_url,
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
            }
        )

        if use_proxy:
            server = (self._proxy or {}).get("server")
            if server:
                s.proxies.update({"http": server, "https": server})
                print(f"[CSA.GOV.SG] requests will use proxy: {server}")

        return s

    # ---------------- Playwright fallback ----------------
    def _fetch_with_playwright(self, url: str, use_proxy: bool) -> str:
        proxy_server = (self._proxy or {}).get("server") if use_proxy else None

        with sync_playwright() as p:
            launch_kwargs = {"headless": True}
            if proxy_server:
                launch_kwargs["proxy"] = {"server": proxy_server}

            browser = p.chromium.launch(**launch_kwargs)
            context = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
                ),
                locale="en-US",
            )
            page = context.new_page()
            page.goto(url, timeout=60000, wait_until="load")
            html = page.content()

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

            return html

    # ---------------- parsing helpers ----------------
    @staticmethod
    def _clean_text(s: str) -> str:
        return re.sub(r"\s+", " ", (s or "")).strip()

    def _normalize_url(self, u: str) -> str:
        if not u:
            return u
        u = u.strip()
        if u.startswith("//"):
            u = "https:" + u
        if u.startswith("/"):
            u = urljoin(self.base_url, u)
        return u

    def _looks_like_article_url(self, u: str) -> bool:
        if not u:
            return False
        try:
            pu = urlparse(u)
        except Exception:
            return False

        if not pu.netloc:
            return False

        if "csa.gov.sg" not in pu.netloc:
            return False

        # keep only alerts/advisories detail pages
        return "/alerts-and-advisories/" in pu.path.rstrip("/") and not pu.path.rstrip("/").endswith("/alerts-and-advisories")

    def _index_url_for_page(self, page_no: int) -> str:
        """
        CSA site pagination behavior can be dynamic. We still provide a deterministic fallback:
        /alerts-and-advisories/?page=N
        If it doesn't work, we will stop when no new links are discovered.
        """
        if page_no <= 1:
            return self.seed_url
        return f"{self.seed_url.rstrip('/')}/?page={page_no}"

    def _extract_article_links_from_index_html(self, html: str) -> Set[str]:
        soup = BeautifulSoup(html, "html.parser")
        urls: Set[str] = set()

        # primary selector from your old script
        for a in soup.select('a.outline.outline-offset-2.outline-link[href]'):
            href = self._normalize_url(a.get("href", ""))
            if self._looks_like_article_url(href):
                urls.add(href)

        # fallback: any link containing the path
        if not urls:
            for a in soup.select('a[href*="/alerts-and-advisories/"]'):
                href = self._normalize_url(a.get("href", ""))
                if self._looks_like_article_url(href):
                    urls.add(href)

        return urls

    def _extract_article(self, html: str, url: str) -> Optional[Tuple[leak_model, entity_model]]:
        s = BeautifulSoup(html, "html.parser")

        # title
        title_el = (
            s.select_one("h1.prose-display-md.break-words.text-base-content-strong")
            or s.select_one("h1")
            or s.select_one("title")
        )
        title = self._clean_text(title_el.get_text(" ", strip=True) if title_el else "")
        if not title:
            return None

        # raw date (CSA pages often show a date label in a <p>)
        raw_date_el = s.select_one("p.prose-label-sm-medium.text-base-content") or s.select_one("time")
        raw_date = self._clean_text(raw_date_el.get_text(" ", strip=True) if raw_date_el else "")

        # content blocks (your old selectors + broad fallback)
        content_parts: List[str] = []

        sel1 = s.select_one("div.prose-title-lg.text-base-content-light")
        if sel1:
            t = self._clean_text(sel1.get_text(" ", strip=True))
            if t:
                content_parts.append(t)

        sel2 = s.select_one(r"div.w-full.overflow-x-auto.break-words.lg\:max-w-\[660px\]")
        if sel2:
            # keep paragraph-ish text readable
            lines: List[str] = []
            for el in sel2.find_all(["p", "li", "h2", "h3", "h4"], recursive=True):
                txt = self._clean_text(el.get_text(" ", strip=True))
                if not txt:
                    continue
                if getattr(el, "name", "").lower() == "li":
                    lines.append(f"- {txt}")
                else:
                    lines.append(txt)
            t = "\n".join(lines).strip()
            if t:
                content_parts.append(t)

        # fallback to main/article if still empty
        if not content_parts:
            main = s.select_one("main") or s.select_one("article")
            if main:
                t = self._clean_text(main.get_text(" ", strip=True))
                if t:
                    content_parts.append(t)

        content = "\n".join([p for p in content_parts if p]).strip()
        important = " ".join((content or title).split()[:200])

        # extract links in content (prefer sel2/main)
        weblinks: List[str] = []
        link_root = sel2 or s.select_one("main") or s
        for a in (link_root.select("a[href]") if link_root else []):
            href = (a.get("href") or "").strip()
            if not href or href.startswith("#"):
                continue
            full = href if href.startswith("http") else urljoin(url, href)
            if full not in weblinks:
                weblinks.append(full)
        leak_date = self._parse_date(raw_date)

        card = leak_model(
            m_title=title,
            m_url=url,
            m_base_url=self.base_url,
            m_content=content,
            m_network=helper_method.get_network_type(self.base_url),
            m_important_content=important,
            m_content_type=["cve", "tracking"],
            m_leak_date=leak_date,
            m_weblink=weblinks,
        )

        entity = entity_model(
            m_scrap_file=self.__class__.__name__,
            m_team="csa-gov-sg",
            m_country=["Singapore"],
            m_name="Cyber Security Agency of Singapore"
        )

        return card, entity

    @staticmethod
    def _parse_date(raw_date: str):
        if not raw_date:
            return None

        raw_date = raw_date.strip()

        # common CSA formats
        formats = [
            "%d %B %Y",  # 12 January 2025
            "%d %b %Y",  # 12 Jan 2025
            "%B %d, %Y",  # January 12, 2025
            "%b %d, %Y",
            "%Y-%m-%d",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(raw_date, fmt).date()
            except Exception:
                continue

        # fallback: try to extract date using regex
        match = re.search(r"\d{1,2}\s+\w+\s+\d{4}", raw_date)
        if match:
            try:
                return datetime.strptime(match.group(0), "%d %B %Y").date()
            except Exception:
                pass

        return None
    # ---------------- raw store ----------------
    def _store_raw_card(self, card: leak_model) -> str:
        aid = self._sha1(card.m_url or (card.m_title or "") + str(datetime.now(timezone.utc).timestamp()))
        base = f"CSA:raw:{aid}"

        self._redis_set(f"{base}:url", card.m_url)
        self._redis_set(f"{base}:title", card.m_title)
        self._redis_set(f"{base}:date", self._date_to_string(card.m_leak_date))
        self._redis_set(f"{base}:content", card.m_content or "")
        self._redis_set(f"{base}:important", card.m_important_content or "")
        self._redis_set(f"{base}:network:type", card.m_network or "")
        self._redis_set(f"{base}:seed_url", self.seed_url)
        self._redis_set(f"{base}:base_url", self.base_url)
        self._redis_set(f"{base}:scraped_at", int(datetime.now(timezone.utc).timestamp()))
        self._redis_set(f"{base}:rendered", "0")

        cts = getattr(card, "m_content_type", None) or []
        self._redis_set(f"{base}:content_type_count", len(cts))
        for i, v in enumerate(cts):
            self._redis_set(f"{base}:content_type:{i}", v)

        links = getattr(card, "m_weblink", None) or getattr(card, "m_websites", None) or []
        self._redis_set(f"{base}:weblinks_count", len(links))
        for i, u in enumerate(links):
            self._redis_set(f"{base}:weblink:{i}", u)

        self._append_index(self._raw_index_key, aid)
        return aid

    # ---------------- JSON store for UI ----------------
    def _store_json_for_ui(self, aid: str, card: leak_model, entity: entity_model):
        payload = {
            "aid": aid,
            "leak": card.to_dict() if hasattr(card, "to_dict") else {
                "title": card.m_title,
                "url": card.m_url,
                "base_url": card.m_base_url,
                "network": card.m_network,
                "important_content": card.m_important_content,
                "content_type": getattr(card, "m_content_type", []) or [],
                "weblinks": getattr(card, "m_weblink", []) or [],
                "leak_date": self._date_to_string(card.m_leak_date),
                "content": card.m_content,
            },
            "entity": entity.__dict__ if hasattr(entity, "__dict__") else str(entity),
            "scraped_at": int(datetime.now(timezone.utc).timestamp()),
        }

        key = f"CSA:ui:{aid}"
        self._redis_set(key, json.dumps(payload, ensure_ascii=False))
        self._append_index(self._json_index_key, aid)

    # ---------------- callback append ----------------
    def append_leak_data(self, leak: leak_model, entity: entity_model):
        self._card_data.append(leak)
        self._entity_data.append(entity)

        if self.callback:
            try:
                if self.callback():
                    self._card_data.clear()
                    self._entity_data.clear()
            except Exception:
                pass

    # ---------------- main runner ----------------
    def run(self) -> dict:
        return self.parse_leak_data()

    def parse_leak_data(self) -> dict:
        collected = 0
        seen_links: Set[str] = set()
        all_links_in_order: List[str] = []

        min_year = self._first_crawl_min_year if not self.is_crawled else self._next_crawl_min_year

        # if we already crawled once in runtime, reduce pages a bit (like your old script)
        effective_max_pages = min(self._max_pages, 5) if self._is_crawled else self._max_pages

        session = self._make_requests_session(use_proxy=True)

        # --------- collect article links from index pages ----------
        for page_no in range(1, effective_max_pages + 1):
            index_url = self._index_url_for_page(page_no)

            html = ""
            try:
                r = session.get(index_url, timeout=60)
                r.encoding = "utf-8"
                if r.status_code in (403, 429):
                    print(f"[CSA.GOV.SG] ⚠ {r.status_code} on proxy index. Retrying WITHOUT proxy: {index_url}")
                    s_np = self._make_requests_session(use_proxy=False)
                    r2 = s_np.get(index_url, timeout=60)
                    r2.encoding = "utf-8"
                    if r2.status_code in (403, 429):
                        print(f"[CSA.GOV.SG] ⚠ {r2.status_code} even without proxy. Using Playwright: {index_url}")
                        html = self._fetch_with_playwright(index_url, use_proxy=False)
                    else:
                        r2.raise_for_status()
                        html = r2.text
                else:
                    r.raise_for_status()
                    html = r.text
            except Exception as ex:
                try:
                    print(f"[CSA.GOV.SG] ⚠ Index fetch failed via requests: {ex}. Using Playwright: {index_url}")
                    html = self._fetch_with_playwright(index_url, use_proxy=False)
                except Exception as ex2:
                    print(f"[CSA.GOV.SG] ❌ Index fetch failed: {index_url} -> {ex2}")
                    break

            links = self._extract_article_links_from_index_html(html)
            new_count = 0
            for u in links:
                if u not in seen_links:
                    seen_links.add(u)
                    all_links_in_order.append(u)
                    new_count += 1

            print(f"[CSA.GOV.SG] Index page {page_no}: +{new_count} new links | total={len(all_links_in_order)}")

            # if pagination param doesn't work, we usually stop seeing new links quickly
            if new_count == 0 and page_no >= 2:
                break

            if self._max_articles and len(all_links_in_order) >= self._max_articles:
                break

        # --------- fetch & parse each article ----------
        for article_url in all_links_in_order:
            if self._max_articles and collected >= self._max_articles:
                break

            try:
                art_html = ""
                try:
                    s_np = self._make_requests_session(use_proxy=False)
                    rr = s_np.get(article_url, timeout=120)
                    rr.encoding = "utf-8"
                    if rr.status_code in (403, 429):
                        art_html = self._fetch_with_playwright(article_url, use_proxy=False)
                    else:
                        rr.raise_for_status()
                        art_html = rr.text
                except Exception:
                    art_html = self._fetch_with_playwright(article_url, use_proxy=False)

                parsed = self._extract_article(art_html, article_url)
                if not parsed:
                    continue

                leak, ent = parsed

                # year filter (only if date exists)
                if leak.m_leak_date and getattr(leak.m_leak_date, "year", None):
                    if leak.m_leak_date.year < min_year:
                        continue

                self.append_leak_data(leak, ent)

                aid = self._store_raw_card(leak)
                self._store_json_for_ui(aid, leak, ent)

                collected += 1
                d = self._date_to_string(leak.m_leak_date)
                print(f"[CSA.GOV.SG] +1 | {d} | {leak.m_title[:90]}")

            except Exception as ex:
                print(f"[CSA.GOV.SG] ❌ Error parsing article: {ex}")
                continue

        self._is_crawled = True
        print(f"[CSA.GOV.SG] ✅ Done. Collected={collected}")

        return {
            "seed_url": self.seed_url,
            "articles_collected": collected,
            "min_year": min_year,
            "developer_signature": self.developer_signature,
        }