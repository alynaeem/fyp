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
from crawler.common.dev_signature import developer_signature


class _cert_pl(leak_extractor_interface, ABC):
    _instance = None

    # ---------------- singleton ----------------
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_cert_pl, cls).__new__(cls)
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

        # crawling limits (CERT.PL old behavior: first crawl=16 pages, next=2 pages)
        self._first_crawl_pages: int = 16
        self._next_crawl_pages: int = 2

        # user override (if set_limits called)
        self._max_pages: Optional[int] = None
        self._max_articles: Optional[int] = None

        # Redis master indexes (pipe-delimited strings, NOT JSON)
        self._raw_index_key = "CERTPL:raw_index"
        self._json_index_key = "CERTPL:json_index"

        # log tuning
        self._log_every_pages = 1

        print("[CERT.PL] Initialized ✅ (pure Redis, no NLP)")

    # ---------------- interface hooks ----------------
    def init_callback(self, callback=None):
        self.callback = callback
        print("[CERT.PL] Callback set")

    def set_proxy(self, proxy: dict):
        self._proxy = proxy or {}
        print(f"[CERT.PL] Proxy configured: {self._proxy}")

    def set_limits(self, max_pages: Optional[int] = None, max_articles: Optional[int] = None):
        if max_pages is not None and max_pages >= 1:
            self._max_pages = int(max_pages)
        if max_articles is not None and max_articles >= 1:
            self._max_articles = int(max_articles)
        print(f"[CERT.PL] Limits → pages={self._max_pages or 'auto'}, articles={self._max_articles or '∞'}")

    def reset_cache(self):
        self._redis_set("CERTPL:last_crawl", "", 60)

    # ---------------- required properties ----------------
    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "https://cert.pl/en"

    @property
    def base_url(self) -> str:
        return "https://cert.pl"

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_threat_type=ThreatType.TRACKING,
            m_fetch_proxy=FetchProxy.NONE,
            m_fetch_config=FetchConfig.REQUESTS,
            m_resoource_block=False
        )

    @property
    def card_data(self) -> List[leak_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    @property
    def developer_signature(self) -> str:
        return developer_signature(self._developer_name, self._developer_note)

    def contact_page(self) -> str:
        return "https://x.com/CERT_Polska_en"

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
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",  # ✅ force English
            "Referer": self.base_url,
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        })


        if use_proxy:
            server = (self._proxy or {}).get("server")
            if server:
                s.proxies.update({"http": server, "https": server})
                print(f"[CERT.PL] requests will use proxy: {server}")

        return s

    # ---------------- parsing helpers ----------------
    @staticmethod
    def _clean_text(s: str) -> str:
        return re.sub(r"\s+", " ", (s or "")).strip()

    @staticmethod
    def _safe_get_text(el) -> str:
        if not el:
            return ""
        return el.get_text(" ", strip=True)

    @staticmethod
    def _parse_date(raw: str):
        if not raw:
            return None
        s = raw.strip()

        # Most common: "12 January 2025 | something..."
        s = s.split("|")[0].strip()

        # Try English month name
        for fmt in ("%d %B %Y", "%d %b %Y"):
            try:
                return datetime.strptime(s, fmt).date()
            except Exception:
                continue

        # Fallback: numeric
        for fmt in ("%Y-%m-%d", "%d.%m.%Y", "%d/%m/%Y"):
            try:
                return datetime.strptime(s, fmt).date()
            except Exception:
                continue

        return None

    def _index_url_for_page(self, page_number: int) -> str:
        if page_number <= 1:
            return self.seed_url
        # old script: https://cert.pl/en/2/
        return f"{self.seed_url}/{page_number}/"

    def _force_en(self, url: str) -> str:
        # ✅ force /en/ path
        u = urlparse(url)
        if u.path.startswith("/en/"):
            return url
        if u.path == "/en":
            return url
        # If it's already absolute cert.pl but not /en, prefix /en
        if u.netloc.endswith("cert.pl"):
            new_path = "/en" + u.path if not u.path.startswith("/en") else u.path
            return f"{u.scheme}://{u.netloc}{new_path}" + (f"?{u.query}" if u.query else "")
        return url

    def _extract_post_links_from_index(self, soup: BeautifulSoup, index_url: str) -> List[str]:
        post_links: List[str] = []
        for a in soup.select("a.post-outer-container[href]"):
            href = (a.get("href") or "").strip()
            if not href:
                continue

            # ✅ correct join (no manual ../ cutting)
            full = urljoin(index_url.rstrip("/") + "/", href)

            # ✅ force EN
            full = self._force_en(full)

            post_links.append(full)

        # de-dup preserve order
        seen = set()
        out = []
        for u in post_links:
            if u not in seen:
                seen.add(u)
                out.append(u)
        return out

    def _extract_article_from_html(self, html: str, url: str) -> Optional[Tuple[leak_model, entity_model]]:
        s = BeautifulSoup(html, "html.parser")




        title_el = s.select_one("div.cert-title") or s.select_one("h1") or s.select_one("title")
        title = self._clean_text(self._safe_get_text(title_el))
        title = self._clean_text(self._safe_get_text(title_el))
        if (not title) or ("Nie znaleziono strony" in title) or title.lower() == "page not found":
            return None

        if not title or title.lower() == "no title":
            return None

        date_el = s.select_one("div.cert-subtitle")
        date_text = self._clean_text(self._safe_get_text(date_el))
        leak_date = self._parse_date(date_text)

        # content selectors (same as your old script)
        desc_selectors = [
            "div.main.cell.entry div.article p",
            "div.main.cell.entry div.article li",
            "div.main.cell.entry div.article ul",
            "div.main.cell.entry div.article ol",
            "div.main.cell.entry div.article h2",
            "div.main.cell.entry div.article h3",
            "div.main.cell.entry div.article h4",
        ]

        description_parts: List[str] = []
        for sel in desc_selectors:
            for el in s.select(sel):
                txt = self._clean_text(el.get_text(" ", strip=True))
                if not txt:
                    continue
                if getattr(el, "name", "").lower() == "li":
                    description_parts.append(f"- {txt}")
                else:
                    description_parts.append(txt)

        description = "\n".join(description_parts).strip()
        content = description  # keep content clean (no "Title:" prefix)

        # source links (your old rule: keep if href==text OR http)
        source_links: List[str] = []
        content_div = s.select_one("div.main.cell.entry div.article")
        if content_div:
            for a in content_div.select("a[href]"):
                href = (a.get("href") or "").strip()
                if not href:
                    continue
                txt = self._clean_text(a.get_text(" ", strip=True))
                if href.startswith("http") or (txt and href == txt):
                    source_links.append(href)
        source_links = list(dict.fromkeys(source_links))

        # images
        image_urls: List[str] = []
        for img in s.select("div.main.cell.entry div.article img[src], img[src]"):
            src = (img.get("src") or "").strip()
            if not src:
                continue
            full = src if src.startswith("http") else urljoin(self.base_url, src)
            if full not in image_urls:
                image_urls.append(full)

        important = (description[:500] if description else title[:500])

        card = leak_model(
            m_title=title,
            m_url=url,
            m_base_url=self.base_url,
            m_content=content,
            m_network=helper_method.get_network_type(self.base_url),
            m_important_content=important,
            m_content_type=["news", "tracking"],
            m_logo_or_images=image_urls,
            m_leak_date=leak_date,
            # keep compatibility with your previous field name
            m_websites=source_links,
        )

        entity = entity_model(
            m_scrap_file=self.__class__.__name__,
            m_team="CERT Polska Team",
            m_author=["CERT Author"],
            m_country=["Poland"]
        )

        return card, entity

    # ---------------- raw store ----------------
    def _store_raw_card(self, card: leak_model) -> str:
        aid = self._sha1(card.m_url or (card.m_title or "") + str(datetime.now(timezone.utc).timestamp()))
        base = f"CERTPL:raw:{aid}"

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

        imgs = getattr(card, "m_logo_or_images", None) or []
        self._redis_set(f"{base}:images_count", len(imgs))
        for i, u in enumerate(imgs):
            self._redis_set(f"{base}:images:{i}", u)

        weblinks = getattr(card, "m_websites", None) or getattr(card, "m_weblink", None) or []
        self._redis_set(f"{base}:weblinks_count", len(weblinks))
        for i, u in enumerate(weblinks):
            self._redis_set(f"{base}:weblink:{i}", u)

        self._append_index(self._raw_index_key, aid)
        return aid

    # ---------------- JSON store for UI ----------------
    def _store_json_for_ui(self, aid: str, card: leak_model, entity: entity_model):
        weblinks = getattr(card, "m_websites", None) or getattr(card, "m_weblink", None) or []

        payload = {
            "aid": aid,
            "leak": card.to_dict() if hasattr(card, "to_dict") else {
                "title": card.m_title,
                "url": card.m_url,
                "base_url": card.m_base_url,
                "network": card.m_network,
                "important_content": card.m_important_content,
                "content_type": getattr(card, "m_content_type", []) or [],
                "images": getattr(card, "m_logo_or_images", []) or [],
                "weblinks": weblinks,
                "leak_date": self._date_to_string(card.m_leak_date),
                "content": card.m_content,
            },
            "entity": entity.__dict__ if hasattr(entity, "__dict__") else str(entity),
            "scraped_at": int(datetime.now(timezone.utc).timestamp()),
        }

        key = f"CERTPL:ui:{aid}"
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

    # ---------------- main runner ----------------
    def run(self) -> dict:
        return self.parse_leak_data()

    def parse_leak_data(self) -> dict:
        collected = 0
        seen_links: Set[str] = set()

        # auto pages behavior like old script, unless overridden by set_limits()
        effective_max_pages = (
            self._max_pages
            if self._max_pages is not None
            else (self._next_crawl_pages if self.is_crawled else self._first_crawl_pages)
        )

        session = self._make_requests_session(use_proxy=True)

        for page_number in range(1, effective_max_pages + 1):
            index_url = self._index_url_for_page(page_number)

            html = ""
            try:
                r = session.get(index_url, timeout=60)
                r.encoding = "utf-8"
                if r.status_code == 403:
                    print(f"[CERT.PL] ⚠ 403 on proxy index. Retrying WITHOUT proxy: {index_url}")
                    s_np = self._make_requests_session(use_proxy=False)
                    r2 = s_np.get(index_url, timeout=60)
                    if r2.status_code == 403:
                        print(f"[CERT.PL] ⚠ 403 even without proxy. Using Playwright: {index_url}")
                        html = self._fetch_with_playwright(index_url, use_proxy=False)
                    else:
                        r2.raise_for_status()
                        html = r2.text
                else:
                    r.raise_for_status()
                    html = r.text
            except Exception as ex:
                try:
                    print(f"[CERT.PL] ⚠ Index fetch failed via requests: {ex}. Using Playwright: {index_url}")
                    html = self._fetch_with_playwright(index_url, use_proxy=False)
                except Exception as ex2:
                    print(f"[CERT.PL] ❌ Index fetch failed: {index_url} -> {ex2}")
                    break

            soup = BeautifulSoup(html, "html.parser")
            post_links = self._extract_post_links_from_index(soup, index_url)

            if page_number % self._log_every_pages == 0:
                print(f"[CERT.PL] Index page {page_number}: links={len(post_links)} | collected={collected}")

            if not post_links:
                print(f"[CERT.PL] No posts found on {index_url}, stopping.")
                break

            for url in post_links:
                if url in seen_links:
                    continue
                seen_links.add(url)

                if self._max_articles and collected >= self._max_articles:
                    break

                try:
                    # article fetch prefer no proxy
                    art_html = ""
                    try:
                        s_np = self._make_requests_session(use_proxy=False)
                        rr = s_np.get(url, timeout=60)
                        rr.encoding = "utf-8"
                        if rr.status_code == 403:
                            art_html = self._fetch_with_playwright(url, use_proxy=False)
                        else:
                            rr.raise_for_status()
                            art_html = rr.text
                    except Exception:
                        art_html = self._fetch_with_playwright(url, use_proxy=False)

                    parsed = self._extract_article_from_html(art_html, url)
                    if not parsed:
                        continue

                    card, entity = parsed

                    self.append_leak_data(card, entity)

                    aid = self._store_raw_card(card)
                    self._store_json_for_ui(aid, card, entity)

                    collected += 1
                    d = self._date_to_string(card.m_leak_date)
                    print(f"[CERT.PL] +1 | {d} | {card.m_title[:90]}")

                except Exception as ex:
                    print(f"[CERT.PL] ❌ Error parsing article: {ex}")
                    continue

            if self._max_articles and collected >= self._max_articles:
                break

        self._is_crawled = True
        print(f"[CERT.PL] ✅ Done. Collected={collected}")

        return {
            "seed_url": self.seed_url,
            "articles_collected": collected,
            "developer_signature": self.developer_signature
        }
