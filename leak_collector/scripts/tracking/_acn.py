import re
import json
import hashlib
import requests
from abc import ABC
from datetime import datetime, timezone
from typing import List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse

from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

from crawler.common.crawler_instance.local_interface_model.leak.leak_extractor_interface import leak_extractor_interface
from crawler.common.crawler_instance.local_shared_model.data_model import entity_model
from crawler.common.crawler_instance.local_shared_model.data_model import leak_model
from crawler.common.crawler_instance.local_shared_model import RuleModel, FetchProxy, FetchConfig, ThreatType
from crawler.common.crawler_instance.crawler_services.redis_manager.redis_controller import redis_controller
from crawler.common.crawler_instance.crawler_services.shared.helper_method import helper_method
from crawler.common.dev_signature import developer_signature


class _acn(leak_extractor_interface, ABC):
    _instance = None

    # ---------------- singleton ----------------
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_acn, cls).__new__(cls)
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

        # NOTE: max_pages=20 means you only walk first 20 index pages
        self._max_pages: int = 5
        self._max_articles: Optional[int] = None

        # Redis master indexes (pipe-delimited strings, NOT JSON)
        self._raw_index_key = "ACN:raw_index"
        self._json_index_key = "ACN:json_index"

        # log tuning
        self._log_every_pages = 1  # print index info every N pages

        print("[ACN] Initialized ✅ (pure Redis, no NLP)")

    # ---------------- interface hooks ----------------
    def init_callback(self, callback=None):
        self.callback = callback
        print("[ACN] Callback set")

    def set_proxy(self, proxy: dict):
        self._proxy = proxy or {}
        print(f"[ACN] Proxy configured: {self._proxy}")

    def set_limits(self, max_pages: Optional[int] = None, max_articles: Optional[int] = None):
        if max_pages is not None and max_pages >= 1:
            self._max_pages = int(max_pages)
        if max_articles is not None and max_articles >= 1:
            self._max_articles = int(max_articles)
        print(f"[ACN] Limits → pages={self._max_pages}, articles={self._max_articles or '∞'}")

    def reset_cache(self):
        self._redis_set("ACN:last_crawl", "", 60)

    # ---------------- required properties ----------------
    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "https://www.acn.gov.it/portale/en/archivio-comunicazione"

    @property
    def base_url(self) -> str:
        return "https://www.acn.gov.it/"

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
        return "info@acn.gov.it"

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

    # ---------------- URL helpers ----------------
    @staticmethod
    def _add_query(url: str, **params) -> str:
        """Append/override query params safely."""
        u = urlparse(url)
        q = dict(parse_qsl(u.query, keep_blank_values=True))
        for k, v in params.items():
            q[k] = str(v)
        new_q = urlencode(q, doseq=True)
        return urlunparse((u.scheme, u.netloc, u.path, u.params, new_q, u.fragment))

    @staticmethod
    def _force_en_path(url: str) -> str:
        """
        ACN sometimes gives /portale/web/guest/ links even from EN archive.
        Force EN segment for consistency.
        """
        if "/portale/web/guest/" in url and "/portale/en/web/guest/" not in url:
            return url.replace("/portale/web/guest/", "/portale/en/web/guest/")
        return url

    # ---------------- HTTP session ----------------
    def _make_requests_session(self, use_proxy: bool = True) -> requests.Session:
        s = requests.Session()
        s.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            # ✅ ONLY ENGLISH (remove it-IT to stop Italian responses)
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://www.acn.gov.it/",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        })

        if use_proxy:
            server = (self._proxy or {}).get("server")
            if server:
                s.proxies.update({"http": server, "https": server})
                print(f"[ACN] requests will use proxy: {server}")

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
    def _parse_date(raw_date: str):
        if not raw_date:
            return None
        s = raw_date.strip()
        for fmt in ("%d %B %Y", "%d %b %Y", "%Y-%m-%d", "%d/%m/%Y"):
            try:
                return datetime.strptime(s, fmt).date()
            except Exception:
                continue

        m = re.search(
            r"\b(\d{1,2})\s+(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{4})\b",
            s
        )
        if m:
            try:
                return datetime.strptime(m.group(0), "%d %B %Y").date()
            except Exception:
                pass
        return None

    def _extract_post_links_from_index(self, soup: BeautifulSoup) -> List[str]:
        links: List[str] = []
        for a in soup.select("div.card-body h3.card-title a[href]"):
            href = a.get("href")
            if not href:
                continue
            full = urljoin(self.base_url, href)
            full = self._force_en_path(full)
            # ✅ Force languageId for Liferay
            full = self._add_query(full, languageId="en_US")
            links.append(full)

        # de-dup
        seen = set()
        out = []
        for u in links:
            if u not in seen:
                seen.add(u)
                out.append(u)
        return out

    def _extract_article_from_html(self, html: str, url: str) -> Optional[Tuple[leak_model, entity_model]]:
        s = BeautifulSoup(html, "html.parser")

        # ✅ Title
        title_el = s.select_one("div.h1.text-white.mb-0") or s.select_one("h1")
        title = self._clean_text(self._safe_get_text(title_el))
        if not title:
            return None

        # ✅ Date (exact structure: div.mb-4 > div)
        date_raw = ""
        date_container = s.select_one("div.mb-4")
        if date_container:
            date_value = date_container.select_one("div")
            if date_value:
                date_raw = self._clean_text(date_value.get_text(" ", strip=True))

        leak_date = self._parse_date(date_raw)
        date_iso = leak_date.strftime("%Y-%m-%d") if leak_date else ""

        # ✅ Content (collect p/h4/li inside content block)
        content_blocks: List[str] = []
        main_content = s.select_one("div.fs-lg.pb-5") or s.select_one("article")
        if main_content:
            for el in main_content.find_all(["p", "h4", "li"], recursive=True):
                txt = self._clean_text(el.get_text(" ", strip=True))
                if txt:
                    content_blocks.append(txt)
        description = "\n".join(content_blocks).strip()

        # ✅ Images
        images = s.select("img.img-fluid") or s.select("article img")
        image_urls: List[str] = []
        for img in images:
            src = img.get("src")
            if not src:
                continue
            image_urls.append(urljoin(self.base_url, src))
        image_urls = list(dict.fromkeys(image_urls))

        # ✅ IMPORTANT: keep title separate, content separate (no "Title:" prefix inside content)
        m_content = description

        important = (description[:500] if description else title[:500])

        card = leak_model(
            m_title=title,
            m_url=url,
            m_base_url=self.base_url,
            m_content=m_content,
            m_network=helper_method.get_network_type(self.base_url),
            m_important_content=important,
            m_content_type=["news", "tracking"],
            m_logo_or_images=image_urls,
            m_leak_date=leak_date
        )

        entity = entity_model(
            m_scrap_file=self.__class__.__name__,
            m_team="Agenzia per la Cybersicurezza Nazionale (ACN)",
            m_country=["italy"]
        )

        return card, entity

    # ---------------- raw store ----------------
    def _store_raw_card(self, card: leak_model) -> str:
        aid = self._sha1(card.m_url or (card.m_title or "") + str(datetime.now(timezone.utc).timestamp()))
        base = f"ACN:raw:{aid}"

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
                "images": getattr(card, "m_logo_or_images", []) or [],
                "leak_date": self._date_to_string(card.m_leak_date),
                "content": card.m_content,
            },
            "entity": entity.__dict__ if hasattr(entity, "__dict__") else str(entity),
            "scraped_at": int(datetime.now(timezone.utc).timestamp()),
        }

        key = f"ACN:ui:{aid}"
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

        session = self._make_requests_session(use_proxy=True)

        for page_no in range(1, self._max_pages + 1):
            index_url = f"{self.seed_url}?start={page_no}"

            html = ""
            try:
                r = session.get(index_url, timeout=60)
                if r.status_code == 403:
                    print(f"[ACN] ⚠ 403 on proxy for index. Retrying WITHOUT proxy: {index_url}")
                    session_np = self._make_requests_session(use_proxy=False)
                    r2 = session_np.get(index_url, timeout=60)
                    if r2.status_code == 403:
                        print(f"[ACN] ⚠ 403 even without proxy. Using Playwright: {index_url}")
                        html = self._fetch_with_playwright(index_url, use_proxy=False)
                    else:
                        r2.raise_for_status()
                        html = r2.text
                else:
                    r.raise_for_status()
                    html = r.text

            except Exception as ex:
                try:
                    print(f"[ACN] ⚠ Index fetch failed via requests: {ex}. Using Playwright: {index_url}")
                    html = self._fetch_with_playwright(index_url, use_proxy=False)
                except Exception as ex2:
                    print(f"[ACN] ❌ Index fetch failed: {index_url} -> {ex2}")
                    break

            soup = BeautifulSoup(html, "html.parser")
            post_links = self._extract_post_links_from_index(soup)

            if not post_links:
                print(f"[ACN] No links on index page {page_no}. Stopping.")
                break

            # cleaner logging (no jungle)
            if page_no % self._log_every_pages == 0:
                print(f"[ACN] Index page {page_no}: links={len(post_links)} | collected={collected}")

            for link in post_links:
                if link in seen_links:
                    continue
                seen_links.add(link)

                if self._max_articles and collected >= self._max_articles:
                    break

                try:
                    # article fetch (prefer no proxy)
                    art_html = ""
                    try:
                        s_np = self._make_requests_session(use_proxy=False)
                        rr = s_np.get(link, timeout=60)
                        if rr.status_code == 403:
                            art_html = self._fetch_with_playwright(link, use_proxy=False)
                        else:
                            rr.raise_for_status()
                            art_html = rr.text
                    except Exception:
                        art_html = self._fetch_with_playwright(link, use_proxy=False)

                    parsed = self._extract_article_from_html(art_html, link)
                    if not parsed:
                        continue

                    card, entity = parsed
                    self.append_leak_data(card, entity)

                    aid = self._store_raw_card(card)
                    self._store_json_for_ui(aid, card, entity)

                    collected += 1

                    # ✅ one-line output per item (no jungle)
                    d = self._date_to_string(card.m_leak_date)
                    print(f"[ACN] +1 | {d} | {card.m_title[:90]}")

                except Exception as ex:
                    print(f"[ACN] ❌ Error parsing article: {ex}")
                    continue

            if self._max_articles and collected >= self._max_articles:
                break

        self._is_crawled = True
        print(f"[ACN] ✅ Done. Collected={collected}")

        return {
            "seed_url": self.seed_url,
            "articles_collected": collected,
            "developer_signature": self.developer_signature
        }
