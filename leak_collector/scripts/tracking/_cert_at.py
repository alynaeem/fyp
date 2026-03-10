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


class _cert_at(leak_extractor_interface, ABC):
    _instance = None

    # ---------------- singleton ----------------
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_cert_at, cls).__new__(cls)
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
        self._max_pages: int = 10
        self._max_articles: Optional[int] = None

        # first crawl rules
        self._first_crawl_min_year = 2023
        self._next_crawl_min_year = 2024

        # Redis master indexes (pipe-delimited strings, NOT JSON)
        self._raw_index_key = "CERTAT:raw_index"
        self._json_index_key = "CERTAT:json_index"

        # log tuning
        self._log_every_pages = 1

        print("[CERT.at] Initialized ✅ (pure Redis, no NLP)")

    # ---------------- interface hooks ----------------
    def init_callback(self, callback=None):
        self.callback = callback
        print("[CERT.at] Callback set")

    def set_proxy(self, proxy: dict):
        self._proxy = proxy or {}
        print(f"[CERT.at] Proxy configured: {self._proxy}")

    def set_limits(self, max_pages: Optional[int] = None, max_articles: Optional[int] = None):
        if max_pages is not None and max_pages >= 1:
            self._max_pages = int(max_pages)
        if max_articles is not None and max_articles >= 1:
            self._max_articles = int(max_articles)
        print(f"[CERT.at] Limits → pages={self._max_pages}, articles={self._max_articles or '∞'}")

    def reset_cache(self):
        self._redis_set("CERTAT:last_crawl", "", 60)

    # ---------------- required properties ----------------
    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "https://www.cert.at/de/meldungen/aktuelles"

    @property
    def base_url(self) -> str:
        return "https://www.cert.at"

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
        return "https://www.cert.at/de/ueber-uns/kontakt"

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
        u = urlparse(url)
        q = dict(parse_qsl(u.query, keep_blank_values=True))
        for k, v in params.items():
            q[k] = str(v)
        new_q = urlencode(q, doseq=True)
        return urlunparse((u.scheme, u.netloc, u.path, u.params, new_q, u.fragment))

    # ---------------- HTTP session ----------------
    def _make_requests_session(self, use_proxy: bool = True) -> requests.Session:
        s = requests.Session()
        s.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
            "Referer": self.base_url,
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        })

        if use_proxy:
            server = (self._proxy or {}).get("server")
            if server:
                s.proxies.update({"http": server, "https": server})
                print(f"[CERT.at] requests will use proxy: {server}")

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
    def _parse_date_from_text(raw: str):
        if not raw:
            return None
        s = raw.strip()

        # common CERT.at format: 17.01.2025 12:34
        for fmt in ("%d.%m.%Y %H:%M", "%d.%m.%Y", "%Y-%m-%d"):
            try:
                return datetime.strptime(s, fmt).date()
            except Exception:
                continue

        # fallback: try to find dd.mm.yyyy
        m = re.search(r"\b(\d{2}\.\d{2}\.\d{4})\b", s)
        if m:
            try:
                return datetime.strptime(m.group(1), "%d.%m.%Y").date()
            except Exception:
                pass
        return None

    def _extract_post_links_from_index(self, soup: BeautifulSoup) -> List[str]:
        links: List[str] = []
        for row in soup.select("div.row"):
            a = row.select_one("a#article-ref[href]")
            if not a:
                continue
            href = a.get("href")
            if not href:
                continue
            links.append(urljoin(self.seed_url, href))

        # de-dup preserve order
        seen = set()
        out = []
        for u in links:
            if u not in seen:
                seen.add(u)
                out.append(u)
        return out

    def _extract_date_from_row(self, row: BeautifulSoup):
        # index row date is inside: div.col-sm-11 > h2 > small
        h2 = row.select_one("div.col-sm-11 > h2")
        if not h2:
            return None
        small = h2.select_one("small")
        if not small:
            return None
        return self._parse_date_from_text(small.get_text(strip=True))

    def _extract_next_page(self, soup: BeautifulSoup) -> Optional[str]:
        next_btn = soup.select_one('ul.pagination li.page-item a.page-link[rel="next"][href]')
        if not next_btn:
            return None
        href = next_btn.get("href")
        if not href:
            return None
        return urljoin(self.seed_url, href)

    def _extract_article_from_html(self, html: str, url: str) -> Optional[Tuple[leak_model, entity_model]]:
        s = BeautifulSoup(html, "html.parser")

        # Title + Date from h1 small
        h1 = s.select_one("h1")
        if not h1:
            return None

        date_val = ""
        small = h1.select_one("small")
        if small:
            date_val = self._clean_text(small.get_text(" ", strip=True))

        all_text = self._clean_text(h1.get_text(" ", strip=True))
        title = all_text
        if date_val:
            # remove date piece from title if embedded
            if all_text.startswith(date_val):
                title = self._clean_text(all_text[len(date_val):])
            title = title.lstrip("-").strip()

        if not title:
            return None

        leak_date = self._parse_date_from_text(date_val)

        # content blocks
        content_blocks = s.select("div.block p.block")
        lines: List[str] = []
        for p in content_blocks:
            t = self._clean_text(p.get_text(" ", strip=True))
            if t:
                lines.append(t)
        content = "\n".join(lines).strip()

        # weblinks
        weblinks: List[str] = []
        for p in content_blocks:
            for a in p.select("a[href]"):
                href = a.get("href")
                if not href:
                    continue
                weblinks.append(urljoin(self.base_url, href) if not href.startswith("http") else href)
        weblinks = list(dict.fromkeys(weblinks))

        # images (best-effort)
        image_urls: List[str] = []
        for img in s.select("div.block img[src], article img[src], img[src]"):
            src = img.get("src")
            if not src:
                continue
            full = urljoin(self.base_url, src)
            if full not in image_urls:
                image_urls.append(full)

        important = (content[:500] if content else title[:500])

        card = leak_model(
            m_title=title,
            m_url=url,
            m_base_url=self.base_url,
            m_content=content,
            m_network=helper_method.get_network_type(self.base_url),
            m_important_content=important,
            m_weblink=weblinks,
            m_content_type=["news", "tracking"],
            m_logo_or_images=image_urls,
            m_leak_date=leak_date
        )

        entity = entity_model(
            m_scrap_file=self.__class__.__name__,
            m_team="cert.at",
            m_country=["austria"]
        )

        return card, entity

    # ---------------- raw store ----------------
    def _store_raw_card(self, card: leak_model) -> str:
        aid = self._sha1(card.m_url or (card.m_title or "") + str(datetime.now(timezone.utc).timestamp()))
        base = f"CERTAT:raw:{aid}"

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

        links = getattr(card, "m_weblink", None) or []
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
                "images": getattr(card, "m_logo_or_images", []) or [],
                "weblinks": getattr(card, "m_weblink", []) or [],
                "leak_date": self._date_to_string(card.m_leak_date),
                "content": card.m_content,
            },
            "entity": entity.__dict__ if hasattr(entity, "__dict__") else str(entity),
            "scraped_at": int(datetime.now(timezone.utc).timestamp()),
        }

        key = f"CERTAT:ui:{aid}"
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
                locale="de-DE",
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
        visited_index: Set[str] = set()

        min_year = self._first_crawl_min_year if not self.is_crawled else self._next_crawl_min_year

        session = self._make_requests_session(use_proxy=True)

        current_url = self.seed_url
        page_count = 0

        while current_url and page_count < self._max_pages:
            if current_url in visited_index:
                break
            visited_index.add(current_url)
            page_count += 1

            html = ""
            try:
                r = session.get(current_url, timeout=60)
                if r.status_code == 403:
                    print(f"[CERT.at] ⚠ 403 on proxy index. Retrying WITHOUT proxy: {current_url}")
                    s_np = self._make_requests_session(use_proxy=False)
                    r2 = s_np.get(current_url, timeout=60)
                    if r2.status_code == 403:
                        print(f"[CERT.at] ⚠ 403 even without proxy. Using Playwright: {current_url}")
                        html = self._fetch_with_playwright(current_url, use_proxy=False)
                    else:
                        r2.raise_for_status()
                        html = r2.text
                else:
                    r.raise_for_status()
                    html = r.text
            except Exception as ex:
                try:
                    print(f"[CERT.at] ⚠ Index fetch failed via requests: {ex}. Using Playwright: {current_url}")
                    html = self._fetch_with_playwright(current_url, use_proxy=False)
                except Exception as ex2:
                    print(f"[CERT.at] ❌ Index fetch failed: {current_url} -> {ex2}")
                    break

            soup = BeautifulSoup(html, "html.parser")

            # log
            if page_count % self._log_every_pages == 0:
                print(f"[CERT.at] Index page {page_count}: {current_url} | collected={collected}")

            # parse rows and links
            rows = soup.select("div.row")
            links_this_page = self._extract_post_links_from_index(soup)

            if not rows or not links_this_page:
                print(f"[CERT.at] No rows/links on page {page_count}. Stopping.")
                break

            # Walk each row (date filter based on index row date)
            # Map row->url best-effort by scanning row itself for a#article-ref
            for row in rows:
                a = row.select_one("a#article-ref[href]")
                if not a:
                    continue
                link = urljoin(self.seed_url, a.get("href"))

                if link in seen_links:
                    continue

                row_date = self._extract_date_from_row(row)
                if row_date and row_date.year < min_year:
                    # old item => skip
                    continue

                if self._max_articles and collected >= self._max_articles:
                    break

                seen_links.add(link)

                try:
                    # article fetch prefer no proxy
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

                    # final date filter: if detail date exists and < min_year skip
                    if card.m_leak_date and card.m_leak_date.year < min_year:
                        continue

                    self.append_leak_data(card, entity)

                    aid = self._store_raw_card(card)
                    self._store_json_for_ui(aid, card, entity)

                    collected += 1
                    d = self._date_to_string(card.m_leak_date)
                    print(f"[CERT.at] +1 | {d} | {card.m_title[:90]}")

                except Exception as ex:
                    print(f"[CERT.at] ❌ Error parsing article: {ex}")
                    continue

            if self._max_articles and collected >= self._max_articles:
                break

            # next page
            next_url = self._extract_next_page(soup)
            if not next_url:
                break
            current_url = next_url

        self._is_crawled = True
        print(f"[CERT.at] ✅ Done. Collected={collected}")

        return {
            "seed_url": self.seed_url,
            "articles_collected": collected,
            "min_year": min_year,
            "developer_signature": self.developer_signature
        }
