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


class _csocybercrime_tracking(leak_extractor_interface, ABC):
    _instance = None

    # ---------------- singleton ----------------
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_csocybercrime_tracking, cls).__new__(cls)
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
        self._max_articles: Optional[int] = 25

        # year filters (best-effort)
        self._first_crawl_min_year = 2023
        self._next_crawl_min_year = 2024

        # Redis master indexes (pipe-delimited strings, NOT JSON)
        self._raw_index_key = "CSO:CYBERCRIME:raw_index"
        self._json_index_key = "CSO:CYBERCRIME:json_index"

        # keep your fixed signature exactly as provided
        self._fixed_signature = "Muhammad Abdullah:owGbwMvMwMEYdOzLoajv79gZTxskMWRU6bi8370/...===weDX"

        print("[CSO.CYBERCRIME] Initialized ✅ (requests + Playwright fallback + Redis indexing)")

    # ---------------- interface hooks ----------------
    def init_callback(self, callback=None):
        self.callback = callback
        print("[CSO.CYBERCRIME] Callback set")

    def set_proxy(self, proxy: dict):
        self._proxy = proxy or {}
        print(f"[CSO.CYBERCRIME] Proxy configured: {self._proxy}")

    def set_limits(self, max_pages: Optional[int] = None, max_articles: Optional[int] = None):
        if max_pages is not None and max_pages >= 1:
            self._max_pages = int(max_pages)
        if max_articles is not None and max_articles >= 1:
            self._max_articles = int(max_articles)
        print(f"[CSO.CYBERCRIME] Limits → pages={self._max_pages}, articles={self._max_articles or '∞'}")

    def reset_cache(self):
        self._redis_set("CSO:CYBERCRIME:last_crawl", "", 60)

    # ---------------- required properties ----------------
    @property
    def seed_url(self) -> str:
        return "https://www.csoonline.com/uk/cybercrime/"

    @property
    def base_url(self) -> str:
        return "https://www.csoonline.com"

    @property
    def developer_signature(self) -> str:
        return self._fixed_signature

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_fetch_proxy=FetchProxy.NONE,
            m_fetch_config=FetchConfig.REQUESTS,
            m_resoource_block=False,
            m_threat_type=ThreatType.TRACKING,
        )

    @property
    def card_data(self) -> List[leak_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    def contact_page(self) -> str:
        return self.base_url

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
                "Accept-Language": "en-GB,en;q=0.9",
                "Referer": self.base_url,
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
            }
        )

        if use_proxy:
            server = (self._proxy or {}).get("server")
            if server:
                s.proxies.update({"http": server, "https": server})
                print(f"[CSO.CYBERCRIME] requests will use proxy: {server}")

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
                locale="en-GB",
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
            return ""
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
        if "csoonline.com" not in pu.netloc:
            return False

        # CSO articles usually under /article/...
        return "/article/" in (pu.path or "")

    def _index_url_for_page(self, page_no: int) -> str:
        # Best effort pagination (many IDG sites support /page/N/ or ?page=N)
        if page_no <= 1:
            return self.seed_url
        return f"{self.seed_url.rstrip('/')}/page/{page_no}/"

    def _extract_article_links_from_index_html(self, html: str) -> List[str]:
        soup = BeautifulSoup(html, "html.parser")

        urls: List[str] = []
        seen: Set[str] = set()

        selectors = [
            "div.river-well.article h3 a[href]",
            "h3 a[href*='/article/']",
            "a[href*='/article/']",
            ".content-listing a[href]",
            "article a[href*='/article/']",
        ]

        for sel in selectors:
            for a in soup.select(sel):
                href = self._normalize_url(a.get("href", ""))
                if not href:
                    continue
                if not self._looks_like_article_url(href):
                    continue
                if href in seen:
                    continue
                seen.add(href)
                urls.append(href)
                if self._max_articles and len(urls) >= self._max_articles:
                    return urls

            if urls:
                # if we found something with a higher-quality selector, stop early
                break

        # last-resort scan
        if not urls:
            for a in soup.select("a[href]"):
                href = self._normalize_url(a.get("href", ""))
                if not href:
                    continue
                if not self._looks_like_article_url(href):
                    continue
                if href in seen:
                    continue
                seen.add(href)
                urls.append(href)
                if self._max_articles and len(urls) >= self._max_articles:
                    return urls

        return urls

    @staticmethod
    def _parse_date(raw: str):
        """
        CSO pages can show:
          - "Aug 12, 2025"
          - "12 Aug 2025"
          - ISO in time[datetime]
          - "2025-08-12"
        """
        if not raw:
            return None

        s = raw.strip()
        s = re.sub(r"\s+", " ", s)

        fmts = (
            "%b %d, %Y",
            "%B %d, %Y",
            "%d %b %Y",
            "%d %B %Y",
            "%Y-%m-%d",
        )
        for fmt in fmts:
            try:
                return datetime.strptime(s, fmt).date()
            except Exception:
                continue

        # regex fallback
        m = re.search(r"\b([A-Za-z]{3,9})\s+(\d{1,2}),\s*(\d{4})\b", s)
        if m:
            try:
                return datetime.strptime(m.group(0), "%b %d, %Y").date()
            except Exception:
                try:
                    return datetime.strptime(m.group(0), "%B %d, %Y").date()
                except Exception:
                    pass

        m2 = re.search(r"\b(\d{1,2})\s+([A-Za-z]{3,9})\s+(\d{4})\b", s)
        if m2:
            for fmt in ("%d %b %Y", "%d %B %Y"):
                try:
                    return datetime.strptime(m2.group(0), fmt).date()
                except Exception:
                    continue

        return None

    def _extract_article(self, html: str, url: str) -> Optional[Tuple[leak_model, entity_model]]:
        s = BeautifulSoup(html, "html.parser")

        # ---------------- title ----------------
        h1 = s.select_one("h1")
        title = self._clean_text(h1.get_text(" ", strip=True) if h1 else "")
        if not title:
            t = s.select_one("title")
            title = self._clean_text(t.get_text(" ", strip=True) if t else "")
        if not title:
            return None

        # ---------------- author ----------------
        author = ""
        author_box = s.select_one("div.author__name[itemprop='name']")
        if author_box:
            a = author_box.select_one("a")
            if a:
                author = self._clean_text(a.get_text(" ", strip=True))
            else:
                # fallback: remove "by"
                author = self._clean_text(author_box.get_text(" ", strip=True))
                author = re.sub(r"^\s*by\s+", "", author, flags=re.I).strip()

        # ---------------- date ----------------
        leak_date = None

        # 1) prefer meta published_time (most reliable)
        meta_pub = s.select_one("meta[property='article:published_time']")
        if meta_pub and meta_pub.get("content"):
            raw = (meta_pub.get("content") or "").strip()
            try:
                leak_date = datetime.fromisoformat(raw.replace("Z", "+00:00")).date()
            except Exception:
                leak_date = self._parse_date(raw)

        # 2) time[datetime]
        if not leak_date:
            t = s.select_one("time[datetime]")
            if t and t.get("datetime"):
                raw = (t.get("datetime") or "").strip()
                try:
                    leak_date = datetime.fromisoformat(raw.replace("Z", "+00:00")).date()
                except Exception:
                    leak_date = None

        # 3) card__info first span (your example: "Feb 5, 2026")
        if not leak_date:
            info = s.select_one("div.card__info.card__info--light")
            if info:
                first_span = info.select_one("span")
                raw = self._clean_text(first_span.get_text(" ", strip=True) if first_span else "")
                leak_date = self._parse_date(raw)

        # 4) common fallback selectors
        if not leak_date:
            date_el = (
                    s.select_one(".article-date")
                    or s.select_one(".byline-date")
                    or s.select_one("span.date")
                    or s.select_one("span.card__time")
            )
            if date_el:
                raw = self._clean_text(date_el.get_text(" ", strip=True))
                leak_date = self._parse_date(raw)

        # ---------------- content ----------------
        content_root = (
                s.select_one("article")
                or s.select_one(".article-body")
                or s.select_one(".article-content")
                or s.select_one("main")
        )

        lines: List[str] = []
        if content_root:
            for el in content_root.find_all(["p", "li", "h2", "h3", "h4"], recursive=True):
                txt = self._clean_text(el.get_text(" ", strip=True))
                if not txt:
                    continue
                if el.name.lower() == "li":
                    lines.append(f"- {txt}")
                else:
                    if txt == title:
                        continue
                    lines.append(txt)

        content = "\n".join(lines).strip()
        if not content:
            content = self._clean_text(s.get_text(" ", strip=True))

        important = " ".join((content or title).split()[:200])

        # ---------------- weblinks ----------------
        weblinks: List[str] = []
        link_root = content_root or s
        for a in link_root.select("a[href]"):
            href = (a.get("href") or "").strip()
            if not href or href.startswith("#"):
                continue
            full = href if href.startswith("http") else urljoin(url, href)
            if full not in weblinks:
                weblinks.append(full)

        # ---------------- models ----------------
        card = leak_model(
            m_title=title,
            m_weblink=[url],
            m_dumplink=[url],
            m_url=url,
            m_base_url=self.base_url,
            m_content=content[:1500] if content else title,
            m_network=helper_method.get_network_type(self.base_url),
            m_important_content=f"{title}\n{content}",
            m_content_type=["news", "tracking"],
            m_leak_date=leak_date,
        )

        # ✅ add author into leak_model if model supports it
        if author:
            try:
                setattr(card, "m_author", author)
            except Exception:
                pass
            try:
                extra = getattr(card, "m_extra", None) or {}
                if isinstance(extra, dict):
                    extra["author"] = author
                    setattr(card, "m_extra", extra)
            except Exception:
                pass

        entity = entity_model(
            m_scrap_file=self.__class__.__name__,
            m_team="CSO Cybercrime Section",
            m_country=["united kingdom"],
            m_name="CSO Online (UK) - Cybercrime",
        )

        # ✅ add author into entity_model if model supports it
        if author:
            try:
                setattr(entity, "m_author", author)
            except Exception:
                pass
            try:
                extra = getattr(entity, "m_extra", None) or {}
                if isinstance(extra, dict):
                    extra["author"] = author
                    setattr(entity, "m_extra", extra)
            except Exception:
                pass

        return card, entity

    # ---------------- raw store ----------------
    def _store_raw_card(self, card: leak_model) -> str:
        aid = self._sha1(card.m_url or (card.m_title or "") + str(datetime.now(timezone.utc).timestamp()))
        base = f"CSO:CYBERCRIME:raw:{aid}"

        self._redis_set(f"{base}:url", getattr(card, "m_url", ""))
        self._redis_set(f"{base}:title", getattr(card, "m_title", ""))
        self._redis_set(f"{base}:date", self._date_to_string(getattr(card, "m_leak_date", None)))
        self._redis_set(f"{base}:content", getattr(card, "m_content", "") or "")
        self._redis_set(f"{base}:important", getattr(card, "m_important_content", "") or "")
        self._redis_set(f"{base}:network:type", getattr(card, "m_network", "") or "")
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
                "title": getattr(card, "m_title", ""),
                "url": getattr(card, "m_url", ""),
                "base_url": getattr(card, "m_base_url", self.base_url),
                "network": getattr(card, "m_network", ""),
                "important_content": getattr(card, "m_important_content", ""),
                "content_type": getattr(card, "m_content_type", []) or [],
                "weblinks": getattr(card, "m_weblink", []) or [],
                "leak_date": self._date_to_string(getattr(card, "m_leak_date", None)),
                "content": getattr(card, "m_content", ""),
            },
            "entity": entity.__dict__ if hasattr(entity, "__dict__") else str(entity),
            "scraped_at": int(datetime.now(timezone.utc).timestamp()),
        }

        key = f"CSO:CYBERCRIME:ui:{aid}"
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
        links_in_order: List[str] = []

        min_year = self._first_crawl_min_year if not self.is_crawled else self._next_crawl_min_year
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
                    print(f"[CSO.CYBERCRIME] ⚠ {r.status_code} on proxy index. Retrying WITHOUT proxy: {index_url}")
                    s_np = self._make_requests_session(use_proxy=False)
                    r2 = s_np.get(index_url, timeout=60)
                    r2.encoding = "utf-8"
                    if r2.status_code in (403, 429):
                        print(f"[CSO.CYBERCRIME] ⚠ {r2.status_code} even without proxy. Using Playwright: {index_url}")
                        html = self._fetch_with_playwright(index_url, use_proxy=False)
                    else:
                        r2.raise_for_status()
                        html = r2.text
                else:
                    r.raise_for_status()
                    html = r.text
            except Exception as ex:
                try:
                    print(f"[CSO.CYBERCRIME] ⚠ Index fetch failed via requests: {ex}. Using Playwright: {index_url}")
                    html = self._fetch_with_playwright(index_url, use_proxy=False)
                except Exception as ex2:
                    print(f"[CSO.CYBERCRIME] ❌ Index fetch failed: {index_url} -> {ex2}")
                    break

            page_links = self._extract_article_links_from_index_html(html)
            new_count = 0
            for u in page_links:
                if u in seen_links:
                    continue
                seen_links.add(u)
                links_in_order.append(u)
                new_count += 1
                if self._max_articles and len(links_in_order) >= self._max_articles:
                    break

            print(f"[CSO.CYBERCRIME] Index page {page_no}: +{new_count} new links | total={len(links_in_order)}")

            if new_count == 0 and page_no >= 2:
                break
            if self._max_articles and len(links_in_order) >= self._max_articles:
                break

        # --------- fetch & parse each article ----------
        for url in links_in_order:
            if self._max_articles and collected >= self._max_articles:
                break

            try:
                art_html = ""
                try:
                    s_np = self._make_requests_session(use_proxy=False)
                    rr = s_np.get(url, timeout=90)
                    rr.encoding = "utf-8"
                    if rr.status_code in (403, 429):
                        art_html = self._fetch_with_playwright(url, use_proxy=False)
                    else:
                        rr.raise_for_status()
                        art_html = rr.text
                except Exception:
                    art_html = self._fetch_with_playwright(url, use_proxy=False)

                parsed = self._extract_article(art_html, url)
                if not parsed:
                    continue

                leak, ent = parsed

                # year filter (only if date exists)
                if getattr(leak, "m_leak_date", None) and getattr(leak.m_leak_date, "year", None):
                    if leak.m_leak_date.year < min_year:
                        continue

                self.append_leak_data(leak, ent)

                aid = self._store_raw_card(leak)
                self._store_json_for_ui(aid, leak, ent)

                collected += 1
                d = self._date_to_string(getattr(leak, "m_leak_date", None))
                print(f"[CSO.CYBERCRIME] +1 | {d} | {leak.m_title[:90]}")

            except Exception as ex:
                print(f"[CSO.CYBERCRIME] ❌ Error parsing article: {ex}")
                continue

        self._is_crawled = True
        print(f"[CSO.CYBERCRIME] ✅ Done. Collected={collected}")

        return {
            "seed_url": self.seed_url,
            "articles_collected": collected,
            "min_year": min_year,
            "developer_signature": self.developer_signature,
        }