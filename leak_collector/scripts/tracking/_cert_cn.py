import re
import json
import hashlib
import requests

from abc import ABC
from datetime import datetime, timezone
from typing import List, Optional, Set, Tuple
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

from crawler.common.crawler_instance.local_interface_model.leak.leak_extractor_interface import leak_extractor_interface
from crawler.common.crawler_instance.local_shared_model.data_model import entity_model
from crawler.common.crawler_instance.local_shared_model.data_model import leak_model
from crawler.common.crawler_instance.local_shared_model import RuleModel, FetchProxy, FetchConfig, ThreatType
from crawler.common.crawler_instance.crawler_services.redis_manager.redis_controller import redis_controller
from crawler.common.crawler_instance.crawler_services.shared.helper_method import helper_method
from crawler.common.dev_signature import developer_signature


class _cert_cn(leak_extractor_interface, ABC):
    _instance = None

    # ---------------- singleton ----------------
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_cert_cn, cls).__new__(cls)
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

        # Redis master indexes (pipe-delimited strings, NOT JSON)
        self._raw_index_key = "CERTCN:raw_index"
        self._json_index_key = "CERTCN:json_index"

        # log tuning
        self._log_every_pages = 1

        # keep your fixed signature (old script) available
        self._fixed_signature = (
            "Usman Ali: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qDMP"
        )

        print("[CERT.CN] Initialized ✅ (pure Redis, no NLP)")

    # ---------------- interface hooks ----------------
    def init_callback(self, callback=None):
        self.callback = callback
        print("[CERT.CN] Callback set")

    def set_proxy(self, proxy: dict):
        self._proxy = proxy or {}
        print(f"[CERT.CN] Proxy configured: {self._proxy}")

    def set_limits(self, max_pages: Optional[int] = None, max_articles: Optional[int] = None):
        if max_pages is not None and max_pages >= 1:
            self._max_pages = int(max_pages)
        if max_articles is not None and max_articles >= 1:
            self._max_articles = int(max_articles)
        print(f"[CERT.CN] Limits → pages={self._max_pages}, articles={self._max_articles or '∞'}")

    def reset_cache(self):
        self._redis_set("CERTCN:last_crawl", "", 60)

    # ---------------- required properties ----------------
    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "https://www.cert.org.cn/publish/english/55/index.html"

    @property
    def base_url(self) -> str:
        return "https://www.cert.org.cn"

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
        # keep old signature exactly; if you want generator instead, replace with:
        # return developer_signature(self._developer_name, self._developer_note)
        return self._fixed_signature

    def contact_page(self) -> str:
        return "https://www.cert.org.cn/publish/english/121/index.html"

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
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": self.base_url,
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        })

        if use_proxy:
            server = (self._proxy or {}).get("server")
            if server:
                s.proxies.update({"http": server, "https": server})
                print(f"[CERT.CN] requests will use proxy: {server}")

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

    def _extract_post_links_from_index(self, soup: BeautifulSoup) -> List[str]:
        # original selector was 'div.left.li a' (likely wrong). Keep broad + safe.
        selectors = [
            "div.left li a[href]",
            "div.left a[href]",
            "div.list a[href]",
            "a[href]"
        ]

        links: List[str] = []
        for sel in selectors:
            for a in soup.select(sel):
                href = a.get("href")
                if not href:
                    continue
                # avoid nav/footer junk: keep only publish/english/55 or obvious news paths
                if "publish/english/55" in href or "/publish/english/" in href:
                    links.append(urljoin(self.base_url, href))

        # de-dup preserve order
        seen = set()
        out = []
        for u in links:
            if u not in seen:
                seen.add(u)
                out.append(u)
        return out

    @staticmethod
    def _extract_date_from_url(url: str):
        # original regex: /(\d{8})\d+/
        # keep that + add fallback for /YYYYMMDD/ anywhere
        m = re.search(r"/(\d{8})\d+/", url)
        if m:
            try:
                return datetime.strptime(m.group(1), "%Y%m%d").date()
            except Exception:
                return None
        m2 = re.search(r"\b(\d{8})\b", url)
        if m2:
            try:
                return datetime.strptime(m2.group(1), "%Y%m%d").date()
            except Exception:
                return None
        return None

    def _guess_next_index_url(self, current_url: str, next_page_no: int) -> str:
        """
        CNCERT often uses:
          index.html, index_1.html, index_2.html ...
        """
        if current_url.endswith("/index.html") or current_url.endswith("\\index.html"):
            return current_url.replace("index.html", f"index_{next_page_no}.html")
        if "index_" in current_url and current_url.endswith(".html"):
            # replace last index_N.html
            return re.sub(r"index_\d+\.html$", f"index_{next_page_no}.html", current_url)
        # fallback: if no pattern, just return same (will be stopped by visited_index)
        return current_url

    def _extract_article_from_html(self, html: str, url: str) -> Optional[Tuple[leak_model, entity_model]]:
        s = BeautifulSoup(html, "html.parser")

        title_el = s.select_one("div.title") or s.select_one("h1") or s.select_one("title")
        title = self._clean_text(self._safe_get_text(title_el))
        if not title:
            return None

        # content: div.content p
        content_elements = s.select("div.content p")
        parts: List[str] = []
        for p in content_elements:
            t = self._clean_text(p.get_text(" ", strip=True))
            if t:
                parts.append(t)
        content = " ".join(parts).strip()

        # images: div.content img
        img_srcs: List[str] = []
        for img in s.select("div.content img[src], img[src]"):
            src = img.get("src")
            if not src:
                continue
            full = urljoin(self.base_url, src)
            if full not in img_srcs:
                img_srcs.append(full)

        leak_date = self._extract_date_from_url(url)

        important = (content[:500] if content else title[:500])

        card = leak_model(
            m_title=title,
            m_url=url,
            m_base_url=self.base_url,
            m_content=content,
            m_network=helper_method.get_network_type(self.base_url),
            m_important_content=important,
            m_content_type=["news", "tracking"],
            m_leak_date=leak_date,
            m_logo_or_images=img_srcs,
        )

        entity = entity_model(
            m_scrap_file=self.__class__.__name__,
            m_team="National Computer Network Emergency Response Technical Team",
            m_country=["CHINA"],
            m_author=["CNCERT/CC"]
        )

        return card, entity

    # ---------------- raw store ----------------
    def _store_raw_card(self, card: leak_model) -> str:
        aid = self._sha1(card.m_url or (card.m_title or "") + str(datetime.now(timezone.utc).timestamp()))
        base = f"CERTCN:raw:{aid}"

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

        key = f"CERTCN:ui:{aid}"
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
        visited_index: Set[str] = set()

        session = self._make_requests_session(use_proxy=True)

        current_url = self.seed_url
        page_no = 0

        while current_url and page_no < self._max_pages:
            if current_url in visited_index:
                break
            visited_index.add(current_url)
            page_no += 1

            html = ""
            try:
                r = session.get(current_url, timeout=60)
                if r.status_code == 403:
                    print(f"[CERT.CN] ⚠ 403 on proxy index. Retrying WITHOUT proxy: {current_url}")
                    s_np = self._make_requests_session(use_proxy=False)
                    r2 = s_np.get(current_url, timeout=60)
                    if r2.status_code == 403:
                        print(f"[CERT.CN] ⚠ 403 even without proxy. Using Playwright: {current_url}")
                        html = self._fetch_with_playwright(current_url, use_proxy=False)
                    else:
                        r2.raise_for_status()
                        html = r2.text
                else:
                    r.raise_for_status()
                    html = r.text
            except Exception as ex:
                try:
                    print(f"[CERT.CN] ⚠ Index fetch failed via requests: {ex}. Using Playwright: {current_url}")
                    html = self._fetch_with_playwright(current_url, use_proxy=False)
                except Exception as ex2:
                    print(f"[CERT.CN] ❌ Index fetch failed: {current_url} -> {ex2}")
                    break

            soup = BeautifulSoup(html, "html.parser")
            post_links = self._extract_post_links_from_index(soup)

            if page_no % self._log_every_pages == 0:
                print(f"[CERT.CN] Index page {page_no}: links={len(post_links)} | collected={collected}")

            if not post_links:
                print(f"[CERT.CN] No links on index page {page_no}. Stopping.")
                break

            for link in post_links:
                if link in seen_links:
                    continue
                seen_links.add(link)

                if self._max_articles and collected >= self._max_articles:
                    break

                try:
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
                    d = self._date_to_string(card.m_leak_date)
                    print(f"[CERT.CN] +1 | {d} | {card.m_title[:90]}")

                except Exception as ex:
                    print(f"[CERT.CN] ❌ Error parsing article: {ex}")
                    continue

            if self._max_articles and collected >= self._max_articles:
                break

            # try next index url by pattern
            current_url = self._guess_next_index_url(self.seed_url, page_no)

        self._is_crawled = True
        print(f"[CERT.CN] ✅ Done. Collected={collected}")

        return {
            "seed_url": self.seed_url,
            "articles_collected": collected,
            "developer_signature": self.developer_signature
        }
