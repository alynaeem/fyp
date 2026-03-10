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


class _certeu(leak_extractor_interface, ABC):
    _instance = None

    # ---------------- singleton ----------------
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_certeu, cls).__new__(cls)
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

        # limits
        self._max_list_items_per_target: int = 30
        self._max_articles: Optional[int] = None

        # Redis master indexes (pipe-delimited strings, NOT JSON)
        self._raw_index_key = "CERTEU:raw_index"
        self._json_index_key = "CERTEU:json_index"

        self._log_every_targets = 1

        print("[CERT.EU] Initialized ✅ (pure Redis, no NLP)")

    # ---------------- interface hooks ----------------
    def init_callback(self, callback=None):
        self.callback = callback
        print("[CERT.EU] Callback set")

    def set_proxy(self, proxy: dict):
        self._proxy = proxy or {}
        print(f"[CERT.EU] Proxy configured: {self._proxy}")

    def set_limits(self, max_list_items_per_target: Optional[int] = None, max_articles: Optional[int] = None):
        if max_list_items_per_target is not None and max_list_items_per_target >= 1:
            self._max_list_items_per_target = int(max_list_items_per_target)
        if max_articles is not None and max_articles >= 1:
            self._max_articles = int(max_articles)
        print(
            f"[CERT.EU] Limits → list_items/target={self._max_list_items_per_target}, articles={self._max_articles or '∞'}"
        )

    def reset_cache(self):
        self._redis_set("CERTEU:last_crawl", "", 60)

    # ---------------- required properties ----------------
    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "https://cert.europa.eu/blog"

    @property
    def base_url(self) -> str:
        return "https://cert.europa.eu"

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_threat_type=ThreatType.TRACKING,
            m_fetch_proxy=FetchProxy.NONE,
            m_fetch_config=FetchConfig.REQUESTS,
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
        return developer_signature(self._developer_name, self._developer_note)

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
                print(f"[CERT.EU] requests will use proxy: {server}")

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
    def _parse_iso_date(raw: str):
        if not raw:
            return None
        s = raw.strip()
        try:
            return datetime.fromisoformat(s.replace("Z", "")).date()
        except Exception:
            return None

    @staticmethod
    def _parse_date_with_formats(raw: str, fmts: Tuple[str, ...]):
        if not raw:
            return None
        s = raw.strip()
        for fmt in fmts:
            try:
                return datetime.strptime(s, fmt).date()
            except Exception:
                continue
        return None

    def _extract_blog_index(self, html: str) -> List[Tuple[str, str, Optional[datetime]]]:
        """
        Returns list of tuples: (url, title, date)
        """
        soup = BeautifulSoup(html, "html.parser")
        items = soup.select("article.news--articles--item")
        out: List[Tuple[str, str, Optional[datetime]]] = []

        for it in items[: self._max_list_items_per_target]:
            a = it.select_one("a[href]")
            if not a:
                continue
            href = (a.get("href") or "").strip()
            if not href:
                continue
            url = urljoin(self.base_url, href)
            title = self._clean_text(a.get_text(" ", strip=True))
            if not title:
                # sometimes title is in heading inside the card
                h = it.select_one("h2, h3")
                title = self._clean_text(self._safe_get_text(h))

            date = None
            t = it.select_one("time.news--articles--item--time[datetime]")
            if t:
                date = self._parse_iso_date(t.get("datetime", ""))

            if url and title:
                out.append((url, title, date))

        # de-dup preserve order
        seen = set()
        dedup = []
        for u, t, d in out:
            if u in seen:
                continue
            seen.add(u)
            dedup.append((u, t, d))
        return dedup

    def _extract_ti_2025_index(self, html: str) -> List[Tuple[str, str, Optional[datetime]]]:
        """
        Threat Intelligence 2025 listing.
        Returns list: (url, title, date)
        """
        soup = BeautifulSoup(html, "html.parser")
        cards = soup.select("div.c-teaser__content")
        out: List[Tuple[str, str, Optional[datetime]]] = []

        for c in cards[: self._max_list_items_per_target]:
            a = c.select_one("h3 a[href]") or c.select_one("a[href]")
            if not a:
                continue
            href = (a.get("href") or "").strip()
            if not href:
                continue
            url = urljoin(self.base_url, href)
            title = self._clean_text(a.get_text(" ", strip=True))
            if not title:
                h3 = c.select_one("h3")
                title = self._clean_text(self._safe_get_text(h3))

            date = None
            p = c.select_one("p.c-meta")
            if p:
                raw = self._clean_text(p.get_text(" ", strip=True))
                # try common CERT-EU formats
                date = self._parse_date_with_formats(raw, ("%d %b %Y", "%d %B %Y", "%Y-%m-%d"))

            if url and title:
                out.append((url, title, date))

        # de-dup preserve order
        seen = set()
        dedup = []
        for u, t, d in out:
            if u in seen:
                continue
            seen.add(u)
            dedup.append((u, t, d))
        return dedup

    def _extract_article_content(self, html: str) -> Tuple[str, List[str], Optional[datetime]]:
        """
        Returns: (content, out_links, date)
        """
        soup = BeautifulSoup(html, "html.parser")

        # date (blog pages commonly use time.text-grey)
        date = None
        t = soup.select_one("time.text-grey[datetime]") or soup.select_one("time[datetime]")
        if t:
            date = self._parse_iso_date(t.get("datetime", ""))

        # content
        content_blocks = soup.select("main p, article p")
        paragraphs = []
        for p in content_blocks:
            txt = self._clean_text(p.get_text(" ", strip=True))
            if txt:
                paragraphs.append(txt)
        content = "\n".join(paragraphs).strip()

        # out links (best-effort: all http(s) inside main/article)
        out_links: List[str] = []
        container = soup.select_one("main") or soup.select_one("article") or soup
        for a in container.select("a[href]"):
            href = (a.get("href") or "").strip()
            if not href:
                continue
            full = href if href.startswith("http") else urljoin(self.base_url, href)
            out_links.append(full)
        out_links = list(dict.fromkeys(out_links))

        return content, out_links, date

    # ---------------- raw store ----------------
    def _store_raw_card(self, card: leak_model) -> str:
        aid = self._sha1(card.m_url or (card.m_title or "") + str(datetime.now(timezone.utc).timestamp()))
        base = f"CERTEU:raw:{aid}"

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

        key = f"CERTEU:ui:{aid}"
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
        seen_urls: Set[str] = set()

        session = self._make_requests_session(use_proxy=True)

        targets = [
            {
                "name": "blog",
                "url": "https://cert.europa.eu/blog",
                "country": "European Union",
                "team": "CERT-EU",
                "index_type": "blog",
            },
            {
                "name": "ti_2025",
                "url": "https://cert.europa.eu/publications/threat-intelligence/2025",
                "country": "European Union",
                "team": "CERT-EU",
                "index_type": "ti_2025",
            },
        ]

        for ti, target in enumerate(targets, start=1):
            index_url = target["url"]
            html = ""

            try:
                r = session.get(index_url, timeout=60)
                r.encoding = "utf-8"
                if r.status_code == 403:
                    print(f"[CERT.EU] ⚠ 403 on proxy index. Retrying WITHOUT proxy: {index_url}")
                    s_np = self._make_requests_session(use_proxy=False)
                    r2 = s_np.get(index_url, timeout=60)
                    r2.encoding = "utf-8"
                    if r2.status_code == 403:
                        print(f"[CERT.EU] ⚠ 403 even without proxy. Using Playwright: {index_url}")
                        html = self._fetch_with_playwright(index_url, use_proxy=False)
                    else:
                        r2.raise_for_status()
                        html = r2.text
                else:
                    r.raise_for_status()
                    html = r.text
            except Exception as ex:
                try:
                    print(f"[CERT.EU] ⚠ Index fetch failed via requests: {ex}. Using Playwright: {index_url}")
                    html = self._fetch_with_playwright(index_url, use_proxy=False)
                except Exception as ex2:
                    print(f"[CERT.EU] ❌ Index fetch failed: {index_url} -> {ex2}")
                    continue

            if target["index_type"] == "blog":
                articles = self._extract_blog_index(html)
            else:
                articles = self._extract_ti_2025_index(html)

            if ti % self._log_every_targets == 0:
                print(f"[CERT.EU] Target {ti}/{len(targets)} '{target['name']}': found={len(articles)}")

            for url, title, list_date in articles:
                if self._max_articles and collected >= self._max_articles:
                    break
                if not url or url in seen_urls:
                    continue
                seen_urls.add(url)

                try:
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

                    content, out_links, content_date = self._extract_article_content(art_html)
                    leak_date = content_date or (list_date.date() if isinstance(list_date, datetime) else list_date)

                    important = (content[:500] if content else title[:500])

                    card = leak_model(
                        m_title=title,
                        m_weblink=[url],
                        m_dumplink=[url],
                        m_url=url,
                        m_base_url=self.base_url,
                        m_content=content,
                        m_network=helper_method.get_network_type(self.base_url),
                        m_important_content=important,
                        m_content_type=["news", "tracking"],
                        m_leak_date=leak_date,
                    )

                    # keep outgoing resources too (if your model supports it)
                    try:
                        setattr(card, "m_websites", out_links)
                    except Exception:
                        pass

                    ent = entity_model(
                        m_scrap_file=self.__class__.__name__,
                        m_team=target["team"],
                        m_country=[target["country"]],
                    )

                    self.append_leak_data(card, ent)

                    aid = self._store_raw_card(card)
                    self._store_json_for_ui(aid, card, ent)

                    collected += 1
                    d = self._date_to_string(card.m_leak_date)
                    print(f"[CERT.EU] +1 | {d} | {card.m_title[:90]}")

                except Exception as ex:
                    print(f"[CERT.EU] ❌ Error parsing article: {ex}")
                    continue

            if self._max_articles and collected >= self._max_articles:
                break

        self._is_crawled = True
        print(f"[CERT.EU] ✅ Done. Collected={collected}")

        return {
            "seed_url": self.seed_url,
            "articles_collected": collected,
            "developer_signature": self.developer_signature,
        }
