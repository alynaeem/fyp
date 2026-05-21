import re
import json
import hashlib
import requests
from deep_translator import GoogleTranslator

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


class _cncs_pt(leak_extractor_interface, ABC):
    _instance = None

    # ---------------- singleton ----------------
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_cncs_pt, cls).__new__(cls)
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

        # language behavior
        # If True => uses EN listing: https://dyn.cncs.gov.pt/en/news
        # If False => uses PT listing: https://dyn.cncs.gov.pt/pt/noticias
        self._force_english: bool = True

        # first crawl rules
        self._first_crawl_min_year = 2023
        self._next_crawl_min_year = 2024

        # Redis master indexes (pipe-delimited strings, NOT JSON)
        self._raw_index_key = "CNCS:raw_index"
        self._json_index_key = "CNCS:json_index"

        # keep your fixed signature (old script) available
        self._fixed_signature = (
            "Muhammad Hassan Arshad: owEBeAKH/ZANAwAKAbKjqaChU0IoAcsxYgBoei5jVmVyaWZpZWQgZGV2ZWxvcGVyOiBNdWhhbW1hZCBIYXNzYW4gQXJzaGFkCokCMwQAAQoAHRYhBD5p3c9aqX5fJ9SIZbKjqaChU0IoBQJoei5jAAoJELKjqaChU0Io2i8QAKRGGxAbMJGV97ym5wcir4mn2es2/npd+MFDa/LZFnkcoPOP9/fKtg9pZ1a2PVa0h9s5ewU6wGJ4HIvjP/2gxd1maDIjv6IM+5mtlpJvQJhzoqHdAg//IRwJU5QO2krqxBQrtcvNwfkW1IoNSEaJCr0EmXht3rkGhkJ3J3XqEvrBeH0DtaZLnCLOJ3eTIRleqbBOUdq2Uf9hDZZY9rdqynjjsADo1lhchdyPjwBz1g8M/q1Ud3sTUA+/8gas5l15jR9SGQZxbgnzZRjG19oq5GAhLwUYgKuoH+zANQEB7leF9jBudzYz2Ey/4BglnVE6kszUo7RxPoqtNOFvq6WzCcRKPLO323sLfFYtwXDwvJ0iviVTOwrbXlA80GFANcAbSR76nN0XrsaLM2L/KT6oe0wTVq35j1QZnt4Jq5PWALA8hQNr7w1KtuwnpN5PmE741h+9OfZP2ogd9ERbmGb10DROsd9t4RL4hpxpsCoekHRbLI3XmHFZqFAB/GgF194Tmh3LcoIAcwOYty/PVDuPYMGMmm5Nttg2vvVrMg82P0LeOrIN2Mq03HCiZm/HaOvePniPg+EeaWPMiVmGWvCJUOMI/TJRz4jVLR4BUlvoiUSNBWrJhxMRQZpViam2rVUaojPaZhzoIF4sqS6hYqzZbbXHwtYjJfNOHh00gucABJHw=gmDH"
        )

        print("[CNCS.PT] Initialized ✅ (pure Redis, no NLP)")

    # ---------------- interface hooks ----------------
    def init_callback(self, callback=None):
        self.callback = callback
        print("[CNCS.PT] Callback set")

    def set_proxy(self, proxy: dict):
        self._proxy = proxy or {}
        print(f"[CNCS.PT] Proxy configured: {self._proxy}")

    def set_limits(self, max_pages: Optional[int] = None, max_articles: Optional[int] = None):
        if max_pages is not None and max_pages >= 1:
            self._max_pages = int(max_pages)
        if max_articles is not None and max_articles >= 1:
            self._max_articles = int(max_articles)
        print(f"[CNCS.PT] Limits → pages={self._max_pages}, articles={self._max_articles or '∞'}")

    def set_language(self, english: bool = True):
        self._force_english = bool(english)
        print(f"[CNCS.PT] Language → {'EN' if self._force_english else 'PT'}")

    def reset_cache(self):
        self._redis_set("CNCS:last_crawl", "", 60)

    # ---------------- required properties ----------------
    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        # ✅ EN list exists: https://dyn.cncs.gov.pt/en/news
        # ✅ PT list exists: https://dyn.cncs.gov.pt/pt/noticias
        return "https://dyn.cncs.gov.pt/pt/noticias"

    @property
    def base_url(self) -> str:
        return "https://dyn.cncs.gov.pt"

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
        # keep old signature exactly; if you want generator instead, replace with:
        # return developer_signature(self._developer_name, self._developer_note)
        return self._fixed_signature

    def contact_page(self) -> str:
        return "https://x.com/CNCSgovpt"

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
                # EN pages can still be served with pt content sometimes; keep EN preferred
                "Accept-Language": "en-US,en;q=0.9,pt-PT;q=0.8,pt;q=0.7",
                "Referer": self.base_url,
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
            }
        )

        if use_proxy:
            server = (self._proxy or {}).get("server")
            if server:
                s.proxies.update({"http": server, "https": server})
                print(f"[CNCS.PT] requests will use proxy: {server}")

        return s

    def _translate_to_en(self, text: str) -> str:
        if not text:
            return text
        try:
            return GoogleTranslator(source="auto", target="en").translate(text)
        except Exception:
            return text

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
    def _parse_pt_date_from_card(day: str, month_year: str):
        """
        Old CNCS layout shows date as:
          .post-date .day  =>  "05"
          .post-date .month => "dezembro 2025"  OR "dez 2025"
        """
        if not day or not month_year:
            return None

        tokens = month_year.split()
        if len(tokens) != 2:
            return None

        month_txt, year_txt = tokens[0].strip(), tokens[1].strip()

        pt_month_map = {
            "janeiro": 1, "fevereiro": 2, "março": 3, "marco": 3, "abril": 4, "maio": 5,
            "junho": 6, "julho": 7, "agosto": 8, "setembro": 9, "outubro": 10,
            "novembro": 11, "dezembro": 12,
            "jan": 1, "fev": 2, "mar": 3, "abr": 4, "mai": 5,
            "jun": 6, "jul": 7, "ago": 8, "set": 9, "out": 10,
            "nov": 11, "dez": 12,
        }

        month_key = month_txt.lower().strip().replace(".", "")
        month_num = pt_month_map.get(month_key)
        if not month_num or not day.isdigit() or not year_txt.isdigit():
            return None

        try:
            return datetime(year=int(year_txt), month=month_num, day=int(day)).date()
        except Exception:
            return None

    @staticmethod
    def _parse_en_date_text(raw: str):
        """
        EN list pages often show: 20-Jun-2023 or 26 JAN 2026.
        We'll parse several patterns.
        """
        if not raw:
            return None
        s = raw.strip()

        # normalize
        s = re.sub(r"\s+", " ", s)

        fmts = (
            "%d-%b-%Y",     # 20-Jun-2023
            "%d-%B-%Y",     # 20-June-2023
            "%d %b %Y",     # 20 Jun 2023
            "%d %B %Y",     # 20 June 2023
            "%d %b %y",
            "%d %B %y",
            "%d %b, %Y",
            "%d %B, %Y",
            "%d %m %Y",
            "%Y-%m-%d",
        )

        for fmt in fmts:
            try:
                return datetime.strptime(s, fmt).date()
            except Exception:
                continue

        # support: "26 JAN 2026"
        m = re.search(r"\b(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})\b", s)
        if m:
            try:
                return datetime.strptime(m.group(0).title(), "%d %b %Y").date()
            except Exception:
                pass

        return None

    def _index_url_for_page(self, page_no: int) -> str:
        # CNCS listing supports ?page=N on PT, and likely also on EN
        if page_no <= 1:
            return self.seed_url
        # keep consistent with your old script which used sibling pagination
        # CNCS has: /pt/noticias/?page=5 and /en/news/?page=5
        return f"{self.seed_url.rstrip('/')}/?page={page_no}"

    def _force_lang_path(self, url: str) -> str:
        """
        Force links into /en/ or /pt/ namespace (only for dyn.cncs.gov.pt).
        """
        try:
            u = urlparse(url)
        except Exception:
            return url

        if not u.netloc.endswith("dyn.cncs.gov.pt"):
            return url

        path = u.path or "/"
        if self._force_english:
            if path.startswith("/pt/"):
                path = "/en/" + path[len("/pt/") :]
            elif not path.startswith("/en/"):
                # best effort: wrap under /en
                path = "/en" + (path if path.startswith("/") else "/" + path)
        else:
            if path.startswith("/en/"):
                path = "/pt/" + path[len("/en/") :]
            elif not path.startswith("/pt/"):
                path = "/pt" + (path if path.startswith("/") else "/" + path)

        rebuilt = f"{u.scheme}://{u.netloc}{path}"
        if u.query:
            rebuilt += f"?{u.query}"
        if u.fragment:
            rebuilt += f"#{u.fragment}"
        return rebuilt

    def _extract_cards_from_index(self, html: str) -> List[BeautifulSoup]:
        soup = BeautifulSoup(html, "html.parser")

        # CNCS dyn site variants (keep broad)
        cards = soup.select(".blog-posts .row.px-3 article.post")
        if cards:
            return cards

        cards = soup.select(".blog-posts article.post")
        if cards:
            return cards

        cards = soup.select("article.post")
        if cards:
            return cards

        # last resort: teaser blocks
        cards = soup.select("article")
        return cards

    def _extract_card_url_title_date_tags(self, card: BeautifulSoup) -> Tuple[Optional[str], str, Optional[datetime], List[str]]:
        """
        Returns (url, title, date_obj, tags)
        """
        # URL
        a_tag = (
            card.select_one(".post-meta a.btn[href]")
            or card.select_one("a.btn[href]")
            or card.select_one("a[href]")
        )
        href = (a_tag.get("href") or "").strip() if a_tag else ""
        card_url = urljoin(self.base_url, href) if href else None
        if card_url:
            card_url = self._force_lang_path(card_url)

        # Title
        title_tag = (
            card.select_one("h2.news-title-2")
            or card.select_one("h2")
            or card.select_one("h3")
        )
        title = self._clean_text(self._safe_get_text(title_tag))

        # Date (PT layout with .post-date)
        date_obj = None
        date_meta = card.select_one(".post-date")
        if date_meta:
            day_elem = date_meta.select_one(".day")
            month_elem = date_meta.select_one(".month")
            day = self._clean_text(self._safe_get_text(day_elem))
            month_year = self._clean_text(self._safe_get_text(month_elem))
            date_obj = self._parse_pt_date_from_card(day, month_year)

        # Date (EN layout can have direct date text)
        if not date_obj:
            # common: time[datetime]
            t = card.select_one("time[datetime]")
            if t and t.get("datetime"):
                dt_raw = t.get("datetime", "").strip()
                try:
                    date_obj = datetime.fromisoformat(dt_raw.replace("Z", "")).date()
                except Exception:
                    date_obj = None

        if not date_obj:
            # find something that looks like a date anywhere in card
            raw_text = self._clean_text(card.get_text(" ", strip=True))
            # quick capture "20-Jun-2023"
            m = re.search(r"\b\d{1,2}-[A-Za-z]{3}-\d{4}\b", raw_text)
            if m:
                date_obj = self._parse_en_date_text(m.group(0))

        # Tags
        tags: List[str] = []
        tags_elem = card.select_one(".post-meta span")
        if tags_elem:
            tags_str = self._clean_text(tags_elem.get_text(" ", strip=True))
            tags_str = tags_str.replace("\uf02b", "")
            tags = [t.strip() for t in tags_str.split(",") if t.strip()]

        return card_url, title, date_obj, tags

    def _extract_article_from_html(
        self, html: str, url: str, fallback_title: str = "", fallback_date=None, fallback_tags: Optional[List[str]] = None
    ) -> Optional[Tuple[leak_model, entity_model]]:
        s = BeautifulSoup(html, "html.parser")

        # content
        content_elem = s.select_one(".post-content") or s.select_one("article .post-content") or s.select_one("main")
        content = ""
        if content_elem:
            # keep paragraphs clean (avoid nav junk)
            ps = content_elem.find_all(["p", "li", "h2", "h3", "h4"], recursive=True)
            lines: List[str] = []
            for el in ps:
                txt = self._clean_text(el.get_text(" ", strip=True))
                if txt:
                    if getattr(el, "name", "").lower() == "li":
                        lines.append(f"- {txt}")
                    else:
                        lines.append(txt)
            content = "\n".join(lines).strip()
        else:
            content = self._clean_text(s.get_text(" ", strip=True))

        # title from page if present
        page_title_el = s.select_one("h1") or s.select_one("title")
        page_title = self._clean_text(self._safe_get_text(page_title_el))
        title = page_title or (fallback_title or "")
        title = self._translate_to_en(title)

        if not title:
            return None

        # date from page (EN pages often have time[datetime])
        leak_date = None
        t = s.select_one("time[datetime]")
        if t and t.get("datetime"):
            dt_raw = t.get("datetime", "").strip()
            try:
                leak_date = datetime.fromisoformat(dt_raw.replace("Z", "")).date()
            except Exception:
                leak_date = None

        if not leak_date:
            leak_date = fallback_date

        # weblinks (only from content area)
        weblinks: List[str] = []
        if content_elem:
            for a in content_elem.select("a[href]"):
                href = (a.get("href") or "").strip()
                if not href or href.startswith("#"):
                    continue
                full = href if href.startswith("http") else urljoin(url, href)
                if full not in weblinks:
                    weblinks.append(full)
        content = self._translate_to_en(content)
        important = (content[:500] if content else title[:500])

        card = leak_model(
            m_title=title,
            m_url=url,
            m_base_url=self.base_url,
            m_content=content,
            m_network=helper_method.get_network_type(self.base_url),
            m_important_content=important,
            m_weblink=weblinks,
            m_leak_date=leak_date,
            m_content_type=["news", "tracking"],
        )

        tags = fallback_tags or []

        entity = entity_model(
            m_scrap_file=self.__class__.__name__,
            m_team="CNCS",
            m_name="CNCS Portugal",
            m_country=["portugal"],
        )

        # optional tags field (only if your model supports it)
        try:
            setattr(entity, "m_tags", tags)
        except Exception:
            pass

        return card, entity

    # ---------------- raw store ----------------
    def _store_raw_card(self, card: leak_model) -> str:
        aid = self._sha1(card.m_url or (card.m_title or "") + str(datetime.now(timezone.utc).timestamp()))
        base = f"CNCS:raw:{aid}"

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

        key = f"CNCS:ui:{aid}"
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
                locale="en-US" if self._force_english else "pt-PT",
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

        min_year = self._first_crawl_min_year if not self.is_crawled else self._next_crawl_min_year

        session = self._make_requests_session(use_proxy=True)

        for page_no in range(1, self._max_pages + 1):
            index_url = self._index_url_for_page(page_no)

            html = ""
            try:
                r = session.get(index_url, timeout=60)
                r.encoding = "utf-8"
                if r.status_code == 403:
                    print(f"[CNCS.PT] ⚠ 403 on proxy index. Retrying WITHOUT proxy: {index_url}")
                    s_np = self._make_requests_session(use_proxy=False)
                    r2 = s_np.get(index_url, timeout=60)
                    r2.encoding = "utf-8"
                    if r2.status_code == 403:
                        print(f"[CNCS.PT] ⚠ 403 even without proxy. Using Playwright: {index_url}")
                        html = self._fetch_with_playwright(index_url, use_proxy=False)
                    else:
                        r2.raise_for_status()
                        html = r2.text
                else:
                    r.raise_for_status()
                    html = r.text
            except Exception as ex:
                try:
                    print(f"[CNCS.PT] ⚠ Index fetch failed via requests: {ex}. Using Playwright: {index_url}")
                    html = self._fetch_with_playwright(index_url, use_proxy=False)
                except Exception as ex2:
                    print(f"[CNCS.PT] ❌ Index fetch failed: {index_url} -> {ex2}")
                    break

            cards = self._extract_cards_from_index(html)
            if not cards:
                print(f"[CNCS.PT] No cards on index page {page_no}. Stopping.")
                break

            print(f"[CNCS.PT] Index page {page_no}: cards={len(cards)} | collected={collected}")

            for card in cards:
                if self._max_articles and collected >= self._max_articles:
                    break

                card_url, title, date_obj, tags = self._extract_card_url_title_date_tags(card)

                if not card_url or card_url in seen_links:
                    continue

                # year filter (based on index date if available)
                if date_obj and date_obj.year < min_year:
                    continue

                seen_links.add(card_url)

                try:
                    # article fetch prefer no proxy
                    art_html = ""
                    try:
                        s_np = self._make_requests_session(use_proxy=False)
                        rr = s_np.get(card_url, timeout=60)
                        rr.encoding = "utf-8"
                        if rr.status_code == 403:
                            art_html = self._fetch_with_playwright(card_url, use_proxy=False)
                        else:
                            rr.raise_for_status()
                            art_html = rr.text
                    except Exception:
                        art_html = self._fetch_with_playwright(card_url, use_proxy=False)

                    parsed = self._extract_article_from_html(
                        art_html,
                        card_url,
                        fallback_title=title,
                        fallback_date=date_obj,
                        fallback_tags=tags,
                    )
                    if not parsed:
                        continue

                    leak, ent = parsed

                    # final year filter (detail date)
                    if leak.m_leak_date and leak.m_leak_date.year < min_year:
                        continue

                    self.append_leak_data(leak, ent)

                    aid = self._store_raw_card(leak)
                    self._store_json_for_ui(aid, leak, ent)

                    collected += 1
                    d = self._date_to_string(leak.m_leak_date)
                    print(f"[CNCS.PT] +1 | {d} | {leak.m_title[:90]}")

                except Exception as ex:
                    print(f"[CNCS.PT] ❌ Error parsing article: {ex}")
                    continue

            if self._max_articles and collected >= self._max_articles:
                break

        self._is_crawled = True
        print(f"[CNCS.PT] ✅ Done. Collected={collected}")

        return {
            "seed_url": self.seed_url,
            "articles_collected": collected,
            "min_year": min_year,
            "developer_signature": self.developer_signature,
        }
