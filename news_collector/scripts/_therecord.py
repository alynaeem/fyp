import re
import hashlib
import requests
from abc import ABC
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Set
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

from crawler.common.crawler_instance.local_interface_model.leak.leak_extractor_interface import (
    leak_extractor_interface,
)
from crawler.common.crawler_instance.local_shared_model.data_model import entity_model
from crawler.common.crawler_instance.local_shared_model.data_model import news_model
from crawler.common.crawler_instance.local_shared_model import (
    RuleModel,
    FetchProxy,
    FetchConfig,
    ThreatType,
)
from crawler.common.crawler_instance.crawler_services.redis_manager.redis_controller import (
    redis_controller,
)
from crawler.common.crawler_instance.crawler_services.shared.helper_method import helper_method
from crawler.common.dev_signature import developer_signature
from . import nlp_processor as nlp


class _therecord(leak_extractor_interface, ABC):
    """
    TheRecord (cybercrime section) collector
    Output format: THN-style
      1) parse ALL articles first (Visiting/Parsed lines)
      2) then NLP enrichment batch + per-article NLP output block
    Storage: Redis only (flattened keys), NO JSON
    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_therecord, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, developer_name: str = "Anonymous", developer_note: str = ""):
        if getattr(self, "_initialized", False):
            return
        self._initialized = True

        # ✅ keep THN-style tag
        self._tag = "[THN]"

        self._card_data: List[news_model] = []
        self._entity_data: List[entity_model] = []
        self._redis = redis_controller()
        self._is_crawled = False
        self._proxy = {}
        self._developer_name = developer_name
        self._developer_note = developer_note
        self.callback = None

        # pagination limits
        self._max_pages: int = 5
        self._max_articles: Optional[int] = None

        # Master index keys (pipe-delimited strings, NOT JSON)
        self._raw_index_key = "THERECORD:raw_index"
        self._processed_index_key = "THERECORD:processed_index"

        # optional: path to local Chromium
        self._chromium_exe = None

        print(f"{self._tag} Initialized ✅ (pure Redis, no JSON)")

    # ------- lifecycle/config hooks --------
    def init_callback(self, callback=None):
        self.callback = callback
        print(f"{self._tag} Callback set")

    def set_proxy(self, proxy: dict):
        self._proxy = proxy or {}
        print(f"{self._tag} Proxy configured: {self._proxy}")

    def set_limits(self, max_pages: Optional[int] = None, max_articles: Optional[int] = None):
        if max_pages is not None and max_pages >= 1:
            self._max_pages = int(max_pages)
        if max_articles is not None and max_articles >= 1:
            self._max_articles = int(max_articles)
        print(f"{self._tag} Limits → pages={self._max_pages}, articles={self._max_articles or '∞'}")

    def reset_cache(self):
        print(f"{self._tag} Resetting crawl timestamp …")
        self._redis_set("THERECORD:last_crawl", "", 60)

    # ------- required interface props -------
    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "https://therecord.media/news/leadership"

    @property
    def base_url(self) -> str:
        return "https://therecord.media"

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_threat_type=ThreatType.NEWS,
            m_fetch_proxy=FetchProxy.NONE,
            m_fetch_config=FetchConfig.REQUESTS,
            m_resoource_block=False,
        )

    @property
    def card_data(self) -> List[news_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def developer_signature(self) -> str:
        return developer_signature(self._developer_name, self._developer_note)

    def contact_page(self) -> str:
        return "https://therecord.media/contact"

    # ------- minimal Redis helpers (NO JSON) ------------
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

    # ------- helpers -------
    @staticmethod
    def _sha1(text: str) -> str:
        return hashlib.sha1(text.encode("utf-8")).hexdigest()

    @staticmethod
    def _date_to_string(d) -> str:
        if d is None:
            return ""
        try:
            return d.strftime("%Y-%m-%d")
        except Exception:
            return str(d)

    def _safe_n_a(self, s: str) -> str:
        s = (s or "").strip()
        return s if s else "(n/a)"

    # ✅ FIXED link activity: no HEAD; 403/429 are REACHABLE not UNREACHABLE
    def _check_link_activity(self, url: str, timeout: int = 12) -> str:
        """
        Returns:
          - ACTIVE (2xx/3xx)
          - REACHABLE (<status>) for 4xx/5xx (still reachable)
          - UNREACHABLE for network errors
        """
        if not url:
            return "UNREACHABLE"
        try:
            r = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                stream=True,
                headers={
                    "User-Agent": "TheRecordCollector/1.0 (+contact)",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                },
            )
            code = int(getattr(r, "status_code", 0) or 0)
            try:
                r.close()
            except Exception:
                pass

            if 200 <= code < 400:
                return "ACTIVE"
            return f"REACHABLE ({code})"
        except Exception:
            return "UNREACHABLE"

    @staticmethod
    def _format_categories(categories) -> str:
        if not categories:
            return "(none)"
        lines = []
        try:
            cats = list(categories)
            cats.sort(key=lambda x: float(x.get("score", 0.0)), reverse=True)
            for c in cats:
                lab = str(c.get("label", "")).strip()
                sc = float(c.get("score", 0.0))
                if lab:
                    lines.append(f"- {lab} ({sc:.2f})")
        except Exception:
            return str(categories)
        return "\n".join(lines) if lines else "(none)"

    @staticmethod
    def _top_category(categories) -> str:
        if not categories:
            return ""
        try:
            cats = list(categories)
            cats.sort(key=lambda x: float(x.get("score", 0.0)), reverse=True)
            top = cats[0]
            return f"{top.get('label', '')} ({float(top.get('score', 0.0)):.2f})"
        except Exception:
            return ""

    # ------- store raw article (per-field keys) ---------
    def _store_raw_card(self, card: news_model) -> str:
        """
        Generate AID once and keep it in card.m_extra['aid'] (like THN).
        Also store http_status to avoid false UNREACHABLE later.
        """
        aid = self._sha1(
            card.m_url or (card.m_title or "") + str(datetime.now(timezone.utc).timestamp())
        )

        card.m_extra = (card.m_extra or {})
        card.m_extra["aid"] = aid

        base = f"THERECORD:raw:{aid}"

        self._redis_set(f"{base}:url", card.m_url)
        self._redis_set(f"{base}:title", card.m_title)
        self._redis_set(f"{base}:author", card.m_author)
        self._redis_set(f"{base}:date", self._date_to_string(card.m_leak_date))

        date_raw = ""
        content_html = ""
        iso_datetime = ""
        http_status = ""
        try:
            date_raw = (card.m_extra or {}).get("date_raw", "")
            content_html = (card.m_extra or {}).get("content_html", "")
            iso_datetime = (card.m_extra or {}).get("iso_datetime", "")
            http_status = (card.m_extra or {}).get("http_status", "")
        except Exception:
            pass

        self._redis_set(f"{base}:date_raw", date_raw)
        self._redis_set(f"{base}:iso_datetime", iso_datetime)
        self._redis_set(f"{base}:content_html", content_html)
        self._redis_set(f"{base}:http_status", http_status)

        self._redis_set(f"{base}:description", card.m_description)
        self._redis_set(f"{base}:location", card.m_location or "")
        self._redis_set(f"{base}:content", card.m_content or "")
        self._redis_set(f"{base}:network:type", card.m_network)
        self._redis_set(f"{base}:seed_url", self.seed_url)
        self._redis_set(f"{base}:rendered", "1")
        self._redis_set(f"{base}:scraped_at", int(datetime.now(timezone.utc).timestamp()))

        links = card.m_links or []
        self._redis_set(f"{base}:links_count", len(links))
        for i, link in enumerate(links):
            self._redis_set(f"{base}:links:{i}", link)

        weblinks = card.m_weblink or []
        self._redis_set(f"{base}:weblink_count", len(weblinks))
        for i, link in enumerate(weblinks):
            self._redis_set(f"{base}:weblink:{i}", link)

        dumplinks = card.m_dumplink or []
        self._redis_set(f"{base}:dumplink_count", len(dumplinks))
        for i, link in enumerate(dumplinks):
            self._redis_set(f"{base}:dumplink:{i}", link)

        self._append_index(self._raw_index_key, aid)
        return aid

    # ------- store processed NLP output (generic flattener, no JSON) ----
    def _store_processed(self, aid: str, processed: dict):
        base = f"THERECORD:processed:{aid}"

        def write_obj(prefix: str, obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    write_obj(f"{prefix}:{k}", v)
            elif isinstance(obj, list):
                self._redis_set(f"{prefix}:count", len(obj))
                for i, v in enumerate(obj):
                    write_obj(f"{prefix}:{i}", v)
            else:
                self._redis_set(prefix, "" if obj is None else obj)

        write_obj(base, processed)
        self._append_index(self._processed_index_key, aid)

    # ------- HTTP session (fallback path) ---
    def _make_requests_session(self) -> requests.Session:
        print(f"{self._tag} Creating requests session …")
        s = requests.Session()
        s.headers.update(
            {
                "User-Agent": "TheRecordCollector/1.0 (+contact)",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }
        )

        server = (self._proxy or {}).get("server")
        if server and not str(server).lower().startswith("socks"):
            s.proxies.update({"http": server, "https": server})
            print(f"{self._tag} requests will use proxy: {server}")
        else:
            if server:
                print(f"{self._tag} SOCKS proxy configured ({server}) but will NOT be used by requests (no socks support).")
        return s

    # ------- Playwright helpers -------------
    def _launch_browser(self, p, use_proxy: bool) -> Tuple[object, object]:
        launch_kwargs = {"headless": False}
        if self._chromium_exe:
            launch_kwargs["executable_path"] = self._chromium_exe
        if use_proxy and (self._proxy or {}).get("server"):
            launch_kwargs["proxy"] = {"server": self._proxy["server"]}
            print(f"{self._tag} Launching Chromium WITH proxy: {self._proxy['server']}")
        else:
            print(f"{self._tag} Launching Chromium WITHOUT proxy")
        browser = p.chromium.launch(**launch_kwargs)
        context = browser.new_context()
        return browser, context

    # ------- index page helpers (pagination) ----
    def _extract_article_links_from_index(self, soup: BeautifulSoup) -> Set[str]:
        links: Set[str] = set()
        container = soup.select_one("div.article-listing__list")
        if not container:
            return links

        for a in container.select("a.article-tile[href]"):
            href = a.get("href")
            if not href:
                continue
            full = urljoin(self.base_url, href)
            if full.startswith(self.base_url):
                links.add(full)

        return links

    def _page_url(self, page_no: int) -> str:
        if page_no <= 1:
            return self.seed_url
        return f"{self.seed_url}?page={page_no}"

    # ------- meta extraction (title/author/date/content) ----
    def _extract_article_meta(self, soup: BeautifulSoup) -> Tuple[str, str, str, str, str]:
        title = ""
        title_el = soup.select_one("main article h1") or soup.select_one("article h1") or soup.select_one("h1")
        if title_el:
            title = title_el.get_text(strip=True)

        author = ""
        author_el = soup.select_one("a.article__editor")
        if author_el:
            author = author_el.get_text(" ", strip=True)

        date_raw = ""
        date_el = soup.select_one("span.article__date")
        if date_el:
            date_raw = date_el.get_text(" ", strip=True)

        content_html = ""
        content_text = ""
        article_el = soup.select_one("main article") or soup.select_one("article")
        if article_el:
            span_el = article_el.select_one("span.wysiwyg-parsed-content")
            if span_el:
                content_html = str(span_el)
                content_text = span_el.get_text(" ", strip=True)
            else:
                paras = article_el.select("p")
                if paras:
                    content_text = " ".join(p.get_text(" ", strip=True) for p in paras)
                    content_html = "".join(str(p) for p in paras)

        return title, author, date_raw, content_text, content_html

    # ------- core crawling ------------------
    def run(self) -> dict:
        print(f"{self._tag} run() → Playwright first, then requests fallback")
        try:
            return self.parse_leak_data()
        except Exception as ex:
            print(f"{self._tag} Playwright failed ({ex}). Falling back to requests.")
            return self._run_with_requests()

    def parse_leak_data(self) -> dict:
        collected = 0
        all_links: Set[str] = set()

        with sync_playwright() as p:
            # open first page
            try:
                browser, context = self._launch_browser(p, use_proxy=True)
                page = context.new_page()
                print(f"{self._tag} Opening seed (proxy): {self.seed_url}")
                page.goto(self.seed_url, timeout=60000, wait_until="load")
            except Exception as ex:
                print(f"{self._tag} Proxy navigation failed: {ex}. Retrying without proxy …")
                try:
                    context.close()
                except Exception:
                    pass
                try:
                    browser.close()
                except Exception:
                    pass
                browser, context = self._launch_browser(p, use_proxy=False)
                page = context.new_page()
                print(f"{self._tag} Opening seed (no proxy): {self.seed_url}")
                page.goto(self.seed_url, timeout=60000, wait_until="load")

            # iterate category pages (Playwright + next button)
            for page_no in range(1, self._max_pages + 1):
                soup = BeautifulSoup(page.content(), "html.parser")
                page_links = self._extract_article_links_from_index(soup)
                all_links.update(page_links)
                print(f"{self._tag} Index page {page_no}: found {len(page_links)} post links (unique total {len(all_links)})")

                if self._max_articles and len(all_links) >= self._max_articles:
                    break
                if page_no >= self._max_pages:
                    break

                try:
                    next_btn = page.locator("button.pagination__btn-next")
                    if not next_btn or not next_btn.is_enabled():
                        print(f"{self._tag} No further pages found.")
                        break
                    print(f"{self._tag} → Clicking Next pagination button")
                    next_btn.click()
                    page.wait_for_timeout(2000)
                except Exception as e:
                    print(f"{self._tag} No further pages found.")
                    break

            visit_list = sorted(all_links)
            if self._max_articles:
                visit_list = visit_list[: self._max_articles]

            # ✅ THN-style visiting header
            print(f"{self._tag} Visiting {len(visit_list)} articles after pagination")

            for idx, link in enumerate(visit_list, 1):
                try:
                    print(f"{self._tag} Visiting [{idx}/{len(visit_list)}]: {link}")

                    # ✅ capture HTTP status from Playwright response
                    resp = page.goto(link, timeout=60000, wait_until="load")
                    status_code = None
                    try:
                        status_code = resp.status if resp is not None else None
                    except Exception:
                        status_code = None

                    s = BeautifulSoup(page.content(), "html.parser")
                    title, author, date_raw, content_text, content_html = self._extract_article_meta(s)
                    parsed_date = self._parse_date(date_raw)

                    important_text = " ".join(content_text.split()[:150]) if content_text else ""
                    card = news_model(
                        m_screenshot="",
                        m_title=title or "(No title)",
                        m_weblink=[link],
                        m_dumplink=[link],
                        m_url=link,
                        m_base_url=self.base_url,
                        m_content=content_text,
                        m_network=helper_method.get_network_type(self.base_url),
                        m_important_content=important_text,
                        m_content_type=["news"],
                        m_leak_date=parsed_date,
                        m_author=author,
                        m_description=important_text,
                        m_location="",
                        m_links=[link],
                        m_extra={
                            "date_raw": date_raw,
                            "iso_datetime": "",
                            "content_html": content_html,
                            "http_status": int(status_code) if isinstance(status_code, int) else status_code,
                        },
                    )

                    entity = entity_model(m_scrap_file=self.__class__.__name__, m_team="therecord")

                    self._card_data.append(card)
                    self._entity_data.append(entity)

                    aid = self._store_raw_card(card)
                    collected += 1

                    # ✅ THN-style parsed lines
                    title_out = (title or "").strip() or "(No title)"
                    author_out = self._safe_n_a(author)
                    date_out = self._safe_n_a(date_raw)
                    print(f"{self._tag} ✅ Parsed ({idx}/{len(visit_list)}): {title_out[:90]}")
                    print(f"{self._tag}    Author: {author_out} | Date: {date_out} | AID: {aid}")

                    if self.callback and self.callback():
                        self._card_data.clear()
                        self._entity_data.clear()

                except Exception as ex:
                    print(f"{self._tag} ❌ Error parsing article {link}: {ex}")
                    continue

            # close browser
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

        # ✅ AFTER all parsed -> NLP batch output like THN
        self._nlp_enrich_batch_and_store()

        self._is_crawled = True
        print(f"{self._tag} ✅ Done. Collected={collected}")
        return {
            "seed_url": self.seed_url,
            "articles_collected": collected,
            "developer_signature": self.developer_signature(),
        }

    def _run_with_requests(self) -> dict:
        print(f"{self._tag} Fallback: requests-based crawl")
        collected = 0
        session = self._make_requests_session()

        all_links: Set[str] = set()
        for page_no in range(1, self._max_pages + 1):
            list_url = self._page_url(page_no)
            print(f"{self._tag} Index (requests) page {page_no}: {list_url}")
            try:
                r = session.get(list_url, timeout=60)
            except Exception as ex:
                print(f"{self._tag} Request failed for page {page_no}: {ex}")
                break

            if r.status_code != 200:
                print(f"{self._tag} Stopped at page {page_no}, status {r.status_code}")
                break

            soup = BeautifulSoup(r.text, "html.parser")
            page_links = self._extract_article_links_from_index(soup)
            all_links.update(page_links)
            print(f"{self._tag} Index page {page_no}: found {len(page_links)} post links (unique total {len(all_links)})")

            if self._max_articles and len(all_links) >= self._max_articles:
                break

        visit_list = sorted(all_links)
        if self._max_articles:
            visit_list = visit_list[: self._max_articles]

        print(f"{self._tag} Visiting {len(visit_list)} articles after pagination")

        for idx, link in enumerate(visit_list, 1):
            try:
                print(f"{self._tag} Visiting [{idx}/{len(visit_list)}]: {link}")

                art = session.get(link, timeout=60)
                status_code = int(getattr(art, "status_code", 0) or 0)
                if status_code != 200:
                    print(f"{self._tag} Article request failed ({status_code}) for {link}")
                    continue

                s = BeautifulSoup(art.text, "html.parser")
                title, author, date_raw, content_text, content_html = self._extract_article_meta(s)
                parsed_date = self._parse_date(date_raw)
                important_text = " ".join(content_text.split()[:150]) if content_text else ""

                card = news_model(
                    m_screenshot="",
                    m_title=title or "(No title)",
                    m_weblink=[link],
                    m_dumplink=[link],
                    m_url=link,
                    m_base_url=self.base_url,
                    m_content=content_text,
                    m_network=helper_method.get_network_type(self.base_url),
                    m_important_content=important_text,
                    m_content_type=["news"],
                    m_leak_date=parsed_date,
                    m_author=author,
                    m_description=important_text,
                    m_location="",
                    m_links=[link],
                    m_extra={
                        "date_raw": date_raw,
                        "iso_datetime": "",
                        "content_html": content_html,
                        "http_status": status_code,
                    },
                )
                entity = entity_model(m_scrap_file=self.__class__.__name__, m_team="therecord")

                self._card_data.append(card)
                self._entity_data.append(entity)

                aid = self._store_raw_card(card)
                collected += 1

                title_out = (title or "").strip() or "(No title)"
                author_out = self._safe_n_a(author)
                date_out = self._safe_n_a(date_raw)
                print(f"{self._tag} ✅ Parsed ({idx}/{len(visit_list)}): {title_out[:90]}")
                print(f"{self._tag}    Author: {author_out} | Date: {date_out} | AID: {aid}")

            except Exception as ex:
                print(f"{self._tag} ❌ Error (requests) parsing {link}: {ex}")
                continue

        self._nlp_enrich_batch_and_store()
        self._is_crawled = True
        print(f"{self._tag} ✅ Done (requests). Collected={collected}")
        return {
            "seed_url": self.seed_url,
            "articles_collected": collected,
            "developer_signature": self.developer_signature(),
        }

    # ------- NLP (AFTER ALL PARSED) ----
    def _nlp_enrich_batch_and_store(self):
        print(f"{self._tag} NLP enrichment on {len(self._card_data)} records (no JSON)")

        for card in self._card_data:
            date_raw = ""
            try:
                date_raw = (card.m_extra or {}).get("date_raw", "")
            except Exception:
                date_raw = ""

            date_iso = self._date_to_string(card.m_leak_date)

            rec = {
                "url": card.m_url,
                "title": card.m_title,
                "author": card.m_author,
                "date": date_raw,
                "published": date_iso,
                "description": card.m_description,
                "location": card.m_location,
                "links": card.m_links or [],
                "content": card.m_content,
                "network": {"type": card.m_network},
                "seed_url": self.seed_url,
                "rendered": True,
                "scraped_at": int(datetime.now(timezone.utc).timestamp()),
            }

            processed = None
            try:
                processed = nlp.process_record(rec)
            except Exception as e:
                print(f"{self._tag} NLP processing failed for record: {e}")
                processed = None

            aid = (card.m_extra or {}).get("aid", "") or self._sha1(card.m_url or card.m_title)

            if isinstance(processed, dict):
                nlp._RedisIO().write_processed(aid, processed)

            p = processed if isinstance(processed, dict) else {}

            date_raw_out = str(p.get("date_raw") or rec.get("date") or "")
            date_iso_out = str(p.get("date") or rec.get("published") or "")
            title = str(p.get("title") or rec.get("title") or "")
            author = str(p.get("author") or rec.get("author") or "")

            summary = str(
                p.get("summary")
                or p.get("short_summary")
                or p.get("abstract")
                or ""
            )

            categories = (
                p.get("categories")
                or p.get("classification")
                or p.get("labels")
                or []
            )

            url = str(p.get("url") or rec.get("url") or "")
            seed = rec.get("seed_url") or self.seed_url

            # ✅ Prefer parsed http_status => never UNREACHABLE if parsed
            http_status = (card.m_extra or {}).get("http_status", None)
            if isinstance(http_status, int) and http_status > 0:
                if 200 <= http_status < 400:
                    activity_status = "ACTIVE"
                else:
                    activity_status = f"REACHABLE ({http_status})"
            else:
                activity_status = self._check_link_activity(url) if url else "UNREACHABLE"

            top_cat = self._top_category(categories) if isinstance(categories, list) else ""
            cat_block = self._format_categories(categories) if isinstance(categories, list) else str(categories)

            print("\n----------------------------------------")
            print(f"Date(raw): {date_raw_out}")
            print(f"Date(iso): {date_iso_out}")
            print(f"title: {title}")
            print(f"Author: {author}")
            print(f"Network Type: {card.m_network}")
            print(f"Link Status: {activity_status}")
            print(f"description: {str(rec.get('description') or '')[:300]}\n")

            print("SUMMARY:")
            print(summary if summary else "(empty)")

            print("\nCLASSIFICATION (zero-shot):")
            if top_cat:
                print(f"Top: {top_cat}")
            print(cat_block if cat_block else "(none)")

            print(f"\nseed url: {seed}")
            print(f"dump url: {url}")
            print("----------------------------------------\n")

    # ------- date parsing -------------------
    @staticmethod
    def _normalize_ordinal_suffix(s: str) -> str:
        if not s:
            return s
        return re.sub(r"(\d{1,2})(st|nd|rd|th)", r"\1", s)

    @classmethod
    def _parse_date(cls, s: str):
        if not s:
            return None
        s = s.strip()
        s = cls._normalize_ordinal_suffix(s)

        for fmt in (
            "%Y-%m-%d",
            "%B %d, %Y",
            "%b %d, %Y",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S",
            "%d %b %Y",
            "%d %B %Y",
        ):
            try:
                return datetime.strptime(s, fmt).date()
            except Exception:
                continue

        m = re.search(
            r"(\d{1,2})\s+"
            r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|"
            r"January|February|March|April|May|June|July|August|September|October|November|December)"
            r"\s+\d{4}",
            s,
        )
        if m:
            try:
                return datetime.strptime(m.group(0), "%d %B %Y").date()
            except Exception:
                try:
                    return datetime.strptime(m.group(0), "%d %b %Y").date()
                except Exception:
                    pass

        return None
