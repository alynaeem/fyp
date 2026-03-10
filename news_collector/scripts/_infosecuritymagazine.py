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


class _infosecuritymagazine(leak_extractor_interface, ABC):
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_infosecuritymagazine, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, developer_name: str = "Anonymous", developer_note: str = ""):
        if getattr(self, "_initialized", False):
            return
        self._initialized = True

        self._card_data: List[news_model] = []
        self._entity_data: List[entity_model] = []
        self._redis = redis_controller()
        self._is_crawled = False
        self._proxy = {}
        self._developer_name = developer_name
        self._developer_note = developer_note
        self.callback = None

        # data-breaches + news: dono ke liye 5 pages
        self._max_pages: int = 5
        # combined cap: data-breaches + news milake max 50 articles
        self._max_articles: Optional[int] = 50

        self._raw_index_key = "INFOSEC:raw_index"
        self._processed_index_key = "INFOSEC:processed_index"

        self._chromium_exe = None

        print("[INFOSEC] Initialized ✅ (pure Redis, no JSON)")

    # ---------------- lifecycle/config ----------------

    def init_callback(self, callback=None):
        self.callback = callback
        print("[INFOSEC] Callback set")

    def set_proxy(self, proxy: dict):
        self._proxy = proxy or {}
        print(f"[INFOSEC] Proxy configured: {self._proxy}")

    def set_limits(self, max_pages: Optional[int] = None, max_articles: Optional[int] = None):
        if max_pages is not None and max_pages >= 1:
            self._max_pages = int(max_pages)
        if max_articles is not None and max_articles >= 1:
            self._max_articles = int(max_articles)
        print(f"[INFOSEC] Limits → pages={self._max_pages}, articles={self._max_articles or '∞'}")

    def reset_cache(self):
        print("[INFOSEC] Resetting crawl timestamp …")
        self._redis_set("INFOSEC:last_crawl", "", 60)

    # ---------------- required interface props --------

    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "https://www.infosecurity-magazine.com/data-breaches/"

    @property
    def news_seed_url(self) -> str:
        return "https://www.infosecurity-magazine.com/news/"

    @property
    def base_url(self) -> str:
        return "https://www.infosecurity-magazine.com/"

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
        return "https://www.infosecurity-magazine.com/about/contact-us/"

    # ---------------- Redis helpers (no JSON) ---------

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

    # ---------------- small helpers -------------------

    @staticmethod
    def _sha1(text: str) -> str:
        return hashlib.sha1(text.encode("utf-8")).hexdigest()

    @staticmethod
    def _date_to_string(d) -> str:
        if d is None:
            return ""
        if isinstance(d, datetime):
            return d.strftime("%Y-%m-%d")
        return str(d)

    def _check_link_activity(self, url: str, timeout: int = 10) -> str:
        """
        HEAD sites often return 403/405. So:
        HEAD -> if blocked (403/405/429) => GET(stream=True)
        Returns: ACTIVE / INACTIVE(<status>) / UNREACHABLE
        """
        if not url:
            return "UNREACHABLE"

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/121.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        }

        try:
            r = requests.head(url, timeout=timeout, allow_redirects=True, headers=headers)
            if 200 <= r.status_code < 300:
                return "ACTIVE"

            if r.status_code in (403, 405, 429):
                rg = requests.get(url, timeout=timeout, allow_redirects=True, headers=headers, stream=True)
                try:
                    rg.close()
                except Exception:
                    pass
                if 200 <= rg.status_code < 300:
                    return "ACTIVE"
                return f"INACTIVE ({rg.status_code})"

            return f"INACTIVE ({r.status_code})"
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
            return f"{top.get('label','')} ({float(top.get('score',0.0)):.2f})"
        except Exception:
            return ""

    # ---------------- store raw card ------------------

    def _store_raw_card(self, card: news_model) -> str:
        """
        IMPORTANT:
        - generate AID once and store into card.m_extra["aid"] for NLP reuse
        """
        aid_source = card.m_url or (card.m_title or "") + str(datetime.now(timezone.utc).timestamp())
        aid = self._sha1(aid_source)

        card.m_extra = (card.m_extra or {})
        card.m_extra["aid"] = aid

        base = f"INFOSEC:raw:{aid}"

        self._redis_set(f"{base}:url", card.m_url)
        self._redis_set(f"{base}:title", card.m_title)
        self._redis_set(f"{base}:author", card.m_author)
        self._redis_set(f"{base}:date", self._date_to_string(card.m_leak_date))

        date_raw = ""
        content_html = ""
        content_type = ""
        iso_datetime = ""
        http_status = ""
        try:
            date_raw = (card.m_extra or {}).get("date_raw", "")  # type: ignore
            content_html = (card.m_extra or {}).get("content_html", "")  # type: ignore
            content_type = (card.m_extra or {}).get("content_type", "")  # type: ignore
            iso_datetime = (card.m_extra or {}).get("iso_datetime", "")  # type: ignore
            http_status = str((card.m_extra or {}).get("http_status", ""))  # type: ignore
        except Exception:
            pass

        self._redis_set(f"{base}:date_raw", date_raw)
        self._redis_set(f"{base}:iso_datetime", iso_datetime)
        self._redis_set(f"{base}:content_html", content_html)
        self._redis_set(f"{base}:content_type", content_type)
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

    # ---------------- store processed NLP ------------

    def _store_processed(self, aid: str, processed: dict):
        base = f"INFOSEC:processed:{aid}"

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

    # ---------------- HTTP session fallback ----------

    def _make_requests_session(self) -> requests.Session:
        print("[INFOSEC] Creating requests session …")
        s = requests.Session()
        s.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/121.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "close",
            }
        )

        server = (self._proxy or {}).get("server")
        if server:
            if str(server).lower().startswith("socks"):
                print(f"[INFOSEC] SOCKS proxy detected for requests ({server}) → IGNORING for requests fallback")
            else:
                s.proxies.update({"http": server, "https": server})
                print(f"[INFOSEC] requests will use proxy: {server}")

        return s

    # ---------------- Playwright helpers --------------

    def _launch_browser(self, p, use_proxy: bool) -> Tuple[object, object]:
        launch_kwargs = {"headless": False}
        if self._chromium_exe:
            launch_kwargs["executable_path"] = self._chromium_exe
        if use_proxy and (self._proxy or {}).get("server"):
            launch_kwargs["proxy"] = {"server": self._proxy["server"]}
            print(f"[INFOSEC] Launching Chromium WITH proxy: {self._proxy['server']}")
        else:
            print("[INFOSEC] Launching Chromium WITHOUT proxy")
        browser = p.chromium.launch(**launch_kwargs)
        context = browser.new_context()
        return browser, context

    # ---------------- meta extraction -----------------

    def _extract_meta(self, soup: BeautifulSoup) -> Tuple[str, str, str, str]:
        """
        returns: (author, date_raw_str, iso_datetime, content_type_label)
        """
        author = ""
        date_raw = ""
        iso_dt = ""
        content_type = ""

        time_el = (
            soup.select_one("#cphContent_pnlArticleTitlebar > div > div > span > time")
            or soup.select_one("#cphContent_pnlArticleTitlebar time")
            or soup.select_one("div.article-meta time")
            or soup.select_one("time[datetime]")
        )
        if time_el:
            date_raw = time_el.get_text(" ", strip=True)
            iso_dt = (time_el.get("datetime") or "").strip()

        type_el = soup.select_one("#cphContent_lnkContentType")
        if type_el:
            content_type = type_el.get_text(strip=True)

        author_el = (
            soup.select_one("#cphContent_pnlMainContent > div > div.article-authors > div > div > h3 > a")
            or soup.select_one(".article-authors h3 a")
            or soup.select_one("a[rel='author']")
        )
        if author_el:
            author = author_el.get_text(strip=True)

        return author, date_raw, iso_dt, content_type

    # ---------------- index helpers -------------------

    def _extract_breaches_links(self, soup: BeautifulSoup) -> Set[str]:
        links: Set[str] = set()
        grid = soup.select_one("#pnlMainContent > section:nth-child(3) > div > div.col-2-3 > div.grid")
        if not grid:
            grid = soup.select_one("div.grid")  # fallback
        if not grid:
            return links

        for a in grid.select("h2 a[href], h3 a[href], a[href*='/data-breaches/']"):
            href = a.get("href")
            if not href:
                continue
            full = urljoin(self.base_url, href)
            if full.startswith(self.base_url):
                links.add(full)
        return links

    def _extract_news_links(self, soup: BeautifulSoup) -> Set[str]:
        links: Set[str] = set()
        container = soup.select_one("#pnlMainContent > section > div > div.col-2-3") or soup
        for a in container.select("ol.webpages-list li.webpage-item h2.webpage-title a[href], a[href*='/news/']"):
            href = a.get("href")
            if not href:
                continue
            full = urljoin(self.base_url, href)
            if full.startswith(self.base_url) and "/news/" in full:
                links.add(full)
        return links

    def _data_breaches_page_url(self, page_no: int) -> str:
        if page_no <= 1:
            return self.seed_url
        return f"{self.seed_url}?page={page_no}"

    def _news_page_url(self, page_no: int) -> str:
        if page_no <= 1:
            return self.news_seed_url
        return f"{self.news_seed_url}page-{page_no}/"

    # ---------------- core crawling -------------------

    def run(self) -> dict:
        print("[INFOSEC] run() → Playwright first, then requests fallback")
        try:
            return self.parse_leak_data()
        except Exception as ex:
            print(f"[INFOSEC] Playwright failed ({ex}). Falling back to requests.")
            return self._run_with_requests()

    def parse_leak_data(self) -> dict:
        collected = 0
        all_links: Set[str] = set()

        with sync_playwright() as p:
            try:
                browser, context = self._launch_browser(p, use_proxy=True)
                page = context.new_page()
                first_url = self._data_breaches_page_url(1)
                print(f"[INFOSEC] Opening seed (proxy): {first_url}")
                page.goto(first_url, timeout=60000, wait_until="load")
            except Exception as ex:
                print(f"[INFOSEC] Proxy navigation failed: {ex}. Retrying without proxy …")
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
                first_url = self._data_breaches_page_url(1)
                print(f"[INFOSEC] Opening seed (no proxy): {first_url}")
                page.goto(first_url, timeout=60000, wait_until="load")

            # 1) DATA-BREACHES pages
            for page_no in range(1, self._max_pages + 1):
                list_url = self._data_breaches_page_url(page_no)
                print(f"[INFOSEC] Index (data-breaches) page {page_no}: {list_url}")
                page.goto(list_url, timeout=60000, wait_until="load")
                soup = BeautifulSoup(page.content(), "html.parser")
                page_links = self._extract_breaches_links(soup)
                all_links.update(page_links)
                print(f"[INFOSEC] data-breaches page {page_no}: +{len(page_links)} links (unique {len(all_links)})")

                if self._max_articles and len(all_links) >= self._max_articles:
                    break

            # 2) NEWS pages
            if not (self._max_articles and len(all_links) >= self._max_articles):
                for page_no in range(1, self._max_pages + 1):
                    list_url = self._news_page_url(page_no)
                    print(f"[INFOSEC] Index (news) page {page_no}: {list_url}")
                    page.goto(list_url, timeout=60000, wait_until="load")
                    soup = BeautifulSoup(page.content(), "html.parser")
                    page_links = self._extract_news_links(soup)
                    all_links.update(page_links)
                    print(f"[INFOSEC] news page {page_no}: +{len(page_links)} links (unique {len(all_links)})")

                    if self._max_articles and len(all_links) >= self._max_articles:
                        break

            visit_list = sorted(all_links)
            if self._max_articles:
                visit_list = visit_list[: self._max_articles]

            print(f"[INFOSEC] Visiting {len(visit_list)} articles after pagination (breaches + news)")
            for idx, link in enumerate(visit_list, 1):
                try:
                    print(f"[INFOSEC] Visiting [{idx}/{len(visit_list)}]: {link}")

                    resp = page.goto(link, timeout=60000, wait_until="load")
                    http_status = 0
                    try:
                        if resp is not None:
                            http_status = int(resp.status)
                    except Exception:
                        http_status = 0

                    s = BeautifulSoup(page.content(), "html.parser")

                    title_el = (
                        s.select_one("#cphContent_pnlArticleTitlebar > div > h1")
                        or s.select_one("#cphContent_pnlArticleTitlebar h1")
                        or s.select_one("h1")
                    )
                    title = title_el.get_text(strip=True) if title_el else "(No title)"

                    main_content = s.select_one("#cphContent_pnlMainContent") or s
                    entry_el = None
                    if main_content:
                        entry_el = main_content.select_one("div[id^='layout-']")
                        if not entry_el:
                            entry_el = main_content.select_one("div.article-body, div.page-content")

                    content_html = str(entry_el) if entry_el else ""
                    content_text = entry_el.get_text(" ", strip=True) if entry_el else ""
                    important_text = " ".join(content_text.split()[:150]) if content_text else ""

                    author, date_raw, iso_dt, content_type = self._extract_meta(s)
                    parsed_date = self._parse_date(date_raw or iso_dt)

                    network_type = helper_method.get_network_type(self.base_url)

                    card = news_model(
                        m_screenshot="",
                        m_title=title,
                        m_weblink=[link],
                        m_dumplink=[link],
                        m_url=link,
                        m_base_url=self.base_url,
                        m_content=content_text,
                        m_network=network_type,
                        m_important_content=important_text,
                        m_content_type=["news", content_type.lower()] if content_type else ["news"],
                        m_leak_date=parsed_date,
                        m_author=author,
                        m_description=important_text,
                        m_location="",
                        m_links=[link],
                        m_extra={
                            "date_raw": date_raw,
                            "iso_datetime": iso_dt,
                            "content_type": content_type,
                            "content_html": content_html,
                            "http_status": http_status,  # ✅ saved
                        },
                    )
                    entity = entity_model(m_scrap_file=self.__class__.__name__, m_team="infosecuritymagazine")

                    self._card_data.append(card)
                    self._entity_data.append(entity)
                    aid = self._store_raw_card(card)

                    collected += 1
                    print(f"[INFOSEC] ✅ Parsed ({collected}/{len(visit_list)}): {title[:90]}")
                    print(
                        f"[INFOSEC]    Author: {author or '(n/a)'} | "
                        f"Date: {date_raw or iso_dt or '(n/a)'} | "
                        f"Type: {content_type or '(n/a)'} | "
                        f"AID: {aid}"
                    )

                except Exception as ex:
                    print(f"[INFOSEC] ❌ Error parsing article {link}: {ex}")
                    continue

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

        self._nlp_enrich_and_store()
        self._is_crawled = True
        print(f"[INFOSEC] ✅ Done. Collected={collected}")
        return {
            "seed_url": self.seed_url,
            "articles_collected": collected,
            "developer_signature": self.developer_signature(),
        }

    # ---------------- requests fallback ----------------

    def _run_with_requests(self) -> dict:
        print("[INFOSEC] Fallback: requests-based crawl")
        collected = 0
        session = self._make_requests_session()

        all_links: Set[str] = set()

        # 1) data-breaches pages
        for page_no in range(1, self._max_pages + 1):
            list_url = self._data_breaches_page_url(page_no)
            print(f"[INFOSEC] Index (data-breaches, requests) page {page_no}: {list_url}")
            r = session.get(list_url, timeout=60)
            if r.status_code != 200:
                print(f"[INFOSEC] Stopped (data-breaches) at page {page_no}, status {r.status_code}")
                break
            soup = BeautifulSoup(r.text, "html.parser")
            page_links = self._extract_breaches_links(soup)
            all_links.update(page_links)
            print(f"[INFOSEC] data-breaches page {page_no} (requests): +{len(page_links)} links (unique {len(all_links)})")
            if self._max_articles and len(all_links) >= self._max_articles:
                break

        # 2) news pages
        if not (self._max_articles and len(all_links) >= self._max_articles):
            for page_no in range(1, self._max_pages + 1):
                list_url = self._news_page_url(page_no)
                print(f"[INFOSEC] Index (news, requests) page {page_no}: {list_url}")
                r = session.get(list_url, timeout=60)
                if r.status_code != 200:
                    print(f"[INFOSEC] Stopped (news) at page {page_no}, status {r.status_code}")
                    break
                soup = BeautifulSoup(r.text, "html.parser")
                page_links = self._extract_news_links(soup)
                all_links.update(page_links)
                print(f"[INFOSEC] news page {page_no} (requests): +{len(page_links)} links (unique {len(all_links)})")
                if self._max_articles and len(all_links) >= self._max_articles:
                    break

        visit_list = sorted(all_links)
        if self._max_articles:
            visit_list = visit_list[: self._max_articles]

        print(f"[INFOSEC] Visiting {len(visit_list)} articles (requests mode, breaches + news)")
        for idx, link in enumerate(visit_list, 1):
            try:
                art = session.get(link, timeout=60)
                http_status = art.status_code
                if http_status != 200:
                    continue
                s = BeautifulSoup(art.text, "html.parser")

                title_el = (
                    s.select_one("#cphContent_pnlArticleTitlebar > div > h1")
                    or s.select_one("#cphContent_pnlArticleTitlebar h1")
                    or s.select_one("h1")
                )
                title = title_el.get_text(strip=True) if title_el else "(No title)"

                main_content = s.select_one("#cphContent_pnlMainContent") or s
                entry_el = None
                if main_content:
                    entry_el = main_content.select_one("div[id^='layout-']")
                    if not entry_el:
                        entry_el = main_content.select_one("div.article-body, div.page-content")

                content_html = str(entry_el) if entry_el else ""
                content_text = entry_el.get_text(" ", strip=True) if entry_el else ""
                important_text = " ".join(content_text.split()[:150]) if content_text else ""

                author, date_raw, iso_dt, content_type = self._extract_meta(s)
                parsed_date = self._parse_date(date_raw or iso_dt)

                network_type = helper_method.get_network_type(self.base_url)

                card = news_model(
                    m_screenshot="",
                    m_title=title,
                    m_weblink=[link],
                    m_dumplink=[link],
                    m_url=link,
                    m_base_url=self.base_url,
                    m_content=content_text,
                    m_network=network_type,
                    m_important_content=important_text,
                    m_content_type=["news", content_type.lower()] if content_type else ["news"],
                    m_leak_date=parsed_date,
                    m_author=author,
                    m_description=important_text,
                    m_location="",
                    m_links=[link],
                    m_extra={
                        "date_raw": date_raw,
                        "iso_datetime": iso_dt,
                        "content_type": content_type,
                        "content_html": content_html,
                        "http_status": http_status,  # ✅ saved
                    },
                )
                entity = entity_model(m_scrap_file=self.__class__.__name__, m_team="infosecuritymagazine")

                self._card_data.append(card)
                self._entity_data.append(entity)
                aid = self._store_raw_card(card)

                collected += 1
                print(f"[INFOSEC] ✅ Parsed (requests) ({idx}/{len(visit_list)}): {title[:90]}")
                print(
                    f"[INFOSEC]    Author: {author or '(n/a)'} | "
                    f"Date: {date_raw or iso_dt or '(n/a)'} | "
                    f"Type: {content_type or '(n/a)'} | "
                    f"AID: {aid}"
                )

            except Exception as ex:
                print(f"[INFOSEC] ❌ Error (requests) parsing {link}: {ex}")
                continue

        self._nlp_enrich_and_store()
        self._is_crawled = True
        print(f"[INFOSEC] ✅ Done (requests). Collected={collected}")
        return {
            "seed_url": self.seed_url,
            "articles_collected": collected,
            "developer_signature": self.developer_signature(),
        }

    # ---------------- NLP enrichment (UPDATED prints) --

    def _nlp_enrich_and_store(self):
        try:
            print(f"[INFOSEC] NLP enrichment on {len(self._card_data)} records (no JSON)")
            for card in self._card_data:
                # raw human date + ISO
                try:
                    date_raw = (card.m_extra or {}).get("date_raw", "")  # type: ignore
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

                try:
                    processed = nlp.process_record(rec)
                except Exception as e:
                    print("[INFOSEC] NLP processing failed for record:", e)
                    processed = None

                # ✅ reuse same AID from raw store
                aid = ""
                try:
                    aid = (card.m_extra or {}).get("aid", "")  # type: ignore
                except Exception:
                    aid = ""
                if not aid:
                    aid = self._sha1(card.m_url or card.m_title)

                # ✅ link status: prefer stored http_status, fallback to checker
                try:
                    http_status = int((card.m_extra or {}).get("http_status", 0))  # type: ignore
                except Exception:
                    http_status = 0

                if 200 <= http_status < 300:
                    activity_status = "ACTIVE"
                elif http_status:
                    activity_status = f"INACTIVE ({http_status})"
                else:
                    activity_status = self._check_link_activity(card.m_url)

                network_type = card.m_network

                categories = []
                top_cat = ""
                cat_block = "(none)"

                if processed:
                    nlp._RedisIO().write_processed(aid, processed)
                    categories = processed.get("categories") or []
                    top_cat = self._top_category(categories)
                    cat_block = self._format_categories(categories)

                date_raw_out = str((processed or {}).get("date_raw") or rec.get("date") or "")
                date_iso_out = str((processed or {}).get("date") or rec.get("published") or "")
                title = str((processed or {}).get("title") or rec.get("title") or "")
                author = str((processed or {}).get("author") or rec.get("author") or "")
                description = str((processed or {}).get("description") or "")[:1200]
                summary = str((processed or {}).get("summary") or "")
                url = str((processed or {}).get("url") or rec.get("url") or "")
                seed = rec.get("seed_url") or self.seed_url

                print("\n----------------------------------------")
                print(f"Date(raw): {date_raw_out}")
                print(f"Date(iso): {date_iso_out}")
                print(f"title: {title}")
                print(f"Author: {author}")
                print(f"Network Type: {network_type}")
                print(f"Link Status: {activity_status}")

                if description:
                    print(f"description: {description}\n")

                print("SUMMARY:")
                print(summary if summary else "(empty)")

                print("\nCLASSIFICATION (zero-shot):")
                if top_cat:
                    print(f"Top: {top_cat}")
                print(cat_block)

                print(f"\nseed url: {seed}")
                print(f"dump url: {url}")
                print("----------------------------------------\n")

            print("[INFOSEC] NLP enrichment stored to Redis ✅ (no JSON)")

        except Exception as ex:
            print("[INFOSEC] ⚠ NLP enrichment error:", ex)

    # ---------------- date parsing --------------------

    @staticmethod
    def _parse_date(s: str):
        if not s:
            return None
        s = s.strip()
        if s.endswith("Z"):
            s = s.replace("Z", "+00:00")

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
