import re
import json
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


class _csocybercrime(leak_extractor_interface, ABC):
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_csocybercrime, cls).__new__(cls)
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

        # Crawl limits
        self._max_pages: int = 1
        self._max_articles: Optional[int] = None

        # Master index keys (pipe-delimited strings, NOT JSON)
        self._raw_index_key = "CSO:raw_index"
        self._processed_index_key = "CSO:processed_index"

        # optional: path to local Chromium
        self._chromium_exe = None  # let Playwright use its own managed Chromium on Linux

        print("[CSO] Initialized ✅ (pure Redis, no JSON)")

    # ------- lifecycle/config --------
    def init_callback(self, callback=None):
        self.callback = callback
        print("[CSO] Callback set")

    def set_proxy(self, proxy: dict):
        self._proxy = proxy or {}
        print(f"[CSO] Proxy configured: {self._proxy}")

    def set_limits(self, max_pages: Optional[int] = None, max_articles: Optional[int] = None):
        if max_pages is not None and max_pages >= 1:
            self._max_pages = int(max_pages)
        if max_articles is not None and max_articles >= 1:
            self._max_articles = int(max_articles)
        print(f"[CSO] Limits → pages={self._max_pages}, articles={self._max_articles or '∞'}")

    def reset_cache(self):
        print("[CSO] Resetting crawl timestamp …")
        self._redis_set("CSO:last_crawl", "", 60)

    # ------- required interface props -------
    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "https://www.csoonline.com/uk/cybercrime/"

    @property
    def base_url(self) -> str:
        return "https://www.csoonline.com"

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
        return "https://www.csoonline.com/contact-us/"

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

    # ------- pretty print helpers (ADDED) ----
    @staticmethod
    def _format_categories(categories) -> str:
        """
        categories expected like:
        [{"label":"ransomware","score":0.92}, ...]
        """
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

    # ------- store raw article (per-field keys) ---------
    def _store_raw_card(self, card: news_model) -> str:
        """
        IMPORTANT:
        - Generate AID once
        - Store it in card.m_extra["aid"] so NLP stage reuses same AID
        """
        aid_source = card.m_url or (card.m_title or "") + str(datetime.now(timezone.utc).timestamp())
        aid = self._sha1(aid_source)

        card.m_extra = (card.m_extra or {})
        card.m_extra["aid"] = aid

        base = f"CSO:raw:{aid}"

        self._redis_set(f"{base}:url", card.m_url)
        self._redis_set(f"{base}:title", card.m_title)
        self._redis_set(f"{base}:author", card.m_author)
        self._redis_set(f"{base}:date", self._date_to_string(card.m_leak_date))

        date_raw = ""
        content_html = ""
        http_status = ""
        try:
            date_raw = (card.m_extra or {}).get("date_raw", "")  # type: ignore
            content_html = (card.m_extra or {}).get("content_html", "")  # type: ignore
            http_status = str((card.m_extra or {}).get("http_status", ""))  # type: ignore
        except Exception:
            date_raw = ""
            content_html = ""
            http_status = ""

        self._redis_set(f"{base}:date_raw", date_raw)
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
        base = f"CSO:processed:{aid}"

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
        print("[CSO] Creating requests session …")
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
            s.proxies.update({"http": server, "https": server})
            print(f"[CSO] requests will use proxy: {server}")
        return s

    # ------- Playwright helpers -------------
    def _launch_browser(self, p, use_proxy: bool) -> Tuple[object, object]:
        launch_kwargs = {"headless": True}
        if self._chromium_exe:
            launch_kwargs["executable_path"] = self._chromium_exe
        if use_proxy and (self._proxy or {}).get("server"):
            launch_kwargs["proxy"] = {"server": self._proxy["server"]}
            print(f"[CSO] Launching Chromium WITH proxy: {self._proxy['server']}")
        else:
            print("[CSO] Launching Chromium WITHOUT proxy")
        browser = p.chromium.launch(**launch_kwargs)
        context = browser.new_context()
        return browser, context

    # ------- author/date extraction ----------
    @staticmethod
    def _is_date_like(text: str) -> bool:
        if not text:
            return False
        t = text.strip()
        if re.match(r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2},\s+\d{4}$", t, re.IGNORECASE):
            return True
        if re.match(r"^\d{4}-\d{2}-\d{2}", t):
            return True
        if re.match(
            r"^\d{1,2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}$",
            t,
            re.IGNORECASE,
        ):
            return True
        return False

    def _extract_author_date(self, soup: BeautifulSoup) -> Tuple[str, str]:
        date_raw = ""
        author = ""

        time_el = soup.select_one("time[datetime]")
        if time_el:
            date_raw = (time_el.get("datetime") or time_el.get_text(strip=True) or "").strip()

        if not date_raw:
            m_pub = soup.select_one("meta[property='article:published_time']")
            if m_pub and m_pub.get("content"):
                date_raw = m_pub.get("content").strip()

        if not date_raw:
            m_pub2 = soup.select_one("meta[name='pubdate']")
            if m_pub2 and m_pub2.get("content"):
                date_raw = m_pub2.get("content").strip()

        if not date_raw:
            for script in soup.select("script[type='application/ld+json']"):
                try:
                    data = json.loads(script.string or "")
                except Exception:
                    continue
                items = data if isinstance(data, list) else [data]
                for obj in items:
                    if not isinstance(obj, dict):
                        continue
                    cand = obj.get("datePublished") or obj.get("dateModified")
                    if cand and isinstance(cand, str):
                        date_raw = cand.strip()
                        break
                if date_raw:
                    break

        if not date_raw:
            for el in soup.select(
                "#primary div.card__info span, "
                ".article-hero .card__info span, "
                "div.card__info.card__info--light span, "
                ".card__info span"
            ):
                txt = el.get_text(strip=True)
                if txt and self._is_date_like(txt):
                    date_raw = txt
                    break

        if date_raw:
            date_raw = re.sub(r"\bSept\b", "Sep", date_raw, flags=re.IGNORECASE)
            m = re.search(
                r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},\s+\d{4}",
                date_raw,
                re.IGNORECASE,
            )
            if m:
                date_raw = m.group(0).title()

        a_el = soup.select_one(
            "a[rel='author'], .byline a, span.byline a, .author a, span.author a, "
            "a[href*='/author/'], .card__info a[rel='author']"
        )
        if a_el:
            author = a_el.get_text(strip=True)
        if not author:
            m_auth = soup.select_one("meta[name='author']")
            if m_auth and m_auth.get("content"):
                author = m_auth.get("content").strip()

        return author, date_raw

    # ------- index page helpers (pagination) ----
    def _extract_article_links_from_index(self, soup: BeautifulSoup) -> Set[str]:
        links: Set[str] = set()
        selectors = [
            "div.river-well.article h3 a",
            "h3 a[href*='/article/']",
            "a[href*='/cybercrime/']",
            ".content-listing a",
            "a[href*='/article/']",
        ]
        for sel in selectors:
            for el in soup.select(sel):
                href = el.get("href")
                if not href:
                    continue
                full = urljoin(self.base_url, href)
                if "/article/" in full and full.startswith(self.base_url):
                    links.add(full)
        return links

    def _page_url(self, page_no: int) -> str:
        if page_no <= 1:
            return self.seed_url
        return urljoin(self.seed_url, f"page/{page_no}/")

    # ------- core crawling ------------------
    def run(self) -> dict:
        print("[CSO] run() → Playwright first, then requests fallback")
        try:
            return self.parse_leak_data()
        except Exception as ex:
            print(f"[CSO] Playwright failed ({ex}). Falling back to requests.")
            return self._run_with_requests()

    def parse_leak_data(self) -> dict:
        collected = 0
        all_links: Set[str] = set()

        with sync_playwright() as p:
            # Playwright doesn't support socks5h:// (needed for Tor DNS), so skip proxy
            browser, context = self._launch_browser(p, use_proxy=False)
            page = context.new_page()
            first_url = self._page_url(1)
            print(f"[CSO] Opening seed: {first_url}")
            page.goto(first_url, timeout=70000, wait_until="load")

            for page_no in range(1, self._max_pages + 1):
                html = page.content()
                soup = BeautifulSoup(html, "html.parser")
                page_links = self._extract_article_links_from_index(soup)
                all_links.update(page_links)
                print(f"[CSO] Index page {page_no}: +{len(page_links)} links (unique {len(all_links)})")

                if self._max_articles and len(all_links) >= self._max_articles:
                    break
                if page_no >= self._max_pages:
                    break
                next_url = self._page_url(page_no + 1)
                print(f"[CSO] → Next Page: {next_url}")
                page.goto(next_url, timeout=70000, wait_until="load")

            visit_list = sorted(all_links)
            if self._max_articles:
                visit_list = visit_list[: self._max_articles]

            print(f"[CSO] Visiting {len(visit_list)} articles after pagination")
            for idx, link in enumerate(visit_list, 1):
                try:
                    print(f"[CSO] Visiting [{idx}/{len(visit_list)}]: {link}")
                    page.goto(link, timeout=70000, wait_until="load")
                    s = BeautifulSoup(page.content(), "html.parser")

                    title_el = s.select_one("h1")
                    title = title_el.get_text(strip=True) if title_el else "(No title)"

                    entry_el = (
                        s.select_one("div.article-content")
                        or s.select_one("article .content")
                        or s.select_one("div.content")
                        or s.select_one("article")
                    )
                    content_html = str(entry_el) if entry_el else ""
                    if entry_el:
                        for bad in entry_el.select("aside, nav, form, script, style, iframe"):
                            bad.extract()
                        content_html = str(entry_el)
                        content_text = entry_el.get_text(" ", strip=True)
                    else:
                        paras = [p.get_text(" ", strip=True) for p in s.select("p")]
                        paras = [p for p in paras if p and len(p) > 25]
                        content_text = " ".join(paras[:8])

                    if not content_text:
                        continue

                    author, date_raw = self._extract_author_date(s)
                    parsed_date = self._parse_date(date_raw)

                    paragraphs = [p.strip() for p in content_text.split(". ") if p.strip()]
                    lead = ". ".join(paragraphs[:2]) if paragraphs else content_text[:240]

                    # ✅ get network type once (for printing + storing)
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
                        m_important_content=lead,
                        m_content_type=["news"],
                        m_leak_date=parsed_date,
                        m_author=author,
                        m_description=lead,
                        m_location="",
                        m_links=[link],
                        m_extra={"date_raw": date_raw, "content_html": content_html},
                    )
                    entity = entity_model(
                        m_scrap_file=self.__class__.__name__,
                        m_team="CSO Cybercrime Section",
                    )

                    self._card_data.append(card)
                    self._entity_data.append(entity)
                    aid = self._store_raw_card(card)

                    collected += 1
                    print(f"[CSO] ✅ Parsed ({collected}/{len(visit_list)}): {title[:90]}")
                    print(f"[CSO]    Author: {author or '(n/a)'} | Date: {date_raw or '(n/a)'} | AID: {aid}")

                except Exception as ex:
                    print(f"[CSO] ❌ Error parsing article {link}: {ex}")
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

        # NLP enrichment
        self._nlp_enrich_and_store()

        # ✅ mark crawled BEFORE return
        self._is_crawled = True
        print(f"[CSO] ✅ Done. Collected={collected}")

        # Optional UI payload
        articles_for_ui = []
        for aid in self._redis_get(self._raw_index_key, "").split("|"):
            if not aid:
                continue
            articles_for_ui.append(
                {
                    "id": aid,
                    "title": self._redis_get(f"CSO:raw:{aid}:title"),
                    "content": self._redis_get(f"CSO:raw:{aid}:content"),
                    "author": self._redis_get(f"CSO:raw:{aid}:author"),
                    "date": self._redis_get(f"CSO:raw:{aid}:date"),
                }
            )

        return {
            "seed_url": self.seed_url,
            "articles_collected": collected,
            "developer_signature": self.developer_signature(),
            "articles": articles_for_ui,
        }

    def _run_with_requests(self) -> dict:
        print("[CSO] Fallback: requests-based crawl")
        collected = 0
        session = self._make_requests_session()

        all_links: Set[str] = set()
        for page_no in range(1, self._max_pages + 1):
            list_url = self._page_url(page_no)
            r = session.get(list_url, timeout=60)
            if r.status_code != 200:
                print(f"[CSO] Stopped at page {page_no}, status {r.status_code}")
                break
            soup = BeautifulSoup(r.text, "html.parser")
            page_links = self._extract_article_links_from_index(soup)
            all_links.update(page_links)
            print(f"[CSO] Index page {page_no} (requests): +{len(page_links)} links (unique {len(all_links)})")
            if self._max_articles and len(all_links) >= self._max_articles:
                break

        visit_list = sorted(all_links)
        if self._max_articles:
            visit_list = visit_list[: self._max_articles]

        print(f"[CSO] Visiting {len(visit_list)} articles (requests mode)")
        for idx, link in enumerate(visit_list, 1):
            try:
                art = session.get(link, timeout=60)
                http_status = art.status_code
                if not (200 <= http_status < 300):
                    continue

                s = BeautifulSoup(art.text, "html.parser")

                title_el = s.select_one("h1")
                title = title_el.get_text(strip=True) if title_el else "(No title)"

                entry_el = (
                    s.select_one("div.article-content")
                    or s.select_one("article .content")
                    or s.select_one("div.content")
                    or s.select_one("article")
                )
                content_html = str(entry_el) if entry_el else ""
                if entry_el:
                    for bad in entry_el.select("aside, nav, form, script, style, iframe"):
                        bad.extract()
                    content_html = str(entry_el)
                    content_text = entry_el.get_text(" ", strip=True)
                else:
                    paras = [p.get_text(" ", strip=True) for p in s.select("p")]
                    paras = [p for p in paras if p and len(p) > 25]
                    content_text = " ".join(paras[:8])

                if not content_text:
                    continue

                author, date_raw = self._extract_author_date(s)
                parsed_date = self._parse_date(date_raw)

                paragraphs = [p.strip() for p in content_text.split(". ") if p.strip()]
                lead = ". ".join(paragraphs[:2]) if paragraphs else content_text[:240]

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
                    m_important_content=lead,
                    m_content_type=["news"],
                    m_leak_date=parsed_date,
                    m_author=author,
                    m_description=lead,
                    m_location="",
                    m_links=[link],
                    m_extra={
                        "date_raw": date_raw,
                        "content_html": content_html,
                        "http_status": http_status,  # ✅ store crawl-time status
                    },
                )
                entity = entity_model(
                    m_scrap_file=self.__class__.__name__,
                    m_team="CSO Cybercrime Section",
                )

                self._card_data.append(card)
                self._entity_data.append(entity)
                aid = self._store_raw_card(card)

                collected += 1
                print(f"[CSO] ✅ Parsed (requests) ({idx}/{len(visit_list)}): {title[:90]}")
                print(f"[CSO]    Author: {author or '(n/a)'} | Date: {date_raw or '(n/a)'} | AID: {aid}")

            except Exception as ex:
                print(f"[CSO] ❌ Error (requests) parsing article {link}: {ex}")
                continue

        self._nlp_enrich_and_store()
        self._is_crawled = True
        print(f"[CSO] ✅ Done (requests). Collected={collected}")
        return {
            "seed_url": self.seed_url,
            "articles_collected": collected,
            "developer_signature": self.developer_signature(),
        }

    # ------- NLP (pure Redis, no JSON) ----
    def _nlp_enrich_and_store(self):
        try:
            print(f"[CSO] NLP enrichment on {len(self._card_data)} records (no JSON)")
            for card in self._card_data:
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
                    print("[CSO] NLP processing failed for record:", e)
                    processed = None

                # ✅ reuse same AID if present
                aid = ""
                try:
                    aid = (card.m_extra or {}).get("aid", "")  # type: ignore
                except Exception:
                    aid = ""
                if not aid:
                    aid = self._sha1(card.m_url or card.m_title)

                # ✅ network type for printing
                network_type = card.m_network

                # ✅ Link Status without re-requesting (use stored http_status when available)
                try:
                    http_status = int((card.m_extra or {}).get("http_status", 0))  # type: ignore
                except Exception:
                    http_status = 0

                if 200 <= http_status < 300:
                    activity_status = "ACTIVE"
                elif http_status:
                    activity_status = f"INACTIVE ({http_status})"
                else:
                    # Playwright path may not have http_status; don't spam requests here
                    activity_status = "ACTIVE"

                if processed:
                    nlp._RedisIO().write_processed(aid, processed)

                    date_raw_out = str(processed.get("date_raw") or rec.get("date") or "")
                    date_iso_out = str(processed.get("date") or rec.get("published") or "")
                    title = str(processed.get("title") or rec.get("title") or "")
                    author = str(processed.get("author") or rec.get("author") or "")
                    description = str(processed.get("description") or "")[:1200]
                    summary = str(processed.get("summary") or "")
                    url = str(processed.get("url") or rec.get("url") or "")
                    seed = rec.get("seed_url") or self.seed_url

                    categories = processed.get("categories") or []
                    top_cat = self._top_category(categories)
                    cat_block = self._format_categories(categories)

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

            print("[CSO] NLP enrichment stored to Redis ✅ (no JSON)")

        except Exception as ex:
            print("[CSO] ⚠ NLP enrichment error:", ex)

    # ------- date parsing -------------------
    @staticmethod
    def _parse_date(s: str):
        if not s:
            return None
        s = s.strip()
        s = re.sub(r"\bSept\b", "Sep", s, flags=re.IGNORECASE)
        for fmt in (
            "%Y-%m-%d",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%B %d, %Y",
            "%b %d, %Y",
            "%d %b %Y",
            "%d %B %Y",
        ):
            try:
                if fmt == "%Y-%m-%dT%H:%M:%SZ" and re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$", s):
                    s_iso = s + "Z"
                    return datetime.strptime(s_iso, fmt).date()
                return datetime.strptime(s, fmt).date()
            except Exception:
                continue
        m = re.search(r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2},\s+\d{4}", s, re.IGNORECASE)
        if m:
            try:
                return datetime.strptime(m.group(0).title(), "%b %d, %Y").date()
            except Exception:
                pass
        return None
