import re
import hashlib
import requests
from abc import ABC
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Set
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

from crawler.common.crawler_instance.local_interface_model.leak.leak_extractor_interface import leak_extractor_interface
from crawler.common.crawler_instance.local_shared_model.data_model import entity_model
from crawler.common.crawler_instance.local_shared_model.data_model import news_model
from crawler.common.crawler_instance.local_shared_model import RuleModel, FetchProxy, FetchConfig, ThreatType
from crawler.common.crawler_instance.crawler_services.redis_manager.redis_controller import redis_controller
from crawler.common.crawler_instance.crawler_services.shared.helper_method import helper_method
from crawler.common.dev_signature import developer_signature
from . import nlp_processor as nlp
from .json_saver import save_collector_json



class _thehackernews(leak_extractor_interface, ABC):
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_thehackernews, cls).__new__(cls)
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

        # pagination limits
        self._max_pages: int = 5         # how many index pages to walk (homepage + 4 "Next Page")
        self._max_articles: Optional[int] = None  # None = no cap, else stop after N articles

        # Master index keys (pipe-delimited strings, NOT JSON)
        self._raw_index_key = "THN:raw_index"
        self._processed_index_key = "THN:processed_index"

        # optional: path to local Chromium
        self._chromium_exe = None  # let Playwright use its own managed Chromium on Linux

        print("[THN] Initialized ✅ (pure Redis, no JSON)")

    # ------- lifecycle/config hooks --------
    def init_callback(self, callback=None):
        self.callback = callback
        print("[THN] Callback set")

    def set_proxy(self, proxy: dict):
        self._proxy = proxy or {}
        print(f"[THN] Proxy configured: {self._proxy}")

    def set_limits(self, max_pages: Optional[int] = None, max_articles: Optional[int] = None):
        if max_pages is not None and max_pages >= 1:
            self._max_pages = int(max_pages)
        if max_articles is not None and max_articles >= 1:
            self._max_articles = int(max_articles)
        print(f"[THN] Limits → pages={self._max_pages}, articles={self._max_articles or '∞'}")

    def reset_cache(self):
        print("[THN] Resetting crawl timestamp …")
        self._redis_set("THN:last_crawl", "", 60)

    # ------- required interface props -------
    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "https://thehackernews.com/"

    @property
    def base_url(self) -> str:
        return "https://thehackernews.com/"

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_threat_type=ThreatType.NEWS,
            m_fetch_proxy=FetchProxy.NONE,
            m_fetch_config=FetchConfig.REQUESTS,
            m_resoource_block=False
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
        return "https://thehackernews.com/p/submit-news.html"

    # ------- JSON output helpers -----------------------------------------------
    def _build_full_json_output(self, collected: int) -> dict:
        """Serialise all collected card_data to a structured dict."""
        articles = []
        for card in self._card_data:
            articles.append({
                "title": card.m_title,
                "url": card.m_url,
                "author": card.m_author,
                "published_date": self._date_to_string(card.m_leak_date),
                "date_raw": (card.m_extra or {}).get("date_raw", ""),
                "description": card.m_description,
                "content": card.m_content,
                "network_type": card.m_network,
                "links": card.m_links or [],
                "weblink": card.m_weblink or [],
                "dumplink": card.m_dumplink or [],
                "seed_url": self.seed_url,
                "scraped_at": int(datetime.now(timezone.utc).timestamp()),
            })
        return {
            "meta": {
                "source": "thehackernews",
                "seed_url": self.seed_url,
                "articles_collected": collected,
                "developer_signature": self.developer_signature(),
            },
            "data": articles,
        }

    def _save_json(self, collected: int) -> str:
        """Persist collected data to a timestamped JSON file."""
        import os
        output_dir = os.path.join(os.path.dirname(__file__), "output")
        return save_collector_json(
            source="thehackernews",
            seed_url=self.seed_url,
            cards=self._card_data,
            output_dir=output_dir,
            developer_signature=self.developer_signature(),
        )

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

    def _check_link_activity(self, url: str, timeout: int = 10) -> str:
        """
        Returns: ACTIVE / INACTIVE(<status>) / UNREACHABLE
        """
        try:
            r = requests.head(url, timeout=timeout, allow_redirects=True)
            if 200 <= r.status_code < 300:
                return "ACTIVE"
            return f"INACTIVE ({r.status_code})"
        except Exception:
            return "UNREACHABLE"

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

    # ------- pretty print helpers (NEW) ----
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
            # sort high->low if not already
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
        aid = self._sha1(card.m_url or (card.m_title or "") + str(datetime.now(timezone.utc).timestamp()))
        base = f"THN:raw:{aid}"

        # scalar fields
        self._redis_set(f"{base}:url", card.m_url)
        self._redis_set(f"{base}:title", card.m_title)
        self._redis_set(f"{base}:author", card.m_author)
        self._redis_set(f"{base}:date", self._date_to_string(card.m_leak_date))
        date_raw = ""
        try:
            date_raw = (card.m_extra or {}).get("date_raw", "")  # type: ignore
        except Exception:
            date_raw = ""
        self._redis_set(f"{base}:date_raw", date_raw)

        self._redis_set(f"{base}:description", card.m_description)
        self._redis_set(f"{base}:location", card.m_location or "")
        self._redis_set(f"{base}:content", card.m_content or "")
        self._redis_set(f"{base}:network:type", card.m_network)
        self._redis_set(f"{base}:seed_url", self.seed_url)
        self._redis_set(f"{base}:rendered", "1")
        self._redis_set(f"{base}:scraped_at", int(datetime.now(timezone.utc).timestamp()))

        # lists (no JSON)
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
        base = f"THN:processed:{aid}"

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
        print("[THN] Creating requests session …")
        s = requests.Session()
        s.headers.update({"User-Agent": "THNCollector/1.0 (+contact)"})
        server = (self._proxy or {}).get("server")
        if server:
            s.proxies.update({"http": server, "https": server})
            print(f"[THN] requests will use proxy: {server}")
        return s

    # ------- Playwright helpers -------------
    def _launch_browser(self, p, use_proxy: bool) -> Tuple[object, object]:
        launch_kwargs = {"headless": False}
        if self._chromium_exe:
            launch_kwargs["executable_path"] = self._chromium_exe
        if use_proxy and (self._proxy or {}).get("server"):
            launch_kwargs["proxy"] = {"server": self._proxy["server"]}
            print(f"[THN] Launching Chromium WITH proxy: {self._proxy['server']}")
        else:
            print("[THN] Launching Chromium WITHOUT proxy")
        browser = p.chromium.launch(**launch_kwargs)
        context = browser.new_context()
        return browser, context

    # ------- robust author/date extraction --
    @staticmethod
    def _is_date_like(text: str) -> bool:
        if not text:
            return False
        t = text.strip()
        if re.match(r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2},\s+\d{4}$", t):
            return True
        if re.match(r"^\d{4}-\d{2}-\d{2}$", t):
            return True
        if re.match(r"^\d{1,2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}$", t):
            return True
        return False

    def _extract_author_date(self, soup: BeautifulSoup) -> Tuple[str, str]:
        """
        THN usually renders:
          <span class="p-author">
            <span class="author">Author Name</span>
            <span class="author">Jan 23, 2026</span>
          </span>
        But HTML wrappers vary (postmeta/clear/post-head etc).
        """
        author, date_raw = "", ""

        # 1) Most reliable: p-author block
        container = soup.select_one("span.p-author")
        if container:
            vals = [sp.get_text(strip=True) for sp in container.select("span.author") if sp.get_text(strip=True)]

            # de-dup while preserving order
            seen = set()
            vals2 = []
            for v in vals:
                if v not in seen:
                    seen.add(v)
                    vals2.append(v)

            # classify tokens
            for token in vals2:
                if not date_raw and self._is_date_like(token):
                    date_raw = token
                elif not author and token.lower() not in {"by", "-", "—"} and not self._is_date_like(token):
                    author = token

            # Common THN pattern: first author, second date
            if (not author or not date_raw) and len(vals2) >= 2:
                if not author and not self._is_date_like(vals2[0]):
                    author = vals2[0]
                if not date_raw and self._is_date_like(vals2[1]):
                    date_raw = vals2[1]

        # 2) Meta/rel author fallback
        if not author:
            a = soup.select_one("a[rel='author'], span.vcard a, span[itemprop='name']")
            if a:
                author = a.get_text(strip=True)

        # 3) Time tag fallback
        if not date_raw:
            t = soup.select_one("time[datetime]") or soup.select_one("time")
            if t:
                date_raw = (t.get("datetime") or t.get_text(strip=True) or "").strip()

        # 4) Normalize date (keep only 'Mon DD, YYYY' if embedded)
        if date_raw:
            m = re.search(r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2},\s+\d{4}", date_raw)
            if m:
                date_raw = m.group(0)

        return author, date_raw

    # ------- index page helpers (pagination) ----
    def _extract_article_links_from_index(self, soup: BeautifulSoup) -> Set[str]:
        links: Set[str] = set()
        selectors = [
            "a.story-link", "article h2 a", ".post-title a",
            "h2.post-title a", "a[href*='/20']", ".article-title a",
            "h3 a[href*='/']"
        ]
        for sel in selectors:
            for tag in soup.select(sel):
                href = tag.get("href")
                if not href:
                    continue
                full = urljoin(self.base_url, href)
                # only blog posts: /20YY/... ; skip sections that are not posts
                if full.startswith(self.base_url) and "/20" in full and not any(
                    bad in full for bad in ("tag", "search", "page", "/contact", "/p/", "/videos/", "/expert-insights/")
                ):
                    links.add(full)
        return links

    def _find_next_page_url(self, soup: BeautifulSoup) -> Optional[str]:
        # Prefer explicit "Next Page" or "Older Posts" anchors, else look for updated-max param
        for a in soup.select("a"):
            txt = (a.get_text(strip=True) or "").lower()
            href = a.get("href") or ""
            if not href:
                continue
            if ("next page" in txt) or ("older" in txt):
                return urljoin(self.base_url, href)
        a = soup.select_one("a[href*='updated-max=']")
        if a and a.get("href"):
            return urljoin(self.base_url, a.get("href"))
        return None

    # ------- core crawling ------------------
    def run(self) -> dict:
        print("[THN] run() → Playwright first, then requests fallback")
        try:
            return self.parse_leak_data()
        except Exception as ex:
            print(f"[THN] Playwright failed ({ex}). Falling back to requests.")
            return self._run_with_requests()

    def parse_leak_data(self) -> dict:
        collected = 0
        all_links: Set[str] = set()

        with sync_playwright() as p:
            # open seed
            try:
                browser, context = self._launch_browser(p, use_proxy=True)
                page = context.new_page()
                print(f"[THN] Opening seed (proxy): {self.seed_url}")
                page.goto(self.seed_url, timeout=60000, wait_until="load")
            except Exception as ex:
                print(f"[THN] Proxy navigation failed: {ex}. Retrying without proxy …")
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
                print(f"[THN] Opening seed (no proxy): {self.seed_url}")
                page.goto(self.seed_url, timeout=60000, wait_until="load")

            # paginate index pages
            current_url = self.seed_url
            for page_no in range(1, self._max_pages + 1):
                html = page.content()
                soup = BeautifulSoup(html, "html.parser")

                page_links = self._extract_article_links_from_index(soup)
                all_links.update(page_links)
                print(f"[THN] Index page {page_no}: found {len(page_links)} post links (unique total {len(all_links)})")

                # cap by article limit if set
                if self._max_articles and len(all_links) >= self._max_articles:
                    break

                next_url = self._find_next_page_url(soup)
                if not next_url:
                    print("[THN] No further pages found.")
                    break

                if next_url == current_url:
                    print("[THN] Next page URL same as current (loop guard).")
                    break

                current_url = next_url
                print(f"[THN] → Next Page: {current_url}")
                page.goto(current_url, timeout=60000, wait_until="load")

            # now visit each article
            visit_list = sorted(all_links)
            if self._max_articles:
                visit_list = visit_list[: self._max_articles]

            print(f"[THN] Visiting {len(visit_list)} articles after pagination")
            for idx, link in enumerate(visit_list, 1):
                try:
                    print(f"[THN] Visiting [{idx}/{len(visit_list)}]: {link}")
                    page.goto(link, timeout=60000, wait_until="load")
                    s = BeautifulSoup(page.content(), "html.parser")

                    # title
                    title_el = s.select_one("h1, .post-title, .entry-title, .article-title")
                    title = title_el.get_text(strip=True) if title_el else "(No title)"

                    # author + date
                    author, date_raw = self._extract_author_date(s)

                    # content
                    content_tag = None
                    for sel in ["div.articlebody", ".post-body", ".entry-content", ".article-content"]:
                        el = s.select_one(sel)
                        if el:
                            content_tag = el
                            break

                    full_text = ""
                    first_two_sentences = "Content not found."
                    if content_tag:
                        full_text = content_tag.get_text(" ", strip=True).replace("\n", " ")
                        parts = re.split(r"(?<=[.!?])\s+", full_text)
                        first_two = parts[:2]
                        first_two_sentences = " ".join(first_two).strip() or first_two_sentences

                    parsed_date = self._parse_date(date_raw)

                    card = news_model(
                        m_screenshot="",
                        m_title=title,
                        m_weblink=[link],
                        m_dumplink=[link],
                        m_url=link,
                        m_base_url=self.base_url,
                        m_content=full_text,
                        m_network=helper_method.get_network_type(self.base_url),
                        m_important_content=first_two_sentences,
                        m_content_type=["news"],
                        m_leak_date=parsed_date,
                        m_author=author,
                        m_description=first_two_sentences,
                        m_location="",
                        m_links=[link],
                        m_extra={"date_raw": date_raw}
                    )
                    entity = entity_model(m_scrap_file=self.__class__.__name__, m_team="hackernews live")

                    self._card_data.append(card)
                    self._entity_data.append(entity)
                    aid = self._store_raw_card(card)

                    collected += 1
                    print(f"[THN] ✅ Parsed ({collected}/{len(visit_list)}): {title[:80]}")
                    print(f"[THN]    Author: {author or '(n/a)'} | Date: {date_raw or '(n/a)'} | AID: {aid}")

                except Exception as ex:
                    print(f"[THN] ❌ Error parsing article {link}: {ex}")
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

        # NLP enrichment (stores processed per-field, no JSON)
        self._nlp_enrich_and_store()

        self._is_crawled = True
        print(f"[THN] ✅ Done. Collected={collected}")
        self._save_json(collected)
        return self._build_full_json_output(collected)

    def _run_with_requests(self) -> dict:
        print("[THN] Fallback: requests-based crawl")
        collected = 0
        session = self._make_requests_session()

        # paginate index pages
        all_links: Set[str] = set()
        current_url = self.seed_url

        for page_no in range(1, self._max_pages + 1):
            r = session.get(current_url, timeout=60)
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "html.parser")

            page_links = self._extract_article_links_from_index(soup)
            all_links.update(page_links)
            print(f"[THN] Index page {page_no} (requests): +{len(page_links)} links (unique {len(all_links)})")

            if self._max_articles and len(all_links) >= self._max_articles:
                break

            next_url = self._find_next_page_url(soup)
            if not next_url or next_url == current_url:
                print("[THN] No further pages (requests).")
                break
            current_url = next_url

        visit_list = sorted(all_links)
        if self._max_articles:
            visit_list = visit_list[: self._max_articles]

        print(f"[THN] Visiting {len(visit_list)} articles (requests mode)")
        for idx, link in enumerate(visit_list, 1):
            try:
                art = session.get(link, timeout=60)
                art.raise_for_status()
                s = BeautifulSoup(art.text, "html.parser")

                title_el = s.select_one("h1, .post-title, .entry-title, .article-title")
                title = title_el.get_text(strip=True) if title_el else "(No title)"

                author, date_raw = self._extract_author_date(s)

                content_tag = None
                for sel in ["div.articlebody", ".post-body", ".entry-content", ".article-content"]:
                    el = s.select_one(sel)
                    if el:
                        content_tag = el
                        break

                full_text = ""
                first_two_sentences = "Content not found."
                if content_tag:
                    full_text = content_tag.get_text(" ", strip=True).replace("\n", " ")
                    parts = re.split(r"(?<=[.!?])\s+", full_text)
                    first_two = parts[:2]
                    first_two_sentences = " ".join(first_two).strip() or first_two_sentences

                parsed_date = self._parse_date(date_raw)

                card = news_model(
                    m_screenshot="",
                    m_title=title,
                    m_weblink=[link],
                    m_dumplink=[link],
                    m_url=link,
                    m_base_url=self.base_url,
                    m_content=full_text,
                    m_network=helper_method.get_network_type(self.base_url),
                    m_important_content=first_two_sentences,
                    m_content_type=["news"],
                    m_leak_date=parsed_date,
                    m_author=author,
                    m_description=first_two_sentences,
                    m_location="",
                    m_links=[link],
                    m_extra={"date_raw": date_raw}
                )
                entity = entity_model(m_scrap_file=self.__class__.__name__, m_team="hackernews live")

                self._card_data.append(card)
                self._entity_data.append(entity)
                aid = self._store_raw_card(card)

                collected += 1
                print(f"[THN] ✅ Parsed (requests) ({idx}/{len(visit_list)}): {title[:80]}")
                print(f"[THN]    Author: {author or '(n/a)'} | Date: {date_raw or '(n/a)'} | AID: {aid}")

            except Exception as ex:
                print(f"[THN] ❌ Error (requests) parsing {link}: {ex}")
                continue

        self._nlp_enrich_and_store()
        self._is_crawled = True
        print(f"[THN] ✅ Done (requests). Collected={collected}")
        self._save_json(collected)
        return self._build_full_json_output(collected)

    # ------- NLP (pure Redis, no JSON) ----
    def _nlp_enrich_and_store(self):
        try:
            print(f"[THN] NLP enrichment on {len(self._card_data)} records (no JSON)")
            for card in self._card_data:
                date_raw = ""
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
                    "scraped_at": int(datetime.now(timezone.utc).timestamp())
                }
                try:
                    processed = nlp.process_record(rec)
                except Exception as e:
                    print("[THN] NLP processing failed for record:", e)
                    processed = None

                #aid = self._sha1(card.m_url or card.m_title)
                aid = self._store_raw_card(card)
                card.m_extra = (card.m_extra or {})
                card.m_extra["aid"] = aid

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
                    network_type = card.m_network  # already set during crawl
                    activity_status = self._check_link_activity(url) if url else "UNREACHABLE"

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

            print("[THN] NLP enrichment stored to Redis ✅ (no JSON)")

        except Exception as ex:
            print("[THN] ⚠ NLP enrichment error:", ex)

    # ------- date parsing -------------------
    @staticmethod
    def _parse_date(s: str):
        if not s:
            return None
        s = s.strip()
        for fmt in ("%Y-%m-%d", "%B %d, %Y", "%b %d, %Y", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%d %b %Y", "%d %B %Y"):
            try:
                return datetime.strptime(s, fmt).date()
            except Exception:
                continue
        m = re.search(r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2},\s+\d{4}", s)
        if m:
            try:
                return datetime.strptime(m.group(0), "%b %d, %Y").date()
            except Exception:
                pass
        return None
