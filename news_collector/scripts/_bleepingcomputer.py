import re
import hashlib
import requests
from abc import ABC
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Set
from urllib.parse import urljoin

from bs4 import BeautifulSoup

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
from ._request_utils import create_direct_session
from .json_saver import save_collector_json


class _bleepingcomputer(leak_extractor_interface, ABC):
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_bleepingcomputer, cls).__new__(cls)
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
        self._max_pages: int = 5
        self._max_articles: Optional[int] = None  # None = no cap

        # Master index keys (pipe-delimited strings, NOT JSON)
        self._raw_index_key = "BLEEPING:raw_index"
        self._processed_index_key = "BLEEPING:processed_index"

        print("[BLEEPING] Initialized ✅ (pure Redis, pure requests, no browser)")

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
                "source": "bleepingcomputer",
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
            source="bleepingcomputer",
            seed_url=self.seed_url,
            cards=self._card_data,
            output_dir=output_dir,
            developer_signature=self.developer_signature(),
        )

    # ------- lifecycle/config hooks --------
    def init_callback(self, callback=None):
        self.callback = callback
        print("[BLEEPING] Callback set")

    def set_proxy(self, proxy: dict):
        """
        Proxy config is accepted but intentionally ignored
        (per requirement: 'proxy tor kardo' + pure requests).
        """
        self._proxy = proxy or {}
        print("[BLEEPING] Proxy config received but will NOT be used (requests without proxy).")

    def set_limits(self, max_pages: Optional[int] = None, max_articles: Optional[int] = None):
        if max_pages is not None and max_pages >= 1:
            self._max_pages = int(max_pages)
        if max_articles is not None and max_articles >= 1:
            self._max_articles = int(max_articles)
        print(f"[BLEEPING] Limits → pages={self._max_pages}, articles={self._max_articles or '∞'}")

    def reset_cache(self):
        print("[BLEEPING] Resetting crawl timestamp …")
        self._redis_set("BLEEPING:last_crawl", "", 60)

    # ------- required interface props -------
    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "https://www.bleepingcomputer.com/"

    @property
    def base_url(self) -> str:
        return "https://www.bleepingcomputer.com/"

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_threat_type=ThreatType.NEWS,
            m_fetch_proxy=FetchProxy.TOR,
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
        return "https://www.bleepingcomputer.com/contact/"

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

    # ------- helpers ----------
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
        External link checker only.
        Use carefully: many sites block HEAD/automated requests.
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

        # Try HEAD first
        try:
            r = requests.head(url, timeout=timeout, allow_redirects=True, headers=headers)
            if 200 <= r.status_code < 300:
                return "ACTIVE"
            if r.status_code in (403, 405):
                raise RuntimeError("HEAD blocked")
            return f"INACTIVE ({r.status_code})"
        except Exception:
            pass

        # Fallback to GET (stream)
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=True, headers=headers, stream=True)
            status = r.status_code
            r.close()
            if 200 <= status < 300:
                return "ACTIVE"
            return f"INACTIVE ({status})"
        except Exception:
            return "UNREACHABLE"

    # ------- pretty print helpers ----------
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

    # ------- store raw article (per-field keys) ---------
    def _store_raw_card(self, card: news_model) -> str:
        """
        IMPORTANT:
        - Generate AID once.
        - Store same AID into card.m_extra["aid"] so NLP stage reuses it.
        """
        aid_source = card.m_url or (card.m_title or "") + str(datetime.now(timezone.utc).timestamp())
        aid = self._sha1(aid_source)

        card.m_extra = (card.m_extra or {})
        card.m_extra["aid"] = aid

        base = f"BLEEPING:raw:{aid}"

        # scalar fields
        self._redis_set(f"{base}:url", card.m_url)
        self._redis_set(f"{base}:title", card.m_title)
        self._redis_set(f"{base}:author", card.m_author)
        self._redis_set(f"{base}:date", self._date_to_string(card.m_leak_date))

        # extras
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
        base = f"BLEEPING:processed:{aid}"

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

    # ------- HTTP session (pure requests, no proxy) ---
    def _make_requests_session(self) -> requests.Session:
        print("[BLEEPING] Creating requests session (no proxy) …")
        return create_direct_session(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/121.0.0.0 Safari/537.36"
        )

    # ------- author/date extraction ----------
    @staticmethod
    def _extract_author_date(soup: BeautifulSoup) -> Tuple[str, str]:
        author = ""
        date_raw = ""

        author_el = soup.select_one(
            "div.cz-news-story-title-section "
            "div.cz-news-title-left-area h6 a span span[itemprop='name']"
        )
        if not author_el:
            author_el = soup.select_one("span[itemprop='name']")
        if author_el:
            author = author_el.get_text(strip=True)

        date_el = soup.select_one("li.cz-news-date")
        if date_el:
            date_raw = date_el.get_text(strip=True)

        return author, date_raw

    # ------- index page helpers (pagination) ----
    def _extract_article_links_from_index(self, soup: BeautifulSoup) -> Set[str]:
        links: Set[str] = set()
        for a in soup.select("ul#bc-home-news-main-wrap li div.bc_latest_news_text h4 a[href]"):
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
        return urljoin(self.seed_url, f"page/{page_no}/")

    # ------- core crawling entrypoints (pure requests) ------------------
    def run(self) -> dict:
        print("[BLEEPING] run() → pure requests crawl (no Chromium)")
        return self.parse_leak_data()

    def parse_leak_data(self) -> dict:
        print("[BLEEPING] Starting requests-based crawl")
        collected = 0
        session = self._make_requests_session()

        all_links: Set[str] = set()

        # --- collect article links from index pages ---
        for page_no in range(1, self._max_pages + 1):
            list_url = self._page_url(page_no)
            try:
                r = session.get(list_url, timeout=60)
            except Exception as ex:
                print(f"[BLEEPING] Error fetching index page {page_no}: {ex}")
                break

            if not (200 <= r.status_code < 300):
                print(f"[BLEEPING] Stopped at page {page_no}, status {r.status_code}")
                break

            soup = BeautifulSoup(r.text, "html.parser")
            page_links = self._extract_article_links_from_index(soup)
            all_links.update(page_links)
            print(f"[BLEEPING] Index page {page_no} (requests): +{len(page_links)} links (unique {len(all_links)})")

            if self._max_articles and len(all_links) >= self._max_articles:
                break

        visit_list = sorted(all_links)
        if self._max_articles:
            visit_list = visit_list[: self._max_articles]

        print(f"[BLEEPING] Visiting {len(visit_list)} articles (requests mode)")

        # --- visit each article ---
        for idx, link in enumerate(visit_list, 1):
            try:
                art = session.get(link, timeout=60)
                http_status = art.status_code

                if not (200 <= http_status < 300):
                    print(f"[BLEEPING] Skipping {link}, status {http_status}")
                    continue

                s = BeautifulSoup(art.text, "html.parser")

                # title
                title_el = s.select_one(
                    "body div.bc_wrapper section.bc_main_content "
                    "div.col-md-8 div > article > div > h1"
                )
                if not title_el:
                    title_el = s.select_one("div.bc_main_content h1")
                title = title_el.get_text(strip=True) if title_el else "(No title)"

                # article body (HTML + text)
                body_el = s.select_one("div.articleBody")
                content_html = str(body_el) if body_el else ""
                content_text = body_el.get_text(" ", strip=True) if body_el else ""

                # important / description
                important_text = " ".join(content_text.split()[:150])

                # author + date
                author, date_raw = self._extract_author_date(s)
                parsed_date = self._parse_date(date_raw)

                card = news_model(
                    m_screenshot="",
                    m_title=title,
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
                        "content_html": content_html,
                        "http_status": http_status,  # ✅ store crawl-time status here
                    },
                )

                entity = entity_model(
                    m_scrap_file=self.__class__.__name__,
                    m_team="bleepingcomputer",
                )

                self._card_data.append(card)
                self._entity_data.append(entity)

                aid = self._store_raw_card(card)

                collected += 1
                print(f"[BLEEPING] ✅ Parsed (requests) ({idx}/{len(visit_list)}): {title[:90]}")
                print(f"[BLEEPING]    Author: {author or '(n/a)'} | Date: {date_raw or '(n/a)'} | AID: {aid}")

                if self.callback and self.callback():
                    self._card_data.clear()
                    self._entity_data.clear()

            except Exception as ex:
                print(f"[BLEEPING] ❌ Error (requests) parsing {link}: {ex}")
                continue

        # NLP enrichment
        self._nlp_enrich_and_store()

        self._is_crawled = True
        print(f"[BLEEPING] ✅ Done (requests). Collected={collected}")
        self._save_json(collected)
        return self._build_full_json_output(collected)

    # ------- NLP (pure Redis, no JSON) ----
    def _nlp_enrich_and_store(self):
        try:
            print(f"[BLEEPING] NLP enrichment on {len(self._card_data)} records (no JSON)")

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
                    print("[BLEEPING] NLP processing failed for record:", e)
                    processed = None

                # Reuse the SAME AID generated in _store_raw_card
                aid = ""
                try:
                    aid = (card.m_extra or {}).get("aid", "")  # type: ignore
                except Exception:
                    aid = ""
                if not aid:
                    aid = self._sha1(card.m_url or card.m_title)

                # ✅ compute link status WITHOUT hitting site again
                try:
                    http_status = int((card.m_extra or {}).get("http_status", 0))  # type: ignore
                except Exception:
                    http_status = 0

                if 200 <= http_status < 300:
                    activity_status = "ACTIVE"
                elif http_status:
                    activity_status = f"INACTIVE ({http_status})"
                else:
                    activity_status = "UNREACHABLE"

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
                    network_type = card.m_network

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

            print("[BLEEPING] NLP enrichment stored to Redis ✅ (no JSON)")

        except Exception as ex:
            print("[BLEEPING] ⚠ NLP enrichment error:", ex)

    # ------- date parsing -------------------
    @staticmethod
    def _parse_date(s: str):
        if not s:
            return None
        s = s.strip()
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

        m = re.search(r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2},\s+\d{4}", s)
        if m:
            try:
                return datetime.strptime(m.group(0), "%b %d, %Y").date()
            except Exception:
                pass
        return None
