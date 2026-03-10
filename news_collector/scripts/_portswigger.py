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


class _portswigger(leak_extractor_interface, ABC):
    """
    PortSwigger Research Articles collector
    Output format: THN-style (visit/parsed first), then NLP enrichment (per article).
    Storage: pure Redis (flattened keys), no JSON.
    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_portswigger, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, developer_name: str = "Anonymous", developer_note: str = ""):
        if getattr(self, "_initialized", False):
            return
        self._initialized = True

        self._tag = "[THN]"  # ✅ keep THN-style tag as you requested

        self._card_data: List[news_model] = []
        self._entity_data: List[entity_model] = []
        self._redis = redis_controller()
        self._is_crawled = False
        self._proxy = {}
        self._developer_name = developer_name
        self._developer_note = developer_note
        self.callback = None

        self._max_pages: int = 1
        self._max_articles: Optional[int] = None

        self._raw_index_key = "PORTSWIGGER:raw_index"
        self._processed_index_key = "PORTSWIGGER:processed_index"

        # Linux: None so Playwright uses managed Chromium
        self._chromium_exe = None

        print(f"{self._tag} Initialized ✅ (pure Redis, no JSON)")

    # ---------------- lifecycle/config hooks ----------------
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
        self._redis_set("PORTSWIGGER:last_crawl", "", 60)

    # ---------------- required interface props ----------------
    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "https://portswigger.net/research/articles"

    @property
    def base_url(self) -> str:
        return "https://portswigger.net/"

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
        return "https://portswigger.net/contact"

    # ---------------- Redis helpers (NO JSON) ----------------
    def _redis_get(self, key: str, default: str = "") -> str:
        try:
            val = self._redis.invoke_trigger(1, [key, default, None])
            if val is None:
                return default
            return str(val)
        except Exception:
            return default

    def _build_full_json_output(self, collected: int) -> dict:
        """
        Build complete JSON output with all article fields.
        """
        articles = []

        for card in self._card_data:
            articles.append({
                "title": card.m_title,
                "url": card.m_url,
                "author": card.m_author,
                "published_date": self._date_to_string(card.m_leak_date),
                "description": card.m_description,
                "content": card.m_content,
                "network_type": card.m_network,
                "links": card.m_links or [],
                "weblink": card.m_weblink or [],
                "dumplink": card.m_dumplink or [],
                "seed_url": self.seed_url,
                "scraped_at": int(datetime.now(timezone.utc).timestamp())
            })

        return {
            "meta": {
                "source": "portswigger",
                "seed_url": self.seed_url,
                "articles_collected": collected,
                "developer_signature": self.developer_signature(),
            },
            "data": articles
        }
    def _redis_set(self, key: str, value: object, expiry: Optional[int] = None):
        val = "" if value is None else str(value)
        self._redis.invoke_trigger(2, [key, val, expiry])

    def _append_index(self, index_key: str, item_id: str):
        cur = self._redis_get(index_key, "")
        parts = [p for p in cur.split("|") if p] if cur else []
        if item_id not in parts:
            parts.append(item_id)
            self._redis_set(index_key, "|".join(parts), expiry=None)

    # ---------------- misc helpers ----------------
    @staticmethod
    def _sha1(text: str) -> str:
        return hashlib.sha1(text.encode("utf-8")).hexdigest()

    @staticmethod
    def _date_to_string(d) -> str:
        if d is None:
            return ""
        if hasattr(d, "strftime"):
            try:
                return d.strftime("%Y-%m-%d")
            except Exception:
                return str(d)
        return str(d)

    @staticmethod
    def _date_to_thn_string(d) -> str:
        if not d:
            return "(n/a)"
        try:
            # d is likely date()
            return d.strftime("%b %d, %Y")
        except Exception:
            return str(d)

    def _safe_n_a(self, s: str) -> str:
        s = (s or "").strip()
        return s if s else "(n/a)"

    def _check_link_activity(self, url: str, timeout: int = 12) -> str:
        """
        Returns:
          - ACTIVE (2xx/3xx)
          - REACHABLE (<status>) e.g. 403/429/500
          - UNREACHABLE (network error)

        NOTE: Do NOT use HEAD (often blocked). Use lightweight GET(stream).
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
                    "User-Agent": "PortSwiggerResearchCollector/1.0 (+contact)",
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
        try:
            cats = list(categories)
            cats.sort(key=lambda x: float(x.get("score", 0.0)), reverse=True)
            out = []
            for c in cats:
                lab = str(c.get("label", "")).strip()
                sc = float(c.get("score", 0.0))
                if lab:
                    out.append(f"- {lab} ({sc:.2f})")
            return "\n".join(out) if out else "(none)"
        except Exception:
            return str(categories)

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

    # ---------------- store raw ----------------
    def _store_raw_card(self, card: news_model) -> str:
        """
        Generate AID once and keep it in card.m_extra['aid'].
        """
        aid = self._sha1(
            card.m_url
            or (card.m_title or "") + str(datetime.now(timezone.utc).timestamp())
        )

        card.m_extra = (card.m_extra or {})
        card.m_extra["aid"] = aid

        base = f"PORTSWIGGER:raw:{aid}"

        self._redis_set(f"{base}:url", card.m_url)
        self._redis_set(f"{base}:title", card.m_title)
        self._redis_set(f"{base}:author", card.m_author)
        self._redis_set(f"{base}:date", self._date_to_string(card.m_leak_date))

        date_raw = ""
        content_html = ""
        http_status = ""
        try:
            date_raw = (card.m_extra or {}).get("date_raw", "")
            content_html = (card.m_extra or {}).get("content_html", "")
            http_status = (card.m_extra or {}).get("http_status", "")
        except Exception:
            pass

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

    # ---------------- store processed (flattened, no JSON) ----------------
    def _store_processed(self, aid: str, processed: dict):
        base = f"PORTSWIGGER:processed:{aid}"

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

    # ---------------- requests session (fallback) ----------------
    def _make_requests_session(self) -> requests.Session:
        print(f"{self._tag} Creating requests session …")
        s = requests.Session()
        s.headers.update(
            {
                "User-Agent": "PortSwiggerResearchCollector/1.0 (+contact)",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }
        )

        server = (self._proxy or {}).get("server")
        if server:
            if str(server).lower().startswith("socks"):
                print(f"{self._tag} SOCKS proxy detected for requests ({server}) → IGNORING for requests fallback")
            else:
                s.proxies.update({"http": server, "https": server})
                print(f"{self._tag} requests will use proxy: {server}")

        return s

    # ---------------- Playwright helpers ----------------
    def _launch_browser(self, p, use_proxy: bool):
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

    @staticmethod
    def _scroll_to_load(page, steps: int = 2, wait_ms: int = 900):
        try:
            for _ in range(max(1, int(steps))):
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                page.wait_for_timeout(wait_ms)
        except Exception:
            pass

    # ---------------- extraction helpers ----------------
    def _extract_author_date(self, soup: BeautifulSoup) -> Tuple[str, str]:
        author = ""
        date_raw = ""

        auth_el = soup.select_one("div.callout-individual-profile h3 a[href^='/research/']")
        if auth_el:
            author = auth_el.get_text(strip=True)

        pub_p = soup.select_one("ul.publication-list li p")
        if pub_p:
            txt = pub_p.get_text(" ", strip=True)
            m = re.search(r"(\d{1,2}\s+[A-Za-z]+\s+\d{4})", txt)
            if m:
                date_raw = m.group(1).strip()
            else:
                date_raw = txt.strip()

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
                    if isinstance(cand, str) and cand.strip():
                        date_raw = cand.strip()
                        break
                if date_raw:
                    break

        return author, date_raw

    def _extract_article_links_from_index(self, soup: BeautifulSoup) -> Set[str]:
        links: Set[str] = set()
        root = soup.select_one("div.section-full-width.theme-navy-1") or soup

        for a in root.select("a.tile-container[href]"):
            href = (a.get("href") or "").strip()
            if href.startswith("/research/"):
                links.add(urljoin(self.base_url, href))

        for a in root.select("div.noscript-postlist a.noscript-post[href]"):
            href = (a.get("href") or "").strip()
            if href.startswith("/research/"):
                links.add(urljoin(self.base_url, href))

        return links

    def _build_card_from_soup(self, url: str, soup: BeautifulSoup) -> news_model:
        section = soup.select_one("div.section.theme-navy-1") or soup

        title_el = section.select_one("h1") or soup.select_one("h1")
        title = title_el.get_text(strip=True) if title_el else "(No title)"

        author, date_raw = self._extract_author_date(section)
        parsed_date = self._parse_date(date_raw)

        for bad in section.select("aside, nav, form, script, style, iframe"):
            bad.extract()

        pub_list = section.select_one("ul.publication-list")
        if pub_list:
            html_parts = []
            for sib in pub_list.next_siblings:
                if isinstance(sib, str) and not sib.strip():
                    continue
                html_parts.append(str(sib))
            content_html = "".join(html_parts).strip() or str(section)
        else:
            content_html = str(section)

        tmp = BeautifulSoup(content_html, "html.parser")
        content_text = tmp.get_text(" ", strip=True)

        subtitle_el = tmp.find("h2")
        subtitle = subtitle_el.get_text(" ", strip=True) if subtitle_el else ""

        full_content_text = f"{subtitle}\n\n{content_text}".strip() if subtitle else content_text
        important_text = subtitle if subtitle else " ".join(content_text.split()[:150])

        return news_model(
            m_screenshot="",
            m_title=title,
            m_weblink=[url],
            m_dumplink=[url],
            m_url=url,
            m_base_url=self.base_url,
            m_content=full_content_text,
            m_network=helper_method.get_network_type(self.base_url),
            m_important_content=important_text,
            m_content_type=["news"],
            m_leak_date=parsed_date,
            m_author=author,
            m_description=important_text,
            m_location="",
            m_links=[url],
            m_extra={"date_raw": date_raw, "content_html": content_html},
        )

    # ---------------- THN-style NLP batch (AFTER ALL PARSED) ----------------
    def _nlp_enrich_batch_and_print(self, cards: List[news_model]):
        print(f"{self._tag} NLP enrichment on {len(cards)} records (no JSON)")

        for card in cards:
            date_raw = (card.m_extra or {}).get("date_raw", "")
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

            network_type = card.m_network

            # ✅ Prefer parsed http_status -> never show UNREACHABLE if parsed
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
            print(f"Network Type: {network_type}")
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

    # ---------------- core crawling ----------------
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
            try:
                browser, context = self._launch_browser(p, use_proxy=True)
                page = context.new_page()
                print(f"{self._tag} Opening seed (proxy): {self.seed_url}")
                page.goto(self.seed_url, timeout=70000, wait_until="load")
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
                page.goto(self.seed_url, timeout=70000, wait_until="load")

            self._scroll_to_load(page, steps=6, wait_ms=900)

            soup = BeautifulSoup(page.content(), "html.parser")
            page_links = self._extract_article_links_from_index(soup)
            all_links.update(page_links)

            visit_list = sorted(all_links)
            if self._max_articles:
                visit_list = visit_list[: self._max_articles]

            # ✅ THN-style: show “Visiting N articles …”
            print(f"{self._tag} Visiting {len(visit_list)} articles after pagination")

            for idx, link in enumerate(visit_list, 1):
                try:
                    print(f"{self._tag} Visiting [{idx}/{len(visit_list)}]: {link}")

                    resp = page.goto(link, timeout=70000, wait_until="load")
                    status_code = None
                    try:
                        status_code = resp.status if resp is not None else None
                    except Exception:
                        status_code = None

                    s = BeautifulSoup(page.content(), "html.parser")
                    card = self._build_card_from_soup(link, s)

                    # ✅ store status on card
                    card.m_extra = (card.m_extra or {})
                    card.m_extra["http_status"] = int(status_code) if isinstance(status_code, int) else status_code

                    entity = entity_model(m_scrap_file=self.__class__.__name__,m_team="portswigger_research",m_name="portswigger")


                    self._card_data.append(card)
                    self._entity_data.append(entity)

                    aid = self._store_raw_card(card)
                    collected += 1

                    # ✅ THN-style parsed lines (NO RAW block here)
                    title_out = card.m_title if (card.m_title or "").strip() else "(No title)"
                    author_out = self._safe_n_a(card.m_author)
                    date_out = self._safe_n_a((card.m_extra or {}).get("date_raw", ""))

                    print(f"{self._tag} ✅ Parsed ({idx}/{len(visit_list)}): {title_out}")
                    print(f"{self._tag}    Author: {author_out} | Date: {date_out} | AID: {aid}")

                    if self.callback and self.callback():
                        self._card_data.clear()
                        self._entity_data.clear()

                except Exception as ex:
                    print(f"{self._tag} ❌ Error parsing article {link}: {ex}")
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

        # ✅ AFTER all parsed → run NLP batch exactly like you asked
        self._nlp_enrich_batch_and_print(self._card_data)

        self._is_crawled = True
        print(f"{self._tag} ✅ Done. Collected={collected}")
        return self._build_full_json_output(collected)

    def _run_with_requests(self) -> dict:
        print(f"{self._tag} Fallback: requests-based crawl")
        collected = 0
        session = self._make_requests_session()

        try:
            r = session.get(self.seed_url, timeout=60)
        except Exception as ex:
            print(f"{self._tag} Index fetch error: {ex}")
            return {
                "seed_url": self.seed_url,
                "articles_collected": 0,
                "developer_signature": self.developer_signature(),
            }

        all_links: Set[str] = set()
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            all_links.update(self._extract_article_links_from_index(soup))
        else:
            print(f"{self._tag} Index request failed with status {r.status_code}")

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
                    print(f"{self._tag} Article status {status_code} → {link}")
                    continue

                s = BeautifulSoup(art.text, "html.parser")
                card = self._build_card_from_soup(link, s)

                # ✅ store status on card
                card.m_extra = (card.m_extra or {})
                card.m_extra["http_status"] = status_code

                entity = entity_model(m_scrap_file=self.__class__.__name__, m_team="portswigger_research",m_name=   "portswigger")

                self._card_data.append(card)
                self._entity_data.append(entity)

                aid = self._store_raw_card(card)
                collected += 1

                # ✅ THN-style parsed lines
                title_out = card.m_title if (card.m_title or "").strip() else "(No title)"
                author_out = self._safe_n_a(card.m_author)
                date_out = self._safe_n_a((card.m_extra or {}).get("date_raw", ""))

                print(f"{self._tag} ✅ Parsed ({idx}/{len(visit_list)}): {title_out}")
                print(f"{self._tag}    Author: {author_out} | Date: {date_out} | AID: {aid}")

                if self.callback and self.callback():
                    self._card_data.clear()
                    self._entity_data.clear()

            except Exception as ex:
                print(f"{self._tag} ❌ Error (requests) parsing {link}: {ex}")
                continue

        # ✅ AFTER all parsed → run NLP batch exactly like you asked
        self._nlp_enrich_batch_and_print(self._card_data)
        self._is_crawled = True
        print(f"{self._tag} ✅ Done (requests). Collected={collected}")
        return self._build_full_json_output(collected)

    # ---------------- date parsing ----------------
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
            re.IGNORECASE,
        )
        if m:
            chunk = m.group(0)
            try:
                return datetime.strptime(chunk, "%d %B %Y").date()
            except Exception:
                try:
                    return datetime.strptime(chunk, "%d %b %Y").date()
                except Exception:
                    return None

        m2 = re.search(
            r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2},\s+\d{4}",
            s,
            re.IGNORECASE,
        )
        if m2:
            try:
                return datetime.strptime(m2.group(0).title(), "%b %d, %Y").date()
            except Exception:
                pass

        return None
