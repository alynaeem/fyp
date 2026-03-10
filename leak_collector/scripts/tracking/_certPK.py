import re
import io
import json
import hashlib
import requests
import pdfplumber
from bs4 import BeautifulSoup
from abc import ABC
from datetime import datetime, timezone
from typing import List, Optional, Set, Tuple

from playwright.sync_api import sync_playwright

from crawler.common.crawler_instance.local_interface_model.leak.leak_extractor_interface import leak_extractor_interface
from crawler.common.crawler_instance.local_shared_model.data_model import entity_model
from crawler.common.crawler_instance.local_shared_model.data_model import leak_model
from crawler.common.crawler_instance.local_shared_model import RuleModel, FetchProxy, FetchConfig, ThreatType
from crawler.common.crawler_instance.crawler_services.redis_manager.redis_controller import redis_controller
from crawler.common.dev_signature import developer_signature


class _certPK(leak_extractor_interface, ABC):
    _instance = None

    # ---------------- singleton ----------------
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_certPK, cls).__new__(cls)
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
        self._start_year: int = 2024
        self._limit_latest_year: Optional[int] = None  # if you want to stop at a year
        self._max_pdfs_per_year_latest_only: Optional[int] = 6  # keep your 2025 shortcut style
        self._max_total: Optional[int] = None  # hard cap for everything

        # Redis master indexes (pipe-delimited strings, NOT JSON)
        self._raw_index_key = "CERTPK:raw_index"
        self._json_index_key = "CERTPK:json_index"

        self._log_every_years = 1

        print("[PKCERT] Initialized ✅ (pure Redis, no NLP)")

    # ---------------- interface hooks ----------------
    def init_callback(self, callback=None):
        self.callback = callback
        print("[PKCERT] Callback set")

    def set_proxy(self, proxy: dict):
        self._proxy = proxy or {}
        print(f"[PKCERT] Proxy configured: {self._proxy}")

    def set_limits(
        self,
        start_year: Optional[int] = None,
        limit_latest_year: Optional[int] = None,
        max_total: Optional[int] = None,
        max_pdfs_per_year_latest_only: Optional[int] = None,
    ):
        if start_year is not None and start_year >= 2000:
            self._start_year = int(start_year)
        if limit_latest_year is not None and limit_latest_year >= self._start_year:
            self._limit_latest_year = int(limit_latest_year)
        if max_total is not None and max_total >= 1:
            self._max_total = int(max_total)
        if max_pdfs_per_year_latest_only is not None and max_pdfs_per_year_latest_only >= 1:
            self._max_pdfs_per_year_latest_only = int(max_pdfs_per_year_latest_only)

        print(
            f"[PKCERT] Limits → start_year={self._start_year}, "
            f"latest_year={self._limit_latest_year or 'auto'}, "
            f"max_total={self._max_total or '∞'}, "
            f"latest_year_cap={self._max_pdfs_per_year_latest_only or '∞'}"
        )

    def reset_cache(self):
        self._redis_set("CERTPK:last_crawl", "", 60)

    # ---------------- required properties ----------------
    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "https://pkcert.gov.pk/get-advisories.asp"

    @property
    def base_url(self) -> str:
        return "https://pkcert.gov.pk"

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
                print(f"[PKCERT] requests will use proxy: {server}")

        return s

    # ---------------- parsing helpers ----------------
    @staticmethod
    def _clean_text(s: str) -> str:
        return re.sub(r"\s+", " ", (s or "")).strip()

    @staticmethod
    def _extract_year_num_from_url(url: str) -> Tuple[Optional[int], Optional[str]]:
        """
        Best-effort: tries to capture trailing numeric doc id.
        Returns: (year, doc_id_str)
        """
        m = re.search(r"/(\d{4})", url)
        y = int(m.group(1)) if m else None
        m2 = re.search(r"(\d+)(?:\.pdf)?$", url)
        doc = m2.group(1) if m2 else None
        return y, doc

    @staticmethod
    def _is_pdf_response(headers: dict) -> bool:
        ct = (headers or {}).get("content-type", "") or ""
        return "application/pdf" in ct.lower() or ct.lower().endswith("/pdf")

    def _fetch_with_playwright(self, url: str, use_proxy: bool) -> bytes:
        """
        Returns raw bytes of response body for PDF via Playwright (fallback only).
        """
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

            # capture response
            data = b""

            def _on_response(resp):
                nonlocal data
                try:
                    if resp.url == url and resp.status == 200:
                        # NOTE: Playwright's Response.body() returns bytes
                        data = resp.body()
                except Exception:
                    pass

            page.on("response", _on_response)

            page.goto(url, timeout=60000, wait_until="load")

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

            return data

    # ---------------- raw store ----------------
    def _store_raw_card(self, card: leak_model) -> str:
        aid = self._sha1(card.m_url or (card.m_title or "") + str(datetime.now(timezone.utc).timestamp()))
        base = f"CERTPK:raw:{aid}"

        self._redis_set(f"{base}:url", card.m_url)
        self._redis_set(f"{base}:title", card.m_title)
        self._redis_set(f"{base}:date", self._date_to_string(card.m_leak_date))
        self._redis_set(f"{base}:content", card.m_content or "")
        self._redis_set(f"{base}:important", card.m_important_content or "")
        self._redis_set(f"{base}:seed_url", self.seed_url)
        self._redis_set(f"{base}:base_url", self.base_url)
        self._redis_set(f"{base}:scraped_at", int(datetime.now(timezone.utc).timestamp()))
        self._redis_set(f"{base}:rendered", "0")

        cts = getattr(card, "m_content_type", None) or []
        self._redis_set(f"{base}:content_type_count", len(cts))
        for i, v in enumerate(cts):
            self._redis_set(f"{base}:content_type:{i}", v)

        links = getattr(card, "m_weblink", None) or []
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
                "important_content": card.m_important_content,
                "content_type": getattr(card, "m_content_type", []) or [],
                "leak_date": self._date_to_string(card.m_leak_date),
                "content": card.m_content,
                "weblinks": getattr(card, "m_weblink", []) or [],
            },
            "entity": entity.__dict__ if hasattr(entity, "__dict__") else str(entity),
            "scraped_at": int(datetime.now(timezone.utc).timestamp()),
        }

        key = f"CERTPK:ui:{aid}"
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
        """
        PKCERT advisories are PDFs listed per catId (year%100).
        We crawl years from start_year -> current_year.
        Uses Redis to mark parsed PDFs to avoid duplicates.
        """
        collected = 0
        seen_urls: Set[str] = set()
        any_success = False

        now_year = datetime.now(timezone.utc).year
        end_year = self._limit_latest_year or now_year

        session = self._make_requests_session(use_proxy=True)

        for year_idx, year in enumerate(range(self._start_year, end_year + 1), start=1):
            if year_idx % self._log_every_years == 0:
                print(f"[PKCERT] Year {year}: collecting… (total={collected})")

            cat_id = year % 100
            index_url = f"{self.seed_url}?catId={cat_id}"

            # fetch index html
            html = ""
            try:
                r = session.get(index_url, timeout=60)
                r.encoding = "utf-8"
                r.raise_for_status()
                html = r.text
            except Exception as ex:
                print(f"[PKCERT] ❌ Index fetch failed for {year}: {ex}")
                continue

            soup = BeautifulSoup(html, "html.parser")

            # same selector as old Playwright code
            anchors = soup.select('div.card-2 a[href$=".pdf"]')
            if not anchors:
                continue

            urls_to_process: List[Tuple[str, int, str, str, str]] = []
            for a in anchors:
                href = (a.get("href") or "").strip()
                if not href:
                    continue
                pdf_url = href if href.startswith("http") else (self.base_url.rstrip("/") + "/" + href.lstrip("/"))

                if pdf_url in seen_urls:
                    continue
                seen_urls.add(pdf_url)

                title_text = self._clean_text(a.get_text(" ", strip=True))
                m = re.search(r"(\d+)(?:\.pdf)?$", pdf_url)
                num = m.group(1) if m else "unknown"

                key = f"ADVISORY_PARSED_{year}_{num}"
                already_parsed = self._redis_get(key, "0") == "1"
                if already_parsed:
                    continue

                urls_to_process.append((pdf_url, year, num, key, title_text))

            # keep your "latest-year cut" behavior (previously hard-coded 2025)
            # now it applies to most recent year we are crawling (end_year)
            if year == end_year and any_success and self._max_pdfs_per_year_latest_only:
                urls_to_process = urls_to_process[: self._max_pdfs_per_year_latest_only]

            for pdf_url, y, num, key, title_text in urls_to_process:
                if self._max_total and collected >= self._max_total:
                    break

                try:
                    # prefer requests for pdf bytes
                    pdf_bytes = b""
                    try:
                        rr = session.get(pdf_url, timeout=60)
                        if rr.status_code == 403 or rr.status_code == 401:
                            pdf_bytes = self._fetch_with_playwright(pdf_url, use_proxy=False)
                        else:
                            rr.raise_for_status()
                            if not self._is_pdf_response(rr.headers):
                                continue
                            pdf_bytes = rr.content
                    except Exception:
                        pdf_bytes = self._fetch_with_playwright(pdf_url, use_proxy=False)

                    if not pdf_bytes:
                        continue

                    all_text = ""
                    try:
                        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
                            for p in pdf.pages:
                                text = p.extract_text() or ""
                                if text.strip():
                                    all_text += text + "\n"
                    except Exception:
                        continue

                    all_text = all_text.strip()
                    if not all_text:
                        continue

                    heading = title_text or f"Advisory {y}-{num}"

                    card = leak_model(
                        m_title=heading,
                        m_weblink=[pdf_url],
                        m_dumplink=[pdf_url],
                        m_url=pdf_url,
                        m_base_url=self.base_url,
                        m_content=all_text,
                        m_network="clearnet",
                        m_important_content=all_text[:500],
                        m_content_type=["news"],
                        m_leak_date=None,
                    )

                    entity = entity_model(
                        m_scrap_file=self.__class__.__name__,
                        m_team="PKCERT",
                        m_country=["Pakistan"],
                        m_name=f"PKCERT Advisory {y}-{num}",
                    )

                    self.append_leak_data(card, entity)

                    # store raw + UI JSON (optional but consistent with your new style)
                    aid = self._store_raw_card(card)
                    self._store_json_for_ui(aid, card, entity)

                    # mark parsed
                    self._redis_set(key, "1", expiry=None)

                    collected += 1
                    any_success = True
                    print(f"[PKCERT] +1 | {y} | {heading[:90]}")

                except Exception as ex:
                    print(f"[PKCERT] ❌ Error parsing PDF: {ex}")
                    continue

            if self._max_total and collected >= self._max_total:
                break

        self._is_crawled = True
        print(f"[PKCERT] ✅ Done. Collected={collected}")

        return {
            "seed_url": self.seed_url,
            "articles_collected": collected,
            "developer_signature": self.developer_signature,
        }
