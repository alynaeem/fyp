import re
import asyncio
from abc import ABC
from dataclasses import dataclass
from typing import List, Dict, Optional, Any, Tuple

import requests
from bs4 import BeautifulSoup

from playwright.sync_api import BrowserContext
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeoutError

# Keep your original imports
from crawler.common.crawler_instance.local_interface_model.api.api_apk_model import apk_data_model
from crawler.common.crawler_instance.local_interface_model.api.api_collector_interface import api_collector_interface
from crawler.common.crawler_instance.local_shared_model.data_model.apk_model import apk_model
from crawler.common.crawler_instance.local_shared_model.data_model.entity_model import entity_model
from crawler.common.crawler_instance.local_shared_model import RuleModel, FetchProxy, FetchConfig, ThreatType


class _pakdb(api_collector_interface, ABC):
    """
    ACTIVE IMPLEMENTATION (Tor Optimized):
    - Waits for DOM Load specifically.
    - Uses Enter key instead of Click (more reliable).
    - Adds patience sleeps for Tor latency.
    """

    _instance = None

    BASE_URL = "https://pakistandatabase.com/index.php"
    TOR_SOCKS_PLAYWRIGHT = "socks5://127.0.0.1:9150"
    TOR_SOCKS_REQUESTS = "socks5h://127.0.0.1:9150"

    DEFAULT_TIMEOUT_SEC = 120000

    # ---------- singleton ----------
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_pakdb, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, developer_name: str = "Muhammad Abdullah", developer_note: str = ""):
        if getattr(self, "_initialized", False):
            return
        self._initialized = True

        self._developer_name = developer_name
        self._developer_note = developer_note

        self._apk_data: List[apk_model] = []
        self._entity_data: List[entity_model] = []
        self._is_crawled: bool = False
        self._last_query: Dict[str, Any] = {}

        self.callback = None
        self._max_items: Optional[int] = 50
        self._timeout: int = self.DEFAULT_TIMEOUT_SEC
        self._proxy: Dict[str, Any] = {}

        # requests session
        self._session = requests.Session()
        self._session.headers.update(self._default_headers())

        self._session.proxies.update({
            "http": self.TOR_SOCKS_REQUESTS,
            "https": self.TOR_SOCKS_REQUESTS,
        })

        print("[API] _pakdb Initialized ✅ (Tor Patience Mode)")

    # ---------- interface required ----------
    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "pakdb://active-search"

    @property
    def base_url(self) -> str:
        return self.BASE_URL

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_threat_type=ThreatType.API,
            m_fetch_proxy=FetchProxy.TOR,
            m_fetch_config=FetchConfig.PLAYWRIGHT,
            m_resoource_block=False,
        )

    @property
    def apk_data(self) -> List[apk_model]:
        return self._apk_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def init_callback(self, callback=None):
        self.callback = callback

    def contact_page(self) -> str:
        return "https://pakistandatabase.com/"

    def reset_cache(self):
        self._apk_data.clear()
        self._entity_data.clear()
        self._is_crawled = False
        self._last_query = {}

    def set_limits(self, max_pages: Optional[int] = None, max_items: Optional[int] = None):
        if max_items is not None and max_items >= 1:
            self._max_items = int(max_items)

    def set_proxy(self, proxy: dict):
        self._proxy = proxy or {}
        server = (self._proxy or {}).get("server")
        if not server:
            return
        if server.startswith("socks5://"):
            server = server.replace("socks5://", "socks5h://", 1)
        self._session.proxies.update({"http": server, "https": server})

    # ---------- helpers ----------
    @staticmethod
    def _default_headers() -> Dict[str, str]:
        return {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

    @staticmethod
    def _normalize_to_92(number: str) -> str:
        n = re.sub(r"\D+", "", number or "")
        if not n:
            return ""
        if n.startswith("92"):
            return n
        if n.startswith("0"):
            return "92" + n[1:]
        if len(n) == 10 and n.startswith("3"):
            return "92" + n
        return n

    def _fetch_data_via_playwright(self, query_text: str, timeout_ms: int = 180_000) -> str:
        html_content = ""
        with sync_playwright() as p:
            print("[PW] Launching browser via Tor:", self.TOR_SOCKS_PLAYWRIGHT)

            browser = p.chromium.launch(
                headless=False,
                proxy={"server": self.TOR_SOCKS_PLAYWRIGHT},
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            )

            ctx = browser.new_context(ignore_https_errors=True)
            ctx.set_default_navigation_timeout(timeout_ms)
            ctx.set_default_timeout(60_000)

            page = ctx.new_page()

            # Block heavy resources (Tor-friendly)
            def route_handler(route):
                rtype = route.request.resource_type
                if rtype in ("image", "media", "font"):
                    return route.abort()
                return route.continue_()

            page.route("**/*", route_handler)

            try:
                print(f"[PW] Navigating to {self.BASE_URL}...")
                page.goto(self.BASE_URL, wait_until="domcontentloaded", timeout=timeout_ms)

                input_sel = "input[name='search_query']"
                btn_sel = "form button[type='submit']"

                page.wait_for_selector(input_sel, state="visible", timeout=60_000)

                inp = page.locator(input_sel).first
                btn = page.locator(btn_sel).first

                # Focus + fill
                inp.click(timeout=100_000)
                inp.fill(str(query_text), timeout=30_000)

                # Verify it actually got filled
                val = inp.input_value(timeout=30_000)
                print("[PW] Input value now:", val)

                if val.strip() != str(query_text).strip():
                    page.evaluate(
                        """([sel, v]) => {
                            const el = document.querySelector(sel);
                            if (el) {
                                el.value = v;
                                el.dispatchEvent(new Event('input', {bubbles: true}));
                                el.dispatchEvent(new Event('change', {bubbles: true}));
                            }
                        }""",
                        [input_sel, str(query_text)],
                    )
                    val2 = inp.input_value(timeout=30_000)
                    print("[PW] Input value after JS set:", val2)

                # ---- KEY FIX: Don't let Playwright wait for navigation to "finish" ----
                print("[PW] Submitting form (no_wait_after=True)...")
                btn.click(timeout=60_000, no_wait_after=True)

                # Wait for results to appear (preferred over navigation waits)
                # Some pages update via same-url navigation or XHR; Tor can stall load events.
                try:
                    page.wait_for_selector("table.api-response tbody tr", timeout=timeout_ms)
                    print("[PW] Results table row appeared.")
                except Exception:
                    # Fallback: maybe table exists but no rows / different markup
                    try:
                        page.wait_for_selector("table", timeout=30_000)
                        print("[PW] A table appeared, but rows selector not matched.")
                    except Exception:
                        print("[PW] No table detected, capturing current page anyway.")

                html_content = page.content()

            except Exception as e:
                print(f"[PW] Error during interaction: {e}")
                try:
                    html_content = page.content()
                except Exception:
                    html_content = ""
            finally:
                try:
                    ctx.close()
                except Exception:
                    pass
                try:
                    browser.close()
                except Exception:
                    pass

        return html_content

    def _parse_html_results(self, html: str):
        if not html:
            return

        soup = BeautifulSoup(html, "html.parser")

        tables = soup.find_all("table")
        if not tables:
            print("[API] No tables found in HTML.")
            # Debug: Print title to see if we are on error page
            title = soup.title.string if soup.title else "No Title"
            print(f"[API] Page Title: {title}")
            return

        count = 0
        for table in tables:
            rows = table.find_all("tr")
            for row in rows:
                cols = row.find_all(["td", "th"])
                cleaned_cols = [c.get_text(strip=True) for c in cols]

                if not cleaned_cols: continue

                # Skip Header
                if "mobile" in cleaned_cols[0].lower() or "name" in cleaned_cols[1].lower():
                    continue

                if len(cleaned_cols) >= 4:
                    mobile = cleaned_cols[0]
                    name = cleaned_cols[1]
                    cnic = cleaned_cols[2]
                    address = cleaned_cols[3]

                    self._apk_data.append(self._make_card(
                        name=name, cnic=cnic, mobile=mobile, address=address
                    ))
                    count += 1

                    if self._max_items and count >= self._max_items:
                        return
        print(f"[API] Parsed {count} items from HTML.")

    # ---------- REQUIRED by runner ----------
    async def parse_leak_data(self, query: Dict, context: BrowserContext):
        if not isinstance(query, dict): query = {}
        raw = (query.get("number") or query.get("name") or query.get("query") or "").strip()
        if not raw: raw = "03000000000"

        normalized = self._normalize_to_92(raw)
        if not normalized:
            return None

        self._last_query = dict(query)
        self._apk_data.clear()
        self._entity_data.clear()
        self._is_crawled = False

        print(f"[API] Starting Active Search for: {normalized}")

        loop = asyncio.get_running_loop()
        html_source = await loop.run_in_executor(None, self._fetch_data_via_playwright, normalized)

        if html_source:
            self._parse_html_results(html_source)
        else:
            print("[API] No HTML returned from Playwright.")

        self._is_crawled = True
        print(f"[API] Done ✅ items_collected={len(self._apk_data)}")
        return self._build_model(self._apk_data)

    # ---------- model builders ----------
    def _make_card(self, name: str, cnic: str, mobile: str, address: str) -> apk_model:
        card = apk_model()
        setattr(card, "m_app_name", name if name else "Unknown Name")
        setattr(card, "m_app_url", self.BASE_URL)
        setattr(card, "m_package_id", f"pakdb-{mobile}")
        setattr(card, "m_network", "tor")
        desc = f"CNIC: {cnic} | Mobile: {mobile} | Address: {address}"
        setattr(card, "m_description", desc)
        extra_data = {"mobile": mobile, "cnic": cnic, "address": address, "name": name}
        setattr(card, "m_extra", extra_data)
        return card

    def _build_model(self, cards: List[apk_model]):
        model = apk_data_model()
        setattr(model, "base_url", self.base_url)
        setattr(model, "content_type", ["leaked_data", "sim_db"])
        setattr(model, "cards_data", cards or [])
        return model

    def developer_signature(self) -> str:
        return f"{self._developer_name}:{self._developer_note}".strip(":")

    def run(self) -> dict:
        q = {"number": "03336523185"}
        result_model = None
        try:
            result_model = asyncio.run(self.parse_leak_data(query=q, context=None))
        except Exception as e:
            print("[API] run() failed:", e)

        cards = list(getattr(result_model, "cards_data", []) or []) if result_model else []
        count = len(cards)

        print("\n[DEBUG] Extracted Data:")
        for i, c in enumerate(cards, 1):
            name = getattr(c, "m_app_name", "")
            desc = getattr(c, "m_description", "")
            print(f"\n--- Result #{i} ---")
            print(f"Name: {name}")
            print(f"Details: {desc}")

        return {
            "seed_url": self.seed_url,
            "items_collected": count,
            "developer_signature": self.developer_signature(),
        }


if __name__ == "__main__":
    scraper = _pakdb()
    out = scraper.run()
    print("\n[FINAL Output]", out)