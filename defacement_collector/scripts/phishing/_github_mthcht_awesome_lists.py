import json
import re
import hashlib
from abc import ABC
from datetime import date
from typing import List, Optional, Any, Dict, Tuple

import requests
from bs4 import BeautifulSoup

from crawler.common.constants.constant import RAW_PATH_CONSTANTS
from crawler.common.crawler_instance.local_interface_model.leak.leak_extractor_interface import (
    leak_extractor_interface,
)
from crawler.common.crawler_instance.local_shared_model.data_model.defacement_model import (
    defacement_model,
)
from crawler.common.crawler_instance.local_shared_model.data_model.entity_model import (
    entity_model,
)
from crawler.common.crawler_instance.local_shared_model.rule_model import (
    RuleModel,
    FetchProxy,
    FetchConfig,
    ThreatType,
)
from crawler.common.crawler_instance.crawler_services.redis_manager.redis_controller import (
    redis_controller,
)
from crawler.common.crawler_instance.crawler_services.redis_manager.redis_enums import (
    REDIS_COMMANDS,
    CUSTOM_SCRIPT_REDIS_KEYS,
)
from crawler.common.crawler_instance.crawler_services.shared.helper_method import (
    helper_method,
)
from crawler.common.crawler_instance.crawler_services.log_manager.log_controller import log


class _github_mthcht_awesome_lists(leak_extractor_interface, ABC):
    """
    GitHub: mthcht/awesome-lists -> openphish_url_list.csv

    Framework behavior:
    - RequestParser calls model.run() with no args.
    - For REQUESTS models we opt-in seed fetching by: needs_seed_fetch = True
      (RequestParser attaches _seed_response + _request_page).

    What this script does:
    - Extracts phishing URLs from GitHub embeddedData JSON.
    - Fetches each URL with requests (proxy supported).
    - Prints debug + analysis (category/brands/forms/password fields/etc).
    """

    _instance = None
    needs_seed_fetch = True  # ✅ RequestParser will seed_fetch ONLY for this model

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_github_mthcht_awesome_lists, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, callback=None):
        if getattr(self, "_initialized", False):
            return
        self._initialized = True

        self.callback = callback
        self._card_data: List[defacement_model] = []
        self._entity_data: List[entity_model] = []
        self._redis_instance = redis_controller()
        self._is_crawled = False

        # runtime limits
        self._max_rows: Optional[int] = 20   # set None to process all URLs
        self._timeout: int = 25
        self._verify_tls: bool = True

        # print controls
        self._print_analysis: bool = True
        self._snippet_len: int = 400

        # proxy holder (set by RequestParser via set_proxy())
        self._proxy: Dict[str, str] = {}

        print("[GITHUB_MTHCHT] Initialized ✅")

    # ---------------- hooks/config ----------------
    def init_callback(self, callback=None):
        self.callback = callback
        print("[GITHUB_MTHCHT] Callback set")

    def set_limits(self, max_rows: Optional[int] = None):
        if max_rows is not None:
            self._max_rows = int(max_rows) if max_rows >= 1 else None
        print(f"[GITHUB_MTHCHT] Limits → rows={self._max_rows or '∞'}")

    def set_proxy(self, proxy: dict):
        self._proxy = proxy or {}
        print(f"[GITHUB_MTHCHT] Proxy configured: {self._proxy}")

    # ---------------- required interface props ----------------
    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return (
            "https://github.com/mthcht/awesome-lists/blob/main/Lists/Phishing/"
            "openphish/openphish_url_list.csv"
        )

    @property
    def base_url(self) -> str:
        return "https://github.com/"

    @property
    def developer_signature(self) -> str:
        return "Usman Ali"

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_fetch_proxy=FetchProxy.NONE,
            m_fetch_config=FetchConfig.REQUESTS,
            m_threat_type=ThreatType.DEFACEMENT,
        )

    @property
    def card_data(self) -> List[defacement_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def contact_page(self) -> str:
        return "https://github.com/mthcht/awesome-lists/tree/main/Lists/Phishing"

    # ---------------- redis + output helpers ----------------
    def invoke_db(self, command: int, key: str, default_value, expiry: int = None):
        return self._redis_instance.invoke_trigger(
            command, [key + self.__class__.__name__, default_value, expiry]
        )

    def append_leak_data(self, leak: defacement_model, entity: entity_model):
        self._card_data.append(leak)
        self._entity_data.append(entity)
        if self.callback:
            try:
                if self.callback():
                    self._card_data.clear()
                    self._entity_data.clear()
            except Exception:
                pass

    # ---------------- framework entrypoint ----------------
    def run(self) -> dict:
        """
        RequestParser calls run() with no args.
        RequestParser will attach:
          - self._seed_response (requests.Response)
          - self._request_page (RequestsPage wrapper)
        """
        print("[GITHUB_MTHCHT] run() called")
        page_like = getattr(self, "_request_page", None) or getattr(self, "_seed_response", None) or self
        return self.parse_leak_data(page_like)

    # ---------------- small helpers ----------------
    @staticmethod
    def _safe_get(obj: Any, chain: List[str], default=None):
        cur = obj
        for k in chain:
            try:
                if isinstance(cur, dict):
                    cur = cur.get(k)
                else:
                    cur = getattr(cur, k)
            except Exception:
                return default
            if cur is None:
                return default
        return cur

    @staticmethod
    def _looks_like_url(s: str) -> bool:
        s = (s or "").strip().lower()
        return s.startswith("http://") or s.startswith("https://")

    @staticmethod
    def _dedupe_keep_order(items: List[str]) -> List[str]:
        seen = set()
        out = []
        for x in items:
            x = (x or "").strip()
            if not x or x in seen:
                continue
            seen.add(x)
            out.append(x)
        return out

    def _extract_html(self, page_like: Any) -> str:
        # Most compatible: page_like._seed_response.text
        t = self._safe_get(page_like, ["_seed_response", "text"], None)
        if isinstance(t, str) and t.strip():
            return t

        # Or: page_like.text
        t = self._safe_get(page_like, ["text"], None)
        if isinstance(t, str) and t.strip():
            return t

        # Or: page_like.response.text
        t = self._safe_get(page_like, ["response", "text"], None)
        if isinstance(t, str) and t.strip():
            return t

        # Or: page_like.content (bytes)
        c = self._safe_get(page_like, ["content"], None)
        if isinstance(c, bytes):
            return c.decode("utf-8", errors="ignore")
        if isinstance(c, str) and c.strip():
            return c

        return ""

    def _build_requests_proxies(self) -> Optional[Dict[str, str]]:
        server = (self._proxy or {}).get("server")
        if not server:
            return None
        # tor dns via proxy
        if server.startswith("socks5://"):
            server = server.replace("socks5://", "socks5h://", 1)
        return {"http": server, "https": server}

    def _fetch_refhtml(self, url: str) -> Tuple[str, Dict[str, str]]:
        """
        Fetch phishing URL content using requests (proxy supported).
        Returns (html_text, fetch_meta)
        """
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        }

        proxies = self._build_requests_proxies()

        try:
            r = requests.get(
                url,
                headers=headers,
                timeout=self._timeout,
                allow_redirects=True,
                proxies=proxies,
                verify=self._verify_tls,
            )
            txt = r.text or ""
            meta = {
                "status_code": str(r.status_code),
                "final_url": r.url or url,
                "content_len": str(len(txt)),
                "content_type": (r.headers.get("Content-Type") or "").strip(),
                "server": (r.headers.get("Server") or "").strip(),
            }
            return txt, meta
        except Exception as ex:
            return "", {
                "error": str(ex),
                "status_code": "",
                "final_url": url,
                "content_len": "0",
                "content_type": "",
                "server": "",
            }

    def _parse_urls_from_embedded_data(self, soup: BeautifulSoup) -> List[str]:
        urls: List[str] = []
        script = soup.select_one('script[data-target="react-app.embeddedData"]')
        if not script or not script.string:
            return urls
        try:
            payload = json.loads(script.string)
        except Exception:
            return urls

        csv_rows = ((payload.get("payload") or {}).get("blob", {}) or {}).get("csv") or []
        if not isinstance(csv_rows, list):
            return urls

        for r in csv_rows[1:]:
            if not r or not isinstance(r, list) or len(r) < 1:
                continue
            u = (r[0] or "").strip()
            if self._looks_like_url(u):
                urls.append(u)
        return urls

    # ---------------- YOUR ANALYZER (integrated) ----------------
    def _analyze_html(self, html: str, final_url: str) -> Dict[str, Any]:
        html = html or ""
        soup = BeautifulSoup(html, "html.parser")

        title = ""
        try:
            title = (soup.title.string or "").strip() if soup.title and soup.title.string else ""
        except Exception:
            title = ""

        text = soup.get_text(" ", strip=True).lower()
        forms = len(soup.find_all("form"))
        pw_inputs = len(soup.select("input[type='password']"))
        scripts = len(soup.find_all("script"))
        iframes = len(soup.find_all("iframe"))

        host = ""
        try:
            host = re.sub(r"^https?://", "", (final_url or "")).split("/")[0].lower()
        except Exception:
            host = ""

        category = "unknown"
        if any(x in host for x in ["bit.ly", "t.co", "surl.li", "tinyurl", "linktr.ee"]):
            category = "redirector"
        elif "ipfs" in host or ".ipfs." in host:
            category = "ipfs"
        elif any(
            x in host
            for x in [
                "vercel.app",
                "netlify.app",
                "github.io",
                "pages.dev",
                "godaddysites.com",
                "weebly.com",
                "wixsite.com",
                "webflow.io",
                "framer.app",
                "framer.website",
            ]
        ):
            category = "cloud_hosted"
        elif any(k in text for k in ["sign in", "login", "verify", "password", "account", "authentication"]):
            category = "login_branding"

        brands: List[str] = []
        brand_map = {
            "microsoft": ["microsoft", "outlook", "office", "live.com"],
            "google": ["google", "gmail"],
            "meta": ["facebook", "meta", "instagram"],
            "paypal": ["paypal"],
            "apple": ["apple", "icloud"],
            "banking": ["bank", "credit", "secure payment", "card"],
            "crypto": ["wallet", "metamask", "trezor", "coinbase", "binance"],
        }
        for b, keys in brand_map.items():
            if any(k in text for k in keys):
                brands.append(b)

        sha1 = hashlib.sha1(html.encode("utf-8", errors="ignore")).hexdigest()
        snippet = re.sub(r"\s+", " ", (html[: self._snippet_len] or "")).strip()

        return {
            "title": title,
            "host": host,
            "category": category,
            "brands": brands,
            "forms": forms,
            "pw_inputs": pw_inputs,
            "scripts": scripts,
            "iframes": iframes,
            "sha1": sha1,
            "snippet": snippet,
        }

    # ---------------- main parse ----------------
    def parse_leak_data(self, page_like):
        html = self._extract_html(page_like)

        print("\n================= [GITHUB_MTHCHT] DEBUG =================")
        print(f"Seed URL: {self.seed_url}")
        print(f"Seed HTML length: {len(html or '')}")
        print("=========================================================\n")

        if not html:
            log.g().e("[GITHUB_MTHCHT] No HTML received for seed page.")
            self._is_crawled = True
            return {
                "seed_url": self.seed_url,
                "items_collected": 0,
                "developer_signature": self.developer_signature,
                "error": "no_html_seed",
            }

        soup = BeautifulSoup(html, "html.parser")
        urls = self._dedupe_keep_order(self._parse_urls_from_embedded_data(soup))

        print("[GITHUB_MTHCHT] Parse results:")
        print(f"unique urls used:  {len(urls)}")
        for i, u in enumerate(urls[:20], start=1):
            print(f"  {i:02d}. {u}")
        if len(urls) > 20:
            print(f"  ... and {len(urls) - 20} more")

        collected = 0
        max_rows = self._max_rows or len(urls)

        for idx, url in enumerate(urls, start=1):
            if idx > max_rows:
                print("[GITHUB_MTHCHT] Max rows reached, stopping.")
                break

            try:
                print("\n------------------ [GITHUB_MTHCHT] ITEM ------------------")
                print(f"#{idx}/{len(urls)}")
                print(f"URL: {url}")
                print("----------------------------------------------------------")

                content, fetch_meta = self._fetch_refhtml(url)

                if fetch_meta.get("error"):
                    print(f"[GITHUB_MTHCHT] Fetch ERROR: {fetch_meta['error']}")
                else:
                    print(f"[GITHUB_MTHCHT] Status: {fetch_meta.get('status_code')}")
                    print(f"[GITHUB_MTHCHT] Final URL: {fetch_meta.get('final_url')}")
                    print(f"[GITHUB_MTHCHT] Content-Type: {fetch_meta.get('content_type')}")
                    print(f"[GITHUB_MTHCHT] Server: {fetch_meta.get('server')}")
                    print(f"[GITHUB_MTHCHT] HTML len: {fetch_meta.get('content_len')}")

                if self._print_analysis:
                    analysis = self._analyze_html(content, fetch_meta.get("final_url", url))

                    print(f"[GITHUB_MTHCHT] Host: {analysis['host']}")
                    print(f"[GITHUB_MTHCHT] Title: {analysis['title']}")
                    print(f"[GITHUB_MTHCHT] Category: {analysis['category']}")
                    print(f"[GITHUB_MTHCHT] Brands: {', '.join(analysis['brands']) if analysis['brands'] else '-'}")
                    print(f"[GITHUB_MTHCHT] Forms: {analysis['forms']} | Password inputs: {analysis['pw_inputs']}")
                    print(f"[GITHUB_MTHCHT] Scripts: {analysis['scripts']} | Iframes: {analysis['iframes']}")
                    print(f"[GITHUB_MTHCHT] SHA1: {analysis['sha1']}")
                    print(f"[GITHUB_MTHCHT] Snippet(0..{self._snippet_len}): {analysis['snippet']}")

                # store content in models (same pattern as your system)
                card = defacement_model(
                    m_content=content or "",
                    m_url=url,
                    m_base_url=self.base_url,
                    m_network=helper_method.get_network_type(self.base_url),
                    m_ioc_type=["phishing"],
                    m_leak_date=date.today(),
                )

                ent = entity_model(
                    m_scrap_file=self.__class__.__name__,
                    m_team="mthcht",
                    m_weblink=[url],
                )

                self.append_leak_data(card, ent)
                collected += 1

            except Exception as ex:
                log.g().e(f"[GITHUB_MTHCHT] ITEM ERROR {url}: {ex}")
                continue

        self._is_crawled = True
        print(f"\n[GITHUB_MTHCHT] ✅ Done. Collected={collected}")

        return {
            "seed_url": self.seed_url,
            "items_collected": collected,
            "developer_signature": self.developer_signature,
        }
