import re
import json
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


class _phishunt(leak_extractor_interface, ABC):
    """
    phishunt.io -> feed.txt

    Adds:
    - score/severity/recommended_action
    - IOC CARD print (Score HIGH/MED/LOW)
    - Writes JSON file: phishunt_output_YYYY-MM-DD.json (in CWD)
    """

    _instance = None
    needs_seed_fetch = True  # ✅ RequestParser seed_fetch

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_phishunt, cls).__new__(cls)
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
        self._max_rows: Optional[int] = 50  # None => all
        self._timeout: int = 25
        self._verify_tls: bool = True

        # printing
        self._print_analysis: bool = True
        self._enable_ioc_card_print: bool = True  # ✅ flag (no name clash)
        self._snippet_len: int = 400

        # json output
        self._write_json_file: bool = True
        self._json_out_path: Optional[str] = None  # None => auto
        self._include_raw_html_in_json: bool = False

        # proxy holder set by RequestParser
        self._proxy: Dict[str, str] = {}

        # store items for json
        self._output_items: List[Dict[str, Any]] = []

        print("[PHISHUNT] Initialized ✅")

    # -------- config hooks --------
    def init_callback(self, callback=None):
        self.callback = callback
        print("[PHISHUNT] Callback set")

    def set_proxy(self, proxy: dict):
        self._proxy = proxy or {}
        print(f"[PHISHUNT] Proxy configured: {self._proxy}")

    def set_limits(self, max_rows: Optional[int] = None):
        if max_rows is not None:
            self._max_rows = int(max_rows) if max_rows >= 1 else None
        print(f"[PHISHUNT] Limits → rows={self._max_rows or '∞'}")

    def set_output_json(self, enable: bool = True, path: Optional[str] = None, include_raw_html: bool = False):
        self._write_json_file = bool(enable)
        self._json_out_path = path
        self._include_raw_html_in_json = bool(include_raw_html)
        print(f"[PHISHUNT] JSON output → enable={self._write_json_file}, path={self._json_out_path}, raw_html={self._include_raw_html_in_json}")

    def set_print_cards(self, enable: bool = True):
        self._enable_ioc_card_print = bool(enable)
        print(f"[PHISHUNT] IOC card printing → {self._enable_ioc_card_print}")

    # -------- required props --------
    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "https://phishunt.io/feed.txt"

    @property
    def base_url(self) -> str:
        return "https://phishunt.io/feed.txt"

    @property
    def developer_signature(self) -> str:
        return "Muhammad Marij Younas:..."

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_fetch_proxy=FetchProxy.NONE,
            m_fetch_config=FetchConfig.REQUESTS,
            m_resoource_block=False,
            m_threat_type=ThreatType.DEFACEMENT,
        )

    @property
    def card_data(self) -> List[defacement_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def contact_page(self) -> str:
        return "https://phishunt.io/contact/"

    # -------- helpers --------
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

    def run(self) -> dict:
        print("[PHISHUNT] run() called")
        page_like = getattr(self, "_request_page", None) or getattr(self, "_seed_response", None) or self
        return self.parse_leak_data(page_like)

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

    def _extract_seed_text(self, page_like: Any) -> str:
        t = self._safe_get(page_like, ["_seed_response", "text"], None)
        if isinstance(t, str) and t.strip():
            return t
        t = self._safe_get(page_like, ["text"], None)
        if isinstance(t, str) and t.strip():
            return t
        t = self._safe_get(page_like, ["response", "text"], None)
        if isinstance(t, str) and t.strip():
            return t
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
        if server.startswith("socks5://"):
            server = server.replace("socks5://", "socks5h://", 1)
        return {"http": server, "https": server}

    def _fetch_refhtml(self, url: str) -> Tuple[str, Dict[str, Any]]:
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
                "status_code": int(r.status_code),
                "final_url": r.url or url,
                "content_len": int(len(txt)),
                "content_type": (r.headers.get("Content-Type") or "").strip(),
                "server": (r.headers.get("Server") or "").strip(),
            }
            return txt, meta
        except Exception as ex:
            return "", {
                "error": str(ex),
                "status_code": 0,
                "final_url": url,
                "content_len": 0,
                "content_type": "",
                "server": "",
            }

    def _parse_urls_from_feed_text(self, text: str) -> List[str]:
        text = text or ""
        urls = re.findall(r"https?://[^\s\"\'<>]+", text)
        out: List[str] = []
        for u in urls:
            u = (u or "").strip()
            if self._looks_like_url(u):
                out.append(u)
        return out

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

        challenge = ("one moment, please" in text) or ("checking your browser" in text) or ("security checkpoint" in text)

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
            "amazon": ["amazon", "aws"],
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

        login_keywords = any(k in text for k in ["sign in", "login", "verify", "password", "otp", "2fa", "authenticate"])

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
            "challenge": challenge,
            "login_keywords": login_keywords,
        }

    @staticmethod
    def _severity_from_score(score: int) -> str:
        if score >= 80:
            return "HIGH"
        if score >= 50:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _action_from_score(score: int) -> str:
        if score >= 80:
            return "BLOCK NOW"
        if score >= 50:
            return "REVIEW"
        return "IGNORE"

    def _score_analysis(self, analysis: Dict[str, Any], fetch_meta: Dict[str, Any]) -> Tuple[int, List[str]]:
        score = 0
        reasons: List[str] = []

        forms = int(analysis.get("forms") or 0)
        pw = int(analysis.get("pw_inputs") or 0)
        category = (analysis.get("category") or "unknown").lower()
        brands = analysis.get("brands") or []
        login_kw = bool(analysis.get("login_keywords"))
        challenge = bool(analysis.get("challenge"))
        status = int(fetch_meta.get("status_code") or 0)

        if status in (200, 201, 202):
            score += 5
            reasons.append("reachable_http_2xx")
        if status in (301, 302, 307, 308):
            score += 3
            reasons.append("redirect_http_3xx")
        if status in (401, 403):
            score += 1
            reasons.append("blocked_or_checkpoint")

        if forms > 0:
            score += 20
            reasons.append("form_detected")
        if pw > 0:
            score += 40
            reasons.append("password_input_detected")
        if login_kw:
            score += 15
            reasons.append("login_keywords_detected")

        if category == "cloud_hosted":
            score += 10
            reasons.append("cloud_hosted_platform")
        if category == "redirector":
            score += 10
            reasons.append("redirector_or_shortener")

        if brands:
            score += 10
            reasons.append(f"brand_keywords:{','.join(brands)}")

        if challenge:
            score -= 25
            reasons.append("challenge_page_detected")

        score = max(0, min(100, score))
        return score, reasons

    def _print_ioc_card(self, url: str, fetch_meta: Dict[str, Any], analysis: Dict[str, Any], score: int, reasons: List[str]):
        sev = self._severity_from_score(score)
        action = self._action_from_score(score)

        print("\n[IOC CARD]")
        print(f"  Score: {score} ({sev})   Recommended: {action}")
        print(f"  URL: {url}")
        print(f"  Final URL: {fetch_meta.get('final_url')}")
        print(f"  Host: {analysis.get('host')}")
        print(f"  Category: {analysis.get('category')}")
        print(f"  Brands: {', '.join(analysis.get('brands') or []) if (analysis.get('brands') or []) else '-'}")
        print(f"  HTTP: {fetch_meta.get('status_code')} | Content-Type: {fetch_meta.get('content_type')} | Server: {fetch_meta.get('server')}")
        print("  Signals:")
        print(f"    form_detected={analysis.get('forms')} | password_inputs={analysis.get('pw_inputs')} | login_keywords={analysis.get('login_keywords')}")
        print(f"    challenge_page={analysis.get('challenge')}")
        print("  Fingerprint:")
        print(f"    SHA1={analysis.get('sha1')}")
        print(f"  Reasons: {', '.join(reasons) if reasons else '-'}")
        if self._print_analysis:
            print(f"  Snippet(0..{self._snippet_len}): {analysis.get('snippet')}")

    def _add_output_item(self, url: str, html: str, fetch_meta: Dict[str, Any], analysis: Dict[str, Any], score: int, reasons: List[str]):
        item = {
            "date": str(date.today()),
            "source": "phishunt",
            "seed_url": self.seed_url,
            "url": url,
            "final_url": fetch_meta.get("final_url"),
            "host": analysis.get("host"),
            "category": analysis.get("category"),
            "brands": analysis.get("brands") or [],
            "fetch": fetch_meta,
            "analysis": {
                "title": analysis.get("title"),
                "forms": analysis.get("forms"),
                "password_inputs": analysis.get("pw_inputs"),
                "scripts": analysis.get("scripts"),
                "iframes": analysis.get("iframes"),
                "login_keywords": analysis.get("login_keywords"),
                "challenge": analysis.get("challenge"),
                "sha1": analysis.get("sha1"),
                "snippet": analysis.get("snippet"),
                "raw_html_len": len(html or ""),
            },
            "score": score,
            "severity": self._severity_from_score(score),
            "recommended_action": self._action_from_score(score),
            "reasons": reasons,
        }
        if self._include_raw_html_in_json:
            item["raw_html"] = html or ""
        self._output_items.append(item)

    def _write_output_json(self):
        if not self._write_json_file:
            return

        out_path = self._json_out_path or f"phishunt_output_{date.today().isoformat()}.json"
        payload = {
            "generated_on": str(date.today()),
            "seed_url": self.seed_url,
            "count": len(self._output_items),
            "items": self._output_items,
        }

        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            print(f"[PHISHUNT] ✅ JSON written: {out_path} (items={len(self._output_items)})")
        except Exception as ex:
            print(f"[PHISHUNT] ❌ Failed to write JSON: {ex}")

    def parse_leak_data(self, page_like):
        try:
            seed_text = self._extract_seed_text(page_like)

            print("\n=================== [PHISHUNT] DEBUG ===================")
            print(f"Seed URL: {self.seed_url}")
            print(f"Seed TEXT length: {len(seed_text or '')}")
            print("========================================================\n")

            if not seed_text:
                log.g().e("[PHISHUNT] No text received for seed page.")
                self._is_crawled = True
                return {"seed_url": self.seed_url, "items_collected": 0, "error": "no_seed_text"}

            urls = self._dedupe_keep_order(self._parse_urls_from_feed_text(seed_text))
            collected = 0
            max_rows = self._max_rows or len(urls)

            for idx, url in enumerate(urls, start=1):
                if idx > max_rows:
                    print("[PHISHUNT] Max rows reached, stopping.")
                    break

                print("\n------------------- [PHISHUNT] ITEM -------------------")
                print(f"#{idx}/{len(urls)}")
                print(f"URL: {url}")
                print("------------------------------------------------------")

                html, fetch_meta = self._fetch_refhtml(url)

                if fetch_meta.get("error"):
                    print(f"[PHISHUNT] Fetch ERROR: {fetch_meta['error']}")
                else:
                    print(f"[PHISHUNT] Status: {fetch_meta.get('status_code')}")
                    print(f"[PHISHUNT] Final URL: {fetch_meta.get('final_url')}")
                    print(f"[PHISHUNT] Content-Type: {fetch_meta.get('content_type')}")
                    print(f"[PHISHUNT] Server: {fetch_meta.get('server')}")
                    print(f"[PHISHUNT] HTML len: {fetch_meta.get('content_len')}")

                analysis = self._analyze_html(html, fetch_meta.get("final_url", url))
                score, reasons = self._score_analysis(analysis, fetch_meta)

                # ✅ prints score
                if self._enable_ioc_card_print:
                    self._print_ioc_card(url, fetch_meta, analysis, score, reasons)

                # ✅ store JSON envelope in m_content for UI
                envelope = {
                    "fetch": fetch_meta,
                    "analysis": analysis,
                    "score": score,
                    "severity": self._severity_from_score(score),
                    "recommended_action": self._action_from_score(score),
                    "reasons": reasons,
                }
                if self._include_raw_html_in_json:
                    envelope["raw_html"] = html or ""

                card = defacement_model(
                    m_content=json.dumps(envelope, ensure_ascii=False),
                    m_url=url,
                    m_base_url=self.base_url,
                    m_source_url=[self.base_url],
                    m_network=helper_method.get_network_type(self.base_url),
                    m_ioc_type=["phishing"],
                    m_leak_date=date.today(),
                )

                ent = entity_model(
                    m_scrap_file=self.__class__.__name__,
                    m_team="phishunt",
                    m_weblink=[url],
                )

                self.append_leak_data(card, ent)
                self._add_output_item(url, html, fetch_meta, analysis, score, reasons)
                collected += 1

            self._is_crawled = True
            self._write_output_json()

            print(f"\n[PHISHUNT] ✅ Done. Collected={collected}")
            return {"seed_url": self.seed_url, "items_collected": collected}

        except Exception as ex:
            log.g().e(f"[PHISHUNT] SCRIPT ERROR {ex} " + str(self.__class__.__name__))
            self._is_crawled = True
            return {"seed_url": self.seed_url, "items_collected": 0, "error": str(ex)}
