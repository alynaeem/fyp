import re
import json
import hashlib
from abc import ABC
from datetime import datetime, timezone
from typing import List, Optional, Set, Tuple

from playwright.sync_api import (
    Page,
    sync_playwright,
    TimeoutError as PlaywrightTimeoutError,
)

# ✅ SAME STYLE AS ACN
from crawler.common.crawler_instance.local_interface_model.leak.leak_extractor_interface import (
    leak_extractor_interface,
)
from crawler.common.crawler_instance.local_shared_model.data_model import entity_model
from crawler.common.crawler_instance.local_shared_model.data_model import leak_model
from crawler.common.crawler_instance.local_shared_model import (
    RuleModel,
    FetchProxy,
    FetchConfig,
    ThreatType,
)
from crawler.common.crawler_instance.crawler_services.redis_manager.redis_controller import (
    redis_controller,
)
from crawler.common.crawler_instance.crawler_services.shared.helper_method import (
    helper_method,
)

# Optional developer signature helper (keeps backward compatibility if project doesn't have it)
try:
    from crawler.common.dev_signature import developer_signature as _dev_sig
except Exception:
    _dev_sig = None


class _akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad(
    leak_extractor_interface, ABC
):
    """
    Akira onion (CLI-like UI):
      - waits for textarea.cmd-clipboard
      - writes 'leaks' and presses Enter
      - expects a JSON response containing a list of leak items:
            { "name": "...", "desc": "...", "url": "..." }

    Notes:
      - RequestParser calls model.run() WITHOUT args in your framework.
      - So this class creates Playwright browser/page inside run().
      - Onion SSL is often invalid → ignore_https_errors=True is REQUIRED.
    """

    _instance = None

    # ---------------- singleton ----------------
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(
                _akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad, cls
            ).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, developer_name: str = "open", developer_note: str = "open"):
        if getattr(self, "_initialized", False):
            return
        self._initialized = True

        self.callback = None
        self._proxy: dict = {}

        self._card_data: List[leak_model] = []
        self._entity_data: List[entity_model] = []

        self._redis = redis_controller()
        self._is_crawled: bool = False

        self._developer_name = developer_name
        self._developer_note = developer_note

        # Redis master indexes (pipe-delimited strings, NOT JSON)
        self._raw_index_key = "AKIRA:raw_index"
        self._json_index_key = "AKIRA:json_index"

        # De-dup across one run
        self._seen_ids: Set[str] = set()

        print("[AKIRA] Initialized ✅ (Playwright/Tor, Redis raw+ui)")

    # ---------------- config hooks ----------------
    def init_callback(self, callback=None):
        self.callback = callback
        print("[AKIRA] Callback set")

    def set_proxy(self, proxy: dict):
        """
        Example:
          model.set_proxy({"server": "socks5://127.0.0.1:9150"})
        """
        self._proxy = proxy or {}
        print(f"[AKIRA] Proxy configured: {self._proxy}")

    # ---------------- required properties ----------------
    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    def developer_signature(self) -> str:
        if _dev_sig:
            return _dev_sig(self._developer_name, self._developer_note)
        return f"{self._developer_name}:{self._developer_note}"

    @property
    def seed_url(self) -> str:
        return (
            "https://akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion/"
        )

    @property
    def base_url(self) -> str:
        return (
            "https://akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion/"
        )

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_timeout=57200,
            m_fetch_proxy=FetchProxy.TOR,
            m_fetch_config=FetchConfig.PLAYWRIGHT,
            m_resoource_block=False,
            m_threat_type=ThreatType.LEAK,
        )

    @property
    def card_data(self) -> List[leak_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def contact_page(self) -> str:
        return self.seed_url

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
        return hashlib.sha1((text or "").encode("utf-8")).hexdigest()

    @staticmethod
    def _clean_text(s: str) -> str:
        return re.sub(r"\s+", " ", (s or "")).strip()

    @staticmethod
    def _extract_magnet(desc: str) -> str:
        if not desc:
            return ""
        idx = desc.find("magnet:?")
        if idx == -1:
            return ""
        tail = desc[idx:].strip()
        return tail.split()[0].strip()

    @staticmethod
    def _normalize_dump_url(raw: str) -> str:
        if not raw:
            return ""
        u = raw.strip()
        if u.startswith("[[!;;;;") and "]" in u:
            u = u.split("]")[0].replace("[[!;;;;", "").strip()
        return u.strip()

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

    # ---------------- raw store ----------------
    def _store_raw_card(self, aid: str, card: leak_model, magnet: str, dump_url: str):
        base = f"AKIRA:raw:{aid}"

        self._redis_set(f"{base}:url", card.m_url or "")
        self._redis_set(f"{base}:title", card.m_title or "")
        self._redis_set(f"{base}:base_url", card.m_base_url or "")
        self._redis_set(f"{base}:seed_url", self.seed_url)
        self._redis_set(f"{base}:network:type", card.m_network or "")
        self._redis_set(f"{base}:important", card.m_important_content or "")
        self._redis_set(f"{base}:content", card.m_content or "")
        self._redis_set(f"{base}:magnet", magnet or "")
        self._redis_set(f"{base}:dump_url", dump_url or "")
        self._redis_set(
            f"{base}:scraped_at", int(datetime.now(timezone.utc).timestamp())
        )
        self._redis_set(f"{base}:rendered", "0")

        cts = getattr(card, "m_content_type", None) or []
        self._redis_set(f"{base}:content_type_count", len(cts))
        for i, v in enumerate(cts):
            self._redis_set(f"{base}:content_type:{i}", v)

        dumps = getattr(card, "m_dumplink", None) or []
        self._redis_set(f"{base}:dumplink_count", len(dumps))
        for i, v in enumerate(dumps):
            self._redis_set(f"{base}:dumplink:{i}", v)

        self._append_index(self._raw_index_key, aid)

    # ---------------- JSON store for UI ----------------
    def _store_json_for_ui(self, aid: str, card: leak_model, entity: entity_model):
        payload = {
            "aid": aid,
            "leak": card.to_dict()
            if hasattr(card, "to_dict")
            else {
                "title": card.m_title,
                "url": card.m_url,
                "base_url": card.m_base_url,
                "network": card.m_network,
                "important_content": card.m_important_content,
                "content_type": getattr(card, "m_content_type", []) or [],
                "dumplink": getattr(card, "m_dumplink", []) or [],
                "content": card.m_content,
            },
            "entity": entity.__dict__ if hasattr(entity, "__dict__") else str(entity),
            "scraped_at": int(datetime.now(timezone.utc).timestamp()),
            "developer_signature": self.developer_signature(),
        }

        key = f"AKIRA:ui:{aid}"
        self._redis_set(key, json.dumps(payload, ensure_ascii=False))
        self._append_index(self._json_index_key, aid)

    # ---------------- response parsing ----------------
    def _parse_json_list_response(
        self, json_data
    ) -> List[Tuple[leak_model, entity_model, str, str, str]]:
        """
        Returns list of tuples: (card, entity, aid, magnet, dump_url)
        """
        out: List[Tuple[leak_model, entity_model, str, str, str]] = []
        if not isinstance(json_data, list):
            return out

        for item in json_data:
            if not isinstance(item, dict):
                continue

            name = self._clean_text(str(item.get("name", "")))
            desc = self._clean_text(str(item.get("desc", "")))
            raw_url = str(item.get("url", "") or "")
            dump_url = self._normalize_dump_url(raw_url)

            if not name and not desc and not dump_url:
                continue

            magnet = self._extract_magnet(desc)

            key_material = dump_url or name or (desc[:200] if desc else "")
            aid = self._sha1(key_material)
            if aid in self._seen_ids:
                continue
            self._seen_ids.add(aid)

            m_content = (
                f"Name: {name}\n"
                f"Description: {desc}\n"
                f"Magnet: {magnet}\n"
                f"URL: {dump_url}"
            )

            dump_links = [x for x in [magnet, dump_url] if x]

            card = leak_model(
                m_title=name or (dump_url[:80] if dump_url else "Akira Leak"),
                m_url=self.seed_url,  # keep stable
                m_base_url=self.base_url,
                #m_screenshot=None,
                m_content=m_content,
                m_network=helper_method.get_network_type(self.base_url),
                m_important_content=(
                    desc[:500] if desc else (name[:500] if name else "")
                ),
                m_dumplink=dump_links,
                m_content_type=["leaks"],
            )

            entity = entity_model(
                m_scrap_file=self.__class__.__name__,
                m_team="akira",
            )

            out.append((card, entity, aid, magnet, dump_url))

        return out

    def _capture_json_response(self, page: Page, timeout_ms: int = 30000):
        """
        Capture JSON list response after submitting 'leaks'.
        """
        def _is_json_response(r):
            try:
                ct = (r.headers or {}).get("content-type", "")
                return "application/json" in (ct or "").lower()
            except Exception:
                return False

        try:
            with page.expect_response(_is_json_response, timeout=timeout_ms) as resp_info:
                page.keyboard.press("Enter")
            return resp_info.value
        except PlaywrightTimeoutError:
            pass

        try:
            page.keyboard.press("Enter")
            return page.context.wait_for_event("response", timeout=timeout_ms)
        except Exception:
            return None

    # ---------------- main extraction ----------------
    def parse_leak_data(self, page: Page):
        try:
            page.wait_for_load_state("networkidle")
        except Exception:
            pass

        page.wait_for_selector("textarea.cmd-clipboard", timeout=30000)
        page.fill("textarea.cmd-clipboard", "leaks")

        response = self._capture_json_response(page, timeout_ms=30000)
        if not response:
            self._is_crawled = True
            print("[AKIRA] ❌ No response captured")
            return

        try:
            json_data = response.json()
        except Exception as e:
            self._is_crawled = True
            print(f"[AKIRA] ❌ Response JSON parse failed: {e}")
            return

        parsed_items = self._parse_json_list_response(json_data)
        if not parsed_items:
            self._is_crawled = True
            print("[AKIRA] No leaks found (empty/unsupported JSON)")
            return

        for card, entity, aid, magnet, dump_url in parsed_items:
            try:
                card.m_screenshot = helper_method.get_screenshot_base64(
                    page, card.m_title or "akira", self.base_url
                )
            except Exception:
                card.m_screenshot = None

            self.append_leak_data(card, entity)

            try:
                self._store_raw_card(aid, card, magnet=magnet, dump_url=dump_url)
                self._store_json_for_ui(aid, card, entity)
            except Exception as e:
                print(f"[AKIRA] ⚠ Redis store failed for {aid}: {e}")

            print(f"[AKIRA] +1 | {card.m_title[:90]}")

        self._is_crawled = True
        print(f"[AKIRA] ✅ Done. Collected={len(parsed_items)}")

    # ---------------- main runner (RequestParser calls model.run() with NO args) ----------------
    def run(self) -> dict:
        """
        Your framework calls model.run() with no args.
        We create Playwright here, enable onion SSL bypass, and execute parse_leak_data(page).
        """
        collected_before = len(self._card_data)

        proxy_server = (self._proxy or {}).get("server")
        if not proxy_server and self.rule_config.m_fetch_proxy == FetchProxy.TOR:
            proxy_server = "socks5://127.0.0.1:9050"

        try:
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
                    ignore_https_errors=True,  # ✅ FIX for ERR_CERT_AUTHORITY_INVALID
                )

                page = context.new_page()
                page.goto(self.seed_url, timeout=180000, wait_until="domcontentloaded")

                self.parse_leak_data(page)

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

        except Exception as e:
            self._is_crawled = True
            print(f"[AKIRA] ❌ run() failed: {e}")
            return {
                "seed_url": self.seed_url,
                "items_collected": max(0, len(self._card_data) - collected_before),
                "developer_signature": self.developer_signature(),
                "error": str(e),
            }

        return {
            "seed_url": self.seed_url,
            "items_collected": max(0, len(self._card_data) - collected_before),
            "developer_signature": self.developer_signature(),
        }