from __future__ import annotations

import inspect
import json
import re
from abc import ABC
from datetime import date, datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse
import os
from pathlib import Path
from datetime import timezone
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

from crawler.common.crawler_instance.local_interface_model.leak.leak_extractor_interface import (
    leak_extractor_interface,
)
from crawler.common.crawler_instance.local_shared_model.data_model.entity_model import (
    entity_model,
)
from crawler.common.crawler_instance.local_shared_model.data_model.social_model import (
    social_model,
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


class _4hpfzoj3tgyp2w7sbe3gnmphqiqpxwwyijyvotamrvojl7pkra7z7byd(leak_extractor_interface, ABC):
    _instance = None

    # RequestParser ko hint: seed_fetch zaroor chahiye
    needs_seed_fetch = True

    NAV_TIMEOUT_MS = 120_000
    SEED_MAX_URLS = 50
    POSTS_LIMIT_FIRST_RUN = 30
    POSTS_LIMIT_NEXT_RUN = 30

    def __init__(self, callback=None):
        self.callback = callback
        self._card_data: List[social_model] = []
        self._entity_data: List[entity_model] = []
        self._redis_instance = redis_controller()
        self._is_crawled = False
        # -------------------------
        # JSONL File output
        # -------------------------
        base_dir = os.getenv("DARKPULSE_EXPORT_DIR", "data/exports")
        Path(base_dir).mkdir(parents=True, exist_ok=True)

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        script_name = self.__class__.__name__
        self._jsonl_path = str(Path(base_dir) / f"{script_name}_{ts}.jsonl")
        # RequestParser may set one of these
        self.page = None
        self._page = None
        self.seed_page = None
        self._request_page = None

        # RequestParser seed fetch attaches these
        self._seed_response = None
        self._seed_html = ""

    def __new__(cls, callback=None):
        if cls._instance is None:
            cls._instance = super(_4hpfzoj3tgyp2w7sbe3gnmphqiqpxwwyijyvotamrvojl7pkra7z7byd, cls).__new__(cls)
        return cls._instance

    # -------------------------
    # META
    # -------------------------
    @property
    def seed_url(self) -> str:
        return "http://4hpfzoj3tgyp2w7sbe3gnmphqiqpxwwyijyvotamrvojl7pkra7z7byd.onion"

    @property
    def base_url(self) -> str:
        u = urlparse(self.seed_url)
        return f"{u.scheme}://{u.netloc}"

    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def rule_config(self) -> RuleModel:
        # IMPORTANT: RequestParser does REQUESTS seed fetch (HTML already).
        # Drilldown hum run() me Playwright se karenge.
        return RuleModel(
            m_fetch_proxy=FetchProxy.TOR,
            m_fetch_config=FetchConfig.REQUESTS,
            m_threat_type=ThreatType.SOCIAL,
        )

    @property
    def card_data(self) -> List[social_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def contact_page(self) -> str:
        return self.seed_url

    # -------------------------
    # Printing (JSONL)
    # -------------------------
    def _print_jsonl(self, payload: Dict[str, Any]):
        line = json.dumps(payload, ensure_ascii=False, default=str)

        # 1) Console
        print(line, flush=True)

        # 2) File (JSONL append)
        try:
            with open(self._jsonl_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
        except Exception as ex:
            # File write fail ho to crawling rukni nahi chahiye
            log.g().e(f"[onion] JSONL file write failed: {ex} | path={getattr(self, '_jsonl_path', '')}")

    # -------------------------
    # Redis helpers (same pattern)
    # -------------------------
    def invoke_db(self, command, key: str, default_value, expiry: int = None):
        try:
            cmd_value = command.value if hasattr(command, "value") else int(command)
        except Exception:
            cmd_value = command
        namespaced_key = f"{key}{self.__class__.__name__}"
        return self._redis_instance.invoke_trigger(cmd_value, [namespaced_key, default_value, expiry])

    def _redis_cmd(self, name: str):
        return getattr(REDIS_COMMANDS, name, None)

    def _redis_key(self, name: str, default: str) -> str:
        key_enum = getattr(CUSTOM_SCRIPT_REDIS_KEYS, name, None)
        if key_enum is not None and hasattr(key_enum, "value"):
            return str(key_enum.value)
        return default

    def _redis_save_json(self, key: str, payload: Dict[str, Any], expiry: int = 60 * 60 * 24 * 7):
        data = json.dumps(payload, ensure_ascii=False, default=str)

        rpush_cmd = self._redis_cmd("RPUSH")
        lpush_cmd = self._redis_cmd("LPUSH")
        set_cmd = self._redis_cmd("SET")

        if rpush_cmd is not None:
            self.invoke_db(rpush_cmd, key, data, expiry=expiry)
            return
        if lpush_cmd is not None:
            self.invoke_db(lpush_cmd, key, data, expiry=expiry)
            return
        if set_cmd is not None:
            uniq = payload.get("m_hash") or payload.get("hash") or str(datetime.utcnow().timestamp())
            self.invoke_db(set_cmd, f"{key}:{uniq}", data, expiry=expiry)
            return

        log.g().e(f"[onion] Redis save skipped (no RPUSH/LPUSH/SET) | key={key}")

    # -------------------------
    # Safe entity_model creator (no crashes)
    # -------------------------
    def _safe_entity(self, **kwargs) -> entity_model:
        sig = inspect.signature(entity_model.__init__)
        params = sig.parameters

        allowed = set(params.keys())
        allowed.discard("self")

        filtered = {k: v for k, v in kwargs.items() if k in allowed}

        for name, p in params.items():
            if name == "self":
                continue
            is_required = (p.default is inspect._empty) and (
                p.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
            )
            if is_required and name not in filtered:
                if name == "m_scrap_file":
                    filtered[name] = self.__class__.__name__
                elif name in ("m_username",):
                    filtered[name] = ["unknown"]
                else:
                    filtered[name] = "unknown"

        if "m_scrap_file" not in filtered:
            filtered["m_scrap_file"] = self.__class__.__name__

        return entity_model(**filtered)

    # -------------------------
    # Utils
    # -------------------------
    @staticmethod
    def _clean(s: str) -> str:
        return re.sub(r"\s+", " ", (s or "")).strip()

    def _parse_date_str(self, s: str) -> Optional[date]:
        if not s:
            return None
        s = (s or "").strip()

        # --- ISO 8601 support (e.g. 2025-12-01T10:20:30Z or with timezone) ---
        try:
            iso = s.replace("Z", "+00:00")
            dt = datetime.fromisoformat(iso)
            return dt.date()
        except Exception:
            pass

        # Common formats
        fmts = [
            "%Y-%m-%d",
            "%Y/%m/%d",
            "%d-%m-%Y",
            "%d/%m/%Y",
            "%B %d, %Y",
            "%b %d, %Y",
            "%d %B %Y",
            "%d %b %Y",
        ]
        for f in fmts:
            try:
                return datetime.strptime(s, f).date()
            except Exception:
                pass

        # Regex fallback: YYYY-MM-DD inside text
        m = re.search(r"(\d{4})-(\d{2})-(\d{2})", s)
        if m:
            try:
                return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            except Exception:
                return None

        # Regex fallback: YYYY/M/D or YYYY-M-D
        m2 = re.search(r"(\d{4})[-/](\d{1,2})[-/](\d{1,2})", s)
        if m2:
            try:
                return date(int(m2.group(1)), int(m2.group(2)), int(m2.group(3)))
            except Exception:
                return None

        return None

    def _get_seed_html(self, page_obj) -> str:
        # 1) RequestParser seed_fetch response
        try:
            if hasattr(page_obj, "_seed_response") and page_obj._seed_response is not None:
                return page_obj._seed_response.text or ""
        except Exception:
            pass

        try:
            if hasattr(self, "_seed_response") and self._seed_response is not None:
                return self._seed_response.text or ""
        except Exception:
            pass

        # 2) cached
        html = getattr(self, "_seed_html", "") or ""
        if html:
            return html

        # 3) if playwright Page was passed
        try:
            if hasattr(page_obj, "content"):
                return page_obj.content() or ""
        except Exception:
            pass

        return ""

    def _collect_post_urls_from_seed(self, html: str) -> List[str]:
        soup = BeautifulSoup(html, "lxml")

        # primary selector
        anchors = soup.select("a.post__title-link")

        # fallback selectors
        if not anchors:
            anchors = soup.select("article a[href]") or soup.select("h2 a[href]") or soup.select("h3 a[href]") or []

        urls: List[str] = []
        seen = set()

        for a in anchors:
            href = (a.get("href") or "").strip()
            if not href or href == "#":
                continue

            full = urljoin(self.base_url, href)

            # internal only
            try:
                pu = urlparse(full)
                if pu.netloc != urlparse(self.base_url).netloc:
                    continue
            except Exception:
                continue

            low = full.lower()
            if any(x in low for x in ("/category", "/tag", "/tags", "/search", "/login", "/register", "/author")):
                continue

            # keep post-ish urls
            if not re.search(r"/\d{4}/\d{2}/", low) and not re.search(r"/\d{4}/", low):
                path = urlparse(full).path.strip("/")
                if not path or path.count("/") < 1:
                    continue

            if full not in seen:
                seen.add(full)
                urls.append(full)

        return urls[: self.SEED_MAX_URLS]

    def _get_tor_proxy_server(self) -> str:
        return "socks5://127.0.0.1:9150"

    # -------------------------
    # Extract post fields from HTML
    # -------------------------
    def _extract_post_fields(self, post_html: str, post_url: str) -> Dict[str, Any]:
        soup = BeautifulSoup(post_html, "lxml")

        title_el = soup.select_one("h1.post__title") or soup.select_one("h1") or soup.select_one("title")
        title = self._clean(title_el.get_text(" ", strip=True)) if title_el else ""

        blocks = soup.select("div.post__content")
        if not blocks:
            article = soup.select_one("article")
            if article:
                blocks = [article]
        if not blocks:
            blocks = soup.select("div.content") or soup.select("main") or []

        content = "\n".join(self._clean(b.get_text(" ", strip=True)) for b in blocks if b).strip()

        user_el = (
                soup.select_one("a.meta-categories__link[rel='category']")
                or soup.select_one("a[rel='author']")
                or soup.select_one(".author a")
                or soup.select_one(".post-author a")
        )
        username = self._clean(user_el.get_text(" ", strip=True)) if user_el else "unknown"

        time_el = soup.select_one("time.post__meta-published") or soup.select_one("time")
        raw_date = self._clean(time_el.get_text(" ", strip=True)) if time_el else ""

        if not raw_date:
            meta = soup.select_one("meta[property='article:published_time']") or soup.select_one("meta[name='date']")
            if meta:
                raw_date = self._clean(meta.get("content", ""))

        # ✅ IMPORTANT: keep as date object (NOT string) so social_model can .isoformat() safely
        d = self._parse_date_str(raw_date)
        post_date_obj: date = d if d is not None else datetime.utcnow().date()

        tags = [self._clean(a.get_text(" ", strip=True)) for a in soup.select("a[rel='tag'], .tags a, .tag a") if a]
        categories = [
            self._clean(a.get_text(" ", strip=True))
            for a in soup.select("a[rel='category'], .categories a, .category a")
            if a
        ]
        tags = [t for t in tags if t]
        categories = [c for c in categories if c]

        out_links: List[str] = []
        for a in soup.select("a[href]"):
            href = (a.get("href") or "").strip()
            if not href:
                continue
            full = urljoin(post_url, href)
            if full.startswith(("http://", "https://")):
                out_links.append(full)

        seen = set()
        out_links_u: List[str] = []
        for u in out_links:
            if u not in seen:
                seen.add(u)
                out_links_u.append(u)

        return {
            "title": title,
            "content": content,
            "username": username,
            "post_date": post_date_obj,  # ✅ date object
            "tags": tags,
            "categories": categories,
            "out_links": out_links_u[:200],
        }

    # -------------------------
    # REQUIRED by abstract interface ✅
    # This ONLY parses seed html and prepares URLs + debug.
    # Drilldown actual parsing happens in run() using playwright.
    # -------------------------
    def parse_leak_data(self, page_obj):
        seed_html = self._get_seed_html(page_obj)

        self._print_jsonl(
            {
                "source": "onion_forum",
                "type": "debug",
                "seed_url": self.seed_url,
                "html_length": len(seed_html),
                "has_seed_html": bool(seed_html),
            }
        )

        if not seed_html:
            log.g().e("[onion] Seed HTML empty. Ensure RequestParser(seed_fetch=True)")
            return

        post_urls = self._collect_post_urls_from_seed(seed_html)

        self._print_jsonl(
            {
                "source": "onion_forum",
                "type": "debug",
                "post_links_found": len(post_urls),
                "sample_links": post_urls[:30],
            }
        )

    # -------------------------
    # Drilldown parsing
    # -------------------------
    def _parse_posts_with_nav_page(self, nav_page, post_urls: List[str]):
        redis_items = self._redis_key("SOCIAL_ITEMS", "SOCIAL_ITEMS")
        redis_entities = self._redis_key("SOCIAL_ENTITIES", "SOCIAL_ENTITIES")

        limit = self.POSTS_LIMIT_NEXT_RUN if self.is_crawled else self.POSTS_LIMIT_FIRST_RUN

        for post_url in post_urls[:limit]:
            try:
                nav_page.goto(post_url, wait_until="domcontentloaded", timeout=self.NAV_TIMEOUT_MS)
                nav_page.wait_for_load_state("networkidle")

                post_html = nav_page.content() or ""
                if not post_html:
                    continue

                data = self._extract_post_fields(post_html, post_url)

                card = social_model(
                    m_channel_url=self.seed_url,
                    m_sender_name=data["username"],
                    m_message_sharable_link=post_url,
                    m_weblink=[post_url],
                    m_title=data["title"],
                    m_content=(data["content"][:4000] if data["content"] else ""),
                    m_content_type=["leak", "onion"],
                    m_network=helper_method.get_network_type(self.base_url),
                    m_message_date=data["post_date"],
                    m_message_id=post_url,
                    m_platform="forum",
                    m_source="onion_forum",
                    m_raw={
                        "url": post_url,
                        "username": data["username"],
                        "tags": data["tags"],
                        "categories": data["categories"],
                        "out_links": data["out_links"],
                    },
                )

                if hasattr(card, "compute_hash"):
                    try:
                        card.compute_hash()
                    except Exception:
                        pass

                ent = self._safe_entity(
                    m_scrap_file=self.__class__.__name__,
                    m_username=[data["username"]],
                    m_weblink=[post_url],
                    m_extra={
                        "source": "onion_forum",
                        "hash": getattr(card, "m_hash", ""),
                        "seed": self.seed_url,
                        "tags": data["tags"],
                        "categories": data["categories"],
                    },
                )

                card_payload = card.to_dict() if hasattr(card, "to_dict") else card.__dict__
                ent_payload = ent.to_dict() if hasattr(ent, "to_dict") else ent.__dict__

                record = {"source": "onion_forum", "type": "record", "social": card_payload, "entity": ent_payload}

                # ✅ JSONL output
                self._print_jsonl(record)

                # ✅ Redis save
                self._redis_save_json(redis_items, card_payload)
                self._redis_save_json(redis_entities, ent_payload)

                self._card_data.append(card)
                self._entity_data.append(ent)

            except Exception as ex:
                log.g().e(f"[onion] parse error {ex} | {self.__class__.__name__}")

        self._is_crawled = True

    # -------------------------
    # RUN
    # -------------------------
    def run(self):
        try:
            self._card_data.clear()
            self._entity_data.clear()

            # RequestParser injected object (has _seed_response)
            page_obj = (
                getattr(self, "_request_page", None)
                or getattr(self, "seed_page", None)
                or getattr(self, "_page", None)
                or getattr(self, "page", None)
            )
            if page_obj is None:
                raise RuntimeError("[onion] RequestParser did not inject seed page object")

            seed_html = self._get_seed_html(page_obj)
            if not seed_html:
                raise RuntimeError("[onion] Seed HTML empty. Enable RequestParser(seed_fetch=True)")

            post_urls = self._collect_post_urls_from_seed(seed_html)

            # ✅ debug output
            self._print_jsonl(
                {
                    "source": "onion_forum",
                    "type": "debug",
                    "export_jsonl_path": getattr(self, "_jsonl_path", ""),
                    "post_links_found": len(post_urls),
                    "sample_links": post_urls[:30],
                }
            )

            if not post_urls:
                log.g().e("[onion] No post links found (selectors mismatch).")
                return []

            tor = self._get_tor_proxy_server()

            # ✅ Playwright drilldown ALWAYS created here (no dependency on RequestParser page)
            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        f"--proxy-server={tor}",
                    ],
                )
                context = browser.new_context(
                    user_agent=(
                        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/120 Safari/537.36"
                    ),
                    viewport={"width": 1280, "height": 720},
                    locale="en-US",
                    ignore_https_errors=True,
                )
                nav_page = context.new_page()

                try:
                    nav_page.add_init_script("Object.defineProperty(navigator, 'webdriver', { get: () => undefined });")
                except Exception:
                    pass

                self._parse_posts_with_nav_page(nav_page, post_urls)

                context.close()
                browser.close()

            return [
                {
                    "social": c.to_dict() if hasattr(c, "to_dict") else c.__dict__,
                    "entity": e.to_dict() if hasattr(e, "to_dict") else e.__dict__,
                }
                for c, e in zip(self._card_data, self._entity_data)
            ]

        except Exception as ex:
            log.g().e(f"SCRIPT ERROR (run) {ex} | {self.__class__.__name__}")
            raise
