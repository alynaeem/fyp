from __future__ import annotations

import hashlib
import inspect
import json
import re
from abc import ABC
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

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
from crawler.common.crawler_instance.crawler_services.log_manager.log_controller import log


class _dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad(leak_extractor_interface, ABC):
    _instance = None

    needs_seed_fetch = True

    NAV_TIMEOUT_MS = 220_000

    SEED_MAX_THREADS = 250
    THREADS_LIMIT_FIRST_RUN = 120
    THREADS_LIMIT_NEXT_RUN = 60

    COMMENTS_FIRST_N = 10
    COMMENTS_LAST_N = 10
    CONTENT_LIMIT = 4000

    MAX_DAYS_FIRST_RUN = 1500
    MAX_DAYS_NEXT_RUN = 500

    def __init__(self, callback=None):
        self.callback = callback
        self._card_data: List[social_model] = []
        self._entity_data: List[entity_model] = []
        self._redis_instance = redis_controller()
        self._is_crawled = False

        # RequestParser may set these, but we DO NOT depend on them anymore
        self.page = None
        self._page = None
        self.seed_page = None
        self._request_page = None
        self._seed_response = None
        self._seed_html = ""

    def __new__(cls, callback=None):
        if cls._instance is None:
            cls._instance = super(
                _dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad, cls
            ).__new__(cls)
        return cls._instance

    # -------------------------
    # META
    # -------------------------
    @property
    def seed_url(self) -> str:
        return "http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/"

    @property
    def base_url(self) -> str:
        u = urlparse(self.seed_url)
        return f"{u.scheme}://{u.netloc}"

    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def rule_config(self) -> RuleModel:
        # RequestParser seed_fetch is flaky for onion + tls; we handle everything in run()
        return RuleModel(
            m_fetch_proxy=FetchProxy.TOR,
            m_fetch_config=FetchConfig.REQUESTS,
            m_threat_type=getattr(ThreatType, "FORUM", ThreatType.SOCIAL),
        )

    @property
    def card_data(self) -> List[social_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def contact_page(self) -> str:
        return f"{self.base_url}/d/Dread/message/"

    # -------------------------
    # JSONL printing
    # -------------------------
    def _print_jsonl(self, payload: Dict[str, Any]):
        print(json.dumps(payload, ensure_ascii=False, default=str), flush=True)

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

        log.g().e(f"[dread] Redis save skipped (no RPUSH/LPUSH/SET) | key={key}")

    # -------------------------
    # Local utils (NO helper_method)
    # -------------------------
    @staticmethod
    def _clean(s: str) -> str:
        return re.sub(r"\s+", " ", (s or "")).strip()

    @staticmethod
    def _sha256(s: str) -> str:
        return hashlib.sha256((s or "").encode("utf-8", errors="ignore")).hexdigest()

    @staticmethod
    def _network_type(url: str) -> str:
        try:
            host = urlparse(url).netloc.lower()
            if host.endswith(".onion"):
                return "onion"
        except Exception:
            pass
        return "clearnet"

    @staticmethod
    def _date_to_str(d: Optional[date]) -> str:
        if not d:
            return ""
        return d.strftime("%Y%m%d")

    def _parse_date_any(self, s: str) -> Optional[datetime]:
        if not s:
            return None
        s = (s or "").strip()

        # ISO 8601
        try:
            iso = s.replace("Z", "+00:00")
            dt = datetime.fromisoformat(iso)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass

        # common formats
        fmts = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y/%m/%d %H:%M:%S",
            "%Y/%m/%d %H:%M",
            "%d-%m-%Y %H:%M",
            "%d/%m/%Y %H:%M",
        ]
        for f in fmts:
            try:
                dt = datetime.strptime(s, f)
                return dt.replace(tzinfo=timezone.utc)
            except Exception:
                pass

        # loose YYYY-MM-DD
        m = re.search(r"(\d{4})-(\d{2})-(\d{2})", s)
        if m:
            try:
                return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=timezone.utc)
            except Exception:
                return None

        return None

    @staticmethod
    def _filter_comment_text(txt: str) -> str:
        if not txt:
            return ""
        t = txt.strip()
        t = re.sub(r"_\s*_{3,}", " ", t)
        t = re.sub(r"={3,}", " ", t)
        t = re.sub(r"-{3,}", " ", t)
        t = re.sub(r"\n{3,}", "\n\n", t)
        return t.strip()

    def _get_tor_proxy_server(self) -> str:
        return "socks5://127.0.0.1:9150"

    # -------------------------
    # Safe model creators (no crashes)
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

    def _safe_social(self, **kwargs) -> social_model:
        sig = inspect.signature(social_model.__init__)
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
            if not is_required or name in filtered:
                continue

            if name in ("m_channel_url",):
                filtered[name] = self.seed_url
            elif name in ("m_message_sharable_link", "m_message_id"):
                filtered[name] = kwargs.get("m_message_sharable_link") or kwargs.get("m_message_id") or self.seed_url
            elif name in ("m_title",):
                filtered[name] = kwargs.get("m_title") or ""
            elif name in ("m_content",):
                filtered[name] = kwargs.get("m_content") or ""
            elif name in ("m_network",):
                filtered[name] = self._network_type(self.base_url)
            elif name in ("m_message_date",):
                filtered[name] = datetime.utcnow().date()
            elif name in ("m_platform",):
                filtered[name] = "forum"
            else:
                filtered[name] = "unknown"

        return social_model(**filtered)

    # -------------------------
    # Seed parsing
    # -------------------------
    def _collect_threads_from_seed(self, seed_html: str, seed_url: str) -> List[Dict[str, Any]]:
        soup = BeautifulSoup(seed_html, "lxml")
        items: List[Dict[str, Any]] = []
        seen = set()

        for post in soup.select("div.postTop"):
            a = post.select_one("a.title")
            if not a:
                continue

            href = (a.get("href") or "").strip()
            if not href:
                continue

            span_title = a.select_one("span.title-text")
            title = self._clean(span_title.get_text(" ", strip=True) if span_title else a.get_text(" ", strip=True))

            date_span = post.select_one("span[title]")
            raw_date = self._clean(date_span.get("title", "") if date_span else "")
            dt = self._parse_date_any(raw_date)

            thread_url = urljoin(seed_url, href)
            if thread_url in seen:
                continue
            seen.add(thread_url)

            items.append({"thread_url": thread_url, "title": title, "raw_date": raw_date, "dt": dt})

        return items[: self.SEED_MAX_THREADS]

    # -------------------------
    # Last-seen (per section)
    # -------------------------
    def _get_last_seen_date(self, section_url: str, max_days: int) -> date:
        key_timeout = self._redis_key("S_URL_TIMEOUT", "S_URL_TIMEOUT")
        redis_key = self._sha256(section_url) + str(key_timeout)

        get_cmd = getattr(REDIS_COMMANDS, "S_GET_STRING", None) or self._redis_cmd("GET")
        last_seen_str = self.invoke_db(get_cmd, redis_key, "")

        if last_seen_str:
            s = str(last_seen_str).strip()
            try:
                if re.fullmatch(r"\d{8}", s):
                    return datetime.strptime(s, "%Y%m%d").date()
            except Exception:
                pass
            try:
                iso = s.replace("Z", "+00:00")
                return datetime.fromisoformat(iso).date()
            except Exception:
                pass

        return (datetime.now(timezone.utc) - timedelta(days=max_days)).date()

    def _set_last_seen_date(self, section_url: str, d: date):
        key_timeout = self._redis_key("S_URL_TIMEOUT", "S_URL_TIMEOUT")
        redis_key = self._sha256(section_url) + str(key_timeout)

        set_cmd = getattr(REDIS_COMMANDS, "S_SET_STRING", None) or self._redis_cmd("SET")
        self.invoke_db(set_cmd, redis_key, self._date_to_str(d))

    # -------------------------
    # Thread extraction
    # -------------------------
    def _extract_thread_page(self, thread_html: str, thread_url: str) -> Dict[str, Any]:
        soup = BeautifulSoup(thread_html, "lxml")

        body = soup.select_one("div.postContent.viewPostBody")
        body_text = self._clean(body.get_text("\n", strip=True)) if body else ""

        comments = soup.select("div.commentBody")
        count_comments = len(comments)

        parts: List[str] = []
        seen = set()

        if body_text:
            parts.append(body_text)
            seen.add(body_text)

        first = comments[: self.COMMENTS_FIRST_N]
        last = comments[-self.COMMENTS_LAST_N :] if count_comments > self.COMMENTS_LAST_N else []

        for c in list(first) + list(last):
            txt = self._clean(c.get_text("\n", strip=True))
            txt = self._filter_comment_text(txt)
            if txt and txt not in seen:
                seen.add(txt)
                parts.append(txt)

        content = "\n\n".join(parts).strip()
        content = re.sub(r"\n{3,}", "\n\n", content)

        # usernames (best-effort)
        usernames: List[str] = []
        for u in soup.select("a.userName, span.userName, div.userName"):
            name = self._clean(u.get_text(" ", strip=True))
            if name and name not in usernames:
                usernames.append(name)
            if len(usernames) >= 30:
                break

        # out links
        out_links: List[str] = []
        for a in soup.select("a[href]"):
            href = (a.get("href") or "").strip()
            if not href:
                continue
            full = urljoin(thread_url, href)
            if full.startswith(("http://", "https://")):
                out_links.append(full)

        dedup = []
        sset = set()
        for u in out_links:
            if u not in sset:
                sset.add(u)
                dedup.append(u)

        return {
            "content": content,
            "count_comments": count_comments,
            "usernames": usernames,
            "out_links": dedup[:200],
        }

    # -------------------------
    # REQUIRED by abstract interface ✅
    # Only debug; real work in run()
    # -------------------------
    def parse_leak_data(self, page_obj):
        seed_html = ""
        try:
            if hasattr(page_obj, "_seed_response") and page_obj._seed_response is not None:
                seed_html = page_obj._seed_response.text or ""
        except Exception:
            seed_html = ""

        self._print_jsonl(
            {
                "source": "dread_forum",
                "type": "debug",
                "seed_url": self.seed_url,
                "html_length": len(seed_html),
                "has_seed_html": bool(seed_html),
            }
        )

    # -------------------------
    # Drilldown parsing
    # -------------------------
    def _parse_threads_with_nav_page(self, nav_page, section_url: str, threads: List[Dict[str, Any]]):
        redis_items = self._redis_key("SOCIAL_ITEMS", "SOCIAL_ITEMS")
        redis_entities = self._redis_key("SOCIAL_ENTITIES", "SOCIAL_ENTITIES")

        limit = self.THREADS_LIMIT_NEXT_RUN if self.is_crawled else self.THREADS_LIMIT_FIRST_RUN
        max_days = self.MAX_DAYS_NEXT_RUN if self.is_crawled else self.MAX_DAYS_FIRST_RUN
        min_date = (datetime.now(timezone.utc) - timedelta(days=max_days)).date()

        last_seen = self._get_last_seen_date(section_url, max_days=max_days)
        latest_seen: Optional[date] = None
        processed = 0

        for th in threads[:limit]:
            thread_url = th.get("thread_url") or ""
            title = th.get("title") or ""
            dt = th.get("dt")

            if not thread_url:
                continue

            # fast filter if seed dt
            try:
                if isinstance(dt, datetime):
                    d = dt.date()
                    if d < min_date:
                        continue
                    if d <= last_seen:
                        continue
            except Exception:
                pass

            try:
                nav_page.goto(thread_url, wait_until="domcontentloaded", timeout=self.NAV_TIMEOUT_MS)
                nav_page.wait_for_load_state("networkidle")

                html = nav_page.content() or ""
                if not html:
                    continue

                extracted = self._extract_thread_page(html, thread_url)

                # message date
                msg_dt = dt if isinstance(dt, datetime) else datetime.now(timezone.utc)
                msg_date = msg_dt.date()

                if msg_date < min_date:
                    continue
                if msg_date <= last_seen:
                    continue

                if latest_seen is None or msg_date > latest_seen:
                    latest_seen = msg_date

                card = self._safe_social(
                    m_title=title,
                    m_channel_url=section_url,
                    m_message_sharable_link=thread_url,
                    m_weblink=[thread_url],
                    m_content=(extracted["content"][: self.CONTENT_LIMIT] if extracted["content"] else ""),
                    m_content_type=["forum", "onion"],
                    m_network=self._network_type(self.base_url),
                    m_message_date=msg_date,
                    m_message_id=thread_url,
                    m_platform="forum",
                    m_source="dread_forum",
                    m_post_comments_count=str(extracted.get("count_comments") or "0"),
                    m_raw={
                        "url": thread_url,
                        "section": section_url,
                        "usernames": extracted.get("usernames") or [],
                        "out_links": extracted.get("out_links") or [],
                    },
                )

                if hasattr(card, "compute_hash"):
                    try:
                        card.compute_hash()
                    except Exception:
                        pass

                ent = self._safe_entity(
                    m_scrap_file=self.__class__.__name__,
                    m_username=(extracted.get("usernames") or ["unknown"]),
                    m_weblink=[thread_url],
                    m_extra={
                        "source": "dread_forum",
                        "hash": getattr(card, "m_hash", ""),
                        "seed": section_url,
                    },
                )

                card_payload = card.to_dict() if hasattr(card, "to_dict") else card.__dict__
                ent_payload = ent.to_dict() if hasattr(ent, "to_dict") else ent.__dict__

                self._print_jsonl({"source": "dread_forum", "type": "record", "social": card_payload, "entity": ent_payload})

                self._redis_save_json(redis_items, card_payload)
                self._redis_save_json(redis_entities, ent_payload)

                self._card_data.append(card)
                self._entity_data.append(ent)
                processed += 1

                if self.callback:
                    try:
                        if self.callback():
                            self._card_data.clear()
                            self._entity_data.clear()
                    except Exception:
                        pass

            except Exception as ex:
                log.g().e(f"[dread] thread parse error {ex} | {self.__class__.__name__}")

        if latest_seen:
            try:
                self._set_last_seen_date(section_url, latest_seen)
            except Exception:
                pass

        self._is_crawled = True
        self._print_jsonl(
            {
                "source": "dread_forum",
                "type": "debug",
                "section": section_url,
                "processed": processed,
                "latest_seen": str(latest_seen) if latest_seen else "",
                "last_seen_cutoff": str(last_seen),
            }
        )

    # -------------------------
    # RUN (NO dependency on RequestParser injection)
    # -------------------------
    def run(self):
        try:
            self._card_data.clear()
            self._entity_data.clear()

            sections = [
                self.seed_url,
                f"{self.base_url}/d/all",
            ]

            tor = self._get_tor_proxy_server()

            self._print_jsonl(
                {
                    "source": "dread_forum",
                    "type": "debug",
                    "msg": "run() using Playwright+TOR directly (ignoring RequestParser seed_fetch).",
                    "tor_proxy": tor,
                    "sections": sections,
                }
            )

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
                    ignore_https_errors=True,  # ✅ important for weird tls/certs
                )
                nav_page = context.new_page()

                try:
                    nav_page.add_init_script("Object.defineProperty(navigator, 'webdriver', { get: () => undefined });")
                except Exception:
                    pass

                # optional: wait logo
                try:
                    nav_page.goto(self.seed_url, wait_until="domcontentloaded", timeout=self.NAV_TIMEOUT_MS)
                    nav_page.wait_for_selector("a.dreadLogo", state="visible", timeout=self.NAV_TIMEOUT_MS)
                except Exception:
                    pass

                for section_url in sections:
                    try:
                        nav_page.goto(section_url, wait_until="domcontentloaded", timeout=self.NAV_TIMEOUT_MS)
                        nav_page.wait_for_load_state("networkidle")
                        seed_html = nav_page.content() or ""
                    except Exception as ex:
                        log.g().e(f"[dread] section seed fetch failed {ex} | {section_url}")
                        continue

                    self._print_jsonl(
                        {
                            "source": "dread_forum",
                            "type": "debug",
                            "section": section_url,
                            "seed_html_length": len(seed_html),
                        }
                    )
                    if not seed_html:
                        continue

                    threads = self._collect_threads_from_seed(seed_html, section_url)
                    self._print_jsonl(
                        {
                            "source": "dread_forum",
                            "type": "debug",
                            "section": section_url,
                            "threads_found": len(threads),
                            "sample_threads": threads[:30],
                        }
                    )
                    if not threads:
                        continue

                    self._parse_threads_with_nav_page(nav_page, section_url, threads)

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
