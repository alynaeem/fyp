from __future__ import annotations

import inspect
import json
import re
import time
from abc import ABC
from datetime import datetime, date
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse, urljoin

from playwright.sync_api import sync_playwright, Page

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
)

try:
    from crawler.common.crawler_instance.crawler_services.redis_manager.redis_enums import (
        CUSTOM_SCRIPT_REDIS_KEYS,
    )
except Exception:
    CUSTOM_SCRIPT_REDIS_KEYS = None  # type: ignore

try:
    from crawler.common.crawler_instance.crawler_services.redis_manager.redis_enums import (
        REDIS_KEYS,
    )
except Exception:
    REDIS_KEYS = None  # type: ignore

from crawler.common.crawler_instance.crawler_services.shared.helper_method import (
    helper_method,
)
from crawler.common.crawler_instance.crawler_services.log_manager.log_controller import (
    log,
)


class _mastodon(leak_extractor_interface, ABC):
    """
    ✅ Pure Playwright Chromium DOM extractor (public profile)
    ✅ Robust waiting + scroll/load-more
    ✅ Avoids false-positive login-wall detection on mastodon.social
    ✅ Prints JSON (pretty) + JSONL (single-line) for profile + each post + each record
    """

    _instance = None
    needs_seed_fetch = False  # we don't want RequestParser seed HTML

    # tune these if needed
    NAV_TIMEOUT_MS = 60_000
    DEFAULT_TIMEOUT_MS = 30_000

    POST_TARGET_FIRST = 30   # collect this many quickly
    POST_TARGET_MAX = 120    # collect up to this (if page allows)

    MAX_ROUNDS = 2
    ROUND_SLEEP_MS = 850

    def __init__(self, callback=None):
        self.callback = callback
        self._card_data: List[social_model] = []
        self._entity_data: List[entity_model] = []
        self._redis_instance = redis_controller()
        self._is_crawled = False

        # compatibility fields (framework may inject, we ignore)
        self.page = None
        self._page = None
        self._request_page = None

        self.m_seed_url = "https://mastodon.social/@falconfeedsio/"
        self._seen_urls: Set[str] = set()

    def __new__(cls, callback=None):
        if cls._instance is None:
            cls._instance = super(_mastodon, cls).__new__(cls)
        return cls._instance

    # ────────────────────────────────────────────────
    # Required props
    # ────────────────────────────────────────────────

    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return self.m_seed_url

    @property
    def base_url(self) -> str:
        u = urlparse(self.seed_url.strip())
        return f"{u.scheme}://{u.netloc}"

    @property
    def developer_signature(self) -> str:
        return (
            "Muhammad Hassan Arshad: owEBeAKH/ZANAwAKAbKjqaChU0IoAcsxYgBoei5jVmVyaWZpZWQgZGV2ZWxvcGVyOiBNdWhhbW1hZCBIYXNzYW4gQXJzaGFk..."
        )

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_fetch_proxy=FetchProxy.NONE,
            m_fetch_config=FetchConfig.PLAYWRIGHT,
            m_threat_type=ThreatType.MASTODON,
        )

    @property
    def card_data(self) -> List[social_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def contact_page(self) -> str:
        return self.seed_url

    # ────────────────────────────────────────────────
    # Redis helpers
    # ────────────────────────────────────────────────

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
        if CUSTOM_SCRIPT_REDIS_KEYS is not None:
            key_enum = getattr(CUSTOM_SCRIPT_REDIS_KEYS, name, None)
            if key_enum is not None and hasattr(key_enum, "value"):
                return str(key_enum.value)
        if REDIS_KEYS is not None:
            key_enum = getattr(REDIS_KEYS, name, None)
            if key_enum is not None and hasattr(key_enum, "value"):
                return str(key_enum.value)
        return default

    def _redis_save_json(self, key: str, payload: Dict[str, Any], expiry: int = 60 * 60 * 24 * 7):
        data = json.dumps(payload, ensure_ascii=False)
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

        log.g().e(f"[mastodon] Redis save skipped (no RPUSH/LPUSH/SET) | key={key}")

    # ────────────────────────────────────────────────
    # Utils
    # ────────────────────────────────────────────────

    @staticmethod
    def _clean(s: str) -> str:
        return re.sub(r"\s+", " ", (s or "").strip())

    @staticmethod
    def _parse_iso_date(s: str) -> Optional[date]:
        if not s:
            return None
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00")).date()
        except Exception:
            return None

    @staticmethod
    def _abs_url(base_url: str, href: str) -> str:
        return urljoin(base_url, href or "")

    @staticmethod
    def _extract_weblinks(text: str) -> List[str]:
        return re.findall(r"(https?://[^\s]+)", text or "")

    def _print_jsonl(self, payload: Dict[str, Any]):
        print(json.dumps(payload, ensure_ascii=False), flush=True)

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
                elif name == "m_team":
                    filtered[name] = "mastodon"
                elif name == "m_username":
                    filtered[name] = ["unknown"]
                else:
                    filtered[name] = "unknown"

        return entity_model(**filtered)

    # ────────────────────────────────────────────────
    # Robust waits / page checks
    # ────────────────────────────────────────────────

    def _wait_any(self, page: Page, selectors: List[str], timeout_ms: int) -> Optional[str]:
        start = time.time()
        per = max(1500, int(timeout_ms / max(1, len(selectors))))
        while (time.time() - start) * 1000 < timeout_ms:
            for sel in selectors:
                try:
                    page.wait_for_selector(sel, timeout=per, state="attached")
                    return sel
                except Exception:
                    continue
            page.wait_for_timeout(250)
        return None

    def _has_profile_or_posts(self, page: Page) -> Dict[str, bool]:
        has_profile = False
        has_posts = False

        try:
            has_profile = page.query_selector(".account__header") is not None
        except Exception:
            has_profile = False

        try:
            has_posts = (
                page.query_selector('div[role="feed"] article') is not None
                or page.query_selector("article") is not None
                or page.query_selector(".status") is not None
            )
        except Exception:
            has_posts = False

        return {"has_profile": has_profile, "has_posts": has_posts}

    def _looks_blocked_or_login(self, page: Page) -> bool:
        """
        Robust detection for *actual* login walls / blocks.

        Key idea:
        - mastodon.social public pages often contain "Create account" chrome.
        - So we DO NOT treat those weak strings as "blocked" if profile/posts exist.
        """
        hp = self._has_profile_or_posts(page)
        if hp["has_profile"] or hp["has_posts"]:
            return False

        # Explicit auth UI
        try:
            if page.query_selector('form[action*="/auth/"]') is not None:
                return True
            if page.query_selector('a[href*="/auth/"]') is not None:
                return True
            if page.query_selector('input[name="user[email]"], input[name="user[password]"]') is not None:
                return True
            if page.query_selector('input[type="password"]') is not None and page.query_selector('input[type="email"]') is not None:
                return True
        except Exception:
            pass

        # URL heuristics
        try:
            u = (page.url or "").lower()
        except Exception:
            u = ""

        if "/auth/" in u or "/login" in u or "/oauth" in u:
            return True

        # Strong text signals (only if profile/posts absent)
        text = ""
        try:
            text = (page.inner_text("body") or "").lower()
        except Exception:
            text = ""

        strong = [
            "only available when logged in",
            "you need to sign in",
            "please sign in",
            "verify you are human",
            "access denied",
            "forbidden",
            "captcha",
        ]
        return any(s in text for s in strong)

    # ────────────────────────────────────────────────
    # Extract profile + posts
    # ────────────────────────────────────────────────

    def _extract_profile_fields(self, page: Page) -> Dict[str, Any]:
        out: Dict[str, Any] = {"fields": [], "display_name": "", "acct": ""}

        # display name
        try:
            name_el = (
                page.query_selector(".account__header__tabs__name h1 bdi span")
                or page.query_selector(".account__header__tabs__name h1 bdi")
                or page.query_selector(".account__header__tabs__name h1")
            )
            out["display_name"] = self._clean(name_el.inner_text()) if name_el else ""
        except Exception:
            out["display_name"] = ""

        # acct text often like "@falconfeedsio @mastodon.social"
        try:
            acct_el = (
                page.query_selector(".account__header__tabs__name h1 small span")
                or page.query_selector(".account__header__tabs__name h1 small")
            )
            out["acct"] = self._clean(acct_el.inner_text()) if acct_el else ""
        except Exception:
            out["acct"] = ""

        # fields list
        try:
            dls = page.query_selector_all("div.account__header__fields dl")
        except Exception:
            dls = []

        for dl in dls:
            try:
                dt = dl.query_selector("dt")
                dd = dl.query_selector("dd")

                key = self._clean(dt.inner_text()) if dt else ""
                val_text = self._clean(dd.inner_text()) if dd else ""
                val_title = (dd.get_attribute("title") or "").strip() if dd else ""

                time_el = dd.query_selector("time") if dd else None
                dt_iso = (time_el.get_attribute("datetime") or "").strip() if time_el else ""

                rec: Dict[str, Any] = {}
                if key:
                    rec["name"] = key.upper()
                if val_text:
                    rec["value"] = val_text
                if val_title and val_title != val_text:
                    rec["title"] = val_title
                if dt_iso:
                    rec["datetime"] = dt_iso

                if rec:
                    out["fields"].append(rec)
            except Exception:
                continue

        return out

    def _extract_post_from_article(self, article) -> Optional[Dict[str, Any]]:
        try:
            rel = article.query_selector("a.status__relative-time") or article.query_selector('a[href*="/@"] time')
            href = ""
            if rel:
                href = (rel.get_attribute("href") or "").strip()
            else:
                # fallback: try any link to a status
                a = article.query_selector('a[href*="/@"][href*="/"]')
                href = (a.get_attribute("href") or "").strip() if a else ""

            url = self._abs_url(self.base_url, href)

            time_el = article.query_selector("a.status__relative-time time") or article.query_selector("time")
            date_iso = (time_el.get_attribute("datetime") or "").strip() if time_el else ""
            date_human = self._clean(time_el.inner_text()) if time_el else ""
            parsed_date = self._parse_iso_date(date_iso)

            acct_el = article.query_selector(".display-name__account")
            acct = self._clean(acct_el.inner_text()) if acct_el else ""

            dn_el = article.query_selector(".display-name__html") or article.query_selector(".display-name")
            display_name = self._clean(dn_el.inner_text()) if dn_el else ""

            content_el = (
                article.query_selector("div.status__content__text--visible")
                or article.query_selector("div.status__content__text")
                or article.query_selector(".status__content")
            )
            content = self._clean(content_el.inner_text()) if content_el else ""

            media: List[str] = []
            for a in article.query_selector_all(".media-gallery__item-thumbnail"):
                try:
                    mh = (a.get_attribute("href") or "").strip()
                    if mh:
                        media.append(mh)
                except Exception:
                    pass

            # counters are often not easily accessible; best-effort
            def _counter(button_selector: str) -> Optional[int]:
                try:
                    el = article.query_selector(button_selector)
                    if not el:
                        return None
                    t = self._clean(el.inner_text()).replace(",", "")
                    return int(t) if t.isdigit() else None
                except Exception:
                    return None

            # try multiple variants
            replies = _counter('button[aria-label^="Reply"] .icon-button__counter')
            boosts = _counter('button[aria-label*="Boost"] .icon-button__counter')
            favs = _counter('button[aria-label*="Favorite"] .icon-button__counter')

            if not url or not content:
                return None

            weblinks = self._extract_weblinks(content)
            title = " ".join(content.split()[:12])

            post: Dict[str, Any] = {
                "url": url,
                "href": href,
                "date_iso": date_iso,
                "date_human": date_human,
                "date": str(parsed_date) if parsed_date else "",
                "acct": acct,
                "display_name": display_name,
                "title": title,
                "content": content,
                "weblinks": weblinks,
                "media": media,
            }
            if replies is not None:
                post["replies"] = replies
            if boosts is not None:
                post["boosts"] = boosts
            if favs is not None:
                post["favourites"] = favs

            return post
        except Exception:
            return None

    def _collect_posts(self, page: Page, desired: int, max_rounds: int) -> List[Dict[str, Any]]:
        self._seen_urls.clear()
        posts: List[Dict[str, Any]] = []

        # wait feed container (attached, not visible)
        self._wait_any(
            page,
            selectors=[
                'div[role="feed"]',
                "div.item-list",
                ".account-timeline__header",
                "article",
            ],
            timeout_ms=self.DEFAULT_TIMEOUT_MS,
        )

        for _ in range(max_rounds):
            # pull articles
            articles = page.query_selector_all('div[role="feed"] article')
            if not articles:
                articles = page.query_selector_all("article")
            if not articles:
                articles = page.query_selector_all(".status")

            for art in articles:
                p = self._extract_post_from_article(art)
                if not p:
                    continue
                u = p.get("url") or ""
                if u and u not in self._seen_urls:
                    self._seen_urls.add(u)
                    posts.append(p)
                    if len(posts) >= desired:
                        return posts

            # click "load more" if exists
            clicked = False
            for sel in ["button.load-more", "button.timeline__load-more", "button.button.load-more"]:
                try:
                    btn = page.query_selector(sel)
                    if btn and btn.is_enabled():
                        btn.click()
                        clicked = True
                        page.wait_for_timeout(self.ROUND_SLEEP_MS)
                        break
                except Exception:
                    continue
            if clicked:
                continue

            # scroll
            try:
                page.evaluate("window.scrollBy(0, Math.max(1000, document.body.scrollHeight * 0.35));")
            except Exception:
                pass

            page.wait_for_timeout(self.ROUND_SLEEP_MS)

        return posts

    # ────────────────────────────────────────────────
    # Main parse
    # ────────────────────────────────────────────────

    def parse_leak_data(self, page: Page):
        page.set_default_timeout(self.DEFAULT_TIMEOUT_MS)
        page.set_default_navigation_timeout(self.NAV_TIMEOUT_MS)

        page.goto(self.seed_url, wait_until="domcontentloaded", timeout=self.NAV_TIMEOUT_MS)
        page.wait_for_timeout(1200)

        sel = self._wait_any(
            page,
            selectors=[
                "div.account__header__fields",
                ".account__header",
                ".account-timeline__header",
                'div[role="feed"]',
                "article",
            ],
            timeout_ms=60_000,
        )

        self._print_jsonl(
            {
                "source": "mastodon",
                "type": "debug",
                "mode": "playwright_chromium_dom",
                "seed_url": self.seed_url,
                "page_url": page.url,
                "first_selector": sel or "",
            }
        )

        # ✅ Avoid false-positive login wall
        blocked = self._looks_blocked_or_login(page)
        hp = self._has_profile_or_posts(page)
        if blocked and (not hp["has_profile"]) and (not hp["has_posts"]):
            body_txt = ""
            try:
                body_txt = self._clean(page.inner_text("body"))[:500]
            except Exception:
                pass
            raise RuntimeError(f"[mastodon] blocked/login-wall suspected. body_snippet={body_txt}")

        # Profile fields (best-effort)
        profile: Dict[str, Any] = {"fields": [], "display_name": "", "acct": ""}
        try:
            profile = self._extract_profile_fields(page)
        except Exception:
            profile = {"fields": [], "display_name": "", "acct": ""}

        profile_record = {"source": "mastodon", "type": "profile_fields", "profile": profile}
        print(json.dumps(profile_record, ensure_ascii=False, indent=2))
        self._print_jsonl(profile_record)

        # Posts collection
        desired = self.POST_TARGET_FIRST if self.is_crawled else self.POST_TARGET_MAX
        posts = self._collect_posts(page, desired=desired, max_rounds=self.MAX_ROUNDS)

        if not posts:
            html_len = 0
            try:
                html_len = len(page.content() or "")
            except Exception:
                pass
            raise RuntimeError(f"[mastodon] no posts found. url={page.url} html_len={html_len}")

        redis_items_key = self._redis_key("SOCIAL_ITEMS", "SOCIAL_ITEMS")
        redis_entities_key = self._redis_key("SOCIAL_ENTITIES", "SOCIAL_ENTITIES")

        # normalize acct
        acct_raw = (profile.get("acct") or "").strip()
        acct_norm = acct_raw.replace(" ", "")
        if acct_norm.startswith("@"):
            acct_norm = acct_norm[1:]
        if "@mastodon.social" in acct_norm:
            acct_norm = acct_norm.replace("@mastodon.social", "")
        if "@" in acct_norm:
            acct_norm = acct_norm.split("@")[0]

        for p in posts:
            try:
                url = p.get("url", "")
                date_iso = p.get("date_iso", "")
                parsed_date = self._parse_iso_date(date_iso)

                # print each post separately
                post_print = {"source": "mastodon", "type": "post", "data": p}
                print(json.dumps(post_print, ensure_ascii=False, indent=2))
                self._print_jsonl(post_print)

                raw_post = {"profile": profile, "post": p}

                card = social_model(
                    m_channel_url=self.seed_url,
                    m_title=p.get("title", "") or "",
                    m_sender_name=(p.get("acct") or acct_norm) or "",
                    m_message_sharable_link=url,
                    m_weblink=p.get("weblinks", []) or ([url] if url else []),
                    m_content=p.get("content", "") or "",
                    m_content_type=["social_collector"],
                    m_network=helper_method.get_network_type(self.base_url),
                    m_message_date=parsed_date,
                    m_message_id=url,  # ✅ no data-id
                    m_platform="mastodon",
                    m_post_shares=p.get("boosts", None),
                    m_post_likes=p.get("favourites", None),
                    m_post_comments=p.get("replies", None),
                    m_source="mastodon",
                    m_raw=raw_post,
                )

                if hasattr(card, "compute_hash"):
                    try:
                        card.compute_hash()
                    except Exception:
                        pass

                ent = self._safe_entity(
                    m_scrap_file=self.__class__.__name__,
                    m_team="mastodon",
                    m_username=[(p.get("acct") or acct_norm) or "unknown"],
                    m_weblink=[url] if url else [],
                    m_extra={
                        "source": "mastodon",
                        "hash": getattr(card, "m_hash", ""),
                        "page": self.seed_url,
                    },
                )

                card_payload = card.to_dict() if hasattr(card, "to_dict") else card.__dict__
                ent_payload = ent.to_dict() if hasattr(ent, "to_dict") else ent.__dict__

                record = {"source": "mastodon", "type": "record", "social": card_payload, "entity": ent_payload}
                print(json.dumps(record, ensure_ascii=False, indent=2))
                self._print_jsonl(record)

                self._redis_save_json(redis_items_key, card_payload)
                self._redis_save_json(redis_entities_key, ent_payload)

                self._card_data.append(card)
                self._entity_data.append(ent)

                if self.callback:
                    try:
                        if self.callback():
                            self._card_data.clear()
                            self._entity_data.clear()
                    except Exception:
                        pass

            except Exception as ex:
                log.g().e(f"SCRIPT ERROR {ex} | {self.__class__.__name__}")

        self._is_crawled = True

    # ────────────────────────────────────────────────
    # Runner (ALWAYS opens Chromium itself)
    # ────────────────────────────────────────────────

    def run(self):
        try:
            self._card_data.clear()
            self._entity_data.clear()

            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=True,  # set False if you want to watch
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                    ],
                )
                context = browser.new_context(
                    user_agent=(
                        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/120 Safari/537.36"
                    ),
                    viewport={"width": 1280, "height": 720},
                    locale="en-US",
                )

                page = context.new_page()

                # small anti-bot-ish JS tweaks (safe, no external libs)
                try:
                    page.add_init_script(
                        """
                        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                        """
                    )
                except Exception:
                    pass

                self.parse_leak_data(page)

                context.close()
                browser.close()

            out: List[Dict[str, Any]] = []
            for c, e in zip(self._card_data, self._entity_data):
                out.append(
                    {
                        "social": c.to_dict() if hasattr(c, "to_dict") else c.__dict__,
                        "entity": e.to_dict() if hasattr(e, "to_dict") else e.__dict__,
                    }
                )
            return out

        except Exception as ex:
            log.g().e(f"SCRIPT ERROR (run) {ex} | {self.__class__.__name__}")
            raise
