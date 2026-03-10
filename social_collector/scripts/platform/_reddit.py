from __future__ import annotations

import inspect
import json
import re
from abc import ABC
from datetime import datetime, timedelta, timezone, date
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from playwright.sync_api import Page, sync_playwright

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
        REDIS_KEYS,
    )
except Exception:
    REDIS_KEYS = None

from crawler.common.crawler_instance.crawler_services.log_manager.log_controller import (
    log,
)
from crawler.common.crawler_instance.crawler_services.shared.helper_method import (
    helper_method,
)

from crawler.common.crawler_instance.genbot_service.helpers.reddit.reddit_helper_method import (
    RedditHelperMethod,
)


class _reddit(leak_extractor_interface, ABC):
    _instance = None
    needs_seed_fetch = False

    DEFAULT_TIMEOUT_MS = 45_000
    NAV_TIMEOUT_MS = 60_000

    POST_TARGET_FIRST = 10
    POST_TARGET_MAX = 50
    MAX_COMMENTS = 5

    def __init__(self, callback=None):
        self.callback = callback
        self._card_data: List[social_model] = []
        self._entity_data: List[entity_model] = []
        self._redis_instance = redis_controller()
        self._is_crawled = False

        # ✅ MUST be subreddit URL (keep trailing slash)
        self.m_seed_url = (
            "https://www.reddittorjg6rue252oqsxryoxengawnmo46qy4kyii5wtqnwfj4ooad.onion/r/politics/"
        )

        self._subreddit_metadata: Dict[str, Any] = {}
        self._seen_ids: Set[str] = set()

        # framework-compat fields
        self.page = None
        self._page = None
        self._request_page = None

    def __new__(cls, callback=None):
        if cls._instance is None:
            cls._instance = super(_reddit, cls).__new__(cls)
        return cls._instance

    # ────────────────────────────────────────────────
    # Required properties
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
        return "Muhammad Hassan Arshad: owEBeAKH/ZANAwAKAbKjqaChU0IoAcsxYgBo..."

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_fetch_proxy=FetchProxy.TOR,
            m_fetch_config=FetchConfig.PLAYWRIGHT,
            m_threat_type=ThreatType.REDDIT,
        )

    @property
    def card_data(self) -> List[social_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def contact_page(self) -> str:
        return "https://www.reddit.com/contact"

    # ────────────────────────────────────────────────
    # Redis helpers
    # ────────────────────────────────────────────────

    def invoke_db(self, command, key: str, default_value, expiry: int = None):
        try:
            cmd_value = command.value if hasattr(command, "value") else int(command)
        except Exception:
            cmd_value = command

        namespaced_key = f"{key}:{self.__class__.__name__}"
        return self._redis_instance.invoke_trigger(cmd_value, [namespaced_key, default_value, expiry])

    def _redis_cmd(self, name: str):
        return getattr(REDIS_COMMANDS, name, None)

    def _redis_key(self, name: str, default: str) -> str:
        if REDIS_KEYS is not None:
            key_enum = getattr(REDIS_KEYS, name, None)
            if key_enum is not None and hasattr(key_enum, "value"):
                return str(key_enum.value)
        return default

    def _redis_save_json(self, key: str, payload: Dict[str, Any], expiry: int = 604800):
        data = json.dumps(payload, ensure_ascii=False)
        rpush_cmd = self._redis_cmd("RPUSH")
        set_cmd = self._redis_cmd("SET")

        if rpush_cmd:
            self.invoke_db(rpush_cmd, key, data, expiry)
        elif set_cmd:
            uniq = payload.get("m_hash") or str(datetime.utcnow().timestamp())
            self.invoke_db(set_cmd, f"{key}:{uniq}", data, expiry)
        else:
            log.g().e(f"[reddit] Redis command missing for key={key}")

    # ────────────────────────────────────────────────
    # Utils
    # ────────────────────────────────────────────────

    @staticmethod
    def _clean(s: str) -> str:
        return re.sub(r"\s+", " ", (s or "").strip())

    @staticmethod
    def _parse_date(s: str) -> Optional[date]:
        if not s:
            return None
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00")).date()
        except Exception:
            return None

    @staticmethod
    def _extract_weblinks(text: str) -> List[str]:
        return re.findall(r"(https?://[^\s)>\]]+)", text or "")

    def _safe_entity(self, **kwargs) -> entity_model:
        sig = inspect.signature(entity_model.__init__)
        params = sig.parameters
        allowed = set(params.keys())
        allowed.discard("self")
        filtered = {k: v for k, v in kwargs.items() if k in allowed}

        for name, p in params.items():
            if name == "self":
                continue
            if name not in filtered and p.default is inspect._empty:
                if name == "m_scrap_file":
                    filtered[name] = self.__class__.__name__
                elif name == "m_username":
                    filtered[name] = ["unknown"]
                else:
                    filtered[name] = "unknown"

        return entity_model(**filtered)

    def _safe_social(self, **kwargs) -> social_model:
        """
        ✅ Signature-safe social_model constructor:
        drops any unsupported kwargs (prevents TypeError).
        """
        sig = inspect.signature(social_model.__init__)
        params = sig.parameters
        allowed = set(params.keys())
        allowed.discard("self")
        filtered = {k: v for k, v in kwargs.items() if k in allowed}

        # fill required fields if missing
        for name, p in params.items():
            if name == "self":
                continue
            if name not in filtered and p.default is inspect._empty:
                # try best defaults for common required fields
                if name == "m_channel_url":
                    filtered[name] = self.seed_url
                elif name == "m_title":
                    filtered[name] = ""
                elif name == "m_sender_name":
                    filtered[name] = "unknown"
                elif name == "m_message_sharable_link":
                    filtered[name] = ""
                elif name == "m_content":
                    filtered[name] = ""
                else:
                    filtered[name] = "unknown"

        return social_model(**filtered)

    # ────────────────────────────────────────────────
    # Main parser
    # ────────────────────────────────────────────────

    def parse_leak_data(self, page: Page):
        page.set_default_timeout(self.DEFAULT_TIMEOUT_MS)
        page.set_default_navigation_timeout(self.NAV_TIMEOUT_MS)

        # navigate
        try:
            page.goto(self.seed_url, wait_until="domcontentloaded", timeout=self.NAV_TIMEOUT_MS)
            page.wait_for_timeout(1500)
        except Exception as ex:
            raise RuntimeError(f"[reddit] goto failed: {ex}")

        subreddit_name = RedditHelperMethod.extract_subreddit_name(self.seed_url)
        self._subreddit_metadata = RedditHelperMethod.get_subreddit_metadata(page, subreddit_name)

        desired_posts = self.POST_TARGET_FIRST if self.is_crawled else self.POST_TARGET_MAX
        filter_date = datetime.now(timezone.utc) - timedelta(days=60)

        posts = RedditHelperMethod.scroll_and_collect_posts(
            page=page,
            subreddit_name=subreddit_name,
            desired_count=desired_posts,
            max_scrolls=1200,
            filter_date=filter_date,
        )

        if not posts:
            raise RuntimeError("[reddit] No posts found")

        redis_items_key = self._redis_key("SOCIAL_ITEMS", "SOCIAL_ITEMS")
        redis_entities_key = self._redis_key("SOCIAL_ENTITIES", "SOCIAL_ENTITIES")

        for post in posts:
            try:
                post_id = post.get("id")
                if not post_id or post_id in self._seen_ids:
                    continue
                self._seen_ids.add(post_id)

                comments = RedditHelperMethod.get_comments_from_post(
                    page=page,
                    post_url=post.get("url", ""),
                    max_comments=self.MAX_COMMENTS,
                )

                content = self._clean(post.get("content", ""))
                comment_text = "\n".join(self._clean(c.get("content", "")) for c in comments if c.get("content"))
                full_content = "\n".join([t for t in [content, comment_text] if t]).strip()

                parsed_date = self._parse_date(post.get("timestamp"))

                card = self._safe_social(
                    m_title=post.get("title", "") or "",
                    m_channel_url=self.seed_url,
                    m_sender_name=post.get("username", "unknown") or "unknown",
                    m_message_sharable_link=post.get("url", "") or "",
                    m_weblink=post.get("weblinks", []) or self._extract_weblinks(full_content),
                    m_content=(full_content[:2000] if full_content else ""),
                    m_content_type=["social_collector"],
                    m_network=helper_method.get_network_type(self.base_url),
                    m_message_date=parsed_date,
                    m_message_id=post_id,
                    m_platform="reddit",
                    m_group_name=subreddit_name,
                    m_raw={"post": post, "comments": comments},
                )

                if hasattr(card, "compute_hash"):
                    try:
                        card.compute_hash()
                    except Exception:
                        pass

                ent = self._safe_entity(
                    m_scrap_file=self.__class__.__name__,
                    m_username=[post.get("username", "unknown") or "unknown"],
                    m_weblink=[post.get("url", "")] if post.get("url") else [],
                    m_extra={
                        "source": "reddit",
                        "hash": getattr(card, "m_hash", ""),
                        "page": self.seed_url,
                        "subreddit": subreddit_name,
                    },
                )

                card_payload = card.to_dict() if hasattr(card, "to_dict") else card.__dict__
                ent_payload = ent.to_dict() if hasattr(ent, "to_dict") else ent.__dict__

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
    # Runner (RequestParser expects model.run())
    # ────────────────────────────────────────────────

    def run(self):
        try:
            self._card_data.clear()
            self._entity_data.clear()

            tor = "socks5://127.0.0.1:9150"

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

                page = context.new_page()

                try:
                    page.add_init_script("Object.defineProperty(navigator, 'webdriver', { get: () => undefined });")
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
