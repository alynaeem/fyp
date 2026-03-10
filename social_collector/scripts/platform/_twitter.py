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

# kept ONLY because you explicitly demanded same import style
from crawler.common.crawler_instance.genbot_service.helpers.reddit.reddit_helper_method import (
    RedditHelperMethod,
)

from crawler.common.crawler_instance.genbot_service.helpers.twitter.tweet_helper_methods import (
    TweetHelperMethods,
)


class _twitter(leak_extractor_interface, ABC):
    _instance = None
    needs_seed_fetch = False

    DEFAULT_TIMEOUT_MS = 45_000
    NAV_TIMEOUT_MS = 60_000

    POST_TARGET_FIRST = 10
    POST_TARGET_MAX = 100

    def __init__(self, callback=None):
        self.callback = callback
        self._card_data: List[social_model] = []
        self._entity_data: List[entity_model] = []
        self._redis_instance = redis_controller()
        self._is_crawled = False
        self.m_seed_url = "https://x.com/IntelCrab"   # e.g. https://x.com/username
        self._seen_ids: Set[str] = set()
        self._helper = TweetHelperMethods()

    def __new__(cls, callback=None):
        if cls._instance is None:
            cls._instance = super(_twitter, cls).__new__(cls)
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
            m_fetch_proxy=FetchProxy.NONE,
            m_fetch_config=FetchConfig.PLAYWRIGHT,
            m_threat_type=ThreatType.TWITTER,
        )

    @property
    def card_data(self) -> List[social_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def contact_page(self) -> str:
        return "https://x.com/contact"

    # ────────────────────────────────────────────────
    # Utils
    # ────────────────────────────────────────────────

    @staticmethod
    def _parse_date(s: str) -> Optional[date]:
        if not s:
            return None
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00")).date()
        except Exception:
            return None

    def _safe_social(self, **kwargs) -> social_model:
        sig = inspect.signature(social_model.__init__)
        allowed = set(sig.parameters.keys()) - {"self"}
        filtered = {k: v for k, v in kwargs.items() if k in allowed}

        for name, p in sig.parameters.items():
            if name == "self":
                continue
            if name not in filtered and p.default is inspect._empty:
                filtered[name] = "unknown"

        return social_model(**filtered)

    def _safe_entity(self, **kwargs) -> entity_model:
        sig = inspect.signature(entity_model.__init__)
        allowed = set(sig.parameters.keys()) - {"self"}
        filtered = {k: v for k, v in kwargs.items() if k in allowed}

        for name, p in sig.parameters.items():
            if name == "self":
                continue
            if name not in filtered and p.default is inspect._empty:
                filtered[name] = "unknown"

        return entity_model(**filtered)

    # ────────────────────────────────────────────────
    # Main parser
    # ────────────────────────────────────────────────

    def parse_leak_data(self, page: Page):
        page.set_default_timeout(self.DEFAULT_TIMEOUT_MS)
        page.set_default_navigation_timeout(self.NAV_TIMEOUT_MS)

        page.goto(self.seed_url, wait_until="domcontentloaded")
        page.wait_for_timeout(1500)

        username = self._helper.extract_username(self.seed_url)
        desired = self.POST_TARGET_FIRST if self.is_crawled else self.POST_TARGET_MAX

        tweets = self._helper.scroll_and_collect(
            profile_page=page,
            username=username,
            existing_ids=self._seen_ids,
            desired_count=desired,
            max_scrolls=80,
        )

        if not tweets:
            raise RuntimeError("[twitter] No tweets found")

        for tweet in tweets:
            try:
                parsed_date = self._parse_date(tweet.get("date"))

                card = self._safe_social(
                    m_channel_url=self.seed_url,
                    m_sender_name=f"@{username}",
                    m_message_sharable_link=tweet.get("url", ""),
                    m_weblink=tweet.get("weblink", []),
                    m_content=tweet.get("content", "")[:500],
                    m_content_type=["social_collector"],
                    m_network=helper_method.get_network_type(self.base_url),
                    m_message_date=parsed_date,
                    m_message_id=tweet.get("id", ""),
                    m_platform="twitter",
                    m_likes=str(tweet.get("likes", 0)),
                    m_comment_count=str(tweet.get("comment_count", 0)),
                    m_retweets=str(tweet.get("retweets", 0)),
                    m_views=str(tweet.get("views", 0)),
                )

                ent = self._safe_entity(
                    m_scrap_file=self.__class__.__name__,
                    m_username=[username],
                    m_weblink=[tweet.get("url", "")],
                )

                self._card_data.append(card)
                self._entity_data.append(ent)

                if self.callback and self.callback():
                    self._card_data.clear()
                    self._entity_data.clear()

            except Exception as ex:
                log.g().e(f"SCRIPT ERROR {ex} | _twitter")

        self._is_crawled = True

    # ────────────────────────────────────────────────
    # Runner
    # ────────────────────────────────────────────────

    def run(self):
        try:
            self._card_data.clear()
            self._entity_data.clear()

            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage"],
                )
                context = browser.new_context(
                    viewport={"width": 1280, "height": 720},
                    locale="en-US",
                )
                page = context.new_page()

                self.parse_leak_data(page)

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
            log.g().e(f"SCRIPT ERROR (run) {ex} | _twitter")
            raise
