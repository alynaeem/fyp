from __future__ import annotations

from abc import ABC
from typing import List
from urllib.parse import urlparse

from playwright.sync_api import Page, TimeoutError as PlaywrightTimeoutError

from crawler.crawler_instance.local_interface_model.leak.leak_extractor_interface import leak_extractor_interface
from crawler.crawler_instance.local_shared_model.data_model.entity_model import entity_model
from crawler.crawler_instance.local_shared_model.data_model.leak_model import leak_model
from crawler.crawler_instance.local_shared_model.rule_model import RuleModel, FetchProxy, FetchConfig, ThreatType
from crawler.crawler_services.log_manager.log_controller import log
from crawler.crawler_services.redis_manager.redis_controller import redis_controller
from crawler.crawler_services.shared.helper_method import helper_method


class generic_leak_snapshot(leak_extractor_interface, ABC):
    _instance = None

    SITE_NAME = "Leak Snapshot"
    SITE_URL = ""
    TEAM_NAME = "leak snapshot"
    CONTACT = ""
    USE_TOR = True

    def __init__(self, callback=None):
        self.callback = callback
        self._card_data = []
        self._entity_data = []
        self.soup = None
        self._initialized = None
        self._redis_instance = redis_controller()
        self._is_crawled = False

    def init_callback(self, callback=None):
        self.callback = callback

    def __new__(cls, callback=None):
        if cls._instance is None:
            cls._instance = super(generic_leak_snapshot, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    def developer_signature(self) -> str:
        return "open:open"

    @property
    def seed_url(self) -> str:
        return self.SITE_URL

    @property
    def base_url(self) -> str:
        return self.SITE_URL

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_fetch_proxy=FetchProxy.TOR if self.USE_TOR else FetchProxy.NONE,
            m_fetch_config=FetchConfig.PLAYRIGHT,
            m_resoource_block=False,
            m_threat_type=ThreatType.LEAK,
        )

    @property
    def card_data(self) -> List[leak_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def invoke_db(self, command: int, key: str, default_value, expiry: int = None):
        return self._redis_instance.invoke_trigger(command, [key + self.__class__.__name__, default_value, expiry])

    def contact_page(self) -> str:
        return self.CONTACT or self.base_url

    def append_leak_data(self, leak: leak_model, entity: entity_model):
        self._card_data.append(leak)
        self._entity_data.append(entity)
        if self.callback:
            if self.callback():
                self._card_data.clear()
                self._entity_data.clear()

    def _alternate_seed_url(self) -> str | None:
        if not self.seed_url.endswith(".onion/") and not self.seed_url.endswith(".onion"):
            return None
        if self.seed_url.startswith("http://"):
            return "https://" + self.seed_url[len("http://") :]
        if self.seed_url.startswith("https://"):
            return "http://" + self.seed_url[len("https://") :]
        return None

    def _open_seed_page(self, page: Page) -> str:
        last_error = None
        for candidate in [self.seed_url, self._alternate_seed_url()]:
            if not candidate:
                continue
            try:
                page.goto(candidate, wait_until="domcontentloaded", timeout=90000)
                try:
                    page.wait_for_load_state("networkidle", timeout=15000)
                except PlaywrightTimeoutError:
                    page.wait_for_timeout(2500)
                return page.url or candidate
            except Exception as exc:
                last_error = exc
                log.g().i(f"{self.__class__.__name__}: failed to open {candidate}: {exc}")
        if last_error:
            raise last_error
        raise RuntimeError(f"{self.__class__.__name__}: no seed URL configured")

    def _extract_meta_description(self, page: Page) -> str:
        try:
            locator = page.locator('meta[name="description"], meta[property="og:description"]').first
            if locator.count() > 0:
                content = locator.get_attribute("content") or ""
                return " ".join(content.split())
        except Exception:
            return ""
        return ""

    def _extract_primary_heading(self, page: Page) -> str:
        selectors = ["h1", "main h2", "article h2", "h2", "h3"]
        for selector in selectors:
            try:
                locator = page.locator(selector).first
                if locator.count() > 0:
                    text = " ".join((locator.inner_text() or "").split())
                    if text:
                        return text
            except Exception:
                continue
        return ""

    def _extract_body_excerpt(self, page: Page, limit: int = 900) -> str:
        try:
            body_text = page.locator("body").inner_text(timeout=5000)
        except Exception:
            return ""
        compact = " ".join((body_text or "").split())
        return compact[:limit]

    def _host_label(self) -> str:
        parsed = urlparse(self.base_url)
        return (parsed.netloc or self.SITE_NAME or self.__class__.__name__).strip("/")

    def parse_leak_data(self, page: Page):
        try:
            active_url = self._open_seed_page(page)
            page_title = " ".join((page.title() or "").split()) or self.SITE_NAME or self._host_label()
            meta_description = self._extract_meta_description(page)
            primary_heading = self._extract_primary_heading(page)
            body_excerpt = self._extract_body_excerpt(page)
            screenshot = helper_method.get_screenshot_base64(page, page_title, self.base_url)

            content_lines = [
                f"Source Site: {self.base_url}",
                f"Captured URL: {active_url}",
                f"Page Title: {page_title}",
            ]
            if primary_heading:
                content_lines.append(f"Primary Heading: {primary_heading}")
            if meta_description:
                content_lines.append(f"Meta Description: {meta_description}")
            if body_excerpt:
                content_lines.append(f"Visible Page Excerpt: {body_excerpt}")

            important_content = meta_description or primary_heading or body_excerpt or page_title
            links = [value for value in [active_url, self.base_url] if value]

            card_data = leak_model(
                m_title=page_title,
                m_url=active_url,
                m_base_url=self.base_url,
                m_screenshot=screenshot,
                m_content="\n".join(content_lines),
                m_network=helper_method.get_network_type(self.base_url),
                m_important_content=important_content[:900],
                m_content_type=["leaks"],
                m_weblink=links,
                m_team=self.TEAM_NAME,
                m_extra={
                    "collection_mode": "homepage_snapshot",
                    "source_name": self.SITE_NAME,
                    "source_host": self._host_label(),
                },
            )

            entity_data = entity_model(
                m_scrap_file=self.__class__.__name__,
                m_team=self.TEAM_NAME,
                m_company_name=page_title,
                m_weblink=links,
                m_extra={
                    "collection_mode": "homepage_snapshot",
                    "source_name": self.SITE_NAME,
                    "source_host": self._host_label(),
                },
            )

            self.append_leak_data(card_data, entity_data)
            self._is_crawled = True
        except Exception as ex:
            log.g().e(f"SCRIPT ERROR {ex} " + str(self.__class__.__name__))
            raise
