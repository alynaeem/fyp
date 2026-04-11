import re
from abc import ABC
from typing import List
from playwright.sync_api import Page

from crawler.crawler_instance.local_interface_model.leak.leak_extractor_interface import leak_extractor_interface
from crawler.crawler_instance.local_shared_model.data_model.entity_model import entity_model
from crawler.crawler_instance.local_shared_model.data_model.leak_model import leak_model
from crawler.crawler_instance.local_shared_model.rule_model import RuleModel, FetchProxy, FetchConfig, ThreatType
from crawler.crawler_services.log_manager.log_controller import log
from crawler.crawler_services.redis_manager.redis_controller import redis_controller
from crawler.crawler_services.shared.helper_method import helper_method


class _dounczge5jhw4iztnnpzp54kd4ot3tikhjsimurtcewqssgye6vvrhqd(leak_extractor_interface, ABC):
    _instance = None

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
            cls._instance = super(_dounczge5jhw4iztnnpzp54kd4ot3tikhjsimurtcewqssgye6vvrhqd, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "http://dounczge5jhw4iztnnpzp54kd4ot3tikhjsimurtcewqssgye6vvrhqd.onion"

    @property
    def developer_signature(self) -> str:
        return "name:signature"

    @property
    def base_url(self) -> str:
        return "http://dounczge5jhw4iztnnpzp54kd4ot3tikhjsimurtcewqssgye6vvrhqd.onion"

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(m_fetch_proxy=FetchProxy.TOR,m_resoource_block=False, m_fetch_config=FetchConfig.PLAYRIGHT, m_threat_type= ThreatType.LEAK)

    @property
    def card_data(self) -> List[leak_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def invoke_db(self, command: int, key: str, default_value, expiry: int = None):
        return self._redis_instance.invoke_trigger(command, [key + self.__class__.__name__, default_value, expiry])

    def contact_page(self) -> str:
        return "http://dounczge5jhw4iztnnpzp54kd4ot3tikhjsimurtcewqssgye6vvrhqd.onion"

    def append_leak_data(self, leak: leak_model, entity: entity_model):
        self._card_data.append(leak)
        self._entity_data.append(entity)
        if self.callback:
            if self.callback():
                self._card_data.clear()
                self._entity_data.clear()

    def parse_leak_data(self, page: Page):
        try:
            page.wait_for_load_state("networkidle", timeout=60000)

            try:
                close_btn = page.query_selector("a.closes")
                if close_btn:
                    close_btn.click()
                    page.wait_for_timeout(500)
            except Exception:
                pass

            processed_titles = set()

            page.wait_for_selector("table.table-bordered.table-content", timeout=15000)
            cards = page.query_selector_all("table.table-bordered.table-content")

            for card in cards:
                title_el = card.query_selector("h1.target-name")
                title = title_el.inner_text().strip() if title_el else ""

                if not title or title in processed_titles:
                    continue

                processed_titles.add(title)

                desc_el = card.query_selector("p.description")
                description = desc_el.inner_text().strip() if desc_el else ""

                dumplinks = []
                link_el = card.query_selector("a.website.fa.fa-globe")
                if link_el:
                    href = link_el.get_attribute("href")
                    if href:
                        dumplinks.append(href.strip())

                proof_text = ""
                proof_images = []
                revenue = ""
                proof_btn = card.query_selector("i.data.fa.fa-list-ul")
                if proof_btn:
                    onclick_attr = proof_btn.get_attribute("onclick")
                    modal_class = None
                    if onclick_attr:
                        match = re.search(r"\$\('(\.[^']+)'\)\.modal", onclick_attr)
                        if match:
                            modal_class = match.group(1)

                    if modal_class:
                        proof_btn.click()
                        modal_el = page.query_selector(modal_class)

                        if modal_el:
                            try:
                                modal_el.wait_for_selector(
                                    "div.target-block a[class^='proof_images_'] div.gallery img",
                                    timeout=10000
                                )
                            except:
                                pass

                            img_elements = modal_el.query_selector_all(
                                "div.target-block a[class^='proof_images_'] div.gallery img"
                            )
                            proof_images = [img.get_attribute("src").strip() for img in img_elements if
                                            img.get_attribute("src")]

                            proof_text = modal_el.inner_text().strip()

                            revenue_match = re.search(r'(\$\s?[\d,.]+[^\n]*)\nREVENUE', proof_text, re.IGNORECASE)
                            revenue = revenue_match.group(1).strip() if revenue_match else ""

                        page.mouse.click(10, 10)
                        page.wait_for_timeout(300)

                card_data = leak_model(
                    m_title=title,
                    m_url=page.url,
                    m_base_url=self.base_url,
                    m_screenshot=helper_method.get_screenshot_base64(page, title, self.base_url),
                    m_content=description + ("\n" + proof_text if proof_text else ""),
                    m_network=helper_method.get_network_type(self.base_url),
                    m_important_content=(description + ("\n" + proof_text if proof_text else ""))[:500],
                    m_dumplink=dumplinks,
                    m_logo_or_images=proof_images,
                    m_revenue=revenue,
                    m_content_type=["leaks"],
                )

                entity = entity_model(
                    m_team="BLACKBYTE",
                    m_scrap_file=self.__class__.__name__,
                )

                self.append_leak_data(card_data, entity)

        except Exception as ex:
            log.g().e(f"SCRIPT ERROR {ex} {self.__class__.__name__}")