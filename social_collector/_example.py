from abc import ABC
from typing import List

from playwright.sync_api import Page

from crawler.crawler_instance.local_interface_model.leak.leak_extractor_interface import leak_extractor_interface
from crawler.crawler_instance.local_shared_model.data_model.entity_model import entity_model

from crawler.crawler_instance.local_shared_model.data_model.social_model import social_model
from crawler.crawler_instance.local_shared_model.rule_model import RuleModel, FetchProxy, FetchConfig, ThreatType
from crawler.crawler_services.redis_manager.redis_controller import redis_controller
from crawler.crawler_services.shared.helper_method import helper_method


class _example(leak_extractor_interface, ABC):
    _instance = None

    def __init__(self, callback=None):
        """
        Initialize the _example class instance.
        Optionally accepts a callback function (no params) to be called after each leak is added.
        Sets up Redis controller and initializes internal storage for parsed data.
        """
        self.callback = callback
        self._card_data = []
        self._entity_data = []
        self.soup = None
        self._initialized = None
        self._redis_instance = redis_controller()
        self._is_crawled = False

    def init_callback(self, callback=None):
        """
        Initialize or update the callback function.
        The callback is triggered each time a new leak is parsed and added.
        """
        self.callback = callback

    def __new__(cls, callback=None):
        """
        Singleton pattern: ensures only one instance of _example exists.
        Optionally accepts a callback function during instantiation.
        """
        if cls._instance is None:
            cls._instance = super(_example, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        """Return the seed URL to start crawling from."""
        return "https://example.com/"

    @property
    def developer_signature(self) -> str:
        """
            Returns developer signature.
            format name:signature

            Example:
                >> instance = _example()
                >> print(instance.developer_signature)
            """
        return "name:signature"

    @property
    def base_url(self) -> str:
        """Return the base domain URL of the source."""
        return "https://example.com/"

    @property
    def rule_config(self) -> RuleModel:
        """Return the crawling rule configuration for Playwright with TOR proxy."""
        return RuleModel(m_fetch_proxy=FetchProxy.TOR, m_fetch_config=FetchConfig.PLAYRIGHT, m_threat_type= ThreatType.SOCIAL)

    @property
    def card_data(self) -> List[social_model]:
        """Return the list of parsed leak models (card data)."""
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        """Return the list of parsed entity models."""
        return self._entity_data

    def invoke_db(self, command: int, key: str, default_value, expiry: int = None):
        """
        Perform a Redis database operation using the provided command, key, and default value.
        The key is suffixed with the current class name to ensure uniqueness.
        """
        return self._redis_instance.invoke_trigger(command, [key + self.__class__.__name__, default_value, expiry])

    def contact_page(self) -> str:
        """Return the contact page URL of the data source."""
        return "https://www.iana.org/help/example-domains"

    def append_leak_data(self, leak: social_model, entity: entity_model):
        """
        Append a forum_model and entity_model instance to internal storage.
        Triggers the callback function if it was initialized.
        """
        self._card_data.append(leak)
        self._entity_data.append(entity)
        if self.callback:
            if self.callback():
                self._card_data.clear()
                self._entity_data.clear()

    def parse_leak_data(self, page: Page):
        """
        Extract leak-related information from a Playwright Page object.
        Parses the title and URL, derives network type, and extracts emails and phone numbers from the content.
        Constructs and stores corresponding forum_model and entity_model instances.
        """
        m_content = ""

        card_data = social_model(
            m_weblink=[page.url],
            m_content=m_content,
            m_content_type=["leaks"],
            m_network="clearnet",
            m_platform="twitter",
            m_message_sharable_link="twitter.com",
        )

        entity_data = entity_model(
            m_team="akira",
        )

        self.append_leak_data(card_data, entity_data)
