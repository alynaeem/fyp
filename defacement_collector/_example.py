from abc import ABC
from typing import List

from playwright.sync_api import Page

from crawler.crawler_instance.local_interface_model.leak.leak_extractor_interface import leak_extractor_interface
from crawler.crawler_instance.local_shared_model.data_model.defacement_model import defacement_model
from crawler.crawler_instance.local_shared_model.data_model.entity_model import entity_model
from crawler.crawler_instance.local_shared_model.data_model.leak_model import leak_model
from crawler.crawler_instance.local_shared_model.rule_model import RuleModel, FetchProxy, FetchConfig, ThreatType
from crawler.crawler_services.redis_manager.redis_controller import redis_controller
from crawler.crawler_services.shared.helper_method import helper_method


class _example(leak_extractor_interface, ABC):
    _instance = None

    def __init__(self, callback=None):
        """
        Initialize the _example class instance.
        Sets up attributes for storing card data, parsing content, and interacting with Redis.
        Optionally accepts a no-argument callback function.
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
        Initialize or update the callback function that will be triggered upon parsing new leak data.
        """
        self.callback = callback

    def __new__(cls, callback=None):
        """
        Implements singleton behavior to ensure only one instance of the class exists.
        Optionally accepts a no-argument callback function.
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
        """Return the crawling rule configuration."""
        return RuleModel(m_fetch_proxy=FetchProxy.TOR, m_fetch_config=FetchConfig.PLAYRIGHT, m_threat_type= ThreatType.DEFACEMENT)

    @property
    def card_data(self) -> List[leak_model]:
        """Return the list of parsed leak models (card data)."""
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        """Return the list of parsed leak models (entity data)."""
        return self._entity_data

    def invoke_db(self, command: int, key: str, default_value, expiry: int = None):
        """
        Interact with Redis using the given command and key.
        Returns the result of invoking a Redis trigger with the current class name as context.
        """
        return self._redis_instance.invoke_trigger(command, [key + self.__class__.__name__, default_value, expiry])

    def contact_page(self) -> str:
        """Return the contact page URL of the data source."""
        return "https://www.iana.org/help/example-domains"

    def append_leak_data(self, leak: defacement_model, entity: entity_model):
        """
        Appends a defacement_model object to the internal card data list.
        Calls the callback function if it is provided.
        """
        self._card_data.append(leak)
        self._entity_data.append(entity)
        if self.callback:
            if self.callback():
                self._card_data.clear()
                self._entity_data.clear()

    def parse_leak_data(self, page: Page):
        """
        Parses defacement data from the given Playwright page and appends a defacement_model.
        This is an example implementation that creates hardcoded sample leak and entity data.
        """

        card_data = defacement_model(
            m_url=self.base_url,
            m_web_server=["Apache/2.4.41", "nginx/1.18.0"],
            m_base_url=self.base_url,
            m_network=helper_method.get_network_type(self.base_url),
            m_mirror_links=["https://mirror1.example.com", "https://mirror2.example.com"],
            m_ioc_type=[]
        )

        entity_data = entity_model(
            m_team="akira",
        )

        self.append_leak_data(card_data, entity_data)
