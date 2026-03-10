# crawler/common/crawler_instance/local_interface_model/api/api_collector_interface.py
from abc import ABC, abstractmethod
from typing import List, Optional

from crawler.common.crawler_instance.local_shared_model import RuleModel
from crawler.common.crawler_instance.local_shared_model.data_model.apk_model import apk_model
from crawler.common.crawler_instance.local_shared_model.data_model.entity_model import entity_model


class api_collector_interface(ABC):
    """
    Standard interface for API collectors (APK/app collectors).
    Similar to leak_extractor_interface but for API/APK domain.
    """

    @property
    @abstractmethod
    def is_crawled(self) -> bool:
        raise NotImplementedError

    @property
    @abstractmethod
    def seed_url(self) -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def base_url(self) -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def rule_config(self) -> RuleModel:
        raise NotImplementedError

    @property
    @abstractmethod
    def apk_data(self) -> List[apk_model]:
        raise NotImplementedError

    @property
    @abstractmethod
    def entity_data(self) -> List[entity_model]:
        raise NotImplementedError

    @abstractmethod
    def init_callback(self, callback=None):
        raise NotImplementedError

    @abstractmethod
    def set_proxy(self, proxy: dict):
        raise NotImplementedError

    @abstractmethod
    def set_limits(self, max_pages: Optional[int] = None, max_items: Optional[int] = None):
        raise NotImplementedError

    @abstractmethod
    def reset_cache(self):
        raise NotImplementedError

    @abstractmethod
    def developer_signature(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def contact_page(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def run(self) -> dict:
        """
        Must return a dict summary: {seed_url, items_collected, developer_signature, ...}
        """
        raise NotImplementedError
