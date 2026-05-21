# crawler/crawler_instance/local_interface_model/leak/leak_extractor_interface.py
from abc import ABC, abstractmethod
from typing import List

class leak_extractor_interface(ABC):
    @property
    @abstractmethod
    def is_crawled(self) -> bool:
        ...

    @property
    @abstractmethod
    def seed_url(self) -> str:
        ...

    @property
    @abstractmethod
    def base_url(self) -> str:
        ...

    @property
    @abstractmethod
    def card_data(self) -> List:
        ...

    @property
    @abstractmethod
    def entity_data(self) -> List:
        ...

    @abstractmethod
    def parse_leak_data(self, session=None):
        ...
