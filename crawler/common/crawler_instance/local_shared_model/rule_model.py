from dataclasses import dataclass
from enum import Enum, auto

class ThreatType(Enum):
    NEWS = auto()
    LEAK = auto()

class FetchProxy(Enum):
    NONE = auto()
    TOR = auto()

class FetchConfig(Enum):
    REQUESTS = auto()
    PLAYWRIGHT = auto()

@dataclass
class RuleModel:
    m_threat_type: ThreatType
    m_fetch_proxy: FetchProxy
    m_fetch_config: FetchConfig
    m_resoource_block: bool = False
