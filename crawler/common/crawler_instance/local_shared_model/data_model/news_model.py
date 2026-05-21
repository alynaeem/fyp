from dataclasses import dataclass
from typing import List, Optional, Dict, Any

@dataclass
class news_model:
    m_screenshot: str
    m_title: str
    m_weblink: List[str]
    m_dumplink: List[str]
    m_url: str
    m_base_url: str
    m_content: str
    m_network: str
    m_important_content: str
    m_content_type: List[str]
    m_leak_date: Optional[object] = None
    m_author: str = ""
    m_description: str = ""
    m_location: str = ""
    m_links: List[str] = None
    m_extra: Dict[str, Any] = None
    m_tag:Optional[object] = None