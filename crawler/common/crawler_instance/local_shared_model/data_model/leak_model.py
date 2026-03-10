# File: crawler/common/crawler_instance/local_shared_model/data_model/leak_model.py

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Union


DateLike = Union[date, datetime]


@dataclass
class leak_model:
    """
    Generic Leak/Tracking/Advisory model (same style as news_model usage)
    Keep field names compatible with your collectors.

    Fields used by your scripts:
      - m_title
      - m_url
      - m_base_url
      - m_content
      - m_network
      - m_important_content
      - m_content_type (list)
      - m_logo_or_images (list)
      - m_leak_date (date|datetime|None)
      - m_extra (optional dict)
    """

    m_title: str = ""
    m_url: str = ""
    m_base_url: str = ""
    m_content: str = ""
    m_network: str = ""

    m_important_content: str = ""
    #m_weblink: list[str] = ""
    m_content_type: List[str] = field(default_factory=list)
    m_logo_or_images: List[str] = field(default_factory=list)
    m_author: List[str] = field(default_factory=list)
    m_leak_date: Optional[DateLike] = None
    m_extra: Dict[str, Any] = field(default_factory=dict)
    #m_websites: list[str] = ""
    #m_dumplink: list[str] = ""
    m_weblink: List[str] = field(default_factory=list)
    m_websites: List[str] = field(default_factory=list)
    m_dumplink: List[str] = field(default_factory=list)

    # keep existing if you want, but must be list
    m_sections: List[str] = field(default_factory=list)

    # ✅ ADD these for backward compatibility with your scripts
    m_section: List[str] = field(default_factory=list)  # your script uses m_section
    m_data_size: Optional[str] = None

    # Optional: convenience converters
    def leak_date_iso(self) -> str:
        if not self.m_leak_date:
            return ""
        if isinstance(self.m_leak_date, datetime):
            return self.m_leak_date.strftime("%Y-%m-%d")
        return self.m_leak_date.strftime("%Y-%m-%d")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.m_title,
            "url": self.m_url,
            "base_url": self.m_base_url,
            "content": self.m_content,
            "network": self.m_network,
            "important_content": self.m_important_content,
            "content_type": list(self.m_content_type or []),
            "logo_or_images": list(self.m_logo_or_images or []),
            "leak_date": self.leak_date_iso(),
            "extra": dict(self.m_extra or {}),
        }
