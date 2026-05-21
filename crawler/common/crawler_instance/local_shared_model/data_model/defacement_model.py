from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, List, Optional


@dataclass
class defacement_model:
    """
    Defacement / IOC card model
    Covers: usom, defacer, ownzyou, tweetfeed
    """

    # IOC / URL / domain / IP
    m_url: str = ""

    # Extracted HTML / page content
    m_content: str = ""

    # Base crawler URL
    m_base_url: str = ""

    # Source references (detail pages, tweets, etc.)
    m_source_url: List[str] = field(default_factory=list)

    # IOC types / tags
    m_ioc_type: List[str] = field(default_factory=list)

    # Network type (http / https / onion / etc.)
    m_network: str = ""

    # Date of leak / defacement
    m_leak_date: Optional[date] = None

    # =========================
    # ✅ EXTENDED FIELDS
    # =========================

    # Web server (Apache, nginx, IIS, etc.)
    m_web_server: List[str] = field(default_factory=list)

    # Mirror / iframe URLs
    m_mirror_links: List[str] = field(default_factory=list)

    # Screenshot URLs (future use)
    m_screenshot_links: List[str] = field(default_factory=list)

    # Inline/base64 screenshot evidence
    m_screenshot: str = ""

    # Raw title / headline if site provides
    m_title: str = ""

    # Raw description (short)
    m_description: str = ""

    # Criticality / score (if any)
    m_severity: str = ""

    # Flexible metadata bucket for collector-specific fields
    m_extra: Dict[str, Any] = field(default_factory=dict)
