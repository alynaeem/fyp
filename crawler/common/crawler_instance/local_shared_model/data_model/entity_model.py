from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class entity_model:
    """
    Universal entity model (NO BREAKS)

    Old code → works
    New crawlers → supported
    Future junk → stored safely
    """

    # REQUIRED (never remove)
    m_scrap_file: str
    m_team: str
    m_name: Optional[str] = ""
    # =========================
    # BASIC ENRICHMENT
    # =========================
    m_ip: List[str] = field(default_factory=list)
    m_weblink: List[str] = field(default_factory=list)
    m_country: List[str] = field(default_factory=list)

    # =========================
    # DEFACER / OWNZYOU FIELDS
    # =========================
    m_attacker: List[str] = field(default_factory=list)   # hacker / reporter
    m_vulnerability: str = ""                             # PoC / Mode
    m_isp: List[str] = field(default_factory=list)
    m_company_name: str = ""
    m_states: List[str] = field(default_factory=list)

    # tum list pass kar rahe ho, isliye isko list bana do
    m_location: List[str] = field(default_factory=list)
    # Location info
                                # city / country text
    m_author: List[str] = field(default_factory=list)
    # Reports / stats
    m_total_report: str = ""                              # total reports count

    # =========================
    # SOCIAL / OSINT
    # =========================
    m_social_media_profiles: List[str] = field(default_factory=list)
    m_external_scanners: List[str] = field(default_factory=list)

    # =========================
    # IDENTITY / CONTACT
    # =========================
    m_email: List[str] = field(default_factory=list)
    m_username: List[str] = field(default_factory=list)

    # =========================
    # FLEX ZONE (dump anything)
    # =========================
    m_extra: Optional[Dict[str, Any]] = None
    m_exploit_year: Optional[str] = ""