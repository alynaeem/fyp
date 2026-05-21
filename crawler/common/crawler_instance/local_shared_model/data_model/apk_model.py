# crawler/common/crawler_instance/local_shared_model/data_model/apk_model.py
from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class apk_model:
    """
    Normalized APK/app record stored/returned by collectors.
    """
    m_url: str = ""
    m_base_url: str = ""
    m_package_name: str = ""
    m_app_name: str = ""
    m_version: str = ""
    m_sha256: str = ""
    m_md5: str = ""
    m_download_url: str = ""
    m_description: str = ""
    m_publisher: str = ""
    m_category: str = ""
    m_permissions: List[str] = field(default_factory=list)
    m_tags: List[str] = field(default_factory=list)
    m_extra: Dict[str, Any] = field(default_factory=dict)
