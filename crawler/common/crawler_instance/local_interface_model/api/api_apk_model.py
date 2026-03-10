# crawler/common/crawler_instance/local_interface_model/api/api_apk_model.py
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class apk_data_model:
    """
    API output payload model (raw collected data).
    Keep it flexible for different app stores / sources.
    """
    package_name: str = ""
    app_name: str = ""
    version: str = ""
    sha256: str = ""
    md5: str = ""
    download_url: str = ""
    source_url: str = ""
    publisher: str = ""
    category: str = ""
    description: str = ""
    permissions: List[str] = field(default_factory=list)
    trackers: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    scraped_at: int = 0  # unix timestamp
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "app_name": self.app_name,
            "version": self.version,
            "sha256": self.sha256,
            "md5": self.md5,
            "download_url": self.download_url,
            "source_url": self.source_url,
            "publisher": self.publisher,
            "category": self.category,
            "description": self.description,
            "permissions": list(self.permissions),
            "trackers": list(self.trackers),
            "tags": list(self.tags),
            "scraped_at": int(self.scraped_at or 0),
            "extra": dict(self.extra or {}),
        }
