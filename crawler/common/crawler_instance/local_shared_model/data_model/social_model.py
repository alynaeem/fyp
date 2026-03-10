from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, List, Optional


@dataclass
class social_model:
    m_channel_url: str = ""
    m_title: str = ""
    m_sender_name: str = ""
    m_message_sharable_link: str = ""
    m_weblink: List[str] = field(default_factory=list)
    m_content: str = ""
    m_content_type: List[str] = field(default_factory=list)
    m_network: str = ""
    m_message_date: Optional[date] = None
    m_message_id: str = ""
    m_platform: str = ""
    m_post_shares: Optional[int] = None
    m_post_likes: Optional[int] = None
    m_post_comments: Optional[str] = None
    m_post_comments_count: Optional[str] = None

    # extras (safe to keep)
    m_source: str = ""
    m_raw: Dict[str, Any] = field(default_factory=dict)

    # dedupe/hash (optional)
    m_hash: str = ""

    def compute_hash(self) -> str:
        payload = {
            "platform": self.m_platform,
            "url": self.m_message_sharable_link,
            "id": self.m_message_id,
            "title": self.m_title,
            "sender": self.m_sender_name,
            "content": self.m_content,
            "date": self.m_message_date.isoformat() if self.m_message_date else "",
        }
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.m_hash = hashlib.sha256(raw).hexdigest()
        return self.m_hash

    def to_dict(self) -> Dict[str, Any]:
        return {
            "m_channel_url": self.m_channel_url,
            "m_title": self.m_title,
            "m_sender_name": self.m_sender_name,
            "m_message_sharable_link": self.m_message_sharable_link,
            "m_weblink": self.m_weblink,
            "m_content": self.m_content,
            "m_content_type": self.m_content_type,
            "m_network": self.m_network,
            "m_message_date": self.m_message_date.isoformat() if self.m_message_date else None,
            "m_message_id": self.m_message_id,
            "m_platform": self.m_platform,
            "m_post_shares": self.m_post_shares,
            "m_post_likes": self.m_post_likes,
            "m_post_comments": self.m_post_comments,
            "m_source": self.m_source,
            "m_raw": self.m_raw,
            "m_hash": self.m_hash,
        }
