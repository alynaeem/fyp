"""
config.py — centralized configuration for DarkPulse.
All values are read from environment variables (loaded from .env).
Import this module everywhere instead of hardcoding values.

Usage:
    from config import cfg
    proxy = cfg.proxy        # e.g. {"server": "socks5://127.0.0.1:9150"}
    key   = cfg.api_key      # FastAPI auth key
"""

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from dotenv import load_dotenv

# Load .env from the project root (same directory as this file)
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))


def _bool(val: str, default: bool = False) -> bool:
    return str(val).strip().lower() in ("1", "true", "yes", "y") if val else default


def _int(val: str, default: int = 0) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


@dataclass
class DarkPulseConfig:
    # ── Tor / Proxy ──────────────────────────────────────────────────────────
    tor_proxy_url: str = ""        # e.g. "socks5://127.0.0.1:9150", empty = no proxy

    # ── MongoDB ──────────────────────────────────────────────────────────────
    mongo_uri: str = "mongodb://127.0.0.1:27017"
    mongo_db: str = "darkpulse"

    # ── API Server ───────────────────────────────────────────────────────────
    api_key: str = ""              # X-API-Key header value; empty = auth disabled
    cors_origins: List[str] = field(default_factory=lambda: ["*"])
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # ── GitHub ───────────────────────────────────────────────────────────────
    github_token: str = ""

    # ── Collector defaults ───────────────────────────────────────────────────
    max_pages: int = 5
    max_articles: int = 50

    # ── Scheduler ────────────────────────────────────────────────────────────
    schedule_interval_hours: int = 6   # how often orchestrator runs all collectors

    # ── Logging ──────────────────────────────────────────────────────────────
    log_level: str = "INFO"
    log_dir: str = "logs"

    @property
    def proxy(self) -> Optional[Dict[str, str]]:
        """Returns a proxy dict for RequestParser/Playwright, or None if not configured."""
        url = self.tor_proxy_url.strip()
        return {"server": url} if url else None

    @property
    def requests_proxies(self) -> Optional[Dict[str, str]]:
        """Returns a requests-compatible proxies dict."""
        url = self.tor_proxy_url.strip()
        if not url:
            return None
        # Ensure socks5h so DNS resolves through the proxy (important for .onion)
        if url.startswith("socks5://"):
            url = url.replace("socks5://", "socks5h://", 1)
        return {"http": url, "https": url}



    def __repr__(self) -> str:
        proxy_display = self.tor_proxy_url or "(none)"
        token_display = "***set***" if self.github_token else "(not set)"
        key_display = "***set***" if self.api_key else "(disabled)"
        return (
            f"DarkPulseConfig("
            f"proxy={proxy_display}, "
            f"mongo={self.mongo_uri}/{self.mongo_db}, "
            f"github_token={token_display}, "
            f"api_key={key_display}, "
            f"schedule={self.schedule_interval_hours}h"
            f")"
        )


def _load() -> DarkPulseConfig:
    cors_raw = os.getenv("CORS_ORIGINS", "*")
    cors_list = [o.strip() for o in cors_raw.split(",") if o.strip()]
    return DarkPulseConfig(
        tor_proxy_url=os.getenv("TOR_PROXY_URL", ""),
        mongo_uri=os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017"),
        mongo_db=os.getenv("MONGO_DB", "darkpulse"),
        api_key=os.getenv("API_KEY", ""),
        cors_origins=cors_list or ["*"],
        api_host=os.getenv("API_HOST", "0.0.0.0"),
        api_port=_int(os.getenv("API_PORT", "8000"), 8000),
        github_token=os.getenv("GITHUB_TOKEN", ""),
        max_pages=_int(os.getenv("MAX_PAGES", "5"), 5),
        max_articles=_int(os.getenv("MAX_ARTICLES", "50"), 50),
        schedule_interval_hours=_int(os.getenv("SCHEDULE_INTERVAL_HOURS", "6"), 6),
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        log_dir=os.getenv("LOG_DIR", "logs"),
    )


# Singleton — import and use everywhere:  from config import cfg
cfg: DarkPulseConfig = _load()
