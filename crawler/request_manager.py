# crawler/request_manager.py
import os
import sys
import time
import random
from typing import Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from logger import get_logger

log = get_logger(__name__)

# --------------------------------------------------
# Default headers (rotate UA later if needed)
# --------------------------------------------------
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}

# --------------------------------------------------
# Core Request Manager
# --------------------------------------------------
class RequestManager:
    def __init__(
        self,
        proxy: Optional[Dict[str, str]] = None,
        timeout: int = 20,
        max_retries: int = 3,
        backoff_factor: float = 1.5,
    ):
        self.proxy = proxy
        self.timeout = timeout
        self.session = self._init_session(max_retries, backoff_factor)

        if proxy:
            self.session.proxies.update(proxy)

    def _init_session(self, max_retries: int, backoff_factor: float) -> requests.Session:
        session = requests.Session()
        session.headers.update(DEFAULT_HEADERS)

        retries = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
            raise_on_status=False,
        )

        adapter = HTTPAdapter(max_retries=retries)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> Optional[requests.Response]:
        """
        Safe GET request.
        Returns Response or None (never raises).
        """
        try:
            merged_headers = DEFAULT_HEADERS.copy()
            if headers:
                merged_headers.update(headers)

            # small jitter to avoid fingerprinting
            time.sleep(random.uniform(0.3, 1.2))

            resp = self.session.get(
                url,
                headers=merged_headers,
                timeout=self.timeout,
                allow_redirects=True,
            )

            if resp.status_code >= 400:
                log.warning(f"[HTTP] {resp.status_code} -> {url}")
                return None

            return resp

        except Exception as e:
            log.error(f"[HTTP] Exception for {url}: {e}")
            return None

# --------------------------------------------------
# Service Init / Health Check (kept compatible)
# --------------------------------------------------
def init_services():
    """
    Initialize external services / runtime context.
    """
    info = {
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "cwd": os.getcwd(),
    }

    log.info(f"Python: {info['python_version']}")
    log.info(f"CWD: {info['cwd']}")

    return info


def check_services_status():
    """
    Dependency sanity check.
    """
    log.info("=== Service Status ===")

    def check(pkg, label):
        try:
            __import__(pkg)
            log.info(f"  {label}: OK")
        except Exception:
            log.warning(f"  {label}: MISSING")

    check("requests", "requests")
    check("bs4", "beautifulsoup4")
    check("lxml", "lxml (HTML parser)")

    try:
        import transformers  # noqa
        import sentence_transformers  # noqa
        log.info("  NLP stack: OK")
    except Exception:
        log.warning("  NLP stack: MISSING (crawler will still run)")

    log.info("======================")
