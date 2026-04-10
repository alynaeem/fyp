from urllib.parse import urlparse
import re
import requests
from bs4 import BeautifulSoup


class helper_method:
    @staticmethod
    def get_network_type(base_url: str) -> str:
        try:
            netloc = urlparse(base_url).netloc.lower()
            if netloc.endswith(".onion"):
                return "tor"
            scheme = urlparse(base_url).scheme.lower()
            if scheme in ("http", "https"):
                return "clearnet"
        except Exception:
            pass
        return "unknown"

    @staticmethod
    def _html_to_text(html: str) -> str:
        """
        Convert HTML to readable plain text (for NLP + printing).
        """
        if not html:
            return ""
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup(["script", "style", "noscript"]):
                tag.decompose()
            text = soup.get_text(" ", strip=True)
            text = re.sub(r"\s+", " ", text).strip()
            return text
        except Exception:
            return re.sub(r"\s+", " ", html).strip()

    @staticmethod
    def get_screenshot_base64(page, name: str | None, base_url: str) -> str:
        """
        Capture a base64-encoded screenshot of the current page.
        """
        if not page:
            return ""
        try:
            # Take screenshot and return as base64 string
            import base64
            screenshot_bytes = page.screenshot(type='jpeg', quality=50)
            return base64.b64encode(screenshot_bytes).decode('utf-8')
        except Exception:
            return ""

    @staticmethod
    def extract_refhtml(
        value: str,
        invoke_db,
        REDIS_COMMANDS,
        CUSTOM_SCRIPT_REDIS_KEYS,
        RAW_PATH_CONSTANTS,
        page=None,
        timeout: int = 15,
    ) -> str:
        """
        Fetch & cache content, but return CLEAN TEXT (not raw HTML).
        """
        v = (value or "").strip()
        if not v:
            return ""

        def _is_ip(x: str) -> bool:
            return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", x))

        candidates = []
        if v.startswith(("http://", "https://")):
            candidates.append(v)
        else:
            if _is_ip(v):
                candidates.append(f"http://{v}")
                candidates.append(f"https://{v}")
            else:
                candidates.append(f"https://{v}")
                candidates.append(f"http://{v}")

        prefix = getattr(CUSTOM_SCRIPT_REDIS_KEYS, "RAWHTML", "RAWHTML:")
        expiry = getattr(RAW_PATH_CONSTANTS, "DEFAULT_EXPIRY_SEC", None)

        for url in candidates:
            cache_key = f"{prefix}{url}"

            # cache GET
            try:
                cached = invoke_db(REDIS_COMMANDS.GET, cache_key, "", None)
                if cached:
                    return helper_method._html_to_text(str(cached))
            except Exception:
                pass

            # fetch
            try:
                r = requests.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                if r.text:
                    # cache SET raw html
                    try:
                        invoke_db(REDIS_COMMANDS.SET, cache_key, r.text, expiry)
                    except Exception:
                        pass
                    return helper_method._html_to_text(r.text)
            except Exception:
                continue

        return ""
