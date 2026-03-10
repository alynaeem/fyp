from dataclasses import dataclass

@dataclass(frozen=True)
class RAW_PATH_CONSTANTS:
    """
    Minimal constants for crawlers.
    Add more keys/paths as your project needs.
    """
    RAW_HTML_CACHE_PREFIX: str = "RAWHTML:"
    DEFAULT_EXPIRY_SEC: int = 60 * 60 * 24  # 24 hours
