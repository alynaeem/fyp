# crawler/common/crawler_instance/crawler_services/redis_manager/redis_enums.py

from __future__ import annotations

from enum import IntEnum


class REDIS_COMMANDS(IntEnum):
    """
    Redis command identifiers
    Must match invoke_trigger usage in crawlers
    """

    # Base commands (as you requested)
    GET = 1
    SET = 2
    DELETE = 3

    # Backward-compatible aliases used by existing crawler scripts
    S_GET_STRING = 1
    S_SET_STRING = 2
    S_DELETE = 3


class REDIS_KEYS(IntEnum):
    """
    Redis key suffix/purpose identifiers used by crawler framework.
    Add more here if your framework already uses them.
    """

    # Used in your script:
    S_URL_TIMEOUT = 1001


class CUSTOM_SCRIPT_REDIS_KEYS:
    """
    Redis key prefixes used by crawler scripts
    """

    RAWHTML: str = "RAWHTML:"
    TWEETFEED: str = "TWEETFEED:"
    GENERIC: str = "GENERIC:"
