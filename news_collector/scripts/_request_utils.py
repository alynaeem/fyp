import socket

import requests
from urllib3.util import connection as urllib3_connection


def _prefer_ipv4() -> None:
    current = getattr(urllib3_connection, "allowed_gai_family", None)
    if not current:
        return
    if getattr(current, "__name__", "") == "_darkpulse_ipv4_only":
        return

    def _darkpulse_ipv4_only():
        return socket.AF_INET

    urllib3_connection.allowed_gai_family = _darkpulse_ipv4_only


def create_direct_session(user_agent: str) -> requests.Session:
    _prefer_ipv4()
    session = requests.Session()
    session.trust_env = False
    session.headers.update(
        {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        }
    )
    return session
