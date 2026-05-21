import sys as _sys
import importlib as _importlib

# ── Bridge: redirect old-style imports missing ".common" ──────────────────
# Some scrapers use  `from crawler.crawler_instance.…`
# instead of           `from crawler.common.crawler_instance.…`
# This meta-path finder transparently rewrites them.

class _CommonBridgeFinder:
    """Redirect crawler.crawler_instance.* → crawler.common.crawler_instance.*
       and      crawler.crawler_services.* → crawler.common.crawler_instance.crawler_services.*"""
    _PREFIXES = {
        "crawler.crawler_instance": "crawler.common.crawler_instance",
        "crawler.crawler_services": "crawler.common.crawler_instance.crawler_services",
    }

    def find_module(self, fullname, path=None):
        for short in self._PREFIXES:
            if fullname == short or fullname.startswith(short + "."):
                return self
        return None

    def load_module(self, fullname):
        if fullname in _sys.modules:
            return _sys.modules[fullname]
        for short, long in self._PREFIXES.items():
            if fullname == short or fullname.startswith(short + "."):
                real = long + fullname[len(short):]
                mod = _importlib.import_module(real)
                _sys.modules[fullname] = mod
                return mod
        raise ImportError(fullname)

_sys.meta_path.insert(0, _CommonBridgeFinder())

from .request_manager import init_services, check_services_status
from .request_parser import RequestParser

__all__ = ["init_services", "check_services_status", "RequestParser"]
