from pathlib import Path

# Compatibility shim for legacy imports that still reference
# `crawler.crawler_instance.*` instead of `crawler.common.crawler_instance.*`.
_current_dir = Path(__file__).resolve().parent
_legacy_root = _current_dir.parent / "common" / "crawler_instance"

__path__ = [str(_legacy_root)]
