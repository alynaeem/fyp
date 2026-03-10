"""
logger.py — centralized logging for DarkPulse.

Usage:
    from logger import get_logger
    log = get_logger(__name__)
    log.info("Starting collector")
    log.warning("Rate limited by source")
    log.error("Request failed", exc_info=True)
"""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler

_loggers: dict = {}


def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger. Loggers are cached so the same name always
    returns the same instance (idempotent across multiple imports).

    Log output goes to:
      - stderr (console) — always
      - logs/<name>.log  — rotating, 5 MB × 3 backups
    """
    if name in _loggers:
        return _loggers[name]

    # ── resolve config lazily to avoid circular import ────────────────────────
    try:
        from config import cfg
        log_level_str = cfg.log_level.upper()
        log_dir = cfg.log_dir
    except Exception:
        log_level_str = os.getenv("LOG_LEVEL", "INFO").upper()
        log_dir = os.getenv("LOG_DIR", "logs")

    log_level = getattr(logging, log_level_str, logging.INFO)

    logger = logging.getLogger(name)
    logger.setLevel(log_level)

    if logger.handlers:
        _loggers[name] = logger
        return logger

    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # ── Console handler ───────────────────────────────────────────────────────
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(log_level)
    console.setFormatter(fmt)
    logger.addHandler(console)

    # ── File handler (rotating) ───────────────────────────────────────────────
    try:
        os.makedirs(log_dir, exist_ok=True)
        # Sanitize name to a safe filename (replace dots and slashes)
        safe_name = name.replace(".", "_").replace("/", "_").replace("\\", "_")
        log_path = os.path.join(log_dir, f"{safe_name}.log")
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=5 * 1024 * 1024,   # 5 MB per file
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)
    except Exception as e:
        # Non-fatal — console logging still works
        logger.warning(f"Could not set up file logging at {log_dir}: {e}")

    # Prevent propagation to root logger (avoids duplicate output)
    logger.propagate = False

    _loggers[name] = logger
    return logger
