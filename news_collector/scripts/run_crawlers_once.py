# run_crawlers_once.py — run all news collectors once (no scheduler).
import sys
import os
import traceback

# ── ensure project root is on sys.path ────────────────────────────────────────
# This file lives at:  darkpulse/news_collector/scripts/run_crawlers_once.py
# Project root is:     darkpulse/
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# --- import crawlers ---
from news_collector.scripts._thehackernews import _thehackernews
from news_collector.scripts._hackread import _hackread
from news_collector.scripts._csocybercrime import _csocybercrime
from news_collector.scripts._bleepingcomputer import _bleepingcomputer
from news_collector.scripts._krebsonsecurity import _krebsonsecurity
from news_collector.scripts._portswigger import _portswigger
from news_collector.scripts._therecord import _therecord
from news_collector.scripts._infosecuritymagazine import _infosecuritymagazine
from config import cfg
from logger import get_logger

log = get_logger(__name__)


def run_one(model, name, proxy=None, max_pages=None, max_articles=None):
    try:
        if proxy:
            model.set_proxy({"server": proxy})
        if max_pages or max_articles:
            model.set_limits(max_pages=max_pages, max_articles=max_articles)
        out = model.run()
        log.info(f"[OK] {name}: {out}")
    except Exception:
        log.error(f"[ERR] {name} crashed:\n{traceback.format_exc()}")


def main():
    proxy = cfg.tor_proxy_url or None    # reads from .env TOR_PROXY_URL
    max_pages = cfg.max_pages
    max_articles = cfg.max_articles

    log.info("=== Running news crawlers once ===")
    run_one(_thehackernews(), "thehackernews", proxy=proxy, max_pages=max_pages, max_articles=max_articles)
    run_one(_hackread(), "hackread", proxy=proxy, max_pages=max_pages, max_articles=max_articles)
    run_one(_csocybercrime(), "csocybercrime", proxy=proxy, max_pages=max_pages, max_articles=max_articles)
    run_one(_bleepingcomputer(), "bleepingcomputer", proxy=proxy, max_pages=max_pages, max_articles=max_articles)
    run_one(_krebsonsecurity(), "krebsonsecurity", proxy=proxy, max_pages=max_pages, max_articles=max_articles)
    run_one(_portswigger(), "portswigger", proxy=proxy, max_pages=max_pages, max_articles=max_articles)
    run_one(_therecord(), "therecord", proxy=proxy, max_pages=max_pages, max_articles=max_articles)
    run_one(_infosecuritymagazine(), "infosecuritymagazine", proxy=proxy, max_pages=max_pages, max_articles=max_articles)
    log.info("=== Done ===")


if __name__ == "__main__":
    main()
