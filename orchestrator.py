"""
orchestrator.py — Central scheduler for all DarkPulse collectors.
Reads all settings from .env via config.py.

Usage:
    python orchestrator.py --once                    # run all collectors once and exit
    python orchestrator.py --schedule                # run on cron schedule (every N hours)
    python orchestrator.py --once --collector news   # run only the news collector
    python orchestrator.py --help
"""

import argparse
import sys
import traceback
from typing import Callable, Optional

from config import cfg
from logger import get_logger

log = get_logger("orchestrator")


# ─────────────────────────────────────────────────────────────────────────────
# Collector registry
# Each entry: (name, run_fn)
# run_fn must accept no arguments and return None (errors are caught here)
# ─────────────────────────────────────────────────────────────────────────────

def _run_news() -> None:
    from crawler.request_manager import init_services
    from crawler.request_parser import RequestParser
    from news_collector.scripts._thehackernews import _thehackernews
    from news_collector.scripts._hackread import _hackread
    from news_collector.scripts._bleepingcomputer import _bleepingcomputer
    from news_collector.scripts._krebsonsecurity import _krebsonsecurity
    from news_collector.scripts._portswigger import _portswigger
    from news_collector.scripts._csocybercrime import _csocybercrime

    init_services()
    proxy = cfg.proxy
    sources = [
        ("thehackernews", _thehackernews),
        ("hackread", _hackread),
        ("bleepingcomputer", _bleepingcomputer),
        ("krebsonsecurity", _krebsonsecurity),
        ("portswigger", _portswigger),
        ("csocybercrime", _csocybercrime),
    ]
    for name, cls in sources:
        try:
            model = cls()
            model.set_limits(max_pages=cfg.max_pages, max_articles=cfg.max_articles)
            result = RequestParser(proxy=proxy, model=model, reset_cache=True).parse()
            log.info(f"  [{name}] {result.get('meta', {})}")
        except Exception as e:
            log.error(f"  [{name}] failed: {e}", exc_info=True)


def _run_leaks() -> None:
    from crawler.request_manager import init_services
    from crawler.request_parser import RequestParser
    from leak_collector.scripts.tracking._public_tableau import _public_tableau

    init_services()
    proxy = cfg.proxy
    sources = [
        ("public_tableau", _public_tableau),
    ]
    for name, cls in sources:
        try:
            model = cls()
            result = RequestParser(proxy=proxy, model=model, reset_cache=True).parse()
            log.info(f"  [{name}] {result.get('meta', {})}")
        except Exception as e:
            log.error(f"  [{name}] failed: {e}", exc_info=True)


def _run_exploits() -> None:
    from exploit_collector.main import run_all
    run_all()


def _run_defacement() -> None:
    from crawler.request_manager import init_services
    from crawler.request_parser import RequestParser
    from defacement_collector.scripts.hacks._defacer import _defacer
    from defacement_collector.scripts.phishing._phishunt import _phishunt
    from defacement_collector.scripts.generic._tweetfeed import _tweetfeed

    init_services()
    proxy = cfg.proxy
    sources = [
        ("defacer", _defacer),
        ("phishunt", _phishunt),
        ("tweetfeed", _tweetfeed),
    ]
    for name, cls in sources:
        try:
            model = cls()
            result = RequestParser(
                proxy=proxy, model=model, reset_cache=True, seed_fetch=True
            ).parse()
            log.info(f"  [{name}] {result.get('meta', {})}")
        except Exception as e:
            log.error(f"  [{name}] failed: {e}", exc_info=True)


def _run_social() -> None:
    log.info("  [social] social_collector — add your collectors here")


COLLECTORS: dict[str, Callable[[], None]] = {
    "news":       _run_news,
    "leaks":      _run_leaks,
    "exploits":   _run_exploits,
    "defacement": _run_defacement,
    "social":     _run_social,
}


# ─────────────────────────────────────────────────────────────────────────────
# Core runner
# ─────────────────────────────────────────────────────────────────────────────

def run_collector(name: str) -> None:
    """Run a single named collector with full error isolation."""
    fn = COLLECTORS.get(name)
    if fn is None:
        log.error(f"Unknown collector: '{name}'. Available: {list(COLLECTORS)}")
        return

    log.info(f"▶ Starting collector: {name}")
    try:
        fn()
        log.info(f"✔ Collector finished: {name}")
    except Exception:
        log.error(f"✘ Collector crashed: {name}\n{traceback.format_exc()}")


def run_all_collectors(selected: Optional[str] = None) -> None:
    """Run all collectors (or a single one if `selected` is given)."""
    targets = [selected] if selected else list(COLLECTORS)
    log.info(f"=== DarkPulse Orchestrator | collectors={targets} | proxy={cfg.tor_proxy_url or 'none'} ===")
    for name in targets:
        run_collector(name)
    log.info("=== All collectors finished ===")


# ─────────────────────────────────────────────────────────────────────────────
# Scheduler
# ─────────────────────────────────────────────────────────────────────────────

def start_scheduler(collector: Optional[str] = None) -> None:
    """Run all collectors on a recurring schedule using APScheduler."""
    try:
        from apscheduler.schedulers.blocking import BlockingScheduler
    except ImportError:
        log.error(
            "APScheduler is not installed. Run: pip install apscheduler\n"
            "Or use --once to run without a scheduler."
        )
        sys.exit(1)

    interval_hours = cfg.schedule_interval_hours
    log.info(f"Scheduler starting | interval={interval_hours}h | collector={collector or 'all'}")

    scheduler = BlockingScheduler(timezone="UTC")
    scheduler.add_job(
        run_all_collectors,
        "interval",
        hours=interval_hours,
        kwargs={"selected": collector},
        id="darkpulse_collect",
        replace_existing=True,
    )

    # Run once immediately on start
    run_all_collectors(selected=collector)

    log.info(f"Scheduler running — next run in {interval_hours}h. Press Ctrl+C to stop.")
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        log.info("Scheduler stopped.")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="orchestrator",
        description="DarkPulse — central collector orchestrator",
    )
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--once",
        action="store_true",
        help="Run all collectors once and exit",
    )
    mode.add_argument(
        "--schedule",
        action="store_true",
        help=f"Run on a recurring schedule (every SCHEDULE_INTERVAL_HOURS hours, default: {cfg.schedule_interval_hours})",
    )
    p.add_argument(
        "--collector",
        metavar="NAME",
        choices=list(COLLECTORS),
        default=None,
        help=f"Run only this collector. Choices: {list(COLLECTORS)}",
    )
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    log.info(f"DarkPulse Orchestrator starting | config={cfg}")

    if args.once:
        run_all_collectors(selected=args.collector)
    elif args.schedule:
        start_scheduler(collector=args.collector)


if __name__ == "__main__":
    main()
