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
import gc
import json
import hashlib
import importlib
import os
import signal
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

import pymongo
from config import cfg
from logger import get_logger
from mongo_persistence import (
    extract_model_documents,
    persist_raw_documents,
    serialise_document,
)

log = get_logger("orchestrator")

_LEAK_SCRIPT_DIR = Path(__file__).resolve().parent / "leak_collector" / "scripts" / "leak"
_SOURCE_STATUS_COLLECTION = "collector_source_status"


def _cleanup_browsers():
    """Kill any orphaned Chromium processes spawned by Playwright to prevent
    resource exhaustion.  Called after each scraper finishes."""
    try:
        # Find Playwright-spawned Chromium processes
        result = subprocess.run(
            ["pgrep", "-f", "chromium.*--headless"],
            capture_output=True, text=True, timeout=5
        )
        pids = result.stdout.strip().split("\n")
        pids = [p.strip() for p in pids if p.strip()]
        if pids:
            for pid in pids:
                try:
                    os.kill(int(pid), signal.SIGTERM)
                except (ProcessLookupError, ValueError, PermissionError):
                    pass
            log.info(f"  [cleanup] terminated {len(pids)} orphaned Chromium processes")
            time.sleep(1)
    except Exception:
        pass
    gc.collect()

# ─────────────────────────────────────────────────────────────────────────────
# MongoDB persistence helper for non-news collectors
# ─────────────────────────────────────────────────────────────────────────────
_mongo_client = None

def _get_kv_collection():
    global _mongo_client
    if _mongo_client is None:
        _mongo_client = pymongo.MongoClient(cfg.mongo_uri)
    return _mongo_client[cfg.mongo_db]["redis_kv_store"]


def _get_source_status_collection():
    global _mongo_client
    if _mongo_client is None:
        _mongo_client = pymongo.MongoClient(cfg.mongo_uri)
    return _mongo_client[cfg.mongo_db][_SOURCE_STATUS_COLLECTION]


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _target_host(value: str) -> str:
    if not value:
        return ""
    try:
        return urlparse(value).netloc or value
    except Exception:
        return value


def _script_identity(name: str, cls=None, *, module_stem: str | None = None, script_file: str | None = None) -> tuple[str, str]:
    resolved_module_stem = module_stem or getattr(cls, "__module__", "").rsplit(".", 1)[-1] or name
    resolved_script_file = script_file or f"{resolved_module_stem}.py"
    return resolved_module_stem, resolved_script_file


def _env_csv_set(name: str) -> set[str]:
    raw = os.getenv(name, "")
    return {part.strip().lower() for part in raw.split(",") if part.strip()}


def _model_target_url(model) -> str:
    for attr_name in ("seed_url", "base_url"):
        try:
            value = getattr(model, attr_name, "")
        except Exception:
            value = ""
        if callable(value):
            try:
                value = value()
            except Exception:
                value = ""
        if value:
            return str(value)
    try:
        contact = model.contact_page()
        if contact:
            return str(contact)
    except Exception:
        pass
    return ""


def _summarize_error(error) -> str:
    if not error:
        return ""
    message = str(error).strip()
    if len(message) > 900:
        return f"{message[:897]}..."
    return message


def _derive_leak_status(parse_meta: dict | None, db_stats: dict | None) -> str:
    parse_meta = parse_meta or {}
    db_stats = db_stats or {}
    raw_items = int(db_stats.get("raw_items") or 0)
    parse_count = int(parse_meta.get("count") or 0)
    parse_error = str(parse_meta.get("error") or "").strip().lower()
    parse_state = str(parse_meta.get("status") or "").strip().lower()

    if raw_items > 0 or parse_count > 0:
        return "ingested"
    if parse_error:
        unreachable_markers = (
            "err_socks_connection_failed",
            "socks",
            "proxy",
            "timed out",
            "timeout",
            "name resolution",
            "dns",
            "connection refused",
            "connection reset",
            "net::err",
            "tunnel",
            "unreachable",
        )
        if any(marker in parse_error for marker in unreachable_markers):
            return "unreachable"
        return "error"
    if parse_state and parse_state != "success":
        return "error"
    return "empty"


def _record_source_status(
    collector_type: str,
    name: str,
    *,
    cls=None,
    model=None,
    status: str,
    source_kind: str = "",
    parse_meta: dict | None = None,
    db_stats: dict | None = None,
    error=None,
    auto_discovered: bool | None = None,
    module_stem: str | None = None,
    script_file: str | None = None,
) -> None:
    collection = _get_source_status_collection()
    now = _utcnow_iso()
    resolved_module_stem, resolved_script_file = _script_identity(
        name,
        cls,
        module_stem=module_stem,
        script_file=script_file,
    )
    target_url = _model_target_url(model) if model is not None else ""
    parse_meta = parse_meta or {}
    db_stats = db_stats or {}
    normalized_status = str(status or "unknown").strip().lower() or "unknown"
    error_message = _summarize_error(error or parse_meta.get("error"))

    update_fields = {
        "collector_type": collector_type,
        "source_name": name,
        "module_stem": resolved_module_stem,
        "script_file": resolved_script_file,
        "status": normalized_status,
        "updated_at": now,
        "target_url": target_url,
        "target_host": _target_host(target_url),
        "parse_count": int(parse_meta.get("count") or 0),
        "parse_duration_seconds": float(parse_meta.get("duration") or 0),
        "raw_items": int(db_stats.get("raw_items") or 0),
        "raw_entities": int(db_stats.get("raw_entities") or 0),
    }
    if source_kind:
        update_fields["source_kind"] = source_kind
    if auto_discovered is not None:
        update_fields["auto_discovered"] = bool(auto_discovered)
    if error_message:
        update_fields["last_error"] = error_message
    elif normalized_status not in {"error", "import_error", "unreachable"}:
        update_fields["last_error"] = ""

    if normalized_status in {"running", "queued"}:
        update_fields["last_started_at"] = now
    if normalized_status in {"ingested", "empty", "error", "unreachable", "import_error"}:
        update_fields["last_run_at"] = now
    if normalized_status == "ingested":
        update_fields["last_success_at"] = now

    collection.update_one(
        {"_id": f"{collector_type}:{resolved_module_stem}"},
        {
            "$set": update_fields,
            "$setOnInsert": {
                "created_at": now,
            },
        },
        upsert=True,
    )


def _persist_model_data(collector_type: str, name: str, model, parsed_data=None):
    """Persist collector output into raw MongoDB collections and legacy KV docs."""
    kv = _get_kv_collection()
    prefix = f"{collector_type.upper()}_ITEMS"
    entity_prefix = f"{collector_type.upper()}_ENTITIES"
    written = 0

    card_data, entity_data = extract_model_documents(model, parsed_data)
    raw_stats = persist_raw_documents(collector_type, name, card_data, entity_data)

    if collector_type == "news":
        return {**raw_stats, "legacy_kv": 0}

    for i, card in enumerate(card_data):
        d = serialise_document(card)
        if not isinstance(d, dict):
            continue

        d['m_source'] = name
        d['m_collector_type'] = collector_type
        raw = json.dumps(d, ensure_ascii=False, default=str)
        h = hashlib.sha256(raw.encode()).hexdigest()[:16]
        key = f"{prefix}:{h}_{name}"
        kv.update_one({"_id": key}, {"$set": {"value": raw}}, upsert=True)
        written += 1

        # Also persist entity data if available
        if i < len(entity_data):
            ent = entity_data[i]
            ed = serialise_document(ent)
            if not isinstance(ed, dict):
                continue
            ed['m_source'] = name
            eraw = json.dumps(ed, ensure_ascii=False, default=str)
            ekey = f"{entity_prefix}:{h}_{name}"
            kv.update_one({"_id": ekey}, {"$set": {"value": eraw}}, upsert=True)

    return {**raw_stats, "legacy_kv": written}


def _discover_additional_leak_sources(existing_sources):
    """Load any leak collectors present on disk that are not manually registered yet.

    This keeps backwards-compatible aliases for the known collectors while ensuring
    newly dropped-in leak scripts are picked up automatically by the collector
    scheduler and pushed into MongoDB without further manual wiring.
    """
    known_modules = {
        getattr(cls, "__module__", "").rsplit(".", 1)[-1]
        for _, cls in existing_sources
    }
    discovered = []

    for script_path in sorted(_LEAK_SCRIPT_DIR.glob("_*.py")):
        module_stem = script_path.stem
        if module_stem == "__init__" or module_stem in known_modules:
            continue

        module_name = f"leak_collector.scripts.leak.{module_stem}"
        try:
            module = importlib.import_module(module_name)
            cls = getattr(module, module_stem, None)
            if cls is None:
                _record_source_status(
                    "leak",
                    module_stem.lstrip("_"),
                    status="import_error",
                    error=f"collector class `{module_stem}` not found",
                    source_kind="leak_site",
                    auto_discovered=True,
                    module_stem=module_stem,
                    script_file=script_path.name,
                )
                log.warning(f"  [{module_stem}] skipped: collector class `{module_stem}` not found")
                continue
            discovered.append((module_stem.lstrip("_"), cls))
        except Exception as exc:
            _record_source_status(
                "leak",
                module_stem.lstrip("_"),
                status="import_error",
                error=exc,
                source_kind="leak_site",
                auto_discovered=True,
                module_stem=module_stem,
                script_file=script_path.name,
            )
            log.warning(f"  [{module_stem}] skipped during auto-discovery: {exc}")

    return discovered


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
    from news_collector.scripts._therecord import _therecord
    from news_collector.scripts._infosecuritymagazine import _infosecuritymagazine

    init_services()
    proxy = cfg.proxy
    sources = [
        ("thehackernews", _thehackernews),
        ("hackread", _hackread),
        ("bleepingcomputer", _bleepingcomputer),
        ("krebsonsecurity", _krebsonsecurity),
        ("portswigger", _portswigger),
        ("csocybercrime", _csocybercrime),
        ("therecord", _therecord),
        ("infosecuritymagazine", _infosecuritymagazine),
    ]
    for name, cls in sources:
        try:
            model = cls()
            model.set_limits(max_pages=cfg.max_pages, max_articles=cfg.max_articles)
            result = RequestParser(proxy=proxy, model=model, reset_cache=True).parse()
            db_stats = _persist_model_data("news", name, model, parsed_data=result.get("data"))
            log.info(
                f"  [{name}] meta={result.get('meta', {})} "
                f"raw_items={db_stats['raw_items']} raw_entities={db_stats['raw_entities']}"
            )
        except Exception as e:
            log.error(f"  [{name}] failed: {e}", exc_info=True)
        finally:
            _cleanup_browsers()


def _run_leaks() -> None:
    from crawler.request_manager import init_services
    from crawler.request_parser import RequestParser
    leak_sites_only = os.getenv("LEAK_SITES_ONLY", "").strip().lower() in {"1", "true", "yes", "on"}

    # --- tracking (REQUESTS-based, self-contained with run()) ---
    from leak_collector.scripts.tracking._acn import _acn
    from leak_collector.scripts.tracking._certPK import _certPK
    from leak_collector.scripts.tracking._cert_at import _cert_at
    from leak_collector.scripts.tracking._cert_cn import _cert_cn
    from leak_collector.scripts.tracking._cert_pl import _cert_pl
    from leak_collector.scripts.tracking._certeu import _certeu
    from leak_collector.scripts.tracking._cncs_pt import _cncs_pt
    from leak_collector.scripts.tracking._csa_gov_sg import _csa_gov_sg
    from leak_collector.scripts.tracking._csocybercrime_tracking import _csocybercrime_tracking
    from leak_collector.scripts.tracking._public_tableau import _public_tableau

    # --- leak sites (Playwright-based, most need Tor) ---
    from leak_collector.scripts.leak._akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad import _akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad
    from leak_collector.scripts.leak._business_data_leaks import _business_data_leaks
    from leak_collector.scripts.leak._5butbkrljkaorg5maepuca25oma7eiwo6a2rlhvkblb4v6mf3ki2ovid import _5butbkrljkaorg5maepuca25oma7eiwo6a2rlhvkblb4v6mf3ki2ovid
    from leak_collector.scripts.leak._black3gnkizshuynieigw6ejgpblb53mpasftzd6pydqpmq2vn2xf6yd import _black3gnkizshuynieigw6ejgpblb53mpasftzd6pydqpmq2vn2xf6yd
    from leak_collector.scripts.leak._csidb import _csidb
    from leak_collector.scripts.leak._darkleakyqmv62eweqwy4dnhaijg4m4dkburo73pzuqfdumcntqdokyd import _darkleakyqmv62eweqwy4dnhaijg4m4dkburo73pzuqfdumcntqdokyd
    from leak_collector.scripts.leak._dataleakypypu7uwblm5kttv726l3iripago6p336xjnbstkjwrlnlid import _dataleakypypu7uwblm5kttv726l3iripago6p336xjnbstkjwrlnlid
    from leak_collector.scripts.leak._ddosecrets import _ddosecrets
    from leak_collector.scripts.leak._fjg4zi4opkxkvdz7mvwp7h6goe4tcby3hhkrz43pht4j3vakhy75znyd import _fjg4zi4opkxkvdz7mvwp7h6goe4tcby3hhkrz43pht4j3vakhy75znyd
    from leak_collector.scripts.leak._handala_hack import _handala_hack
    from leak_collector.scripts.leak._hptqq2o2qjva7lcaaq67w36jihzivkaitkexorauw7b2yul2z6zozpqd import _hptqq2o2qjva7lcaaq67w36jihzivkaitkexorauw7b2yul2z6zozpqd
    from leak_collector.scripts.leak._hunters55atbdusuladzv7vzv6a423bkh6ksl2uftwrxyuarbzlfh7yd import _hunters55atbdusuladzv7vzv6a423bkh6ksl2uftwrxyuarbzlfh7yd
    from leak_collector.scripts.leak._ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd import _ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd
    from leak_collector.scripts.leak._incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad import _incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad
    from leak_collector.scripts.leak._intelrepository import _intelrepository
    from leak_collector.scripts.leak._leak_lookup import _leak_lookup
    from leak_collector.scripts.leak._leaksndi6i6m2ji6ozulqe4imlrqn6wrgjlhxe25vremvr3aymm4aaid import _leaksndi6i6m2ji6ozulqe4imlrqn6wrgjlhxe25vremvr3aymm4aaid
    from leak_collector.scripts.leak._lockbit7z2jwcskxpbokpemdxmltipntwlkmidcll2qirbu7ykg46eyd import _lockbit7z2jwcskxpbokpemdxmltipntwlkmidcll2qirbu7ykg46eyd
    from leak_collector.scripts.leak._monitor_mozilla import _monitor_mozilla
    from leak_collector.scripts.leak._nitrogenczslprh3xyw6lh5xyjvmsz7ciljoqxxknd7uymkfetfhgvqd import _nitrogenczslprh3xyw6lh5xyjvmsz7ciljoqxxknd7uymkfetfhgvqd
    from leak_collector.scripts.leak._peargxn3oki34c4savcbcfqofjjwjnnyrlrbszfv6ujlx36mhrh57did import _peargxn3oki34c4savcbcfqofjjwjnnyrlrbszfv6ujlx36mhrh57did
    from leak_collector.scripts.leak._pearsmob5sn44ismokiusuld34pnfwi6ctgin3qbvonpoob4lh3rmtqd import _pearsmob5sn44ismokiusuld34pnfwi6ctgin3qbvonpoob4lh3rmtqd
    from leak_collector.scripts.leak._ransom import _ransom
    from leak_collector.scripts.leak._ransomed import _ransomed
    from leak_collector.scripts.leak._ransomlook import _ransomlook
    from leak_collector.scripts.leak._ransomocmou6mnbquqz44ewosbkjk3o5qjsl3orawojexfook2j7esad import _ransomocmou6mnbquqz44ewosbkjk3o5qjsl3orawojexfook2j7esad
    from leak_collector.scripts.leak._ransomware_live import _ransomware_live
    from leak_collector.scripts.leak._rhysidafohrhyy2aszi7bm32tnjat5xri65fopcxkdfxhi4tidsg7cad import _rhysidafohrhyy2aszi7bm32tnjat5xri65fopcxkdfxhi4tidsg7cad
    from leak_collector.scripts.leak._rnsmwareartse3m4hjsumjf222pnka6gad26cqxqmbjvevhbnym5p6ad import _rnsmwareartse3m4hjsumjf222pnka6gad26cqxqmbjvevhbnym5p6ad
    from leak_collector.scripts.leak._safepaypfxntwixwjrlcscft433ggemlhgkkdupi2ynhtcmvdgubmoyd import _safepaypfxntwixwjrlcscft433ggemlhgkkdupi2ynhtcmvdgubmoyd
    from leak_collector.scripts.leak._securo45z554mw7rgrt7wcgv5eenj2xmxyrsdj3fcjsvindu63s4bsid import _securo45z554mw7rgrt7wcgv5eenj2xmxyrsdj3fcjsvindu63s4bsid
    from leak_collector.scripts.leak._toufanleaks import _toufanleaks
    from leak_collector.scripts.leak._yzcpwxuhbkyjnyn4qsf4o5dkvu6m2fyo7dwizmnlutanlmzlos7pa6qd import _yzcpwxuhbkyjnyn4qsf4o5dkvu6m2fyo7dwizmnlutanlmzlos7pa6qd

    optional_leak_sources = []
    try:
        from leak_collector.scripts.leak._darkfeed import _darkfeed
        optional_leak_sources.append(("darkfeed", _darkfeed))
    except Exception as exc:
        log.warning(f"  [darkfeed] skipped: optional collector unavailable ({exc})")

    init_services()
    proxy = cfg.proxy

    # Tracking sources (REQUESTS-based, have run())
    tracking_sources = [
        ("acn", _acn),
        ("certPK", _certPK),
        ("cert_at", _cert_at),
        ("cert_cn", _cert_cn),
        ("cert_pl", _cert_pl),
        ("certeu", _certeu),
        ("cncs_pt", _cncs_pt),
        ("csa_gov_sg", _csa_gov_sg),
        ("csocybercrime_tracking", _csocybercrime_tracking),
        ("public_tableau", _public_tableau),
    ]

    # Leak sites (Playwright-based)
    leak_sources = [
        ("akira", _akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad),
        ("business_data_leaks", _business_data_leaks),
        ("fivebutb", _5butbkrljkaorg5maepuca25oma7eiwo6a2rlhvkblb4v6mf3ki2ovid),
        ("black3g", _black3gnkizshuynieigw6ejgpblb53mpasftzd6pydqpmq2vn2xf6yd),
        ("csidb", _csidb),
        ("darkleak", _darkleakyqmv62eweqwy4dnhaijg4m4dkburo73pzuqfdumcntqdokyd),
        ("blacklock", _dataleakypypu7uwblm5kttv726l3iripago6p336xjnbstkjwrlnlid),
        ("ddosecrets", _ddosecrets),
        ("fjg4zi", _fjg4zi4opkxkvdz7mvwp7h6goe4tcby3hhkrz43pht4j3vakhy75znyd),
        ("handala_hack", _handala_hack),
        ("hptqq2", _hptqq2o2qjva7lcaaq67w36jihzivkaitkexorauw7b2yul2z6zozpqd),
        ("hunters_intl", _hunters55atbdusuladzv7vzv6a423bkh6ksl2uftwrxyuarbzlfh7yd),
        ("ijzn3sic", _ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd),
        ("incblog", _incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad),
        ("intelrepository", _intelrepository),
        ("leak_lookup", _leak_lookup),
        ("leaks_onion", _leaksndi6i6m2ji6ozulqe4imlrqn6wrgjlhxe25vremvr3aymm4aaid),
        ("lockbit", _lockbit7z2jwcskxpbokpemdxmltipntwlkmidcll2qirbu7ykg46eyd),
        ("monitor_mozilla", _monitor_mozilla),
        ("nitrogen", _nitrogenczslprh3xyw6lh5xyjvmsz7ciljoqxxknd7uymkfetfhgvqd),
        ("pear", _peargxn3oki34c4savcbcfqofjjwjnnyrlrbszfv6ujlx36mhrh57did),
        ("pearmob", _pearsmob5sn44ismokiusuld34pnfwi6ctgin3qbvonpoob4lh3rmtqd),
        ("ransom_wiki", _ransom),
        ("ransomed", _ransomed),
        ("ransomlook", _ransomlook),
        ("ransomhub", _ransomocmou6mnbquqz44ewosbkjk3o5qjsl3orawojexfook2j7esad),
        ("ransomware_live", _ransomware_live),
        ("rhysida", _rhysidafohrhyy2aszi7bm32tnjat5xri65fopcxkdfxhi4tidsg7cad),
        ("rnsmware", _rnsmwareartse3m4hjsumjf222pnka6gad26cqxqmbjvevhbnym5p6ad),
        ("safepay", _safepaypfxntwixwjrlcscft433ggemlhgkkdupi2ynhtcmvdgubmoyd),
        ("securo", _securo45z554mw7rgrt7wcgv5eenj2xmxyrsdj3fcjsvindu63s4bsid),
        ("toufanleaks", _toufanleaks),
        ("yzcpwx", _yzcpwxuhbkyjnyn4qsf4o5dkvu6m2fyo7dwizmnlutanlmzlos7pa6qd),
    ]
    leak_sources.extend(optional_leak_sources)
    auto_discovered_leak_sources = _discover_additional_leak_sources(leak_sources)
    if auto_discovered_leak_sources:
        leak_sources.extend(auto_discovered_leak_sources)
        log.info(
            "  [leaks] auto-discovered %s additional script(s): %s",
            len(auto_discovered_leak_sources),
            ", ".join(name for name, _ in auto_discovered_leak_sources[:20]),
        )

    leak_status_filters = _env_csv_set("LEAK_STATUS_FILTER")
    leak_source_filters = _env_csv_set("LEAK_SOURCE_NAMES")
    if leak_status_filters or leak_source_filters:
        status_docs = list(_get_source_status_collection().find({"collector_type": "leak"}))
        status_by_module = {
            str(doc.get("module_stem") or ""): str(doc.get("status") or "not_run").lower()
            for doc in status_docs
            if doc.get("module_stem")
        }
        filtered_sources = []
        for name, cls in leak_sources:
            module_stem, script_file = _script_identity(name, cls)
            current_status = status_by_module.get(module_stem, "not_run")
            name_candidates = {
                str(name).lower(),
                str(module_stem).lower(),
                str(script_file).lower(),
                str(module_stem).lstrip("_"),
            }
            matches_status = not leak_status_filters or current_status in leak_status_filters
            matches_name = not leak_source_filters or bool(name_candidates & leak_source_filters)
            if matches_status and matches_name:
                filtered_sources.append((name, cls))
        log.info(
            "  [leaks] filtered leak site scripts: kept %s of %s (status_filter=%s, name_filter=%s)",
            len(filtered_sources),
            len(leak_sources),
            sorted(leak_status_filters) or ["all"],
            sorted(leak_source_filters) or ["all"],
        )
        leak_sources = filtered_sources

    all_sources = leak_sources if leak_sites_only else tracking_sources + leak_sources
    if leak_sites_only:
        log.info("  [leaks] running leak site scripts only (tracking sources skipped)")
    auto_discovered_names = {name for name, _ in auto_discovered_leak_sources}
    leak_source_names = {name for name, _ in leak_sources}
    for name, cls in all_sources:
        model = None
        try:
            model = cls()
            if hasattr(model, "set_proxy"):
                model.set_proxy(proxy or {})
            if name in leak_source_names:
                _record_source_status(
                    "leak",
                    name,
                    cls=cls,
                    model=model,
                    status="running",
                    source_kind="leak_site",
                    auto_discovered=name in auto_discovered_names,
                )
            result = RequestParser(proxy=proxy, model=model, reset_cache=True).parse()
            parse_meta = result.get("meta", {}) or {}
            count = parse_meta.get("count", 0)
            db_stats = _persist_model_data("leak", name, model, parsed_data=result.get('data'))
            if name in leak_source_names:
                _record_source_status(
                    "leak",
                    name,
                    cls=cls,
                    model=model,
                    status=_derive_leak_status(parse_meta, db_stats),
                    source_kind="leak_site",
                    parse_meta=parse_meta,
                    db_stats=db_stats,
                    auto_discovered=name in auto_discovered_names,
                )
            log.info(
                f"  [{name}] parse_count={count} raw_items={db_stats['raw_items']} "
                f"raw_entities={db_stats['raw_entities']} kv_written={db_stats['legacy_kv']}"
            )
        except Exception as e:
            if name in leak_source_names:
                target_url = _model_target_url(model) if model is not None else ""
                _record_source_status(
                    "leak",
                    name,
                    cls=cls,
                    model=model,
                    status="unreachable" if ".onion" in target_url else "error",
                    source_kind="leak_site",
                    error=e,
                    auto_discovered=name in auto_discovered_names,
                )
            log.error(f"  [{name}] failed: {e}", exc_info=True)
        finally:
            _cleanup_browsers()


def _run_exploits() -> None:
    from crawler.request_manager import init_services
    from crawler.request_parser import RequestParser
    from exploit_collector.main import COLLECTORS

    init_services()
    proxy = cfg.proxy

    for name, cls in COLLECTORS:
        try:
            model = cls()
            if hasattr(model, "set_proxy"):
                model.set_proxy(proxy or {})
            result = RequestParser(
                proxy=proxy,
                model=model,
                reset_cache=True,
                seed_fetch=True,
            ).parse()
            count = result.get("meta", {}).get("count", 0)
            db_stats = _persist_model_data("exploit", name, model, parsed_data=result.get("data"))
            log.info(
                f"  [{name}] parse_count={count} raw_items={db_stats['raw_items']} "
                f"raw_entities={db_stats['raw_entities']} kv_written={db_stats['legacy_kv']}"
            )
        except Exception as e:
            log.error(f"  [{name}] failed: {e}", exc_info=True)
        finally:
            _cleanup_browsers()


def _run_defacement() -> None:
    from crawler.request_manager import init_services
    from crawler.request_parser import RequestParser
    from defacement_collector.scripts.hacks._defacer import _defacer
    from defacement_collector.scripts.hacks._ownzyou import _ownzyou
    from defacement_collector.scripts.hacks._zone_xsec import _zone_xsec
    from defacement_collector.scripts.phishing._phishunt import _phishunt
    from defacement_collector.scripts.phishing._github_mthcht_awesome_lists import _github_mthcht_awesome_lists
    from defacement_collector.scripts.phishing._github_openfish import _github_openfish
    from defacement_collector.scripts.generic._tweetfeed import _tweetfeed
    from defacement_collector.scripts.generic._usom import _usom

    init_services()
    proxy = cfg.proxy
    sources = [
        ("defacer", _defacer),
        ("ownzyou", _ownzyou),
        ("zone_xsec", _zone_xsec),
        ("phishunt", _phishunt),
        ("github_mthcht", _github_mthcht_awesome_lists),
        ("github_openfish", _github_openfish),
        ("tweetfeed", _tweetfeed),
        ("usom", _usom),
    ]
    for name, cls in sources:
        try:
            model = cls()
            if hasattr(model, "set_proxy"):
                model.set_proxy(proxy or {})
            result = RequestParser(
                proxy=proxy, model=model, reset_cache=True, seed_fetch=True
            ).parse()
            count = result.get('meta', {}).get('count', 0)
            db_stats = _persist_model_data("defacement", name, model, parsed_data=result.get('data'))
            log.info(
                f"  [{name}] parse_count={count} raw_items={db_stats['raw_items']} "
                f"raw_entities={db_stats['raw_entities']} kv_written={db_stats['legacy_kv']}"
            )
        except Exception as e:
            log.error(f"  [{name}] failed: {e}", exc_info=True)
        finally:
            _cleanup_browsers()


def _run_social() -> None:
    from crawler.request_manager import init_services
    from crawler.request_parser import RequestParser

    # Forums
    from social_collector.scripts.forums._4hpfzoj3tgyp2w7sbe3gnmphqiqpxwwyijyvotamrvojl7pkra7z7byd import _4hpfzoj3tgyp2w7sbe3gnmphqiqpxwwyijyvotamrvojl7pkra7z7byd
    from social_collector.scripts.forums._crackingx import _crackingx
    from social_collector.scripts.forums._csrin import _csrin
    from social_collector.scripts.forums._dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad import _dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad
    from social_collector.scripts.forums._hacksnation import _hacksnation
    from social_collector.scripts.forums._ownzyou import _ownzyou
    from social_collector.scripts.forums._quartertothree import _quartertothree
    from social_collector.scripts.forums._rambleeeqrhty6s5jgefdfdtc6tfgg4jj6svr4jpgk4wjtg3qshwbaad import _rambleeeqrhty6s5jgefdfdtc6tfgg4jj6svr4jpgk4wjtg3qshwbaad

    # Platforms
    from social_collector.scripts.platform._mastodon import _mastodon
    from social_collector.scripts.platform._pastebin import _pastebin
    from social_collector.scripts.platform._reddit import _reddit
    from social_collector.scripts.platform._twitter import _twitter

    init_services()
    proxy = cfg.proxy
    sources = [
        # Forums
        ("4chan_onion", _4hpfzoj3tgyp2w7sbe3gnmphqiqpxwwyijyvotamrvojl7pkra7z7byd),
        ("crackingx", _crackingx),
        ("csrin", _csrin),
        ("dread", _dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad),
        ("hacksnation", _hacksnation),
        ("ownzyou_forum", _ownzyou),
        ("quartertothree", _quartertothree),
        ("ramble", _rambleeeqrhty6s5jgefdfdtc6tfgg4jj6svr4jpgk4wjtg3qshwbaad),
        # Platforms
        ("mastodon", _mastodon),
        ("pastebin", _pastebin),
        ("reddit", _reddit),
        ("twitter", _twitter),
    ]
    for name, cls in sources:
        try:
            model = cls()
            if hasattr(model, "set_proxy"):
                model.set_proxy(proxy or {})
            result = RequestParser(proxy=proxy, model=model, reset_cache=True, seed_fetch=True).parse()
            count = result.get('meta', {}).get('count', 0)
            db_stats = _persist_model_data("social", name, model, parsed_data=result.get('data'))
            log.info(
                f"  [{name}] parse_count={count} raw_items={db_stats['raw_items']} "
                f"raw_entities={db_stats['raw_entities']} kv_written={db_stats['legacy_kv']}"
            )
        except Exception as e:
            log.error(f"  [{name}] failed: {e}", exc_info=True)
        finally:
            _cleanup_browsers()


def _run_api() -> None:
    from crawler.request_manager import init_services
    from crawler.request_parser import RequestParser
    from api_collector.scripts._apk_mod import _apk_mod
    from api_collector.scripts._pakdb import _pakdb
    from api_collector.scripts._pcgame_mod import _pcgame_mod
    from api_collector.scripts.github_trivy_checker import github_trivy_checker

    init_services()
    proxy = cfg.proxy
    sources = [
        ("apk_mod", _apk_mod),
        ("pakdb", _pakdb),
        ("pcgame_mod", _pcgame_mod),
        ("github_trivy", github_trivy_checker),
    ]

    # --- SEO checker (standalone, not RequestParser-based) ---
    try:
        from api_collector.scripts.seo_checker import pagespeed_seo, URLS, API_KEY
        seo_kv = _get_kv_collection()
        seo_count = 0
        seo_items = []
        for site_name, site_url in URLS.items():
            try:
                result = pagespeed_seo(site_url, API_KEY)
                if result and not result.get("error"):
                    d = {
                        "m_app_name": f"SEO: {site_name}",
                        "m_app_url": result.get("url", site_url),
                        "m_description": f"SEO Score: {result.get('seoScore', 'N/A')}",
                        "m_source": "seo_checker",
                        "m_collector_type": "api",
                        "m_network": "clearnet",
                        "m_extra": result,
                    }
                    seo_items.append(d)
                    raw = json.dumps(d, ensure_ascii=False, default=str)
                    h = hashlib.sha256(raw.encode()).hexdigest()[:16]
                    key = f"API_ITEMS:{h}_seo_{site_name}"
                    seo_kv.update_one({"_id": key}, {"$set": {"value": raw}}, upsert=True)
                    seo_count += 1
            except Exception as e:
                log.warning(f"  [seo_checker/{site_name}] failed: {e}")
        seo_raw_stats = persist_raw_documents("api", "seo_checker", seo_items, [])
        log.info(
            f"  [seo_checker] raw_items={seo_raw_stats['raw_items']} "
            f"raw_entities={seo_raw_stats['raw_entities']} kv_written={seo_count}"
        )
    except Exception as e:
        log.error(f"  [seo_checker] failed: {e}", exc_info=True)

    for name, cls in sources:
        try:
            model = cls()
            if hasattr(model, "set_proxy"):
                model.set_proxy(proxy or {})
            result = RequestParser(proxy=proxy, model=model, reset_cache=True).parse()
            count = result.get('meta', {}).get('count', 0)
            db_stats = _persist_model_data("api", name, model, parsed_data=result.get('data'))
            log.info(
                f"  [{name}] parse_count={count} raw_items={db_stats['raw_items']} "
                f"raw_entities={db_stats['raw_entities']} kv_written={db_stats['legacy_kv']}"
            )
        except Exception as e:
            log.error(f"  [{name}] failed: {e}", exc_info=True)
        finally:
            _cleanup_browsers()


COLLECTORS: dict[str, Callable[[], None]] = {
    "news":       _run_news,
    "leaks":      _run_leaks,
    "exploits":   _run_exploits,
    "defacement": _run_defacement,
    "social":     _run_social,
    "api":        _run_api,
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
    from concurrent.futures import ThreadPoolExecutor
    
    targets = [selected] if selected else list(COLLECTORS)
    log.info(f"=== DarkPulse Orchestrator | collectors={targets} | proxy={cfg.tor_proxy_url or 'none'} ===")
    
    # Run all collectors in parallel to hit the 10k target as fast as possible
    with ThreadPoolExecutor(max_workers=len(targets)) as executor:
        executor.map(run_collector, targets)
        
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
