from __future__ import annotations

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

os.environ.setdefault("TOR_PROXY_URL", "socks5://127.0.0.1:19050")
os.environ.setdefault("MONGO_URI", "mongodb://127.0.0.1:27017")
os.environ.setdefault("MONGO_DB", "darkpulse")

from crawler.request_manager import init_services
from crawler.request_parser import RequestParser
from orchestrator import _persist_model_data

from leak_collector.scripts.leak._5butbkrljkaorg5maepuca25oma7eiwo6a2rlhvkblb4v6mf3ki2ovid import _5butbkrljkaorg5maepuca25oma7eiwo6a2rlhvkblb4v6mf3ki2ovid
from leak_collector.scripts.leak._black3gnkizshuynieigw6ejgpblb53mpasftzd6pydqpmq2vn2xf6yd import _black3gnkizshuynieigw6ejgpblb53mpasftzd6pydqpmq2vn2xf6yd
from leak_collector.scripts.leak._csidb import _csidb
from leak_collector.scripts.leak._fjg4zi4opkxkvdz7mvwp7h6goe4tcby3hhkrz43pht4j3vakhy75znyd import _fjg4zi4opkxkvdz7mvwp7h6goe4tcby3hhkrz43pht4j3vakhy75znyd
from leak_collector.scripts.leak._hptqq2o2qjva7lcaaq67w36jihzivkaitkexorauw7b2yul2z6zozpqd import _hptqq2o2qjva7lcaaq67w36jihzivkaitkexorauw7b2yul2z6zozpqd
from leak_collector.scripts.leak._ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd import _ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd
from leak_collector.scripts.leak._incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad import _incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad
from leak_collector.scripts.leak._rhysidafohrhyy2aszi7bm32tnjat5xri65fopcxkdfxhi4tidsg7cad import _rhysidafohrhyy2aszi7bm32tnjat5xri65fopcxkdfxhi4tidsg7cad
from leak_collector.scripts.leak._safepaypfxntwixwjrlcscft433ggemlhgkkdupi2ynhtcmvdgubmoyd import _safepaypfxntwixwjrlcscft433ggemlhgkkdupi2ynhtcmvdgubmoyd
from leak_collector.scripts.leak._securo45z554mw7rgrt7wcgv5eenj2xmxyrsdj3fcjsvindu63s4bsid import _securo45z554mw7rgrt7wcgv5eenj2xmxyrsdj3fcjsvindu63s4bsid
from leak_collector.scripts.leak._yzcpwxuhbkyjnyn4qsf4o5dkvu6m2fyo7dwizmnlutanlmzlos7pa6qd import _yzcpwxuhbkyjnyn4qsf4o5dkvu6m2fyo7dwizmnlutanlmzlos7pa6qd


COLLECTORS = [
    ("fivebutb", _5butbkrljkaorg5maepuca25oma7eiwo6a2rlhvkblb4v6mf3ki2ovid),
    ("black3g", _black3gnkizshuynieigw6ejgpblb53mpasftzd6pydqpmq2vn2xf6yd),
    ("csidb", _csidb),
    ("fjg4zi", _fjg4zi4opkxkvdz7mvwp7h6goe4tcby3hhkrz43pht4j3vakhy75znyd),
    ("hptqq2", _hptqq2o2qjva7lcaaq67w36jihzivkaitkexorauw7b2yul2z6zozpqd),
    ("ijzn3sic", _ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd),
    ("incblog", _incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad),
    ("rhysida", _rhysidafohrhyy2aszi7bm32tnjat5xri65fopcxkdfxhi4tidsg7cad),
    ("safepay", _safepaypfxntwixwjrlcscft433ggemlhgkkdupi2ynhtcmvdgubmoyd),
    ("securo", _securo45z554mw7rgrt7wcgv5eenj2xmxyrsdj3fcjsvindu63s4bsid),
    ("yzcpwx", _yzcpwxuhbkyjnyn4qsf4o5dkvu6m2fyo7dwizmnlutanlmzlos7pa6qd),
]


def main() -> int:
    init_services()
    proxy_url = os.environ.get("TOR_PROXY_URL", "").strip()
    proxy = {"server": proxy_url} if proxy_url else None

    print(f"[selected-snapshots] starting {len(COLLECTORS)} collectors")
    for name, cls in COLLECTORS:
        try:
            model = cls()
            if hasattr(model, "set_proxy"):
                model.set_proxy(proxy or {})
            result = RequestParser(proxy=proxy, model=model, reset_cache=True).parse()
            count = (result or {}).get("meta", {}).get("count", 0)
            db_stats = _persist_model_data("leak", name, model, parsed_data=(result or {}).get("data"))
            print(
                f"[selected-snapshots] {name}: parse_count={count} "
                f"raw_items={db_stats['raw_items']} raw_entities={db_stats['raw_entities']} "
                f"legacy_kv={db_stats['legacy_kv']}"
            )
        except Exception as exc:
            print(f"[selected-snapshots] {name}: failed -> {exc}")
    print("[selected-snapshots] complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
