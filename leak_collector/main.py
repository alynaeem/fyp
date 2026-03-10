import json
from crawler.request_manager import check_services_status, init_services
from crawler.request_parser import RequestParser
from leak_collector.scripts.leak._akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad import \
    _akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad
from leak_collector.scripts.tracking._public_tableau import _public_tableau

print("[MAIN] Initializing crawler services ...")
init_services()
check_services_status()
print("[MAIN] Services ready ✅")


if __name__ == "__main__":
    # ---- example: run ACN tracking crawler ----
    print("[MAIN] Starting ACN crawler ...")

    # ⭐ crawler ka instance banao

    parse_sample = _akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad()
    parse_sample.set_proxy({"server": "socks5://127.0.0.1:9150"})
    # ⭐ RequestParser ko yeh instance model ke taur pe do
    RequestParser(
        proxy=None,
        model=parse_sample,
        reset_cache=True
    ).parse()

    # optional debug prints


    print(json.dumps([c.to_dict() for c in parse_sample.card_data], ensure_ascii=False, indent=2))
    print(json.dumps([e.__dict__ for e in parse_sample.entity_data], ensure_ascii=False, indent=2))

