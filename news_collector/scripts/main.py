from crawler.request_manager import check_services_status, init_services
from crawler.request_parser import RequestParser

from news_collector.scripts._csocybercrime import _csocybercrime
from news_collector.scripts._hackread import _hackread
from news_collector.scripts._infosecuritymagazine import _infosecuritymagazine
from news_collector.scripts._krebsonsecurity import _krebsonsecurity
from news_collector.scripts._portswigger import _portswigger
from news_collector.scripts._thehackernews import _thehackernews
from news_collector.scripts._therecord import _therecord
from news_collector.scripts._bleepingcomputer import _bleepingcomputer

import json
import os
from datetime import datetime


print("[MAIN] Initializing crawler services ...")
init_services()
check_services_status()
print("[MAIN] Services ready ✅")


if __name__ == "__main__":
    print("[MAIN] Starting portswigger crawler ...")

    parse_sample = _thehackernews()
    parse_sample.set_limits(max_articles=3)
    parser = RequestParser(
        proxy={"server": "socks5://127.0.0.1:9150"},
        model=parse_sample,
        reset_cache=True
    )

    results = parser.parse()

    print("[MAIN] Crawl finished. Saving JSON output...")

    if results:
        output_dir = os.path.join(os.path.dirname(__file__), "output")
        os.makedirs(output_dir, exist_ok=True)

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(output_dir, f"news_output_{timestamp}.json")

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

        print(f"[MAIN] JSON saved at: {output_path}")
    else:
        print("[MAIN] No results returned from parser.")