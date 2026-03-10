from crawler.request_manager import check_services_status, init_services
from crawler.request_parser import RequestParser

from defacement_collector.scripts.generic._tweetfeed import _tweetfeed
from defacement_collector.scripts.generic._usom import _usom
from defacement_collector.scripts.hacks._defacer import _defacer
from defacement_collector.scripts.hacks._ownzyou import _ownzyou
from defacement_collector.scripts.hacks._zone_xsec import _zone_xsec
from defacement_collector.scripts.phishing._github_mthcht_awesome_lists import _github_mthcht_awesome_lists
from defacement_collector.scripts.phishing._github_openfish import _github_openfish
from defacement_collector.scripts.phishing._phishunt import _phishunt

check_services_status()

if __name__ == "__main__":
    init_services()

    parse_sample = _phishunt()
    result = RequestParser(
        proxy={"server": "socks5://127.0.0.1:9150"},
        model=parse_sample,
        reset_cache=True,
        seed_fetch = True,
    ).parse()

    print("\n========== RUN RESULT ==========")
    print(result)
