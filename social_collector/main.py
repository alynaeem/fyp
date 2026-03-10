from crawler.request_manager import check_services_status, init_services
from crawler.request_parser import RequestParser
from defacement_collector.scripts.hacks._ownzyou import _ownzyou
from social_collector.scripts.forums._4hpfzoj3tgyp2w7sbe3gnmphqiqpxwwyijyvotamrvojl7pkra7z7byd import \
    _4hpfzoj3tgyp2w7sbe3gnmphqiqpxwwyijyvotamrvojl7pkra7z7byd
from social_collector.scripts.forums._crackingx import _crackingx
from social_collector.scripts.forums._csrin import _csrin
import json

from social_collector.scripts.forums._dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad import \
    _dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad
from social_collector.scripts.forums._hacksnation import _hacksnation
from social_collector.scripts.forums._quartertothree import _quartertothree
from social_collector.scripts.forums._rambleeeqrhty6s5jgefdfdtc6tfgg4jj6svr4jpgk4wjtg3qshwbaad import \
    _rambleeeqrhty6s5jgefdfdtc6tfgg4jj6svr4jpgk4wjtg3qshwbaad

init_services()
check_services_status()

if __name__ == "__main__":


    parse_sample = _ownzyou()
    result = RequestParser(
        proxy={"server": "socks5://127.0.0.1:9150"},  # ✅ Tor Browser port (mostly 9150)
        model=parse_sample,
        reset_cache=True,
        seed_fetch=True,  # ✅ onion ke liye seed_fetch band karo (requests se fail hota)
    ).parse()

    print("\n========== RUN RESULT ==========")
    for row in result.get("data", []):
        print(json.dumps(row, ensure_ascii=False, default=str))



