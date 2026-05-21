import json
import hashlib
from config import cfg
from leak_collector.scripts.leak._ransomware_live import _ransomware_live
from crawler.request_parser import RequestParser
from crawler.request_manager import init_services
from logger import get_logger

log = get_logger("ransom_only")

def main():
    init_services()
    proxy = cfg.proxy
    name = "ransomware_live"
    cls = _ransomware_live
    
    print(f"▶ Starting standalone collector: {name}")
    try:
        model = cls()
        if hasattr(model, "set_proxy"):
            model.set_proxy(proxy or {})
        
        # Use RequestParser to handle the Playwright execution
        # Ensure it's not called inside an asyncio loop
        result = RequestParser(proxy=proxy, model=model, reset_cache=True).parse()
        
        count = result.get('meta', {}).get('count', 0)
        print(f"  [{name}] parse_count={count}")
        
        # Persist to MongoDB using the orchestrator's helper
        from orchestrator import _persist_model_data
        db_stats = _persist_model_data("leak", name, model, parsed_data=result.get('data'))
        
        print(f"✔ Finished {name}")
        print(f"  raw_items={db_stats['raw_items']} raw_entities={db_stats['raw_entities']}")
        
    except Exception as e:
        print(f"✘ Collector failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
