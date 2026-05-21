import os
import json
import importlib
import traceback
from datetime import datetime
from config import cfg
from crawler.request_parser import RequestParser
from crawler.request_manager import init_services
from logger import get_logger

log = get_logger("leak_dump_runner")

DUMP_FILE = "leak_data_dump.json"
LEAK_DIR = "leak_collector/scripts/leak"
TOR_PROXY = {"server": "socks5://127.0.0.1:19050"}

def load_existing_data():
    if not os.path.exists(DUMP_FILE):
        return []
    try:
        with open(DUMP_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def save_data(data):
    with open(DUMP_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def get_leak_classes():
    classes = []
    for filename in os.listdir(LEAK_DIR):
        if filename.startswith("_") and filename.endswith(".py") and filename != "__init__.py":
            module_name = filename[:-3]
            try:
                # Import module
                # Path is leak_collector.scripts.leak._mod_name
                path = f"leak_collector.scripts.leak.{module_name}"
                module = importlib.import_module(path)
                
                # The class name is usually the same as the module name
                cls = getattr(module, module_name, None)
                if cls:
                    classes.append((module_name, cls))
            except Exception as e:
                print(f"Failed to import {module_name}: {e}")
    return classes

def run_collector(name, cls, proxy):
    print(f"▶ [{name}] Trying with proxy: {proxy}")
    try:
        model = cls()
        if hasattr(model, "set_proxy"):
            model.set_proxy(proxy or {})
        
        # Use a realistic User-Agent to bypass basic anti-bot
        parser = RequestParser(
            proxy=proxy, 
            model=model, 
            reset_cache=True,
            playwright_headless=True
        )
        result = parser.parse()
        
        items = result.get('data', [])
        print(f"  [{name}] Found {len(items)} items")
        return items
    except Exception as e:
        print(f"  [{name}] Error: {e}")
        return []

def main():
    init_services()
    classes = get_leak_classes()
    print(f"Discovered {len(classes)} collectors")
    
    existing_data = load_existing_data()
    # Build a set of seen URLs for deduplication
    seen_urls = set()
    for item in existing_data:
        val = item.get('url') or item.get('m_url')
        if val: seen_urls.add(val)
    
    new_total = 0
    
    for name, cls in classes:
        # 1. Try with Tor
        items = run_collector(name, cls, TOR_PROXY)
        
        # 2. If zero, try with Clearnet
        if not items:
            print(f"  [{name}] Zero items with Tor. Retrying with Clearnet...")
            items = run_collector(name, cls, None)
            
        if items:
            added_for_this_site = 0
            for item in items:
                # Use 'url' as primary since our dashboard expects it
                url = item.get('url') or item.get('m_url')
                if url and url not in seen_urls:
                    item['collected_at'] = datetime.now().isoformat()
                    item['source_name'] = name # Tag it with the collector name
                    
                    # Ensure url field is populated for UI
                    if 'url' not in item: item['url'] = url
                    
                    existing_data.append(item)
                    seen_urls.add(url)
                    added_for_this_site += 1
            
            new_total += added_for_this_site
            print(f"  [{name}] Added {added_for_this_site} new items to dump")
            # Save incrementally after each site
            save_data(existing_data)
            
    print(f"FINISHED. Total new items added: {new_total}. Grand total: {len(existing_data)}")

if __name__ == "__main__":
    main()
