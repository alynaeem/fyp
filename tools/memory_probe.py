#!/usr/bin/env python3
import asyncio
import resource
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def rss_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


async def main() -> None:
    import ui_server

    print(f"rss_after_import_mb={rss_mb():.1f}")
    news = await ui_server._fetch_news_items(include_raw=False)
    print(f"news_items={len(news)} rss_after_news_mb={rss_mb():.1f}")
    threats = await ui_server._fetch_threat_items(include_raw=False)
    print(f"threat_items={len(threats)} rss_after_threats_mb={rss_mb():.1f}")
    combined = await ui_server._fetch_combined_feed_items(include_raw=False)
    print(f"combined_items={len(combined)} rss_after_combined_mb={rss_mb():.1f}")
    print(f"feed_cache_keys={list(ui_server._FEED_ITEMS_CACHE.keys())}")


if __name__ == "__main__":
    asyncio.run(main())
