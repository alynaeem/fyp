import asyncio

from crawler.request_manager import check_services_status, init_services
from api_collector.scripts._pcgame_mod import _pcgame_mod

print("[MAIN] Initializing crawler services ...")
init_services()
check_services_status()
print("[MAIN] Services ready ✅")


async def main():
    model = _pcgame_mod()

    game_name = "GTA V"  # ✅ only change this
    query = {"name": game_name}

    print(f"[MAIN] Starting pcgame_mod API collector ... | query={game_name}")

    result = await model.parse_leak_data(query=query, context=None)

    if result is None:
        print("[MAIN] ❌ No result returned")
        return

    cards = getattr(result, "cards_data", []) or []
    print(f"[MAIN] ✅ Done. Items collected = {len(cards)}")

    for i, c in enumerate(cards[:10], 1):
        name = getattr(c, "m_app_name", "")
        url = getattr(c, "m_app_url", "")
        extra = getattr(c, "m_extra", {}) or {}
        source = extra.get("source", "") if isinstance(extra, dict) else ""
        score = extra.get("score", "") if isinstance(extra, dict) else ""
        pcgw = extra.get("pcgamingwiki", "") if isinstance(extra, dict) else ""
        print(f"[{i}] {name} | {url} | {source} | score={score} | pcgw={pcgw}")


if __name__ == "__main__":
    asyncio.run(main())
