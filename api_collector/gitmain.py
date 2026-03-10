import asyncio
import os

from crawler.request_manager import check_services_status, init_services
from api_collector.scripts.github_trivy_checker import github_trivy_checker  # adjust import

print("[MAIN] Initializing crawler services ...")
init_services()
check_services_status()
print("[MAIN] Services ready ✅")

async def main():
    model = github_trivy_checker()

    repo = "https://github.com/OWASP/NodeGoat"

    # ✅ set token from env (recommended)
    token = os.getenv("GITHUB_TOKEN", "")

    query = {
        "github": "https://github.com/OWASP/NodeGoat",
        "git_token": os.getenv("GITHUB_TOKEN"),  # token env var me rakho
        "timeout": 900,
        "print_details": True,
        "max_vulns_print": 80,
        "max_secrets_print": 30,
        "keep_workdir": False
    }

    print(f"[MAIN] Starting github_trivy_checker ... | repo={repo}")

    result = await model.parse_leak_data(query=query, context=None)

    raw = getattr(result, "raw_data", {}) or {}
    cards = getattr(result, "cards_data", []) or []
    print(f"[MAIN] ✅ Done. Items collected = {len(cards)}")
    print("[MAIN] raw keys:", list(raw.keys())[:50])

if __name__ == "__main__":
    asyncio.run(main())
