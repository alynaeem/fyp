import asyncio
from playwright.async_api import async_playwright
from api_collector.scripts._apk_mod import _apk_mod



PLAYSTORE_URL = "https://play.google.com/store/apps/details?id=com.supercell.clashofclans&hl=en"


async def main():
    crawler = _apk_mod()

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=False,   # debugging ke liye False
            slow_mo=50
        )
        context = await browser.new_context()

        print("[MAIN] Starting APK crawler …")
        print(f"[MAIN] URL: {PLAYSTORE_URL}")

        result = await crawler.parse_leak_data(
            query={"playstore": PLAYSTORE_URL},
            context=context
        )

        print("\n[MAIN] ===== RESULTS =====")
        for card in result.cards_data:
            print("----------------------------------")
            print("App Name      :", card.m_app_name)
            print("Package ID    :", card.m_package_id)
            print("Version       :", card.m_version)
            print("Updated       :", card.m_latest_date)
            print("Download URLs :", card.m_download_link)
            print("Source URL    :", card.m_app_url)

        await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
