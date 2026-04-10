import asyncio
import os
import sys

# Add current dir to path to find crawler and api_collector
sys.path.append(os.getcwd())

from api_collector.scripts.github_trivy_checker import github_trivy_checker

async def main():
    scanner = github_trivy_checker()
    repo_url = "https://github.com/juice-shop/juice-shop"
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if not token:
        print("Warning: GITHUB_TOKEN is not set. Private repositories may fail to scan.")
    print(f"Scanning {repo_url} with environment-based token...")
    result = await scanner.parse_leak_data(query={"github": repo_url, "token": token}, context=None)
    print("Result raw_data keys:", result.raw_data.keys() if hasattr(result, 'raw_data') else "No raw_data")
    if hasattr(result, 'raw_data') and 'error' in result.raw_data:
        print("Error detected:", result.raw_data['error'])
    else:
        print("Success or unknown state")

if __name__ == "__main__":
    asyncio.run(main())
