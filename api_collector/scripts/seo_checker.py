import json, requests, time

API = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
API_KEY = "AIzaSyDYnYVADHyEE8lYpOTXf0f838CIDwSyRzg"

URLS = {
    "HackerNews": "https://thehackernews.com/",
    "Google": "https://www.google.com/",
    "GitHub": "https://github.com/",
    "Fraktalia": "https://fraktalia-studios.com/"
}

def pagespeed_seo(target_url, api_key, strategy="mobile"):
    try:
        r = requests.get(API, params={
            "url": target_url,
            "key": api_key,
            "strategy": strategy,
            "category": "seo"
        }, timeout=60)
        if r.status_code != 200:
            return {"url": target_url, "error": f"HTTP {r.status_code}", "response": r.text[:200]}

        d = r.json()
        lh = d.get("lighthouseResult", {})
        seo = lh.get("categories", {}).get("seo", {})
        ids = [a["id"] for a in seo.get("auditRefs", [])]
        audits = lh.get("audits", {})

        return {
            "url": lh.get("finalUrl"),
            "seoScore": seo.get("score"),
            "audits": {
                i: {
                    "score": audits.get(i, {}).get("score"),
                    "title": audits.get(i, {}).get("title"),
                    "description": audits.get(i, {}).get("description"),
                } for i in ids
            }
        }
    except Exception as e:
        return {"url": target_url, "error": str(e)}

def main():
    results = {}
    for name, url in URLS.items():
        data = pagespeed_seo(url, API_KEY)
        results[name] = data

    with open("seo_report.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    main()
