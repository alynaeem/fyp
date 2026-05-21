import asyncio
import subprocess
import time
from motor.motor_asyncio import AsyncIOMotorClient
from config import cfg
from logger import get_logger

log = get_logger("agent_manager")

client = AsyncIOMotorClient(cfg.mongo_uri)
db = client[cfg.mongo_db]

# The Janitor will move items from these collections to clean_intel
SOURCE_COLLECTIONS = [
    "news_items",
    "leak_items",
    "exploit_items",
    "defacement_items",
    "social_items",
    "api_items",
    "github_scans",
    "apk_scans",
    "pcgame_scans",
]

clean_intel_col = db["clean_intel"]
agent_state = db["agent_state"]


async def get_last_processed(agent_name: str, source_col: str) -> str:
    """Get the last processed ObjectId or timestamp for a specific collection."""
    doc = await agent_state.find_one({"agent": agent_name, "source_col": source_col})
    return doc.get("last_id") if doc else None


async def update_last_processed(agent_name: str, source_col: str, last_id: str):
    await agent_state.update_one(
        {"agent": agent_name, "source_col": source_col},
        {"$set": {"last_id": last_id}},
        upsert=True
    )


import sys

async def the_scout():
    """
    The Scout runs periodically and aggregates data from multiple sources.
    It relies on orchestrator.py which already targets specific raw collections.
    """
    log.info("[Scout] Initialized. Monitoring sources...")
    while True:
        try:
            log.info("[Scout] Waking up to gather raw intelligence...")
            # We call orchestrator.py synchronously in a subprocess to reuse existing logic
            # This fetches the latest news, leaks, github repos, etc., and populates raw collections
            subprocess.run([sys.executable, "orchestrator.py", "--once"], check=False)
            log.info("[Scout] Gathering complete. Sleeping for 15 minutes.")
            await asyncio.sleep(900)
        except Exception as e:
            log.error(f"[Scout] Exception: {e}")
            await asyncio.sleep(60)


async def the_janitor():
    """
    The Janitor watches raw collections, cleans the payload, unifies the schema,
    and inserts it into the clean_intel collection.
    """
    log.info("[Janitor] Initialized. Awaiting raw intel...")
    while True:
        try:
            for col_name in SOURCE_COLLECTIONS:
                col = db[col_name]
                last_id = await get_last_processed("janitor", col_name)
                
                query = {}
                if last_id:
                    from bson import ObjectId
                    query = {"_id": {"$gt": ObjectId(last_id)}}
                
                cursor = col.find(query).sort("_id", 1).limit(50)
                items = await cursor.to_list(length=50)
                
                if not items:
                    continue
                
                cleaned_items = []
                latest_id = None
                
                for item in items:
                    latest_id = str(item["_id"])
                    
                    # 1. Unify ID
                    raw_id = str(item.pop("_id", ""))
                    
                    # 2. Extract standard fields safely based on source type
                    # For GitHub/APK/PCGame scans from api tab vs News/Leaks
                    title = (
                        item.get("title")
                        or item.get("m_title")
                        or item.get("app_name")
                        or item.get("m_app_name")
                        or item.get("repo_name")
                        or item.get("m_name")
                        or "Untitled"
                    )
                    url = (
                        item.get("url")
                        or item.get("m_url")
                        or item.get("m_app_url")
                        or item.get("m_message_sharable_link")
                        or item.get("m_channel_url")
                        or item.get("seed_url")
                        or item.get("html_url")
                        or ""
                    )
                    date = (
                        item.get("date")
                        or item.get("m_leak_date")
                        or item.get("m_message_date")
                        or item.get("m_latest_date")
                        or item.get("scraped_at")
                        or item.get("created_at")
                        or time.strftime("%Y-%m-%d")
                    )
                    
                    source_type = col_name.replace("_items", "").replace("_scans", "")
                    
                    cleaned_item = {
                        "raw_id": raw_id,
                        "source_collection": col_name,
                        "source_type": source_type,
                        "title": title,
                        "url": url,
                        "date": date,
                        "raw_payload": item,  # kept for context
                        "status": "pending_analysis"
                    }
                    cleaned_items.append(cleaned_item)
                
                if cleaned_items:
                    await clean_intel_col.insert_many(cleaned_items)
                    await update_last_processed("janitor", col_name, latest_id)
                    log.info(f"[Janitor] Cleaned {len(cleaned_items)} items from {col_name}.")
            
            await asyncio.sleep(10)  # Check for new items every 10 seconds
        except Exception as e:
            log.error(f"[Janitor] Exception: {e}")
            await asyncio.sleep(10)


intel_feed_col = db["intel_feed"]

async def the_analyst():
    """
    The Analyst watches the clean_intel collection for pending items,
    validates the evidence via Gemini 3 Flash, scores the impact,
    and publishes the final enriched intelligence to intel_feed.
    """
    # Wait to ensure google-genai is installed before importing if running too fast
    await asyncio.sleep(5)
    try:
        from google import genai
        from google.genai import types
        import os
        
        # We assume the user has set GEMINI_API_KEY in their environment or .env
        api_key = os.environ.get("GEMINI_API_KEY", "")
        if not api_key:
            log.warning("[Analyst] GEMINI_API_KEY missing. The Analyst will run in bypass mode.")
            bypass_mode = True
        else:
            client = genai.Client(api_key=api_key)
            bypass_mode = False
            
    except ImportError:
        log.error("[Analyst] google-genai not installed. Running in bypass mode.")
        bypass_mode = True

    log.info("[Analyst] Initialized. Awaiting clean intel...")
    while True:
        try:
            # Find 10 pending analysis items
            cursor = clean_intel_col.find({"status": "pending_analysis"}).limit(10)
            items = await cursor.to_list(length=10)
            
            if not items:
                await asyncio.sleep(5)
                continue
                
            for item in items:
                title = item.get("title", "")
                url = item.get("url", "")
                source_type = item.get("source_type", "unknown")
                raw_payload = item.get("raw_payload", {})
                
                impact_score = 0
                is_fake = False
                threat_actors = []
                
                if not bypass_mode:
                    prompt = f"""
                    You are a cybersecurity intelligence analyst evaluating crawled threat data.
                    Evaluate the following intercepted threat data for Impact on a scale of 0 to 100.
                    Also assess the probability that this is a 'Fake Leak' or misinformation.
                    Extract any handles, emails, or threat actors mentioned.
                    
                    Source Type: {source_type}
                    Title/Snippet: {title}
                    URL: {url}
                    Payload summary: {str(raw_payload)[:1000]}
                    
                    Return ONLY a JSON object in this exact format:
                    {{
                        "impact_score": <int 0-100>,
                        "is_fake": <bool>,
                        "threat_actors": ["<string>", ...],
                        "summary": "<string, a concise 1-sentence analysis>"
                    }}
                    """
                    
                    try:
                        # Call Gemini to score the item using loop.run_in_executor to avoid blocking
                        loop = asyncio.get_running_loop()
                        def call_gemini():
                            response = client.models.generate_content(
                                model='gemini-2.5-flash',
                                contents=prompt,
                                config=types.GenerateContentConfig(
                                    temperature=0.1,
                                    response_mime_type="application/json"
                                )
                            )
                            return response.text
                            
                        result_text = await loop.run_in_executor(None, call_gemini)
                        import json
                        analysis = json.loads(result_text)
                        
                        impact_score = analysis.get("impact_score", 0)
                        is_fake = analysis.get("is_fake", False)
                        threat_actors = analysis.get("threat_actors", [])
                        ai_summary = analysis.get("summary", "")
                    except Exception as ai_e:
                        log.error(f"[Analyst] AI evaluation failed for item {item.get('_id')}: {ai_e}")
                        ai_summary = "AI Evaluation Failed."
                else:
                    impact_score = 50
                    ai_summary = "Bypass mode active. AI scoring skipped."

                from identity_engine import enrich_threat_actors
                if threat_actors:
                    threat_actor_profiles = await enrich_threat_actors(threat_actors)
                else:
                    threat_actor_profiles = []

                enriched_item = item.copy()
                enriched_item["status"] = "analyzed"
                enriched_item["impact_score"] = impact_score
                enriched_item["is_fake"] = is_fake
                enriched_item["threat_actors"] = threat_actor_profiles
                enriched_item["ai_summary"] = ai_summary
                
                # Copy the original _id from source object as raw_id if possible
                del enriched_item["_id"]
                
                # Insert into final feed
                await intel_feed_col.insert_one(enriched_item)
                
                # Mark as analyzed in clean_intel
                await clean_intel_col.update_one({"_id": item["_id"]}, {"$set": {"status": "analyzed"}})
                
                log.info(f"[Analyst] Evaluated node '{title[:30]}...' -> Impact: {impact_score}")
                
            await asyncio.sleep(2)
        except Exception as e:
            log.error(f"[Analyst] Exception: {e}")
            await asyncio.sleep(5)


async def main():
    log.info("Starting DarkPulse 2.0 Agent Manager...")
    await asyncio.gather(
        the_scout(),
        the_janitor(),
        the_analyst()
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Agent Manager stopped.")
