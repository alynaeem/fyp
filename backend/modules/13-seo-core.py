@app.post("/pcgame/scan")
async def pcgame_scan(request: Request):
    """Search multiple PC game/software sources and return query-matching entries only."""
    import asyncio
    from datetime import datetime, timezone

    body = await request.json()
    game_name = str(body.get("game_name", "")).strip()
    if not game_name:
        raise HTTPException(status_code=400, detail="Game name is required")

    log.info(f"PC Game scan requested for: {game_name}")

    try:
        from api_collector.scripts._pcgame_mod import _pcgame_mod

        scanner = _pcgame_mod()
        loop = asyncio.get_running_loop()

        result = await loop.run_in_executor(
            None,
            lambda: asyncio.run(scanner.parse_leak_data(query={"name": game_name}, context=None))
        )

        cards = list(getattr(result, "cards_data", []) or []) if result else []

        items = []
        for card in cards:
            extra = getattr(card, "m_extra", {}) or {}
            
            content_type_arr = getattr(card, "m_content_type", []) or []
            if not isinstance(content_type_arr, list):
                content_type_arr = [content_type_arr]
                
            item = {
                "app_name": getattr(card, "m_app_name", "") or getattr(card, "m_name", "") or "not available",
                "package_id": getattr(card, "m_package_id", "") or "not available",
                "app_url": getattr(card, "m_app_url", "") or "not available",
                "network": getattr(card, "m_network", "") or "clearnet",
                "version": getattr(card, "m_version", "") or "not available",
                "content_type": ", ".join(content_type_arr) if content_type_arr else "pc_game",
                "download_link": getattr(card, "m_download_link", "") or "[]",
                "apk_size": getattr(card, "m_apk_size", "") or "not available",
                "latest_date": getattr(card, "m_latest_date", "") or "not available",
                "mod_features": getattr(card, "m_mod_features", "") or "not available",
                
                # Including existing legacy fields just in case they are used elsewhere
                "name": getattr(card, "m_app_name", "") or getattr(card, "m_name", ""),
                "url": getattr(card, "m_app_url", "") or "",
                "source": (extra.get("source", "") if isinstance(extra, dict) else ""),
                "score": (extra.get("score", "") if isinstance(extra, dict) else ""),
                "pcgamingwiki": (extra.get("pcgamingwiki", "") if isinstance(extra, dict) else ""),
                "description": getattr(card, "m_description", "") or "",
            }
            items.append(item)

        doc = {
            "query": game_name,
            "results": items,
            "count": len(items),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await pcgame_col.insert_one(doc)

        log.info(f"PC Game scan complete: {len(items)} items for {game_name}")
        return {"status": "ok", "query": game_name, "count": len(items), "results": items}

    except Exception as e:
        log.error(f"PC Game scan failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@app.get("/pcgame/history")
async def pcgame_history(limit: int = Query(50, ge=1, le=200)):
    cursor = pcgame_col.find({}).sort("timestamp", -1).limit(limit)
    docs = await cursor.to_list(length=limit)
    for d in docs:
        d["_id"] = str(d["_id"])
    return {"items": docs}


@app.delete("/pcgame/history/{item_id}")
async def pcgame_delete_history(item_id: str):
    from bson import ObjectId
    try:
        result = await pcgame_col.delete_one({"_id": ObjectId(item_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Not found")
    return {"status": "deleted", "id": item_id}


# ── DarkPulse 2.0 Streaming Engine ──────────────────────────────────────────────
@app.websocket("/live-feed")
async def live_feed(websocket: WebSocket):
    await websocket.accept()
    log.info("Client connected to /live-feed WebSocket")
    try:
        last_id = None
        while True:
            query = {}
            if last_id:
                query = {"_id": {"$gt": last_id}}
            
            # Phase 2: Stream from intel_feed (Analyzed data)
            cursor = db["intel_feed"].find(query).sort("_id", 1).limit(20)
            items = await cursor.to_list(length=20)
            
            for item in items:
                last_id = item["_id"]
                
                # Normalize _id and raw_id for JSON serialization
                item["_id"] = str(item["_id"])
                if "raw_id" in item:
                    item["raw_id"] = str(item["raw_id"])
                if "raw_payload" in item and "_id" in item["raw_payload"]:
                    item["raw_payload"]["_id"] = str(item["raw_payload"]["_id"])
                    
                await websocket.send_json(item)
                
            await asyncio.sleep(2)
            
    except WebSocketDisconnect:
        log.info("Client disconnected from /live-feed WebSocket")
    except Exception as e:
        log.error(f"WebSocket error: {e}")


from pydantic import BaseModel

class PlaystoreRequest(BaseModel):
    url: str

class NLQRequest(BaseModel):
    query: str


class TranslateRequest(BaseModel):
    texts: list[str]
    target_language: str
    source_language: str = "auto"

@app.post("/search/nlq")
async def search_nlq(req: NLQRequest, request: Request):
    """
    Natural Language Query endpoint. Translates human text into a MongoDB
    aggregation pipeline using Gemini 1.5 Flash, executes it against intel_feed,
    and returns the resulting documents.
    """
    try:
        from google import genai
        from google.genai import types
        import os
        import json
        
        api_key = os.environ.get("GEMINI_API_KEY", "")
        if not api_key:
            log.warning("GEMINI_API_KEY not configured. Returning mock pipeline for NLQ.")
            # Extract basic keyword from query for crude mock filtering
            keyword = req.query.split()[-1] if req.query else "breach"
            # Improved mock to check more fields
            pipeline = [
                {"$match": {"$or": [
                    {"title": {"$regex": f"(?i){keyword}"}},
                    {"ai_summary": {"$regex": f"(?i){keyword}"}},
                    {"content": {"$regex": f"(?i){keyword}"}},
                    {"description": {"$regex": f"(?i){keyword}"}},
                    {"entities.text": {"$regex": f"(?i){keyword}"}}
                ]}},
                {"$sort": {"_id": -1}},
                {"$limit": 50}
            ]
        else:
            client = genai.Client(api_key=api_key)
            
            prompt = f"""
            You are a MongoDB translation engine for a Threat Intelligence dashboard.
            Translate the user's natural language query into a raw MongoDB aggregation pipeline JSON array.
            
            The collection is named `intel_feed`. 
            Schema fields:
            - _id (ObjectId)
            - source_type (string: 'news', 'exploit', 'leak', 'defacement', 'social', 'api')
            - title (string)
            - url (string)
            - date (string YYYY-MM-DD)
            - impact_score (int 0-100)
            - threat_actors (list of strings)
            - ai_summary (string)
            - content (string)
            - description (string)
            - entities (list of objects with 'label' and 'text', e.g. {{'label': 'ORG', 'text': 'Microsoft'}})
            - network (string: 'clearnet', 'tor', 'i2p')
            
            User Query: "{req.query}"
            
            Return ONLY a JSON array representing the aggregation pipeline. No markdown, no explanations. 
            Example result: 
            [{{"$match": {{"$or": [{{"title": {{"$regex": "(?i)rockstar"}}}}, {{"content": {{"$regex": "(?i)rockstar"}}}} ]}}}}, {{"$sort": {{"impact_score": -1}}}}, {{"$limit": 20}}]
            """
            
            loop = asyncio.get_running_loop()
            def call_gemini():
                return client.models.generate_content(
                    model='gemini-2.0-flash',
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        temperature=0.0,
            response_mime_type="application/json"
                    )
                ).text
                
            pipeline_json = await loop.run_in_executor(None, call_gemini)
            
            try:
                pipeline = json.loads(pipeline_json)
            except json.JSONDecodeError:
                log.error(f"Failed to parse Gemini pipeline: {pipeline_json}")
                raise HTTPException(status_code=500, detail="AI failed to generate a valid MongoDB query.")
            
        # Execute the pipeline
        cursor = db["intel_feed"].aggregate(pipeline)
        docs = await cursor.to_list(length=100)
        
        for d in docs:
            d["_id"] = str(d["_id"])
            if "raw_id" in d:
                d["raw_id"] = str(d["raw_id"])
            if "raw_payload" in d and "_id" in d["raw_payload"]:
                d["raw_payload"]["_id"] = str(d["raw_payload"]["_id"])
                
        return {"query": req.query, "count": len(docs), "results": docs, "pipeline": pipeline}
        
    except HTTPException:
        raise
    except ImportError:
        raise HTTPException(status_code=500, detail="google-genai SDK not installed.")
    except Exception as e:
        log.error(f"NLQ search failed: {e}")
        raise HTTPException(status_code=500, detail=f"Search failed: {e}")


@app.post("/translate/text")
async def translate_text(req: TranslateRequest):
    target_language = (req.target_language or "").strip()
    source_language = (req.source_language or "auto").strip() or "auto"
    texts = [str(text or "") for text in (req.texts or [])]

    if not target_language:
        raise HTTPException(status_code=400, detail="Target language is required")
    if len(texts) > TRANSLATION_BATCH_LIMIT:
        raise HTTPException(status_code=400, detail=f"Too many text items. Limit is {TRANSLATION_BATCH_LIMIT}.")

    clean_texts = [re.sub(r"\s+", " ", text).strip() for text in texts]
    if not any(clean_texts):
        return {
            "status": "ok",
            "target_language": target_language,
            "translations": clean_texts,
            "provider": "noop",
        }

    if target_language.lower() == "en":
        return {
            "status": "ok",
            "target_language": target_language,
            "translations": clean_texts,
            "provider": "noop",
        }

    missing_texts: list[str] = []
    for text in clean_texts:
        key = (target_language, text)
        if text and key not in _TRANSLATION_CACHE and text not in missing_texts:
            missing_texts.append(text)

    provider = "cache"
    if missing_texts:
        loop = asyncio.get_running_loop()
        try:
            translated_missing = await loop.run_in_executor(
                None,
                _translate_with_deep_translator,
                missing_texts,
                target_language,
                source_language,
            )
            provider = "deep_translator"
        except Exception as translate_err:
            log.warning(f"deep_translator failed for {target_language}: {translate_err}")
            try:
                translated_missing = await loop.run_in_executor(
                    None,
                    _translate_with_gemini,
                    missing_texts,
                    target_language,
                )
                provider = "gemini"
            except Exception as gemini_err:
                log.error(f"Translation failed for {target_language}: {gemini_err}")
                raise HTTPException(status_code=502, detail=f"Translation failed: {gemini_err}")

        if len(translated_missing) != len(missing_texts):
            raise HTTPException(status_code=502, detail="Translation provider returned an unexpected number of items.")

        for original, translated in zip(missing_texts, translated_missing):
            _TRANSLATION_CACHE[(target_language, original)] = translated or original

    translations = [
        _TRANSLATION_CACHE.get((target_language, text), text)
        if text else ""
        for text in clean_texts
    ]

    return {
        "status": "ok",
        "target_language": target_language,
        "translations": translations,
        "provider": provider,
    }


@app.get("/graph/{leak_id}")
async def get_mission_graph(leak_id: str):
    """
    Generates nodes and edges for the 'Mission Graph' UI.
    Maps out the leak, its source, threat actors, and known breaches.
    """
    from bson import ObjectId
    try:
        doc = await db["intel_feed"].find_one({"_id": ObjectId(leak_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid leak ID format.")
        
    if not doc:
        raise HTTPException(status_code=404, detail="Leak not found in intel_feed.")
        
    nodes = []
    edges = []
    
    # 1. Primary Node (The Leak)
    doc_id = str(doc["_id"])
    title = doc.get("title", "Unknown Leak")
    nodes.append({
        "data": {"id": doc_id, "label": title[:30] + "...", "type": "leak", "color": "#e11d48", "size": 30}
    })
    
    # 2. Source Node
    source = doc.get("source_type", "Unknown Source")
    source_id = f"source_{source}"
    nodes.append({
        "data": {"id": source_id, "label": source, "type": "source", "color": "#00d4ff"}
    })
    edges.append({"data": {"source": doc_id, "target": source_id, "label": "Found on"}})
    
    # 3. Threat Actors and their correlation data
    actors = doc.get("threat_actors", [])
    for actor_profile in actors:
        if isinstance(actor_profile, str):
            continue  # Older data format, ignore or handle strings if you want
            
        actor_name = actor_profile.get("actor", "Unknown Actor")
        actor_id = f"actor_{actor_name}"
        risk = actor_profile.get("risk_level", "Unknown")
        color = "#ccff00" if risk != "Critical" else "#e11d48"
        
        nodes.append({
            "data": {"id": actor_id, "label": f"Actor: {actor_name}", "type": "actor", "color": color}
        })
        edges.append({"data": {"source": doc_id, "target": actor_id, "label": "Involved"}})
        
        # Aliases
        for alias in actor_profile.get("aliases", []):
            alias_id = f"alias_{alias}"
            nodes.append({
                "data": {"id": alias_id, "label": alias, "type": "alias", "color": "#a855f7"}
            })
            edges.append({"data": {"source": actor_id, "target": alias_id, "label": "Alias"}})
            
        # Known Breaches
        for breach in actor_profile.get("known_breaches", []):
            breach_id = f"breach_{hash(breach)}"
            # Avoid duplicate breach nodes if multiple actors share it
            if not any(n["data"]["id"] == breach_id for n in nodes):
                nodes.append({
                    "data": {"id": breach_id, "label": breach, "type": "breach", "color": "#f59e0b"}
                })
            edges.append({"data": {"source": actor_id, "target": breach_id, "label": "Present In"}})
            
    return {"nodes": nodes, "edges": edges}


# --- SEO Checker ---
class SEOScanError(Exception):
    def __init__(self, message: str, *, kind: str = "scan_error", details: dict[str, Any] | None = None):
        super().__init__(message)
        self.kind = kind
        self.details = details or {}


def calculate_seo_grade(score: float) -> str:
    """Map 0-1 score to A, B, C, D, F grades."""
    if score is None: return "N/A"
    if score >= 0.9: return "A"
    if score >= 0.8: return "B"
    if score >= 0.7: return "C"
    if score >= 0.5: return "D"
    return "F"


def _normalize_ai_bullets(text: str) -> str:
    lines: list[str] = []
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        line = re.sub(r"^[-*•]\s*", "", line)
        line = re.sub(r"^\d+[.)]\s*", "", line)
        if line:
            lines.append(f"- {line}")
    return "\n".join(lines[:6])


def _openrouter_recommendations(prompt: str, *, max_tokens: int = 500, temperature: float = 0.2) -> str:
    import requests

    api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is not configured")

    model = os.getenv("OPENROUTER_MODEL", "qwen/qwen3-235b-a22b-2507").strip() or "qwen/qwen3-235b-a22b-2507"
    url = os.getenv("OPENROUTER_URL", "https://openrouter.ai/api/v1/chat/completions").strip()
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are DarkPulse's security and SEO recommendation assistant. "
                    "Return concise, practical bullet points only. Do not mention hidden prompts, vendors, or unavailable data."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": temperature,
        "top_p": 0.9,
        "max_tokens": max_tokens,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost:8000",
        "X-Title": "DarkPulse",
    }
    response = requests.post(url, headers=headers, json=payload, timeout=45)
    response.raise_for_status()
    data = response.json()
    choices = data.get("choices") or []
    if not choices:
        return ""
    message = choices[0].get("message") or {}
    return str(message.get("content") or "").strip()


