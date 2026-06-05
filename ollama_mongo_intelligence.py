"""
ollama_mongo_intelligence.py

Schema-agnostic MongoDB search + local Ollama summarization for DarkPulse.

This module is intentionally defensive:
- Mongo documents in DarkPulse can come from many collectors and vary widely.
- Local llama3.1 on 16GB RAM needs strict prompt/context limits.
- Ollama may not be running, so connection errors are returned cleanly.

Usage:
    python ollama_mongo_intelligence.py "Show me leaks about Iran"
    python ollama_mongo_intelligence.py "Show me leaks about Iran" --collection redis_kv_store
"""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Iterable, Iterator
import sys

import requests
from bson import ObjectId
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.errors import OperationFailure, PyMongoError

from config import cfg


COMMON_TEXT_FIELDS = (
    "title",
    "summary",
    "description",
    "content",
    "payload",
    "data",
    "body",
    "text",
    "value",
    "raw",
    "message",
    "url",
    "source",
    "source_name",
)

SYSTEM_FIELD_NAMES = {
    "_id",
    "__v",
    "_class",
    "_search_blob",
    "embedding",
    "embeddings",
    "vector",
    "vectors",
    "image",
    "images",
    "screenshot",
    "screenshots",
    "html",
    "raw_html",
    "m_ref_html",
    "binary",
    "blob",
}

BINARY_TYPES = (bytes, bytearray, memoryview)
MAX_FIELD_CHARS = 2_000
MAX_CONTEXT_WORDS = int(os.getenv("OLLAMA_MAX_CONTEXT_WORDS", "1000"))
DEFAULT_LIMIT = int(os.getenv("OLLAMA_QUERY_LIMIT", "8"))
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
OLLAMA_FALLBACK_MODELS = (
    "dolphin-llama3:latest",
    "llama3.2:latest",
    "dolphin-mistral:latest",
)
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "").strip()
OPENROUTER_URL = os.getenv("OPENROUTER_URL", "https://openrouter.ai/api/v1/chat/completions")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "qwen/qwen3-235b-a22b-2507")
AI_PROVIDER = os.getenv("AI_PROVIDER", "openrouter" if OPENROUTER_API_KEY else "ollama").strip().lower()


@dataclass
class SearchResult:
    query: str
    collection: str
    count: int
    context_word_count: int
    answer: str
    documents: list[dict[str, Any]]


def _clean_key(key: Any) -> str:
    text = str(key).strip().replace("_", " ")
    return re.sub(r"\s+", " ", text).title()


def _safe_string(value: Any, max_chars: int = MAX_FIELD_CHARS) -> str:
    """Convert arbitrary Mongo values into compact, readable text."""
    if value is None:
        return ""
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, BINARY_TYPES):
        return "[Binary content omitted]"
    if isinstance(value, (dict, list, tuple)):
        try:
            text = json.dumps(value, ensure_ascii=False, default=str)
        except TypeError:
            text = str(value)
    else:
        text = str(value)

    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_chars:
        return text[:max_chars].rstrip() + " ... [truncated]"
    return text


def flatten_mongo_document(
    document: dict[str, Any],
    *,
    parent_key: str = "",
    max_depth: int = 6,
    current_depth: int = 0,
) -> str:
    """
    Recursively flatten any MongoDB document into human-readable lines.

    The flattener skips system/binary fields and truncates large values so a
    single oversized document cannot consume the full local LLM context.
    """
    lines: list[str] = []

    if current_depth > max_depth:
        return ""

    for key, value in (document or {}).items():
        key_text = str(key)
        if key_text in SYSTEM_FIELD_NAMES or key_text.startswith("__"):
            continue

        label = f"{parent_key}.{_clean_key(key_text)}" if parent_key else _clean_key(key_text)

        if isinstance(value, BINARY_TYPES):
            continue

        if isinstance(value, dict):
            nested = flatten_mongo_document(
                value,
                parent_key=label,
                max_depth=max_depth,
                current_depth=current_depth + 1,
            )
            if nested:
                lines.append(nested)
            continue

        if isinstance(value, list):
            if not value:
                continue
            primitive_items = []
            complex_items = []
            for item in value[:20]:
                if isinstance(item, dict):
                    nested = flatten_mongo_document(
                        item,
                        parent_key=label,
                        max_depth=max_depth,
                        current_depth=current_depth + 1,
                    )
                    if nested:
                        complex_items.append(nested)
                elif not isinstance(item, BINARY_TYPES):
                    primitive_items.append(_safe_string(item, max_chars=400))

            if primitive_items:
                lines.append(f"{label}: {', '.join(x for x in primitive_items if x)}")
            if complex_items:
                lines.extend(complex_items)
            if len(value) > 20:
                lines.append(f"{label}: ... [{len(value) - 20} additional list items omitted]")
            continue

        text = _safe_string(value)
        if text:
            lines.append(f"{label}: {text}")

    return "\n".join(lines)


def _keywords_from_query(query: str) -> list[str]:
    words = re.findall(r"[A-Za-z0-9_@./:-]{3,}", query.lower())
    stopwords = {
        "show",
        "about",
        "with",
        "from",
        "that",
        "this",
        "please",
        "find",
        "give",
        "tell",
        "data",
        "records",
    }
    return [word for word in words if word not in stopwords][:8]


# NOTE: we DO NOT dynamically call list_indexes() on every execution because
# that introduces a measurable latency overhead. Assume the $text index exists.
# If the index is missing, a PyMongo OperationFailure will be raised and we
# fallback to regex search. This keeps runtime fast while still defensive.


def _fallback_regex_query(query: str) -> dict[str, Any]:
    keywords = _keywords_from_query(query)
    if not keywords:
        keywords = [query.strip()]

    field_clauses = []
    for keyword in keywords:
        escaped = re.escape(keyword)
        field_clauses.extend(
            {field: {"$regex": escaped, "$options": "i"}}
            for field in COMMON_TEXT_FIELDS
        )

    return {"$or": field_clauses} if field_clauses else {}


def search_mongo_documents(
    collection: Collection,
    user_query: str,
    *,
    limit: int = DEFAULT_LIMIT,
) -> list[dict[str, Any]]:
    """
    Search Mongo using $text when available, otherwise use bounded regex search
    across common textual fields. The regex fallback is intentionally limited to
    common fields instead of scanning every nested key dynamically, because that
    would be too expensive on large local collections.
    """
    projection = None

    search_str = " ".join(_keywords_from_query(user_query))
    if not search_str:
        search_str = user_query

    # Try $text search first (fast when index exists). Do NOT call
    # list_indexes() here to avoid the per-call overhead — instead rely on
    # the DB to have the index; on failure we fall back to regex.
    try:
        cursor = (
            collection.find(
                {"$text": {"$search": search_str}},
                {"score": {"$meta": "textScore"}},
            )
            .sort([("score", {"$meta": "textScore"})])
            .limit(limit)
        )
        docs = list(cursor)
        if docs:
            return docs
    except (OperationFailure, PyMongoError):
        # Text search failed (likely missing text index or other issue).
        # Fall back to bounded regex search across common fields.
        pass

    query_doc = _fallback_regex_query(user_query)
    try:
        return list(collection.find(query_doc, projection).limit(limit))
    except PyMongoError:
        return []


def build_bounded_context(
    documents: Iterable[dict[str, Any]],
    *,
    max_words: int = MAX_CONTEXT_WORDS,
) -> tuple[str, list[dict[str, Any]], int]:
    """Flatten docs and keep only the first N words across the aggregate context."""
    context_parts: list[str] = []
    included_docs: list[dict[str, Any]] = []
    used_words = 0

    for index, doc in enumerate(documents, start=1):
        flattened = flatten_mongo_document(doc)
        if not flattened:
            continue

        words = flattened.split()
        remaining = max_words - used_words
        if remaining <= 0:
            break

        if len(words) > remaining:
            flattened = " ".join(words[:remaining]) + " ... [context budget reached]"
            words = flattened.split()

        context_parts.append(f"--- Document {index} ---\n{flattened}")
        included_docs.append(_source_reference_from_doc(doc, flattened))
        used_words += len(words)

    return "\n\n".join(context_parts), included_docs, used_words


def _source_reference_from_doc(doc: dict[str, Any], preview: str) -> dict[str, Any]:
    doc_id = str(doc.get("_id", ""))
    reference: dict[str, Any] = {
        "_id": doc_id,
        "preview": preview[:500],
    }

    raw_match = re.match(r"^[A-Z0-9_]+:raw:([^:]+):([^:]+)", doc_id)
    if raw_match:
        aid, field = raw_match.groups()
        reference["aid"] = aid
        reference["field"] = field
        reference["open_label"] = "Open full article"
        return reference

    if doc_id.startswith(("EXPLOIT_ITEMS:", "LEAK_ITEMS:", "DEFACEMENT_ITEMS:", "SOCIAL_ITEMS:", "API_ITEMS:")):
        reference["aid"] = doc_id
        reference["field"] = "record"
        reference["open_label"] = "Open full record"
        return reference

    aid = doc.get("aid") or doc.get("dedupe_key")
    if aid:
        reference["aid"] = str(aid)
        reference["field"] = "record"
        reference["open_label"] = "Open full article"

    return reference


def _ollama_tags_url(ollama_url: str) -> str:
    return ollama_url.rsplit("/", 2)[0] + "/api/tags"


def _installed_ollama_models(ollama_url: str, timeout: int = 10) -> list[str]:
    try:
        response = requests.get(_ollama_tags_url(ollama_url), timeout=timeout)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException:
        return []
    except ValueError:
        return []
    return [
        item.get("name") or item.get("model")
        for item in data.get("models", [])
        if item.get("name") or item.get("model")
    ]


def _fallback_model_for_ollama(ollama_url: str, preferred_model: str) -> str:
    installed = _installed_ollama_models(ollama_url)
    if preferred_model in installed:
        return preferred_model
    for model in OLLAMA_FALLBACK_MODELS:
        if model in installed:
            return model
    return installed[0] if installed else preferred_model


def _chat_system_prompt() -> str:
    return (
        "You are DarkPulse's defensive OSINT summarization assistant. "
        "The operator is authorized to analyze locally stored security records. "
        "Use only the database context provided. Be objective and concise. "
        "Do not invent names, dates, counts, countries, sources, or conclusions. "
        "If a value is missing, say 'Not Specified'. "
        "If the context is weak or incomplete, say so explicitly. "
        "Return exactly four readable sections with these headings: "
        "Summary, Key Findings, Relevant Records, Missing Values. "
        "Use short bullet points under Key Findings, Relevant Records, and Missing Values. "
        "Do not write one long paragraph."
    )


def _chat_user_prompt(user_query: str, context: str) -> str:
    return (
        f"User query: {user_query}\n\n"
        f"Database context:\n{context}\n\n"
        "Synthesize the answer now."
    )


def _iter_utf8_lines(response: requests.Response) -> Iterator[str]:
    for raw_line in response.iter_lines(decode_unicode=False):
        if raw_line:
            yield raw_line.decode("utf-8", errors="replace")


def _strip_think_tags(chunks: Iterator[str]) -> Iterator[str]:
    """Filter out Qwen-3 <think>…</think> reasoning blocks from a token stream.

    The tags may span multiple chunks, so we track an ``inside_think`` flag
    and buffer partial tag sequences that straddle chunk boundaries.
    """
    inside_think = False
    buf = ""

    for chunk in chunks:
        buf += chunk
        while buf:
            if inside_think:
                end_pos = buf.find("</think>")
                if end_pos == -1:
                    # Still inside <think>; discard everything buffered so far
                    buf = ""
                    break
                # Skip past the closing tag
                buf = buf[end_pos + len("</think>"):]
                inside_think = False
                # Strip the leading newlines that Qwen usually adds after </think>
                buf = buf.lstrip("\n")
            else:
                start_pos = buf.find("<think>")
                if start_pos == -1:
                    # No opening tag – check if a partial "<think" sits at the end
                    # so we don't emit it prematurely.
                    safe_end = len(buf)
                    for i in range(1, min(len("<think>"), len(buf)) + 1):
                        if "<think>".startswith(buf[-i:]):
                            safe_end = len(buf) - i
                            break
                    if safe_end > 0:
                        yield buf[:safe_end]
                    buf = buf[safe_end:]
                    break
                else:
                    # Emit everything before the tag, then enter think mode
                    if start_pos > 0:
                        yield buf[:start_pos]
                    buf = buf[start_pos + len("<think>"):]
                    inside_think = True

    # Flush any remaining buffer (shouldn't contain partial tags in practice)
    if buf and not inside_think:
        yield buf


def call_openrouter(
    user_query: str,
    context: str,
    *,
    model: str = OPENROUTER_MODEL,
    openrouter_url: str = OPENROUTER_URL,
    api_key: str = OPENROUTER_API_KEY,
    timeout: int = 240,
) -> Iterator[str]:
    """Stream OpenRouter chat completions as incremental text chunks."""
    if not api_key:
        yield "OpenRouter is not configured. Set OPENROUTER_API_KEY in .env and restart the server."
        return

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": _chat_system_prompt()},
            {"role": "user", "content": _chat_user_prompt(user_query, context)},
        ],
        "temperature": 0.1,
        "top_p": 0.9,
        "max_tokens": 700,
        "stream": True,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost:8000",
        "X-Title": "DarkPulse",
    }

    def _raw_chunks() -> Iterator[str]:
        """Inner generator that yields raw delta content from the SSE stream."""
        with requests.post(
            openrouter_url,
            headers=headers,
            json=payload,
            timeout=timeout,
            stream=True,
        ) as resp:
            resp.raise_for_status()

            for raw_line in _iter_utf8_lines(resp):
                if not raw_line:
                    continue
                line = raw_line.strip()
                if line.startswith("data:"):
                    line = line[5:].strip()
                if not line or line == "[DONE]":
                    continue

                try:
                    data = json.loads(line)
                except ValueError:
                    continue

                choices = data.get("choices") or []
                if not choices:
                    continue

                delta = choices[0].get("delta") or {}
                chunk = delta.get("content")
                if chunk:
                    yield chunk

    emitted = False
    try:
        for chunk in _strip_think_tags(_raw_chunks()):
            emitted = True
            yield chunk
    except requests.exceptions.Timeout:
        yield "OpenRouter request timed out. Reduce the query scope or try again."
        return
    except requests.RequestException as exc:
        response = getattr(exc, "response", None)
        detail = ""
        if response is not None:
            try:
                error_payload = response.json()
                detail = (
                    error_payload.get("error", {}).get("message")
                    if isinstance(error_payload.get("error"), dict)
                    else error_payload.get("error")
                ) or json.dumps(error_payload, ensure_ascii=False)
            except ValueError:
                detail = response.text.strip()
        suffix = f" Details: {detail}" if detail else ""
        yield f"OpenRouter request failed for model '{model}': {exc}.{suffix}"
        return

    if not emitted:
        yield "OpenRouter returned an empty response."


def call_ollama(
    user_query: str,
    context: str,
    *,
    model: str = OLLAMA_MODEL,
    ollama_url: str = OLLAMA_URL,
    timeout: int = 240,
) -> Iterator[str]:
    """Stream local Ollama responses as incremental text chunks."""
    prompt = f"{_chat_system_prompt()}\n\n{_chat_user_prompt(user_query, context)}"

    selected_model = _fallback_model_for_ollama(ollama_url, model)
    payload = {
        "model": selected_model,
        "prompt": prompt,
        "stream": True,
        "options": {
            "temperature": 0.1,
            "top_p": 0.9,
            "num_ctx": 4096,
            "num_predict": 512,
        },
    }

    if selected_model != model:
        yield f"Model fallback: requested '{model}', used installed model '{selected_model}'.\n\n"

    emitted = False
    try:
        with requests.post(ollama_url, json=payload, timeout=timeout, stream=True) as response:
            response.raise_for_status()

            for raw_line in response.iter_lines(decode_unicode=True):
                if not raw_line:
                    continue
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except ValueError:
                    continue

                chunk = data.get("response")
                if chunk:
                    emitted = True
                    yield chunk

                if data.get("done"):
                    break
    except requests.exceptions.ConnectionError:
        yield f"Ollama is not reachable at {ollama_url}. Start Ollama and pull llama3.1:8b first."
        return
    except requests.exceptions.Timeout:
        yield "Ollama request timed out. Reduce the query scope or confirm the local model is responsive."
        return
    except requests.RequestException as exc:
        response = getattr(exc, "response", None)
        detail = ""
        if response is not None:
            try:
                payload = response.json()
                detail = payload.get("error") or json.dumps(payload, ensure_ascii=False)
            except ValueError:
                detail = response.text.strip()
        suffix = f" Details: {detail}" if detail else ""
        yield f"Ollama request failed for model '{selected_model}': {exc}.{suffix}"
        return

    if not emitted:
        yield "Ollama returned an empty response."


def call_chat_model(user_query: str, context: str, *, model: str = OLLAMA_MODEL) -> Iterator[str]:
    if AI_PROVIDER == "openrouter":
        yield from call_openrouter(user_query, context, model=OPENROUTER_MODEL)
        return
    if AI_PROVIDER == "ollama":
        yield from call_ollama(user_query, context, model=model)
        return
    if OPENROUTER_API_KEY:
        yield from call_openrouter(user_query, context, model=OPENROUTER_MODEL)
        return
    yield from call_ollama(user_query, context, model=model)


def _general_chat_system_prompt() -> str:
    return (
        "You are DarkPulse AI, a concise assistant inside a defensive OSINT dashboard. "
        "For normal conversation, answer naturally and briefly. "
        "If the user asks what you can do, explain that you can search local DarkPulse records "
        "for threats, leaks, CVEs, domains, actors, malware, ransomware, and source evidence. "
        "Do not pretend you searched the database unless database context is provided. "
        "Keep the answer under four sentences."
    )


def call_openrouter_general_chat(
    user_query: str,
    *,
    model: str = OPENROUTER_MODEL,
    openrouter_url: str = OPENROUTER_URL,
    api_key: str = OPENROUTER_API_KEY,
    timeout: int = 90,
) -> Iterator[str]:
    if not api_key:
        yield "I can chat normally and search local DarkPulse records, but OpenRouter is not configured right now."
        return

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": _general_chat_system_prompt()},
            {"role": "user", "content": user_query},
        ],
        "temperature": 0.4,
        "top_p": 0.9,
        "max_tokens": 220,
        "stream": True,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost:8000",
        "X-Title": "DarkPulse",
    }

    def _raw_chunks() -> Iterator[str]:
        with requests.post(
            openrouter_url,
            headers=headers,
            json=payload,
            timeout=timeout,
            stream=True,
        ) as resp:
            resp.raise_for_status()
            for raw_line in _iter_utf8_lines(resp):
                if not raw_line:
                    continue
                line = raw_line.strip()
                if line.startswith("data:"):
                    line = line[5:].strip()
                if not line or line == "[DONE]":
                    continue
                try:
                    data = json.loads(line)
                except ValueError:
                    continue
                choices = data.get("choices") or []
                if not choices:
                    continue
                chunk = (choices[0].get("delta") or {}).get("content")
                if chunk:
                    yield chunk

    emitted = False
    try:
        for chunk in _strip_think_tags(_raw_chunks()):
            emitted = True
            yield chunk
    except requests.exceptions.Timeout:
        yield "I am here, but the model took too long to answer. Try again in a moment."
        return
    except requests.RequestException:
        yield "I am here, but the chat model is temporarily unavailable. You can still ask a specific intelligence search query."
        return

    if not emitted:
        yield "I am here. Ask me about DarkPulse records, threats, leaks, CVEs, actors, or domains."


def call_general_chat_model(user_query: str) -> Iterator[str]:
    if OPENROUTER_API_KEY and AI_PROVIDER != "ollama":
        yield from call_openrouter_general_chat(user_query)
        return
    # Local fallback keeps general chat working if OpenRouter is disabled.
    prompt = f"{_general_chat_system_prompt()}\n\nUser: {user_query}\nAssistant:"
    selected_model = _fallback_model_for_ollama(OLLAMA_URL, OLLAMA_MODEL)
    payload = {
        "model": selected_model,
        "prompt": prompt,
        "stream": True,
        "options": {"temperature": 0.4, "top_p": 0.9, "num_predict": 220},
    }
    try:
        with requests.post(OLLAMA_URL, json=payload, timeout=90, stream=True) as response:
            response.raise_for_status()
            for raw_line in response.iter_lines(decode_unicode=True):
                if not raw_line:
                    continue
                try:
                    data = json.loads(raw_line.strip())
                except ValueError:
                    continue
                chunk = data.get("response")
                if chunk:
                    yield chunk
                if data.get("done"):
                    break
    except requests.RequestException:
        yield "I am here. Ask me about local DarkPulse records, threats, leaks, CVEs, actors, or domains."


def _is_general_chat_query(user_query: str) -> bool:
    text = re.sub(r"[^\w\s']", " ", str(user_query or "").lower())
    compact_text = re.sub(r"\s+", " ", text).strip()
    words = [word for word in text.split() if word]
    if not words:
        return True

    greeting_words = {"hi", "hello", "hey", "salam", "assalamualaikum", "yo"}
    thanks_words = {"thanks", "thank", "thankyou", "thx"}
    help_words = {"help", "commands"}
    capability_phrases = {
        "what can you do",
        "what else can you do",
        "what do you do",
        "what are your capabilities",
        "show me your capabilities",
        "tell me what you can do",
        "who are you",
        "what are you",
        "tell me about yourself",
        "introduce yourself",
    }
    wellbeing_phrases = {
        "how are you",
        "how r you",
        "how are u",
        "how do you do",
        "how is it going",
        "how's it going",
        "whats up",
        "what's up",
        "sup",
    }

    if len(words) <= 3 and any(word in greeting_words for word in words):
        return True
    if compact_text in wellbeing_phrases or (len(words) <= 5 and compact_text.startswith("how are you")):
        return True
    if compact_text in capability_phrases:
        return True
    if len(words) <= 8 and (
        compact_text.startswith("what can you")
        or compact_text.startswith("what else can you")
        or compact_text.startswith("what do you do")
        or compact_text.startswith("who are you")
        or compact_text.startswith("what are you")
    ):
        return True
    if len(words) <= 4 and any(word in thanks_words for word in words):
        return True
    if len(words) <= 3 and any(word in help_words for word in words):
        return True
    return False


def stream_query_from_mongo(
    user_query: str,
    *,
    mongo_uri: str = cfg.mongo_uri,
    database_name: str = cfg.mongo_db,
    collection_name: str = "redis_kv_store",
    limit: int = DEFAULT_LIMIT,
    max_context_words: int = MAX_CONTEXT_WORDS,
    model: str = OLLAMA_MODEL,
) -> Iterator[str | dict]:
    """
    Yields a dictionary with database metadata first, 
    then yields the string chunks of the LLM response.
    """
    if _is_general_chat_query(user_query):
        yield {
            "status": "general_chat",
            "collection": collection_name,
            "count": 0,
            "context_word_count": 0,
            "documents": [],
        }
        yield from call_general_chat_model(user_query)
        return

    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
    collection = client[database_name][collection_name]

    try:
        docs = search_mongo_documents(collection, user_query, limit=limit)
    except PyMongoError as exc:
        yield {"status": "error", "message": f"MongoDB search failed: {exc}"}
        return
    finally:
        client.close()

    if not docs:
        yield {"status": "empty", "message": "No matching data found in database."}
        return

    context, included_docs, word_count = build_bounded_context(docs, max_words=max_context_words)
    if not context.strip():
        yield {"status": "empty", "message": "No usable text fields found in database documents."}
        return

    # 1. Yield the metadata payload first so the UI can render sources immediately
    yield {
        "status": "success",
        "collection": collection_name,
        "count": len(docs),
        "context_word_count": word_count,
        "documents": included_docs,
    }

    # 2. Yield the actual text stream
    yield from call_chat_model(user_query, context, model=model)

def main() -> int:
    parser = argparse.ArgumentParser(description="Search MongoDB and summarize results with local Ollama.")
    parser.add_argument("query", help="Natural language query, e.g. 'Show me leaks about Iran'")
    parser.add_argument("--collection", default="redis_kv_store", help="MongoDB collection to search")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="Maximum MongoDB documents to retrieve")
    parser.add_argument("--max-words", type=int, default=MAX_CONTEXT_WORDS, help="Maximum context words sent to Ollama")
    parser.add_argument("--model", default=OLLAMA_MODEL, help="Ollama model name")
    args = parser.parse_args()

    client = MongoClient(cfg.mongo_uri, serverSelectionTimeoutMS=5000)
    collection = client[cfg.mongo_db][args.collection]

    try:
        docs = search_mongo_documents(collection, args.query, limit=args.limit)
    except PyMongoError as exc:
        sys.stdout.write(f"MongoDB search failed: {exc}\n")
        sys.stdout.flush()
        return 1
    finally:
        client.close()

    if not docs:
        sys.stdout.write("No matching data found in database.\n")
        sys.stdout.flush()
        return 0

    context, _, word_count = build_bounded_context(docs, max_words=args.max_words)
    if not context.strip():
        sys.stdout.write("No usable text fields found in matching database documents.\n")
        sys.stdout.flush()
        return 0

    sys.stdout.write(
        f"Collection: {args.collection}\n"
        f"Matched docs: {len(docs)}\n"
        f"Context words: {word_count}\n"
        "Answer:\n"
    )
    sys.stdout.flush()

    for chunk in call_chat_model(args.query, context, model=args.model):
        sys.stdout.write(chunk)
        sys.stdout.flush()

    sys.stdout.write("\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
