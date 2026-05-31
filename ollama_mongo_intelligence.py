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
from typing import Any, Iterable

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
MAX_CONTEXT_WORDS = 6_000
DEFAULT_LIMIT = 25
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
OLLAMA_FALLBACK_MODELS = (
    "dolphin-llama3:latest",
    "llama3.2:latest",
    "dolphin-mistral:latest",
)


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


def _has_text_index(collection: Collection) -> bool:
    try:
        for index in collection.list_indexes():
            key_spec = dict(index.get("key", {}))
            if "text" in key_spec.values():
                return True
    except PyMongoError:
        return False
    return False


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

    if _has_text_index(collection):
        try:
            cursor = (
                collection.find(
                    {"$text": {"$search": user_query}},
                    {"score": {"$meta": "textScore"}},
                )
                .sort([("score", {"$meta": "textScore"})])
                .limit(limit)
            )
            docs = list(cursor)
            if docs:
                return docs
        except OperationFailure:
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


def call_ollama(
    user_query: str,
    context: str,
    *,
    model: str = OLLAMA_MODEL,
    ollama_url: str = OLLAMA_URL,
    timeout: int = 180,
) -> str:
    """Call local Ollama using raw requests to avoid adding dependencies."""
    system_prompt = (
        "You are DarkPulse's local defensive OSINT summarization assistant. "
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
    prompt = (
        f"{system_prompt}\n\n"
        f"User query: {user_query}\n\n"
        f"Database context:\n{context}\n\n"
        "Synthesize the answer now."
    )

    selected_model = _fallback_model_for_ollama(ollama_url, model)
    payload = {
        "model": selected_model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "top_p": 0.9,
            "num_ctx": 8192,
        },
    }

    try:
        response = requests.post(ollama_url, json=payload, timeout=timeout)
        response.raise_for_status()
    except requests.exceptions.ConnectionError:
        return "Ollama is not reachable at http://localhost:11434. Start Ollama and pull llama3.1:8b first."
    except requests.exceptions.Timeout:
        return "Ollama request timed out. Reduce the query scope or confirm the local model is responsive."
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
        return f"Ollama request failed for model '{selected_model}': {exc}.{suffix}"

    try:
        data = response.json()
    except ValueError:
        return "Ollama returned a non-JSON response."

    answer = (data.get("response") or "").strip() or "Ollama returned an empty response."
    if selected_model != model:
        return f"Model fallback: requested '{model}', used installed model '{selected_model}'.\n\n{answer}"
    return answer


def answer_query_from_mongo(
    user_query: str,
    *,
    mongo_uri: str = cfg.mongo_uri,
    database_name: str = cfg.mongo_db,
    collection_name: str = "redis_kv_store",
    limit: int = DEFAULT_LIMIT,
    max_context_words: int = MAX_CONTEXT_WORDS,
    model: str = OLLAMA_MODEL,
) -> SearchResult:
    """End-to-end entry point for app integration."""
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
    collection = client[database_name][collection_name]

    try:
        docs = search_mongo_documents(collection, user_query, limit=limit)
    except PyMongoError as exc:
        return SearchResult(
            query=user_query,
            collection=collection_name,
            count=0,
            context_word_count=0,
            answer=f"MongoDB search failed: {exc}",
            documents=[],
        )
    finally:
        client.close()

    if not docs:
        return SearchResult(
            query=user_query,
            collection=collection_name,
            count=0,
            context_word_count=0,
            answer="No matching data found in database.",
            documents=[],
        )

    context, included_docs, word_count = build_bounded_context(docs, max_words=max_context_words)
    if not context.strip():
        return SearchResult(
            query=user_query,
            collection=collection_name,
            count=len(docs),
            context_word_count=0,
            answer="No usable text fields found in matching database documents.",
            documents=[],
        )

    answer = call_ollama(user_query, context, model=model)
    return SearchResult(
        query=user_query,
        collection=collection_name,
        count=len(docs),
        context_word_count=word_count,
        answer=answer,
        documents=included_docs,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Search MongoDB and summarize results with local Ollama.")
    parser.add_argument("query", help="Natural language query, e.g. 'Show me leaks about Iran'")
    parser.add_argument("--collection", default="redis_kv_store", help="MongoDB collection to search")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="Maximum MongoDB documents to retrieve")
    parser.add_argument("--max-words", type=int, default=MAX_CONTEXT_WORDS, help="Maximum context words sent to Ollama")
    parser.add_argument("--model", default=OLLAMA_MODEL, help="Ollama model name")
    args = parser.parse_args()

    result = answer_query_from_mongo(
        args.query,
        collection_name=args.collection,
        limit=args.limit,
        max_context_words=args.max_words,
        model=args.model,
    )
    print(json.dumps(result.__dict__, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
