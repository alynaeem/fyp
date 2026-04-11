from __future__ import annotations

import hashlib
import json
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

KNOWN_STEALER_FILENAMES = {
    "odoostealerlogs.json",
    "bhariastealerlogs.json",
}
ALLOWED_DATASET_SUFFIXES = {".json", ".jsonl", ".ndjson"}
MAX_RENDERED_RESULTS = 500
_DATASET_CACHE: dict[tuple[str, int, int], list[dict[str, Any]]] = {}

HOST_KEYS = {
    "domain",
    "host",
    "hostname",
    "site",
    "website",
    "target",
    "target_domain",
    "app_domain",
    "service_domain",
}
SOURCE_DOMAIN_KEYS = {
    "source_domain",
    "domain_host",
    "host",
    "hostname",
    "site",
}
URL_KEYS = {
    "url",
    "uri",
    "link",
    "website_url",
    "app_url",
    "source_url",
    "raw_trace",
    "trace",
    "combo",
}
IDENTIFIER_KEYS = {
    "credential_identifier",
    "identifier",
    "email",
    "email_address",
    "mail",
    "login",
    "username",
    "user",
    "user_name",
    "account",
}
PASSWORD_KEYS = {"password", "pass", "passwd", "secret"}
IP_KEYS = {"ip", "ip_address", "ipv4", "ipv6"}
DATE_KEYS = {
    "date",
    "created_at",
    "updated_at",
    "timestamp",
    "last_seen",
    "first_seen",
    "collected_at",
}
YEAR_KEYS = {"year", "month", "period"}
CHANNEL_KEYS = {"channel", "source", "provider", "collection", "cloud", "vendor"}
FILE_TYPE_KEYS = {"file_type", "format", "type", "extension"}
FILE_NAME_KEYS = {"file_name", "filename", "source_file", "artifact"}
RAW_TRACE_KEYS = {
    "raw_trace",
    "trace",
    "raw",
    "combo",
    "line",
    "record",
    "payload",
    "url",
    "uri",
}
CONTAINER_KEYS = {"items", "results", "records", "logs", "entries", "data", "hits"}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def credential_data_dir() -> Path:
    configured = os.getenv("CREDENTIAL_DATA_DIR", "").strip()
    data_dir = Path(configured).expanduser() if configured else (_repo_root() / "data" / "credential_checker")
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def credential_data_roots() -> list[Path]:
    roots: list[Path] = []
    configured = os.getenv("CREDENTIAL_DATA_DIR", "").strip()
    if configured:
        roots.append(Path(configured).expanduser())

    roots.extend([
        _repo_root() / "data" / "credential_checker",
        Path("/app/data/credential_checker"),
    ])

    unique_roots: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        candidate = root.expanduser()
        resolved = str(candidate.resolve())
        if resolved in seen:
            continue
        try:
            if candidate.exists():
                if not candidate.is_dir():
                    continue
            else:
                candidate.mkdir(parents=True, exist_ok=True)
        except OSError:
            continue

        seen.add(resolved)
        unique_roots.append(candidate)
    return unique_roots


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _normalized_key(value: Any) -> str:
    text = _normalize_text(value).lower()
    return re.sub(r"[^a-z0-9]+", "_", text).strip("_")


def _is_dataset_file(path: Path) -> bool:
    name = path.name.lower()
    if not path.is_file():
        return False
    if path.suffix.lower() not in ALLOWED_DATASET_SUFFIXES:
        return False
    return "stealer" in name or name in KNOWN_STEALER_FILENAMES


def discover_credential_files() -> list[Path]:
    root = _repo_root()
    candidates: dict[Path, Path] = {}
    search_roots = [
        *credential_data_roots(),
        root,
        root / "data",
        root / "api_collector",
    ]

    for base in search_roots:
        if not base.exists():
            continue
        iterator = base.rglob("*") if base == credential_data_dir() else base.glob("*")
        for path in iterator:
            if base == credential_data_dir():
                if path.is_file() and path.suffix.lower() in ALLOWED_DATASET_SUFFIXES:
                    candidates[path.resolve()] = path.resolve()
                    continue
            if _is_dataset_file(path):
                candidates[path.resolve()] = path.resolve()

    for file_name in KNOWN_STEALER_FILENAMES:
        for base in search_roots:
            path = base / file_name
            if path.exists() and path.is_file():
                candidates[path.resolve()] = path.resolve()

    return sorted(candidates.values(), key=lambda item: item.name.lower())


def dataset_inventory() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for path in discover_credential_files():
        stat = path.stat()
        items.append({
            "name": path.name,
            "size_bytes": stat.st_size,
            "modified_at": datetime.utcfromtimestamp(stat.st_mtime).isoformat() + "Z",
            "path": str(path),
        })
    return items


def _coerce_scalar(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value).strip()
    if isinstance(value, list):
        for item in value:
            text = _coerce_scalar(item)
            if text:
                return text
    if isinstance(value, dict):
        for nested in value.values():
            text = _coerce_scalar(nested)
            if text:
                return text
    return ""


def _collect_matching_values(value: Any, keys: set[str]) -> list[Any]:
    matches: list[Any] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            if _normalized_key(key) in keys:
                matches.append(nested)
            matches.extend(_collect_matching_values(nested, keys))
    elif isinstance(value, list):
        for nested in value:
            matches.extend(_collect_matching_values(nested, keys))
    return matches


def _first_value(value: Any, keys: set[str]) -> str:
    for match in _collect_matching_values(value, keys):
        text = _coerce_scalar(match)
        if text:
            return text
    return ""


def _find_email(value: Any) -> str:
    blob = json.dumps(value, ensure_ascii=False, default=str)
    match = re.search(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", blob, re.IGNORECASE)
    return match.group(0) if match else ""


def _find_url(value: Any) -> str:
    for candidate in _collect_matching_values(value, URL_KEYS):
        text = _coerce_scalar(candidate)
        if text.startswith(("http://", "https://")):
            return text
    blob = json.dumps(value, ensure_ascii=False, default=str)
    match = re.search(r"https?://[^\s\"'>]+", blob, re.IGNORECASE)
    return match.group(0) if match else ""


def _safe_source_url(value: Any) -> str:
    raw_url = _find_url(value)
    if not raw_url:
        return "-"
    parsed = urlparse(raw_url)
    if parsed.scheme and parsed.hostname:
        return f"{parsed.scheme}://{parsed.hostname}"
    return parsed.hostname or "-"


def _extract_host(record: dict[str, Any], identifier: str = "") -> str:
    host = _first_value(record, HOST_KEYS | SOURCE_DOMAIN_KEYS)
    if host and "." in host:
        return host.lower()

    url_value = _find_url(record)
    if url_value:
        parsed = urlparse(url_value)
        if parsed.hostname:
            return parsed.hostname.lower()

    if "@" in identifier:
        return identifier.split("@", 1)[1].lower()

    raw_trace = _first_value(record, RAW_TRACE_KEYS)
    if raw_trace:
        url_like = raw_trace if raw_trace.startswith(("http://", "https://")) else f"https://{raw_trace}"
        parsed = urlparse(url_like)
        if parsed.hostname:
            return parsed.hostname.lower()
    return ""


def _looks_like_record(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    keys = {_normalized_key(key) for key in value.keys()}
    interesting = (
        HOST_KEYS
        | SOURCE_DOMAIN_KEYS
        | URL_KEYS
        | IDENTIFIER_KEYS
        | PASSWORD_KEYS
        | IP_KEYS
        | DATE_KEYS
        | YEAR_KEYS
        | CHANNEL_KEYS
        | FILE_TYPE_KEYS
        | FILE_NAME_KEYS
        | RAW_TRACE_KEYS
    )
    if keys & interesting:
        return True
    blob = json.dumps(value, ensure_ascii=False, default=str)
    return bool(re.search(r"@[A-Z0-9.\-]+\.[A-Z]{2,}", blob, re.IGNORECASE))


def _iter_records(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, list):
        for item in value:
            yield from _iter_records(item)
        return

    if isinstance(value, dict):
        if _looks_like_record(value):
            yield value
        for key, nested in value.items():
            if _normalized_key(key) in CONTAINER_KEYS or isinstance(nested, (dict, list)):
                yield from _iter_records(nested)


def _cache_key(path: Path) -> tuple[str, int, int]:
    stat = path.stat()
    return (str(path.resolve()), stat.st_mtime_ns, stat.st_size)


def _load_dataset_records(path: Path) -> list[dict[str, Any]]:
    key = _cache_key(path)
    cached = _DATASET_CACHE.get(key)
    if cached is not None:
        return cached

    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        records: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                records.extend(_iter_records(item))
    else:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            payload = json.load(handle)
        records = list(_iter_records(payload))

    _DATASET_CACHE[key] = records
    return records


def _mask_email(value: str) -> str:
    if not value or "@" not in value:
        return _mask_token(value)
    local_part, domain_part = value.split("@", 1)
    if not local_part:
        return f"***@{domain_part}"
    if len(local_part) <= 2:
        return f"{local_part[:1]}***@{domain_part}"
    return f"{local_part[:2]}***{local_part[-1:]}@{domain_part}"


def _mask_token(value: str) -> str:
    value = _normalize_text(value)
    if not value or value == "-":
        return "-"
    if "@" in value:
        return _mask_email(value)
    if len(value) <= 4:
        return value[:1] + "***"
    return f"{value[:2]}***{value[-1:]}"


def _mask_ip(value: str) -> str:
    value = _normalize_text(value)
    if not value:
        return "-"
    if "." in value:
        parts = value.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.x.x"
    if ":" in value:
        parts = value.split(":")
        return ":".join(parts[:2] + ["x", "x"])
    return "-"


def _format_date(value: Any) -> str:
    text = _coerce_scalar(value)
    if not text:
        return "-"
    if re.fullmatch(r"\d{4}-\d{2}", text):
        return text
    if re.fullmatch(r"\d{10}", text):
        parsed = datetime.utcfromtimestamp(int(text))
        return parsed.strftime("%b %d %Y").replace(" 0", " ")
    if re.fullmatch(r"\d{13}", text):
        parsed = datetime.utcfromtimestamp(int(text) / 1000.0)
        return parsed.strftime("%b %d %Y").replace(" 0", " ")

    cleaned = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(cleaned)
        return parsed.strftime("%b %d %Y").replace(" 0", " ")
    except ValueError:
        pass

    for fmt in ("%b %d %Y", "%b %d, %Y", "%Y-%m-%d", "%d-%m-%Y", "%Y/%m/%d"):
        try:
            parsed = datetime.strptime(text, fmt)
            return parsed.strftime("%b %d %Y").replace(" 0", " ")
        except ValueError:
            continue
    return text


def _infer_year(record: dict[str, Any], date_label: str) -> str:
    direct = _first_value(record, YEAR_KEYS)
    if direct:
        normalized = re.sub(r"[^\d\-]", "", direct)
        return normalized or direct
    if date_label and date_label != "-":
        parts = date_label.split()
        if len(parts) == 3:
            return f"{parts[2]}-{datetime.strptime(parts[0], '%b').strftime('%m')}"
        if re.fullmatch(r"\d{4}", parts[0]):
            return parts[0]
    return "-"


def _build_tags(record: dict[str, Any], source_file: str) -> list[dict[str, Any]]:
    tags: list[dict[str, Any]] = []
    if _find_email(record):
        tags.append({"label": "Email", "count": 1})
    if _first_value(record, IDENTIFIER_KEYS - {"email", "email_address", "mail"}):
        tags.append({"label": "Username", "count": 1})
    if _extract_host(record):
        tags.append({"label": "Domain", "count": 1})
    if _first_value(record, SOURCE_DOMAIN_KEYS):
        tags.append({"label": "Source Domain", "count": 1})
    if _first_value(record, FILE_NAME_KEYS) or source_file:
        tags.append({"label": "File Name", "count": 1})
    return tags[:6]


def _redacted_trace(record: dict[str, Any], host: str, identifier: str, password_present: bool) -> str:
    trace = _first_value(record, RAW_TRACE_KEYS)
    if not trace:
        if host:
            trace = f"https://{host}/:[redacted_user]"
            if password_present:
                trace += ":[redacted_secret]"
        else:
            trace = "Credential evidence available in source record (redacted)."

    redacted = trace
    if identifier:
        redacted = redacted.replace(identifier, "[redacted_user]")
    email = _find_email(record)
    if email:
        redacted = redacted.replace(email, "[redacted_email]")
    if password_present:
        password = _first_value(record, PASSWORD_KEYS)
        if password:
            redacted = redacted.replace(password, "[redacted_secret]")
    redacted = re.sub(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", "[redacted_email]", redacted, flags=re.IGNORECASE)
    return redacted[:420]


def _normalize_match(record: dict[str, Any], source_file: Path) -> dict[str, Any] | None:
    identifier = _first_value(record, IDENTIFIER_KEYS) or _find_email(record)
    host = _extract_host(record, identifier=identifier)
    if not host and not identifier:
        return None

    date_label = _format_date(_first_value(record, DATE_KEYS))
    password_present = bool(_first_value(record, PASSWORD_KEYS))
    email_or_username = _first_value(record, {"email", "email_address", "mail", "username", "user", "user_name", "login"})
    source_domain = _first_value(record, SOURCE_DOMAIN_KEYS) or host or "-"
    url_value = _safe_source_url(record)
    domain_from_identifier = identifier.split("@", 1)[1].lower() if "@" in identifier else ""
    normalized_domain = domain_from_identifier or host or "-"

    result = {
        "domain_host": host or "-",
        "credential_identifier": _mask_email(identifier) if "@" in identifier else _mask_token(identifier),
        "date": date_label,
        "source_domain": source_domain,
        "channel": _first_value(record, CHANNEL_KEYS) or "-",
        "year": _infer_year(record, date_label),
        "file_type": _first_value(record, FILE_TYPE_KEYS) or source_file.suffix.lstrip(".") or "json",
        "email_username": _mask_email(email_or_username) if "@" in email_or_username else _mask_token(email_or_username),
        "domain": normalized_domain,
        "ip": _mask_ip(_first_value(record, IP_KEYS)),
        "password": "Present (redacted)" if password_present else "-",
        "password_present": password_present,
        "metadata_tags": _build_tags(record, source_file.name),
        "raw_trace": _redacted_trace(record, host or normalized_domain, identifier, password_present),
        "source_file": _first_value(record, FILE_NAME_KEYS) or source_file.name,
        "source_url": url_value or "-",
    }
    return result


def _record_matches(record: dict[str, Any], query: str) -> bool:
    blob = json.dumps(record, ensure_ascii=False, default=str).lower()
    terms = [term for term in re.split(r"\s+", query.lower()) if term]
    return bool(terms) and all(term in blob for term in terms)


def _build_search_blob(record: dict[str, Any], normalized: dict[str, Any], identifier_raw: str) -> str:
    url_host = ""
    url_value = _find_url(record)
    if url_value:
        parsed = urlparse(url_value)
        url_host = parsed.hostname or ""

    parts = [
        normalized.get("domain_host", ""),
        normalized.get("source_domain", ""),
        normalized.get("domain", ""),
        normalized.get("channel", ""),
        normalized.get("file_type", ""),
        normalized.get("source_file", ""),
        normalized.get("date", ""),
        identifier_raw,
        _find_email(record),
        _first_value(record, IDENTIFIER_KEYS),
        url_host,
    ]
    return " ".join(_normalize_text(part).lower() for part in parts if _normalize_text(part))


def _build_ingest_key(dataset_path: Path, normalized: dict[str, Any], identifier_raw: str) -> str:
    raw = "|".join([
        str(dataset_path.resolve()),
        _normalize_text(normalized.get("domain_host")),
        _normalize_text(identifier_raw),
        _normalize_text(normalized.get("date")),
        _normalize_text(normalized.get("source_file")),
        _normalize_text(normalized.get("source_domain")),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def build_documents_from_file(path: Path) -> list[dict[str, Any]]:
    stat = path.stat()
    dataset_path = path.resolve()
    dataset_modified_at = datetime.utcfromtimestamp(stat.st_mtime).isoformat() + "Z"
    documents: list[dict[str, Any]] = []
    seen_keys: set[str] = set()

    for record in _load_dataset_records(path):
        identifier_raw = _first_value(record, IDENTIFIER_KEYS) or _find_email(record)
        normalized = _normalize_match(record, path)
        if not normalized:
            continue

        ingest_key = _build_ingest_key(dataset_path, normalized, identifier_raw)
        if ingest_key in seen_keys:
            continue

        seen_keys.add(ingest_key)
        doc = dict(normalized)
        doc.update({
            "ingest_key": ingest_key,
            "dataset_name": path.name,
            "dataset_path": str(dataset_path),
            "dataset_size_bytes": stat.st_size,
            "dataset_mtime_ns": stat.st_mtime_ns,
            "dataset_modified_at": dataset_modified_at,
            "identifier_query": _normalize_text(identifier_raw),
            "search_blob": _build_search_blob(record, normalized, identifier_raw),
            "synced_at": datetime.utcnow().isoformat() + "Z",
        })
        documents.append(doc)

    return documents


def search_stealer_logs(query: str, limit: int = 250) -> dict[str, Any]:
    query = _normalize_text(query)
    if len(query) < 2:
        raise ValueError("Search query must be at least 2 characters long.")

    start = time.perf_counter()
    dataset_files = discover_credential_files()
    if not dataset_files:
        return {
            "status": "ok",
            "query": query,
            "count": 0,
            "results": [],
            "elapsed_ms": 0,
            "hosts_count": 0,
            "files_loaded": 0,
            "aggregated_count": 0,
            "datasets": [],
            "message": "No stealer-log JSON files are saved on disk yet. Drop files like odoostealerlogs.json or bhariastealerlogs.json into data/credential_checker so they can be synced into Mongo.",
        }

    matches: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, str, str]] = set()
    matched_hosts: set[str] = set()
    matched_files: set[str] = set()

    for path in dataset_files:
        try:
            records = _load_dataset_records(path)
        except (OSError, json.JSONDecodeError):
            continue

        for record in records:
            if not _record_matches(record, query):
                continue
            normalized = _normalize_match(record, path)
            if not normalized:
                continue

            dedupe_key = (
                normalized.get("domain_host", "-"),
                normalized.get("credential_identifier", "-"),
                normalized.get("date", "-"),
                normalized.get("source_file", path.name),
            )
            if dedupe_key in seen_keys:
                continue

            seen_keys.add(dedupe_key)
            matches.append(normalized)
            if normalized.get("domain_host") and normalized["domain_host"] != "-":
                matched_hosts.add(normalized["domain_host"])
            matched_files.add(normalized.get("source_file", path.name))

    matches.sort(key=lambda item: (item.get("date") == "-", item.get("date"), item.get("domain_host", "")))
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    safe_limit = max(1, min(limit, MAX_RENDERED_RESULTS))

    return {
        "status": "ok",
        "query": query,
        "count": len(matches),
        "results": matches[:safe_limit],
        "elapsed_ms": elapsed_ms,
        "hosts_count": len(matched_hosts),
        "files_loaded": len(dataset_files),
        "aggregated_count": len(matched_files),
        "datasets": [path.name for path in dataset_files],
        "message": (
            f"{len(matches)} redacted credential exposure result(s) found."
            if matches
            else f"No matching exposure records were found for {query}."
        ),
    }
