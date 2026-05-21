from __future__ import annotations

import ast
import re
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from config import cfg


SCRIPT_ROOTS: tuple[tuple[str, str], ...] = (
    ("news", "news_collector/scripts"),
    ("leak", "leak_collector/scripts"),
    ("defacement", "defacement_collector/scripts"),
    ("exploit", "exploit_collector/scripts"),
    ("social", "social_collector/scripts"),
    ("api", "api_collector/scripts"),
)

SKIP_FILE_NAMES = {"__init__.py", "main.py", "apimain.py", "apkmain.py", "gitmain.py"}
SKIP_PATH_PARTS = {"__pycache__", "output"}
UTILITY_NAME_FRAGMENTS = (
    "request_utils",
    "json_saver",
    "nlp_processor",
    "run_crawlers_once",
    "helper",
    "helpers",
    "utility",
    "common",
    "config",
)
QUERY_ONLY_NAME_FRAGMENTS = ("seo_checker", "github_trivy_checker")
TARGET_NAME_HINTS = (
    "seed_url",
    "base_url",
    "target_url",
    "source_url",
    "home_url",
    "site_url",
    "archive_url",
    "feed_url",
    "blog_url",
    "url",
    "domain",
)
PRIORITY_HINTS = (
    "ransomware.live",
    "thehackernews",
    "bleepingcomputer",
    "hackread",
    "portswigger",
    "ownzyou",
    "zone-xsec",
    "ddosecrets",
)
URL_REGEX = re.compile(r"""https?://[^\s'"<>]+""", re.I)
DOMAIN_REGEX = re.compile(
    r"""(?ix)
    \b
    (
      (?:[a-z0-9-]+\.)+[a-z]{2,63}
      |
      [a-z2-7]{16,56}\.onion
    )
    (?:/[^\s'"<>]*)?
    \b
    """
)
SELECTOR_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "css",
        re.compile(
            r"""(?:select_one|select|query_selector|query_selector_all)\(\s*['"]([^'"]{2,220})['"]"""
        ),
    ),
    (
        "tag",
        re.compile(
            r"""find(?:_all)?\(\s*['"]([a-zA-Z][a-zA-Z0-9:_\-]{0,80})['"]"""
        ),
    ),
)


def safe_domain(value: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    try:
        parsed = urlparse(candidate)
        host = parsed.netloc or parsed.path.split("/")[0]
    except ValueError:
        host = re.split(r"[\s<>\[\](){}]+", candidate, maxsplit=1)[0].split("/")[0]
    return host


def _trim_candidate(value: str) -> str:
    return re.split(r"[\s<>\[\](){}]+", value.strip().strip("\"'"), maxsplit=1)[0]


def normalize_url(value: str) -> str:
    candidate = _trim_candidate(value)
    if not candidate or len(candidate) > 320:
        return ""
    if any(ch in candidate for ch in ("\n", "\r", "\t", " ")):
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        if ".onion" in candidate:
            candidate = f"http://{candidate.lstrip('/')}"
        elif DOMAIN_REGEX.fullmatch(candidate):
            candidate = f"https://{candidate.lstrip('/')}"
        else:
            return ""
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return ""
    if not (parsed.netloc or parsed.path):
        return ""
    return candidate.rstrip("\"',);")


def _literal_string(node: ast.AST | None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
        return "".join(parts)
    return ""


def _assign_target_names(node: ast.AST) -> list[str]:
    names: list[str] = []
    if isinstance(node, ast.Name):
        names.append(node.id)
    elif isinstance(node, ast.Attribute):
        names.append(node.attr)
    elif isinstance(node, (ast.Tuple, ast.List)):
        for item in node.elts:
            names.extend(_assign_target_names(item))
    return names


def extract_url_candidates(source: str) -> list[str]:
    candidates: list[tuple[int, str]] = []
    seen: set[str] = set()

    try:
        tree = ast.parse(source)
    except SyntaxError:
        tree = None

    if tree:
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value_node = node.value if hasattr(node, "value") else None
                literal = _literal_string(value_node)
                if not literal:
                    continue
                names: list[str] = []
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    names.extend(_assign_target_names(target))
                score = 2
                if any(name.lower() in TARGET_NAME_HINTS for name in names):
                    score += 4
                normalized = normalize_url(literal)
                if normalized:
                    candidates.append((score, normalized))
            elif isinstance(node, ast.Call):
                for arg in node.args[:2]:
                    literal = _literal_string(arg)
                    normalized = normalize_url(literal) if literal else ""
                    if normalized:
                        candidates.append((3, normalized))

    for match in URL_REGEX.findall(source):
        normalized = normalize_url(match)
        if normalized:
            candidates.append((5, normalized))

    for match in DOMAIN_REGEX.findall(source):
        normalized = normalize_url(match)
        if normalized:
            candidates.append((4, normalized))

    deduped: list[tuple[int, str]] = []
    for score, candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        deduped.append((score, candidate))
    deduped.sort(key=lambda item: (item[0], _score_url(item[1]), -len(item[1])), reverse=True)
    return [candidate for _, candidate in deduped]


def _score_url(url: str) -> int:
    lowered = url.lower()
    score = 0
    if any(fragment in lowered for fragment in PRIORITY_HINTS):
        score += 5
    if ".onion" in lowered:
        score += 4
    if lowered.startswith("https://"):
        score += 2
    if "/support/" not in lowered and "/privacy" not in lowered and "/contact" not in lowered:
        score += 2
    if lowered.count("/") <= 4:
        score += 1
    if any(fragment in lowered for fragment in ("/rss", "/feed", "/api", "/privacy", "/contact")):
        score -= 2
    return score


def extract_selector_hints(source: str) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for selector_type, pattern in SELECTOR_PATTERNS:
        for match in pattern.finditer(source):
            selector = (match.group(1) or "").strip()
            if not selector:
                continue
            key = (selector, selector_type)
            if key in seen:
                continue
            seen.add(key)
            hints.append({"selector": selector, "method": selector_type})
    return hints[:50]


def infer_fetch_strategy(source: str) -> str:
    lowered = source.lower()
    if "playwright" in lowered or "query_selector" in lowered or "page.goto" in lowered:
        return "playwright"
    return "requests"


def _has_collector_class(tree: ast.AST | None, class_name: str) -> bool:
    if not tree:
        return False
    return any(isinstance(node, ast.ClassDef) and node.name == class_name for node in ast.walk(tree))


def _requires_query_input(source: str) -> bool:
    patterns = (
        r"""async\s+def\s+parse_leak_data\(\s*self\s*,\s*query\b""",
        r"""def\s+parse_leak_data\(\s*self\s*,\s*query\b""",
    )
    return any(re.search(pattern, source) for pattern in patterns)


def classify_script(path: Path, source: str, tree: ast.AST | None) -> tuple[bool, str]:
    if path.name in SKIP_FILE_NAMES or path.name.startswith("test_") or path.name.startswith("_example"):
        return False, "infra_file"
    if any(part in SKIP_PATH_PARTS for part in path.parts):
        return False, "generated_or_cache"
    stem_lower = path.stem.lower()
    if any(fragment in stem_lower for fragment in UTILITY_NAME_FRAGMENTS):
        return False, "utility_module"
    if any(fragment in stem_lower for fragment in QUERY_ONLY_NAME_FRAGMENTS):
        return False, "query_driven"
    if _requires_query_input(source) and "def run(" not in source and "async def run(" not in source:
        return False, "query_driven"
    if not _has_collector_class(tree, path.stem):
        return False, "no_collector_class"
    return True, ""


def discover_collector_scripts() -> dict[str, Any]:
    scripts: list[dict[str, Any]] = []
    per_collector = Counter()
    monitorable_per_collector = Counter()
    skipped_per_collector = Counter()
    total_python_files = 0
    skipped_files: list[str] = []
    utility_files: list[str] = []

    for collector_name, root in SCRIPT_ROOTS:
        base = Path(root)
        if not base.exists():
            continue

        for path in sorted(base.rglob("*.py")):
            total_python_files += 1
            rel_path = path.as_posix().lstrip("./")
            per_collector[collector_name] += 1
            try:
                source = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                source = ""
            try:
                tree = ast.parse(source)
            except SyntaxError:
                tree = None

            is_candidate, skip_reason = classify_script(path, source, tree)
            urls = extract_url_candidates(source) if is_candidate else []
            target_url = urls[0] if urls else ""
            is_monitorable = bool(is_candidate and target_url)

            if not is_candidate:
                skipped_per_collector[collector_name] += 1
                skipped_files.append(rel_path)
            elif not target_url:
                skipped_per_collector[collector_name] += 1
                utility_files.append(rel_path)
                skip_reason = "no_real_target"
            else:
                monitorable_per_collector[collector_name] += 1

            scripts.append(
                {
                    "script_id": rel_path.replace("/", "__").replace(".", "_").lower(),
                    "target_key": rel_path.replace("/", "_").replace(".", "_").lower(),
                    "collector_name": collector_name,
                    "collector_type": collector_name,
                    "script_type": collector_name,
                    "script_name": path.stem,
                    "source_name": path.stem.lstrip("_"),
                    "class_name": path.stem,
                    "script_file": path.name,
                    "script_path": rel_path,
                    "module_import_path": rel_path[:-3].replace("/", "."),
                    "target_url": target_url,
                    "probable_target_url": target_url,
                    "domain": safe_domain(target_url),
                    "target_domain": safe_domain(target_url),
                    "additional_urls": urls[1:10],
                    "fetch_strategy": infer_fetch_strategy(source) if is_monitorable else "requests",
                    "selector_hints": extract_selector_hints(source) if is_monitorable else [],
                    "selector_hint_count": len(extract_selector_hints(source)) if is_monitorable else 0,
                    "is_monitorable": is_monitorable,
                    "active": is_monitorable,
                    "discovery_status": "active" if is_monitorable else "skipped",
                    "skip_reason": "" if is_monitorable else skip_reason,
                }
            )

    return {
        "scripts": scripts,
        "discovery_breakdown": {
            "roots": [root for _, root in SCRIPT_ROOTS],
            "root_count": len(SCRIPT_ROOTS),
            "total_python_files": total_python_files,
            "skipped_file_count": len(skipped_files),
            "utility_file_count": len(utility_files),
            "discovered_target_count": sum(1 for item in scripts if item["is_monitorable"]),
            "default_run_limit": int(cfg.healing_monitor_target_limit or 12),
            "skipped_files": skipped_files[:30],
            "utility_files": utility_files[:30],
            "per_collector_total": dict(per_collector),
            "per_collector_monitorable": dict(monitorable_per_collector),
            "per_collector_skipped": dict(skipped_per_collector),
        },
    }
