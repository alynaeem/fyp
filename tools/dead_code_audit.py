#!/usr/bin/env python3
"""
Non-destructive dependency mapper and orphan hunter.

Supports:
  - Python imports via ast
  - JavaScript ESM/CommonJS relative imports via conservative token scanning
  - HTML module/script src entry discovery

The script only reports candidates. It never deletes files.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
from collections import deque
from pathlib import Path
from typing import Iterable


IGNORED_DIRS = {
    ".git",
    ".idea",
    ".venv",
    "venv",
    "env",
    "fyp_env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    ".turbo",
    "mongo_runtime_27021",
    "logs",
}

IGNORED_FILES = {
    ".env",
    ".env.example",
    ".gitignore",
    ".dockerignore",
    "Dockerfile",
    "docker-compose.yml",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements.txt",
    "requirements-ml.txt",
    "README.md",
    "Readme.md",
    "Security.md",
}

SOURCE_SUFFIXES = {".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".html", ".css"}
IMPORTABLE_SUFFIXES = [".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".json", ".css"]

JS_IMPORT_PATTERNS = [
    re.compile(r"""import\s+(?:[^'"]+?\s+from\s+)?["']([^"']+)["']"""),
    re.compile(r"""export\s+[^'"]+?\s+from\s+["']([^"']+)["']"""),
    re.compile(r"""import\s*\(\s*["']([^"']+)["']\s*\)"""),
    re.compile(r"""require\s*\(\s*["']([^"']+)["']\s*\)"""),
]

HTML_SRC_PATTERN = re.compile(r"""<(?:script|link)\b[^>]+(?:src|href)=["']([^"']+)["']""", re.I)
CSS_IMPORT_PATTERN = re.compile(r"""@import\s+(?:url\()?["']?([^"')]+)["']?\)?""", re.I)


def is_ignored(path: Path, root: Path) -> bool:
    rel = path.relative_to(root)
    if any(part in IGNORED_DIRS for part in rel.parts):
        return True
    if path.name in IGNORED_FILES:
        return True
    return False


def project_files(root: Path) -> set[Path]:
    return {
        p.resolve()
        for p in root.rglob("*")
        if p.is_file()
        and p.suffix in SOURCE_SUFFIXES
        and not is_ignored(p, root)
    }


def resolve_relative_import(spec: str, importer: Path, root: Path) -> Path | None:
    if not spec or spec.startswith(("http://", "https://", "data:", "#")):
        return None
    if spec.startswith("/"):
        base = root / spec.lstrip("/")
    elif spec.startswith("."):
        base = importer.parent / spec
    else:
        return None

    candidates: list[Path] = []
    raw = base.resolve()
    candidates.append(raw)
    if raw.suffix:
        candidates.append(raw)
    else:
        candidates.extend(raw.with_suffix(ext) for ext in IMPORTABLE_SUFFIXES)
        candidates.extend((raw / f"index{ext}") for ext in IMPORTABLE_SUFFIXES)

    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            try:
                candidate.relative_to(root)
            except ValueError:
                return None
            if not is_ignored(candidate, root):
                return candidate.resolve()
    return None


def module_name_for_file(path: Path, root: Path) -> str:
    rel = path.relative_to(root).with_suffix("")
    if rel.name == "__init__":
        rel = rel.parent
    return ".".join(rel.parts)


def python_module_index(root: Path) -> dict[str, Path]:
    index: dict[str, Path] = {}
    for path in root.rglob("*.py"):
        if path.is_file() and not is_ignored(path, root):
            index[module_name_for_file(path.resolve(), root)] = path.resolve()
    return index


def resolve_python_import(module: str, importer: Path, root: Path, index: dict[str, Path], level: int = 0) -> Path | None:
    if level:
        package_parts = importer.relative_to(root).with_suffix("").parts[:-1]
        if importer.name == "__init__.py":
            package_parts = importer.relative_to(root).with_suffix("").parts[:-1]
        anchor = package_parts[: max(0, len(package_parts) - level + 1)]
        module = ".".join([*anchor, module] if module else anchor)
    return index.get(module)


def imports_from_python(path: Path, root: Path, index: dict[str, Path]) -> set[Path]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"), filename=str(path))
    except SyntaxError:
        return set()

    deps: set[Path] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                parts = alias.name.split(".")
                for end in range(len(parts), 0, -1):
                    resolved = resolve_python_import(".".join(parts[:end]), path, root, index)
                    if resolved:
                        deps.add(resolved)
                        break
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            resolved = resolve_python_import(base, path, root, index, node.level)
            if resolved:
                deps.add(resolved)
            for alias in node.names:
                if alias.name == "*":
                    continue
                child = f"{base}.{alias.name}" if base else alias.name
                resolved_child = resolve_python_import(child, path, root, index, node.level)
                if resolved_child:
                    deps.add(resolved_child)
    return deps


def imports_from_js(path: Path, root: Path) -> set[Path]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    deps: set[Path] = set()
    for pattern in JS_IMPORT_PATTERNS:
        for spec in pattern.findall(text):
            resolved = resolve_relative_import(spec, path, root)
            if resolved:
                deps.add(resolved)
    return deps


def imports_from_html(path: Path, root: Path) -> set[Path]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    deps: set[Path] = set()
    for spec in HTML_SRC_PATTERN.findall(text):
        resolved = resolve_relative_import(spec.split("?", 1)[0], path, root)
        if resolved:
            deps.add(resolved)
    return deps


def imports_from_css(path: Path, root: Path) -> set[Path]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    deps: set[Path] = set()
    for spec in CSS_IMPORT_PATTERN.findall(text):
        resolved = resolve_relative_import(spec, path, root)
        if resolved:
            deps.add(resolved)
    return deps


def file_dependencies(path: Path, root: Path, py_index: dict[str, Path]) -> set[Path]:
    if path.suffix == ".py":
        return imports_from_python(path, root, py_index)
    if path.suffix in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}:
        return imports_from_js(path, root)
    if path.suffix == ".html":
        return imports_from_html(path, root)
    if path.suffix == ".css":
        return imports_from_css(path, root)
    return set()


def build_dependency_graph(root: Path, entrypoints: Iterable[Path]) -> dict[Path, set[Path]]:
    root = root.resolve()
    py_index = python_module_index(root)
    graph: dict[Path, set[Path]] = {}
    queue = deque()

    for entry in entrypoints:
        candidate = (root / entry).resolve() if not entry.is_absolute() else entry.resolve()
        if not candidate.exists():
            raise FileNotFoundError(f"Entry point does not exist: {entry}")
        if not is_ignored(candidate, root):
            queue.append(candidate)

    while queue:
        current = queue.popleft()
        if current in graph:
            continue
        deps = file_dependencies(current, root, py_index)
        graph[current] = deps
        for dep in sorted(deps):
            if dep not in graph:
                queue.append(dep)
    return graph


def find_orphans(root: Path, graph: dict[Path, set[Path]], extra_keep: Iterable[Path]) -> set[Path]:
    all_files = project_files(root)
    active = set(graph.keys()) | {dep for deps in graph.values() for dep in deps}
    for keep in extra_keep:
        candidate = (root / keep).resolve() if not keep.is_absolute() else keep.resolve()
        if candidate.exists():
            active.add(candidate)
    return all_files - active


def rel(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def main() -> int:
    parser = argparse.ArgumentParser(description="Map active dependencies and report orphan candidates.")
    parser.add_argument("--root", default=".", help="Project root. Default: current directory.")
    parser.add_argument("--entry", action="append", required=True, help="Entrypoint file. Repeat for multiple entries.")
    parser.add_argument("--keep", action="append", default=[], help="Additional file to treat as active. Repeatable.")
    parser.add_argument("--json-out", default="", help="Optional JSON report path.")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    entries = [Path(item) for item in args.entry]
    keep = [Path(item) for item in args.keep]

    graph = build_dependency_graph(root, entries)
    orphans = find_orphans(root, graph, keep)

    report = {
        "root": str(root),
        "entrypoints": [rel((root / p).resolve() if not p.is_absolute() else p, root) for p in entries],
        "active_files": sorted(rel(p, root) for p in graph.keys()),
        "graph": {
            rel(source, root): sorted(rel(dep, root) for dep in deps)
            for source, deps in sorted(graph.items(), key=lambda item: rel(item[0], root))
        },
        "orphan_candidates": sorted(rel(p, root) for p in orphans),
    }

    print("ACTIVE FILES")
    for item in report["active_files"]:
        print(item)
    print("\nORPHAN CANDIDATES")
    for item in report["orphan_candidates"]:
        print(item)

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nJSON REPORT: {args.json_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
