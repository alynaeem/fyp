from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class SelectorHint:
    selector: str
    method: str = "css"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class LiveCheckResult:
    live_status: str
    is_live: bool
    reachable: bool
    status_code: int | None = None
    response_time_ms: int = 0
    final_url: str = ""
    error: str = ""
    html: str = ""
    fetch_strategy: str = "requests"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DriftResult:
    html_change_status: str
    structure_similarity: float
    html_changed: bool
    diff_summary: list[str] = field(default_factory=list)
    changed_components: list[str] = field(default_factory=list)
    diff_excerpt: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SelectorHealthResult:
    selector_health_score: float | None
    total_selectors: int
    matched_selectors: int
    failed_selectors: list[dict[str, Any]] = field(default_factory=list)
    results: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RepairPreview:
    repair_candidate_exists: bool
    repair_confidence: float
    failed_selectors: list[dict[str, Any]] = field(default_factory=list)
    suggested_selectors: list[dict[str, Any]] = field(default_factory=list)
    changed_selector_mappings: list[dict[str, Any]] = field(default_factory=list)
    candidate_patch_path: str = ""
    preview_message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
