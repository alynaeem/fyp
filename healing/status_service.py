from __future__ import annotations

from collections import Counter
from pathlib import Path
import threading
import time
from typing import Any

from .discovery import discover_collector_scripts
from .health_runner import HealthCheckRunner
from .storage import HealingStorage


SUMMARY_STATUSES = (
    "healthy",
    "no_data",
    "target_unreachable",
    "html_changed",
    "repair_ready",
    "needs_review",
    "skipped",
    "discovered",
)

STATUS_ALIASES = {
    "unreachable": "target_unreachable",
    "changed": "html_changed",
    "auto_fixed": "repair_ready",
}


class HealingStatusService:
    def __init__(self) -> None:
        self.storage = HealingStorage()
        self.runner = HealthCheckRunner(self.storage)
        self._discovery_lock = threading.Lock()
        self._last_discovery_monotonic = 0.0
        self._discovery_ttl_seconds = 45.0

    def discover_targets(self, *, force: bool = False) -> dict[str, Any]:
        if not force and (time.monotonic() - self._last_discovery_monotonic) < self._discovery_ttl_seconds:
            runtime = self.storage.get_runtime("healing_registry")
            breakdown = runtime.get("breakdown") or {}
            return {
                "status": "ok",
                "discovered": int(breakdown.get("discovered_target_count") or 0),
                "total_scripts": self.storage.scripts.count_documents({}),
                "discovery_breakdown": breakdown,
                "updated_at": runtime.get("last_discovered_at") or self.storage.now_iso(),
                "cached": True,
            }
        with self._discovery_lock:
            if not force and (time.monotonic() - self._last_discovery_monotonic) < self._discovery_ttl_seconds:
                runtime = self.storage.get_runtime("healing_registry")
                breakdown = runtime.get("breakdown") or {}
                return {
                    "status": "ok",
                    "discovered": int(breakdown.get("discovered_target_count") or 0),
                    "total_scripts": self.storage.scripts.count_documents({}),
                    "discovery_breakdown": breakdown,
                    "updated_at": runtime.get("last_discovered_at") or self.storage.now_iso(),
                    "cached": True,
                }
            return self._run_discovery()

    def _run_discovery(self) -> dict[str, Any]:
        discovery = discover_collector_scripts()
        active_ids: set[str] = set()
        for script_doc in discovery["scripts"]:
            active_ids.add(script_doc["script_id"])
            self.storage.upsert_script(script_doc)
            mongo_count = self.storage.raw_document_count(
                script_doc.get("collector_name") or "",
                script_doc.get("source_name") or "",
            )
            self.storage.update_script_runtime(
                script_doc["script_id"],
                {
                    "mongo_document_count": mongo_count,
                    "discovery_status": script_doc.get("discovery_status"),
                    "skip_reason": script_doc.get("skip_reason"),
                },
            )
        self.storage.mark_missing_scripts_inactive(active_ids)
        breakdown = discovery["discovery_breakdown"]
        self.storage.update_runtime(
            "healing_registry",
            {
                "last_discovered_at": self.storage.now_iso(),
                "target_count": breakdown["discovered_target_count"],
                "total_python_files": breakdown["total_python_files"],
                "breakdown": breakdown,
            },
        )
        self._last_discovery_monotonic = time.monotonic()
        return {
            "status": "ok",
            "discovered": breakdown["discovered_target_count"],
            "total_scripts": len(discovery["scripts"]),
            "discovery_breakdown": breakdown,
            "updated_at": self.storage.now_iso(),
        }

    def _normalize_status(self, status: Any) -> str:
        normalized = str(status or "discovered").strip().lower() or "discovered"
        return STATUS_ALIASES.get(normalized, normalized)

    def _normalize_script_doc(self, doc: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(doc)
        normalized["is_monitorable"] = bool(doc.get("is_monitorable"))
        normalized["status"] = "skipped" if not normalized["is_monitorable"] else self._normalize_status(doc.get("status"))
        normalized["collector_name"] = str(doc.get("collector_name") or doc.get("collector_type") or "")
        normalized["collector_type"] = str(doc.get("collector_type") or normalized["collector_name"])
        normalized["last_data_count"] = int(doc.get("last_data_count") or 0)
        normalized["mongo_document_count"] = int(doc.get("mongo_document_count") or 0)
        normalized["total_runs"] = int(doc.get("total_runs") or 0)
        normalized["success_runs"] = int(doc.get("success_runs") or 0)
        normalized["failed_runs"] = int(doc.get("failed_runs") or 0)
        normalized["selector_health_score"] = doc.get("selector_health_score")
        normalized["repair_confidence"] = float(doc.get("repair_confidence") or 0.0)
        normalized["repair_candidate_exists"] = bool(doc.get("repair_candidate_exists"))
        normalized["diff_summary"] = list(doc.get("diff_summary") or doc.get("last_summary_changes") or [])
        normalized["changed_components"] = list(doc.get("changed_components") or [])
        normalized["failed_selectors"] = list(doc.get("failed_selectors") or [])
        normalized["suggested_selectors"] = list(doc.get("suggested_selectors") or doc.get("last_selector_suggestions") or [])
        normalized["baseline_snapshot_path"] = str(doc.get("baseline_snapshot_path") or "")
        normalized["latest_snapshot_path"] = str(doc.get("latest_snapshot_path") or "")
        normalized["last_event_message"] = str(doc.get("last_event_message") or doc.get("last_error") or "")
        normalized["last_response_code"] = doc.get("last_response_code")
        normalized["last_response_time_ms"] = int(doc.get("last_response_time_ms") or 0)
        normalized["last_final_url"] = str(doc.get("last_final_url") or doc.get("target_url") or "")
        normalized["last_parse_error"] = str(doc.get("last_parse_error") or doc.get("last_error") or "")
        normalized["selector_total_count"] = int(doc.get("selector_total_count") or 0)
        normalized["selector_matched_count"] = int(doc.get("selector_matched_count") or 0)
        normalized["selector_broken_count"] = int(doc.get("selector_broken_count") or 0)
        normalized["selector_fix_count"] = int(doc.get("selector_fix_count") or 0)
        if not normalized["last_data_count"] and normalized["status"] == "healthy":
            normalized["last_data_count"] = normalized["mongo_document_count"]
        if not normalized.get("html_change_status") and doc.get("html_changed") is True:
            normalized["html_change_status"] = "major_change"
        elif not normalized.get("html_change_status"):
            normalized["html_change_status"] = "not_checked"
        normalized["live_status"] = "skipped" if not normalized["is_monitorable"] else str(doc.get("live_status") or "not_checked")
        return normalized

    def _normalize_event_doc(self, doc: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(doc)
        normalized["status"] = self._normalize_status(doc.get("status"))
        normalized["collector_name"] = str(doc.get("collector_name") or doc.get("collector_type") or "")
        normalized["collector_type"] = str(doc.get("collector_type") or normalized["collector_name"])
        normalized["live_status"] = str(doc.get("live_status") or "not_checked")
        normalized["html_change_status"] = str(doc.get("html_change_status") or "not_checked")
        return normalized

    def run_monitor(
        self,
        *,
        limit: int | None = None,
        target_key: str | None = None,
        collector_name: str | None = None,
        mode: str = "default",
        auto_heal: bool = False,
        dry_run_repair: bool = True,
    ) -> dict[str, Any]:
        self.discover_targets(force=True)
        targets = self.storage.list_target_scripts(limit=1000, collector_name=collector_name or "")
        if target_key:
            targets = [item for item in targets if item.get("target_key") == target_key or item.get("script_id") == target_key]
        if mode != "full" and limit:
            targets = targets[: int(limit)]
        elif mode != "full" and not limit:
            runtime = self.storage.get_runtime("healing_registry")
            default_limit = int((runtime.get("breakdown") or {}).get("default_run_limit") or 12)
            targets = targets[:default_limit]

        results: list[dict[str, Any]] = []
        status_counts: Counter[str] = Counter()
        for script_doc in targets:
            result = self.runner.check_script(
                script_doc,
                run_mode=mode if not target_key else "single",
                dry_run_repair=dry_run_repair,
            )
            results.append(result)
            status_counts[str(result.get("status") or "unknown")] += 1
            if auto_heal and result.get("status") == "repair_ready":
                self.apply_repair(script_doc["script_id"], source="auto_heal")

        summary = {
            "status": "ok",
            "target_count": len(results),
            "status_counts": dict(status_counts),
            "results": results[:50],
            "completed_at": self.storage.now_iso(),
        }
        self.storage.update_runtime("healing_monitor", {"last_run_at": self.storage.now_iso(), "last_summary": summary})
        return summary

    def run_target_check(self, target: dict[str, Any] | str) -> dict[str, Any]:
        self.discover_targets()
        script_doc = self.storage.get_script(target if isinstance(target, str) else target["script_id"])
        if not script_doc:
            return {"status": "missing", "script_id": str(target)}
        return self.runner.check_script(script_doc, run_mode="single")

    def get_summary(self) -> dict[str, Any]:
        self.discover_targets()
        all_scripts = [self._normalize_script_doc(item) for item in self.storage.list_scripts(limit=3000)]
        status_counts = Counter(str(item.get("status") or "discovered") for item in all_scripts)
        summary = {
            "total_scripts": len(all_scripts),
            "monitorable_scripts": sum(1 for item in all_scripts if item.get("is_monitorable")),
            "skipped_scripts": sum(1 for item in all_scripts if not item.get("is_monitorable")),
            "healthy": status_counts.get("healthy", 0),
            "no_data": status_counts.get("no_data", 0),
            "target_unreachable": status_counts.get("target_unreachable", 0),
            "html_changed": status_counts.get("html_changed", 0),
            "repair_ready": status_counts.get("repair_ready", 0),
            "needs_review": status_counts.get("needs_review", 0),
            "skipped": status_counts.get("skipped", 0),
            "discovered": status_counts.get("discovered", 0),
            "status_counts": dict(status_counts),
            "discovery_breakdown": (self.storage.get_runtime("healing_registry") or {}).get("breakdown") or {},
            "last_run_at": (self.storage.get_runtime("healing_monitor") or {}).get("last_run_at"),
            "last_discovered_at": (self.storage.get_runtime("healing_registry") or {}).get("last_discovered_at"),
        }
        return summary

    def get_stats(self) -> dict[str, Any]:
        summary = self.get_summary()
        return {
            "total_targets": summary["monitorable_scripts"],
            "html_changed": summary["html_changed"],
            "auto_fixed": summary["repair_ready"],
            "needs_review": summary["needs_review"],
            "healthy": summary["healthy"],
            "unreachable": summary["target_unreachable"],
            "no_data": summary["no_data"],
            "last_run_at": summary["last_run_at"],
            "last_discovered_at": summary["last_discovered_at"],
            "discovery_breakdown": {
                **summary["discovery_breakdown"],
            },
        }

    def list_collectors(self) -> list[dict[str, Any]]:
        self.discover_targets()
        scripts = [self._normalize_script_doc(item) for item in self.storage.list_scripts(limit=4000)]
        grouped: dict[str, dict[str, Any]] = {}
        for item in scripts:
            collector_name = item.get("collector_name") or "unknown"
            bucket = grouped.setdefault(
                collector_name,
                {
                    "collector_name": collector_name,
                    "total_scripts": 0,
                    "monitorable_scripts": 0,
                    "healthy_count": 0,
                    "failing_count": 0,
                    "skipped_count": 0,
                },
            )
            bucket["total_scripts"] += 1
            if item.get("is_monitorable"):
                bucket["monitorable_scripts"] += 1
            status = item.get("status")
            if status == "healthy":
                bucket["healthy_count"] += 1
            elif status == "skipped":
                bucket["skipped_count"] += 1
            elif status in {"no_data", "target_unreachable", "html_changed", "repair_ready", "needs_review", "error"}:
                bucket["failing_count"] += 1
        return [grouped[name] for name in sorted(grouped)]

    def list_scripts(
        self,
        *,
        limit: int = 200,
        offset: int = 0,
        collector_name: str = "",
        status: str = "",
        only_monitorable: bool = False,
    ) -> dict[str, Any]:
        self.discover_targets()
        fetch_limit = max(int(limit) + int(offset), 400) if status else limit
        items = self.storage.list_scripts(
            limit=fetch_limit,
            offset=0 if status else offset,
            collector_name=collector_name,
            status="",
            only_monitorable=only_monitorable,
        )
        normalized_items = [self._normalize_script_doc(item) for item in items]
        if status:
            wanted_status = self._normalize_status(status)
            normalized_items = [item for item in normalized_items if item.get("status") == wanted_status]
        paged_items = normalized_items[int(offset): int(offset) + int(limit)]
        return {
            "count": len(paged_items),
            "items": paged_items,
        }

    def list_targets(self, *, limit: int = 100) -> list[dict[str, Any]]:
        self.discover_targets()
        return [self._normalize_script_doc(item) for item in self.storage.list_target_scripts(limit=limit)]

    def list_events(self, *, limit: int = 50, target_key: str | None = None) -> list[dict[str, Any]]:
        self.discover_targets()
        return [self._normalize_event_doc(item) for item in self.storage.list_events(limit=limit, script_id=target_key or "")]

    def get_script_detail(self, script_id: str) -> dict[str, Any]:
        self.discover_targets()
        script_doc = self.storage.get_script(script_id)
        if not script_doc:
            return {"status": "missing", "script_id": script_id}
        latest_snapshot = self.storage.latest_snapshot(script_id) or {}
        baseline_snapshot = self.storage.baseline_snapshot(script_id) or {}
        latest_repair = self.storage.latest_repair(script_id) or {}
        recent_events = [self._normalize_event_doc(item) for item in self.storage.list_events(limit=10, script_id=script_id)]
        return {
            "status": "ok",
            "script": self._normalize_script_doc(script_doc),
            "baseline_snapshot": self._serialise_snapshot(baseline_snapshot),
            "latest_snapshot": self._serialise_snapshot(latest_snapshot),
            "latest_repair": self._serialise_doc(latest_repair),
            "recent_events": recent_events,
        }

    def generate_repair(self, script_id: str) -> dict[str, Any]:
        detail = self.get_script_detail(script_id)
        if detail.get("status") != "ok":
            return detail
        script_doc = detail["script"]
        latest_snapshot = detail["latest_snapshot"] or {}
        baseline_snapshot = detail["baseline_snapshot"] or {}
        if not latest_snapshot:
            result = self.run_target_check(script_id)
            detail = self.get_script_detail(script_id)
            script_doc = detail["script"]
            latest_snapshot = detail["latest_snapshot"] or {}
            baseline_snapshot = detail["baseline_snapshot"] or {}
            if result.get("status") == "missing":
                return result
        source_path = Path(script_doc["script_path"])
        from .repair_engine import generate_repair_preview

        preview = generate_repair_preview(
            script_doc,
            source_path,
            latest_snapshot.get("html", ""),
            baseline_snapshot.get("selector_results") or [],
            latest_snapshot.get("selector_results") or [],
        )
        repair_doc = {
            "script_id": script_id,
            "created_at": self.storage.now_iso(),
            "status": "preview",
            "repair_candidate_exists": preview.repair_candidate_exists,
            "repair_confidence": preview.repair_confidence,
            "failed_selectors": preview.failed_selectors,
            "suggested_selectors": preview.suggested_selectors,
            "changed_selector_mappings": preview.changed_selector_mappings,
            "candidate_patch_path": preview.candidate_patch_path,
            "message": preview.preview_message,
        }
        repair_id = self.storage.save_repair_record(repair_doc).inserted_id
        repair_doc["repair_id"] = str(repair_id)
        self.storage.update_script_runtime(
            script_id,
            {
                "repair_candidate_exists": preview.repair_candidate_exists,
                "repair_confidence": preview.repair_confidence,
                "suggested_selectors": preview.suggested_selectors,
            },
        )
        return {"status": "ok", "repair": self._serialise_doc(repair_doc)}

    def apply_repair(self, script_id: str, *, source: str = "manual_apply") -> dict[str, Any]:
        detail = self.get_script_detail(script_id)
        if detail.get("status") != "ok":
            return detail
        script_doc = detail["script"]
        repair_doc = self.latest_or_generated_repair(script_id)
        if repair_doc.get("status") != "ok":
            return repair_doc
        repair = repair_doc["repair"]
        candidate_path = repair.get("candidate_patch_path") or ""
        if not repair.get("repair_candidate_exists") or not candidate_path:
            return {"status": "needs_review", "message": "No patchable repair candidate exists for this script."}

        source_path = Path(script_doc["script_path"])
        if not source_path.exists():
            return {"status": "missing", "message": f"Script file not found: {source_path}"}

        backup_path = self.storage.create_backup(script_id, source_path)
        try:
            patched_source = Path(candidate_path).read_text(encoding="utf-8", errors="ignore")
            source_path.write_text(patched_source, encoding="utf-8")
            result = self.run_target_check(script_id)
            # Only keep the patch if it immediately restores data; otherwise roll back the original file.
            recovered = result.get("status") == "healthy" and int(result.get("data_count") or 0) > 0
            if not recovered:
                original = Path(backup_path).read_text(encoding="utf-8", errors="ignore")
                source_path.write_text(original, encoding="utf-8")
                return {
                    "status": "rolled_back",
                    "message": "Candidate repair did not recover data. Original script was restored.",
                    "backup_path": backup_path,
                    "check_result": result,
                }

            latest_repair = self.storage.latest_repair(script_id)
            if latest_repair:
                self.storage.update_repair_record(
                    latest_repair["_id"],
                    {
                        "status": "applied",
                        "applied_at": self.storage.now_iso(),
                        "backup_path": backup_path,
                        "source": source,
                    },
                )
            return {
                "status": "ok",
                "message": "Repair applied and data recovered successfully.",
                "backup_path": backup_path,
                "check_result": result,
            }
        except Exception as exc:
            try:
                original = Path(backup_path).read_text(encoding="utf-8", errors="ignore")
                source_path.write_text(original, encoding="utf-8")
            except Exception:
                pass
            return {"status": "error", "message": f"Repair apply failed: {exc}", "backup_path": backup_path}

    def latest_or_generated_repair(self, script_id: str) -> dict[str, Any]:
        latest = self.storage.latest_repair(script_id)
        if latest:
            return {"status": "ok", "repair": self._serialise_doc(latest)}
        return self.generate_repair(script_id)

    def _serialise_snapshot(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        if not snapshot:
            return {}
        doc = self._serialise_doc(snapshot)
        path = doc.get("snapshot_path") or ""
        if path:
            try:
                doc["html"] = Path(path).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                doc["html"] = ""
        else:
            doc["html"] = ""
        return doc

    def _serialise_doc(self, doc: dict[str, Any]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in doc.items():
            if key == "_id":
                output[key] = str(value)
            else:
                output[key] = value
        return output


_SERVICE: HealingStatusService | None = None


def get_healing_service() -> HealingStatusService:
    global _SERVICE
    if _SERVICE is None:
        _SERVICE = HealingStatusService()
    return _SERVICE
