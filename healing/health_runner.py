from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any

from config import cfg
from crawler.request_parser import RequestParser
from mongo_persistence import RAW_COLLECTIONS

from .drift_detector import compare_snapshots
from .html_snapshot import fingerprint_summary, persist_snapshot_file, summarize_html
from .live_check import check_target_live
from .repair_engine import generate_repair_preview
from .selector_health import evaluate_selector_health
from .storage import HealingStorage


UNREACHABLE_LIVE_STATES = {"timeout", "dns_failure", "connection_error", "unreachable"}


class HealthCheckRunner:
    def __init__(self, storage: HealingStorage) -> None:
        self.storage = storage

    def check_script(
        self,
        script_doc: dict[str, Any],
        *,
        run_mode: str = "manual",
        dry_run_repair: bool = True,
    ) -> dict[str, Any]:
        script_id = script_doc["script_id"]
        if not script_doc.get("is_monitorable"):
            status = "skipped"
            message = f"{script_doc.get('script_name')} is skipped because it is not a monitorable target."
            event_doc = {
                "script_id": script_id,
                "target_key": script_doc.get("target_key"),
                "script_name": script_doc.get("script_name"),
                "collector_name": script_doc.get("collector_name"),
                "collector_type": script_doc.get("collector_type"),
                "created_at": self.storage.now_iso(),
                "status": status,
                "live_status": "skipped",
                "html_change_status": "not_checked",
                "message": message,
                "summary_changes": [],
                "selector_suggestions": [],
                "broken_selectors": [],
                "repair_confidence": 0.0,
            }
            self.storage.save_event(event_doc)
            self.storage.update_script_runtime(
                script_id,
                {
                    "status": status,
                    "last_event_message": message,
                    "last_checked_at": self.storage.now_iso(),
                    "last_checked_mode": run_mode,
                },
                {"total_runs": 1},
            )
            return {"script_id": script_id, "status": status, "message": message}

        live_result = check_target_live(
            script_doc.get("target_url") or "",
            script_doc.get("fetch_strategy") or "requests",
        )
        validation_result = self._run_script_validation(script_doc)

        html = live_result.html or ""
        current_summary = summarize_html(html)
        selector_health = evaluate_selector_health(html, script_doc.get("selector_hints") or [])
        latest_snapshot_path = persist_snapshot_file(script_doc, html, label="latest")

        baseline_snapshot = self.storage.baseline_snapshot(script_id)
        baseline_summary = (baseline_snapshot or {}).get("summary") or {}
        baseline_hash = str((baseline_snapshot or {}).get("html_sha256") or "")
        baseline_selector_results = (baseline_snapshot or {}).get("selector_results") or []

        current_hash = fingerprint_summary(current_summary)
        drift = compare_snapshots(
            baseline_summary,
            current_summary,
            baseline_hash=baseline_hash,
            current_hash=current_hash,
        )

        snapshot_doc = {
            "script_id": script_id,
            "target_key": script_doc.get("target_key"),
            "script_name": script_doc.get("script_name"),
            "collector_name": script_doc.get("collector_name"),
            "collector_type": script_doc.get("collector_type"),
            "target_url": script_doc.get("target_url"),
            "captured_at": self.storage.now_iso(),
            "is_baseline": False,
            "status_code": live_result.status_code,
            "response_time_ms": live_result.response_time_ms,
            "final_url": live_result.final_url or script_doc.get("target_url"),
            "live_status": live_result.live_status,
            "reachable": live_result.reachable,
            "fetch_strategy": live_result.fetch_strategy,
            "error": live_result.error,
            "html_sha256": current_hash,
            "html_size": len(html.encode("utf-8", errors="ignore")),
            "summary": current_summary,
            "selector_results": selector_health.results,
            "selector_health_score": selector_health.selector_health_score,
            "snapshot_path": latest_snapshot_path,
            "data_count": validation_result["data_count"],
            "parse_status": validation_result["parse_status"],
            "parse_error": validation_result["parse_error"],
        }
        self.storage.save_snapshot(snapshot_doc)
        latest_snapshot = self.storage.latest_snapshot(script_id)
        if not baseline_snapshot or (
            validation_result["data_count"] > 0
            and live_result.is_live
            and latest_snapshot is not None
        ):
            self.storage.promote_baseline(script_id, latest_snapshot["_id"])
            baseline_snapshot = latest_snapshot
            baseline_selector_results = (baseline_snapshot or {}).get("selector_results") or selector_health.results

        source_path = Path(script_doc["script_path"])
        repair_preview = generate_repair_preview(
            script_doc,
            source_path,
            html,
            baseline_selector_results,
            selector_health.results,
        )

        if repair_preview.repair_candidate_exists:
            try:
                source_text = source_path.read_text(encoding="utf-8", errors="ignore")
                patched_source = source_text
                for mapping in repair_preview.changed_selector_mappings:
                    old_selector = str(mapping.get("old_selector") or "")
                    new_selector = str(mapping.get("new_selector") or "")
                    if old_selector and new_selector and old_selector in patched_source:
                        patched_source = patched_source.replace(old_selector, new_selector, 1)
                repair_preview.candidate_patch_path = self.storage.save_candidate_patch(script_id, patched_source)
            except OSError:
                repair_preview.candidate_patch_path = ""
            self.storage.save_repair_metadata(
                script_id,
                {
                    "script_id": script_id,
                    "script_name": script_doc.get("script_name"),
                    "collector_name": script_doc.get("collector_name"),
                    "repair_candidate_exists": repair_preview.repair_candidate_exists,
                    "repair_confidence": repair_preview.repair_confidence,
                    "failed_selectors": repair_preview.failed_selectors,
                    "suggested_selectors": repair_preview.suggested_selectors,
                    "changed_selector_mappings": repair_preview.changed_selector_mappings,
                    "candidate_patch_path": repair_preview.candidate_patch_path,
                    "preview_message": repair_preview.preview_message,
                },
            )

        status = self._derive_status(live_result, validation_result, drift, repair_preview, selector_health)
        message = self._build_status_message(script_doc, live_result, validation_result, drift, repair_preview, selector_health)

        inc_fields = {
            "total_runs": 1,
            "success_runs": 1 if status == "healthy" else 0,
            "failed_runs": 0 if status == "healthy" else 1,
            "non_empty_runs": 1 if validation_result["data_count"] > 0 else 0,
        }
        update_fields = {
            "status": status,
            "live_status": live_result.live_status,
            "html_change_status": drift.html_change_status,
            "selector_health_score": selector_health.selector_health_score,
            "last_data_count": validation_result["data_count"],
            "mongo_document_count": self.storage.raw_document_count(
                script_doc.get("collector_name") or "",
                script_doc.get("source_name") or "",
            ),
            "last_success_time": self.storage.now_iso() if status == "healthy" else script_doc.get("last_success_time"),
            "last_failure_time": self.storage.now_iso() if status != "healthy" else script_doc.get("last_failure_time"),
            "last_non_empty_data_time": self.storage.now_iso() if validation_result["data_count"] > 0 else script_doc.get("last_non_empty_data_time"),
            "baseline_snapshot_path": (baseline_snapshot or {}).get("snapshot_path") or latest_snapshot_path,
            "latest_snapshot_path": latest_snapshot_path,
            "diff_summary": drift.diff_summary,
            "changed_components": drift.changed_components,
            "failed_selectors": selector_health.failed_selectors,
            "suggested_selectors": repair_preview.suggested_selectors,
            "repair_candidate_exists": repair_preview.repair_candidate_exists,
            "repair_confidence": repair_preview.repair_confidence,
            "last_event_message": message,
            "last_response_code": live_result.status_code,
            "last_response_time_ms": live_result.response_time_ms,
            "last_final_url": live_result.final_url,
            "last_parse_error": validation_result["parse_error"],
            "last_checked_at": self.storage.now_iso(),
            "last_checked_mode": run_mode,
            "structure_similarity": drift.structure_similarity,
            "selector_total_count": selector_health.total_selectors,
            "selector_matched_count": selector_health.matched_selectors,
            "selector_broken_count": len(selector_health.failed_selectors),
            "selector_fix_count": len(repair_preview.changed_selector_mappings),
            "last_selector_suggestions": repair_preview.suggested_selectors[:5],
            "last_summary_changes": drift.diff_summary[:5],
            "last_live_fetch_strategy": live_result.fetch_strategy,
        }
        self.storage.update_script_runtime(script_id, update_fields, inc_fields)

        event_doc = {
            "script_id": script_id,
            "target_key": script_doc.get("target_key"),
            "script_name": script_doc.get("script_name"),
            "collector_name": script_doc.get("collector_name"),
            "collector_type": script_doc.get("collector_type"),
            "created_at": self.storage.now_iso(),
            "status": status,
            "live_status": live_result.live_status,
            "html_change_status": drift.html_change_status,
            "message": message,
            "summary_changes": drift.diff_summary,
            "changed_components": drift.changed_components,
            "selector_suggestions": repair_preview.suggested_selectors,
            "broken_selectors": selector_health.failed_selectors,
            "repair_confidence": repair_preview.repair_confidence,
            "response_code": live_result.status_code,
            "response_time_ms": live_result.response_time_ms,
            "data_count": validation_result["data_count"],
            "parse_error": validation_result["parse_error"],
            "structure_similarity": drift.structure_similarity,
        }
        self.storage.save_event(event_doc)

        return {
            "script_id": script_id,
            "status": status,
            "message": message,
            "live_status": live_result.live_status,
            "html_change_status": drift.html_change_status,
            "selector_health_score": selector_health.selector_health_score,
            "repair_confidence": repair_preview.repair_confidence,
            "data_count": validation_result["data_count"],
        }

    def _run_script_validation(self, script_doc: dict[str, Any]) -> dict[str, Any]:
        module_import_path = script_doc.get("module_import_path") or ""
        class_name = script_doc.get("class_name") or script_doc.get("script_name")
        if not module_import_path or not class_name:
            return {"parse_status": "error", "parse_error": "Missing module/class metadata.", "data_count": 0}
        try:
            importlib.invalidate_caches()
            module = importlib.import_module(module_import_path)
            module = importlib.reload(module)
            cls = getattr(module, class_name, None)
            if cls is None:
                return {"parse_status": "error", "parse_error": f"Collector class `{class_name}` not found.", "data_count": 0}
            model = cls()
            if hasattr(model, "set_limits"):
                try:
                    model.set_limits(max_pages=1, max_articles=8)
                except Exception:
                    pass
            result = RequestParser(
                proxy=cfg.proxy,
                model=model,
                reset_cache=True,
                strict=False,
                seed_fetch=False,
                playwright_timeout=15_000,
            ).parse()
            meta = result.get("meta") or {}
            data_count = int(meta.get("count") or 0)
            return {
                "parse_status": str(meta.get("status") or "failed"),
                "parse_error": str(meta.get("error") or ""),
                "data_count": data_count,
            }
        except Exception as exc:
            return {"parse_status": "error", "parse_error": str(exc), "data_count": 0}

    def _derive_status(
        self,
        live_result,
        validation_result: dict[str, Any],
        drift,
        repair_preview,
        selector_health,
    ) -> str:
        if validation_result["data_count"] > 0:
            return "healthy"
        if live_result.live_status in UNREACHABLE_LIVE_STATES or not live_result.reachable:
            return "target_unreachable"
        if drift.html_change_status == "major_change":
            if repair_preview.repair_candidate_exists and repair_preview.repair_confidence >= 0.72:
                return "repair_ready"
            return "html_changed"
        if selector_health.selector_health_score is not None and selector_health.selector_health_score < 35:
            if repair_preview.repair_candidate_exists:
                return "repair_ready"
            return "needs_review"
        if validation_result["parse_error"]:
            return "needs_review"
        return "no_data"

    def _build_status_message(
        self,
        script_doc: dict[str, Any],
        live_result,
        validation_result: dict[str, Any],
        drift,
        repair_preview,
        selector_health,
    ) -> str:
        if validation_result["data_count"] > 0:
            return f"{script_doc.get('script_name')} returned {validation_result['data_count']} record(s)."
        if live_result.live_status in UNREACHABLE_LIVE_STATES or not live_result.reachable:
            return f"{script_doc.get('target_domain') or script_doc.get('target_url')} is unreachable: {live_result.error or live_result.live_status}."
        if drift.html_change_status == "major_change":
            return (
                f"Live target responded but the DOM changed heavily. "
                f"Selector health is {selector_health.selector_health_score or 0}%."
            )
        if repair_preview.repair_candidate_exists:
            return (
                f"Live target responded but selectors drifted. "
                f"Repair preview is ready at {repair_preview.repair_confidence:.2f} confidence."
            )
        if validation_result["parse_error"]:
            return f"Script validation failed while the target stayed live: {validation_result['parse_error']}"
        return "Target is live, but the script returned no records in test mode."
