from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pymongo.errors import DuplicateKeyError

from config import cfg
from mongo_persistence import RAW_COLLECTIONS, get_db


REPAIR_ROOT = Path("data/healing/repairs")
BACKUP_ROOT = Path("data/healing/backups")


class HealingStorage:
    def __init__(self) -> None:
        self.db = get_db()
        self.scripts = self.db["healing_targets"]
        self.snapshots = self.db["healing_snapshots"]
        self.events = self.db["healing_events"]
        self.repairs = self.db["healing_repairs"]
        self.runtime = self.db["healing_runtime"]
        REPAIR_ROOT.mkdir(parents=True, exist_ok=True)
        BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
        self._migrate_legacy_script_documents()
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        try:
            self.scripts.create_index("script_id", unique=True)
        except DuplicateKeyError:
            self._deduplicate_script_documents()
            self.scripts.create_index("script_id", unique=True)
        self.scripts.create_index([("collector_name", 1), ("status", 1)])
        self.scripts.create_index([("is_monitorable", 1), ("active", 1)])
        self.scripts.create_index([("target_domain", 1)])
        self.snapshots.create_index([("script_id", 1), ("captured_at", -1)])
        self.snapshots.create_index([("script_id", 1), ("is_baseline", 1)])
        self.events.create_index([("script_id", 1), ("created_at", -1)])
        self.events.create_index([("created_at", -1)])
        self.repairs.create_index([("script_id", 1), ("created_at", -1)])
        self.runtime.create_index([("updated_at", -1)])

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _normalise_script_path(path_value: str) -> str:
        return str(path_value or "").strip().lstrip("./")

    @classmethod
    def _script_id_from_path(cls, path_value: str) -> str:
        path_value = cls._normalise_script_path(path_value)
        return path_value.replace("/", "__").replace(".", "_").lower()

    @classmethod
    def _target_key_from_path(cls, path_value: str) -> str:
        path_value = cls._normalise_script_path(path_value)
        return path_value.replace("/", "_").replace(".", "_").lower()

    def _migrate_legacy_script_documents(self) -> None:
        cursor = self.scripts.find(
            {
                "$or": [
                    {"script_id": {"$exists": False}},
                    {"script_id": None},
                    {"script_id": ""},
                ]
            }
        )
        for doc in cursor:
            raw_path = doc.get("script_path") or doc.get("file_path") or ""
            script_path = self._normalise_script_path(raw_path)
            if not script_path:
                self.scripts.delete_one({"_id": doc["_id"]})
                continue
            path_obj = Path(script_path)
            script_name = str(doc.get("script_name") or path_obj.stem)
            collector_name = str(doc.get("collector_name") or doc.get("collector_type") or "")
            target_url = str(doc.get("target_url") or "")
            target_domain = str(doc.get("target_domain") or doc.get("domain") or "")
            payload = {
                "script_id": self._script_id_from_path(script_path),
                "script_path": script_path,
                "script_file": str(doc.get("script_file") or path_obj.name),
                "script_name": script_name,
                "class_name": str(doc.get("class_name") or script_name),
                "source_name": str(doc.get("source_name") or script_name.lstrip("_")),
                "collector_name": collector_name,
                "collector_type": str(doc.get("collector_type") or collector_name),
                "script_type": str(doc.get("script_type") or collector_name),
                "module_import_path": str(
                    doc.get("module_import_path") or script_path[:-3].replace("/", ".")
                ),
                "target_key": str(doc.get("target_key") or self._target_key_from_path(script_path)),
                "domain": target_domain,
                "target_domain": target_domain,
                "probable_target_url": str(doc.get("probable_target_url") or target_url),
                "is_monitorable": bool(doc.get("is_monitorable", doc.get("active", False))),
                "active": bool(doc.get("active", True)),
                "updated_at": doc.get("updated_at") or self.now_iso(),
            }
            self.scripts.update_one({"_id": doc["_id"]}, {"$set": payload})

    def _deduplicate_script_documents(self) -> None:
        pipeline = [
            {
                "$group": {
                    "_id": "$script_id",
                    "ids": {"$push": "$_id"},
                    "count": {"$sum": 1},
                }
            },
            {"$match": {"count": {"$gt": 1}}},
        ]
        duplicates = list(self.scripts.aggregate(pipeline))
        for row in duplicates:
            script_id = row.get("_id")
            ids = row.get("ids") or []
            if not script_id:
                self.scripts.delete_many({"_id": {"$in": ids}})
                continue
            keep_doc = self.scripts.find_one(
                {"script_id": script_id},
                sort=[("updated_at", -1), ("discovered_at", -1), ("_id", -1)],
            )
            keep_id = keep_doc["_id"] if keep_doc else None
            drop_ids = [doc_id for doc_id in ids if doc_id != keep_id]
            if drop_ids:
                self.scripts.delete_many({"_id": {"$in": drop_ids}})

    def upsert_script(self, script_doc: dict[str, Any]) -> None:
        now = self.now_iso()
        payload = {
            **script_doc,
            "updated_at": now,
        }
        self.scripts.update_one(
            {"script_id": script_doc["script_id"]},
            {
                "$set": payload,
                "$setOnInsert": {
                    "discovered_at": now,
                    "status": "skipped" if not script_doc.get("is_monitorable") else "discovered",
                    "live_status": "not_checked",
                    "html_change_status": "not_checked",
                    "selector_health_score": None,
                    "total_runs": 0,
                    "success_runs": 0,
                    "failed_runs": 0,
                    "non_empty_runs": 0,
                    "last_data_count": 0,
                    "mongo_document_count": 0,
                    "last_success_time": None,
                    "last_failure_time": None,
                    "last_non_empty_data_time": None,
                    "baseline_snapshot_path": "",
                    "latest_snapshot_path": "",
                    "diff_summary": [],
                    "changed_components": [],
                    "failed_selectors": [],
                    "suggested_selectors": [],
                    "repair_candidate_exists": False,
                    "repair_confidence": 0.0,
                    "last_event_message": "",
                    "last_response_code": None,
                    "last_response_time_ms": 0,
                    "last_final_url": "",
                    "last_parse_error": "",
                    "last_checked_at": None,
                    "last_checked_mode": "",
                },
            },
            upsert=True,
        )

    def mark_missing_scripts_inactive(self, active_script_ids: set[str]) -> None:
        self.scripts.update_many(
            {"script_id": {"$nin": list(active_script_ids)}},
            {
                "$set": {
                    "active": False,
                    "updated_at": self.now_iso(),
                }
            },
        )

    def get_script(self, script_id: str) -> dict[str, Any] | None:
        return self.scripts.find_one({"script_id": script_id}, {"_id": 0})

    def list_scripts(
        self,
        *,
        limit: int = 200,
        offset: int = 0,
        collector_name: str = "",
        status: str = "",
        only_monitorable: bool = False,
    ) -> list[dict[str, Any]]:
        query: dict[str, Any] = {}
        if collector_name:
            query["collector_name"] = collector_name
        if status:
            query["status"] = status
        if only_monitorable:
            query["is_monitorable"] = True
        cursor = (
            self.scripts.find(query, {"_id": 0})
            .sort([("collector_name", 1), ("is_monitorable", -1), ("status", 1), ("script_name", 1)])
            .skip(int(offset))
            .limit(int(limit))
        )
        return list(cursor)

    def list_target_scripts(self, *, limit: int = 100, collector_name: str = "") -> list[dict[str, Any]]:
        query: dict[str, Any] = {"is_monitorable": True, "active": {"$ne": False}}
        if collector_name:
            query["collector_name"] = collector_name
        cursor = (
            self.scripts.find(query, {"_id": 0})
            .sort([("last_checked_at", 1), ("status", 1), ("script_name", 1)])
            .limit(int(limit))
        )
        return list(cursor)

    def update_script_runtime(self, script_id: str, update_fields: dict[str, Any], inc_fields: dict[str, int] | None = None) -> None:
        update_doc: dict[str, Any] = {"$set": {**update_fields, "updated_at": self.now_iso()}}
        if inc_fields:
            update_doc["$inc"] = inc_fields
        self.scripts.update_one({"script_id": script_id}, update_doc)

    def save_snapshot(self, snapshot_doc: dict[str, Any]) -> None:
        self.snapshots.insert_one(snapshot_doc)

    def latest_snapshot(self, script_id: str) -> dict[str, Any] | None:
        return self.snapshots.find_one({"script_id": script_id}, sort=[("captured_at", -1)])

    def baseline_snapshot(self, script_id: str) -> dict[str, Any] | None:
        return self.snapshots.find_one({"script_id": script_id, "is_baseline": True}, sort=[("captured_at", -1)])

    def promote_baseline(self, script_id: str, snapshot_id) -> None:
        self.snapshots.update_many({"script_id": script_id, "is_baseline": True}, {"$set": {"is_baseline": False}})
        self.snapshots.update_one({"_id": snapshot_id}, {"$set": {"is_baseline": True}})

    def save_event(self, event_doc: dict[str, Any]) -> None:
        self.events.insert_one(event_doc)

    def list_events(self, *, limit: int = 50, script_id: str = "") -> list[dict[str, Any]]:
        query = {"script_id": script_id} if script_id else {}
        cursor = self.events.find(query, {"_id": 0}).sort([("created_at", -1)]).limit(int(limit))
        return list(cursor)

    def save_repair_record(self, repair_doc: dict[str, Any]) -> Any:
        return self.repairs.insert_one(repair_doc)

    def latest_repair(self, script_id: str) -> dict[str, Any] | None:
        return self.repairs.find_one({"script_id": script_id}, sort=[("created_at", -1)])

    def update_repair_record(self, repair_id, update_fields: dict[str, Any]) -> None:
        self.repairs.update_one({"_id": repair_id}, {"$set": {**update_fields, "updated_at": self.now_iso()}})

    def update_runtime(self, key: str, payload: dict[str, Any]) -> None:
        self.runtime.update_one(
            {"_id": key},
            {"$set": {**payload, "updated_at": self.now_iso()}},
            upsert=True,
        )

    def get_runtime(self, key: str) -> dict[str, Any]:
        return self.runtime.find_one({"_id": key}, {"_id": 0}) or {}

    def raw_document_count(self, collector_name: str, source_name: str) -> int:
        collection_info = RAW_COLLECTIONS.get(collector_name)
        if not collection_info:
            return 0
        collection_name = collection_info[0]
        return self.db[collection_name].count_documents({"source_name": source_name})

    def collector_breakdown(self) -> list[dict[str, Any]]:
        pipeline = [
            {
                "$group": {
                    "_id": "$collector_name",
                    "total_scripts": {"$sum": 1},
                    "monitorable_scripts": {
                        "$sum": {"$cond": [{"$eq": ["$is_monitorable", True]}, 1, 0]}
                    },
                    "healthy_count": {
                        "$sum": {"$cond": [{"$eq": ["$status", "healthy"]}, 1, 0]}
                    },
                    "failing_count": {
                        "$sum": {
                            "$cond": [
                                {
                                    "$in": [
                                        "$status",
                                        ["no_data", "target_unreachable", "html_changed", "repair_ready", "needs_review", "error"],
                                    ]
                                },
                                1,
                                0,
                            ]
                        }
                    },
                    "skipped_count": {
                        "$sum": {"$cond": [{"$eq": ["$status", "skipped"]}, 1, 0]}
                    },
                }
            },
            {"$sort": {"_id": 1}},
        ]
        rows = list(self.scripts.aggregate(pipeline))
        return [
            {
                "collector_name": row["_id"],
                "total_scripts": row.get("total_scripts", 0),
                "monitorable_scripts": row.get("monitorable_scripts", 0),
                "healthy_count": row.get("healthy_count", 0),
                "failing_count": row.get("failing_count", 0),
                "skipped_count": row.get("skipped_count", 0),
            }
            for row in rows
        ]

    def save_candidate_patch(self, script_id: str, patched_source: str, *, label: str = "candidate") -> str:
        script_dir = REPAIR_ROOT / script_id
        script_dir.mkdir(parents=True, exist_ok=True)
        path = script_dir / f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{label}.py"
        path.write_text(patched_source, encoding="utf-8", errors="ignore")
        return str(path)

    def save_repair_metadata(self, script_id: str, payload: dict[str, Any]) -> str:
        script_dir = REPAIR_ROOT / script_id
        script_dir.mkdir(parents=True, exist_ok=True)
        path = script_dir / f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_repair.json"
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(path)

    def create_backup(self, script_id: str, source_path: Path) -> str:
        script_dir = BACKUP_ROOT / script_id
        script_dir.mkdir(parents=True, exist_ok=True)
        path = script_dir / f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{source_path.name}.bak"
        path.write_text(source_path.read_text(encoding="utf-8", errors="ignore"), encoding="utf-8")
        return str(path)
