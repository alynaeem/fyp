from __future__ import annotations

import asyncio
from typing import Callable

from fastapi import APIRouter, Depends, Query, Request

from .status_service import get_healing_service


def build_healing_router(get_current_user_dep: Callable, admin_required_dep: Callable) -> APIRouter:
    router = APIRouter(prefix="/api/healing", tags=["healing"])

    @router.get("/summary")
    async def healing_summary(current_user: dict = Depends(get_current_user_dep)):
        summary = await asyncio.to_thread(get_healing_service().get_summary)
        return {"status": "ok", "summary": summary}

    @router.get("/collectors")
    async def healing_collectors(current_user: dict = Depends(get_current_user_dep)):
        collectors = await asyncio.to_thread(get_healing_service().list_collectors)
        return {"status": "ok", "count": len(collectors), "items": collectors}

    @router.get("/scripts")
    async def healing_scripts(
        limit: int = Query(160, ge=1, le=1000),
        offset: int = Query(0, ge=0),
        collector: str = Query(""),
        status: str = Query(""),
        monitorable_only: bool = Query(False),
        current_user: dict = Depends(get_current_user_dep),
    ):
        payload = await asyncio.to_thread(
            get_healing_service().list_scripts,
            limit=limit,
            offset=offset,
            collector_name=collector.strip(),
            status=status.strip(),
            only_monitorable=monitorable_only,
        )
        return {"status": "ok", **payload}

    @router.get("/targets")
    async def healing_targets(
        limit: int = Query(80, ge=1, le=500),
        current_user: dict = Depends(get_current_user_dep),
    ):
        items = await asyncio.to_thread(get_healing_service().list_targets, limit=limit)
        return {"status": "ok", "count": len(items), "items": items}

    @router.get("/script/{script_id}")
    async def healing_script_detail(script_id: str, current_user: dict = Depends(get_current_user_dep)):
        payload = await asyncio.to_thread(get_healing_service().get_script_detail, script_id)
        return payload

    @router.get("/events")
    async def healing_events(
        limit: int = Query(40, ge=1, le=300),
        script_id: str = Query(""),
        current_user: dict = Depends(get_current_user_dep),
    ):
        items = await asyncio.to_thread(
            get_healing_service().list_events,
            limit=limit,
            target_key=script_id.strip() or None,
        )
        return {"status": "ok", "count": len(items), "items": items}

    @router.post("/run", dependencies=[Depends(admin_required_dep)])
    async def healing_run(request: Request):
        body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
        payload = await asyncio.to_thread(
            get_healing_service().run_monitor,
            limit=body.get("limit"),
            collector_name=(body.get("collector_name") or "").strip() or None,
            mode=(body.get("mode") or "default").strip() or "default",
            auto_heal=bool(body.get("auto_heal", False)),
            dry_run_repair=bool(body.get("dry_run_repair", True)),
        )
        return {"message": f"Healing run completed for {payload.get('target_count', 0)} scripts.", **payload}

    @router.post("/check/{script_id}", dependencies=[Depends(admin_required_dep)])
    async def healing_check(script_id: str):
        payload = await asyncio.to_thread(get_healing_service().run_target_check, script_id)
        return {"message": f"Healing check finished for {script_id}.", **payload}

    @router.post("/repair/{script_id}", dependencies=[Depends(admin_required_dep)])
    async def healing_repair(script_id: str):
        payload = await asyncio.to_thread(get_healing_service().generate_repair, script_id)
        return payload

    @router.post("/apply-repair/{script_id}", dependencies=[Depends(admin_required_dep)])
    async def healing_apply_repair(script_id: str):
        payload = await asyncio.to_thread(get_healing_service().apply_repair, script_id)
        return payload

    return router
