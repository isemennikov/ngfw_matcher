# Developed by Ilya Semennikov

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import re

from fastapi import APIRouter, BackgroundTasks, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from .. import db, state
from ..deps import require_connection

router = APIRouter()
templates: Jinja2Templates = None  # injected from main

SNAP_DIR = Path(__file__).parent.parent.parent / "data" / "snapshots"
SNAP_DIR.mkdir(parents=True, exist_ok=True)


@router.post("/devices/select/{device_id}")
async def select_device(device_id: str, request: Request):
    _ = require_connection(request)
    request.session["selected_device"] = device_id
    return RedirectResponse("/", status_code=303)


@router.post("/devices/sync/{device_id}", response_class=HTMLResponse)
async def start_sync(
    device_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
):
    sess = require_connection(request)
    job_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    db.create_sync_job(job_id, device_id, now)

    background_tasks.add_task(
        _run_sync,
        job_id=job_id,
        device_id=device_id,
        host=sess["host"],
        token=sess["token"],
    )
    return templates.TemplateResponse(request, "partials/sync_status.html", {
        "job_id": job_id,
        "device_id": device_id,
        "status": "running",
        "message": "Загружаем правила…",
    })


@router.get("/devices/sync/{job_id}/status", response_class=HTMLResponse)
async def sync_status(job_id: str, request: Request):
    job = db.get_sync_job(job_id)
    if not job:
        return HTMLResponse("<span>job not found</span>")

    device = db.get_device(job["device_id"]) if job else {}
    return templates.TemplateResponse(request, "partials/sync_status.html", {
        "job_id": job_id,
        "device_id": job["device_id"],
        "status": job["status"],
        "message": job.get("error") or _status_msg(job["status"], device),
        "device": device,
    })


def _status_msg(status: str, device: dict) -> str:
    if status == "running":
        return "Загружаем правила из СУ…"
    if status == "done":
        n = (device or {}).get("rules_count", 0)
        ts = (device or {}).get("last_sync", "")[:16].replace("T", " ")
        return f"Синхронизировано: {n} правил  ·  {ts}"
    return "Ошибка синхронизации"


@router.post("/devices/{device_id}/snapshot-upload", response_class=HTMLResponse)
async def upload_device_snapshot(
    device_id: str, request: Request, file: UploadFile = File(...)
):
    device = db.get_device(device_id)
    if not device:
        return HTMLResponse("<span class='text-red-400 text-xs'>Устройство не найдено</span>")

    if not file.filename.endswith(".json"):
        return HTMLResponse("<span class='text-red-400 text-xs'>Только .json файлы</span>")

    data = await file.read()
    try:
        parsed = json.loads(data)
        n_rules = len(parsed.get("rules") or [])
        if n_rules == 0:
            raise ValueError("нет правил")
    except Exception as e:
        return HTMLResponse(f"<span class='text-red-400 text-xs'>Некорректный файл: {e}</span>")

    snap_path = SNAP_DIR / f"{device_id}.json"
    snap_path.write_bytes(data)

    state.invalidate(str(snap_path))
    now = datetime.now(timezone.utc).isoformat()
    db.update_device_snapshot(device_id, str(snap_path), now, n_rules)

    resp = Response(
        content=f"<span class='text-green-400 text-xs'>✓ {n_rules} правил загружено из файла</span>",
        media_type="text/html",
        headers={"HX-Refresh": "true"},
    )
    return resp


@router.get("/devices/{device_id}/snapshot-download")
async def download_device_snapshot(device_id: str):
    device = db.get_device(device_id)
    if not device or not device.get("snapshot_path"):
        return HTMLResponse("<span class='text-red-400 text-xs'>Снапшот не найден</span>", status_code=404)

    snap_path = Path(device["snapshot_path"])
    if not snap_path.exists():
        return HTMLResponse("<span class='text-red-400 text-xs'>Файл снапшота не найден</span>", status_code=404)

    raw_name = device.get("name") or device_id
    safe_name = re.sub(r"[^\w\-]", "_", raw_name).strip("_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"state_{safe_name}_{ts}.json"

    return FileResponse(
        path=str(snap_path),
        media_type="application/json",
        filename=filename,
    )


async def _run_sync(job_id: str, device_id: str, host: str, token: str):
    from ...sources.ngfw_api import NGFWDirectSource
    from ...cli.main import _normalize_rule
    from ...core.resolver import ObjectResolver

    finished = datetime.now(timezone.utc).isoformat()
    try:
        src = NGFWDirectSource(host=host, username="", password="",
                               token=token, verify_ssl=False)
        raw_rules = await asyncio.get_event_loop().run_in_executor(
            None, src.get_rules, device_id
        )

        # Группы — раскрываем рекурсивно
        net_groups: dict[str, list] = {}
        svc_groups: dict[str, list] = {}

        def _collect_net(gid):
            if gid in net_groups:
                return net_groups[gid]
            members = src.get_network_group_items(gid)
            net_groups[gid] = members
            for m in members:
                if "networkGroup" in m:
                    _collect_net(m["networkGroup"].get("id", ""))
            return members

        def _collect_svc(gid):
            if gid in svc_groups:
                return svc_groups[gid]
            members = src.get_service_group_items(gid)
            svc_groups[gid] = members
            for m in members:
                if "serviceGroup" in m:
                    _collect_svc(m["serviceGroup"].get("id", ""))
            return members

        for rule in raw_rules:
            for field in (rule.get("sourceAddr"), rule.get("destinationAddr")):
                if not field or field.get("kind") != "RULE_KIND_LIST":
                    continue
                for obj in (field.get("objects") or []):
                    if "networkGroup" in obj:
                        _collect_net(obj["networkGroup"].get("id", ""))
            svc = rule.get("service")
            if svc and svc.get("kind") == "RULE_KIND_LIST":
                for item in (svc.get("objects") or []):
                    if "serviceGroup" in item:
                        _collect_svc(item["serviceGroup"].get("id", ""))

        snap = {
            "_ngfw_matcher":    {"tool": "ngfw-matcher", "source": "web-sync"},
            "device_group_id": device_id,
            "captured_at":    datetime.now(timezone.utc).isoformat(),
            "rules_count":    len(raw_rules),
            "rules":          raw_rules,
            "net_groups":     net_groups,
            "svc_groups":     svc_groups,
        }

        snap_path = SNAP_DIR / f"{device_id}.json"
        snap_path.write_text(json.dumps(snap, ensure_ascii=False, indent=2),
                             encoding="utf-8")

        state.invalidate(str(snap_path))
        finished = datetime.now(timezone.utc).isoformat()
        db.update_device_snapshot(device_id, str(snap_path),
                                  finished, len(raw_rules))
        db.finish_sync_job(job_id, finished)

    except Exception as e:
        finished = datetime.now(timezone.utc).isoformat()
        db.finish_sync_job(job_id, finished, error=str(e))
