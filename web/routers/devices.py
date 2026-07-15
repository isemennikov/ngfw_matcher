from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import re

from fastapi import APIRouter, BackgroundTasks, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from .. import db, state
from ..deps import require_connection, base_ctx

router = APIRouter()
templates: Jinja2Templates = None  # injected from main

SNAP_DIR = Path(__file__).parent.parent.parent / "data" / "snapshots"
SNAP_DIR.mkdir(parents=True, exist_ok=True)


def _host_snapshot_path(host: str) -> Path:
    """Один файл-снапшот на всю СУ — общий для всех групп устройства."""
    slug = hashlib.sha1(host.encode()).hexdigest()[:16]
    return SNAP_DIR / f"host_{slug}.json"


@router.post("/devices/select/{device_id}")
async def select_device(device_id: str, request: Request):
    _ = require_connection(request)
    request.session["selected_device"] = device_id
    request.session.pop("active_group_id", None)  # сбрасываем выбор группы при смене устройства
    return RedirectResponse("/", status_code=303)


@router.post("/devices/group/{group_id}")
async def select_group(group_id: str, request: Request):
    """Выбор активной группы устройств из multi-снапшота."""
    request.session["active_group_id"] = group_id
    return RedirectResponse("/", status_code=303)


@router.post("/devices/include-parents")
async def set_include_parents(request: Request, enabled: str = Form("")):
    """Учитывать ли pre/post-правила родительских групп по цепочке до корня."""
    request.session["include_parent_groups"] = bool(enabled)
    return RedirectResponse("/", status_code=303)


@router.post("/devices/sync", response_class=HTMLResponse)
async def start_sync(
    request: Request,
    background_tasks: BackgroundTasks,
):
    sess = require_connection(request)
    job_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    db.create_sync_job(job_id, sess["host"], now)

    background_tasks.add_task(
        _run_sync,
        job_id=job_id,
        host=sess["host"],
        token=sess["token"],
    )
    return templates.TemplateResponse(request, "partials/sync_status.html", {
        "job_id": job_id,
        "status": "running",
        "message": "Загружаем правила…",
    })


@router.get("/devices/sync/{job_id}/status", response_class=HTMLResponse)
async def sync_status(job_id: str, request: Request):
    job = db.get_sync_job(job_id)
    if not job:
        return HTMLResponse("<span>job not found</span>")

    status = job["status"]
    error  = job.get("error") or ""

    ctx = {"job_id": job_id, "status": status, "detail": error}
    if status == "running":
        ctx["message"] = _status_msg(status, [])
    else:
        # done/error — подмешиваем свежее дерево устройств для OOB-обновления
        # сайдбара (см. partials/sync_status.html), без полной перезагрузки страницы
        ctx.update(base_ctx(request))
        ctx["message"] = error if status == "error" else _status_msg(status, ctx["devices"])

    return templates.TemplateResponse(request, "partials/sync_status.html", ctx)


def _status_msg(status: str, devices: list[dict]) -> str:
    if status == "running":
        return "Загружаем правила и NAT из СУ…"
    if status == "done":
        n_rules   = sum(d.get("rules_count", 0) for d in devices)
        ts_values = [d["last_sync"] for d in devices if d.get("last_sync")]
        ts = max(ts_values)[:16].replace("T", " ") if ts_values else ""
        return f"Синхронизировано: {n_rules} правил · {len(devices)} групп  ·  {ts}"
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


def _collect_objects(src, rules: list, nat_rules: list) -> tuple[dict, dict]:
    """Рекурсивно раскрываем все net/svc группы упомянутые в правилах."""
    net_groups: dict[str, list] = {}
    svc_groups: dict[str, list] = {}

    def _collect_net(gid):
        if gid in net_groups:
            return
        members = src.get_network_group_items(gid)
        net_groups[gid] = members
        for m in members:
            if "networkGroup" in m:
                _collect_net(m["networkGroup"].get("id", ""))

    def _collect_svc(gid):
        if gid in svc_groups:
            return
        members = src.get_service_group_items(gid)
        svc_groups[gid] = members
        for m in members:
            if "serviceGroup" in m:
                _collect_svc(m["serviceGroup"].get("id", ""))

    for rule in rules + nat_rules:
        for f in (rule.get("sourceAddr"), rule.get("destinationAddr"),
                  rule.get("srcTranslatedAddress"), rule.get("dstTranslatedAddress")):
            if not f or f.get("kind") != "RULE_KIND_LIST":
                continue
            for obj in (f.get("objects") or []):
                if "networkGroup" in obj:
                    _collect_net(obj["networkGroup"].get("id", ""))
        svc = rule.get("service")
        if svc and svc.get("kind") == "RULE_KIND_LIST":
            for item in (svc.get("objects") or []):
                if "serviceGroup" in item:
                    _collect_svc(item["serviceGroup"].get("id", ""))

    return net_groups, svc_groups


async def _fetch_group(loop, src, group: dict) -> tuple[str, dict]:
    """Параллельная загрузка правил и объектов для одной группы."""
    gid = group["id"]
    raw_rules, raw_nat = await asyncio.gather(
        loop.run_in_executor(None, src.get_rules, gid),
        loop.run_in_executor(None, src.get_nat_rules, gid),
    )
    net_groups, svc_groups = await loop.run_in_executor(
        None, _collect_objects, src, raw_rules, raw_nat
    )
    return gid, {
        "name":            group.get("name", gid),
        "path":            group.get("_path", ""),
        "depth":           group.get("_depth", 0),
        "rules_count":     len(raw_rules),
        "nat_rules_count": len(raw_nat),
        "rules":           raw_rules,
        "nat_rules":       raw_nat,
        "net_groups":      net_groups,
        "svc_groups":      svc_groups,
    }


async def _run_sync(job_id: str, host: str, token: str):
    from ...sources.ngfw_api import NGFWDirectSource

    finished = datetime.now(timezone.utc).isoformat()
    try:
        src  = NGFWDirectSource(host=host, username="", password="",
                                token=token, verify_ssl=False)
        loop = asyncio.get_event_loop()

        # Получаем всё дерево групп и параллельно грузим каждую — один раз на всю СУ
        groups = await loop.run_in_executor(None, src.get_device_groups)
        results = await asyncio.gather(*[
            _fetch_group(loop, src, g) for g in groups
        ])

        device_groups = {gid: data for gid, data in results}
        total_rules   = sum(d["rules_count"]     for d in device_groups.values())
        total_nat     = sum(d["nat_rules_count"]  for d in device_groups.values())

        snap = {
            "_ngfw_matcher":  {"tool": "ngfw-matcher", "format": "multi", "source": "web-sync"},
            "captured_at":  datetime.now(timezone.utc).isoformat(),
            "groups_count": len(device_groups),
            "rules_count":  total_rules,
            "nat_rules_count": total_nat,
            "tree":         groups,
            "device_groups": device_groups,
        }

        snap_path = _host_snapshot_path(host)
        snap_path.write_text(json.dumps(snap, ensure_ascii=False, indent=2),
                             encoding="utf-8")

        state.invalidate(str(snap_path))
        finished = datetime.now(timezone.utc).isoformat()
        rules_by_id = {gid: d["rules_count"] for gid, d in device_groups.items()}
        db.update_devices_snapshot_for_host(host, str(snap_path), finished, rules_by_id)
        db.finish_sync_job(job_id, finished)

    except Exception as e:
        finished = datetime.now(timezone.utc).isoformat()
        db.finish_sync_job(job_id, finished, error=str(e))
