"""FastAPI dependencies: session helpers, matcher resolution."""
from __future__ import annotations

import json
from datetime import datetime

from fastapi import HTTPException, Request
from fastapi.responses import Response

from . import db, state
from ..core.matcher import RuleMatcher
from ..core.snapshot import list_groups, is_multi
from .._version import __version__


def session(request: Request) -> dict:
    return request.session


def require_connection(request: Request) -> dict:
    s = request.session
    if not s.get("host"):
        raise HTTPException(status_code=401, detail="Not connected")
    return s


def require_device(request: Request) -> str:
    s = request.session
    device_id = s.get("selected_device")
    if not device_id:
        raise HTTPException(status_code=400, detail="No device selected")
    return device_id


def base_ctx(request: Request) -> dict:
    """Sidebar context — always passed to full-page templates."""
    host = request.session.get("host")
    raw = db.get_all_devices(host=host)
    selected_id = request.session.get("selected_device")
    selected_dev = db.get_device(selected_id) if selected_id else None

    devices = []
    for d in raw:
        path = d.get("path") or d.get("name", "")
        depth = path.count(" / ")
        devices.append({**d, "depth": depth})

    for i, d in enumerate(devices):
        depth = d["depth"]
        if depth == 0:
            d["is_last"] = False
            continue
        is_last = True
        for j in range(i + 1, len(devices)):
            next_depth = devices[j]["depth"]
            if next_depth < depth:
                break
            if next_depth == depth:
                is_last = False
                break
        d["is_last"] = is_last

    # Группы внутри оффлайн multi-снапшота (глобальная загрузка JSON) — селектор
    # нужен только здесь: выбор группы устройств из дерева сам по себе уже
    # выбирает нужную группу правил при работе через синхронизацию с СУ.
    snap_groups: list[dict] = []
    active_group_id = request.session.get("active_group_id")
    offline_snap = request.session.get("offline_snap")
    if offline_snap:
        try:
            with open(offline_snap, encoding="utf-8") as f:
                snap = json.load(f)
            if is_multi(snap):
                snap_groups = list_groups(snap)
                if not active_group_id and snap_groups:
                    active_group_id = snap_groups[0]["id"]
        except Exception:
            pass

    return {
        "devices":            devices,
        "selected_dev":       selected_dev,
        "offline_snap_name":  request.session.get("offline_snap_name"),
        "offline_snap_active": bool(offline_snap),
        "app_version":        __version__,
        "snap_groups":        snap_groups,
        "active_group_id":    active_group_id,
        "include_parent_groups": get_include_parents(request),
    }


def has_data_source(request: Request) -> bool:
    """True если есть либо выбранное устройство, либо оффлайн-снапшот."""
    return bool(request.session.get("selected_device") or request.session.get("offline_snap"))


def json_download(data: dict, prefix: str) -> Response:
    """Вернуть dict как скачиваемый JSON-файл с именем prefix_YYYYMMDD_HHMMSS.json."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{prefix}_{ts}.json"
    content  = json.dumps(data, ensure_ascii=False, indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def get_active_group_id(request: Request) -> str | None:
    """Активная группа правил.

    Для оффлайн multi-снапшота (глобальная загрузка JSON) — это отдельный выбор
    пользователя (see base_ctx). Во всех остальных случаях группа правил — это
    просто выбранная в дереве группа устройств, отдельный селектор не нужен.
    """
    if request.session.get("offline_snap"):
        return request.session.get("active_group_id")
    return request.session.get("selected_device")


def get_include_parents(request: Request) -> bool:
    """Учитывать ли pre/post-правила родительских групп по цепочке до корня.

    Включено по умолчанию — так матчинг отражает реальную эффективную политику
    устройства (родительские pre/post-правила физически участвуют в матчинге
    трафика), а не только локальные правила выбранной группы.
    """
    return bool(request.session.get("include_parent_groups", True))


def require_snapshot_path(request: Request) -> str:
    """Возвращает путь к снапшоту (offline или device), или кидает HTTPException."""
    offline = request.session.get("offline_snap")
    if offline:
        return offline
    device_id = request.session.get("selected_device")
    if not device_id:
        raise HTTPException(status_code=400, detail="No device selected")
    device = db.get_device(device_id)
    if not device or not device.get("snapshot_path"):
        raise HTTPException(status_code=400, detail="Snapshot not found — run Sync first")
    return device["snapshot_path"]


def require_matcher(request: Request, strict: bool = True) -> RuleMatcher:
    group_id = get_active_group_id(request)
    include_parents = get_include_parents(request)

    # Приоритет 1: загруженный пользователем JSON-снапшот (оффлайн-режим)
    offline = request.session.get("offline_snap")
    if offline:
        try:
            return state.load_matcher(offline, strict=strict, group_id=group_id,
                                      include_parents=include_parents)
        except FileNotFoundError:
            request.session.pop("offline_snap", None)
            request.session.pop("offline_snap_name", None)
            raise HTTPException(status_code=400,
                                detail="Snapshot file not found — upload again")

    # Приоритет 2: снапшот выбранного устройства (после Sync)
    device_id = require_device(request)
    device = db.get_device(device_id)
    if not device or not device.get("snapshot_path"):
        raise HTTPException(status_code=400,
                            detail="Snapshot not found — run Sync first")
    snap = device["snapshot_path"]
    try:
        return state.load_matcher(snap, strict=strict, group_id=group_id,
                                  include_parents=include_parents)
    except FileNotFoundError:
        raise HTTPException(status_code=400,
                            detail="Snapshot file missing — run Sync again")
