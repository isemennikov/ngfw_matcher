"""FastAPI dependencies: session helpers, matcher resolution."""
from __future__ import annotations

from fastapi import HTTPException, Request

from . import db, state
from ..core.matcher import RuleMatcher
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

    return {
        "devices": devices,
        "selected_dev": selected_dev,
        "offline_snap_name": request.session.get("offline_snap_name"),
        "offline_snap_active": bool(request.session.get("offline_snap")),
        "app_version": __version__,
    }


def has_data_source(request: Request) -> bool:
    """True если есть либо выбранное устройство, либо оффлайн-снапшот."""
    return bool(request.session.get("selected_device") or request.session.get("offline_snap"))


def require_matcher(request: Request, strict: bool = True) -> RuleMatcher:
    # Приоритет 1: загруженный пользователем JSON-снапшот (оффлайн-режим)
    offline = request.session.get("offline_snap")
    if offline:
        try:
            return state.load_matcher(offline, strict=strict)
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
        return state.load_matcher(snap, strict=strict)
    except FileNotFoundError:
        raise HTTPException(status_code=400,
                            detail="Snapshot file missing — run Sync again")
