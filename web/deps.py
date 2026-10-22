"""FastAPI dependencies: session helpers, matcher resolution."""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

from fastapi import HTTPException, Request, UploadFile
from fastapi.responses import Response

from . import db, state
from .config import MAX_UPLOAD_BYTES
from ..core.matcher import RuleMatcher
from ..core.snapshot import list_groups, is_multi
from .._version import __version__


_SAFE_NAME = re.compile(r"[A-Za-z0-9._-]{1,128}")


def session(request: Request) -> dict:
    return request.session


def get_theme(request: Request) -> str:
    """UI theme from cookie: 'light' | 'dark' | 'system' (default)."""
    t = request.cookies.get("theme", "system")
    return t if t in ("light", "dark", "system") else "system"


def safe_json_name(filename: str | None) -> str | None:
    """Basename-only, .json, restricted charset — blocks path traversal."""
    name = Path(filename or "").name
    if not name.lower().endswith(".json"):
        return None
    if not _SAFE_NAME.fullmatch(name):
        return None
    return name


def resolve_under(base: Path, name: str) -> Path | None:
    """Resolve base/name and ensure it stays inside base (defense in depth)."""
    base_r = base.resolve()
    candidate = (base_r / name).resolve()
    if candidate != base_r and base_r not in candidate.parents:
        return None
    return candidate


async def read_upload_limited(file: UploadFile, max_bytes: int = MAX_UPLOAD_BYTES) -> bytes:
    data = await file.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"Файл слишком большой (лимит {max_bytes // (1024 * 1024)} МБ)")
    return data


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


def _build_device_tree(raw: list[dict]) -> list[dict]:
    """Annotate devices with depth + is_last (single pass, O(n)).

    Узел не последний (is_last=False), если ниже есть строка той же глубины
    до того, как встретится строка меньшей глубины (граница группы).
    """
    devices = []
    for d in raw:
        path = d.get("path") or d.get("name", "")
        devices.append({**d, "depth": path.count(" / ")})

    n = len(devices)
    # next_sibling[i]: ближайший индекс j>i с depth[j]==depth[i] и без меньшей
    # глубины между ними (та же группа). n если sibling'а нет.
    next_sibling = [n] * n
    stack: list[int] = []
    for i in range(n):
        depth = devices[i]["depth"]
        while stack and devices[stack[-1]]["depth"] > depth:
            stack.pop()
        if stack and devices[stack[-1]]["depth"] == depth:
            next_sibling[stack[-1]] = i
            stack.pop()
        stack.append(i)

    for i, d in enumerate(devices):
        d["is_last"] = next_sibling[i] >= n if d["depth"] > 0 else False
        d["guides"] = _guides_for(devices, next_sibling, i)

    return devices


def _guides_for(devices: list[dict], next_sibling: list[int], i: int) -> list[bool]:
    """Для узла i: для каждого уровня 1..depth — есть ли ещё вертикаль.

    guides[k] == True, если вертикаль уровня k должна продолжаться ниже узла
    (у соответствующего предка есть следующие siblings). CSS рисует линии.
    """
    depth = devices[i]["depth"]
    if depth == 0:
        return []
    # Ближайшие предки: последний узел каждого уровня < depth, идущий до i.
    ancestors: dict[int, int] = {}
    for j in range(i - 1, -1, -1):
        dj = devices[j]["depth"]
        if dj < depth and dj not in ancestors:
            ancestors[dj] = j
        if len(ancestors) == depth:
            break
    # guides[level] для level = 1..depth: вертикаль уровня (level-1)
    guides = []
    for level in range(1, depth + 1):
        a = ancestors.get(level - 1)
        guides.append(a is not None and next_sibling[a] < len(devices))
    return guides
    return devices


def base_ctx(request: Request) -> dict:
    """Sidebar context — always passed to full-page templates."""
    host = request.session.get("host")
    raw = db.get_all_devices(host=host)
    selected_id = request.session.get("selected_device")
    selected_dev = db.get_device(selected_id) if selected_id else None

    devices = _build_device_tree(raw)

    # Группы внутри оффлайн multi-снапшота (глобальная загрузка JSON) — селектор
    # нужен только здесь: выбор группы устройств из дерева сам по себе уже
    # выбирает нужную группу правил при работе через синхронизацию с СУ.
    snap_groups: list[dict] = []
    active_group_id = request.session.get("active_group_id")
    offline_snap = request.session.get("offline_snap")
    if offline_snap:
        try:
            snap = state.load_snapshot_dict(offline_snap)
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
        "theme":              get_theme(request),
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
