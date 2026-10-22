from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Request, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from ..deps import base_ctx, safe_json_name, resolve_under, read_upload_limited

router = APIRouter()
templates: Jinja2Templates = None

UPLOAD_DIR = Path(__file__).parent.parent.parent / "data" / "snapshots" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


@router.get("/snapshot", response_class=HTMLResponse)
async def snapshot_page(request: Request):
    snaps = _list_snapshots()
    ctx = base_ctx(request)
    ctx.update({"snaps": snaps,
                "active": request.session.get("offline_snap"),
                "active_name": request.session.get("offline_snap_name")})
    return templates.TemplateResponse(request, "snapshot.html", ctx)


@router.post("/snapshot/upload", response_class=HTMLResponse)
async def upload_snapshot(request: Request, file: UploadFile = File(...)):
    name = safe_json_name(file.filename)
    if name is None:
        ctx = base_ctx(request)
        ctx.update({"snaps": _list_snapshots(), "error": "Только .json файлы",
                    "active": request.session.get("offline_snap"),
                    "active_name": request.session.get("offline_snap_name")})
        return templates.TemplateResponse(request, "snapshot.html", ctx)

    try:
        data = await read_upload_limited(file)
    except ValueError as e:
        ctx = base_ctx(request)
        ctx.update({"snaps": _list_snapshots(), "error": str(e),
                    "active": request.session.get("offline_snap"),
                    "active_name": request.session.get("offline_snap_name")})
        return templates.TemplateResponse(request, "snapshot.html", ctx)

    # Базовая проверка что это снапшот ngfw-matcher
    try:
        parsed = json.loads(data)
        if "rules" not in parsed:
            raise ValueError("нет поля 'rules'")
    except Exception as e:
        ctx = base_ctx(request)
        ctx.update({"snaps": _list_snapshots(),
                    "error": f"Некорректный файл: {e}",
                    "active": request.session.get("offline_snap"),
                    "active_name": request.session.get("offline_snap_name")})
        return templates.TemplateResponse(request, "snapshot.html", ctx)

    dest = resolve_under(UPLOAD_DIR, name)
    if dest is None:
        return RedirectResponse("/snapshot", status_code=303)
    dest.write_bytes(data)

    request.session["offline_snap"]      = str(dest)
    request.session["offline_snap_name"] = name

    return RedirectResponse("/snapshot", status_code=303)


@router.post("/snapshot/select/{filename}")
async def select_snapshot(filename: str, request: Request):
    name = safe_json_name(filename)
    dest = resolve_under(UPLOAD_DIR, name) if name else None
    if dest is not None and dest.exists():
        request.session["offline_snap"]      = str(dest)
        request.session["offline_snap_name"] = name
    return RedirectResponse("/snapshot", status_code=303)


@router.post("/snapshot/clear")
async def clear_snapshot(request: Request):
    request.session.pop("offline_snap", None)
    request.session.pop("offline_snap_name", None)
    return RedirectResponse("/snapshot", status_code=303)


def _list_snapshots() -> list[dict]:
    snaps = []
    for f in sorted(UPLOAD_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            size_kb = f.stat().st_size // 1024
            snaps.append({"name": f.name, "size_kb": size_kb})
        except OSError:
            pass
    return snaps
