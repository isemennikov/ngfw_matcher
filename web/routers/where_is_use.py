from __future__ import annotations

import asyncio

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .. import state
from ..deps import base_ctx, has_data_source, require_snapshot_path, json_download
from ...core.where_is_use import audit_non_global, build_audit_summary, find_object, has_owner_data
from ...core.export import build_where_is_use_audit_dict, build_where_is_use_search_dict

router = APIRouter()
templates: Jinja2Templates = None


def _error(request: Request, msg: str) -> HTMLResponse:
    return templates.TemplateResponse(request, "partials/error.html",
                                      {"request": request, "error": msg})


def _load_snap(request: Request) -> dict:
    snap_path = require_snapshot_path(request)
    return state.load_snapshot_dict(snap_path)


def _audit(snap: dict):
    entries = audit_non_global(snap)
    summary = build_audit_summary(snap, entries)
    return entries, summary


@router.get("/where-is-use", response_class=HTMLResponse)
async def where_is_use_page(request: Request):
    if not has_data_source(request):
        return templates.TemplateResponse(request, "no_device.html", base_ctx(request))
    return templates.TemplateResponse(request, "where_is_use.html", base_ctx(request))


@router.post("/where-is-use/audit", response_class=HTMLResponse)
async def do_audit(request: Request):
    try:
        snap = _load_snap(request)
    except Exception as e:
        return _error(request, str(e))

    if not has_owner_data(snap):
        return _error(request, "Снапшот не содержит данных о владении объектами — "
                                "выполните синхронизацию из СУ ещё раз («Обновить из СУ»).")

    entries, summary = await asyncio.to_thread(_audit, snap)
    return templates.TemplateResponse(request, "partials/where_is_use_audit.html", {
        "entries": entries,
        "total":   len(entries),
        "summary": summary,
    })


@router.post("/where-is-use/audit/export")
async def export_audit(request: Request):
    try:
        snap = _load_snap(request)
    except Exception as e:
        from fastapi.responses import Response as _R
        return _R(content=str(e), status_code=400, media_type="text/plain")

    if not has_owner_data(snap):
        from fastapi.responses import Response as _R
        return _R(content="Снапшот не содержит данных о владении объектами — "
                           "выполните синхронизацию заново", status_code=400, media_type="text/plain")

    entries, summary = await asyncio.to_thread(_audit, snap)
    return json_download(build_where_is_use_audit_dict(entries, {}, summary), "where_is_use_audit")


@router.post("/where-is-use/search", response_class=HTMLResponse)
async def do_search(request: Request, query: str = Form("")):
    try:
        snap = _load_snap(request)
    except Exception as e:
        return _error(request, str(e))

    if not has_owner_data(snap):
        return _error(request, "Снапшот не содержит данных о владении объектами — "
                                "выполните синхронизацию из СУ ещё раз («Обновить из СУ»).")

    if not query.strip():
        return _error(request, "Введите UUID или имя объекта")

    result = await asyncio.to_thread(find_object, snap, query)
    return templates.TemplateResponse(request, "partials/where_is_use_search.html", {
        "result": result,
    })


@router.post("/where-is-use/search/export")
async def export_search(request: Request, query: str = Form("")):
    try:
        snap = _load_snap(request)
    except Exception as e:
        from fastapi.responses import Response as _R
        return _R(content=str(e), status_code=400, media_type="text/plain")

    if not has_owner_data(snap):
        from fastapi.responses import Response as _R
        return _R(content="Снапшот не содержит данных о владении объектами — "
                           "выполните синхронизацию заново", status_code=400, media_type="text/plain")

    result = await asyncio.to_thread(find_object, snap, query)
    return json_download(build_where_is_use_search_dict(result), "where_is_use_search")
