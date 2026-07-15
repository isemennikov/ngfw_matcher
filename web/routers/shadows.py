from __future__ import annotations

import asyncio
import uuid

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .. import state
from ..deps import require_matcher, base_ctx, has_data_source, json_download
from ...core.export import build_shadows_dict

router = APIRouter()
templates: Jinja2Templates = None

PAGE_SIZE = 50


@router.get("/shadows", response_class=HTMLResponse)
async def shadows_page(request: Request):
    if not has_data_source(request):
        return templates.TemplateResponse(request, "no_device.html", base_ctx(request))
    return templates.TemplateResponse(request, "shadows.html", base_ctx(request))


def _run_shadows_job(job_id: str, matcher, mode: str):
    def _progress(current: int, total: int):
        state.update_shadows_progress(job_id, current, total)

    try:
        if mode == "partial":
            results = matcher.check_partial_shadowed(progress_cb=_progress)
        else:
            results = matcher.check_shadowed(progress_cb=_progress)
        state.finish_shadows_job(job_id, results)
    except Exception as e:
        state.fail_shadows_job(job_id, str(e))


@router.post("/shadows", response_class=HTMLResponse)
async def do_shadows(
    request: Request,
    mode: str = Form("full"),
):
    try:
        matcher = require_matcher(request)
    except Exception as e:
        return templates.TemplateResponse(request, "partials/error.html",
                                          {"error": str(e)})

    job_id = str(uuid.uuid4())
    state.create_shadows_job(job_id, len(matcher.rules), mode)

    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, _run_shadows_job, job_id, matcher, mode)

    return templates.TemplateResponse(request, "partials/shadows_progress.html", {
        "job_id": job_id, "status": "running", "current": 0, "total": len(matcher.rules),
    })


@router.get("/shadows/status/{job_id}", response_class=HTMLResponse)
async def shadows_status(request: Request, job_id: str, page: int = 0):
    job = state.get_shadows_job(job_id)
    if not job:
        return templates.TemplateResponse(request, "partials/error.html",
            {"error": "Задача анализа не найдена — запустите Shadows заново"})

    if job["status"] == "error":
        return templates.TemplateResponse(request, "partials/error.html",
            {"error": job["error"] or "Ошибка анализа"})

    if job["status"] == "running":
        return templates.TemplateResponse(request, "partials/shadows_progress.html", {
            "job_id": job_id, "status": "running",
            "current": job["current"], "total": job["total"] or job["n_rules"],
        })

    return _render_shadows_page(request, job_id, job, page)


def _render_shadows_page(request: Request, job_id: str, job: dict, page: int) -> HTMLResponse:
    results = job["results"] or []

    groups: dict[str, dict] = {}
    for entry in results:
        key = entry["by"].uid
        if key not in groups:
            groups[key] = {"by": entry["by"], "entries": []}
        groups[key]["entries"].append(entry)

    all_groups = list(groups.values())
    total_groups = len(all_groups)
    total_pages = max(1, (total_groups + PAGE_SIZE - 1) // PAGE_SIZE)
    page = max(0, min(page, total_pages - 1))
    page_groups = all_groups[page * PAGE_SIZE:(page + 1) * PAGE_SIZE]

    return templates.TemplateResponse(request, "partials/shadows_result.html", {
        "job_id":       job_id,
        "groups":       page_groups,
        "total":        len(results),
        "conflicts":    sum(1 for r in results if r["conflict"]),
        "mode":         job["mode"],
        "n_rules":      job["n_rules"],
        "page":         page,
        "total_pages":  total_pages,
        "total_groups": total_groups,
    })


@router.post("/shadows/export")
async def export_shadows(
    request: Request,
    mode: str = Form("full"),
):
    try:
        matcher = require_matcher(request)
    except Exception as e:
        from fastapi.responses import Response as _R
        return _R(content=str(e), status_code=400)

    if mode == "partial":
        results = await asyncio.get_event_loop().run_in_executor(
            None, matcher.check_partial_shadowed
        )
    else:
        results = await asyncio.get_event_loop().run_in_executor(
            None, matcher.check_shadowed
        )

    fetch_net = matcher.resolver._fetch_net_group
    fetch_svc = matcher.resolver._fetch_svc_group
    query = {"mode": mode}
    return json_download(build_shadows_dict(results, query, fetch_net, fetch_svc), f"shadows_{mode}")
