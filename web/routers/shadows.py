from __future__ import annotations

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from ..deps import require_matcher, base_ctx, has_data_source

router = APIRouter()
templates: Jinja2Templates = None


@router.get("/shadows", response_class=HTMLResponse)
async def shadows_page(request: Request):
    if not has_data_source(request):
        return templates.TemplateResponse(request, "no_device.html", base_ctx(request))
    return templates.TemplateResponse(request, "shadows.html", base_ctx(request))


PAGE_SIZE = 50


@router.post("/shadows", response_class=HTMLResponse)
async def do_shadows(
    request: Request,
    mode: str = Form("full"),
    page: int = Form(0),
):
    try:
        matcher = require_matcher(request)
    except Exception as e:
        return templates.TemplateResponse(request, "partials/error.html",
                                          {"error": str(e)})

    import asyncio
    if mode == "partial":
        results = await asyncio.get_event_loop().run_in_executor(
            None, matcher.check_partial_shadowed
        )
    else:
        results = await asyncio.get_event_loop().run_in_executor(
            None, matcher.check_shadowed
        )

    # Группируем по "by"-правилу
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
        "groups":       page_groups,
        "total":        len(results),
        "conflicts":    sum(1 for r in results if r["conflict"]),
        "mode":         mode,
        "n_rules":      len(matcher.rules),
        "page":         page,
        "total_pages":  total_pages,
        "total_groups": total_groups,
    })
