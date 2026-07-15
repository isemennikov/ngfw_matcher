from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates

from .. import db
from ..deps import require_connection, require_matcher, base_ctx, json_download

log = logging.getLogger("ngfw.hits")
router = APIRouter()
templates: Jinja2Templates = None


@router.get("/hits", response_class=HTMLResponse)
async def hits_page(request: Request):
    if not request.session.get("selected_device"):
        return templates.TemplateResponse(request, "no_device.html", base_ctx(request))

    device_id = request.session.get("selected_device")
    rows      = db.get_rule_hits(device_id)
    synced_at = db.get_hits_synced_at(device_id)

    ctx = base_ctx(request)
    ctx["has_data"] = bool(rows)
    ctx.update(_table_ctx(rows, synced_at))
    return templates.TemplateResponse(request, "hits.html", ctx)


@router.get("/hits/export")
async def export_hits(request: Request):
    device_id = request.session.get("selected_device")
    if not device_id:
        from fastapi.responses import Response as _R
        return _R(content="No device selected", status_code=400)
    rows      = db.get_rule_hits(device_id)
    synced_at = db.get_hits_synced_at(device_id)
    output = {
        "synced_at": synced_at,
        "total":     len(rows),
        "rules": [
            {"name": r["name"], "uid": r["rule_id"],
             "hits": r["hits"], "enabled": r["enabled"]}
            for r in rows
        ],
    }
    return json_download(output, "rule_hits")


@router.post("/hits/sync", response_class=HTMLResponse)
async def sync_hits(request: Request):
    sess = require_connection(request)

    try:
        matcher   = require_matcher(request)
        device_id = request.session["selected_device"]
    except Exception as e:
        return templates.TemplateResponse(request, "partials/error.html", {"error": str(e)})

    rules    = list(matcher.rules)
    rule_ids = [r.uid for r in rules]
    meta     = {r.uid: (r.name, r.enabled) for r in rules}

    from ...sources.ngfw_api import NGFWDirectSource
    src = NGFWDirectSource(host=sess["host"], username="", password="",
                           token=sess["token"], verify_ssl=False)

    try:
        hits_data = await asyncio.get_event_loop().run_in_executor(
            None, lambda: src.get_rule_hits(rule_ids)
        )
    except Exception as e:
        return templates.TemplateResponse(request, "partials/error.html", {"error": str(e)})

    log.info("hits sync: %d правил → %d записей от API", len(rule_ids), len(hits_data))

    hits_by_id = {
        (h.get("ruleId") or h.get("id") or ""): h
        for h in hits_data
        if h.get("ruleId") or h.get("id")
    }

    synced_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    save_rows = []
    for rule_id, (name, enabled) in meta.items():
        raw_h = hits_by_id.get(rule_id, {}).get("hits", 0)
        try:
            hits = int(raw_h)
        except (ValueError, TypeError):
            hits = 0
        save_rows.append({"rule_id": rule_id, "name": name,
                          "hits": hits, "enabled": enabled})

    db.save_rule_hits(device_id, save_rows, synced_at)

    # Полная перезагрузка страницы — обновляет и статус-баннер и таблицу
    return Response(content="", media_type="text/html",
                    headers={"HX-Refresh": "true"})


@router.post("/hits/filter", response_class=HTMLResponse)
async def filter_hits(request: Request,
                      rule_filter: str = Form(""),
                      sort_by_hits: str = Form("")):
    device_id = request.session.get("selected_device")
    if not device_id:
        return HTMLResponse("")

    order_by_hits = bool(sort_by_hits)
    rows      = db.get_rule_hits(device_id, order_by_hits=order_by_hits)
    synced_at = db.get_hits_synced_at(device_id)

    if rule_filter:
        fl = rule_filter.lower()
        rows = [r for r in rows if fl in (r["name"] or "").lower()]

    return templates.TemplateResponse(request, "partials/hits_table.html",
                                      _table_ctx(rows, synced_at, order_by_hits))


def _table_ctx(rows: list[dict], synced_at: str | None,
               sorted_by_hits: bool = False) -> dict:
    # Перцентили только по ненулевым значениям, чтобы 300 != красный
    nonzero = sorted(r["hits"] for r in rows if r["hits"] > 0)
    n = len(nonzero)
    max_hits = nonzero[-1] if nonzero else 1
    p33 = nonzero[n // 3]     if n >= 3 else (nonzero[-1] if nonzero else 0)
    p66 = nonzero[2 * n // 3] if n >= 3 else (nonzero[-1] if nonzero else 0)
    return {"rows": rows, "max_hits": max_hits or 1,
            "p33": p33, "p66": p66,
            "synced_at": synced_at, "sorted_by_hits": sorted_by_hits}
