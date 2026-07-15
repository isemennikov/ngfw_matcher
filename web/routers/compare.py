from __future__ import annotations

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from ..deps import require_matcher
from ...core.rule_compare import compare_rules

router = APIRouter()
templates: Jinja2Templates = None


@router.post("/compare", response_class=HTMLResponse)
async def compare_rules_view(
    request: Request,
    uid_a: str = Form(...),
    uid_b: str = Form(...),
):
    try:
        matcher = require_matcher(request)
    except Exception as e:
        return HTMLResponse(f"<span class='text-red-400 text-xs'>{e}</span>")

    rule_a = next((r for r in matcher.rules if r.uid == uid_a), None)
    rule_b = next((r for r in matcher.rules if r.uid == uid_b), None)

    if not rule_a or not rule_b:
        return HTMLResponse("<span class='text-red-400 text-xs'>Правило не найдено</span>")

    cmp = compare_rules(rule_a, rule_b, matcher.resolver)
    return templates.TemplateResponse(request, "partials/rule_compare.html", {
        "rule_a": rule_a,
        "rule_b": rule_b,
        "cmp":    cmp,
    })
