from __future__ import annotations
import re

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from ..deps import require_matcher, base_ctx, has_data_source
from ...core.resolver import is_any_kind, PROTO

router = APIRouter()
templates: Jinja2Templates = None

_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)


@router.get("/find-rule", response_class=HTMLResponse)
async def find_page(request: Request):
    if not has_data_source(request):
        return templates.TemplateResponse(request, "no_device.html", base_ctx(request))
    return templates.TemplateResponse(request, "find_rule.html", base_ctx(request))


@router.post("/find-rule", response_class=HTMLResponse)
async def do_find(
    request: Request,
    pattern: str = Form(""),
    dport:   str = Form(""),
    proto:   str = Form(""),
):
    try:
        matcher = require_matcher(request)
    except Exception as e:
        return templates.TemplateResponse(request, "partials/error.html",
                                          {"error": str(e)})

    pattern = pattern.strip()
    dport   = dport.strip()
    proto   = proto.strip().lower()

    rules = matcher.rules

    # Фильтр по имени / UUID
    if pattern:
        if _UUID_RE.match(pattern):
            rules = [r for r in rules if r.uid.lower() == pattern.lower()]
        else:
            pl = pattern.lower()
            rules = [r for r in rules if pl in r.name.lower()]

    # Фильтр по порту / протоколу
    if dport or proto:
        from ...core.models import TrafficFlow
        port = 0
        if dport and dport.lower() != "any":
            try:
                port = int(dport)
            except ValueError:
                pass
        proto_f = proto or "any"

        from ...core.matcher import RuleMatcher
        filtered = []
        for r in rules:
            svcs = matcher.resolver.resolve_field_service(r.service)
            if svcs == [("any", 0, 65535)]:
                continue
            flow = TrafficFlow(src_ip="0.0.0.0/0", dst_ip="0.0.0.0/0",
                               dst_port=port, protocol=proto_f,
                               src_port=0, zone_src="", zone_dst="")
            if RuleMatcher._service_matches(flow, svcs):
                filtered.append(r)
        rules = filtered

    rules = sorted(rules, key=lambda r: r.index)

    fetch_net = matcher.resolver._fetch_net_group
    fetch_svc = matcher.resolver._fetch_svc_group

    cards = [_build_card(r, fetch_net, fetch_svc) for r in rules[:50]]

    return templates.TemplateResponse(request, "partials/find_results.html", {
        "cards":   cards,
        "total":   len(rules),
        "n_rules": len(matcher.rules),
        "pattern": pattern,
    })


def _build_card(rule, fetch_net, fetch_svc) -> dict:
    from ..routers.match import _obj_to_strs

    def _nets(field) -> list[str]:
        if is_any_kind(field):
            return ["ANY"]
        out = []
        for obj in (field.get("objects") or []):
            out.extend(_obj_to_strs(obj, fetch_net))
        return out or ["ANY"]

    def _svcs(field) -> list[str]:
        if is_any_kind(field):
            return ["ANY"]
        out = []
        for item in (field.get("objects") or []):
            if "service" in item:
                svc = item["service"]
                p   = PROTO.get(svc.get("protocol", 0), "?")
                from ..routers.match import _port_str
                pts = [_port_str(sp) for sp in (svc.get("dstPorts") or [])]
                out.append(f"{p.upper()}/{','.join(pts)}" if pts else p.upper())
            elif "serviceGroup" in item:
                out.append(f"[группа] {item['serviceGroup'].get('name','?')}")
        return out or ["ANY"]

    return {
        "rule": rule,
        "src":  _nets(rule.source_addr),
        "dst":  _nets(rule.destination_addr),
        "svc":  _svcs(rule.service),
    }
