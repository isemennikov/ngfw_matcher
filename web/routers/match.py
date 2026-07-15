from __future__ import annotations

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from ..deps import require_matcher, base_ctx, has_data_source, json_download
from ...core.models import TrafficFlow
from ...core.utils import parse_ports as _parse_ports, port_str as _port_str
from ...core.export import build_match_dict

router = APIRouter()
templates: Jinja2Templates = None


@router.get("/match", response_class=HTMLResponse)
async def match_page(request: Request):
    if not has_data_source(request):
        return templates.TemplateResponse(request, "no_device.html", base_ctx(request))
    return templates.TemplateResponse(request, "match.html", base_ctx(request))


@router.post("/match", response_class=HTMLResponse)
async def do_match(
    request: Request,
    src:     str = Form("any"),
    dst:     str = Form("any"),
    dport:   str = Form("any"),
    proto:   str = Form("any"),
    overlap: str = Form(""),
):
    strict = not bool(overlap)
    try:
        matcher = require_matcher(request, strict=strict)
    except Exception as e:
        return _error(request, str(e))

    src   = src.strip()   or "any"
    dst   = dst.strip()   or "any"
    dport = dport.strip() or "any"
    proto = proto.strip() or "any"

    # Парсим несколько адресов: разделители — запятая, пробел, newline
    def _split_addrs(raw: str) -> list[str]:
        import re
        tokens = re.split(r"[,\s]+", raw.strip())
        return [("0.0.0.0/0" if t.lower() == "any" else t) for t in tokens if t]

    srcs = _split_addrs(src)
    dsts = _split_addrs(dst)
    if not srcs:
        srcs = ["0.0.0.0/0"]
    if not dsts:
        dsts = ["0.0.0.0/0"]

    try:
        ports = _parse_ports(dport)
    except ValueError as e:
        return _error(request, f"Некорректный порт: {e}")

    # Декартово произведение src × dst × port
    flows = [
        TrafficFlow(src_ip=s, dst_ip=d, dst_port=p,
                    protocol=proto.lower(), src_port=0,
                    zone_src="", zone_dst="")
        for s in srcs for d in dsts for p in ports
    ]

    # Раскрываем адреса для отображения
    fetch_net = matcher.resolver._fetch_net_group

    def _nets(field) -> list[str]:
        from ...core.resolver import is_any_kind
        if is_any_kind(field):
            return ["ANY"]
        out = []
        for obj in (field.get("objects") or []):
            out.extend(_obj_to_strs(obj, fetch_net))
        return out or ["ANY"]

    def _svcs(field) -> list[str]:
        from ...core.resolver import is_any_kind, PROTO
        if is_any_kind(field):
            return ["ANY"]
        out = []
        for item in (field.get("objects") or []):
            if "service" in item:
                svc = item["service"]
                p   = PROTO.get(svc.get("protocol", 0), "?")
                pts = [_port_str(sp) for sp in (svc.get("dstPorts") or [])]
                out.append(f"{p.upper()}/{','.join(pts)}" if pts else p.upper())
            elif "serviceGroup" in item:
                out.append(f"[группа] {item['serviceGroup'].get('name','?')}")
        return out or ["ANY"]

    def _build_result(flow):
        result = matcher.match(flow)
        matched_view = None
        if result.matched:
            r = result.matched
            matched_view = {
                "rule": r,
                "src":  _nets(r.source_addr),
                "dst":  _nets(r.destination_addr),
                "svc":  _svcs(r.service),
                "note": result.match_notes.get(r.uid, ""),
            }
        shadowed_views = [{
            "rule": dup,
            "src":  _nets(dup.source_addr),
            "dst":  _nets(dup.destination_addr),
            "svc":  _svcs(dup.service),
            "note": result.match_notes.get(dup.uid, ""),
        } for dup in result.shadowed]
        return {
            "flow":         flow,
            "result":       result,
            "matched":      matched_view,
            "shadowed":     shadowed_views,
            "skipped_app":  result.skipped_app,
            "skipped_fqdn": result.skipped_fqdn,
        }

    flow_results = [_build_result(f) for f in flows]

    return templates.TemplateResponse(request, "partials/match_result.html", {
        "flow_results": flow_results,
        "n_rules":      len(matcher.rules),
        "overlap_mode": not strict,
    })


@router.post("/match/export")
async def export_match(
    request: Request,
    src:     str = Form("any"),
    dst:     str = Form("any"),
    dport:   str = Form("any"),
    proto:   str = Form("any"),
    overlap: str = Form(""),
):
    strict = not bool(overlap)
    try:
        matcher = require_matcher(request, strict=strict)
    except Exception as e:
        from fastapi.responses import Response as _R
        return _R(content=str(e), status_code=400)

    src   = src.strip()   or "any"
    dst   = dst.strip()   or "any"
    dport = dport.strip() or "any"
    proto = proto.strip() or "any"

    import re
    def _split_addrs(raw):
        tokens = re.split(r"[,\s]+", raw.strip())
        return [("0.0.0.0/0" if t.lower() == "any" else t) for t in tokens if t]

    srcs  = _split_addrs(src)  or ["0.0.0.0/0"]
    dsts  = _split_addrs(dst)  or ["0.0.0.0/0"]
    try:
        ports = _parse_ports(dport)
    except ValueError:
        ports = [0]

    flows = [
        TrafficFlow(src_ip=s, dst_ip=d, dst_port=p,
                    protocol=proto.lower(), src_port=0, zone_src="", zone_dst="")
        for s in srcs for d in dsts for p in ports
    ]

    fetch_net = matcher.resolver._fetch_net_group
    fetch_svc = matcher.resolver._fetch_svc_group

    flow_results = []
    for flow in flows:
        result = matcher.match(flow)
        flow_results.append({"flow": flow, "matched": result.matched, "shadowed": result.shadowed})

    query = {"src": src, "dst": dst, "dport": dport, "proto": proto, "overlap": not strict}
    return json_download(build_match_dict(flow_results, query, fetch_net, fetch_svc), "match")


def _error(request, msg: str):
    return templates.TemplateResponse(request, "partials/error.html",
                                      {"error": msg})


def _obj_to_strs(obj: dict, fetch_net, depth=0) -> list[str]:
    if "networkIpAddress" in obj:
        return [obj["networkIpAddress"].get("inet", "?")]
    if "networkIpRange" in obj:
        r = obj["networkIpRange"]
        return [f"{r.get('from','?')}–{r.get('to','?')}"]
    if "networkFqdn" in obj:
        return [f"FQDN:{obj['networkFqdn'].get('fqdn','?')}"]
    if "networkGeoAddress" in obj:
        return [f"GeoIP:{obj['networkGeoAddress'].get('geoId','?')}"]
    if "networkGroup" in obj and depth < 3:
        gid  = obj["networkGroup"].get("id", "")
        name = obj["networkGroup"].get("name", gid)
        if fetch_net and gid:
            try:
                members = fetch_net(gid)
                items = []
                for m in members[:8]:
                    items.extend(_obj_to_strs(m, fetch_net, depth + 1))
                extra = len(members) - 8
                label = f"[{name}]"
                if extra > 0:
                    label += f" +{extra}"
                return [label] + items
            except Exception:
                pass
        return [f"[{name}]"]
    return []
