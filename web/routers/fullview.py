from __future__ import annotations

import re

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates

from ..deps import require_matcher, base_ctx, has_data_source, json_download
from ...core.models import TrafficFlow
from ...core.resolver import is_any_kind, PROTO
from ...core.utils import port_str as _port_str, parse_ports as _parse_ports
from ...core.export import build_fullview_dict

router = APIRouter()
templates: Jinja2Templates = None


@router.get("/fullview", response_class=HTMLResponse)
async def fullview_page(request: Request):
    if not has_data_source(request):
        return templates.TemplateResponse(request, "no_device.html", base_ctx(request))
    return templates.TemplateResponse(request, "fullview.html", base_ctx(request))


@router.post("/fullview", response_class=HTMLResponse)
async def do_fullview(
    request: Request,
    src:     str = Form(""),
    dst:     str = Form(""),
    dport:   str = Form(""),
    proto:   str = Form("any"),
    overlap: str = Form(""),
):
    strict = not bool(overlap)
    try:
        matcher = require_matcher(request, strict=strict)
    except Exception as e:
        return _error(request, str(e))

    src = src.strip()
    dst = dst.strip()

    if not src and not dst:
        return _error(request, "Укажите Source и/или Destination")

    fetch_net = matcher.resolver._fetch_net_group

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
                pts = [_port_str(sp) for sp in (svc.get("dstPorts") or [])]
                out.append(f"{p.upper()}/{','.join(pts)}" if pts else p.upper())
            elif "serviceGroup" in item:
                out.append(f"[группа] {item['serviceGroup'].get('name','?')}")
        return out or ["ANY"]

    scan_results = _run_scan(matcher, src, dst, strict, dport=dport.strip(), proto=proto.strip())
    entries = []
    for entry in scan_results:
        entries.append({
            "mode":  entry["mode"],
            "addr":  entry["addr"],
            "rules": [{"rule": r,
                        "src": _nets(r.source_addr),
                        "dst": _nets(r.destination_addr),
                        "svc": _svcs(r.service)} for r in entry["rules"]],
        })

    total = sum(len(e["rules"]) for e in entries)

    return templates.TemplateResponse(request, "partials/fullview_result.html", {
        "entries":      entries,
        "total":        total,
        "overlap_mode": not strict,
        "n_rules":      len(matcher.rules),
    })


@router.post("/fullview/export")
async def export_fullview(
    request: Request,
    src:     str = Form(""),
    dst:     str = Form(""),
    dport:   str = Form(""),
    proto:   str = Form("any"),
    overlap: str = Form(""),
):
    strict = not bool(overlap)
    try:
        matcher = require_matcher(request, strict=strict)
    except Exception as e:
        return Response(content=str(e), status_code=400)

    src = src.strip()
    dst = dst.strip()
    if not src and not dst:
        return Response(content="Укажите Source и/или Destination", status_code=400)

    flow_results = _run_scan(matcher, src, dst, strict, dport=dport.strip(), proto=proto.strip())

    fetch_net = matcher.resolver._fetch_net_group
    fetch_svc = matcher.resolver._fetch_svc_group
    query = {"src": src or "any", "dst": dst or "any",
             "dport": dport or "any", "proto": proto or "any", "overlap": not strict}
    return json_download(build_fullview_dict(flow_results, query, fetch_net, fetch_svc), "fullview")


def _run_scan(matcher, src: str, dst: str, strict: bool,
              dport: str = "", proto: str = "any") -> list[dict]:
    def _split(raw: str) -> list[str]:
        tokens = re.split(r"[,\s]+", raw.strip())
        return [t for t in tokens if t]

    def _normalize(addr: str) -> str:
        return "0.0.0.0/0" if addr.lower() == "any" else addr

    ports    = _parse_ports(dport) if dport and dport.lower() != "any" else []
    dst_port = ports[0] if ports else 0
    protocol = proto if proto and proto.lower() != "any" else "any"

    results = []
    if src:
        for addr in _split(src):
            flow = TrafficFlow(src_ip=_normalize(addr), dst_ip="0.0.0.0/0",
                               dst_port=dst_port, protocol=protocol, src_port=0,
                               zone_src="", zone_dst="")
            results.append({"flow": flow, "addr": addr, "mode": "src",
                             "rules": matcher.fullview_scan(flow)})
    if dst:
        for addr in _split(dst):
            flow = TrafficFlow(src_ip="0.0.0.0/0", dst_ip=_normalize(addr),
                               dst_port=dst_port, protocol=protocol, src_port=0,
                               zone_src="", zone_dst="")
            results.append({"flow": flow, "addr": addr, "mode": "dst",
                             "rules": matcher.fullview_scan_dst(flow)})
    return results


def _error(request, msg: str):
    return templates.TemplateResponse(request, "partials/error.html", {"request": request, "error": msg})


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
