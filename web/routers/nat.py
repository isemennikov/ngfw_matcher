from __future__ import annotations

import json

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates

from ..deps import (base_ctx, has_data_source, require_snapshot_path,
                    get_active_group_id, get_include_parents, json_download)
from ...cli.builder import load_nat_rules_from_snapshot, _build_rules
from ...core.snapshot import get_effective_group
from ...core.models import NatRule
from ...core.format import format_net_obj, format_svc_obj
from ...core.resolver import ObjectResolver
from ...core.nat_audit import associate_nat_rules, NatAssociation
from ...core.export import build_nat_audit_dict

router = APIRouter()
templates: Jinja2Templates = None


@router.get("/nat", response_class=HTMLResponse)
async def nat_page(request: Request):
    if not has_data_source(request):
        return templates.TemplateResponse(request, "no_device.html", base_ctx(request))
    return templates.TemplateResponse(request, "nat.html", base_ctx(request))


def _load_and_associate(request: Request, nat_type: str, search: str):
    """Shared logic: load snapshot, filter NAT rules, run association."""
    snap_path       = require_snapshot_path(request)
    group_id        = get_active_group_id(request)
    include_parents = get_include_parents(request)
    with open(snap_path, encoding="utf-8") as f:
        snap = json.load(f)

    grp       = get_effective_group(snap, group_id, include_parents=include_parents)
    nat_rules = load_nat_rules_from_snapshot(snap, group_id, include_parents=include_parents)
    sec_rules = _build_rules(grp.get("rules") or [])
    net_cache = grp.get("net_groups") or {}
    svc_cache = grp.get("svc_groups") or {}
    resolver  = ObjectResolver(
        fetch_net_group=lambda gid: net_cache.get(gid, []),
        fetch_svc_group=lambda gid: svc_cache.get(gid, []),
    )

    if nat_type == "snat":
        nat_rules = [r for r in nat_rules if r.is_snat and not r.is_dnat]
    elif nat_type == "dnat":
        nat_rules = [r for r in nat_rules if r.is_dnat and not r.is_snat]

    if search.strip():
        sl = search.strip().lower()
        nat_rules = [r for r in nat_rules if sl in r.name.lower()]

    associations = associate_nat_rules(nat_rules, sec_rules, resolver)
    return associations, net_cache, svc_cache


@router.post("/nat", response_class=HTMLResponse)
async def do_nat(
    request: Request,
    nat_type: str = Form("all"),
    search:   str = Form(""),
):
    try:
        associations, _, _ = _load_and_associate(request, nat_type, search)
    except Exception as e:
        return _error(request, str(e))

    assoc_map = {a.nat_rule.uid: a for a in associations}
    cards     = [_build_card(a.nat_rule, assoc_map.get(a.nat_rule.uid)) for a in associations]

    return templates.TemplateResponse(request, "partials/nat_result.html", {
        "cards":    cards,
        "total":    len(cards),
        "nat_type": nat_type,
    })


@router.post("/nat/export")
async def export_nat(
    request:  Request,
    nat_type: str = Form("all"),
    search:   str = Form(""),
):
    try:
        associations, net_cache, svc_cache = _load_and_associate(request, nat_type, search)
    except Exception as e:
        return _error(request, str(e))

    fetch_net = lambda gid: net_cache.get(gid, [])
    fetch_svc = lambda gid: svc_cache.get(gid, [])
    query     = {"nat_type": nat_type, "search": search.strip() or None}
    data      = build_nat_audit_dict(associations, query, fetch_net, fetch_svc)
    return json_download(data, f"nat_audit_{nat_type}")


def _nets(field: dict | None) -> list[str]:
    if not field or field.get("kind") != "RULE_KIND_LIST":
        return ["ANY"]
    out = [format_net_obj(obj) for obj in (field.get("objects") or [])]
    return out or ["ANY"]


def _svcs(field: dict | None) -> list[str]:
    if not field or field.get("kind") != "RULE_KIND_LIST":
        return ["ANY"]
    out = [format_svc_obj(item) for item in (field.get("objects") or [])]
    return out or ["ANY"]


def _translated_port(port_field: dict | None) -> str:
    if not port_field:
        return ""
    if "portNum" in port_field:
        p = port_field["portNum"].get("port")
        return f":{p}" if p else ""
    if "portRange" in port_field:
        pr = port_field["portRange"]
        return f":{pr.get('from','')}–{pr.get('to','')}"
    return ""


def _build_card(rule: NatRule, assoc: NatAssociation | None = None) -> dict:
    src_addrs  = _nets(rule.source_addr)
    dst_addrs  = _nets(rule.destination_addr)
    svcs       = _svcs(rule.service)

    snat_from = src_addrs
    snat_to   = _nets(rule.src_translated_address) if rule.is_snat else []
    snat_port = _translated_port(rule.src_translated_port) if rule.is_snat else ""
    masq      = rule.is_snat and "TRANSLATED" not in rule.src_translation_addr_type

    dnat_from = dst_addrs
    dnat_to   = _nets(rule.dst_translated_address) if rule.is_dnat else []
    dnat_port = f":{rule.dst_translated_port}" if rule.is_dnat and rule.dst_translated_port else ""

    sec_matches = []
    if assoc:
        for m in assoc.matches:
            r = m.rule
            sec_matches.append({
                "name":         r.name,
                "action":       r.action,
                "position":     r.position_in_precedence,
                "precedence":   r.precedence,
                "full_coverage": m.full_coverage,
                "has_conflict": m.has_conflict,
                "conflict_dims": m.conflict_dims,
                "source_group_name": r.source_group_name,
            })

    return {
        "rule":        rule,
        "src":         src_addrs,
        "dst":         dst_addrs,
        "svc":         svcs,
        "snat_from":   snat_from,
        "snat_to":     snat_to,
        "snat_port":   snat_port,
        "masq":        masq,
        "dnat_from":   dnat_from,
        "dnat_to":     dnat_to,
        "dnat_port":   dnat_port,
        "sec_matches": sec_matches,
    }


def _error(request: Request, msg: str) -> HTMLResponse:
    return templates.TemplateResponse(request, "partials/error.html",
                                      {"request": request, "error": msg})
