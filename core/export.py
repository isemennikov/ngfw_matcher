"""
Pure dict-builders for JSON export. No I/O — return plain dicts.
Used by both CLI (→ write to file) and web (→ HTTP response).
"""
from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

from .resolver import PROTO, is_any_kind
from .utils import port_str as _port_str

if TYPE_CHECKING:
    from .models import NatRule
    from .nat_audit import NatAssociation
from .._version import __version__


# ─── Мета ────────────────────────────────────────────────────────────────────

def json_meta() -> dict:
    return {"tool": "ngfw-matcher", "version": __version__}


# ─── Низкоуровневые сериализаторы объектов ───────────────────────────────────

def _serialize_net_obj(obj: dict, fetch_group=None, _depth: int = 0) -> dict:
    if "networkIpAddress" in obj:
        a = obj["networkIpAddress"]
        return {"type": "ipAddress", "id": a.get("id"), "inet": a.get("inet")}
    if "networkIpRange" in obj:
        r = obj["networkIpRange"]
        return {"type": "ipRange", "id": r.get("id"), "from": r.get("from"), "to": r.get("to")}
    if "networkFqdn" in obj:
        f = obj["networkFqdn"]
        return {"type": "fqdn", "id": f.get("id"), "fqdn": f.get("fqdn")}
    if "networkGeoAddress" in obj:
        g = obj["networkGeoAddress"]
        return {"type": "geoAddress", "id": g.get("id"), "geoId": g.get("geoId")}
    if "networkGroup" in obj:
        g = obj["networkGroup"]
        gid = g.get("id")
        entry: dict = {"type": "group", "id": gid, "name": g.get("name")}
        if fetch_group and gid and _depth < 4:
            try:
                members = fetch_group(gid)
                entry["members"] = [_serialize_net_obj(m, fetch_group, _depth + 1) for m in members]
            except Exception:
                pass
        return entry
    return {"type": "unknown", "raw": obj}


def serialize_net_field(field: dict | None, fetch_group=None) -> dict:
    if field is None or is_any_kind(field):
        return {"kind": "RULE_KIND_ANY"}
    objects = [_serialize_net_obj(obj, fetch_group) for obj in (field.get("objects") or [])]
    return {"kind": field.get("kind", "RULE_KIND_LIST"), "objects": objects}


def _net_obj_matches_src(obj: dict, src, fetch_group=None, _depth: int = 0) -> bool:
    if "networkIpAddress" in obj:
        inet = obj["networkIpAddress"].get("inet", "")
        if not inet:
            return False
        try:
            if "/" not in inet and ":" not in inet:
                inet += "/32"
            net = ipaddress.ip_network(inet, strict=False)
            if isinstance(src, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                return src in net
            return src.subnet_of(net)
        except (ValueError, TypeError):
            return False
    if "networkIpRange" in obj:
        r = obj["networkIpRange"]
        try:
            start = ipaddress.ip_address(r.get("from", ""))
            end   = ipaddress.ip_address(r.get("to",   ""))
            if isinstance(src, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                return start <= src <= end
            return start <= src.network_address and src.broadcast_address <= end
        except (ValueError, TypeError):
            return False
    if "networkFqdn" in obj or "networkGeoAddress" in obj:
        return False
    if "networkGroup" in obj:
        gid = obj["networkGroup"].get("id")
        if not gid or not fetch_group or _depth >= 4:
            return False
        try:
            return any(_net_obj_matches_src(m, src, fetch_group, _depth + 1) for m in fetch_group(gid))
        except Exception:
            return False
    return False


def _serialize_net_obj_filtered(obj: dict, src, fetch_group=None, _depth: int = 0) -> dict | None:
    if "networkIpAddress" in obj:
        if not _net_obj_matches_src(obj, src):
            return None
        a = obj["networkIpAddress"]
        return {"type": "ipAddress", "id": a.get("id"), "inet": a.get("inet")}
    if "networkIpRange" in obj:
        if not _net_obj_matches_src(obj, src):
            return None
        r = obj["networkIpRange"]
        return {"type": "ipRange", "id": r.get("id"), "from": r.get("from"), "to": r.get("to")}
    if "networkFqdn" in obj or "networkGeoAddress" in obj:
        return None
    if "networkGroup" in obj:
        g   = obj["networkGroup"]
        gid = g.get("id")
        if not fetch_group or not gid or _depth >= 4:
            return None
        try:
            filtered = [_serialize_net_obj_filtered(m, src, fetch_group, _depth + 1) for m in fetch_group(gid)]
            matching = [m for m in filtered if m is not None]
        except Exception:
            return None
        if not matching:
            return None
        return {"type": "group", "id": gid, "name": g.get("name"), "members": matching}
    return None


def serialize_src_field(field: dict | None, src_str: str, fetch_group=None) -> dict:
    """Поле source с фильтром: оставляем только объекты покрывающие src_str."""
    if field is None or is_any_kind(field):
        return {"kind": "RULE_KIND_ANY"}
    try:
        src = (ipaddress.ip_network(src_str, strict=False)
               if "/" in src_str else ipaddress.ip_address(src_str))
    except ValueError:
        return serialize_net_field(field, fetch_group)
    objects = [_serialize_net_obj_filtered(obj, src, fetch_group) for obj in (field.get("objects") or [])]
    return {"kind": field.get("kind", "RULE_KIND_LIST"), "objects": [o for o in objects if o is not None]}


def _serialize_svc_obj(item: dict, fetch_group=None, _depth: int = 0) -> dict:
    if "service" in item:
        svc = item["service"]
        proto = PROTO.get(svc.get("protocol", 0), str(svc.get("protocol", 0)))
        entry: dict = {"type": "service", "id": svc.get("id"), "protocol": proto}
        dst_ports = [_port_str(sp) for sp in (svc.get("dstPorts") or [])]
        src_ports = [_port_str(sp) for sp in (svc.get("srcPorts") or [])]
        if dst_ports:
            entry["dst_ports"] = dst_ports
        if src_ports:
            entry["src_ports"] = src_ports
        return entry
    if "serviceGroup" in item:
        g = item["serviceGroup"]
        gid = g.get("id")
        entry = {"type": "serviceGroup", "id": gid, "name": g.get("name")}
        if fetch_group and gid and _depth < 4:
            try:
                members = fetch_group(gid)
                entry["members"] = [_serialize_svc_obj(m, fetch_group, _depth + 1) for m in members]
            except Exception:
                pass
        return entry
    return {"type": "unknown", "raw": item}


def serialize_svc_field(field: dict | None, fetch_group=None) -> dict:
    if is_any_kind(field):
        return {"kind": "RULE_KIND_ANY"}
    objects = [_serialize_svc_obj(item, fetch_group) for item in (field.get("objects") or [])]
    return {"kind": field.get("kind", "RULE_KIND_LIST"), "objects": objects}


def serialize_app_field(field: dict | None) -> dict | None:
    if field is None or field.get("kind") != "RULE_KIND_LIST":
        return None
    objects = [
        {"id": obj.get("id"), "name": obj.get("name") or obj.get("uniqueName")}
        for obj in (field.get("objects") or [])
    ]
    return {"kind": "RULE_KIND_LIST", "objects": objects} if objects else None


# ─── Единый сериализатор правила ─────────────────────────────────────────────

def serialize_rule(rule, fetch_net, fetch_svc, filter_src: str | None = None) -> dict:
    """
    Одно NormalizedRule → dict.
    filter_src: если задан конкретный IP/CIDR (не 0.0.0.0/0) —
                поле source фильтруется до объектов, покрывающих этот адрес.
    """
    is_specific = filter_src and filter_src not in ("0.0.0.0/0", "::/0")
    source = (serialize_src_field(rule.source_addr, filter_src, fetch_net)
              if is_specific
              else serialize_net_field(rule.source_addr, fetch_net))
    r = {
        "name":        rule.name,
        "uid":         rule.uid,
        "action":      rule.action,
        "enabled":     rule.enabled,
        "precedence":  rule.precedence,
        "position":    rule.position_in_precedence or (rule.index + 1),
        "source":      source,
        "destination": serialize_net_field(rule.destination_addr, fetch_net),
        "service":     serialize_svc_field(rule.service, fetch_svc),
    }
    app = serialize_app_field(rule.application)
    if app:
        r["application"] = app
    return r


# ─── Dict-builders — возвращают готовый dict без I/O ─────────────────────────

def build_match_dict(
    flow_results: list[dict],   # [{"flow": TrafficFlow, "matched": NormalizedRule|None, "shadowed": list}]
    query: dict,
    fetch_net=None,
    fetch_svc=None,
) -> dict:
    flows_out = []
    for entry in flow_results:
        flow     = entry["flow"]
        matched  = entry["matched"]
        shadowed = entry["shadowed"]
        flows_out.append({
            "src":      flow.src_ip,
            "dst":      flow.dst_ip,
            "dport":    flow.dst_port or "any",
            "proto":    flow.protocol,
            "matched":  serialize_rule(matched, fetch_net, fetch_svc, filter_src=flow.src_ip) if matched else None,
            "shadowed": [serialize_rule(r, fetch_net, fetch_svc, filter_src=flow.src_ip) for r in shadowed],
        })

    if len(flows_out) == 1:
        output = {"query": query, **flows_out[0]}
    else:
        output = {"query": query, "flows": flows_out}
    return {"_ngfw_matcher": json_meta(), **output}


def build_find_dict(
    rules: list,
    query: dict,
    fetch_net=None,
    fetch_svc=None,
) -> dict:
    rules_out = [serialize_rule(r, fetch_net, fetch_svc) for r in rules]
    return {
        "_ngfw_matcher":   json_meta(),
        "query":         query,
        "matched_count": len(rules_out),
        "rules":         rules_out,
    }


def build_shadows_dict(
    results: list[dict],   # [{"by": NormalizedRule, "shadowed": NormalizedRule, "conflict": bool, ...}]
    query: dict,
    fetch_net=None,
    fetch_svc=None,
) -> dict:
    entries_out = []
    for entry in results:
        e = {
            "shadowed_by": serialize_rule(entry["by"],      fetch_net, fetch_svc),
            "rule":        serialize_rule(entry["shadowed"], fetch_net, fetch_svc),
            "conflict":    entry["conflict"],
        }
        if "overlap_src" in entry:
            e["overlap_src"] = [str(n) for n in entry["overlap_src"]]
            e["overlap_dst"] = [str(n) for n in entry["overlap_dst"]]
        entries_out.append(e)

    return {
        "_ngfw_matcher": json_meta(),
        "query":       query,
        "total":       len(entries_out),
        "conflicts":   sum(1 for r in results if r["conflict"]),
        "entries":     entries_out,
    }


def _serialize_nat_rule(nat: "NatRule", fetch_net=None, fetch_svc=None) -> dict:
    d: dict = {
        "name":        nat.name,
        "uid":         nat.uid,
        "position":    nat.position,
        "precedence":  nat.precedence,
        "enabled":     nat.enabled,
        "nat_type":    nat.nat_type,
        "source":      serialize_net_field(nat.source_addr,      fetch_net),
        "destination": serialize_net_field(nat.destination_addr, fetch_net),
        "service":     serialize_svc_field(nat.service,          fetch_svc),
    }
    if nat.is_snat:
        d["snat"] = {
            "translation_type":      nat.src_translation_type,
            "masquerade":            "TRANSLATED" not in nat.src_translation_addr_type,
            "translated_address":    serialize_net_field(nat.src_translated_address, fetch_net),
            "translated_port":       nat.src_translated_port,
        }
    if nat.is_dnat:
        d["dnat"] = {
            "translation_type":   nat.dst_translation_type,
            "translated_address": serialize_net_field(nat.dst_translated_address, fetch_net),
            "translated_port":    nat.dst_translated_port,
        }
    if nat.description:
        d["description"] = nat.description
    return d


def build_nat_audit_dict(
    associations: "list[NatAssociation]",
    query: dict,
    fetch_net=None,
    fetch_svc=None,
) -> dict:
    entries = []
    for assoc in associations:
        nat  = assoc.nat_rule
        item = _serialize_nat_rule(nat, fetch_net, fetch_svc)
        item["security_rules"] = [
            {
                **serialize_rule(m.rule, fetch_net, fetch_svc),
                "full_coverage":  m.full_coverage,
                "conflict_dims":  m.conflict_dims,
                "has_conflict":   m.has_conflict,
            }
            for m in assoc.matches
        ]
        entries.append(item)

    return {
        "_ngfw_matcher": json_meta(),
        "query":       query,
        "total":       len(entries),
        "rules":       entries,
    }


def build_fullview_dict(
    flow_results: list[dict],   # [{"flow": TrafficFlow, "rules": list, "mode": "src"|"dst", "addr": str}]
    query: dict,
    fetch_net=None,
    fetch_svc=None,
) -> dict:
    flows_out = []
    for entry in flow_results:
        flow  = entry["flow"]
        mode  = entry.get("mode", "src")
        addr  = entry.get("addr", flow.src_ip if mode == "src" else flow.dst_ip)
        # src-скан → фильтруем source field; dst-скан → без фильтра
        filter_src = flow.src_ip if mode == "src" else None
        rules_out  = [serialize_rule(r, fetch_net, fetch_svc, filter_src=filter_src)
                      for r in entry["rules"]]
        flows_out.append({
            "addr":          addr,
            "mode":          mode,
            "matched_count": len(rules_out),
            "rules":         rules_out,
        })

    if len(flows_out) == 1:
        output = {
            "query":         query,
            "matched_count": flows_out[0]["matched_count"],
            "rules":         flows_out[0]["rules"],
        }
    else:
        output = {"query": query, "flows": flows_out}
    return {"_ngfw_matcher": json_meta(), **output}
