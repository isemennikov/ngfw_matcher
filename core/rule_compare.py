# Developed by Ilya Semennikov
"""Side-by-side comparison of two security rules with per-object overlap status."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .format import format_net_obj, format_svc_obj
from .models import NormalizedRule
from .resolver import ObjectResolver

_ANY_KINDS = {"RULE_KIND_ANY", "RULE_KIND_UNSPECIFIED", ""}
_ANY_SVC_TUPLE = ("any", 0, 65535)


def _is_any_field(field: dict | None) -> bool:
    if field is None:
        return True
    return field.get("kind", "") in _ANY_KINDS


def _net_status(obj_nets: list, other_nets: list) -> str:
    """Status of obj_nets against the full resolved other_nets list."""
    if not obj_nets or not other_nets:
        return "none"
    has_full = has_partial = False
    for na in obj_nets:
        for nb in other_nets:
            try:
                if na == nb or na.subnet_of(nb) or nb.subnet_of(na):
                    has_full = True
                elif na.overlaps(nb):
                    has_partial = True
            except TypeError:
                pass  # mixed IPv4/IPv6
    if has_full:
        return "full"
    if has_partial:
        return "partial"
    return "none"


def _svc_status(svc_tuple: tuple, other_svcs: list) -> str:
    """Status of a single (proto, p_from, p_to) tuple against other resolved services."""
    proto, pf, pt = svc_tuple
    if svc_tuple == _ANY_SVC_TUPLE:
        return "full" if other_svcs else "none"
    for ob in other_svcs:
        op, of, ot = ob
        if ob == _ANY_SVC_TUPLE:
            return "full"
        if op != proto and op != "any" and proto != "any":
            continue
        # Port range comparison
        overlap_from = max(pf, of)
        overlap_to   = min(pt, ot)
        if overlap_from > overlap_to:
            continue
        # Full containment?
        if of <= pf and pt <= ot:   # svc_tuple inside other
            return "full"
        if pf <= of and ot <= pt:   # other inside svc_tuple
            return "full"
        return "partial"
    return "none"


@dataclass
class ObjItem:
    text:   str
    status: str  # "full" | "partial" | "none"


@dataclass
class FieldCmp:
    items_a: list[ObjItem]
    items_b: list[ObjItem]


@dataclass
class RuleCmp:
    src: FieldCmp
    dst: FieldCmp
    svc: FieldCmp


def _compare_net_field(
    field_a: dict | None,
    field_b: dict | None,
    resolver: ObjectResolver,
) -> FieldCmp:
    any_a = _is_any_field(field_a)
    any_b = _is_any_field(field_b)

    if any_a and any_b:
        return FieldCmp([ObjItem("ANY", "full")], [ObjItem("ANY", "full")])

    if any_a:
        objs_b = (field_b or {}).get("objects") or []
        return FieldCmp(
            [ObjItem("ANY", "full")],
            [ObjItem(format_net_obj(o), "full") for o in objs_b] or [ObjItem("—", "none")],
        )

    if any_b:
        objs_a = (field_a or {}).get("objects") or []
        return FieldCmp(
            [ObjItem(format_net_obj(o), "full") for o in objs_a] or [ObjItem("—", "none")],
            [ObjItem("ANY", "full")],
        )

    nets_a_all = resolver.resolve_field_network(field_a)
    nets_b_all = resolver.resolve_field_network(field_b)
    objs_a = (field_a or {}).get("objects") or []
    objs_b = (field_b or {}).get("objects") or []

    def items(objs, other_nets):
        result = []
        for obj in objs:
            obj_nets = resolver.resolve_field_network({"kind": "RULE_KIND_LIST", "objects": [obj]})
            result.append(ObjItem(format_net_obj(obj), _net_status(obj_nets, other_nets)))
        return result or [ObjItem("—", "none")]

    return FieldCmp(items(objs_a, nets_b_all), items(objs_b, nets_a_all))


def _compare_svc_field(
    field_a: dict | None,
    field_b: dict | None,
    resolver: ObjectResolver,
) -> FieldCmp:
    any_a = _is_any_field(field_a)
    any_b = _is_any_field(field_b)

    if any_a and any_b:
        return FieldCmp([ObjItem("ANY", "full")], [ObjItem("ANY", "full")])

    if any_a:
        objs_b = (field_b or {}).get("objects") or []
        return FieldCmp(
            [ObjItem("ANY", "full")],
            [ObjItem(format_svc_obj(o), "full") for o in objs_b] or [ObjItem("—", "none")],
        )

    if any_b:
        objs_a = (field_a or {}).get("objects") or []
        return FieldCmp(
            [ObjItem(format_svc_obj(o), "full") for o in objs_a] or [ObjItem("—", "none")],
            [ObjItem("ANY", "full")],
        )

    svcs_a_all = resolver.resolve_field_service(field_a)
    svcs_b_all = resolver.resolve_field_service(field_b)
    objs_a = (field_a or {}).get("objects") or []
    objs_b = (field_b or {}).get("objects") or []

    def items(objs, other_svcs):
        result = []
        for obj in objs:
            obj_svcs = resolver.resolve_field_service({"kind": "RULE_KIND_LIST", "objects": [obj]})
            statuses = [_svc_status(s, other_svcs) for s in obj_svcs]
            status = "full" if statuses and all(s == "full" for s in statuses) \
                else "partial" if any(s in ("full", "partial") for s in statuses) \
                else "none"
            result.append(ObjItem(format_svc_obj(obj), status))
        return result or [ObjItem("—", "none")]

    return FieldCmp(items(objs_a, svcs_b_all), items(objs_b, svcs_a_all))


def compare_rules(
    rule_a: NormalizedRule,
    rule_b: NormalizedRule,
    resolver: ObjectResolver,
) -> RuleCmp:
    return RuleCmp(
        src=_compare_net_field(rule_a.source_addr,      rule_b.source_addr,      resolver),
        dst=_compare_net_field(rule_a.destination_addr, rule_b.destination_addr, resolver),
        svc=_compare_svc_field(rule_a.service,          rule_b.service,          resolver),
    )
