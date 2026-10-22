# Developed by Ilya Semennikov
"""
WhereIsUse — все объекты (адреса/сети/сервисы и их группы) должны жить в
группе устройств Global; всё, что создано в дочерней группе, доступно только
внутри её ветки иерархии. Этот модуль:

  1. audit_non_global(snap)  — по всем группам ищет правила (безопасности и
     NAT), которые ссылаются хотя бы на один объект, реально принадлежащий
     не-Global группе.
  2. find_object(snap, query) — по UUID или имени находит объект(ы) и все
     места использования (группа + правило + поле).

Требует снапшот, синхронизированный с каталогами own_net_objects/
own_svc_objects на группу (см. web/routers/devices.py:_fetch_group) —
проверяй has_owner_data() перед вызовом.
"""
from __future__ import annotations

import re

from .resolver import is_any_kind

GLOBAL_NAME = "Global"

_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)

_NET_TOP_KEYS = (
    "networkIpAddress", "networkIpRange", "networkFqdn",
    "networkGeoAddress", "networkGroup",
)

_NET_FIELDS = (("source", "sourceAddr"), ("destination", "destinationAddr"))
_NAT_NET_FIELDS = _NET_FIELDS + (
    ("snat_to", "srcTranslatedAddress"), ("dnat_to", "dstTranslatedAddress"),
)


def has_owner_data(snap: dict) -> bool:
    """True если снапшот синхронизирован с каталогами владения объектами."""
    groups = snap.get("device_groups") or {}
    return bool(groups) and any(
        "own_net_objects" in g or "own_svc_objects" in g for g in groups.values()
    )


# ─── Индекс владельцев ───────────────────────────────────────────────────────

def build_owner_index(snap: dict) -> dict:
    """{'net': {oid: {id,name,kind,group_id,group_name}}, 'svc': {...}}"""
    net_idx: dict[str, dict] = {}
    svc_idx: dict[str, dict] = {}
    for gid, g in (snap.get("device_groups") or {}).items():
        gname = g.get("name", gid)
        for oid, obj in (g.get("own_net_objects") or {}).items():
            net_idx[oid] = {"id": oid, "name": obj.get("name") or oid,
                             "kind": obj.get("_kind", "?"),
                             "group_id": gid, "group_name": gname}
        for oid, obj in (g.get("own_svc_objects") or {}).items():
            svc_idx[oid] = {"id": oid, "name": obj.get("name") or oid,
                             "kind": obj.get("_kind", "?"),
                             "group_id": gid, "group_name": gname}
    return {"net": net_idx, "svc": svc_idx}


# ─── Извлечение id из объектов правила ──────────────────────────────────────

def _net_obj_id(obj: dict) -> str | None:
    for key in _NET_TOP_KEYS:
        if key in obj:
            return obj[key].get("id")
    return None


def _svc_obj_id(item: dict) -> str | None:
    if "service" in item:
        return item["service"].get("id")
    if "serviceGroup" in item:
        return item["serviceGroup"].get("id")
    return None


def _walk_net_objects(objs: list, cache: dict, seen: set, ids: set) -> None:
    for obj in objs:
        oid = _net_obj_id(obj)
        if not oid:
            continue
        ids.add(oid)
        if "networkGroup" in obj and oid not in seen:
            seen.add(oid)
            _walk_net_objects(cache.get(oid) or [], cache, seen, ids)


def _walk_svc_objects(items: list, cache: dict, seen: set, ids: set) -> None:
    for item in items:
        oid = _svc_obj_id(item)
        if not oid:
            continue
        ids.add(oid)
        if "serviceGroup" in item and oid not in seen:
            seen.add(oid)
            _walk_svc_objects(cache.get(oid) or [], cache, seen, ids)


def _collect_net_ids(field: dict | None, cache: dict) -> set[str]:
    """Все id, затронутые полем (включая содержимое вложенных networkGroup)."""
    if is_any_kind(field):
        return set()
    ids: set[str] = set()
    _walk_net_objects(field.get("objects") or [], cache, set(), ids)
    return ids


def _collect_svc_ids(field: dict | None, cache: dict) -> set[str]:
    if is_any_kind(field):
        return set()
    ids: set[str] = set()
    _walk_svc_objects(field.get("objects") or [], cache, set(), ids)
    return ids


def _rule_ident(raw: dict, prefix: str, index: int) -> tuple[str, str]:
    uid = raw.get("id") or f"{prefix}-{index}"
    name = raw.get("name") or f"{prefix.title()}-{index}"
    return uid, name


def _action(raw: dict) -> str:
    action_raw = str(raw.get("action", "")).upper()
    if "ALLOW" in action_raw:
        return "allow"
    if "DROP" in action_raw:
        return "drop"
    return "deny"


# ─── 1. Аудит: правила с объектами вне Global ───────────────────────────────

def _offending(idx: dict, net_ids: set[str], svc_ids: set[str]) -> list[dict]:
    out = []
    for oid in net_ids:
        entry = idx["net"].get(oid)
        if entry and entry["group_name"] != GLOBAL_NAME:
            out.append(entry)
    for oid in svc_ids:
        entry = idx["svc"].get(oid)
        if entry and entry["group_name"] != GLOBAL_NAME:
            out.append(entry)
    return out


def audit_non_global(snap: dict) -> list[dict]:
    """Правила (безопасности + NAT), ссылающиеся хотя бы на один объект вне
    Global. Правила, где все объекты — из Global, в результат не попадают."""
    idx = build_owner_index(snap)
    groups = snap.get("device_groups") or {}
    results: list[dict] = []

    for gid, g in groups.items():
        gname = g.get("name", gid)
        net_cache = g.get("net_groups") or {}
        svc_cache = g.get("svc_groups") or {}

        for i, raw in enumerate(g.get("rules") or []):
            net_ids = (_collect_net_ids(raw.get("sourceAddr"), net_cache)
                       | _collect_net_ids(raw.get("destinationAddr"), net_cache))
            svc_ids = _collect_svc_ids(raw.get("service"), svc_cache)
            offending = _offending(idx, net_ids, svc_ids)
            if not offending:
                continue
            uid, name = _rule_ident(raw, "rule", i)
            results.append({
                "kind": "security", "group_id": gid, "group_name": gname,
                "rule_uid": uid, "rule_name": name,
                "action": _action(raw), "enabled": bool(raw.get("enabled", True)),
                "precedence": raw.get("_precedence", ""),
                "position": raw.get("position", i + 1),
                "created_at": raw.get("createdAt"), "updated_at": raw.get("updatedAt"),
                "offending": offending,
            })

        for i, raw in enumerate(g.get("nat_rules") or []):
            net_ids: set[str] = set()
            for _, key in _NAT_NET_FIELDS:
                net_ids |= _collect_net_ids(raw.get(key), net_cache)
            svc_ids = _collect_svc_ids(raw.get("service"), svc_cache)
            offending = _offending(idx, net_ids, svc_ids)
            if not offending:
                continue
            uid, name = _rule_ident(raw, "nat", i)
            results.append({
                "kind": "nat", "group_id": gid, "group_name": gname,
                "rule_uid": uid, "rule_name": name,
                "precedence": raw.get("_precedence", ""),
                "position": raw.get("position", i + 1),
                "offending": offending,
            })

    return results


def build_audit_summary(snap: dict, entries: list[dict] | None = None) -> dict:
    """Сводка для шапки/футера страницы: сколько всего объектов вне Global
    (после sync) и сколько правил (безопасности / NAT) их используют."""
    idx = build_owner_index(snap)
    if entries is None:
        entries = audit_non_global(snap)

    net_non_global = sum(1 for e in idx["net"].values() if e["group_name"] != GLOBAL_NAME)
    svc_non_global = sum(1 for e in idx["svc"].values() if e["group_name"] != GLOBAL_NAME)

    rules_total = nat_total = 0
    for g in (snap.get("device_groups") or {}).values():
        rules_total += len(g.get("rules") or [])
        nat_total += len(g.get("nat_rules") or [])

    return {
        "objects_non_global":     net_non_global + svc_non_global,
        "objects_non_global_net": net_non_global,
        "objects_non_global_svc": svc_non_global,
        "rules_total":            rules_total,
        "rules_flagged":          sum(1 for e in entries if e["kind"] == "security"),
        "nat_rules_total":        nat_total,
        "nat_rules_flagged":      sum(1 for e in entries if e["kind"] == "nat"),
    }


# ─── 2. Поиск использования объекта ─────────────────────────────────────────

def _net_field_match(field: dict | None, cache: dict, target_id: str) -> str | None:
    if is_any_kind(field):
        return None
    top_ids = {_net_obj_id(o) for o in (field.get("objects") or [])}
    if target_id in top_ids:
        return "direct"
    if target_id in _collect_net_ids(field, cache):
        return "group"
    return None


def _svc_field_match(field: dict | None, cache: dict, target_id: str) -> str | None:
    if is_any_kind(field):
        return None
    top_ids = {_svc_obj_id(o) for o in (field.get("objects") or [])}
    if target_id in top_ids:
        return "direct"
    if target_id in _collect_svc_ids(field, cache):
        return "group"
    return None


def _scan_usages(snap: dict, space: str, target_id: str) -> list[dict]:
    groups = snap.get("device_groups") or {}
    usages: list[dict] = []

    for gid, g in groups.items():
        gname = g.get("name", gid)
        net_cache = g.get("net_groups") or {}
        svc_cache = g.get("svc_groups") or {}

        for i, raw in enumerate(g.get("rules") or []):
            fields = []
            if space == "net":
                for label, key in _NET_FIELDS:
                    m = _net_field_match(raw.get(key), net_cache, target_id)
                    if m:
                        fields.append({"field": label, "via": m})
            else:
                m = _svc_field_match(raw.get("service"), svc_cache, target_id)
                if m:
                    fields.append({"field": "service", "via": m})
            if fields:
                uid, name = _rule_ident(raw, "rule", i)
                usages.append({"kind": "security", "group_id": gid, "group_name": gname,
                                "rule_uid": uid, "rule_name": name,
                                "created_at": raw.get("createdAt"),
                                "updated_at": raw.get("updatedAt"), "fields": fields})

        for i, raw in enumerate(g.get("nat_rules") or []):
            fields = []
            if space == "net":
                for label, key in _NAT_NET_FIELDS:
                    m = _net_field_match(raw.get(key), net_cache, target_id)
                    if m:
                        fields.append({"field": label, "via": m})
            else:
                m = _svc_field_match(raw.get("service"), svc_cache, target_id)
                if m:
                    fields.append({"field": "service", "via": m})
            if fields:
                uid, name = _rule_ident(raw, "nat", i)
                usages.append({"kind": "nat", "group_id": gid, "group_name": gname,
                                "rule_uid": uid, "rule_name": name, "fields": fields})

    return usages


def find_object(snap: dict, query: str) -> dict:
    """query — UUID (точное совпадение) или имя (точное, затем по подстроке,
    без учёта регистра). Возвращает {'query', 'matches': [{'object','usages'}]}."""
    idx = build_owner_index(snap)
    q = (query or "").strip()
    ql = q.lower()
    is_uuid = bool(_UUID_RE.match(q))

    exact: list[dict] = []
    partial: list[dict] = []
    for space in ("net", "svc"):
        for oid, entry in idx[space].items():
            if is_uuid:
                if oid.lower() == ql:
                    exact.append({**entry, "space": space})
                continue
            name_l = entry["name"].lower()
            if name_l == ql:
                exact.append({**entry, "space": space})
            elif ql in name_l:
                partial.append({**entry, "space": space})

    matches = []
    for obj in (exact or partial):
        matches.append({"object": obj, "usages": _scan_usages(snap, obj["space"], obj["id"])})

    return {"query": q, "matches": matches}
