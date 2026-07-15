# Developed by Ilya Semennikov
"""
Helpers for reading snapshots in both formats:
  - legacy (single group): {"rules": [...], "nat_rules": [...], "net_groups": {...}, ...}
  - multi  (all groups):   {"device_groups": {"<gid>": {...}}, "tree": [...], ...}
"""
from __future__ import annotations


def is_multi(snap: dict) -> bool:
    return "device_groups" in snap


def get_group(snap: dict, group_id: str | None = None) -> dict:
    """
    Return the flat group dict with keys: rules, nat_rules, net_groups, svc_groups.
    Works for both legacy and multi snapshots.
    """
    if not is_multi(snap):
        return snap

    groups = snap["device_groups"]
    if group_id and group_id in groups:
        return groups[group_id]
    if groups:
        return next(iter(groups.values()))
    return {}


def list_groups(snap: dict) -> list[dict]:
    """
    Return [{id, name, path, depth, rules_count, nat_rules_count}] for UI display.
    Legacy snapshots return a single-element list.
    """
    if not is_multi(snap):
        return [{
            "id":              snap.get("device_group_id", ""),
            "name":            snap.get("device_group_id", "—"),
            "path":            "",
            "depth":           0,
            "rules_count":     snap.get("rules_count", 0),
            "nat_rules_count": snap.get("nat_rules_count", 0),
        }]

    return [
        {
            "id":              gid,
            "name":            g.get("name", gid),
            "path":            g.get("path", ""),
            "depth":           g.get("depth", 0),
            "rules_count":     g.get("rules_count", 0),
            "nat_rules_count": g.get("nat_rules_count", 0),
        }
        for gid, g in snap["device_groups"].items()
    ]


def _ancestor_chain(tree: list[dict], group_id: str) -> list[str]:
    """ID предков group_id от корня до непосредственного родителя (сама группа не включена)."""
    idx = next((i for i, n in enumerate(tree) if n.get("id") == group_id), None)
    if idx is None:
        return []
    chain: list[str] = []
    depth = tree[idx].get("_depth", 0)
    for i in range(idx - 1, -1, -1):
        nd = tree[i].get("_depth", 0)
        if nd < depth:
            chain.append(tree[i]["id"])
            depth = nd
            if depth == 0:
                break
    chain.reverse()
    return chain


def _tag_source(rules: list[dict], gid: str, gname: str) -> list[dict]:
    tagged = []
    for r in rules:
        r2 = dict(r)
        r2["_source_group_id"]   = gid
        r2["_source_group_name"] = gname
        tagged.append(r2)
    return tagged


def get_effective_group(snap: dict, group_id: str | None = None,
                         include_parents: bool = False) -> dict:
    """
    Как get_group(), но при include_parents=True для multi-снапшота подмешивает
    pre/post-правила всех родительских групп по цепочке до корня — в порядке
    реального применения на устройстве:

        Root.pre → … → Parent.pre → own.pre → own.post → Parent.post → … → Root.post

    Каждое правило получает теги _source_group_id / _source_group_name, чтобы
    в UI можно было показать, из какой группы оно унаследовано.
    """
    if not is_multi(snap):
        gid = snap.get("device_group_id", "")
        return {
            **snap,
            "rules":     _tag_source(snap.get("rules") or [], gid, gid or "—"),
            "nat_rules": _tag_source(snap.get("nat_rules") or [], gid, gid or "—"),
        }

    groups = snap.get("device_groups") or {}
    if not groups:
        return {}
    if not group_id or group_id not in groups:
        group_id = next(iter(groups))

    own = groups[group_id]

    if not include_parents:
        gname = own.get("name", group_id)
        return {
            **own,
            "rules":     _tag_source(own.get("rules") or [], group_id, gname),
            "nat_rules": _tag_source(own.get("nat_rules") or [], group_id, gname),
        }

    ancestor_ids = [gid for gid in _ancestor_chain(snap.get("tree") or [], group_id)
                    if gid in groups]
    chain = ancestor_ids + [group_id]

    pre_rules,  post_rules  = [], []
    pre_nat,    post_nat    = [], []
    net_cache,  svc_cache   = {}, {}

    for gid in chain:
        g     = groups[gid]
        gname = g.get("name", gid)
        rules = _tag_source(g.get("rules") or [], gid, gname)
        nat   = _tag_source(g.get("nat_rules") or [], gid, gname)
        # extend(...) в порядке root→leaf для pre, вставка в начало для post
        # даёт leaf→root на выходе — за один проход по цепочке.
        pre_rules.extend(r for r in rules if r.get("_precedence") != "post")
        post_rules[0:0] = [r for r in rules if r.get("_precedence") == "post"]
        pre_nat.extend(n for n in nat if n.get("_precedence") != "post")
        post_nat[0:0] = [n for n in nat if n.get("_precedence") == "post"]
        net_cache.update(g.get("net_groups") or {})
        svc_cache.update(g.get("svc_groups") or {})

    return {
        "name":       own.get("name", group_id),
        "path":       own.get("path", ""),
        "depth":      own.get("depth", 0),
        "rules":      pre_rules + post_rules,
        "nat_rules":  pre_nat + post_nat,
        "net_groups": net_cache,
        "svc_groups": svc_cache,
    }
