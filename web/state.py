"""Process-level cache: matchers keyed by snapshot path."""
from __future__ import annotations

from pathlib import Path

from ..core.matcher import RuleMatcher

_cache: dict[str, RuleMatcher] = {}


def get_matcher(snapshot_path: str, strict: bool = True) -> RuleMatcher | None:
    key = f"{snapshot_path}:{strict}"
    return _cache.get(key)


def set_matcher(snapshot_path: str, strict: bool, matcher: RuleMatcher):
    key = f"{snapshot_path}:{strict}"
    _cache[key] = matcher


def invalidate(snapshot_path: str):
    for k in list(_cache):
        if k.startswith(snapshot_path):
            del _cache[k]


def load_matcher(snapshot_path: str, strict: bool = True) -> RuleMatcher:
    """Returns cached matcher or builds from snapshot file."""
    m = get_matcher(snapshot_path, strict)
    if m:
        return m

    import json
    from ..core.resolver import ObjectResolver
    from ..cli.main import _normalize_rule

    with open(snapshot_path, encoding="utf-8") as f:
        snap = json.load(f)

    raw_list  = snap.get("rules") or []
    net_cache = snap.get("net_groups") or {}
    svc_cache = snap.get("svc_groups") or {}

    rules = [_normalize_rule(r, i) for i, r in enumerate(raw_list)]
    counters: dict[str, int] = {}
    for rule in rules:
        counters[rule.precedence] = counters.get(rule.precedence, 0) + 1
        rule.position_in_precedence = counters[rule.precedence]
    rules = [r for r in rules if r.precedence != "default"]

    resolver = ObjectResolver(
        fetch_net_group=lambda gid: net_cache.get(gid, []),
        fetch_svc_group=lambda gid: svc_cache.get(gid, []),
    )
    m = RuleMatcher(rules, resolver, strict=strict)
    set_matcher(snapshot_path, strict, m)
    return m
