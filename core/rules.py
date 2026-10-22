"""Нормализация SecurityRule / NatRule — чистая логика без I/O.

Живёт в ``core/``, чтобы web-слой не зависел от CLI. Используется
``web/state.py`` и ``web/routers/nat.py``; ``cli/builder.py`` переиспользует
те же функции (см. ``BACKLOG.md`` — отказ от CLI).
"""
from __future__ import annotations

from .models import NormalizedRule, NatRule
from .snapshot import get_effective_group

__all__ = [
    "normalize_rule",
    "build_rules",
    "normalize_nat_rule",
    "load_nat_rules_from_snapshot",
]


def normalize_rule(raw: dict, index: int) -> NormalizedRule:
    """Map a raw SecurityRule dict → NormalizedRule."""
    uid  = raw.get("id") or str(index)
    name = raw.get("name") or f"Rule-{index}"

    enabled = raw.get("enabled", True)
    if isinstance(enabled, str):
        enabled = enabled.lower() not in ("false", "0", "disabled")

    action_raw = raw.get("action", "SECURITY_RULE_ACTION_DENY")
    if "ALLOW" in str(action_raw).upper():
        action = "allow"
    elif "DROP" in str(action_raw).upper():
        action = "drop"
    else:
        action = "deny"

    precedence = raw.get("_precedence") or raw.get("precedence") or "default"
    if "PRE" in str(precedence).upper():
        precedence = "pre"
    elif "POST" in str(precedence).upper():
        precedence = "post"
    else:
        precedence = "default"

    return NormalizedRule(
        index            = index,
        uid              = uid,
        name             = name,
        enabled          = bool(enabled),
        action           = action,
        precedence       = precedence,
        source_addr      = raw.get("sourceAddr"),
        destination_addr = raw.get("destinationAddr"),
        service          = raw.get("service"),
        source_zone      = raw.get("sourceZone"),
        destination_zone = raw.get("destinationZone"),
        application      = raw.get("application"),
        source_group_id   = raw.get("_source_group_id", ""),
        source_group_name = raw.get("_source_group_name", ""),
        created_at        = raw.get("createdAt"),
        updated_at        = raw.get("updatedAt"),
        raw              = raw,
    )


def build_rules(raw_list: list[dict]) -> list[NormalizedRule]:
    """Normalize rules, set position_in_precedence, drop default set."""
    rules = [normalize_rule(r, i) for i, r in enumerate(raw_list)]
    counters: dict[str, int] = {}
    for rule in rules:
        counters[rule.precedence] = counters.get(rule.precedence, 0) + 1
        rule.position_in_precedence = counters[rule.precedence]
    return [r for r in rules if r.precedence != "default"]


def normalize_nat_rule(raw: dict, index: int) -> NatRule:
    src_type = raw.get("srcTranslationType", "")
    dst_type = raw.get("dstTranslationType", "")
    return NatRule(
        uid              = raw.get("id") or str(index),
        name             = raw.get("name") or f"NatRule-{index}",
        description      = raw.get("description") or "",
        position         = raw.get("position", index + 1),
        global_position  = raw.get("globalPosition", index + 1),
        enabled          = bool(raw.get("enabled", True)),
        precedence       = raw.get("_precedence", "pre"),
        source_addr      = raw.get("sourceAddr"),
        destination_addr = raw.get("destinationAddr"),
        service          = raw.get("service"),
        source_zone      = raw.get("sourceZone"),
        destination_zone = raw.get("destinationZone"),
        src_translation_type      = src_type,
        src_translation_addr_type = raw.get("srcTranslationAddrType", ""),
        src_translated_address    = raw.get("srcTranslatedAddress"),
        src_translated_port       = raw.get("srcTranslatedPort"),
        dst_translation_type   = dst_type,
        dst_translated_address = raw.get("dstTranslatedAddress"),
        dst_translated_port    = raw.get("dstTranslatedPort"),
        source_group_id   = raw.get("_source_group_id", ""),
        source_group_name = raw.get("_source_group_name", ""),
        raw = raw,
    )


def load_nat_rules_from_snapshot(snap: dict, group_id: str | None = None,
                                 include_parents: bool = False) -> list[NatRule]:
    """Load NAT rules from an already-parsed snapshot dict (single or multi format)."""
    grp = get_effective_group(snap, group_id, include_parents=include_parents)
    raw_list = grp.get("nat_rules") or []
    return [normalize_nat_rule(r, i) for i, r in enumerate(raw_list)]
