"""Хендлеры по загрузке данных: нормализуют правила, создают средства сопоставления, управляют источниками."""
from __future__ import annotations

import csv
import json
import sys
from typing import Optional

from .output import info, ok, warn, err, die, _print_connection_banner, c, _C
from ..core.models import NormalizedRule, NatRule, TrafficFlow
from ..core.resolver import ObjectResolver
from ..core.matcher import RuleMatcher
from ..core.snapshot import get_group, get_effective_group
from ..sources.ngfw_api import NGFWDirectSource
from ..sources.backend_api import NGFWBackendSource


def _normalize_rule(raw: dict, index: int) -> NormalizedRule:
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
        raw              = raw,
    )


def _build_rules(raw_list: list[dict]) -> list[NormalizedRule]:
    """Normalize rules, set position_in_precedence, drop default set."""
    rules = [_normalize_rule(r, i) for i, r in enumerate(raw_list)]
    counters: dict[str, int] = {}
    for rule in rules:
        counters[rule.precedence] = counters.get(rule.precedence, 0) + 1
        rule.position_in_precedence = counters[rule.precedence]
    return [r for r in rules if r.precedence != "default"]


def _normalize_nat_rule(raw: dict, index: int) -> NatRule:
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


def load_nat_rules(source, device_group_id: str) -> list[NatRule]:
    """Fetch NAT rules from API and normalize."""
    raw_list = source.get_nat_rules(device_group_id)
    return [_normalize_nat_rule(r, i) for i, r in enumerate(raw_list)]


def load_nat_rules_from_snapshot(snap: dict, group_id: str | None = None,
                                  include_parents: bool = False) -> list[NatRule]:
    """Load NAT rules from an already-parsed snapshot dict (single or multi format)."""
    grp = get_effective_group(snap, group_id, include_parents=include_parents)
    raw_list = grp.get("nat_rules") or []
    return [_normalize_nat_rule(r, i) for i, r in enumerate(raw_list)]


def build_matcher_from_snapshot(path: str, strict: bool = True,
                                 group_id: str | None = None) -> RuleMatcher:
    """Load RuleMatcher from a snapshot file (single or multi format)."""
    info(f"Снапшот: {path}")
    with open(path, encoding="utf-8") as f:
        snap = json.load(f)
    grp = get_group(snap, group_id)
    net_cache = grp.get("net_groups") or {}
    svc_cache = grp.get("svc_groups") or {}
    rules = _build_rules(grp.get("rules") or [])
    resolver = ObjectResolver(
        fetch_net_group=lambda gid: net_cache.get(gid, []),
        fetch_svc_group=lambda gid: svc_cache.get(gid, []),
    )
    ok(f"Загружено правил: {len(rules)}")
    return RuleMatcher(rules, resolver, strict=strict)


def build_matcher(source, device_group_id: str,
                  local_rules_path: Optional[str] = None,
                  local_objects_path: Optional[str] = None,
                  strict: bool = True) -> RuleMatcher:
    """Load rules from API or local files, build and return RuleMatcher."""
    if local_rules_path:
        info(f"Правила: локальный файл {local_rules_path}")
        with open(local_rules_path, encoding="utf-8") as f:
            raw_list = json.load(f)
    else:
        info("Загружаем правила из API…")
        raw_list = source.get_rules(device_group_id)

    rules = _build_rules(raw_list)
    total_loaded = len([_normalize_rule(r, i) for i, r in enumerate(raw_list)])
    ok(f"Правил загружено: {total_loaded}  →  в анализе PRE+POST: {len(rules)}")
    disabled = sum(1 for r in rules if not r.enabled)
    if disabled:
        info(f"  из них отключено (disabled): {disabled}")

    fetch_net = None
    fetch_svc = None

    if not local_objects_path:
        if hasattr(source, "get_network_group_items"):
            fetch_net = source.get_network_group_items
        if hasattr(source, "get_service_group_items"):
            fetch_svc = source.get_service_group_items
    else:
        info(f"Объекты: локальный файл {local_objects_path}")
        with open(local_objects_path, encoding="utf-8") as f:
            obj_cache = json.load(f)
        net_groups: dict[str, list] = obj_cache.get("net_groups", {})
        svc_groups: dict[str, list] = obj_cache.get("svc_groups", {})
        fetch_net = lambda gid: net_groups.get(gid, [])
        fetch_svc = lambda gid: svc_groups.get(gid, [])

    resolver = ObjectResolver(fetch_net_group=fetch_net, fetch_svc_group=fetch_svc)
    return RuleMatcher(rules, resolver, strict=strict)


def build_source(args):
    """Create and authenticate a data source from CLI args."""
    source_name = getattr(args, "source", "ngfw").lower()

    if source_name == "backend":
        backend_host = getattr(args, "backend_host", None)
        if not backend_host:
            die("--backend-host обязателен при --source backend")
        info(f"Источник: ngfw-manager backend → {backend_host}")
        src = NGFWBackendSource(
            host       = backend_host,
            username   = args.user or "",
            password   = args.password or "",
            token      = args.token,
            verify_ssl = args.verify_ssl,
        )
        if not args.token:
            info("Авторизация на backend…")
            src.login()
            ok("Backend: авторизован")
        _print_connection_banner(src)
        return src

    if not args.host:
        die("Укажите --host (например: https://10.1.31.100  или  https://localhost:3223)")

    src = NGFWDirectSource(
        host       = args.host,
        username   = args.user or "",
        password   = args.password or "",
        token      = args.token,
        verify_ssl = args.verify_ssl,
    )
    if not args.token:
        info("Авторизация…")
        tok = src.login()
        ok(f"Авторизован  BASE_URL={src.base_url}  token={tok[:16]}…")
    _print_connection_banner(src)
    return src


def maybe_save(args, source, device_group_id: str):
    """Save rules/objects to local files if --save-* flags are set."""
    if getattr(args, "save_rules", None):
        info(f"Сохраняем правила → {args.save_rules}")
        raw_rules = source.get_rules(device_group_id)
        with open(args.save_rules, "w", encoding="utf-8") as f:
            json.dump(raw_rules, f, ensure_ascii=False, indent=2)
        ok(f"Сохранено {len(raw_rules)} правил → {args.save_rules}")

    if getattr(args, "save_objects", None):
        warn("--save-objects: объекты встроены в правила, сохраните через --save-rules")


def load_csv(path: str) -> list[TrafficFlow]:
    """Load traffic flows from a CSV file."""
    flows: list[TrafficFlow] = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, 2):
            try:
                flows.append(TrafficFlow(
                    src_ip   = row["src_ip"].strip(),
                    dst_ip   = row["dst_ip"].strip(),
                    dst_port = int(row["dst_port"].strip()),
                    protocol = row["protocol"].strip(),
                    src_port = int(row.get("src_port", "0").strip() or "0"),
                    zone_src = row.get("zone_src", "").strip(),
                    zone_dst = row.get("zone_dst", "").strip(),
                ))
            except Exception as e:
                warn(f"CSV строка {i} пропущена: {e}")
    return flows


def select_device(source) -> tuple[str, str]:
    """Interactive device group selection. Returns (deviceGroupId, name)."""
    info("Получаем дерево групп устройств…")
    groups: list = []
    contexts_by_group: dict[str, list] = {}

    if hasattr(source, "get_device_groups"):
        try:
            groups = source.get_device_groups()
        except Exception as e:
            warn(f"GetDeviceGroupsTree: {e}")

    if hasattr(source, "get_virtual_contexts"):
        try:
            for ctx in source.get_virtual_contexts():
                gid = (ctx.get("deviceGroup") or {}).get("id")
                if not gid:
                    continue
                ctx_name = ctx.get("name") or ctx.get("id", "?")
                dev_name = (ctx.get("logicalDevice") or {}).get("name", "")
                label = dev_name if ctx_name == "Default" and dev_name else ctx_name
                contexts_by_group.setdefault(gid, []).append(label)
        except Exception as e:
            warn(f"ListVirtualContexts (справочно): {e}")

    if groups:
        return _select_from_device_groups(groups, contexts_by_group)

    warn("Не удалось получить список устройств.")
    gid = input("Введите deviceGroupId вручную: ").strip()
    return gid, ""


def _select_from_device_groups(groups: list,
                                contexts_by_group: dict | None = None) -> tuple[str, str]:
    """Render device group tree and prompt user for selection."""
    contexts_by_group = contexts_by_group or {}

    print()
    print(c("  Дерево групп устройств (выберите группу):", _C.BOLD))
    print()
    print(f"  {'#':>4}  {'Группа':<28}  {'ID группы':<38}  Контексты (справочно)")
    print("  " + "─" * 108)

    for i, grp in enumerate(groups, 1):
        gid        = grp.get("id", "?")
        name       = grp.get("name") or grp.get("id", "?")
        depth      = grp.get("_depth", 0)
        name_tree  = "  " * depth + name
        ctx_labels = contexts_by_group.get(gid, [])
        ctx_str    = ", ".join(ctx_labels[:5])
        if len(ctx_labels) > 5:
            ctx_str += f"  … (+{len(ctx_labels) - 5})"
        print(f"  {i:>4}  {name_tree:<28}  {gid:<38}  {c(ctx_str, _C.DIM)}")

    print()
    print(c("  Совет: --device принимает значение из колонки 'ID группы'", _C.DIM))
    print()

    while True:
        raw = input("Выберите номер или введите deviceGroupId: ").strip()
        if not raw:
            continue
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(groups):
                grp = groups[idx]
                return grp["id"], grp.get("name", "")
        except ValueError:
            return raw, ""
