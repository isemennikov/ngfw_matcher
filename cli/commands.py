# Developed by Ilya Semennikov
"""Хендрелы."""
from __future__ import annotations

import json
import sys

from .output import (
    info, ok, warn, err, die,
    _print_rules_list, _row, c, _C,
    print_result, print_summary, export_csv, export_fullview_json,
    print_rule_card, print_shadowed_analysis, print_partial_shadowed_analysis,
    export_shadowed_json, print_hits_table, print_version_footer, _json_meta,
)
from .builder import (
    build_matcher, build_matcher_from_snapshot,
    build_source, maybe_save, select_device, load_csv,
)
from ..core.models import TrafficFlow
from ..core.matcher import RuleMatcher
from ..core.utils import parse_ports
from ..sources.ngfw_api import NGFWDirectSource


_INTERACTIVE_HELP = """
Формат ввода:
  src_ip  dst_ip  dst_port  protocol  [src_port]  [zone_src]  [zone_dst]

Примеры:
  192.168.1.10  10.0.0.5   443   tcp
  10.1.2.3      8.8.8.8    53    udp   1024   LAN   WAN
  172.16.0.1    10.5.0.1   0     icmp

Команды:
  help   — эта справка
  rules  — вывести все правила (краткий список)
  q      — выход
"""


def interactive_mode(matcher: RuleMatcher, verbose: bool):
    print(c("\n[Интерактивный режим] Введите 'help' или запрос трафика.\n", _C.CYAN))

    while True:
        try:
            line = input(c("traffic> ", _C.BOLD, _C.WHITE)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not line:
            continue
        cmd = line.lower()
        if cmd in ("q", "quit", "exit"):
            break
        if cmd == "help":
            print(_INTERACTIVE_HELP)
            continue
        if cmd == "rules":
            _print_rules_list(matcher.rules)
            continue

        parts = line.split()
        if len(parts) < 4:
            warn("Нужно минимум: src_ip dst_ip dst_port protocol")
            continue

        try:
            flow = TrafficFlow(
                src_ip   = parts[0],
                dst_ip   = parts[1],
                dst_port = int(parts[2]),
                protocol = parts[3],
                src_port = int(parts[4]) if len(parts) > 4 else 0,
                zone_src = parts[5] if len(parts) > 5 else "",
                zone_dst = parts[6] if len(parts) > 6 else "",
            )
            result = matcher.match(flow)
            print_result(result, verbose=verbose)
        except ValueError as e:
            warn(f"Ошибка разбора: {e}")
        except Exception as e:
            err(f"Ошибка: {e}")


def _normalize_addr(value: str) -> str:
    return "0.0.0.0/0" if value.strip().lower() == "any" else value.strip()


def _make_flows(args) -> list[TrafficFlow]:
    src_raw = args.src or "any"
    dst_raw = args.dst or "any"
    proto   = (args.proto or "any").lower()

    srcs = [_normalize_addr(s) for s in src_raw.split(",")]
    dsts = [_normalize_addr(d) for d in dst_raw.split(",")]

    dport_str = str(getattr(args, "dport", None) or "any")
    ports     = parse_ports(dport_str)

    total = len(srcs) * len(dsts) * len(ports)
    if total > 200:
        warn(f"Будет проверено {total} комбинаций (src={len(srcs)} × dst={len(dsts)} × port={len(ports)})")

    flows = []
    for src in srcs:
        for dst in dsts:
            for port in ports:
                flows.append(TrafficFlow(
                    src_ip=src, dst_ip=dst, dst_port=port,
                    protocol=proto, src_port=0, zone_src="", zone_dst="",
                ))
    return flows


def _run_flow(args, matcher: RuleMatcher):
    """Dispatch to interactive / batch / single-request mode."""
    fullview = getattr(args, "fullview", False)

    if getattr(args, "interactive", False):
        interactive_mode(matcher, verbose=getattr(args, "verbose", False))
        return

    if getattr(args, "batch", None):
        info(f"Batch-режим: {args.batch}")
        flows = load_csv(args.batch)
        if not flows:
            die("CSV файл не содержит ни одного корректного потока")
        ok(f"Потоков для проверки: {len(flows)}")
        results = []
        for flow in flows:
            r = matcher.match(flow)
            results.append(r)
            print_result(r, verbose=getattr(args, "verbose", False))
        print_summary(results)
        if getattr(args, "output", None):
            export_csv(results, args.output)
        return

    if not fullview and not getattr(args, "proto", None):
        die("Укажите --proto (tcp | udp | icmp | any)")
    if fullview and not getattr(args, "proto", None):
        args.proto = "any"

    flows     = _make_flows(args)
    verbose   = getattr(args, "verbose", False)
    fetch_net = matcher.resolver._fetch_net_group
    fetch_svc = matcher.resolver._fetch_svc_group

    if len(flows) == 1:
        result  = matcher.match(flows[0])
        print_result(result, verbose=verbose, fullview=fullview,
                     fetch_net_group=fetch_net, fetch_svc_group=fetch_svc)
        results = [result]
    else:
        results = []
        for flow in flows:
            r = matcher.match(flow)
            results.append(r)
            print_result(r, verbose=verbose, fullview=fullview,
                         fetch_net_group=fetch_net, fetch_svc_group=fetch_svc)
        print_summary(results)

    if fullview and getattr(args, "output", None):
        query = {
            "src":   args.src   or "any",
            "dst":   args.dst   or "any",
            "dport": str(getattr(args, "dport", None) or "any"),
            "proto": args.proto or "any",
        }
        info(f"Fullview scan: {len(flows)} поток(ов)")
        flow_results = []
        total_matched = 0
        for flow in flows:
            rules = matcher.fullview_scan(flow)
            total_matched += len(rules)
            flow_results.append({"flow": flow, "rules": rules})
        ok(f"Всего правил найдено: {total_matched}  (потоков: {len(flows)})")
        export_fullview_json(
            flow_results, query, args.output,
            fetch_net_group=fetch_net,
            fetch_svc_group=fetch_svc,
        )
    elif not fullview and getattr(args, "output", None):
        export_csv(results, args.output)


def run(args):
    if getattr(args, "snapshot", None):
        strict  = not getattr(args, "overlap", False)
        matcher = build_matcher_from_snapshot(args.snapshot, strict=strict)
        _run_flow(args, matcher)
        return
    if getattr(args, "rules_file", None):
        info("Оффлайн-режим: данные из локальных файлов")
        strict  = not getattr(args, "overlap", False)
        matcher = build_matcher(None, "", args.rules_file,
                                getattr(args, "objects_file", None), strict=strict)
        _run_flow(args, matcher)
        return

    source = build_source(args)
    if getattr(args, "device", None):
        device_group_id, device_group_name = args.device, ""
    else:
        device_group_id, device_group_name = select_device(source)

    if device_group_name:
        ok(f"Device Group Name: {device_group_name}")
    ok(f"Device Group ID:   {device_group_id}")

    maybe_save(args, source, device_group_id)

    strict = not getattr(args, "overlap", False)
    if not strict:
        info("Режим матчинга: --overlap (нестрогий, включая подсети)")
    matcher = build_matcher(source, device_group_id, strict=strict)
    _run_flow(args, matcher)


def cmd_test_connection(args):
    if not args.host:
        die("Укажите --host")

    src = NGFWDirectSource(
        host       = args.host,
        username   = args.user or "",
        password   = args.password or "",
        token      = args.token,
        verify_ssl = args.verify_ssl,
    )

    print(f"\n  Проверка подключения к {c(src.base_url, _C.CYAN, _C.BOLD)}\n")
    r = src.test_connection()

    for s in r.get("steps", []):
        mark   = c("  ✓", _C.GREEN, _C.BOLD) if s["ok"] else c("  ✗", _C.RED, _C.BOLD)
        detail = f"  {c(s['detail'], _C.DIM)}" if s["detail"] else ""
        print(f"{mark}  {s['step']}{detail}")
    print()

    if not r["auth"]:
        err("Авторизация не прошла")
        sys.exit(1)
    if not r["api_reached"]:
        warn("Авторизация прошла, но API недоступен")
        sys.exit(1)

    ok("Подключение работает\n")

    groups = r.get("device_groups") or []
    if groups:
        print(c("  Доступные группы устройств (используйте ID как --device):\n", _C.BOLD))
        print(f"  {'#':>4}  {'deviceGroupId':<38}  {'Путь / Имя'}")
        print("  " + "─" * 80)
        for i, g in enumerate(groups, 1):
            gid  = g.get("id", "?")
            path = g.get("_path") or g.get("name") or gid
            print(f"  {i:>4}  {c(gid, _C.CYAN):<38}  {path}")
        print()
    else:
        warn("Список групп устройств пуст или недоступен")


def cmd_find_rule(args):
    import re

    if getattr(args, "snapshot", None):
        matcher = build_matcher_from_snapshot(args.snapshot)
    elif getattr(args, "rules_file", None):
        info("Оффлайн-режим: данные из локальных файлов")
        matcher = build_matcher(None, "", args.rules_file,
                                getattr(args, "objects_file", None))
    else:
        source = build_source(args)
        if getattr(args, "device", None):
            device_group_id, device_group_name = args.device, ""
        else:
            device_group_id, device_group_name = select_device(source)
        if device_group_name:
            ok(f"Device Group Name: {device_group_name}")
        ok(f"Device Group ID:   {device_group_id}")
        matcher = build_matcher(source, device_group_id)

    pattern  = args.name.strip()
    _UUID_RE = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        re.IGNORECASE,
    )
    if _UUID_RE.match(pattern):
        found = [r for r in matcher.rules if r.uid.lower() == pattern.lower()]
    else:
        pl    = pattern.lower()
        found = [r for r in matcher.rules if pl in r.name.lower()]

    found.sort(key=lambda r: r.index)

    if not found:
        warn(f"Правила не найдены по запросу: {pattern!r}")
        return

    ok(f"Найдено правил: {len(found)}")
    fetch_net = matcher.resolver._fetch_net_group
    fetch_svc = matcher.resolver._fetch_svc_group

    for rule in found:
        print_rule_card(rule, fetch_net, fetch_svc)

    if getattr(args, "output", None):
        _export_find_rule_json(found, args.output)


def _export_find_rule_json(rules: list, path: str):
    out = [
        {
            "name":            r.name,
            "uid":             r.uid,
            "action":          r.action,
            "enabled":         r.enabled,
            "precedence":      r.precedence,
            "position":        r.position_in_precedence or (r.index + 1),
            "global_position": r.index + 1,
        }
        for r in rules
    ]
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"_ngfw_matcher": _json_meta(), "count": len(out), "rules": out},
                  f, ensure_ascii=False, indent=2)
    print(c(f"[+] Найденные правила → {path}  ({len(out)} записей)", _C.GREEN))


def cmd_check_shadowed(args):
    if getattr(args, "snapshot", None):
        matcher = build_matcher_from_snapshot(args.snapshot)
    elif getattr(args, "rules_file", None):
        info("Оффлайн-режим: данные из локальных файлов")
        matcher = build_matcher(None, "", args.rules_file,
                                getattr(args, "objects_file", None))
    else:
        source = build_source(args)
        if getattr(args, "device", None):
            device_group_id, device_group_name = args.device, ""
        else:
            device_group_id, device_group_name = select_device(source)
        if device_group_name:
            ok(f"Device Group Name: {device_group_name}")
        ok(f"Device Group ID:   {device_group_id}")
        matcher = build_matcher(source, device_group_id)

    from ..core.matcher import RuleMatcher as _RM
    total   = len(matcher.rules)
    enabled = sum(1 for r in matcher.rules if r.enabled)
    zonal   = sum(1 for r in matcher.rules if r.enabled and (
        matcher.resolver.resolve_field_zone(r.source_zone) or
        matcher.resolver.resolve_field_zone(r.destination_zone)
    ))
    l7_skip = sum(
        1 for r in matcher.rules
        if r.enabled
        and not matcher.resolver.resolve_field_zone(r.source_zone)
        and not matcher.resolver.resolve_field_zone(r.destination_zone)
        and (
            _RM._is_app_only(r)
            or _RM._field_has_fqdn(r.source_addr)
            or _RM._field_has_fqdn(r.destination_addr)
        )
    )
    info(f"Правил PRE+POST: {total}  включено: {enabled}  "
         f"зональных: {zonal}  FQDN/app-only: {l7_skip}  "
         f"в анализе: {enabled - zonal - l7_skip}")

    if getattr(args, "partial", False):
        info("Режим: частичное пересечение (--partial)")
        results = matcher.check_partial_shadowed()
        print_partial_shadowed_analysis(results)
    else:
        results = matcher.check_shadowed()
        print_shadowed_analysis(results)

    if getattr(args, "output", None):
        export_shadowed_json(results, args.output)


def cmd_rule_hits(args):
    source = build_source(args)

    if getattr(args, "device", None):
        device_group_id, device_group_name = args.device, ""
    else:
        device_group_id, device_group_name = select_device(source)

    if device_group_name:
        ok(f"Device Group Name: {device_group_name}")
    ok(f"Device Group ID:   {device_group_id}")

    info("Загружаем список правил…")
    raw_rules = source.get_rules(device_group_id)
    raw_rules = [r for r in raw_rules if r.get("_precedence") != "default"]

    pattern = getattr(args, "rule", None)
    if pattern:
        pl        = pattern.lower()
        raw_rules = [r for r in raw_rules if pl in (r.get("name") or "").lower()]
        if not raw_rules:
            warn(f"Правила не найдены по шаблону: {pattern!r}")
            return
        ok(f"Совпавших правил: {len(raw_rules)}")
    else:
        ok(f"Правил в политике: {len(raw_rules)}")

    seen_ids: set[str] = set()
    rules_meta = []
    for r in raw_rules:
        rid = r.get("id")
        if rid and rid not in seen_ids:
            seen_ids.add(rid)
            rules_meta.append((rid, r.get("name", "?"), r.get("enabled", True)))

    if not rules_meta:
        warn("У правил нет идентификаторов — статистика недоступна")
        return

    batch_size = getattr(args, "batch_size", 30)
    info(f"Запрашиваем hits-счётчики ({len(rules_meta)} правил, батч {batch_size})…")

    rule_ids   = [rid for rid, _, _ in rules_meta]
    hits_data  = source.get_rule_hits(rule_ids, batch_size=batch_size)
    hits_by_id = {h["ruleId"]: h for h in hits_data}

    rows = []
    for rid, name, enabled in rules_meta:
        raw_hits = hits_by_id.get(rid, {}).get("hits", "0")
        try:
            hits = int(raw_hits)
        except (ValueError, TypeError):
            hits = 0
        rows.append({"name": name, "hits": hits, "enabled": enabled})

    if getattr(args, "sort_hits", False):
        rows.sort(key=lambda r: r["hits"], reverse=True)
    print_hits_table(rows)
