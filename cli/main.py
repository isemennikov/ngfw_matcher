"""
ngfw-matcher — CLI для симуляции трафика через политию PT NGFW.

Два источника данных (выбираются флагом --source):
    ngfw    [приоритет] — прямой PT NGFW API (актуальные данные)
    backend             — REST API ngfw-manager (кэш PostgreSQL)

Три режима ввода трафика:
    одиночный запрос    — флаги --src --dst --dport --proto
    batch               — --batch traffic.csv
    интерактивный       — --interactive
"""
# Developed by Ilya Semennikov
from __future__ import annotations
import argparse
import csv
import getpass
import json
import logging
import sys
from typing import Optional

from ..core.models   import TrafficFlow, NormalizedRule
from ..core.resolver import ObjectResolver
from ..core.matcher  import RuleMatcher
from ..sources.ngfw_api    import NGFWDirectSource
from ..sources.backend_api import NGFWBackendSource

# Forward ref для аннотации в _normalize_rule
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    pass
from .output import (print_result, print_summary, export_csv, export_fullview_json,
                      print_rule_card, print_shadowed_analysis, export_shadowed_json,
                      print_hits_table, print_version_footer, c, _C)


# ─── Утилиты ─────────────────────────────────────────────────────────────────

def info(msg: str):  print(c(f"[*] {msg}", _C.BLUE),   file=sys.stderr)
def ok(msg: str):    print(c(f"[+] {msg}", _C.GREEN),  file=sys.stderr)
def warn(msg: str):  print(c(f"[!] {msg}", _C.YELLOW), file=sys.stderr)
def err(msg: str):   print(c(f"[✗] {msg}", _C.RED),    file=sys.stderr)


def die(msg: str, code: int = 1):
    err(msg)
    sys.exit(code)


# ─── Выбор устройства ────────────────────────────────────────────────────────

def select_device(source) -> tuple[str, str]:
    """
    Интерактивный выбор deviceGroupId из дерева групп устройств.
    Правила в PT NGFW назначаются группам, а не виртуальным контекстам.
    Контексты показываются справочно — чтобы было понятно, что находится в группе.
    Возвращает (deviceGroupId, deviceGroupName).
    """
    info("Получаем дерево групп устройств…")
    groups: list = []
    contexts_by_group: dict[str, list] = {}

    if hasattr(source, "get_device_groups"):
        try:
            groups = source.get_device_groups()
        except Exception as e:
            warn(f"GetDeviceGroupsTree: {e}")

    # Обогащаем контекстами: показываем, какие устройства входят в каждую группу
    if hasattr(source, "get_virtual_contexts"):
        try:
            for ctx in source.get_virtual_contexts():
                gid = (ctx.get("deviceGroup") or {}).get("id")
                if not gid:
                    continue
                ctx_name = ctx.get("name") or ctx.get("id", "?")
                dev_name = (ctx.get("logicalDevice") or {}).get("name", "")
                # Default-контексты идентифицируем по физическому устройству
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
    """Дерево групп устройств с контекстами. Возвращает (deviceGroupId, name)."""
    contexts_by_group = contexts_by_group or {}

    print()
    print(c("  Дерево групп устройств (выберите группу):", _C.BOLD))
    print()
    print(f"  {'#':>4}  {'Группа':<28}  {'ID группы':<38}  Контексты (справочно)")
    print("  " + "─" * 108)

    for i, grp in enumerate(groups, 1):
        gid   = grp.get("id", "?")
        name  = grp.get("name") or grp.get("id", "?")
        depth = grp.get("_depth", 0)

        indent    = "  " * depth
        name_tree = f"{indent}{name}"

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


# ─── Загрузка данных ─────────────────────────────────────────────────────────

def build_matcher_from_snapshot(path: str, strict: bool = True) -> RuleMatcher:
    """Строит RuleMatcher из снапшота — без обращений к API."""
    info(f"Снапшот: {path}")
    with open(path, encoding="utf-8") as f:
        snap = json.load(f)

    device_group_id   = snap.get("device_group_id", "?")
    device_group_name = snap.get("device_group_name", "")
    captured_at       = snap.get("captured_at", "?")
    if device_group_name:
        ok(f"Device Group Name: {device_group_name}")
    ok(f"Device Group ID:   {device_group_id}")
    ok(f"Снапшот от:        {captured_at}  ({snap.get('rules_count', '?')} правил)")

    raw_list  = snap.get("rules") or []
    net_cache = snap.get("net_groups") or {}
    svc_cache = snap.get("svc_groups") or {}

    rules = [_normalize_rule(r, i) for i, r in enumerate(raw_list)]
    counters: dict[str, int] = {}
    for rule in rules:
        counters[rule.precedence] = counters.get(rule.precedence, 0) + 1
        rule.position_in_precedence = counters[rule.precedence]
    total_loaded = len(rules)
    rules = [r for r in rules if r.precedence != "default"]
    ok(f"Правил загружено: {total_loaded}  →  в анализе PRE+POST: {len(rules)}")

    resolver = ObjectResolver(
        fetch_net_group=lambda gid: net_cache.get(gid, []),
        fetch_svc_group=lambda gid: svc_cache.get(gid, []),
    )
    return RuleMatcher(rules, resolver, strict=strict)

def build_matcher(source, device_group_id: str,
                  local_rules_path: Optional[str] = None,
                  local_objects_path: Optional[str] = None,
                  strict: bool = True) -> RuleMatcher:
    """
    Загрузить правила, построить ObjectResolver с callback'ами к API,
    вернуть RuleMatcher.

    PT NGFW API v2 отдаёт объекты прямо внутри SecurityRule в виде
    вложенных dict (NetworkObject / ServiceItem) — они уже содержат
    все нужные данные (inet, from/to, protocol, ports).

    Группы (networkGroup / serviceGroup) содержат только id/name —
    их нужно раскрывать отдельными вызовами GetNetworkObjectGroup /
    GetServiceGroup. Для этого передаём callback'и в ObjectResolver.
    """

    # ── Правила ───────────────────────────────────────────────────────────────
    if local_rules_path:
        info(f"Правила: локальный файл {local_rules_path}")
        with open(local_rules_path, encoding="utf-8") as f:
            raw_list = json.load(f)
        rules = [_normalize_rule(r, i) for i, r in enumerate(raw_list)]
    else:
        info("Загружаем правила из API…")
        raw_list = source.get_rules(device_group_id)
        rules    = [_normalize_rule(r, i) for i, r in enumerate(raw_list)]

    # Проставляем position_in_precedence — позиция внутри каждого набора (1-based)
    # Это то что показывает СУ в своём интерфейсе
    counters: dict[str, int] = {}
    for rule in rules:
        counters[rule.precedence] = counters.get(rule.precedence, 0) + 1
        rule.position_in_precedence = counters[rule.precedence]

    # Исключаем набор default: оставляем только PRE и POST.
    # В типичной конфигурации PT NGFW default дублирует PRE/POST,
    # что порождает ложные теневые правила.
    total_loaded = len(rules)
    rules = [r for r in rules if r.precedence != "default"]

    ok(f"Правил загружено: {total_loaded}  →  в анализе PRE+POST: {len(rules)}")
    disabled = sum(1 for r in rules if not r.enabled)
    if disabled:
        info(f"  из них отключено (disabled): {disabled}")

    # ── Resolver c callback'ами к API ─────────────────────────────────────────
    # ObjectResolver получает функции для раскрытия групп «на лету».
    # Если source не поддерживает эти методы (оффлайн-режим) — передаём None.

    fetch_net = None
    fetch_svc = None

    if not local_objects_path:
        if hasattr(source, "get_network_group_items"):
            fetch_net = source.get_network_group_items
        if hasattr(source, "get_service_group_items"):
            fetch_svc = source.get_service_group_items
    else:
        # Оффлайн: загружаем кэш групп из файла и строим замыкания
        info(f"Объекты: локальный файл {local_objects_path}")
        with open(local_objects_path, encoding="utf-8") as f:
            obj_cache = json.load(f)

        net_groups: dict[str, list] = obj_cache.get("net_groups", {})
        svc_groups: dict[str, list] = obj_cache.get("svc_groups", {})

        def fetch_net(gid: str) -> list:
            return net_groups.get(gid, [])

        def fetch_svc(gid: str) -> list:
            return svc_groups.get(gid, [])

    resolver = ObjectResolver(
        fetch_net_group=fetch_net,
        fetch_svc_group=fetch_svc,
    )
    return RuleMatcher(rules, resolver, strict=strict)


def _normalize_rule(raw: dict, index: int) -> "NormalizedRule":
    """Преобразует сырой SecurityRule dict → NormalizedRule."""
    uid  = raw.get("id") or str(index)
    name = raw.get("name") or f"Rule-{index}"

    enabled = raw.get("enabled", True)
    if isinstance(enabled, str):
        enabled = enabled.lower() not in ("false", "0", "disabled")

    # action: SECURITY_RULE_ACTION_ALLOW / _DROP / _DENY / _RESET_*
    action_raw = raw.get("action", "SECURITY_RULE_ACTION_DENY")
    if "ALLOW" in str(action_raw).upper():
        action = "allow"
    elif "DROP" in str(action_raw).upper():
        action = "drop"
    else:
        action = "deny"

    precedence = raw.get("_precedence") or raw.get("precedence") or "default"
    # Нормализуем строку precedence.
    # Важно: проверять _POST раньше _PRE, потому что "PRECEDENCE" содержит "PRE"
    # как подстроку — иначе RULE_PRECEDENCE_POST ошибочно попадёт в "pre".
    _p = str(precedence).upper()
    if _p.endswith("_POST") or _p == "POST":
        precedence = "post"
    elif _p.endswith("_PRE") or _p == "PRE":
        precedence = "pre"
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
        raw              = raw,
    )


# ─── CSV ─────────────────────────────────────────────────────────────────────

def load_csv(path: str) -> list[TrafficFlow]:
    """
    Ожидаемые колонки (первая строка — заголовок):
      src_ip, dst_ip, dst_port, protocol [, src_port, zone_src, zone_dst]
    """
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


# ─── Интерактивный режим ─────────────────────────────────────────────────────

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


def _print_rules_list(rules: list[NormalizedRule]):
    print(f"\n  {'#':>5}  {'Статус':8}  {'Действие':8}  {'Набор':8}  Имя")
    print("  " + "─" * 70)
    for r in rules:
        st   = c("ON ", _C.GREEN)  if r.enabled else c("OFF", _C.YELLOW)
        act  = c("ALLOW", _C.GREEN) if r.action == "allow" else c("DENY ", _C.RED)
        name = r.name[:42]
        print(f"  {r.index+1:>5}  {st}       {act}    {r.precedence:8}  {name}")
    print()


# ─── Построение источника данных ─────────────────────────────────────────────

def _print_connection_banner(src):
    from ..sources.ngfw_api import NGFWDirectSource
    from ..sources.backend_api import NGFWBackendSource

    print(file=sys.stderr)
    print(c("  ┌─ Подключение ──────────────────────────────────────────────┐", _C.DIM), file=sys.stderr)
    if isinstance(src, NGFWDirectSource):
        print(c(f"  │  BASE_URL : {src.base_url}", _C.DIM), file=sys.stderr)
    elif isinstance(src, NGFWBackendSource):
        print(c(f"  │  Backend  : {src.host}", _C.DIM), file=sys.stderr)
    print(c("  └────────────────────────────────────────────────────────────┘", _C.DIM), file=sys.stderr)
    print(file=sys.stderr)


def build_source(args):
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


# ─── Сохранение правил / объектов ────────────────────────────────────────────

def maybe_save(args, source, device_group_id: str):
    if getattr(args, "save_rules", None):
        info(f"Сохраняем правила → {args.save_rules}")
        raw_rules = source.get_rules(device_group_id)
        with open(args.save_rules, "w", encoding="utf-8") as f:
            json.dump(raw_rules, f, ensure_ascii=False, indent=2)
        ok(f"Сохранено {len(raw_rules)} правил → {args.save_rules}")

    if getattr(args, "save_objects", None):
        warn("--save-objects: объекты встроены в правила, сохраните правила через --save-rules")


# ─── Основной поток ──────────────────────────────────────────────────────────

def run(args):
     # Снапшот-режим
    if getattr(args, "snapshot", None):
        strict  = not getattr(args, "overlap", False)
        matcher = build_matcher_from_snapshot(args.snapshot, strict=strict)
        _run_flow(args, matcher)
        return

    # Оффлайн-режим: всё из локальных файлов
    if getattr(args, "rules_file", None):
        info("Оффлайн-режим: данные из локальных файлов")
        strict = not getattr(args, "overlap", False)
        matcher = build_matcher(None, "", args.rules_file,
                                getattr(args, "objects_file", None),
                                strict=strict)
        _run_flow(args, matcher)
        return

    # Онлайн-режим
    source = build_source(args)

    # Если --device задан явно — имя неизвестно, получаем только ID
    if getattr(args, "device", None):
        device_group_id   = args.device
        device_group_name = ""
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


def _parse_ports(dport_str: str) -> list[int]:
    """
    Парсим --dport в список конкретных портов для проверки.

    "443"           → [443]
    "80,443,8080"   → [80, 443, 8080]
    "5000-5010"     → [5000, 5001, ..., 5010]
    "80,5000-5005"  → [80, 5000, 5001, ..., 5005]
    "any" / ""      → [0]  (0 = any, матчер понимает)

    Диапазоны > 1000 портов усекаются до первого+последнего,
    чтобы не гонять тысячи запросов — для матчинга достаточно
    проверить начало и конец диапазона.
    """
    if not dport_str or dport_str.lower() == "any":
        return [0]  # 0 означает any в TrafficFlow

    # Нормализуем различные варианты тире к ASCII-дефису:
    # en-dash (–, U+2013), em-dash (—, U+2014), минус (−, U+2212) и др.
    dport_str = dport_str.replace("–", "-").replace("—", "-") \
                         .replace("−", "-").replace("‐", "-") \
                         .replace("‑", "-").replace("―", "-")

    ports = []
    for part in dport_str.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo.strip()), int(hi.strip())
            if hi - lo > 1000:
                # Большой диапазон: берём только границы + середину
                ports += [lo, (lo + hi) // 2, hi]
                warn(f"Диапазон {lo}-{hi} ({hi-lo+1} портов) — проверяем границы и середину")
            else:
                ports += list(range(lo, hi + 1))
        else:
            ports.append(int(part))

    return sorted(set(ports))


def _normalize_addr(value: str) -> str:
    """'any' → '0.0.0.0/0', остальное — как есть (IP, CIDR или FQDN)."""
    return "0.0.0.0/0" if value.strip().lower() == "any" else value.strip()


def _make_flows(args) -> list[TrafficFlow]:
    """
    Строим список TrafficFlow из аргументов CLI.

    --src и --dst принимают:
      • Одиночный адрес: 192.168.1.10 | 10.0.0.0/8 | any | google.com
      • Список через запятую: 10.0.0.1,172.16.0.0/16,*.example.com

    --dport принимает одиночный порт, диапазон или список.

    Итоговый список flow = декартово произведение src × dst × port.
    """
    src_raw = args.src or "any"
    dst_raw = args.dst or "any"
    proto   = (args.proto or "any").lower()

    srcs = [_normalize_addr(s) for s in src_raw.split(",")]
    dsts = [_normalize_addr(d) for d in dst_raw.split(",")]

    dport_str = str(getattr(args, "dport", None) or "any")
    ports     = _parse_ports(dport_str)

    total = len(srcs) * len(dsts) * len(ports)
    if total > 200:
        warn(f"Будет проверено {total} комбинаций (src={len(srcs)} × dst={len(dsts)} × port={len(ports)})")

    flows = []
    for src in srcs:
        for dst in dsts:
            for port in ports:
                flows.append(TrafficFlow(
                    src_ip   = src,
                    dst_ip   = dst,
                    dst_port = port,
                    protocol = proto,
                    src_port = 0,
                    zone_src = "",
                    zone_dst = "",
                ))
    return flows


def _run_flow(args, matcher: RuleMatcher):
    """Запустить нужный режим (single / batch / interactive)."""

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

    # Одиночный/множественный запрос
    if not fullview and not getattr(args, "proto", None):
        die("Укажите --proto (tcp | udp | icmp | any)")

    if fullview and not getattr(args, "proto", None):
        args.proto = "any"

    flows   = _make_flows(args)
    verbose = getattr(args, "verbose", False)
    fetch_net = matcher.resolver._fetch_net_group
    fetch_svc = matcher.resolver._fetch_svc_group

    if len(flows) == 1:
        result = matcher.match(flows[0])
        print_result(result, verbose=verbose, fullview=fullview,
                     fetch_net_group=fetch_net, fetch_svc_group=fetch_svc)
        results = [result]
    else:
        # Несколько портов — показываем все, в конце сводку
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


# ─── argparse ────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ngfw-matcher",
        description="Симулятор трафика для PT NGFW — находит совпадающее правило и выявляет дубли.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── Общие аргументы (нужны во всех командах) ──────────────────────────────
    p.add_argument("--host",   metavar="URL",
                   help="Адрес СУ: https://10.1.31.100  или  https://localhost:3223")
    p.add_argument("--user",   metavar="LOGIN", help="Логин")
    p.add_argument("--pass",   dest="password", metavar="PWD", help="Пароль")
    p.add_argument("--token",  metavar="TOKEN", help="Bearer-токен (вместо логина/пароля)")
    p.add_argument("--verify-ssl", action="store_true",
                   help="Проверять TLS-сертификат (по умолчанию отключено)")
    p.add_argument("--log-level", default="WARNING",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    sub = p.add_subparsers(dest="command", metavar="КОМАНДА")

    # ── test-connection ────────────────────────────────────────────────────────
    sub.add_parser(
        "test-connection",
        help="Проверить подключение и авторизацию",
    )

    # ── match (основная команда) ───────────────────────────────────────────────
    m = sub.add_parser("match", help="Проверить трафик по правилам")

    m.add_argument("--source", choices=["ngfw", "backend"], default="ngfw",
                   help="ngfw (прямой API) | backend (кэш ngfw-manager). По умолчанию: ngfw")
    m.add_argument("--backend-host", metavar="URL",
                   help="URL ngfw-manager (при --source backend)")
    m.add_argument("--device", metavar="DEVICE_GROUP_ID",
                   help="deviceGroupId (если не указан — интерактивный выбор)")

    m.add_argument("--src",   metavar="IP/CIDR[,IP/CIDR...]",
                   help=("Source IP/сеть или 'any'. Несколько через запятую.\n"
                         "  Примеры: 192.168.1.10 | 10.0.0.0/8 | any | "
                         "10.0.0.1,172.16.0.0/16,192.168.5.0/24"))
    m.add_argument("--dst",   metavar="IP/CIDR[,IP/CIDR...]",
                   help=("Destination IP/сеть или 'any'. Несколько через запятую.\n"
                         "  Примеры: 10.0.0.5 | 10.43.16.0/24 | any | "
                         "10.0.0.5,192.168.1.0/24,10.43.0.0/16"))
    m.add_argument("--dport", metavar="PORTS",
                   help=("Порт(ы) назначения. Форматы:\n"
                         "  одиночный:  443\n"
                         "  диапазон:   5000-5322\n"
                         "  список:     80,443,8080\n"
                         "  mix:        80,443,5000-5322,8080-8090\n"
                         "  any:        any"))
    m.add_argument("--proto", metavar="PROTO", help="tcp | udp | icmp | any")

    m.add_argument("--fullview", action="store_true",
                   help=("Развернуть группы в выводе совпавшего/теневого правила.\n"
                         "С --output FILE.json — дополнительно сохраняет JSON-скан всех правил."))
    m.add_argument("--overlap", action="store_true",
                   help=("Нестрогий матчинг сетей: включает правила с подсетями запроса.\n"
                         "По умолчанию (строгий режим): правило совпадает только если\n"
                         "полностью покрывает запрошенную сеть (точное совпадение или суперсеть)."))
    m.add_argument("--interactive", "-i", action="store_true",
                   help="Интерактивный ввод трафика в цикле")
    m.add_argument("--batch",   metavar="FILE.csv", help="CSV с потоками трафика")
    m.add_argument("--output",  metavar="FILE.csv", help="Сохранить результаты в CSV")
    m.add_argument("--verbose", "-v", action="store_true")

    m.add_argument("--snapshot",      metavar="FILE.json", help="Снапшот (офлайн, вместо --host)")
    m.add_argument("--save-rules",   metavar="FILE.json", help="Сохранить правила в JSON")
    m.add_argument("--save-objects", metavar="FILE.json", help="Сохранить объекты в JSON")
    m.add_argument("--rules-file",   metavar="FILE.json", help="Правила из локального JSON")
    m.add_argument("--objects-file", metavar="FILE.json", help="Объекты из локального JSON")

    # ── find-rule ──────────────────────────────────────────────────────────────
    ffr = sub.add_parser("find-rule", help="Найти правило по имени, UUID или порту")
    fr.add_argument("name", metavar="PATTERN_OR_UUID", nargs="?", default=None,
                    help="Имя (подстрока, регистронезависимо) или UUID правила")
    fr.add_argument("--dport", metavar="PORT[-PORT]",
                    help="Фильтр по dst-порту (одиночный, диапазон или список через запятую)")
    fr.add_argument("--proto", metavar="PROTO", default="any",
                    help="Протокол для --dport: tcp | udp | icmp | any (по умолчанию any)")                
    fr.add_argument("--source", choices=["ngfw", "backend"], default="ngfw")
    fr.add_argument("--backend-host", metavar="URL")
    fr.add_argument("--device", metavar="DEVICE_GROUP_ID")
    fr.add_argument("--snapshot",     metavar="FILE.json", help="Снапшот (офлайн)")
    fr.add_argument("--rules-file",   metavar="FILE.json")
    fr.add_argument("--objects-file", metavar="FILE.json")
    fr.add_argument("--output", metavar="FILE.json", help="Экспорт найденных правил в JSON")

    # ── check-shadowed ─────────────────────────────────────────────────────────
    cs = sub.add_parser("check-shadowed", help="Найти теневые (перекрытые) правила")
    cs.add_argument("--source", choices=["ngfw", "backend"], default="ngfw")
    cs.add_argument("--backend-host", metavar="URL")
    cs.add_argument("--device", metavar="DEVICE_GROUP_ID")
    cs.add_argument("--snapshot",     metavar="FILE.json", help="Снапшот (офлайн)")
    cs.add_argument("--rules-file",   metavar="FILE.json")
    cs.add_argument("--objects-file", metavar="FILE.json")
    cs.add_argument("--output", metavar="FILE.json", help="Экспорт результатов в JSON")

    # ── snapshot ───────────────────────────────────────────────────────────────
    sn = sub.add_parser("snapshot",
                        help="Сохранить полное состояние политики (правила + группы) в JSON")
    sn.add_argument("--device", metavar="DEVICE_GROUP_ID",
                    help="deviceGroupId (если не указан — интерактивный выбор)")
    sn.add_argument("--out", metavar="FILE.json", default="snapshot.json",
                    help="Путь к выходному файлу (по умолчанию: snapshot.json)")

    # ── rule-hits ──────────────────────────────────────────────────────────────
    rh = sub.add_parser("rule-hits",
                        help="Счётчики срабатываний правил (hits) с цветной шкалой")
    rh.add_argument("--device", metavar="DEVICE_GROUP_ID",
                    help="deviceGroupId (если не указан — интерактивный выбор)")
    rh.add_argument("--rule", metavar="PATTERN",
                    help="Фильтр по имени правила (подстрока, регистронезависимо). "
                         "Если не указан — все правила устройства.")
    rh.add_argument("--batch-size", type=int, default=30, metavar="N",
                    help="Размер батча для ListMetricsRulesStats (по умолчанию: 30)")
    rh.add_argument("--sort-hits", action="store_true",
                    help="Сортировать по убыванию hits (по умолчанию — порядок как в СУ)")

    return p


# ─── test-connection ──────────────────────────────────────────────────────────

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

    # Шаги
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

    # Таблица групп устройств
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


def _row(label: str, value: str):
    print(f"  {c(label + ':', _C.DIM):<24} {value}")


# ─── find-rule ────────────────────────────────────────────────────────────────

def cmd_find_rule(args):
    import re


    pattern  = (args.name or "").strip()
    dport_str = getattr(args, "dport", None)

    if not pattern and not dport_str:
        warn("Укажите имя/UUID или --dport PORT")
        return

    if getattr(args, "snapshot", None):
        matcher = build_matcher_from_snapshot(args.snapshot)
    elif getattr(args, "rules_file", None):
        info("Оффлайн-режим: данные из локальных файлов")
        matcher = build_matcher(None, "", args.rules_file,
                                getattr(args, "objects_file", None))
    else:
        source = build_source(args)
        if getattr(args, "device", None):
            device_group_id   = args.device
            device_group_name = ""
        else:
            device_group_id, device_group_name = select_device(source)
        if device_group_name:
            ok(f"Device Group Name: {device_group_name}")
        ok(f"Device Group ID:   {device_group_id}")
        matcher = build_matcher(source, device_group_id)

   # ── фильтр по имени / UUID ─────────────────────────────────────────────────
    _UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
                          re.IGNORECASE)

    if pattern:
        if _UUID_RE.match(pattern):
            found = [r for r in matcher.rules if r.uid.lower() == pattern.lower()]
        else:
            pl = pattern.lower()
            found = [r for r in matcher.rules if pl in r.name.lower()]
    else:
        found = list(matcher.rules)

    # ── фильтр по порту/протоколу ──────────────────────────────────────────────
    if dport_str:
        proto = (getattr(args, "proto", None) or "any").lower()
        ports = _parse_ports(dport_str)
        filtered = []
        any_svc_count = 0
        for rule in found:
            services = matcher.resolver.resolve_field_service(rule.service)
            # Пропускаем правила с чистым service=ANY — они неявно покрывают любой порт,
            # но пользователь ищет правила с явно прописанным портом.
            if services == [("any", 0, 65535)]:
                any_svc_count += 1
                continue
            for port in ports:
                flow = TrafficFlow(
                    src_ip="0.0.0.0", dst_ip="0.0.0.0",
                    dst_port=port, protocol=proto,
                )
                if matcher._service_matches(flow, services):
                    filtered.append(rule)
                    break
        if any_svc_count:
            info(f"Пропущено {any_svc_count} правил с service=ANY (охватывают любой порт)")
        found = filtered

    found.sort(key=lambda r: r.index)

    if not found:
        parts = []
        if pattern:
            parts.append(f"имя/UUID: {pattern!r}")
        if dport_str:
            parts.append(f"dport: {dport_str}")
        warn("Правила не найдены по запросу: " + ", ".join(parts))
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
            "name":       r.name,
            "uid":        r.uid,
            "action":     r.action,
            "enabled":    r.enabled,
            "precedence": r.precedence,
            "position":   r.position_in_precedence or (r.index + 1),
            "global_position": r.index + 1,
        }
        for r in rules
    ]
    from .output import _json_meta
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"_ngfw_match": _json_meta(), "count": len(out), "rules": out},
                  f, ensure_ascii=False, indent=2)
    print(c(f"[+] Найденные правила → {path}  ({len(out)} записей)", _C.GREEN))


# ─── check-shadowed ───────────────────────────────────────────────────────────

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
            device_group_id   = args.device
            device_group_name = ""
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
#------------------L7 skiper--------------------------------------------------
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

    results = matcher.check_shadowed()
    print_shadowed_analysis(results)

    if getattr(args, "output", None):
        export_shadowed_json(results, args.output)

# ─── snapshot ────────────────────────────────────────────────────────────────

def cmd_snapshot(args):
    source = build_source(args)

    if getattr(args, "device", None):
        device_group_id   = args.device
        device_group_name = ""
    else:
        device_group_id, device_group_name = select_device(source)

    if device_group_name:
        ok(f"Device Group Name: {device_group_name}")
    ok(f"Device Group ID:   {device_group_id}")

    info("Загружаем правила и раскрываем все группы…")
    snap = source.build_snapshot(device_group_id, device_group_name)

    from .output import _json_meta
    snap["_ngfw_match"] = _json_meta()

    out_path = args.out
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(snap, f, ensure_ascii=False, indent=2)

    size_kb = len(json.dumps(snap, ensure_ascii=False)) / 1024
    ok(f"Снапшот сохранён → {out_path}  "
       f"({snap['rules_count']} правил  "
       f"{len(snap['net_groups'])} сет.групп  "
       f"{len(snap['svc_groups'])} серв.групп  "
       f"{size_kb:.0f} KB)")        


# ─── rule-hits ────────────────────────────────────────────────────────────────

def cmd_rule_hits(args):
    source = build_source(args)

    if getattr(args, "device", None):
        device_group_id   = args.device
        device_group_name = ""
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

    rule_ids  = [rid for rid, _, _ in rules_meta]
    hits_data = source.get_rule_hits(rule_ids, batch_size=batch_size)
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


# ─── main ─────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args   = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(levelname)-8s %(name)s: %(message)s",
    )

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Запрашиваем пароль интерактивно если нужен
    if not args.token and args.user and not args.password:
        args.password = getpass.getpass(f"Пароль для {args.user}: ")

    try:
        if args.command == "test-connection":
            cmd_test_connection(args)
        elif args.command == "match":
            run(args)
        elif args.command == "find-rule":
            cmd_find_rule(args)
        elif args.command == "check-shadowed":
            cmd_check_shadowed(args)
        elif args.command == "rule-hits":
            cmd_rule_hits(args)
        elif args.command == "snapshot":
            cmd_snapshot(args)    
        print_version_footer()    
    except KeyboardInterrupt:
        print("\nПрервано.", file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        die(str(e))


if __name__ == "__main__":
    main()