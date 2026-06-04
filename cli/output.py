"""
Форматирование вывода в терминал + экспорт CSV.
"""
# Developed by Ilya Semennikov
from __future__ import annotations
import csv
import ipaddress
import json
import sys
from typing import TextIO

from ..core.models import MatchResult, NormalizedRule


# ─── ANSI цвета ──────────────────────────────────────────────────────────────
def _no_color():
    """Проверяем, поддерживает ли терминал цвет."""
    import os
    return not sys.stdout.isatty() or os.environ.get("NO_COLOR")


class _C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"


def c(text, *codes) -> str:
    if _no_color():
        return str(text)
    return "".join(codes) + str(text) + _C.RESET


# ─── Вывод одного результата ─────────────────────────────────────────────────

def _get_app_names(rule) -> list[str]:
    """Извлекает имена приложений из RuleFieldApplication (kind=LIST)."""
    if rule.application is None:
        return []
    if rule.application.get("kind") != "RULE_KIND_LIST":
        return []
    return [
        obj.get("name") or obj.get("uniqueName", "?")
        for obj in (rule.application.get("objects") or [])
        if obj.get("name") or obj.get("uniqueName")
    ]


def _format_match_note(note: str) -> str:
    """Переводит внутренний код аннотации в человекочитаемый текст."""
    parts = []
    if "↑ dst" in note:
        parts.append("↑ dst: правило охватывает шире запроса (суперсеть)")
    if "↓ dst" in note:
        parts.append("↓ dst: правило охватывает подсеть запроса (частичное)")
    if "↑ src" in note:
        parts.append("↑ src: правило охватывает шире запроса по src (суперсеть)")
    if "↓ src" in note:
        parts.append("↓ src: правило охватывает подсеть запроса по src (частичное)")
    return ";  ".join(parts) if parts else note


def _get_zone_label(rule) -> str:
    """
    Возвращает строку вида '[zone: LAN→DMZ]' если в правиле явно заданы зоны.
    Пустая строка — если зоны ANY/UNSPECIFIED.
    """
    def _names(field) -> list[str]:
        if not field or field.get("kind") != "RULE_KIND_LIST":
            return []
        return [z.get("name", "") for z in (field.get("objects") or []) if z.get("name")]

    src_zones = _names(rule.source_zone)
    dst_zones = _names(rule.destination_zone)

    if not src_zones and not dst_zones:
        return ""

    src_str = ", ".join(src_zones) if src_zones else "any"
    dst_str = ", ".join(dst_zones) if dst_zones else "any"
    return f"[zone: {src_str}→{dst_str}]"


def print_result(result: MatchResult, verbose: bool = False, out: TextIO = sys.stdout):
    w = out.write

    w(c("━" * 72, _C.DIM) + "\n")
    w(f"  {c('Трафик:', _C.DIM)} {c(str(result.flow), _C.BOLD, _C.WHITE)}\n")
    w(c("━" * 72, _C.DIM) + "\n")

    if not result.hit:
        w(f"  {c('✗', _C.RED, _C.BOLD)}  Ни одно правило не совпало "
          f"→ {c('default-deny', _C.RED, _C.BOLD)}\n")
    else:
        r      = result.matched
        action = r.action.upper()
        aclr   = _C.GREEN if r.action == "allow" else _C.RED

        w(f"  {c('✓', _C.GREEN, _C.BOLD)}  {c(r.name, _C.CYAN, _C.BOLD)}\n")
        # Позиция внутри набора — как в СУ
        pos_in_prec = r.position_in_precedence or (r.index + 1)
        w(f"     Позиция   : #{pos_in_prec}  в наборе {c(r.precedence, _C.CYAN)}  "
          f"{c(f'(глобальная #{r.index + 1})', _C.DIM)}\n")
        w(f"     UUID      : {c(r.uid, _C.DIM)}\n")
        w(f"     Действие  : {c(action, aclr, _C.BOLD)}\n")
        w(f"     Включено  : {'да' if r.enabled else c('нет', _C.YELLOW)}\n")

        # Аннотация совпадения сети (суперсеть / подсеть)
        note = result.match_notes.get(r.uid, "")
        if note:
            note_parts = _format_match_note(note)
            w(f"     Охват сети : {c(note_parts, _C.YELLOW)}\n")

        # Приложения — показываем всегда, если заданы явно (L7-правило)
        app_names = _get_app_names(r)
        if app_names:
            apps_str = ", ".join(app_names[:8])
            if len(app_names) > 8:
                apps_str += c(f"  … (+{len(app_names) - 8})", _C.DIM)
            w(f"     Приложение: {c(apps_str, _C.YELLOW)}  "
              f"{c('[L7 — порт не ограничен]', _C.DIM)}\n")

        if verbose:
            _print_rule_fields(r, out)

    # ── Блок 1: чистые дубли по IP/порту — реальные кандидаты на удаление ──────
    if result.shadowed:
        w(f"\n  {c('⚠  Теневые правила (дубли по IP/порту/протоколу):', _C.YELLOW, _C.BOLD)} "
          f"{c(f'({len(result.shadowed)} шт.)', _C.YELLOW)}\n")
        for dup in result.shadowed:
            action_str = c(dup.action.upper(), _C.GREEN if dup.action == "allow" else _C.RED)
            dup_pos    = dup.position_in_precedence or (dup.index + 1)
            dup_note   = result.match_notes.get(dup.uid, "")
            note_str   = c(f"  [{dup_note}]", _C.DIM) if dup_note else ""
            w(f"     [#{dup_pos} в {dup.precedence}] {c(dup.name, _C.YELLOW)}"
              f"  →  {action_str}"
              f"{note_str}"
              f"  {c(f'(глобальная #{dup.index + 1})', _C.DIM)}\n")
        w(f"  {c('  → Кандидаты на удаление — перекрыты правилом выше.', _C.YELLOW)}\n")

    # ── Блок 2: L7-правила (service=ANY, application=LIST) — не проверялись ──
    if result.skipped_app:
        w(f"\n  {c('?  Правила с L7-условием (не проверялись по IP/порту):', _C.DIM, _C.BOLD)} "
          f"{c(f'({len(result.skipped_app)} шт.)', _C.DIM)}\n")
        for dup in result.skipped_app:
            action_str = c(dup.action.upper(), _C.GREEN if dup.action == "allow" else _C.RED)
            dup_pos    = dup.position_in_precedence or (dup.index + 1)
            dup_apps   = _get_app_names(dup)
            app_note   = c(f"  [L7: {', '.join(dup_apps[:4])}]", _C.DIM) if dup_apps else ""
            w(f"     [#{dup_pos} в {dup.precedence}] {c(dup.name, _C.DIM)}"
              f"  →  {action_str}"
              f"{app_note}"
              f"  {c(f'(глобальная #{dup.index + 1})', _C.DIM)}\n")
        w(f"  {c('  → Сервис ANY + приложение L7: инструмент работает на L3/L4, проверьте вручную.', _C.DIM)}\n")

    if result.skipped_disabled:
        w(f"  {c(f'(пропущено disabled: {result.skipped_disabled})', _C.DIM)}\n")

    w(c("━" * 72, _C.DIM) + "\n\n")


def _print_rule_fields(rule: NormalizedRule, out: TextIO):
    out.write(c("     ── Детали правила ──────────────────────────────\n", _C.DIM))
    skip = {"id", "uuid", "rule_id", "ruleId", "name", "rule_name",
            "action", "rule_action", "enabled", "isEnabled"}
    for k, v in rule.raw.items():
        if k in skip or v is None:
            continue
        val_str = json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else str(v)
        if len(val_str) > 90:
            val_str = val_str[:87] + "…"
        out.write(f"     {c(k, _C.DIM)}: {val_str}\n")


# ─── Сводка (batch) ──────────────────────────────────────────────────────────

def print_summary(results: list[MatchResult], out: TextIO = sys.stdout):
    total        = len(results)
    matched      = sum(1 for r in results if r.hit)
    allowed      = sum(1 for r in results if r.hit and r.matched.action == "allow")
    denied       = matched - allowed
    no_match     = total - matched
    dup_cnt      = sum(1 for r in results if r.shadowed)
    shadow_total = sum(len(r.shadowed) for r in results)
    l7_total     = sum(len(r.skipped_app) for r in results)

    out.write(c("\n" + "═" * 72 + "\n", _C.BOLD))
    out.write(c("  ИТОГОВАЯ СВОДКА\n", _C.BOLD))
    out.write(c("═" * 72 + "\n", _C.BOLD))
    out.write(f"  Всего потоков проверено    : {total}\n")
    out.write(f"  Совпало с правилами        : {c(matched, _C.GREEN)}\n")
    out.write(f"    ├─ разрешено (allow)     : {c(allowed, _C.GREEN)}\n")
    out.write(f"    └─ заблокировано (deny)  : {c(denied, _C.RED)}\n")
    out.write(f"  Нет совпадения (default)   : {c(no_match, _C.YELLOW)}\n")

    if shadow_total:
        out.write(c(f"\n  ⚠  Потоков с IP/порт-дублями     : {dup_cnt}\n", _C.YELLOW, _C.BOLD))
        out.write(c(f"  ⚠  IP/порт-дублей всего          : {shadow_total}\n", _C.YELLOW, _C.BOLD))
        out.write(c("     → Кандидаты на удаление!\n", _C.YELLOW))
    if l7_total:
        out.write(c(f"  ?  L7-правил (не проверялось)    : {l7_total}\n", _C.DIM))

    out.write(c("═" * 72 + "\n\n", _C.BOLD))


# ─── Fullview JSON ───────────────────────────────────────────────────────────

_PROTO_NAMES = {0: "any", 1: "icmp", 6: "tcp", 17: "udp", 47: "gre",
                50: "esp", 51: "ah", 58: "icmpv6", 89: "ospf", 132: "sctp"}


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


def _serialize_net_field(field: dict | None, fetch_group=None) -> dict:
    if field is None:
        return {"kind": "RULE_KIND_ANY"}
    kind = field.get("kind", "RULE_KIND_ANY")
    if kind in ("RULE_KIND_ANY", "RULE_KIND_UNSPECIFIED", ""):
        return {"kind": "RULE_KIND_ANY"}
    objects = [_serialize_net_obj(obj, fetch_group) for obj in (field.get("objects") or [])]
    return {"kind": kind, "objects": objects}


# ── Фильтрующий вариант для поля source ──────────────────────────────────────

def _net_obj_matches_src(obj: dict, src, fetch_group=None, _depth: int = 0) -> bool:
    """True если объект покрывает запрошенный src (IPv4Address или IPv4Network)."""
    if "networkIpAddress" in obj:
        inet = obj["networkIpAddress"].get("inet", "")
        if not inet:
            return False
        try:
            if "/" not in inet and ":" not in inet:
                inet = inet + "/32"
            net = ipaddress.ip_network(inet, strict=False)
            if isinstance(src, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                return src in net
            return src.subnet_of(net)  # IPv4Network: src ⊆ rule_net
        except (ValueError, TypeError):
            return False

    if "networkIpRange" in obj:
        r = obj["networkIpRange"]
        try:
            start = ipaddress.ip_address(r.get("from", ""))
            end   = ipaddress.ip_address(r.get("to",   ""))
            if isinstance(src, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                return start <= src <= end
            # Для CIDR: весь диапазон запроса должен быть внутри range
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
            return any(
                _net_obj_matches_src(m, src, fetch_group, _depth + 1)
                for m in fetch_group(gid)
            )
        except Exception:
            return False

    return False


def _serialize_net_obj_filtered(obj: dict, src, fetch_group=None,
                                 _depth: int = 0) -> dict | None:
    """
    Сериализует объект, если он покрывает src. Иначе None.
    Для группы показывает только matching members.
    """
    if "networkIpAddress" in obj:
        if not _net_obj_matches_src(obj, src):
            return None
        a = obj["networkIpAddress"]
        return {"type": "ipAddress", "id": a.get("id"), "inet": a.get("inet")}

    if "networkIpRange" in obj:
        if not _net_obj_matches_src(obj, src):
            return None
        r = obj["networkIpRange"]
        return {"type": "ipRange", "id": r.get("id"),
                "from": r.get("from"), "to": r.get("to")}

    if "networkFqdn" in obj or "networkGeoAddress" in obj:
        return None  # никогда не оставляем в filtered source

    if "networkGroup" in obj:
        g   = obj["networkGroup"]
        gid = g.get("id")
        if not fetch_group or not gid or _depth >= 4:
            return None
        try:
            filtered = [
                _serialize_net_obj_filtered(m, src, fetch_group, _depth + 1)
                for m in fetch_group(gid)
            ]
            matching = [m for m in filtered if m is not None]
        except Exception:
            return None
        if not matching:
            return None
        return {"type": "group", "id": gid, "name": g.get("name"), "members": matching}

    return None


def _serialize_src_field(field: dict | None, src_str: str, fetch_group=None) -> dict:
    """
    Поле source с фильтром: оставляем только объекты/члены групп,
    которые содержат запрошенный src. FQDN/geo всегда убираем.
    """
    if field is None:
        return {"kind": "RULE_KIND_ANY"}
    kind = field.get("kind", "RULE_KIND_ANY")
    if kind in ("RULE_KIND_ANY", "RULE_KIND_UNSPECIFIED", ""):
        return {"kind": "RULE_KIND_ANY"}

    try:
        src = (ipaddress.ip_network(src_str, strict=False)
               if "/" in src_str
               else ipaddress.ip_address(src_str))
    except ValueError:
        # Не смогли распарсить — возвращаем без фильтра
        return _serialize_net_field(field, fetch_group)

    objects = [
        _serialize_net_obj_filtered(obj, src, fetch_group)
        for obj in (field.get("objects") or [])
    ]
    return {"kind": kind, "objects": [o for o in objects if o is not None]}


def _port_str(sp: dict) -> str:
    if "singlePort" in sp:
        return str(sp["singlePort"].get("port", "?"))
    if "portRange" in sp:
        return f"{sp['portRange'].get('from','?')}-{sp['portRange'].get('to','?')}"
    return "?"


def _serialize_svc_obj(item: dict, fetch_group=None, _depth: int = 0) -> dict:
    if "service" in item:
        svc = item["service"]
        proto = _PROTO_NAMES.get(svc.get("protocol", 0), str(svc.get("protocol", 0)))
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


def _serialize_svc_field(field: dict | None, fetch_group=None) -> dict:
    if field is None:
        return {"kind": "RULE_KIND_ANY"}
    kind = field.get("kind", "RULE_KIND_ANY")
    if kind in ("RULE_KIND_ANY", "RULE_KIND_UNSPECIFIED", ""):
        return {"kind": "RULE_KIND_ANY"}
    objects = [_serialize_svc_obj(item, fetch_group) for item in (field.get("objects") or [])]
    return {"kind": kind, "objects": objects}


def _serialize_app_field(field: dict | None) -> dict | None:
    if field is None:
        return None
    if field.get("kind") != "RULE_KIND_LIST":
        return None
    objects = [
        {"id": obj.get("id"), "name": obj.get("name") or obj.get("uniqueName")}
        for obj in (field.get("objects") or [])
    ]
    return {"kind": "RULE_KIND_LIST", "objects": objects} if objects else None


def export_fullview_json(flow_results: list[dict], query: dict, path: str,
                         fetch_net_group=None, fetch_svc_group=None):
    """
    Сохраняет fullview-результаты в JSON.
    flow_results — список: {"flow": TrafficFlow, "rules": list[NormalizedRule]}
    fetch_net_group/fetch_svc_group — callback'и для раскрытия групп.
    """
    flows_out = []
    for entry in flow_results:
        flow  = entry["flow"]
        rules = entry["rules"]
        rules_out = []
        for rule in rules:
            r_dict: dict = {
                "name":            rule.name,
                "uid":             rule.uid,
                "action":          rule.action,
                "enabled":         rule.enabled,
                "precedence":      rule.precedence,
                "position_in_set": rule.position_in_precedence or (rule.index + 1),
                "global_position": rule.index + 1,
                "source":          _serialize_src_field(rule.source_addr, flow.src_ip, fetch_net_group),
                "destination":     _serialize_net_field(rule.destination_addr, fetch_net_group),
                "service":         _serialize_svc_field(rule.service, fetch_svc_group),
            }
            app = _serialize_app_field(rule.application)
            if app:
                r_dict["application"] = app
            rules_out.append(r_dict)

        flows_out.append({
            "src":           flow.src_ip,
            "dst":           flow.dst_ip,
            "dport":         flow.dst_port if flow.dst_port else "any",
            "proto":         flow.protocol,
            "matched_count": len(rules_out),
            "rules":         rules_out,
        })

    # Один поток — плоская структура; несколько — массив flows
    if len(flows_out) == 1:
        output = {
            "query":         query,
            "matched_count": flows_out[0]["matched_count"],
            "rules":         flows_out[0]["rules"],
        }
    else:
        output = {"query": query, "flows": flows_out}

    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    total = sum(f["matched_count"] for f in flows_out)
    print(c(f"[+] Fullview → {path}  ({total} правил)", _C.GREEN))


# ─── Экспорт CSV ─────────────────────────────────────────────────────────────

def export_csv(results: list[MatchResult], path: str):
    fields = [
        "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
        "zone_src", "zone_dst",
        "matched_rule_name", "matched_rule_uid", "action",
        "rule_position", "precedence",
        "shadow_count", "shadow_rules",
        "l7_skipped_count", "l7_skipped_rules",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in results:
            mr = r.matched
            w.writerow({
                "src_ip":              r.flow.src_ip,
                "src_port":            r.flow.src_port,
                "dst_ip":              r.flow.dst_ip,
                "dst_port":            r.flow.dst_port,
                "protocol":            r.flow.protocol,
                "zone_src":            r.flow.zone_src,
                "zone_dst":            r.flow.zone_dst,
                "matched_rule_name":   mr.name      if mr else "NO_MATCH",
                "matched_rule_uid":    mr.uid       if mr else "",
                "action":              mr.action    if mr else "default-deny",
                "rule_position":       mr.index + 1 if mr else "",
                "precedence":          mr.precedence if mr else "",
                "shadow_count":        len(r.shadowed),
                "shadow_rules":        "; ".join(f"[{s.index+1}] {s.name}" for s in r.shadowed),
                "l7_skipped_count":    len(r.skipped_app),
                "l7_skipped_rules":    "; ".join(f"[{s.index+1}] {s.name}" for s in r.skipped_app),
            })
    print(c(f"[+] Результаты сохранены → {path}", _C.GREEN))