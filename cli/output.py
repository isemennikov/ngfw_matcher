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

def _get_fqdn_names(rule) -> list[str]:
    """Извлекает FQDN-значения из source_addr и destination_addr правила."""
    result = []
    for field in (rule.source_addr, rule.destination_addr):
        if not field or field.get("kind") != "RULE_KIND_LIST":
            continue
        for obj in (field.get("objects") or []):
            if "networkFqdn" in obj:
                fqdn = obj["networkFqdn"].get("fqdn", "")
                if fqdn and fqdn not in result:
                    result.append(fqdn)
    return result


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


def print_result(result: MatchResult, verbose: bool = False, out: TextIO = sys.stdout,
                 fullview: bool = False, fetch_net_group=None, fetch_svc_group=None):
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

        if fullview:
            _print_field_expansion(r, fetch_net_group, fetch_svc_group, out)

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
            if fullview:
                src_lines = _format_field_lines(dup.source_addr, fetch_net_group, max_items=5)
                dst_lines = _format_field_lines(dup.destination_addr, fetch_net_group, max_items=5)
                src_first = src_lines[0] if src_lines else "ANY"
                dst_first = dst_lines[0] if dst_lines else "ANY"
                w(f"       {c('src:', _C.DIM)} {src_first}  {c('dst:', _C.DIM)} {dst_first}\n")
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

    # ── Блок 3: FQDN-правила (совпадение только из-за FQDN→ANY) ─────────────────
    if result.skipped_fqdn:
        w(f"\n  {c('?  Правила с FQDN-условием (не проверялись по IP):', _C.DIM, _C.BOLD)} "
          f"{c(f'({len(result.skipped_fqdn)} шт.)', _C.DIM)}\n")
        for dup in result.skipped_fqdn:
            action_str = c(dup.action.upper(), _C.GREEN if dup.action == "allow" else _C.RED)
            dup_pos    = dup.position_in_precedence or (dup.index + 1)
            fqdn_names = _get_fqdn_names(dup)
            fqdn_note  = c(f"  [FQDN: {', '.join(fqdn_names[:3])}]", _C.DIM) if fqdn_names else ""
            w(f"     [#{dup_pos} в {dup.precedence}] {c(dup.name, _C.DIM)}"
              f"  →  {action_str}"
              f"{fqdn_note}"
              f"  {c(f'(глобальная #{dup.index + 1})', _C.DIM)}\n")
        w(f"  {c('  → src/dst содержит FQDN: инструмент работает на L3, проверьте вручную.', _C.DIM)}\n")

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


def _print_field_expansion(rule: NormalizedRule, fetch_net_group, fetch_svc_group,
                            out: TextIO):
    """Выводит раскрытые поля Source/Destination для --fullview."""
    for label, field in (("Source", rule.source_addr), ("Destination", rule.destination_addr)):
        out.write(f"     {c(label + ':', _C.DIM)}\n")
        if field is None or field.get("kind") in ("RULE_KIND_ANY", "RULE_KIND_UNSPECIFIED", ""):
            out.write(f"       ANY\n")
        else:
            for obj in (field.get("objects") or []):
                for ln in _format_net_obj_lines(obj, fetch_net_group, max_items=5, indent="  "):
                    out.write(f"     {ln}\n")


# ─── Раскрытие групп (fullview / find-rule) ──────────────────────────────────

def _format_field_lines(field: dict | None, fetch_group=None, max_items: int = 5) -> list[str]:
    """
    Возвращает список строк для отображения RuleFieldNetwork.
    Группы раскрываются (усекаются до max_items).
    """
    if field is None or field.get("kind") in ("RULE_KIND_ANY", "RULE_KIND_UNSPECIFIED", ""):
        return ["ANY"]

    lines: list[str] = []
    for obj in (field.get("objects") or []):
        lines.extend(_format_net_obj_lines(obj, fetch_group, max_items, indent=""))
    return lines if lines else ["ANY"]


def _format_net_obj_lines(obj: dict, fetch_group, max_items: int, indent: str) -> list[str]:
    if "networkIpAddress" in obj:
        inet = obj["networkIpAddress"].get("inet", "?")
        return [f"{indent}{inet}"]

    if "networkIpRange" in obj:
        r = obj["networkIpRange"]
        return [f"{indent}{r.get('from','?')} – {r.get('to','?')}"]

    if "networkFqdn" in obj:
        return [f"{indent}FQDN: {obj['networkFqdn'].get('fqdn','?')}"]

    if "networkGeoAddress" in obj:
        return [f"{indent}GeoIP: {obj['networkGeoAddress'].get('geoId','?')}"]

    if "networkGroup" in obj:
        g    = obj["networkGroup"]
        name = g.get("name") or g.get("id", "?")
        gid  = g.get("id")
        members: list = []
        if fetch_group and gid:
            try:
                members = fetch_group(gid)
            except Exception:
                pass
        total = len(members)
        shown = members[:max_items]
        count_note = (f"  ({total} объектов, показано первые {max_items})"
                      if total > max_items else f"  ({total} объектов)")
        lines = [f"{indent}Группа {c(name, _C.CYAN)}{c(count_note, _C.DIM)}"]
        for idx, m in enumerate(shown):
            is_last = (idx == len(shown) - 1) and (total <= max_items)
            tree    = "  └─ " if is_last else "  ├─ "
            sub = _format_net_obj_lines(m, fetch_group, max_items, "")
            if sub:
                lines.append(f"{indent}{tree}{sub[0]}")
                for extra in sub[1:]:
                    lines.append(f"{indent}  │  {extra}")
        if total > max_items:
            lines.append(f"{indent}  └─ … +{total - max_items} ещё")
        return lines

    return []


def _format_svc_field_lines(field: dict | None, fetch_group=None, max_items: int = 5) -> list[str]:
    """Возвращает строки для RuleFieldService."""
    if field is None or field.get("kind") in ("RULE_KIND_ANY", "RULE_KIND_UNSPECIFIED", ""):
        return ["ANY"]
    lines: list[str] = []
    for item in (field.get("objects") or []):
        lines.extend(_format_svc_item_lines(item, fetch_group, max_items))
    return lines if lines else ["ANY"]


def _format_svc_item_lines(item: dict, fetch_group, max_items: int) -> list[str]:
    _PROTO = {0: "any", 1: "icmp", 6: "tcp", 17: "udp", 47: "gre",
              50: "esp", 51: "ah", 58: "icmpv6", 89: "ospf", 132: "sctp"}

    if "service" in item:
        svc   = item["service"]
        proto = _PROTO.get(svc.get("protocol", 0), str(svc.get("protocol", 0)))
        ports = [_port_str(sp) for sp in (svc.get("dstPorts") or [])]
        if ports:
            return [f"{proto}/{','.join(ports)}"]
        return [proto]

    if "serviceGroup" in item:
        g    = item["serviceGroup"]
        name = g.get("name") or g.get("id", "?")
        gid  = g.get("id")
        lines = [f"[группа] {name}"]
        members: list = []
        if fetch_group and gid:
            try:
                members = fetch_group(gid)
            except Exception:
                pass
        total = len(members)
        shown = members[:max_items]
        for idx, m in enumerate(shown):
            is_last = (idx == len(shown) - 1) and (total <= max_items)
            tree    = "  └─ " if is_last else "  ├─ "
            sub = _format_svc_item_lines(m, fetch_group, max_items)
            if sub:
                lines.append(f"{tree}{sub[0]}")
        if total > max_items:
            lines.append(f"  └─ … +{total - max_items} ещё")
        return lines

    return []


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
    fqdn_total = sum(len(r.skipped_fqdn) for r in results)
    if fqdn_total:
        out.write(c(f"  ?  FQDN-правил (не проверялось)  : {fqdn_total}\n", _C.DIM))

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

# ─── find-rule карточка ──────────────────────────────────────────────────────

_CARD_LABEL_W = 15   # ширина колонки метки
_CARD_VAL_W   = 54   # ширина колонки значения


def _card_line(label: str, value: str) -> str:
    lbl = label.ljust(_CARD_LABEL_W)
    val = value[:_CARD_VAL_W] if len(value) > _CARD_VAL_W else value
    return f"│ {lbl} │ {val.ljust(_CARD_VAL_W)} │"


def _card_cont(value: str) -> str:
    val = value[:_CARD_VAL_W] if len(value) > _CARD_VAL_W else value
    return f"│ {' ' * _CARD_LABEL_W} │ {val.ljust(_CARD_VAL_W)} │"


def _card_sep() -> str:
    return f"├{'─' * (_CARD_LABEL_W + 2)}┼{'─' * (_CARD_VAL_W + 2)}┤"


def _card_top() -> str:
    return f"┌{'─' * (_CARD_LABEL_W + 2)}┬{'─' * (_CARD_VAL_W + 2)}┐"


def _card_bot() -> str:
    return f"└{'─' * (_CARD_LABEL_W + 2)}┴{'─' * (_CARD_VAL_W + 2)}┘"


def print_rule_card(rule, fetch_net_group=None, fetch_svc_group=None,
                    out: TextIO = sys.stdout):
    """Выводит карточку правила в box-drawing формате."""
    w = out.write

    def section(label: str, lines: list[str]):
        w(_card_sep() + "\n")
        for i, ln in enumerate(lines):
            if i == 0:
                w(_card_line(label, ln) + "\n")
            else:
                w(_card_cont(ln) + "\n")

    action_label = c(rule.action.upper(),
                     _C.GREEN if rule.action == "allow" else _C.RED)
    status_label = "включено" if rule.enabled else c("отключено", _C.YELLOW)
    pos_in_prec  = rule.position_in_precedence or (rule.index + 1)
    pos_str      = f"{rule.precedence.upper()}  #{pos_in_prec}  (глобальная #{rule.index + 1})"

    w(_card_top() + "\n")
    w(_card_line("Имя",           rule.name[:_CARD_VAL_W]) + "\n")
    w(_card_line("UUID",          rule.uid[:_CARD_VAL_W]) + "\n")
    w(_card_line("Действие",      action_label) + "\n")
    w(_card_line("Статус",        status_label) + "\n")
    w(_card_line("Набор/Позиция", pos_str[:_CARD_VAL_W]) + "\n")

    # Source
    src_lines = _format_field_lines(rule.source_addr, fetch_net_group, max_items=10)
    section("Source", src_lines)

    # Destination
    dst_lines = _format_field_lines(rule.destination_addr, fetch_net_group, max_items=10)
    section("Destination", dst_lines)

    # Service
    svc_lines = _format_svc_field_lines(rule.service, fetch_svc_group, max_items=10)
    section("Service", svc_lines)

    # Application
    app_names = _get_app_names(rule)
    if app_names:
        app_lines = [f"{n}  [{rule.application.get('objects', [{}])[i].get('id','')[:20]}]"
                     if i < len((rule.application or {}).get("objects", []))
                     else n
                     for i, n in enumerate(app_names[:10])]
        if len(app_names) > 10:
            app_lines.append(f"… +{len(app_names) - 10} ещё")
        section("Application", app_lines)
    else:
        w(_card_sep() + "\n")
        w(_card_line("Application", "ANY") + "\n")

    w(_card_bot() + "\n\n")


# ─── check-shadowed вывод ────────────────────────────────────────────────────

def print_shadowed_analysis(results: list[dict], out: TextIO = sys.stdout):
    total     = len(results)
    conflicts = sum(1 for r in results if r["conflict"])

    out.write(c("\n" + "═" * 71 + "\n", _C.BOLD))
    out.write(c("  АНАЛИЗ ТЕНЕВЫХ ПРАВИЛ\n", _C.BOLD))
    out.write(c("═" * 71 + "\n", _C.BOLD))
    out.write(f"  Найдено теневых правил    : {total}\n")
    out.write(f"  Конфликтов действий       : {c(conflicts, _C.RED if conflicts else _C.GREEN)}"
              f"  {c('← ALLOW перекрыт DENY или наоборот', _C.DIM) if conflicts else ''}\n")
    out.write(c("═" * 71 + "\n\n", _C.BOLD))

    for entry in results:
        sh  = entry["shadowed"]
        by  = entry["by"]
        con = entry["conflict"]

        sh_pos  = sh.position_in_precedence or (sh.index + 1)
        by_pos  = by.position_in_precedence or (by.index + 1)
        sh_act  = c(sh.action.upper(), _C.GREEN if sh.action == "allow" else _C.RED)
        by_act  = c(by.action.upper(), _C.GREEN if by.action == "allow" else _C.RED)

        if con:
            out.write(f"  {c('⚠  КОНФЛИКТ', _C.RED, _C.BOLD)}  "
                      f"#{sh_pos} [{sh.precedence}] {c(sh.name, _C.YELLOW)}  →  {sh_act}\n")
            out.write(f"               {c('← перекрывается', _C.DIM)}  "
                      f"#{by_pos} [{by.precedence}] {c(by.name, _C.CYAN)}  →  {by_act}\n\n")
        else:
            out.write(f"     #{sh_pos} [{sh.precedence}] {c(sh.name, _C.DIM)}  →  {sh_act}\n")
            out.write(f"      {c('← перекрывается', _C.DIM)}  "
                      f"#{by_pos} [{by.precedence}] {c(by.name, _C.CYAN)}  →  {by_act}\n\n")


def export_shadowed_json(results: list[dict], path: str):
    total     = len(results)
    conflicts = sum(1 for r in results if r["conflict"])

    rules_out = []
    for entry in results:
        sh = entry["shadowed"]
        by = entry["by"]
        rules_out.append({
            "shadowed_name":       sh.name,
            "shadowed_uid":        sh.uid,
            "shadowed_action":     sh.action,
            "shadowed_position":   sh.position_in_precedence or (sh.index + 1),
            "shadowed_precedence": sh.precedence,
            "shadowing_name":      by.name,
            "shadowing_uid":       by.uid,
            "shadowing_action":    by.action,
            "shadowing_position":  by.position_in_precedence or (by.index + 1),
            "shadowing_precedence": by.precedence,
            "conflict":            entry["conflict"],
        })

    output = {"total": total, "conflicts": conflicts, "rules": rules_out}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    print(c(f"[+] Теневые правила → {path}  ({total} записей)", _C.GREEN))


# ─── Экспорт CSV ─────────────────────────────────────────────────────────────

def export_csv(results: list[MatchResult], path: str):
    fields = [
        "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
        "zone_src", "zone_dst",
        "matched_rule_name", "matched_rule_uid", "action",
        "rule_position", "precedence",
        "shadow_count", "shadow_rules",
        "l7_skipped_count", "l7_skipped_rules",
        "fqdn_skipped_count", "fqdn_skipped_rules",
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
                "fqdn_skipped_count":  len(r.skipped_fqdn),
                "fqdn_skipped_rules":  "; ".join(f"[{s.index+1}] {s.name}" for s in r.skipped_fqdn),
            })
    print(c(f"[+] Результаты сохранены → {path}", _C.GREEN))


# ─── rule-hits: статистика срабатываний ──────────────────────────────────────

def _fmt_hits(n: int) -> str:
    """1234567 → '1.2M'  |  12345 → '12.3K'  |  999 → '999'"""
    if n >= 1_000_000_000:
        v = n / 1_000_000_000
        return f"{v:.0f}B" if v >= 100 else f"{v:.1f}B"
    if n >= 1_000_000:
        v = n / 1_000_000
        return f"{v:.0f}M" if v >= 100 else f"{v:.1f}M"
    if n >= 1_000:
        v = n / 1_000
        return f"{v:.0f}K" if v >= 100 else f"{v:.1f}K"
    return str(n)


def _hits_color(hits: int, p33: int, p66: int) -> str:
    """Цвет бара по перцентилям: зелёный < жёлтый < красный."""
    if hits == 0:
        return _C.DIM
    if hits <= p33:
        return _C.GREEN
    if hits <= p66:
        return _C.YELLOW
    return _C.RED


def _hits_bar(hits: int, max_hits: int, p33: int, p66: int, width: int = 22) -> str:
    """Цветная шкала пропорционально max_hits."""
    filled = int(round(hits / max_hits * width)) if max_hits > 0 else 0
    filled = max(0, min(width, filled))
    bar    = "█" * filled + "░" * (width - filled)
    return c(bar, _hits_color(hits, p33, p66))


def print_hits_table(rows: list[dict]) -> None:
    """
    Таблица hits-счётчиков с цветной шкалой.

    rows: [{"name": str, "hits": int, "enabled": bool}]
    Сортировка: по убыванию hits (передаётся уже отсортированной).
    """
    if not rows:
        print(c("  (нет данных)", _C.DIM))
        return

    hits_values  = [r["hits"] for r in rows]
    max_hits     = max(hits_values) if hits_values else 0
    sorted_hits  = sorted(hits_values)
    n            = len(sorted_hits)

    # 33/66-й перцентиль
    p33 = sorted_hits[max(0, n // 3 - 1)]      if n >= 3 else sorted_hits[-1]
    p66 = sorted_hits[max(0, 2 * n // 3 - 1)]  if n >= 3 else sorted_hits[-1]

    name_w = min(max((len(r["name"]) for r in rows), default=20), 52)
    hits_w = 9

    hdr_name = f"{'Правило':<{name_w}}"
    hdr_hits = f"{'Hits':>{hits_w}}"
    print()
    print(c(f"  {hdr_name}  {hdr_hits}  {'':22}", _C.BOLD))
    print("  " + "─" * (name_w + hits_w + 26))

    for row in rows:
        name    = row["name"][:name_w]
        hits    = row["hits"]
        enabled = row.get("enabled", True)

        color       = _hits_color(hits, p33, p66)
        name_col    = f"{name:<{name_w}}" if enabled else c(f"{name:<{name_w}}", _C.DIM)
        hits_col    = c(f"{_fmt_hits(hits):>{hits_w}}", color)
        bar_col     = _hits_bar(hits, max_hits, p33, p66)

        print(f"  {name_col}  {hits_col}  {bar_col}")

    print()
    total = sum(r["hits"] for r in rows)
    legend = (
        c("█ низкие", _C.GREEN) + "  " +
        c("█ средние", _C.YELLOW) + "  " +
        c("█ высокие", _C.RED)
    )
    print(f"  {legend}")
    print(c(f"  Правил: {len(rows)}   Суммарно hits: {_fmt_hits(total)}", _C.DIM))
    print()