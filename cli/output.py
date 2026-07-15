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

from .._version import __version__
from ..core.models import MatchResult, NormalizedRule, NatRule
from ..core.nat_audit import NatAssociation
from ..core.resolver import PROTO, is_any_kind
from ..core.utils import port_str as _port_str
from ..core.export import (
    json_meta as _json_meta,
    serialize_net_field   as _serialize_net_field,
    serialize_src_field   as _serialize_src_field,
    serialize_svc_field   as _serialize_svc_field,
    serialize_app_field   as _serialize_app_field,
    build_fullview_dict,
    build_shadows_dict,
    build_find_dict,
)


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


# ─── CLI log helpers ─────────────────────────────────────────────────────────

def info(msg: str):  print(c(f"[*] {msg}", _C.BLUE),   file=sys.stderr)
def ok(msg: str):    print(c(f"[+] {msg}", _C.GREEN),  file=sys.stderr)
def warn(msg: str):  print(c(f"[!] {msg}", _C.YELLOW), file=sys.stderr)
def err(msg: str):   print(c(f"[✗] {msg}", _C.RED),    file=sys.stderr)


def die(msg: str, code: int = 1):
    err(msg)
    sys.exit(code)


def _row(label: str, value: str):
    print(f"  {c(label + ':', _C.DIM):<24} {value}")


def _print_rules_list(rules: list[NormalizedRule]):
    print(f"\n  {'#':>5}  {'Статус':8}  {'Действие':8}  {'Набор':8}  Имя")
    print("  " + "─" * 70)
    for r in rules:
        st  = c("ON ", _C.GREEN)  if r.enabled else c("OFF", _C.YELLOW)
        act = c("ALLOW", _C.GREEN) if r.action == "allow" else c("DENY ", _C.RED)
        print(f"  {r.index+1:>5}  {st}       {act}    {r.precedence:8}  {r.name[:42]}")
    print()


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


# ─── Thread-нить: Unicode box-drawing символы ────────────────────────────────

_TH_ROOT   = "  "      # отступ корня (● добавляет _rule_dot)
_TH_VERT   = "  │  "  # вертикальная нить
_TH_BRANCH = "  ├─"   # промежуточная ветка (● добавляет _rule_dot)
_TH_LAST   = "  └─"   # последняя ветка
_TH_CONT   = "  │  "  # отступ под промежуточной веткой
_TH_END    = "     "  # отступ под последней веткой


def _rule_dot(rule: NormalizedRule) -> str:
    """Цветная точка ● в цвет действия правила."""
    clr = _C.GREEN if rule.action == "allow" else _C.RED
    if not rule.enabled:
        clr = _C.DIM
    return c("●", clr, _C.BOLD)


def _rule_label(rule: NormalizedRule) -> str:
    """Имя + позиция + действие в одну строку."""
    pos    = rule.position_in_precedence or (rule.index + 1)
    aclr   = _C.GREEN if rule.action == "allow" else _C.RED
    action = c(rule.action.upper(), aclr, _C.BOLD)
    prec   = c(rule.precedence, _C.CYAN)
    gidx   = c(f"(#{rule.index + 1})", _C.DIM)
    en     = "" if rule.enabled else c("  [off]", _C.DIM)
    return f"{c(rule.name, _C.CYAN, _C.BOLD)}  #{pos} {prec}  {action}  {gidx}{en}"


def _shadow_label(rule: NormalizedRule, note: str = "") -> str:
    """Метка теневого правила (без жирного)."""
    pos    = rule.position_in_precedence or (rule.index + 1)
    aclr   = _C.GREEN if rule.action == "allow" else _C.RED
    action = c(rule.action.upper(), aclr)
    prec   = c(rule.precedence, _C.DIM)
    gidx   = c(f"(#{rule.index + 1})", _C.DIM)
    note_s = c(f"  [{note}]", _C.DIM) if note else ""
    en     = "" if rule.enabled else c("  [off]", _C.DIM)
    return f"{c(rule.name, _C.YELLOW)}  #{pos} {prec}  {action}  {gidx}{en}{note_s}"


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
        r = result.matched

        # ── Корень нити: сработавшее правило ─────────────────────────────────
        w(f"{_TH_ROOT}{_rule_dot(r)}  {_rule_label(r)}\n")

        # Дополнительные поля под корнем
        note = result.match_notes.get(r.uid, "")
        if note:
            w(f"{_TH_VERT}     {c('охват: ' + _format_match_note(note), _C.YELLOW)}\n")
        w(f"{_TH_VERT}     {c('UUID: ' + r.uid, _C.DIM)}\n")

        app_names = _get_app_names(r)
        if app_names:
            apps_str = ", ".join(app_names[:8])
            if len(app_names) > 8:
                apps_str += c(f"  … (+{len(app_names) - 8})", _C.DIM)
            w(f"{_TH_VERT}     {c('L7: ' + apps_str, _C.YELLOW)}"
              f"  {c('[порт не ограничен]', _C.DIM)}\n")

        if fullview:
            _print_field_expansion(r, fetch_net_group, fetch_svc_group, out)
        if verbose:
            _print_rule_fields(r, out)

        # ── Ветки нити: теневые правила ──────────────────────────────────────
        if result.shadowed:
            w(f"{_TH_VERT}\n")
            shadows = result.shadowed
            for i, dup in enumerate(shadows):
                is_last = (i == len(shadows) - 1)
                prefix  = _TH_LAST if is_last else _TH_BRANCH
                indent  = _TH_END  if is_last else _TH_CONT
                dup_note = result.match_notes.get(dup.uid, "")
                w(f"{prefix}{_rule_dot(dup)}  {_shadow_label(dup, dup_note)}\n")
                if fullview:
                    src_lines = _format_field_lines(dup.source_addr, fetch_net_group, max_items=3)
                    dst_lines = _format_field_lines(dup.destination_addr, fetch_net_group, max_items=3)
                    src_first = src_lines[0] if src_lines else "ANY"
                    dst_first = dst_lines[0] if dst_lines else "ANY"
                    w(f"{indent}  {c('src:', _C.DIM)} {src_first}"
                      f"  {c('dst:', _C.DIM)} {dst_first}\n")
            w(f"{c('  → Кандидаты на удаление — перекрыты правилом выше.', _C.YELLOW)}\n")

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
        if is_any_kind(field):
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
    if is_any_kind(field):
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
    if is_any_kind(field):
        return ["ANY"]
    lines: list[str] = []
    for item in (field.get("objects") or []):
        lines.extend(_format_svc_item_lines(item, fetch_group, max_items))
    return lines if lines else ["ANY"]


def _format_svc_item_lines(item: dict, fetch_group, max_items: int) -> list[str]:
    if "service" in item:
        svc   = item["service"]
        proto = PROTO.get(svc.get("protocol", 0), str(svc.get("protocol", 0)))
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


# ─── Fullview / find-rule / shadows JSON — делегируем в core.export ─────────

def export_fullview_json(flow_results: list[dict], query: dict, path: str,
                         fetch_net_group=None, fetch_svc_group=None):
    output = build_fullview_dict(flow_results, query, fetch_net_group, fetch_svc_group)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    total = sum(len(e.get("rules", [])) for e in flow_results)
    print(c(f"[+] Fullview → {path}  ({total} правил)", _C.GREEN))


def export_shadowed_json(results: list[dict], path: str,
                         fetch_net_group=None, fetch_svc_group=None):
    output = build_shadows_dict(results, {}, fetch_net_group, fetch_svc_group)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    print(c(f"[+] Теневые правила → {path}  ({output['total']} записей)", _C.GREEN))


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

    # Группируем по "by"-правилу, сохраняем порядок первого появления
    seen_by: dict[str, list[dict]] = {}
    for entry in results:
        key = entry["by"].uid
        seen_by.setdefault(key, []).append(entry)

    for by_uid, entries in seen_by.items():
        by  = entries[0]["by"]
        has_conflict = any(e["conflict"] for e in entries)

        # Корень нити — перекрывающее правило
        conflict_mark = c("  ⚠ КОНФЛИКТ", _C.RED, _C.BOLD) if has_conflict else ""
        out.write(f"{_TH_ROOT}{_rule_dot(by)}  {_rule_label(by)}{conflict_mark}\n")
        out.write(f"{_TH_VERT}\n")

        # Ветки — перекрытые правила
        for i, entry in enumerate(entries):
            sh      = entry["shadowed"]
            con     = entry["conflict"]
            is_last = (i == len(entries) - 1)
            prefix  = _TH_LAST if is_last else _TH_BRANCH
            conflict_s = c("  ⚠", _C.RED) if con else ""
            out.write(f"{prefix}{_rule_dot(sh)}  {_shadow_label(sh)}{conflict_s}\n")

        out.write("\n")


# ─── partial-shadow вывод ─────────────────────────────────────────────────────

_ANY_NETS = {"0.0.0.0/0", "::/0"}


def _fmt_nets(nets: list, limit: int = 4) -> str:
    """Дедуплицирует сети, заменяет 0.0.0.0/0 на ANY, форматирует список."""
    seen: list[str] = []
    seen_set: set[str] = set()
    for n in nets:
        s = str(n)
        if s in _ANY_NETS:
            s = "ANY"
        if s not in seen_set:
            seen_set.add(s)
            seen.append(s)
        if "ANY" in seen_set:
            return "ANY"  # достаточно одного ANY
    if not seen:
        return "—"
    extra = len(seen) - limit
    result = ", ".join(seen[:limit])
    if extra > 0:
        result += f" +{extra}"
    return result


def _fmt_svcs(svcs: list, limit: int = 6) -> str:
    """Дедуплицирует сервисы и форматирует список."""
    seen: list[str] = []
    seen_set: set[str] = set()
    for s in svcs:
        label = _fmt_svc_overlap(*s)
        if label not in seen_set:
            seen_set.add(label)
            seen.append(label)
        if label == "ANY":
            return "ANY"
    if not seen:
        return "—"
    extra = len(seen) - limit
    result = ", ".join(seen[:limit])
    if extra > 0:
        result += f" +{extra}"
    return result


def _fmt_svc_overlap(proto: str, lo: int, hi: int) -> str:
    if proto == "any":
        return "ANY"
    if proto in ("icmp", "icmpv6"):
        return proto.upper()
    if lo == 0 and hi == 65535:
        return proto.upper()
    if lo == hi:
        return f"{proto.upper()}:{lo}"
    return f"{proto.upper()}:{lo}-{hi}"


def print_partial_shadowed_analysis(results: list[dict], out: TextIO = sys.stdout):
    total     = len(results)
    conflicts = sum(1 for r in results if r["conflict"])

    out.write(c("\n" + "═" * 71 + "\n", _C.BOLD))
    out.write(c("  ЧАСТИЧНОЕ ЗАТЕМНЕНИЕ ПРАВИЛ\n", _C.BOLD))
    out.write(c("═" * 71 + "\n", _C.BOLD))
    out.write(f"  Найдено пар с пересечением: {total}\n")
    out.write(f"  Конфликтов действий       : {c(conflicts, _C.RED if conflicts else _C.GREEN)}"
              f"  {c('← ALLOW пересекается с DENY', _C.DIM) if conflicts else ''}\n")
    out.write(c("─" * 71 + "\n", _C.DIM))
    out.write(c("  Показаны только частичные пересечения (полные тени исключены).\n", _C.DIM))
    out.write(c("  Серым выделены значения объектов которые пересекаются.\n", _C.DIM))
    out.write(c("═" * 71 + "\n\n", _C.BOLD))

    # Группируем по "by"-правилу
    seen_by: dict[str, list[dict]] = {}
    for entry in results:
        seen_by.setdefault(entry["by"].uid, []).append(entry)

    for by_uid, entries in seen_by.items():
        by = entries[0]["by"]
        has_conflict = any(e["conflict"] for e in entries)
        conflict_mark = c("  ⚠ КОНФЛИКТ", _C.RED, _C.BOLD) if has_conflict else ""

        out.write(f"{_TH_ROOT}{_rule_dot(by)}  {_rule_label(by)}{conflict_mark}\n")
        out.write(f"{_TH_VERT}\n")

        for i, entry in enumerate(entries):
            sh      = entry["shadowed"]
            con     = entry["conflict"]
            is_last = (i == len(entries) - 1)
            prefix  = _TH_LAST if is_last else _TH_BRANCH
            indent  = _TH_END  if is_last else _TH_CONT
            conflict_s = c("  ⚠", _C.RED) if con else ""

            out.write(f"{prefix}{_rule_dot(sh)}  {_shadow_label(sh)}{conflict_s}\n")

            # Пересекающиеся объекты — серым (DIM), дедупликация + ANY вместо 0.0.0.0/0
            out.write(f"{indent}  {c('∩ src', _C.DIM)}  {c(_fmt_nets(entry['overlap_src']), _C.DIM)}\n")
            out.write(f"{indent}  {c('∩ dst', _C.DIM)}  {c(_fmt_nets(entry['overlap_dst']), _C.DIM)}\n")
            out.write(f"{indent}  {c('∩ svc', _C.DIM)}  {c(_fmt_svcs(entry['overlap_svc']), _C.DIM)}\n")

        out.write("\n")


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

    output = {"_ngfw_matcher": _json_meta(), "total": total, "conflicts": conflicts, "rules": rules_out}
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


# ─── Версия ──────────────────────────────────────────────────────────────────

def print_version_footer() -> None:
    """Однострочный футер с версией — выводится после любой успешной команды."""
    print(c(f"\n  ngfw-matcher  v{__version__}", _C.DIM))


def _json_meta() -> dict:
    """Мета-блок для вставки в начало JSON-экспортов."""
    return {"tool": "ngfw-matcher", "version": __version__}


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
    total    = sum(r["hits"] for r in rows)
    zero_cnt = sum(1 for r in rows if r["hits"] == 0)
    legend = (
        c("█ низкие", _C.GREEN) + "  " +
        c("█ средние", _C.YELLOW) + "  " +
        c("█ высокие", _C.RED)
    )
    print(f"  {legend}")
    summary = f"  Правил: {len(rows)}   Суммарно hits: {_fmt_hits(total)}"
    if zero_cnt:
        summary += f"   {c(f'Без срабатываний: {zero_cnt}', _C.DIM)}"
    print(c(summary, _C.DIM))
    print()

# ─── NAT правила ─────────────────────────────────────────────────────────────

def _nat_field_nets(field: dict | None) -> list[str]:
    """Извлекает читаемые адреса из RuleFieldNetwork (сетевое поле NAT правила)."""
    if not field or field.get("kind") != "RULE_KIND_LIST":
        return ["ANY"]
    out = []
    for obj in (field.get("objects") or []):
        if "networkIpAddress" in obj:
            out.append(obj["networkIpAddress"].get("inet", "?"))
        elif "networkIpRange" in obj:
            r = obj["networkIpRange"]
            out.append(f"{r.get('from','?')}–{r.get('to','?')}")
        elif "networkFqdn" in obj:
            out.append(f"FQDN:{obj['networkFqdn'].get('fqdn','?')}")
        elif "networkGeoAddress" in obj:
            out.append(f"GeoIP:{obj['networkGeoAddress'].get('geoId','?')}")
        elif "networkGroup" in obj:
            out.append(f"[{obj['networkGroup'].get('name','группа')}]")
    return out or ["ANY"]


def _nat_field_svcs(field: dict | None) -> list[str]:
    """Извлекает читаемые сервисы из RuleFieldService NAT правила."""
    if not field or field.get("kind") != "RULE_KIND_LIST":
        return ["ANY"]
    out = []
    for item in (field.get("objects") or []):
        if "service" in item:
            svc  = item["service"]
            p    = PROTO.get(svc.get("protocol", 0), "?")
            pts  = []
            for port_obj in (svc.get("dstPorts") or []):
                if "singlePort" in port_obj:
                    pts.append(str(port_obj["singlePort"].get("port", "")))
                elif "portRange" in port_obj:
                    pr = port_obj["portRange"]
                    pts.append(f"{pr.get('from','')}–{pr.get('to','')}")
            out.append(f"{p.upper()}/{','.join(pts)}" if pts else p.upper())
        elif "serviceGroup" in item:
            out.append(f"[{item['serviceGroup'].get('name','группа')}]")
    return out or ["ANY"]


def _nat_translated_port(port_field: dict | None) -> str:
    """Читаемое представление srcTranslatedPort."""
    if not port_field:
        return ""
    if "portNum" in port_field:
        p = port_field["portNum"].get("port")
        if p:
            return f":{p}"
    if "portRange" in port_field:
        pr = port_field["portRange"]
        return f":{pr.get('from','')}–{pr.get('to','')}"
    return ""


def print_nat_rules(
    nat_rules: list[NatRule],
    associations: list[NatAssociation] | None = None,
) -> None:
    """Вывод NAT правил с типом, направлением, адресами трансляции и ассоциированными правилами."""
    SEP = c("═" * 72, _C.DIM)
    assoc_map = {a.nat_rule.uid: a for a in (associations or [])}
    print()
    print(SEP)
    print(c(f"  NAT ПРАВИЛА  ({len(nat_rules)} шт.)", _C.BOLD))
    print(SEP)

    for rule in nat_rules:
        # ── Заголовок ───────────────────────────────────────────────────────
        st      = c("ON ", _C.GREEN) if rule.enabled else c("OFF", _C.YELLOW)
        prec    = c(rule.precedence, _C.CYAN)
        arrow   = c(rule.direction_arrow, _C.BOLD)
        nat_lbl = c(rule.nat_type, _C.YELLOW, _C.BOLD) if rule.nat_type != "—" else c("—", _C.DIM)
        print()
        print(f"  {nat_lbl}  {arrow}  {c(rule.name, _C.CYAN, _C.BOLD)}  "
              f"#{rule.position} {prec}  {st}")
        print(c("  " + "─" * 68, _C.DIM))

        # ── Условия матчинга ─────────────────────────────────────────────────
        srcs = _nat_field_nets(rule.source_addr)
        dsts = _nat_field_nets(rule.destination_addr)
        svcs = _nat_field_svcs(rule.service)

        print(f"  {c('Src:', _C.DIM):<20} {', '.join(srcs)}")
        print(f"  {c('Dst:', _C.DIM):<20} {', '.join(dsts)}")
        print(f"  {c('Svc:', _C.DIM):<20} {', '.join(svcs)}")

        # ── Трансляция источника (SNAT) ──────────────────────────────────────
        if rule.is_snat:
            t_addrs = _nat_field_nets(rule.src_translated_address)
            t_port  = _nat_translated_port(rule.src_translated_port)
            src_str = ', '.join(srcs)
            dst_str = ', '.join(t_addrs) + t_port
            masq    = "TRANSLATED" not in rule.src_translation_addr_type
            lbl     = c("Masquerade", _C.DIM) if masq else ""
            print(f"  {c('SNAT  -->:', _C.GREEN):<20} "
                  f"{c(src_str, _C.BLUE)} --> {c(dst_str, _C.WHITE)} {lbl}")

        # ── Трансляция назначения (DNAT) ─────────────────────────────────────
        if rule.is_dnat:
            t_addrs  = _nat_field_nets(rule.dst_translated_address)
            t_port_s = f":{rule.dst_translated_port}" if rule.dst_translated_port else ""
            dst_str  = ', '.join(dsts)
            real_str = ', '.join(t_addrs) + t_port_s
            print(f"  {c('DNAT  <--:', _C.CYAN):<20} "
                  f"{c(dst_str, _C.BLUE)} --> {c(real_str, _C.WHITE)}")

        if rule.description:
            print(f"  {c('Описание:', _C.DIM):<20} {c(rule.description, _C.DIM)}")

        # ── Ассоциированные правила безопасности ─────────────────────────────
        assoc = assoc_map.get(rule.uid)
        if assoc is not None:
            _print_assoc_sec_rules(assoc)

    print()
    print(SEP)
    print()


def _print_assoc_sec_rules(assoc: NatAssociation) -> None:
    """Вывод ассоциированных правил безопасности под NAT правилом."""
    matches = assoc.matches
    if not matches:
        print(f"  {c('Sec rules:', _C.DIM):<20} {c('нет совпадений', _C.YELLOW)}")
        return

    label = c(f"Sec rules ({len(matches)}):", _C.DIM)
    print(f"  {label}")
    for m in matches:
        r = m.rule
        action_color = _C.GREEN if r.action == "allow" else _C.RED
        action_str   = c(r.action.upper(), action_color)
        prec_str     = c(r.precedence, _C.DIM)

        if m.has_conflict:
            dims    = "+".join(m.conflict_dims)
            warn_lbl = c(f"[!narrower:{dims}]", _C.YELLOW, _C.BOLD)
        elif m.full_coverage:
            warn_lbl = c("[full]", _C.GREEN)
        else:
            warn_lbl = c("[partial]", _C.DIM)

        print(f"    {action_str}  {c(r.name, _C.WHITE)}  #{r.position_in_precedence} {prec_str}  {warn_lbl}")
