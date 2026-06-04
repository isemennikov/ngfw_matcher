# Developed by Ilya Semennikov
"""
RuleMatcher — first-match движок.

Режимы матчинга сетей (параметр strict):
    strict=True (по умолчанию) — flow ⊆ rule_net (суперсеть или точное совпадение)
    strict=False (--overlap)   — любое пересечение (включая подсети)

Зональные правила пропускаются — анализ только IP/порт/протокол.

Аннотации (match_notes):
    "↑ dst"  — правило охватывает шире запроса (суперсеть)
    "↓ dst"  — частичное покрытие (подсеть, только в --overlap)
"""
from __future__ import annotations

import ipaddress
import logging

from .models import TrafficFlow, NormalizedRule, MatchResult
from .resolver import ObjectResolver

log = logging.getLogger("ngfw.matcher")

# IP-типы
_IPv4Addr  = ipaddress.IPv4Address
_IPv6Addr  = ipaddress.IPv6Address
_IPv4Net   = ipaddress.IPv4Network
_IPv6Net   = ipaddress.IPv6Network
_AnyAddr   = (_IPv4Addr, _IPv6Addr)
_AnyNet    = (_IPv4Net,  _IPv6Net)

_ZERO_NETS = {
    ipaddress.ip_network("0.0.0.0/0"),
    ipaddress.ip_network("::/0"),
}


def _parse_flow_addr(value: str):
    """
    '192.168.1.10'   → IPv4Address
    '192.168.1.0/24' → IPv4Network
    """
    if "/" in value:
        return ipaddress.ip_network(value, strict=False)
    return ipaddress.ip_address(value)


# ─── IP матчинг ──────────────────────────────────────────────────────────────

def _flow_matches_rule_net(flow, rule_net, strict: bool = True) -> bool:
    if isinstance(flow, _AnyAddr):
        return flow in rule_net
    try:
        if strict:
            return flow.subnet_of(rule_net)   # flow ⊆ rule_net
        else:
            return flow.overlaps(rule_net)
    except TypeError:
        return False


def _addr_in_nets(flow, rule_nets: list, strict: bool = True) -> bool:
    return any(_flow_matches_rule_net(flow, rn, strict) for rn in rule_nets)


def _net_relation(flow_net, rule_nets: list) -> str:
    if isinstance(flow_net, _AnyAddr) or flow_net in _ZERO_NETS:
        return ""
    for rn in rule_nets:
        if not isinstance(rn, (_IPv4Net, _IPv6Net)):
            continue
        try:
            if flow_net == rn:
                return ""
            if flow_net.subnet_of(rn):
                return "supernet"
            if rn.subnet_of(flow_net):
                return "subnet"
        except TypeError:
            pass
    return ""


# ─── RuleMatcher ─────────────────────────────────────────────────────────────

class RuleMatcher:
    def __init__(self, rules: list[NormalizedRule], resolver: ObjectResolver,
                 strict: bool = True):
        self.rules    = rules
        self.resolver = resolver
        self.strict   = strict

    @staticmethod
    def _has_ip_src(field: dict | None) -> bool:
        """True если field содержит хотя бы один IP/range/group объект (не только FQDN/geo)."""
        if field is None:
            return True
        kind = field.get("kind", "")
        if kind in ("RULE_KIND_ANY", "RULE_KIND_UNSPECIFIED", ""):
            return True
        return any(
            "networkIpAddress" in obj or "networkIpRange" in obj or "networkGroup" in obj
            for obj in (field.get("objects") or [])
        )

    @staticmethod
    def _is_app_only(rule: NormalizedRule) -> bool:
        """True: service=ANY, application=LIST — L7-only, нельзя проверить по IP/порту."""
        svc = rule.service
        if svc and svc.get("kind") == "RULE_KIND_LIST":
            return False
        app = rule.application
        return bool(app and app.get("kind") == "RULE_KIND_LIST" and app.get("objects"))

    def _build_match_note(self, src, dst, rule: NormalizedRule) -> str:
        """Аннотация совпадения для сетевых запросов (суперсеть / подсеть)."""
        parts = []

        # Сетевые аннотации для IP-сетей
        if isinstance(dst, _AnyNet) and dst not in _ZERO_NETS:
            dst_nets = self.resolver.resolve_field_network(rule.destination_addr)
            rel = _net_relation(dst, dst_nets)
            if rel == "supernet":
                parts.append("↑ dst")
            elif rel == "subnet":
                parts.append("↓ dst")

        if isinstance(src, _AnyNet) and src not in _ZERO_NETS:
            src_nets = self.resolver.resolve_field_network(rule.source_addr)
            rel = _net_relation(src, src_nets)
            if rel == "supernet":
                parts.append("↑ src")
            elif rel == "subnet":
                parts.append("↓ src")

        return "  ".join(parts)

    def fullview_scan(self, flow: TrafficFlow) -> list[NormalizedRule]:
        """
        Возвращает ВСЕ включённые правила, где src совпадает с flow.src_ip.
        dst/port/proto — дополнительные фильтры (пропускаются если any/0).
        Зональные правила включаются в выдачу (в отличие от match()).
        """
        try:
            src = _parse_flow_addr(flow.src_ip)
        except ValueError as e:
            log.error("Некорректный адрес: %s", e)
            return []

        is_dst_any   = (flow.dst_ip in ("0.0.0.0/0", "::/0"))
        is_port_any  = (flow.dst_port == 0)
        is_proto_any = (flow.protocol == "any")

        try:
            dst = None if is_dst_any else _parse_flow_addr(flow.dst_ip)
        except ValueError:
            dst = None
            is_dst_any = True

        matched: list[NormalizedRule] = []
        for rule in self.rules:
            if not rule.enabled:
                continue

            if not self._has_ip_src(rule.source_addr):
                continue

            src_zones = self.resolver.resolve_field_zone(rule.source_zone)
            dst_zones = self.resolver.resolve_field_zone(rule.destination_zone)
            if src_zones or dst_zones:
                continue

            src_nets = self.resolver.resolve_field_network(rule.source_addr)
            if not _addr_in_nets(src, src_nets, self.strict):
                continue

            if not is_dst_any and dst is not None:
                dst_nets = self.resolver.resolve_field_network(rule.destination_addr)
                if not _addr_in_nets(dst, dst_nets, self.strict):
                    continue

            if (not is_port_any or not is_proto_any) and not self._is_app_only(rule):
                services = self.resolver.resolve_field_service(rule.service)
                if not self._service_matches(flow, services):
                    continue

            matched.append(rule)

        return matched

    def match(self, flow: TrafficFlow) -> MatchResult:
        result = MatchResult(flow=flow)

        try:
            src = _parse_flow_addr(flow.src_ip)
            dst = _parse_flow_addr(flow.dst_ip)
        except ValueError as e:
            log.error("Некорректный адрес в запросе: %s", e)
            return result

        for rule in self.rules:
            if not rule.enabled:
                result.skipped_disabled += 1
                continue

            if self._is_app_only(rule):
                if self._rule_matches(rule, flow, src, dst):
                    result.skipped_app.append(rule)
                continue

            if self._rule_matches(rule, flow, src, dst):
                note = self._build_match_note(src, dst, rule)
                if note:
                    result.match_notes[rule.uid] = note
                if result.matched is None:
                    result.matched = rule
                else:
                    result.shadowed.append(rule)

        return result

    def _rule_matches(self, rule: NormalizedRule, flow: TrafficFlow, src, dst) -> bool:

        # ── Зоны ─────────────────────────────────────────────────────────────
        src_zones = self.resolver.resolve_field_zone(rule.source_zone)
        dst_zones = self.resolver.resolve_field_zone(rule.destination_zone)
        if src_zones or dst_zones:
            return False

        # ── Источник ──────────────────────────────────────────────────────────
        src_nets = self.resolver.resolve_field_network(rule.source_addr)
        if not _addr_in_nets(src, src_nets, self.strict):
            return False

        # ── Назначение ────────────────────────────────────────────────────────
        dst_nets = self.resolver.resolve_field_network(rule.destination_addr)
        if not _addr_in_nets(dst, dst_nets, self.strict):
            return False

        # ── Сервис ────────────────────────────────────────────────────────────
        services = self.resolver.resolve_field_service(rule.service)
        if not self._service_matches(flow, services):
            return False

        return True

    @staticmethod
    def _service_matches(flow: TrafficFlow, services: list[tuple]) -> bool:
        proto = flow.protocol.lower()
        dport = flow.dst_port

        if dport == 0 and proto == "any":
            return True

        for svc_proto, port_min, port_max in services:
            svc_proto = svc_proto.lower()
            proto_ok  = svc_proto == "any" or proto == "any" or svc_proto == proto
            port_ok   = (dport == 0
                         or (port_min == 0 and port_max == 65535)
                         or (port_min <= dport <= port_max))
            if proto_ok and port_ok:
                return True

        return False
