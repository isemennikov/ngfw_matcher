# Developed by Ilya Semennikov
"""
ObjectResolver — раскрывает объекты PT NGFW в конкретные IP-сети и порты.

Структуры из openapi.yml:

NetworkObject (oneOf):
    { networkIpAddress: { id, inet: "10.0.0.1/24" | "10.0.0.1" } }
    { networkIpRange:   { id, from: "10.0.0.1", to: "10.0.0.10" } }
    { networkFqdn:      { id, fqdn: "..." } }          → пропускаем (нет DNS)
    { networkGeoAddress: { id, geoId: 123 } }           → пропускаем
    { networkGroup:     { id, name } }                  → рекурсия через API

RuleFieldNetwork:
    { kind: "RULE_KIND_ANY" }                           → совпадает с любым IP
    { kind: "RULE_KIND_LIST", objects: [NetworkObject] }

ServiceItem (oneOf):
    { service:      { id, protocol: 6, srcPorts: [...], dstPorts: [...] } }
    { serviceGroup: { id, name } }                      → рекурсия через API

ServicePorts (oneOf):
    { singlePort: { port: 443 } }
    { portRange:  { from: 80, to: 443 } }

RuleFieldService:
    { kind: "RULE_KIND_ANY" }
    { kind: "RULE_KIND_LIST", objects: [ServiceItem] }

RuleFieldZone:
    { kind: "RULE_KIND_ANY" }
    { kind: "RULE_KIND_LIST", objects: [{ id, name, ... }] }
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Callable

log = logging.getLogger("ngfw.resolver")

_NET = ipaddress.IPv4Network | ipaddress.IPv6Network
ANY_NET = [ipaddress.ip_network("0.0.0.0/0")]
ANY_SVC = [("any", 0, 65535)]   # (proto_name, port_min, port_max)

# IANA → имя протокола (только числа из PT NGFW)
_PROTO = {0: "any", 1: "icmp", 6: "tcp", 17: "udp", 47: "gre",
          50: "esp", 51: "ah", 58: "icmpv6", 89: "ospf", 132: "sctp"}


def _net(cidr: str) -> list[_NET]:
    try:
        # "10.0.0.1" → host-route
        return [ipaddress.ip_network(cidr.strip(), strict=False)]
    except ValueError:
        log.debug("Cannot parse network: %s", cidr)
        return []


class ObjectResolver:
    """
    Раскрывает RuleFieldNetwork и RuleFieldService в плоские списки
    ip_network / (proto, port_min, port_max).

    fetch_net_group(group_id) → list[NetworkObject dict]  — callback к API
    fetch_svc_group(group_id) → list[ServiceItem dict]    — callback к API

    Если callbacks не заданы — группы раскрыть невозможно,
    но одиночные объекты будут работать.
    """

    def __init__(
        self,
        fetch_net_group: Callable[[str], list] | None = None,
        fetch_svc_group: Callable[[str], list] | None = None,
    ):
        self._fetch_net_group = fetch_net_group
        self._fetch_svc_group = fetch_svc_group

    # ─── Публичные методы ────────────────────────────────────────────────────

    def resolve_field_network(self, field: dict | None) -> list[_NET]:
        """
        RuleFieldNetwork → список ip_network.
        field = { kind: "RULE_KIND_ANY"|"RULE_KIND_LIST", objects: [...] }
        """
        if field is None:
            return ANY_NET

        kind = field.get("kind", "")
        if kind in ("RULE_KIND_ANY", "RULE_KIND_UNSPECIFIED", ""):
            return ANY_NET

        nets: list[_NET] = []
        for obj in field.get("objects") or []:
            nets.extend(self._resolve_net_object(obj))

        return nets or ANY_NET

    def resolve_field_network_concrete(self, field: dict | None) -> list[_NET]:
        """
        Как resolve_field_network, но FQDN/geo объекты пропускаются без fallback.
        Возвращает [] если все объекты — FQDN/geo (пустой список = нет IP-совпадений).
        """
        if field is None:
            return ANY_NET
        kind = field.get("kind", "")
        if kind in ("RULE_KIND_ANY", "RULE_KIND_UNSPECIFIED", ""):
            return ANY_NET
        nets: list[_NET] = []
        for obj in field.get("objects") or []:
            nets.extend(self._resolve_net_object_no_fqdn(obj))
        return nets  # Может быть пустым — намеренно, без ANY_NET fallback

    def _resolve_net_object_no_fqdn(self, obj: dict) -> list[_NET]:
        """Как _resolve_net_object, но FQDN/geo возвращают [] вместо ANY_NET."""
        if "networkFqdn" in obj or "networkGeoAddress" in obj:
            return []
        if "networkGroup" in obj:
            group = obj["networkGroup"]
            gid = group.get("id")
            if not gid:
                return ANY_NET
            if self._fetch_net_group is None:
                return ANY_NET
            members = self._fetch_net_group(gid)
            result: list[_NET] = []
            for member in members:
                result.extend(self._resolve_net_object_no_fqdn(member))
            return result  # Пустой если группа содержит только FQDN
        return self._resolve_net_object(obj)

    def resolve_field_service(self, field: dict | None) -> list[tuple]:
        """
        RuleFieldService → список (proto_name, port_min, port_max).
        field = { kind: ..., objects: [ServiceItem] }
        """
        if field is None:
            return ANY_SVC

        kind = field.get("kind", "")
        if kind in ("RULE_KIND_ANY", "RULE_KIND_UNSPECIFIED", ""):
            return ANY_SVC

        services: list[tuple] = []
        for item in field.get("objects") or []:
            services.extend(self._resolve_service_item(item))

        return services or ANY_SVC

    def resolve_field_zone(self, field: dict | None) -> list[str]:
        """
        RuleFieldZone → список имён зон.
        Пустой список = any.
        """
        if field is None:
            return []

        kind = field.get("kind", "")
        if kind in ("RULE_KIND_ANY", "RULE_KIND_UNSPECIFIED", ""):
            return []   # any

        return [z.get("name", "") for z in (field.get("objects") or []) if z.get("name")]

    # ─── NetworkObject ────────────────────────────────────────────────────────

    def _resolve_net_object(self, obj: dict) -> list[_NET]:
        """
        NetworkObject — oneOf по ключу верхнего уровня.
        """
        # networkIpAddress → { id, inet: "10.0.0.1/24" }
        if "networkIpAddress" in obj:
            addr = obj["networkIpAddress"]
            inet = addr.get("inet") or ""
            if inet:
                # Если нет префикса — это хост /32
                if "/" not in inet and ":" not in inet:
                    inet = inet + "/32"
                return _net(inet)

        # networkIpRange → { id, from: "...", to: "..." }
        elif "networkIpRange" in obj:
            r = obj["networkIpRange"]
            start, end = r.get("from"), r.get("to")
            if start and end:
                try:
                    return list(ipaddress.summarize_address_range(
                        ipaddress.ip_address(start),
                        ipaddress.ip_address(end),
                    ))
                except ValueError as e:
                    log.debug("Bad range %s-%s: %s", start, end, e)

        # networkFqdn → пропускаем (нет DNS-резолвинга)
        elif "networkFqdn" in obj:
            fqdn = obj["networkFqdn"].get("fqdn", "?")
            log.debug("Skipping FQDN object: %s", fqdn)
            # Возвращаем ANY чтобы не блокировать правило с FQDN —
            # консервативное решение: считаем что FQDN может совпасть.
            return ANY_NET

        # networkGeoAddress → пропускаем (нет GeoIP БД)
        elif "networkGeoAddress" in obj:
            geo_id = obj["networkGeoAddress"].get("geoId", "?")
            log.debug("Skipping GeoIP object: geoId=%s", geo_id)
            # Аналогично — консервативно считаем совпадением
            return ANY_NET

        # networkGroup → рекурсия через API
        elif "networkGroup" in obj:
            group = obj["networkGroup"]
            gid   = group.get("id")
            if not gid:
                return ANY_NET

            if self._fetch_net_group is None:
                log.warning("networkGroup %s: нет fetch_net_group callback", gid)
                return ANY_NET   # без API не можем раскрыть — консервативно

            members = self._fetch_net_group(gid)
            result: list[_NET] = []
            for member in members:
                result.extend(self._resolve_net_object(member))
            return result or ANY_NET

        return []

    # ─── ServiceItem ─────────────────────────────────────────────────────────

    def _resolve_service_item(self, item: dict) -> list[tuple]:
        """
        ServiceItem — oneOf: { service: Service } | { serviceGroup: ServiceGroup }
        """
        if "service" in item:
            return self._resolve_service(item["service"])

        if "serviceGroup" in item:
            group = item["serviceGroup"]
            gid   = group.get("id")
            if not gid:
                return ANY_SVC

            if self._fetch_svc_group is None:
                log.warning("serviceGroup %s: нет fetch_svc_group callback", gid)
                return ANY_SVC

            members = self._fetch_svc_group(gid)
            result: list[tuple] = []
            for member in members:
                result.extend(self._resolve_service_item(member))
            return result or ANY_SVC

        return ANY_SVC

    def _resolve_service(self, svc: dict) -> list[tuple]:
        """
        Service:
          protocol: int  (IANA, 6=TCP, 17=UDP, 1=ICMP, 0=any)
          dstPorts: [ServicePorts]
          srcPorts: [ServicePorts]  (для матчинга dst_port нас интересует dstPorts)
        """
        proto_num  = svc.get("protocol", 0)
        proto_name = _PROTO.get(proto_num, str(proto_num))

        # ICMP — порты не применяются
        if proto_name in ("icmp", "icmpv6"):
            return [(proto_name, 0, 65535)]

        dst_ports = svc.get("dstPorts") or []

        # Нет dstPorts → сервис разрешает любой dst порт
        if not dst_ports:
            return [(proto_name, 0, 65535)]

        result: list[tuple] = []
        for sp in dst_ports:
            result.extend(self._resolve_service_ports(proto_name, sp))

        return result or [(proto_name, 0, 65535)]

    def _resolve_service_ports(self, proto: str, sp: dict) -> list[tuple]:
        """
        ServicePorts — oneOf:
          { singlePort: { port: 443 } }
          { portRange:  { from: 80, to: 443 } }
        """
        if "singlePort" in sp:
            p = sp["singlePort"].get("port")
            if p is not None:
                return [(proto, int(p), int(p))]

        if "portRange" in sp:
            pr = sp["portRange"]
            lo = pr.get("from")
            hi = pr.get("to")
            if lo is not None and hi is not None:
                return [(proto, int(lo), int(hi))]

        return [(proto, 0, 65535)]