# Developed by Ilya Semennikov
"""NAT ↔ Security rule association and conflict detection."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .models import NatRule, NormalizedRule
from .resolver import ObjectResolver
from .matcher import _nets_overlaps, _svc_overlaps, _nets_covers, _svc_covers

_ZERO_NETS = {
    ipaddress.ip_network("0.0.0.0/0"),
    ipaddress.ip_network("::/0"),
}
_ANY_SVC = ("any", 0, 65535)

# RFC1918 private ranges — for SNAT ANY destination filtering
_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _nets_is_any(nets: list) -> bool:
    return any(n in _ZERO_NETS for n in nets)


def _svc_is_any(svcs: list) -> bool:
    return any(s == _ANY_SVC for s in svcs)


def _nets_all_private(nets: list) -> bool:
    """True if every network in the list is a subnet of an RFC1918 range."""
    if not nets:
        return False
    return all(
        n.version == 4 and n not in _ZERO_NETS and any(n.subnet_of(r) for r in _RFC1918)
        for n in nets
    )


def _field_has_fqdn(field: dict | None) -> bool:
    if not field or field.get("kind") != "RULE_KIND_LIST":
        return False
    return any("networkFqdn" in obj for obj in (field.get("objects") or []))


def _has_nontrivial_overlap(
    nat_src, nat_dst, nat_svc,
    sec_src, sec_dst, sec_svc,
) -> bool:
    """
    At least one dimension must have a specific-to-specific intersection
    (neither side ANY). Rules that match only because one side is 0.0.0.0/0
    or ANY-service are excluded as noise.
    """
    if not _nets_is_any(nat_src) and not _nets_is_any(sec_src) and _nets_overlaps(nat_src, sec_src):
        return True
    if not _nets_is_any(nat_dst) and not _nets_is_any(sec_dst) and _nets_overlaps(nat_dst, sec_dst):
        return True
    if not _svc_is_any(nat_svc) and not _svc_is_any(sec_svc) and _svc_overlaps(nat_svc, sec_svc):
        return True
    return False


@dataclass
class SecRuleMatch:
    """A security rule that overlaps with a NAT rule."""
    rule: NormalizedRule

    # Does the security rule fully cover the NAT rule in each dimension?
    src_covers_nat: bool
    dst_covers_nat: bool
    svc_covers_nat: bool

    # Does the NAT rule fully cover the security rule in each dimension?
    nat_covers_src: bool
    nat_covers_dst: bool
    nat_covers_svc: bool

    @property
    def full_coverage(self) -> bool:
        """Security rule covers the entire NAT match space."""
        return self.src_covers_nat and self.dst_covers_nat and self.svc_covers_nat

    @property
    def conflict_dims(self) -> list[str]:
        """Dimensions where security rule is narrower than the NAT rule (potential block)."""
        dims = []
        if self.nat_covers_src and not self.src_covers_nat:
            dims.append("src")
        if self.nat_covers_dst and not self.dst_covers_nat:
            dims.append("dst")
        if self.nat_covers_svc and not self.svc_covers_nat:
            dims.append("svc")
        return dims

    @property
    def has_conflict(self) -> bool:
        return bool(self.conflict_dims)


@dataclass
class NatAssociation:
    nat_rule: NatRule
    matches: list[SecRuleMatch] = field(default_factory=list)

    @property
    def has_coverage(self) -> bool:
        """At least one security rule fully covers the NAT rule."""
        return any(m.full_coverage for m in self.matches)

    @property
    def has_conflicts(self) -> bool:
        return any(m.has_conflict for m in self.matches)


def associate_nat_rules(
    nat_rules: list[NatRule],
    sec_rules: list[NormalizedRule],
    resolver: ObjectResolver,
) -> list[NatAssociation]:
    """
    For each NAT rule, find security rules that meaningfully overlap in
    src/dst/svc. Applies the same filters as check_shadowed:
      - only enabled rules
      - no zone-based rules
      - no FQDN rules (resolver can't resolve → ANY fallback → false positives)
    Additionally requires at least one non-trivial (specific-to-specific)
    intersection dimension so that rules matching only through ANY don't appear.
    """
    active_sec = [
        r for r in sec_rules
        if r.enabled
        and not resolver.resolve_field_zone(r.source_zone)
        and not resolver.resolve_field_zone(r.destination_zone)
        and not _field_has_fqdn(r.source_addr)
        and not _field_has_fqdn(r.destination_addr)
    ]

    sec_src = {r.uid: resolver.resolve_field_network(r.source_addr)      for r in active_sec}
    sec_dst = {r.uid: resolver.resolve_field_network(r.destination_addr) for r in active_sec}
    sec_svc = {r.uid: resolver.resolve_field_service(r.service)          for r in active_sec}

    results: list[NatAssociation] = []
    for nat in nat_rules:
        nat_src = resolver.resolve_field_network(nat.source_addr)
        nat_svc = resolver.resolve_field_service(nat.service)

        # PT NGFW evaluates security policy post-NAT:
        # - For DNAT: security rule dst matches the translated (internal) address
        # - For SNAT: security rule src matches the original (internal) address
        if nat.is_dnat and nat.dst_translated_address:
            nat_dst = resolver.resolve_field_network(nat.dst_translated_address)
        else:
            nat_dst = resolver.resolve_field_network(nat.destination_addr)

        assoc = NatAssociation(nat_rule=nat)
        for sec in active_sec:
            ssrc = sec_src[sec.uid]
            sdst = sec_dst[sec.uid]
            ssvc = sec_svc[sec.uid]

            if not _nets_overlaps(nat_src, ssrc):
                continue
            if not _nets_overlaps(nat_dst, sdst):
                continue
            if not _svc_overlaps(nat_svc, ssvc):
                continue

            # Exclude matches that exist only because one side is ANY in all dimensions
            if not _has_nontrivial_overlap(nat_src, nat_dst, nat_svc, ssrc, sdst, ssvc):
                continue

            # For SNAT with ANY destination: skip security rules whose destination
            # is entirely RFC1918. SNAT ANY semantically means internet/public traffic —
            # internal routes are not relevant.
            if not nat.is_dnat and _nets_is_any(nat_dst) and _nets_all_private(sdst):
                continue

            assoc.matches.append(SecRuleMatch(
                rule           = sec,
                src_covers_nat = _nets_covers(ssrc, nat_src),
                dst_covers_nat = _nets_covers(sdst, nat_dst),
                svc_covers_nat = _svc_covers(ssvc, nat_svc),
                nat_covers_src = _nets_covers(nat_src, ssrc),
                nat_covers_dst = _nets_covers(nat_dst, sdst),
                nat_covers_svc = _svc_covers(nat_svc, ssvc),
            ))

        results.append(assoc)

    return results
