"""
Модели данных.
"""
# Developed by Ilya Semennikov
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TrafficFlow:
    src_ip:   str
    dst_ip:   str
    dst_port: int
    protocol: str          # tcp | udp | icmp | any
    src_port: int = 0
    zone_src: str = ""
    zone_dst: str = ""

    def __post_init__(self):
        self.protocol = self.protocol.lower()

    def __str__(self) -> str:
        z = f"  [{self.zone_src}→{self.zone_dst}]" if (self.zone_src or self.zone_dst) else ""
        sp = f":{self.src_port}" if self.src_port else ""
        return f"{self.src_ip}{sp} → {self.dst_ip}:{self.dst_port} [{self.protocol.upper()}]{z}"


@dataclass
class NormalizedRule:
    """Правило в виде, готовом к матчингу. Хранит оригинальный SecurityRule dict."""
    index:      int   # глобальная позиция в объединённом списке PRE+default+POST (0-based)
    uid:        str
    name:       str
    enabled:    bool
    action:     str          # allow | deny | drop
    precedence: str          # pre | default | post

    # Позиция внутри своего набора (PRE / default / POST) — как в СУ (1-based)
    position_in_precedence: int = 0

    # Оригинальные поля из SecurityRule (передаются напрямую в resolver)
    source_addr:      Optional[dict] = None  # RuleFieldNetwork
    destination_addr: Optional[dict] = None  # RuleFieldNetwork
    service:          Optional[dict] = None  # RuleFieldService
    source_zone:      Optional[dict] = None  # RuleFieldZone
    destination_zone: Optional[dict] = None  # RuleFieldZone
    application:      Optional[dict] = None  # RuleFieldApplication

    # Группа устройств — источник правила (заполняется при сборке эффективной
    # политики с учётом родительских групп, см. core/snapshot.get_effective_group)
    source_group_id:   str = ""
    source_group_name: str = ""

    raw: dict = field(default_factory=dict, repr=False)


@dataclass
class NatRule:
    """NAT-правило из PT NGFW."""
    uid:             str
    name:            str
    description:     str
    position:        int
    global_position: int
    enabled:         bool
    precedence:      str   # pre / post

    # Условия матчинга — та же структура что у NormalizedRule
    source_addr:      Optional[dict] = None
    destination_addr: Optional[dict] = None
    service:          Optional[dict] = None
    source_zone:      Optional[dict] = None
    destination_zone: Optional[dict] = None

    # Source NAT
    src_translation_type:      str            = ""    # MASQUERADE / ADDRESS / ""
    src_translation_addr_type: str            = ""
    src_translated_address:    Optional[dict] = None  # RuleFieldNetwork
    src_translated_port:       Optional[dict] = None  # {portNum:{port}} | {portRange:{from,to}}

    # Destination NAT
    dst_translation_type:   str            = ""
    dst_translated_address: Optional[dict] = None
    dst_translated_port:    Optional[int]  = None

    source_group_id:   str = ""
    source_group_name: str = ""

    raw: dict = field(default_factory=dict, repr=False)

    @property
    def is_snat(self) -> bool:
        return bool(self.src_translation_type) and "_NONE" not in self.src_translation_type

    @property
    def is_dnat(self) -> bool:
        return bool(self.dst_translation_type) and "_NONE" not in self.dst_translation_type

    @property
    def nat_type(self) -> str:
        parts = []
        if self.is_snat:
            parts.append("SNAT")
        if self.is_dnat:
            parts.append("DNAT")
        return "+".join(parts) if parts else "—"

    @property
    def direction_arrow(self) -> str:
        if self.is_snat and self.is_dnat:
            return "<-->"
        if self.is_snat:
            return "-->"
        if self.is_dnat:
            return "<--"
        return "—"


@dataclass
class MatchResult:
    flow:     TrafficFlow
    matched:  Optional[NormalizedRule]    = None

    # Дубли по IP/порту/протоколу — кандидаты на удаление
    shadowed:      list[NormalizedRule]   = field(default_factory=list)
    # Правила с application-условием (L7): service=ANY, app=LIST — не проверялись
    skipped_app:   list[NormalizedRule]   = field(default_factory=list)
    # Правила с FQDN/geo в src/dst — совпало бы если FQDN=ANY, но не проверить по IP
    skipped_fqdn:  list[NormalizedRule]   = field(default_factory=list)
    # Аннотации совпадений: uid → "↑ dst" / "↓ dst" / "↑ src" / "↓ src" и т.п.
    match_notes:   dict[str, str]         = field(default_factory=dict)

    skipped_disabled: int                 = 0

    @property
    def hit(self) -> bool:
        return self.matched is not None

    @property
    def action(self) -> str:
        return self.matched.action if self.matched else "default-deny"

    @property
    def has_duplicates(self) -> bool:
        return bool(self.shadowed)