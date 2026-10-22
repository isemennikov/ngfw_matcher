"""Shared text formatting for raw PT NGFW rule objects."""
from __future__ import annotations

from datetime import datetime, timezone

from .resolver import PROTO


def format_net_obj(obj: dict) -> str:
    """Return a human-readable string for a single raw network object."""
    if "networkIpAddress" in obj:
        return obj["networkIpAddress"].get("inet", "?")
    if "networkIpRange" in obj:
        r = obj["networkIpRange"]
        return f"{r.get('from','?')}–{r.get('to','?')}"
    if "networkFqdn" in obj:
        return f"FQDN:{obj['networkFqdn'].get('fqdn','?')}"
    if "networkGeoAddress" in obj:
        return f"GeoIP:{obj['networkGeoAddress'].get('geoId','?')}"
    if "networkGroup" in obj:
        return f"[{obj['networkGroup'].get('name','group')}]"
    return "?"


def format_svc_obj(obj: dict) -> str:
    """Return a human-readable string for a single raw service object."""
    if "service" in obj:
        svc = obj["service"]
        proto = PROTO.get(svc.get("protocol", 0), "?")
        ports = []
        for p in svc.get("dstPorts") or []:
            if "singlePort" in p:
                ports.append(str(p["singlePort"].get("port", "")))
            elif "portRange" in p:
                pr = p["portRange"]
                ports.append(f"{pr.get('from','')}–{pr.get('to','')}")
        return f"{proto.upper()}/{','.join(ports)}" if ports else proto.upper()
    if "serviceGroup" in obj:
        return f"[{obj['serviceGroup'].get('name','group')}]"
    return "?"


# ─── Метки времени SecurityRule (createdAt / updatedAt) ──────────────────────

def parse_rule_dt(value: str | None) -> datetime | None:
    """ISO-8601 (возможен суффикс 'Z') → aware datetime в UTC, иначе None."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fmt_rule_date(value: str | None) -> str:
    """'2026-05-19T19:38:08Z' → '19.05.2026' (UTC)."""
    dt = parse_rule_dt(value)
    return dt.strftime("%d.%m.%Y") if dt else ""


def fmt_rule_datetime(value: str | None) -> str:
    """'2026-05-19T19:38:08Z' → '19.05.2026 19:38 UTC'."""
    dt = parse_rule_dt(value)
    return dt.strftime("%d.%m.%Y %H:%M UTC") if dt else ""


def rule_days_ago(value: str | None) -> int | None:
    """Полных дней с момента метки до сейчас. Меньше нуля → 0."""
    dt = parse_rule_dt(value)
    if not dt:
        return None
    delta = datetime.now(timezone.utc) - dt
    return max(0, delta.days)
