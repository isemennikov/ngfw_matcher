"""Shared text formatting for raw PT NGFW rule objects."""
from __future__ import annotations

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
