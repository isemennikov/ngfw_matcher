# Developed by Ilya Semennikov
"""Утилиты анализа общего портов , используемые CLI и веб-роутерах."""
from __future__ import annotations


def parse_ports(dport_str: str) -> list[int]:
    """
    "any"/""         → [0]  (0 зарезервировано: нет фильтра по порту)
    "443"            → [443]
    "80,443"         → [80, 443]
    "5000-5010"      → [5000..5010]
    Допустимые порты: 1–65535. Диапазоны > 1000 → [lo, mid, hi].
    """
    if not dport_str or dport_str.lower() == "any":
        return [0]

    dport_str = (dport_str
                 .replace("–", "-").replace("—", "-")
                 .replace("−", "-").replace("‐", "-")
                 .replace("‑", "-").replace("―", "-"))

    ports: list[int] = []
    for part in dport_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo.strip()), int(hi.strip())
            if hi - lo > 1000:
                ports += [lo, (lo + hi) // 2, hi]
            else:
                ports += list(range(lo, hi + 1))
        else:
            ports.append(int(part))

    return sorted(set(ports)) or [0]


def port_str(sp: dict) -> str:
    """Format a dstPorts/srcPorts entry dict → human-readable string."""
    if "singlePort" in sp:
        return str(sp["singlePort"].get("port", "?"))
    if "portRange" in sp:
        return f"{sp['portRange'].get('from', '?')}-{sp['portRange'].get('to', '?')}"
    return "?"
