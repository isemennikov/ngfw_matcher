"""Process-level cache: matchers keyed by snapshot path + group_id + include_parents."""
from __future__ import annotations

import json
import threading
import time
from collections import OrderedDict

from ..core.matcher import RuleMatcher

# Bound matcher/parsed-snapshot caches so long-running, multi-user sessions
# cannot grow memory without limit.
_MAX_ENTRIES = 64
_TTL_SECONDS = 3600

_cache: "OrderedDict[str, tuple[float, RuleMatcher]]" = OrderedDict()
_snap_cache: "OrderedDict[str, tuple[float, tuple[float, dict]]]" = OrderedDict()
_lock = threading.Lock()


def _cache_key(snapshot_path: str, strict: bool, group_id: str | None,
              include_parents: bool = False) -> str:
    return f"{snapshot_path}:{strict}:{group_id or ''}:{include_parents}"


def get_matcher(snapshot_path: str, strict: bool = True,
                group_id: str | None = None,
                include_parents: bool = False) -> RuleMatcher | None:
    key = _cache_key(snapshot_path, strict, group_id, include_parents)
    with _lock:
        entry = _cache.get(key)
        if not entry:
            return None
        ts, matcher = entry
        if time.monotonic() - ts > _TTL_SECONDS:
            del _cache[key]
            return None
        _cache.move_to_end(key)
        return matcher


def set_matcher(snapshot_path: str, strict: bool, group_id: str | None,
                matcher: RuleMatcher, include_parents: bool = False):
    key = _cache_key(snapshot_path, strict, group_id, include_parents)
    with _lock:
        _cache[key] = (time.monotonic(), matcher)
        _cache.move_to_end(key)
        while len(_cache) > _MAX_ENTRIES:
            _cache.popitem(last=False)


def invalidate(snapshot_path: str):
    with _lock:
        for k in [k for k in _cache if k.startswith(snapshot_path)]:
            del _cache[k]
        _snap_cache.pop(snapshot_path, None)


def load_snapshot_dict(snapshot_path: str) -> dict:
    """Cached json.load of a snapshot (used by NAT / WhereIsUse / sidebar)."""
    with _lock:
        entry = _snap_cache.get(snapshot_path)
        if entry:
            ts, cached = entry
            if time.monotonic() - ts <= _TTL_SECONDS:
                _snap_cache.move_to_end(snapshot_path)
                return cached[1]
            del _snap_cache[snapshot_path]

    with open(snapshot_path, encoding="utf-8") as f:
        data = json.load(f)

    with _lock:
        _snap_cache[snapshot_path] = (time.monotonic(), (0.0, data))
        _snap_cache.move_to_end(snapshot_path)
        while len(_snap_cache) > _MAX_ENTRIES:
            _snap_cache.popitem(last=False)
    return data


def load_matcher(snapshot_path: str, strict: bool = True,
                 group_id: str | None = None,
                 include_parents: bool = False) -> RuleMatcher:
    """Returns cached matcher or builds from snapshot file (single or multi format).

    include_parents=True сшивает pre/post-правила всех родительских групп по
    цепочке до корня (см. core.snapshot.get_effective_group) — так матчинг
    отражает реальную эффективную политику устройства, а не только локальные
    правила выбранной группы.
    """
    m = get_matcher(snapshot_path, strict, group_id, include_parents)
    if m:
        return m

    from ..core.resolver import ObjectResolver
    from ..core.snapshot import get_effective_group
    from ..core.rules import build_rules

    snap = load_snapshot_dict(snapshot_path)

    grp       = get_effective_group(snap, group_id, include_parents=include_parents)
    net_cache = grp.get("net_groups") or {}
    svc_cache = grp.get("svc_groups") or {}
    rules     = build_rules(grp.get("rules") or [])

    resolver = ObjectResolver(
        fetch_net_group=lambda gid: net_cache.get(gid, []),
        fetch_svc_group=lambda gid: svc_cache.get(gid, []),
    )
    m = RuleMatcher(rules, resolver, strict=strict)
    set_matcher(snapshot_path, strict, group_id, m, include_parents)
    return m


# ─── shadows-анализ: in-memory job'ы для прогресса на O(n²) расчёте ──────────
# Не персистится в БД — результаты живут, пока жив процесс, этого достаточно
# для полинга прогресса и постраничной навигации по уже готовому результату.

_shadows_jobs: dict[str, dict] = {}
_shadows_lock = threading.Lock()


def create_shadows_job(job_id: str, n_rules: int, mode: str):
    with _shadows_lock:
        _shadows_jobs[job_id] = {
            "status": "running", "current": 0, "total": 0,
            "results": None, "n_rules": n_rules, "mode": mode, "error": None,
        }


def update_shadows_progress(job_id: str, current: int, total: int):
    with _shadows_lock:
        job = _shadows_jobs.get(job_id)
        if job:
            job["current"] = current
            job["total"] = total


def finish_shadows_job(job_id: str, results: list):
    with _shadows_lock:
        job = _shadows_jobs.get(job_id)
        if job:
            job["status"] = "done"
            job["results"] = results


def fail_shadows_job(job_id: str, error: str):
    with _shadows_lock:
        job = _shadows_jobs.get(job_id)
        if job:
            job["status"] = "error"
            job["error"] = error


def get_shadows_job(job_id: str) -> dict | None:
    with _shadows_lock:
        job = _shadows_jobs.get(job_id)
        return dict(job) if job else None
