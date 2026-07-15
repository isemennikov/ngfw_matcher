"""Process-level cache: matchers keyed by snapshot path + group_id + include_parents."""
from __future__ import annotations

import threading

from ..core.matcher import RuleMatcher

_cache: dict[str, RuleMatcher] = {}


def _cache_key(snapshot_path: str, strict: bool, group_id: str | None,
              include_parents: bool = False) -> str:
    return f"{snapshot_path}:{strict}:{group_id or ''}:{include_parents}"


def get_matcher(snapshot_path: str, strict: bool = True,
                group_id: str | None = None,
                include_parents: bool = False) -> RuleMatcher | None:
    return _cache.get(_cache_key(snapshot_path, strict, group_id, include_parents))


def set_matcher(snapshot_path: str, strict: bool, group_id: str | None,
                matcher: RuleMatcher, include_parents: bool = False):
    _cache[_cache_key(snapshot_path, strict, group_id, include_parents)] = matcher


def invalidate(snapshot_path: str):
    for k in list(_cache):
        if k.startswith(snapshot_path):
            del _cache[k]


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

    import json
    from ..core.resolver import ObjectResolver
    from ..core.snapshot import get_effective_group
    from ..cli.builder import _build_rules

    with open(snapshot_path, encoding="utf-8") as f:
        snap = json.load(f)

    grp       = get_effective_group(snap, group_id, include_parents=include_parents)
    net_cache = grp.get("net_groups") or {}
    svc_cache = grp.get("svc_groups") or {}
    rules     = _build_rules(grp.get("rules") or [])

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
