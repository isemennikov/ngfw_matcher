"""SQLite storage — devices, sync jobs, query history."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "ngfw_matcher.db"


@contextmanager
def _conn():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _conn() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            id            TEXT PRIMARY KEY,
            host          TEXT,
            name          TEXT NOT NULL,
            path          TEXT,
            snapshot_path TEXT,
            last_sync     TEXT,
            rules_count   INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS sync_jobs (
            id          TEXT PRIMARY KEY,
            device_id   TEXT NOT NULL,
            status      TEXT NOT NULL DEFAULT 'pending',
            started_at  TEXT,
            finished_at TEXT,
            error       TEXT
        );
        CREATE TABLE IF NOT EXISTS rule_hits (
            device_id  TEXT NOT NULL,
            rule_id    TEXT NOT NULL,
            name       TEXT,
            hits       INTEGER DEFAULT 0,
            enabled    INTEGER DEFAULT 1,
            synced_at  TEXT,
            PRIMARY KEY (device_id, rule_id)
        );
        """)
        # Миграции — добавляем колонки если их нет (ALTER TABLE игнорирует ошибку)
        for migration in (
            "ALTER TABLE devices ADD COLUMN host TEXT",
        ):
            try:
                con.execute(migration)
            except sqlite3.OperationalError:
                pass


# ─── devices ─────────────────────────────────────────────────────────────────

def upsert_device(id: str, name: str, path: str = "", host: str = ""):
    with _conn() as con:
        con.execute("""
            INSERT INTO devices (id, host, name, path)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                host=excluded.host, name=excluded.name, path=excluded.path
        """, (id, host, name, path))


def update_device_snapshot(id: str, snapshot_path: str,
                            last_sync: str, rules_count: int):
    with _conn() as con:
        con.execute("""
            UPDATE devices
            SET snapshot_path=?, last_sync=?, rules_count=?
            WHERE id=?
        """, (snapshot_path, last_sync, rules_count, id))


def get_device(id: str) -> dict | None:
    with _conn() as con:
        row = con.execute("SELECT * FROM devices WHERE id=?", (id,)).fetchone()
        return dict(row) if row else None


# ─── rule_hits ───────────────────────────────────────────────────────────────

def save_rule_hits(device_id: str, rows: list[dict], synced_at: str):
    with _conn() as con:
        con.execute("DELETE FROM rule_hits WHERE device_id=?", (device_id,))
        con.executemany("""
            INSERT INTO rule_hits (device_id, rule_id, name, hits, enabled, synced_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, [
            (device_id, r["rule_id"], r["name"], r["hits"],
             1 if r["enabled"] else 0, synced_at)
            for r in rows
        ])


def get_rule_hits(device_id: str, order_by_hits: bool = False) -> list[dict]:
    with _conn() as con:
        order = "hits DESC" if order_by_hits else "rowid ASC"
        rows = con.execute(f"""
            SELECT rule_id, name, hits, enabled, synced_at
            FROM rule_hits WHERE device_id=?
            ORDER BY {order}
        """, (device_id,)).fetchall()
        return [dict(r) for r in rows]


def get_hits_synced_at(device_id: str) -> str | None:
    with _conn() as con:
        row = con.execute("""
            SELECT synced_at FROM rule_hits
            WHERE device_id=? LIMIT 1
        """, (device_id,)).fetchone()
        return row["synced_at"] if row else None


def clear_devices_for_host(host: str):
    """Удаляет устройства, снапшоты и хиты только для конкретной СУ."""
    with _conn() as con:
        device_ids = [
            row[0] for row in
            con.execute("SELECT id FROM devices WHERE host=?", (host,)).fetchall()
        ]
        if device_ids:
            placeholders = ",".join("?" * len(device_ids))
            con.execute(f"DELETE FROM sync_jobs WHERE device_id IN ({placeholders})",
                        device_ids)
            con.execute(f"DELETE FROM rule_hits WHERE device_id IN ({placeholders})",
                        device_ids)
        con.execute("DELETE FROM devices WHERE host=?", (host,))


def clear_all_devices():
    """Полная очистка — используется только при disconnect."""
    with _conn() as con:
        con.execute("DELETE FROM rule_hits")
        con.execute("DELETE FROM sync_jobs")
        con.execute("DELETE FROM devices")


def get_all_devices(host: str | None = None) -> list[dict]:
    with _conn() as con:
        if host:
            rows = con.execute(
                "SELECT * FROM devices WHERE host=? ORDER BY path, name", (host,)
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM devices ORDER BY path, name"
            ).fetchall()
        return [dict(r) for r in rows]


# ─── sync jobs ────────────────────────────────────────────────────────────────

def create_sync_job(job_id: str, device_id: str, started_at: str):
    with _conn() as con:
        con.execute("""
            INSERT OR REPLACE INTO sync_jobs (id, device_id, status, started_at)
            VALUES (?, ?, 'running', ?)
        """, (job_id, device_id, started_at))


def finish_sync_job(job_id: str, finished_at: str, error: str | None = None):
    status = "error" if error else "done"
    with _conn() as con:
        con.execute("""
            UPDATE sync_jobs SET status=?, finished_at=?, error=?
            WHERE id=?
        """, (status, finished_at, error, job_id))


def get_sync_job(job_id: str) -> dict | None:
    with _conn() as con:
        row = con.execute("SELECT * FROM sync_jobs WHERE id=?",
                          (job_id,)).fetchone()
        return dict(row) if row else None


def get_latest_sync_job(device_id: str) -> dict | None:
    with _conn() as con:
        row = con.execute("""
            SELECT * FROM sync_jobs WHERE device_id=?
            ORDER BY started_at DESC LIMIT 1
        """, (device_id,)).fetchone()
        return dict(row) if row else None
