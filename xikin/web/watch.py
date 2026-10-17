"""Watch jobs — saved queries with optional recurring runs (SQLite)."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from typing import Dict, List, Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS watch_jobs (
    id               TEXT PRIMARY KEY,
    query            TEXT NOT NULL,
    mode             TEXT NOT NULL,
    engines          TEXT NOT NULL DEFAULT '[]',
    interval_hours   REAL NOT NULL DEFAULT 0,
    enabled          INTEGER NOT NULL DEFAULT 1,
    created          REAL NOT NULL,
    last_run         REAL,
    last_status      TEXT,
    last_results     INTEGER,
    last_indicators  INTEGER,
    last_new         INTEGER,
    last_fingerprint TEXT
);
"""

_UPDATABLE = ("query", "mode", "engines", "interval_hours", "enabled",
              "last_run", "last_status", "last_results", "last_indicators",
              "last_new", "last_fingerprint")


class WatchStore:
    def __init__(self, path: str) -> None:
        self.path = os.path.expanduser(path)
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._local = threading.local()
        self._lock = threading.Lock()
        with self._lock:
            conn = self._conn()
            conn.executescript(_SCHEMA)
            conn.commit()

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, check_same_thread=False, timeout=15)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            self._local.conn = conn
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, object]:
        data = dict(row)
        try:
            data["engines"] = json.loads(data.get("engines") or "[]")
        except (TypeError, ValueError):
            data["engines"] = []
        data["enabled"] = bool(data.get("enabled"))
        return data

    def create(self, query: str, mode: str, interval_hours: float = 0.0,
               engines: Optional[List[str]] = None, enabled: bool = True) -> dict:
        job_id = uuid.uuid4().hex[:12]
        with self._lock:
            self._conn().execute(
                "INSERT INTO watch_jobs(id, query, mode, engines, interval_hours, "
                "enabled, created) VALUES(?,?,?,?,?,?,?)",
                (job_id, query, mode, json.dumps(engines or []),
                 float(interval_hours), 1 if enabled else 0, time.time()),
            )
            self._conn().commit()
        return self.get(job_id)

    def get(self, job_id: str) -> Optional[dict]:
        row = self._conn().execute(
            "SELECT * FROM watch_jobs WHERE id=?", (job_id,)).fetchone()
        return self._row(row) if row else None

    def list(self) -> List[dict]:
        rows = self._conn().execute(
            "SELECT * FROM watch_jobs ORDER BY created DESC").fetchall()
        return [self._row(row) for row in rows]

    def update(self, job_id: str, **fields) -> None:
        clean = {key: value for key, value in fields.items() if key in _UPDATABLE}
        if not clean:
            return
        if "engines" in clean and not isinstance(clean["engines"], str):
            clean["engines"] = json.dumps(clean["engines"])
        if "enabled" in clean:
            clean["enabled"] = 1 if clean["enabled"] else 0
        assignments = ", ".join("%s=?" % key for key in clean)
        values = list(clean.values()) + [job_id]
        with self._lock:
            self._conn().execute(
                "UPDATE watch_jobs SET %s WHERE id=?" % assignments, values)
            self._conn().commit()

    def delete(self, job_id: str) -> bool:
        with self._lock:
            cursor = self._conn().execute(
                "DELETE FROM watch_jobs WHERE id=?", (job_id,))
            self._conn().commit()
            return (cursor.rowcount or 0) > 0

    def due(self, now: Optional[float] = None) -> List[dict]:
        now = time.time() if now is None else now
        jobs = []
        for job in self.list():
            if not job.get("enabled") or float(job.get("interval_hours") or 0) <= 0:
                continue
            last_run = job.get("last_run")
            if last_run is None or float(last_run) + float(job["interval_hours"]) * 3600 <= now:
                jobs.append(job)
        return jobs
