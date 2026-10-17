"""Thread-safe SQLite store for fetch/search caches and engine health history."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import settings

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    key        TEXT NOT NULL,
    cache_type TEXT NOT NULL,
    ts         REAL NOT NULL,
    data       TEXT NOT NULL,
    PRIMARY KEY (key, cache_type)
);
CREATE TABLE IF NOT EXISTS engine_history (
    engine     TEXT NOT NULL,
    ts         REAL NOT NULL,
    status     TEXT NOT NULL,
    latency_ms INTEGER,
    error      TEXT
);
CREATE INDEX IF NOT EXISTS idx_engine_history ON engine_history(engine, ts);
"""


class Cache:
    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or settings.db_path
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._local = threading.local()
        self._lock = threading.Lock()
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, check_same_thread=False, timeout=15)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            self._local.conn = conn
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            conn = self._conn()
            conn.executescript(_SCHEMA)
            conn.commit()

    def get(self, key: str, cache_type: str, ttl: int) -> Optional[Any]:
        if ttl <= 0:
            return None
        try:
            row = self._conn().execute(
                "SELECT ts, data FROM cache WHERE key=? AND cache_type=?",
                (key, cache_type),
            ).fetchone()
        except sqlite3.Error:
            return None
        if row and (time.time() - row["ts"]) < ttl:
            try:
                return json.loads(row["data"])
            except (TypeError, ValueError):
                return None
        return None

    def set(self, key: str, cache_type: str, data: Any) -> None:
        with self._lock:
            try:
                self._conn().execute(
                    "INSERT OR REPLACE INTO cache(key, cache_type, ts, data) "
                    "VALUES(?,?,?,?)",
                    (key, cache_type, time.time(), json.dumps(data, default=str)),
                )
                self._conn().commit()
            except sqlite3.Error:
                pass

    def clear(self, cache_type: Optional[str] = None) -> int:
        with self._lock:
            try:
                if cache_type:
                    count = self._conn().execute(
                        "SELECT COUNT(*) FROM cache WHERE cache_type=?", (cache_type,)
                    ).fetchone()[0]
                    self._conn().execute(
                        "DELETE FROM cache WHERE cache_type=?", (cache_type,))
                else:
                    count = self._conn().execute(
                        "SELECT COUNT(*) FROM cache").fetchone()[0]
                    self._conn().execute("DELETE FROM cache")
                self._conn().commit()
                return int(count)
            except sqlite3.Error:
                return 0

    def prune(self) -> int:
        ttl_by_type = {
            "fetch": settings.fetch_cache_ttl,
            "search": settings.search_cache_ttl,
            "engine": settings.engine_cache_ttl,
        }
        removed = 0
        now = time.time()
        with self._lock:
            for cache_type, ttl in ttl_by_type.items():
                if ttl <= 0:
                    continue
                try:
                    cursor = self._conn().execute(
                        "DELETE FROM cache WHERE cache_type=? AND ?-ts > ?",
                        (cache_type, now, ttl),
                    )
                    removed += cursor.rowcount or 0
                except sqlite3.Error:
                    continue
            try:
                self._conn().commit()
            except sqlite3.Error:
                pass
        return removed

    def engine_record(self, engine: str, status: str,
                      latency_ms: Optional[int], error: Optional[str]) -> None:
        with self._lock:
            try:
                conn = self._conn()
                conn.execute(
                    "INSERT INTO engine_history(engine, ts, status, latency_ms, error) "
                    "VALUES(?,?,?,?,?)",
                    (engine, time.time(), status, latency_ms, error),
                )
                conn.execute(
                    "DELETE FROM engine_history WHERE engine=? AND ts NOT IN ("
                    "SELECT ts FROM engine_history WHERE engine=? ORDER BY ts DESC LIMIT 20)",
                    (engine, engine),
                )
                conn.commit()
            except sqlite3.Error:
                pass

    def engine_history(self, engine: str, limit: int = 20) -> List[Dict[str, Any]]:
        try:
            rows = self._conn().execute(
                "SELECT ts, status, latency_ms, error FROM engine_history "
                "WHERE engine=? ORDER BY ts DESC LIMIT ?",
                (engine, limit),
            ).fetchall()
        except sqlite3.Error:
            return []
        return [dict(row) for row in rows]

    def engine_reliability(self, engine: str, limit: int = 20) -> Optional[float]:
        """Laplace-smoothed up-ratio over the last `limit` checks (None if unknown)."""
        history = self.engine_history(engine, limit)
        if not history:
            return None
        up = sum(1 for row in history if row.get("status") == "up")
        return round((up + 1) / (len(history) + 2), 3)


_cache_instance: Optional[Cache] = None
_cache_lock = threading.Lock()


def get_cache() -> Cache:
    global _cache_instance
    if _cache_instance is None:
        with _cache_lock:
            if _cache_instance is None:
                _cache_instance = Cache()
    return _cache_instance


def clear_cache() -> int:
    return get_cache().clear()
