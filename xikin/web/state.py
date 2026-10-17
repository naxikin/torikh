"""Persistent UI state: users (RBAC), alert acknowledgements, saved filters."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
import uuid
from typing import Dict, List, Optional

ROLES = ("admin", "analyst", "viewer")
_PBKDF2_ITERATIONS = 200_000
_ACK_TTL_SECONDS = 24 * 3600

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created       REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS alert_acks (
    username  TEXT NOT NULL,
    alert_key TEXT NOT NULL,
    signature TEXT NOT NULL,
    acked     REAL NOT NULL,
    PRIMARY KEY (username, alert_key)
);
CREATE TABLE IF NOT EXISTS saved_filters (
    id       TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    name     TEXT NOT NULL,
    query    TEXT NOT NULL DEFAULT '',
    mode     TEXT NOT NULL DEFAULT '',
    status   TEXT NOT NULL DEFAULT '',
    created  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS kv (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def hash_password(password: str, iterations: int = _PBKDF2_ITERATIONS) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 bytes.fromhex(salt), iterations)
    return "pbkdf2_sha256$%d$%s$%s" % (iterations, salt, digest.hex())


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations, salt, digest = (stored or "").split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        expected = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                       bytes.fromhex(salt), int(iterations))
        return secrets.compare_digest(expected.hex(), digest)
    except (ValueError, TypeError):
        return False


class StateStore:
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

    # ── secret / sessions ──────────────────────────────────────────
    def get_secret(self) -> str:
        row = self._conn().execute(
            "SELECT value FROM kv WHERE key='session_secret'").fetchone()
        if row:
            return row["value"]
        secret = secrets.token_hex(32)
        with self._lock:
            self._conn().execute(
                "INSERT OR IGNORE INTO kv(key, value) VALUES('session_secret', ?)",
                (secret,))
            self._conn().commit()
        return self._conn().execute(
            "SELECT value FROM kv WHERE key='session_secret'").fetchone()["value"]

    # ── users ──────────────────────────────────────────────────────
    def users_exist(self) -> bool:
        row = self._conn().execute(
            "SELECT COUNT(*) AS n FROM users").fetchone()
        return bool(row and row["n"])

    def list_users(self) -> List[dict]:
        rows = self._conn().execute(
            "SELECT username, role, enabled, created FROM users "
            "ORDER BY created").fetchall()
        return [{**dict(row), "enabled": bool(row["enabled"])} for row in rows]

    def get_user(self, username: str) -> Optional[dict]:
        row = self._conn().execute(
            "SELECT username, role, enabled, created, password_hash "
            "FROM users WHERE username=?", (username,)).fetchone()
        if not row:
            return None
        data = dict(row)
        data["enabled"] = bool(data["enabled"])
        return data

    def create_user(self, username: str, password: str,
                    role: str = "viewer") -> bool:
        username = (username or "").strip()
        if not username or len(username) > 64 or role not in ROLES:
            return False
        if len(password or "") < 8:
            return False
        if self.get_user(username):
            return False
        with self._lock:
            self._conn().execute(
                "INSERT INTO users(username, password_hash, role, enabled, created) "
                "VALUES(?,?,?,1,?)",
                (username, hash_password(password), role, time.time()))
            self._conn().commit()
        return True

    def authenticate(self, username: str, password: str) -> Optional[dict]:
        user = self.get_user(username)
        if not user or not user["enabled"]:
            return None
        if not verify_password(password, user["password_hash"]):
            return None
        return {"username": user["username"], "role": user["role"]}

    def set_password(self, username: str, password: str) -> bool:
        if len(password or "") < 8:
            return False
        with self._lock:
            cursor = self._conn().execute(
                "UPDATE users SET password_hash=? WHERE username=?",
                (hash_password(password), username))
            self._conn().commit()
            return (cursor.rowcount or 0) > 0

    def set_role(self, username: str, role: str) -> bool:
        if role not in ROLES:
            return False
        with self._lock:
            cursor = self._conn().execute(
                "UPDATE users SET role=? WHERE username=?", (role, username))
            self._conn().commit()
            return (cursor.rowcount or 0) > 0

    def set_enabled(self, username: str, enabled: bool) -> bool:
        with self._lock:
            cursor = self._conn().execute(
                "UPDATE users SET enabled=? WHERE username=?",
                (1 if enabled else 0, username))
            self._conn().commit()
            return (cursor.rowcount or 0) > 0

    def delete_user(self, username: str) -> bool:
        with self._lock:
            cursor = self._conn().execute(
                "DELETE FROM users WHERE username=?", (username,))
            self._conn().execute(
                "DELETE FROM saved_filters WHERE username=?", (username,))
            self._conn().execute(
                "DELETE FROM alert_acks WHERE username=?", (username,))
            self._conn().commit()
            return (cursor.rowcount or 0) > 0

    def admin_count(self) -> int:
        row = self._conn().execute(
            "SELECT COUNT(*) AS n FROM users WHERE role='admin' AND enabled=1"
        ).fetchone()
        return int(row["n"]) if row else 0

    # ── alert acknowledgements ─────────────────────────────────────
    def ack_alert(self, username: str, key: str, signature: str) -> None:
        with self._lock:
            self._conn().execute(
                "INSERT OR REPLACE INTO alert_acks(username, alert_key, "
                "signature, acked) VALUES(?,?,?,?)",
                (username, key, signature, time.time()))
            self._conn().commit()

    def is_acked(self, username: str, key: str, signature: str,
                 ttl: int = _ACK_TTL_SECONDS) -> bool:
        row = self._conn().execute(
            "SELECT signature, acked FROM alert_acks "
            "WHERE username=? AND alert_key=?", (username, key)).fetchone()
        if not row:
            return False
        if row["signature"] != signature:
            return False
        return (time.time() - row["acked"]) < ttl

    def acked_count(self, username: str, ttl: int = _ACK_TTL_SECONDS) -> int:
        row = self._conn().execute(
            "SELECT COUNT(*) AS n FROM alert_acks WHERE username=? AND ?-acked < ?",
            (username, time.time(), ttl)).fetchone()
        return int(row["n"]) if row else 0

    def reset_acks(self, username: str) -> None:
        with self._lock:
            self._conn().execute(
                "DELETE FROM alert_acks WHERE username=?", (username,))
            self._conn().commit()

    # ── saved filters ──────────────────────────────────────────────
    def create_filter(self, username: str, name: str, query: str = "",
                      mode: str = "", status: str = "") -> Optional[dict]:
        name = (name or "").strip()[:80]
        if not name:
            return None
        filter_id = uuid.uuid4().hex[:10]
        with self._lock:
            self._conn().execute(
                "INSERT INTO saved_filters(id, username, name, query, mode, "
                "status, created) VALUES(?,?,?,?,?,?,?)",
                (filter_id, username, name, query or "", mode or "",
                 status or "", time.time()))
            self._conn().commit()
        return self.get_filter(filter_id, username)

    def get_filter(self, filter_id: str, username: str) -> Optional[dict]:
        row = self._conn().execute(
            "SELECT * FROM saved_filters WHERE id=? AND username=?",
            (filter_id, username)).fetchone()
        return dict(row) if row else None

    def list_filters(self, username: str) -> List[dict]:
        rows = self._conn().execute(
            "SELECT * FROM saved_filters WHERE username=? ORDER BY created DESC",
            (username,)).fetchall()
        return [dict(row) for row in rows]

    def delete_filter(self, filter_id: str, username: str) -> bool:
        with self._lock:
            cursor = self._conn().execute(
                "DELETE FROM saved_filters WHERE id=? AND username=?",
                (filter_id, username))
            self._conn().commit()
            return (cursor.rowcount or 0) > 0
