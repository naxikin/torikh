"""Tamper-evident evidence log — a sha256 hash chain for forensic provenance.

Every fetched page is recorded as one JSONL line containing the body hash,
HTTP status, timestamp and the hash of the previous entry. Any later edit to
the log breaks the chain and is detected by ``EvidenceLog.verify()``.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Dict, Optional, Tuple

from .config import settings

GENESIS_HASH = "0" * 64


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _entry_hash(record: dict) -> str:
    trimmed = {key: value for key, value in record.items() if key != "entry_hash"}
    return hashlib.sha256(_canonical(trimmed).encode("utf-8")).hexdigest()


class EvidenceLog:
    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or settings.evidence_path

    def _ensure_parent(self) -> None:
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    def _read_entries(self) -> Tuple[list, Optional[str]]:
        if not os.path.isfile(self.path):
            return [], None
        entries = []
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append((line_number, json.loads(line)))
                    except ValueError:
                        return entries, "line %d is not valid JSON" % line_number
        except OSError as exc:
            return entries, "cannot read log: %s" % exc
        return entries, None

    def last_hash(self) -> str:
        entries, _ = self._read_entries()
        if not entries:
            return GENESIS_HASH
        return str(entries[-1][1].get("entry_hash") or GENESIS_HASH)

    def status(self) -> Dict[str, object]:
        entries, error = self._read_entries()
        return {
            "path": self.path,
            "entries": len(entries),
            "last_hash": self.last_hash(),
            "error": error,
        }

    def entries(self, limit: int = 50) -> list:
        """Most recent chained records, newest first (for the web UI)."""
        entries, _ = self._read_entries()
        records = [record for _, record in entries][-limit:]
        return list(reversed(records))

    def append(self, record: Dict[str, object]) -> Optional[str]:
        """Append one chained record. Returns the entry hash, or None on failure."""
        try:
            self._ensure_parent()
            entry = dict(record)
            entry.setdefault("ts", time.time())
            entry["prev"] = self.last_hash()
            entry["entry_hash"] = _entry_hash(entry)
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(_canonical(entry) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            return entry["entry_hash"]
        except OSError:
            return None

    def record_fetch(self, url: str, status: int, body: bytes,
                     title: str = "", session_tag: str = "") -> Optional[str]:
        return self.append({
            "kind": "fetch",
            "url": url,
            "status": int(status),
            "sha256": sha256_hex(body) if body else None,
            "bytes": len(body) if body else 0,
            "title": (title or "")[:200],
            "session_tag": session_tag,
            "tool_version": _tool_version(),
        })

    def verify(self) -> Dict[str, object]:
        """Walk the chain and confirm every link. Returns a verification report."""
        entries, parse_error = self._read_entries()
        if parse_error:
            return {"ok": False, "entries": len(entries), "error": parse_error,
                    "broken_at": None}
        previous = GENESIS_HASH
        for line_number, record in entries:
            stored_hash = record.get("entry_hash")
            if record.get("prev") != previous:
                return {"ok": False, "entries": len(entries),
                        "error": "chain break: prev hash mismatch at entry %d"
                                 % line_number,
                        "broken_at": line_number}
            if stored_hash != _entry_hash(record):
                return {"ok": False, "entries": len(entries),
                        "error": "entry %d was modified after it was written"
                                 % line_number,
                        "broken_at": line_number}
            previous = stored_hash
        return {"ok": True, "entries": len(entries), "error": None,
                "broken_at": None, "last_hash": previous}


def _tool_version() -> str:
    from . import __version__

    return __version__


def get_log() -> EvidenceLog:
    return EvidenceLog()
