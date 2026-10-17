"""Run manager: queues pipeline runs, persists metadata, results and events."""
from __future__ import annotations

import json
import os
import re
import shutil
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional

from ..pipeline import run_pipeline

_STEP_RE = re.compile(r"^\[(\d+)([a-z]?)\]")
_UUID_RE = re.compile(r"^[0-9a-f]{32}$")
_MAX_STEP = 8


class RunManager:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="xikin-run")
        self._lock = threading.Lock()
        self._active: Optional[str] = None
        self._reset_stale()

    # ── storage ────────────────────────────────────────────────────
    @staticmethod
    def valid_id(run_id: str) -> bool:
        return bool(_UUID_RE.match(run_id or ""))

    def _dir(self, run_id: str) -> Path:
        if not self.valid_id(run_id):
            raise ValueError("invalid run id")
        return self.root / run_id

    @staticmethod
    def _write_json(path: Path, payload: dict) -> None:
        temp = path.with_suffix(path.suffix + ".tmp")
        temp.write_text(json.dumps(payload, ensure_ascii=False, default=str),
                        encoding="utf-8")
        os.replace(temp, path)

    def _read_json(self, path: Path) -> Optional[dict]:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def meta(self, run_id: str) -> Optional[dict]:
        try:
            return self._read_json(self._dir(run_id) / "meta.json")
        except ValueError:
            return None

    def result(self, run_id: str) -> Optional[dict]:
        try:
            return self._read_json(self._dir(run_id) / "result.json")
        except ValueError:
            return None

    def _update(self, run_id: str, **fields) -> None:
        path = self._dir(run_id) / "meta.json"
        meta = self._read_json(path) or {"id": run_id}
        meta.update(fields)
        self._write_json(path, meta)

    def _reset_stale(self) -> None:
        for entry in self.root.iterdir():
            if not entry.is_dir() or not self.valid_id(entry.name):
                continue
            meta = self._read_json(entry / "meta.json")
            if meta and meta.get("status") in ("queued", "running"):
                meta.update({"status": "error", "finished": time.time(),
                             "error": "interrupted by server restart"})
                self._write_json(entry / "meta.json", meta)

    # ── public API ─────────────────────────────────────────────────
    def active(self) -> Optional[str]:
        with self._lock:
            return self._active

    def list_runs(self, limit: int = 20) -> List[dict]:
        runs = []
        for entry in self.root.iterdir():
            if not entry.is_dir() or not self.valid_id(entry.name):
                continue
            meta = self._read_json(entry / "meta.json")
            if meta:
                runs.append(meta)
        runs.sort(key=lambda item: item.get("created", 0), reverse=True)
        return runs[:limit]

    def create(self, query: str, mode: str, engines: Optional[List[str]],
               max_results: int, scrape: int,
               watch_id: Optional[str] = None) -> str:
        with self._lock:
            if self._active:
                raise RuntimeError("another investigation is already running")
            run_id = uuid.uuid4().hex
            run_dir = self._dir(run_id)
            run_dir.mkdir(parents=True, exist_ok=True)
            self._active = run_id
        self._write_json(run_dir / "meta.json", {
            "id": run_id,
            "query": query,
            "mode": mode,
            "engines": engines or [],
            "max_results": max_results,
            "scrape": scrape,
            "status": "queued",
            "created": time.time(),
            "started": None,
            "finished": None,
            "error": None,
            "indicator_count": 0,
            "results_count": 0,
            "refined_query": "",
            "watch_id": watch_id,
        })
        self._event(run_id, "[0] Investigation queued")
        self._pool.submit(self._execute, run_id, query, mode, engines,
                          max_results, scrape)
        return run_id

    def events_path(self, run_id: str) -> Path:
        return self._dir(run_id) / "events.jsonl"

    def report_path(self, run_id: str) -> Path:
        return self._dir(run_id) / "report.md"

    def delete(self, run_id: str) -> bool:
        """Remove a finished run's artifacts. Evidence-log records are retained."""
        with self._lock:
            if self._active == run_id:
                raise RuntimeError("cannot delete a running investigation")
        try:
            run_dir = self._dir(run_id)
        except ValueError:
            return False
        if not run_dir.is_dir() or run_dir.is_symlink():
            return False
        try:
            resolved = run_dir.resolve()
        except OSError:
            return False
        if resolved.parent != self.root.resolve():
            return False
        try:
            shutil.rmtree(run_dir)
            return True
        except OSError:
            return False

    # ── worker ─────────────────────────────────────────────────────
    def _execute(self, run_id: str, query: str, mode: str,
                 engines: Optional[List[str]], max_results: int,
                 scrape: int) -> None:
        self._update(run_id, status="running", started=time.time())
        try:
            result = run_pipeline(
                query,
                mode=mode,
                max_results=max_results,
                scrape=scrape,
                engines=engines or None,
                log=lambda line: self._event(run_id, line),
            )
            if not result.get("ok"):
                raise RuntimeError(result.get("error") or "pipeline failed")

            payload = {
                "query": result.get("query"),
                "refined_query": result.get("refined_query"),
                "mode": result.get("mode"),
                "engines": result.get("engines", []),
                "results": result.get("results", []),
                "scraped": result.get("scraped", []),
                "iocs": result.get("iocs", {}),
                "indicator_count": result.get("indicator_count", 0),
                "errors": result.get("errors", []),
                "tor": result.get("tor", {}),
                "report": result.get("report", ""),
            }
            run_dir = self._dir(run_id)
            self._write_json(run_dir / "result.json", payload)
            (run_dir / "report.md").write_text(payload["report"], encoding="utf-8")
            self._update(
                run_id, status="done", finished=time.time(),
                indicator_count=payload["indicator_count"],
                results_count=len(payload["results"]),
                refined_query=payload.get("refined_query") or "",
            )
            self._event(run_id, "[done] Report ready",
                        final="done", progress=100)
        except Exception as exc:  # noqa: BLE001 - surface to the UI
            self._update(run_id, status="error", finished=time.time(),
                         error=str(exc)[:500])
            self._event(run_id, "[error] %s" % str(exc)[:300], final="error")

    def _event(self, run_id: str, line: str,
               final: Optional[str] = None, progress: Optional[int] = None) -> None:
        step = 0
        match = _STEP_RE.match(line.strip())
        if match:
            step = int(match.group(1))
            if progress is None:
                progress = min(int(step / _MAX_STEP * 100), 100)
        if final == "done" and progress is None:
            progress = 100
        record = {"ts": time.time(), "line": line, "step": step}
        if progress is not None:
            record["progress"] = progress
        if final:
            record["final"] = final
        try:
            with open(self.events_path(run_id), "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            pass
