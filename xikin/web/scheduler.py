"""Scheduled watch runs and optional webhook notifications."""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from typing import Optional

import requests

from ..config import settings
from ..textutil import normalize_url
from .runs import RunManager
from .watch import WatchStore

_MAX_WAIT_SECONDS = 1800
_RETRY_DELAYS = (1, 4, 9)


def notify_webhook(payload: dict) -> bool:
    """POST the payload with retries; HMAC-SHA256 signature when a secret is set.

    Signature header format: ``X-Xikin-Signature: sha256=<hex>`` computed over
    ``"<timestamp>.<compact-json-body>"``; the timestamp is sent separately in
    ``X-Xikin-Timestamp`` so receivers can reject replays.
    """
    url = settings.webhook_url
    if not url:
        return False
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str)
    timestamp = str(int(time.time()))
    headers = {
        "Content-Type": "application/json",
        "X-Xikin-Event": str(payload.get("event", "")),
        "X-Xikin-Timestamp": timestamp,
    }
    secret = settings.webhook_secret
    if secret:
        digest = hmac.new(secret.encode("utf-8"),
                          (timestamp + "." + body).encode("utf-8"),
                          hashlib.sha256).hexdigest()
        headers["X-Xikin-Signature"] = "sha256=" + digest
    attempts = 1 + len(_RETRY_DELAYS)
    for attempt in range(attempts):
        try:
            response = requests.post(url, data=body.encode("utf-8"),
                                     headers=headers, timeout=10)
            if 200 <= response.status_code < 300:
                return True
            if response.status_code not in (429, 500, 502, 503, 504):
                return False
        except requests.RequestException:
            pass
        if attempt < attempts - 1:
            time.sleep(_RETRY_DELAYS[attempt])
    return False


class WatchScheduler:
    def __init__(self, manager: RunManager, store: WatchStore,
                 tick_seconds: int = 60) -> None:
        self.manager = manager
        self.store = store
        self.tick_seconds = tick_seconds
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="xikin-watch")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:  # noqa: BLE001 - scheduler must keep running
                pass
            self._stop.wait(self.tick_seconds)

    def tick(self) -> None:
        if self.manager.active():
            return
        for job in self.store.due():
            if self.manager.active():
                break
            self.run_job(job, trigger="schedule")

    def request_run(self, job: dict) -> bool:
        """Start a manual watch run in the background. False if a run is active."""
        if self.manager.active():
            return False
        threading.Thread(target=self.run_job, args=(job, "manual"),
                         daemon=True).start()
        return True

    def run_job(self, job: dict, trigger: str = "schedule") -> Optional[str]:
        try:
            run_id = self.manager.create(
                job["query"], job["mode"], job.get("engines") or None,
                0, 0, watch_id=job["id"])
        except RuntimeError:
            return None

        meta = {}
        deadline = time.time() + _MAX_WAIT_SECONDS
        while time.time() < deadline:
            meta = self.manager.meta(run_id) or {}
            if meta.get("status") in ("done", "error"):
                break
            time.sleep(3)

        result = self.manager.result(run_id) or {}
        previous = {normalize_url(str(value)) for value in
                    json.loads(job.get("last_fingerprint") or "[]")}
        urls = {normalize_url(str(row.get("url", "")))
                for row in (result.get("results") or [])}
        urls.discard("")
        new_urls = sorted(urls - previous) if job.get("last_run") else []
        self.store.update(
            job["id"], last_run=time.time(), last_status=meta.get("status"),
            last_results=len(result.get("results") or []),
            last_indicators=int(result.get("indicator_count") or 0),
            last_new=len(new_urls),
            last_fingerprint=json.dumps(sorted(urls)),
        )
        if new_urls:
            notify_webhook({
                "event": "watch.new_results",
                "trigger": trigger,
                "job": {"id": job["id"], "query": job["query"],
                        "mode": job["mode"]},
                "run_id": run_id,
                "new_count": len(new_urls),
                "new_urls": new_urls[:20],
                "results": len(result.get("results") or []),
                "indicators": int(result.get("indicator_count") or 0),
            })
        return run_id
