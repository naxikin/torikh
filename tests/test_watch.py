"""Tests for the watch-job store and scheduler helpers."""
from __future__ import annotations

import hashlib
import hmac
import os
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from xikin.web.scheduler import WatchScheduler, notify_webhook
from xikin.web.watch import WatchStore


class TestWatchStore(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = WatchStore(os.path.join(self.temp.name, "watch.db"))

    def tearDown(self):
        self.temp.cleanup()

    def test_crud(self):
        job = self.store.create("acme leak", "corporate", 6, ["Ahmia"])
        self.assertEqual(len(job["id"]), 12)
        self.assertTrue(job["enabled"])
        self.assertEqual(job["engines"], ["Ahmia"])
        self.assertEqual(len(self.store.list()), 1)

        self.store.update(job["id"], enabled=False)
        self.assertFalse(self.store.get(job["id"])["enabled"])
        self.assertTrue(self.store.delete(job["id"]))
        self.assertIsNone(self.store.get(job["id"]))
        self.assertFalse(self.store.delete(job["id"]))

    def test_due_logic(self):
        manual = self.store.create("manual query", "threat_intel", 0)
        scheduled = self.store.create("scheduled", "threat_intel", 1)
        due_ids = {job["id"] for job in self.store.due()}
        self.assertIn(scheduled["id"], due_ids)
        self.assertNotIn(manual["id"], due_ids)

        self.store.update(scheduled["id"], last_run=time.time())
        self.assertNotIn(scheduled["id"], {j["id"] for j in self.store.due()})
        future = time.time() + 3601
        self.assertIn(scheduled["id"], {j["id"] for j in self.store.due(future)})

        self.store.update(scheduled["id"], enabled=False)
        self.assertNotIn(scheduled["id"], {j["id"] for j in self.store.due(future)})


class _FakeManager:
    def __init__(self, result):
        self._result = result

    def active(self):
        return None

    def create(self, *args, **kwargs):
        return "run-1"

    def meta(self, run_id):
        return {"status": "done"}

    def result(self, run_id):
        return self._result


class _FakeStore:
    def __init__(self):
        self.updated = None

    def update(self, job_id, **fields):
        self.updated = (job_id, fields)


class TestScheduler(unittest.TestCase):
    def _job(self, last_run=None):
        return {"id": "job-1", "query": "acme leak", "mode": "corporate",
                "engines": [], "last_run": last_run, "last_fingerprint": "[]"}

    def test_first_run_is_baseline(self):
        store = _FakeStore()
        scheduler = WatchScheduler(
            _FakeManager({"results": [{"url": "http://a.onion/x"}],
                          "indicator_count": 2}), store)
        self.assertEqual(scheduler.run_job(self._job()), "run-1")
        job_id, fields = store.updated
        self.assertEqual(job_id, "job-1")
        self.assertEqual(fields["last_new"], 0)
        self.assertIn("a.onion", fields["last_fingerprint"])
        self.assertEqual(fields["last_indicators"], 2)

    def test_second_run_detects_new_urls(self):
        store = _FakeStore()
        scheduler = WatchScheduler(
            _FakeManager({"results": [{"url": "http://new.onion/"},
                                      {"url": "http://old.onion/"}],
                          "indicator_count": 0}), store)
        job = self._job(last_run=time.time())
        job["last_fingerprint"] = '["http://old.onion/"]'
        with patch("xikin.web.scheduler.notify_webhook") as notify:
            scheduler.run_job(job)
        _, fields = store.updated
        self.assertEqual(fields["last_new"], 1)
        notify.assert_called_once()

    def test_notify_webhook_retries(self):
        import requests as requests_module

        with patch("xikin.web.scheduler.settings",
                   SimpleNamespace(webhook_url="http://hooks.local/x",
                                   webhook_secret=None)):
            with patch("xikin.web.scheduler.time.sleep"):
                with patch("xikin.web.scheduler.requests.post") as post:
                    post.side_effect = [SimpleNamespace(status_code=500),
                                        SimpleNamespace(status_code=204)]
                    self.assertTrue(notify_webhook({"event": "test"}))
                    self.assertEqual(post.call_count, 2)
                with patch("xikin.web.scheduler.requests.post",
                           side_effect=requests_module.RequestException):
                    self.assertFalse(notify_webhook({"event": "test"}))

    def test_webhook_signature(self):
        captured = {}

        def fake_post(url, data=None, headers=None, timeout=None):
            captured["data"] = data
            captured["headers"] = headers
            return SimpleNamespace(status_code=204)

        with patch("xikin.web.scheduler.settings",
                   SimpleNamespace(webhook_url="http://hooks.local/x",
                                   webhook_secret="topsecret")):
            with patch("xikin.web.scheduler.requests.post",
                       side_effect=fake_post):
                self.assertTrue(notify_webhook({"event": "watch.new_results"}))
        timestamp = captured["headers"]["X-Xikin-Timestamp"]
        body = captured["data"].decode("utf-8")
        expected = hmac.new(b"topsecret", (timestamp + "." + body).encode(),
                            hashlib.sha256).hexdigest()
        self.assertEqual(captured["headers"]["X-Xikin-Signature"],
                         "sha256=" + expected)

    def test_notify_disabled_without_url(self):
        with patch("xikin.web.scheduler.settings",
                   SimpleNamespace(webhook_url=None, webhook_secret=None)):
            self.assertFalse(notify_webhook({"event": "test"}))


if __name__ == "__main__":
    unittest.main()
