"""Tests for the tamper-evident evidence log."""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from xikin.evidence import GENESIS_HASH, EvidenceLog, sha256_hex


class TestEvidenceLog(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tempdir.name, "evidence.jsonl")
        self.log = EvidenceLog(self.path)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_append_and_verify(self):
        first = self.log.record_fetch("http://a.onion/", 200, b"<html>a</html>")
        second = self.log.record_fetch("http://b.onion/", 404, b"missing")
        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        report = self.log.verify()
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["entries"], 2)
        self.assertEqual(report["last_hash"], second)

        with open(self.path, "r", encoding="utf-8") as handle:
            lines = [json.loads(line) for line in handle if line.strip()]
        self.assertEqual(lines[0]["prev"], GENESIS_HASH)
        self.assertEqual(lines[1]["prev"], first)
        self.assertEqual(lines[0]["sha256"], sha256_hex(b"<html>a</html>"))

    def test_tampering_is_detected(self):
        self.log.record_fetch("http://a.onion/", 200, b"original")
        self.log.record_fetch("http://b.onion/", 200, b"second")
        with open(self.path, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        record = json.loads(lines[0])
        record["status"] = 500
        lines[0] = json.dumps(record, sort_keys=True, separators=(",", ":"))
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        report = self.log.verify()
        self.assertFalse(report["ok"])
        self.assertIn("modified", report["error"])

    def test_deleted_entry_breaks_chain(self):
        self.log.record_fetch("http://a.onion/", 200, b"one")
        self.log.record_fetch("http://b.onion/", 200, b"two")
        self.log.record_fetch("http://c.onion/", 200, b"three")
        with open(self.path, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        del lines[1]
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        report = self.log.verify()
        self.assertFalse(report["ok"])

    def test_empty_log_is_valid(self):
        report = self.log.verify()
        self.assertTrue(report["ok"])
        self.assertEqual(report["entries"], 0)
        self.assertEqual(self.log.last_hash(), GENESIS_HASH)

    def test_status(self):
        self.log.record_fetch("http://a.onion/", 200, b"x")
        status = self.log.status()
        self.assertEqual(status["entries"], 1)
        self.assertIsNone(status["error"])


if __name__ == "__main__":
    unittest.main()
