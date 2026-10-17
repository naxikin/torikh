"""Tests for static file analysis (no execution, no disk writes)."""
from __future__ import annotations

import hashlib
import unittest
from unittest.mock import patch

from xikin.filescan import MAX_BYTES, analyze, detect_type, shannon_entropy

ONION = ("a" * 56) + ".onion"
SAMPLE = (("contact evil@example.com http://%s/ " % ONION).encode()
          + b"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\n")


class TestFileScan(unittest.TestCase):
    def test_text_analysis(self):
        result = analyze(SAMPLE, "sample.txt")
        self.assertEqual(result["type"], "text")
        self.assertEqual(result["sha256"], hashlib.sha256(SAMPLE).hexdigest())
        self.assertEqual(result["size"], len(SAMPLE))
        self.assertFalse(result["blocked"])
        self.assertIn("evil@example.com", result["strings_preview"])
        self.assertIn("email", result["iocs"])
        self.assertIn("onion_url", result["iocs"])
        self.assertIn("btc", result["iocs"])

    def test_pe_magic(self):
        result = analyze(b"MZ" + b"\x00" * 200, "sample.exe")
        self.assertEqual(result["type"], "PE executable")

    def test_blocked_strings_are_withheld(self):
        result = analyze(b"child porn collection archive", "bad.bin")
        self.assertTrue(result["blocked"])
        self.assertEqual(result["strings_preview"], "")
        self.assertEqual(result["iocs"], {})

    def test_entropy(self):
        self.assertEqual(shannon_entropy(b"\x00" * 1024), 0.0)
        self.assertEqual(shannon_entropy(bytes(range(256)) * 4), 8.0)

    def test_detect_binary(self):
        self.assertEqual(detect_type(b"\x00\x01\x02\x03" * 100), "binary")

    def test_size_limit(self):
        with patch("xikin.filescan.MAX_BYTES", 10):
            with self.assertRaises(ValueError):
                analyze(b"x" * 11)


if __name__ == "__main__":
    unittest.main()
