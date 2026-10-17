"""Tests for VirusTotal helpers (no network calls)."""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from xikin import vt
from xikin.vt import VTError, _summarize, url_id


class TestVtHelpers(unittest.TestCase):
    def test_url_id_is_unpadded_base64url(self):
        self.assertEqual(url_id("http://a.com/"), "aHR0cDovL2EuY29tLw")
        self.assertNotIn("=", url_id("http://example.com/path?q=1"))

    def test_summarize(self):
        summary = _summarize({
            "last_analysis_stats": {"malicious": 3, "suspicious": 1,
                                    "undetected": 5, "harmless": 2},
            "reputation": -10,
            "type_description": "PE32 executable",
            "names": ["a.exe", "b.exe"],
            "tags": ["pe", "exe"],
            "last_analysis_date": 1700000000,
            "categories": {"engine": "malware"},
        })
        self.assertTrue(summary["found"])
        self.assertEqual(summary["malicious"], 3)
        self.assertEqual(summary["suspicious"], 1)
        self.assertEqual(summary["type_description"], "PE32 executable")
        self.assertEqual(summary["names"], ["a.exe", "b.exe"])
        self.assertIn("2023-11-14", summary["last_analysis"])

    def test_disabled_without_key(self):
        with patch.object(vt, "settings", SimpleNamespace(vt_api_key=None)):
            self.assertFalse(vt.enabled())
            with self.assertRaises(VTError):
                vt.lookup_file("a" * 64)
            with self.assertRaises(VTError):
                vt.lookup_url("http://example.com/")


if __name__ == "__main__":
    unittest.main()
