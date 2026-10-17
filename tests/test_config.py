"""Tests for .env fallback parsing and settings loading."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from xikin.config import Settings, _parse_env_file


class TestConfig(unittest.TestCase):
    def test_parse_env_file_fallback(self):
        with tempfile.TemporaryDirectory() as temp:
            env_file = Path(temp) / ".env"
            env_file.write_text(
                "# comment\n\nTOR_SOCKS_PORT=9999\nQUOTED='value with spaces'\n",
                encoding="utf-8",
            )
            os.environ.pop("TOR_SOCKS_PORT", None)
            os.environ.pop("QUOTED", None)
            try:
                _parse_env_file(env_file)
                self.assertEqual(os.environ.get("TOR_SOCKS_PORT"), "9999")
                self.assertEqual(os.environ.get("QUOTED"), "value with spaces")
            finally:
                os.environ.pop("TOR_SOCKS_PORT", None)
                os.environ.pop("QUOTED", None)

    def test_settings_defaults(self):
        settings = Settings.from_env()
        self.assertEqual(settings.tor_socks_port, 9050)
        self.assertTrue(settings.db_path)
        self.assertGreater(settings.tor_timeout, 0)


if __name__ == "__main__":
    unittest.main()
