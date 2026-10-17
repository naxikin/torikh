"""Tests for web security helpers."""
from __future__ import annotations

import unittest

from xikin.web.security import (csrf_ok, is_loopback, new_csrf,
                                sign_session, verify_session)
from xikin.web.runs import RunManager


class TestSession(unittest.TestCase):
    def test_roundtrip_with_role(self):
        cookie = sign_session("s3cret", "alice", "analyst")
        session = verify_session(cookie, "s3cret")
        self.assertEqual(session["user"], "alice")
        self.assertEqual(session["role"], "analyst")

    def test_wrong_secret_rejected(self):
        cookie = sign_session("right", "alice", "viewer")
        self.assertIsNone(verify_session(cookie, "wrong"))

    def test_tampered_cookie_rejected(self):
        cookie = sign_session("secret", "alice", "viewer")
        payload, signature = cookie.split(".", 1)
        tampered = payload[:-2] + ("aa" if payload[-2:] != "aa" else "bb") + "." + signature
        self.assertIsNone(verify_session(tampered, "secret"))

    def test_expired_rejected(self):
        cookie = sign_session("secret", "alice", "viewer", ttl=-10)
        self.assertIsNone(verify_session(cookie, "secret"))

    def test_missing_values(self):
        self.assertIsNone(verify_session(None, "secret"))
        self.assertIsNone(verify_session("abc", None))


class TestCsrf(unittest.TestCase):
    def test_match(self):
        token = new_csrf()
        self.assertTrue(csrf_ok(token, token))

    def test_mismatch(self):
        self.assertFalse(csrf_ok("a", "b"))
        self.assertFalse(csrf_ok(None, "b"))
        self.assertFalse(csrf_ok("a", None))


class TestHelpers(unittest.TestCase):
    def test_loopback(self):
        for host in ("127.0.0.1", "localhost", "::1"):
            self.assertTrue(is_loopback(host))
        for host in ("0.0.0.0", "10.0.0.5", "example.com"):
            self.assertFalse(is_loopback(host))

    def test_run_id_validation(self):
        self.assertTrue(RunManager.valid_id("a" * 32))
        self.assertFalse(RunManager.valid_id("../../etc/passwd"))
        self.assertFalse(RunManager.valid_id("A" * 32))
        self.assertFalse(RunManager.valid_id("a" * 31))


if __name__ == "__main__":
    unittest.main()
