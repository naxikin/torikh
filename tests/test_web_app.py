"""HTTP tests for the web app — auth, CSRF, rendering, exports."""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from xikin.evidence import EvidenceLog
from xikin.web.app import create_app

RUN_ID = "0123456789abcdef0123456789abcdef"


def _write_run(root: Path) -> None:
    run_dir = root / RUN_ID
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "meta.json").write_text(json.dumps({
        "id": RUN_ID, "query": "acme.com leak", "mode": "corporate",
        "status": "done", "created": 1700000000, "finished": 1700000100,
        "results_count": 1, "indicator_count": 2, "refined_query": "acme.com leak",
        "engines": ["Ahmia"], "error": None,
    }), encoding="utf-8")
    (run_dir / "result.json").write_text(json.dumps({
        "query": "acme.com leak", "refined_query": "acme.com leak",
        "mode": "corporate", "engines": ["Ahmia"],
        "results": [{
            "title": "Acme leak", "url": "http://abc.onion/leak",
            "engine": "Ahmia", "score": 0.8, "corroboration": 2,
            "engines": ["Ahmia", "Tor66"],
        }],
        "scraped": ["http://abc.onion/leak"],
        "iocs": {
            "onion_url": [{"value": "http://abc.onion/leak", "count": 2,
                           "sources": ["http://abc.onion/leak"]}],
            "secret": [{"value": "AKIAFAKEFAKEFAKEFAKE", "count": 1,
                        "sources": []}],
        },
        "indicator_count": 2,
        "errors": ["Tor66: timeout"],
        "tor": {"exit_ip": "1.2.3.4"},
        "report": "# Report\n\nScraped <script>alert(1)</script> text.",
    }), encoding="utf-8")
    (run_dir / "report.md").write_text("# Report\n", encoding="utf-8")
    (run_dir / "events.jsonl").write_text("", encoding="utf-8")


class TestWebApp(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        _write_run(self.root)
        self.app = create_app(token="test-token", runs_root=self.root,
                              watch_db=self.root / "watch.db",
                              state_db=self.root / "state.db",
                              start_scheduler=False)
        self.client = TestClient(self.app, follow_redirects=False)

    def tearDown(self):
        self.temp.cleanup()

    def login(self, next_url="/"):
        page = self.client.get("/login")
        csrf = page.cookies.get("xikin_csrf")
        response = self.client.post(
            "/login",
            data={"token": "test-token", "csrf": csrf, "next": next_url},
        )
        self.assertEqual(response.status_code, 303)
        return response

    def test_healthz_is_public(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ok"])

    def test_unauthenticated_redirects(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/login?next=/")

    def test_unauthenticated_api_returns_401(self):
        response = self.client.get("/api/runs/" + RUN_ID)
        self.assertEqual(response.status_code, 401)

    def test_login_requires_csrf(self):
        response = self.client.post("/login",
                                    data={"token": "test-token", "csrf": "bad"})
        self.assertEqual(response.status_code, 400)

    def test_login_rejects_wrong_token(self):
        page = self.client.get("/login")
        csrf = page.cookies.get("xikin_csrf")
        response = self.client.post("/login", data={"token": "nope", "csrf": csrf})
        self.assertEqual(response.status_code, 401)
        self.assertIn("Invalid credentials", response.text)

    def test_login_sanitises_next(self):
        response = self.login("//evil.example")
        self.assertEqual(response.headers["location"], "/")

    def test_pages_render_after_login(self):
        self.login()
        for path, needle in (
            ("/", "Dashboard"),
            ("/new", "New investigation"),
            ("/runs", "Investigations"),
            ("/evidence", "Evidence"),
            ("/settings", "Settings"),
        ):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            self.assertIn(needle, response.text, path)
            self.assertIn("Content-Security-Policy", response.headers)
            self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])

    def test_run_page_masks_secrets_and_escapes_report(self):
        self.login()
        response = self.client.get("/runs/" + RUN_ID)
        self.assertEqual(response.status_code, 200)
        self.assertIn("acme.com leak", response.text)
        self.assertNotIn("AKIAFAKEFAKEFAKEFAKE", response.text)
        self.assertIn("AKIA", response.text)
        self.assertIn("[REDACTED]", response.text)
        self.assertNotIn("<script>alert(1)</script>", response.text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", response.text)

    def test_invalid_run_id_404(self):
        self.login()
        self.assertEqual(self.client.get("/runs/..%2F..%2Fetc").status_code, 404)
        self.assertEqual(self.client.get("/runs/not-a-uuid").status_code, 404)

    def test_export_endpoints(self):
        self.login()
        stix = self.client.get("/runs/%s/export/stix" % RUN_ID)
        self.assertEqual(stix.status_code, 200)
        self.assertEqual(stix.json()["type"], "bundle")
        csv_response = self.client.get("/runs/%s/export/csv" % RUN_ID)
        self.assertEqual(csv_response.status_code, 200)
        self.assertIn("type,value,count,sources", csv_response.text)
        report = self.client.get("/runs/%s/report.md" % RUN_ID)
        self.assertEqual(report.status_code, 200)

    def test_tools_page_renders(self):
        self.login()
        response = self.client.get("/tools?url=http://abc.onion/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Fetch URL", response.text)
        self.assertIn("Analyse file", response.text)
        self.assertIn("http://abc.onion/", response.text)

    def test_tools_fetch_rejects_invalid_scheme(self):
        self.login()
        csrf = self.client.cookies.get("xikin_csrf")
        response = self.client.post("/tools/fetch",
                                    data={"url": "ftp://x", "csrf": csrf})
        self.assertEqual(response.status_code, 200)
        self.assertIn("must start with http", response.text)

    def test_tools_file_requires_csrf(self):
        self.login()
        response = self.client.post(
            "/tools/file",
            files={"file": ("a.txt", b"hello", "text/plain")})
        self.assertEqual(response.status_code, 400)

    def test_tools_file_analysis_and_evidence(self):
        self.login()
        csrf = self.client.cookies.get("xikin_csrf")
        payload = (b"contact evil@example.com http://abc.onion/ "
                   b"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\n")
        log = EvidenceLog(str(self.root / "evidence.jsonl"))
        with patch("xikin.web.app.get_log", return_value=log):
            response = self.client.post(
                "/tools/file",
                data={"csrf": csrf},
                files={"file": ("sample.txt", payload, "text/plain")})
        self.assertEqual(response.status_code, 200)
        self.assertIn(hashlib.sha256(payload).hexdigest(), response.text)
        self.assertIn("evil@example.com", response.text)
        self.assertIn("Extracted indicators", response.text)
        self.assertEqual(log.verify()["entries"], 1)

    def test_tools_file_blocks_illegal_strings(self):
        self.login()
        csrf = self.client.cookies.get("xikin_csrf")
        payload = b"child porn collection archive"
        log = EvidenceLog(str(self.root / "evidence.log"))
        with patch("xikin.web.app.get_log", return_value=log):
            response = self.client.post(
                "/tools/file",
                data={"csrf": csrf},
                files={"file": ("bad.bin", payload, "application/octet-stream")})
        self.assertEqual(response.status_code, 200)
        self.assertIn("withheld", response.text)
        self.assertNotIn("child porn collection archive", response.text)

    def test_runs_page_has_delete_button(self):
        self.login()
        response = self.client.get("/runs")
        self.assertEqual(response.status_code, 200)
        self.assertIn("/runs/%s/delete" % RUN_ID, response.text)
        self.assertIn("Delete", response.text)

    def test_delete_run(self):
        self.login()
        csrf = self.client.cookies.get("xikin_csrf")
        response = self.client.post("/runs/%s/delete" % RUN_ID,
                                    data={"csrf": csrf})
        self.assertEqual(response.status_code, 303)
        self.assertIn("deleted=", response.headers["location"])
        self.assertFalse((self.root / RUN_ID).exists())
        listing = self.client.get(response.headers["location"])
        self.assertIn("deleted", listing.text)

    def test_delete_requires_csrf(self):
        self.login()
        response = self.client.post("/runs/%s/delete" % RUN_ID)
        self.assertEqual(response.status_code, 400)
        self.assertTrue((self.root / RUN_ID).exists())

    def test_delete_running_refused(self):
        self.login()
        csrf = self.client.cookies.get("xikin_csrf")
        self.app.state.manager._active = RUN_ID
        try:
            response = self.client.post("/runs/%s/delete" % RUN_ID,
                                        data={"csrf": csrf})
            self.assertEqual(response.status_code, 303)
            self.assertIn("error=running", response.headers["location"])
            self.assertTrue((self.root / RUN_ID).exists())
        finally:
            self.app.state.manager._active = None

    def test_dashboard_has_complete_widgets(self):
        self.login()
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        for needle in ("Quick start", "Check a URL", "Indicator overview",
                       "Export PDF", "Investigations", "Recent investigations"):
            self.assertIn(needle, response.text)
        self.assertNotIn("Recent evidence", response.text)

    def test_urlcheck_partial(self):
        self.login()
        csrf = self.client.cookies.get("xikin_csrf")

        def fake_fetch(url, **kwargs):
            return {"ok": True, "status": 200, "title": "Mock page",
                    "sha256": "ab" * 32, "bytes": 123, "links": ["http://x"],
                    "error": None}

        with patch("xikin.web.app.fetch", side_effect=fake_fetch):
            response = self.client.post("/partials/urlcheck",
                                        data={"url": "http://abc.onion/",
                                              "csrf": csrf})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Mock page", response.text)
        self.assertIn("HTTP 200", response.text)
        self.assertIn("123 bytes", response.text)
        self.assertIn("http://abc.onion/", response.text)

    def test_urlcheck_rejects_bad_scheme(self):
        self.login()
        csrf = self.client.cookies.get("xikin_csrf")
        response = self.client.post("/partials/urlcheck",
                                    data={"url": "file:///etc/passwd",
                                          "csrf": csrf})
        self.assertEqual(response.status_code, 200)
        self.assertIn("must start with http", response.text)

    def test_urlcheck_requires_csrf(self):
        self.login()
        response = self.client.post("/partials/urlcheck",
                                    data={"url": "http://abc.onion/"})
        self.assertEqual(response.status_code, 400)

    def test_ioc_overview(self):
        from xikin.web.app import _ioc_overview

        top, total = _ioc_overview(self.app.state.manager)
        self.assertEqual(total, 2)
        labels = {item["label"] for item in top}
        self.assertIn("Onion URLs", labels)

    def test_watch_create_toggle_delete(self):
        self.login()
        csrf = self.client.cookies.get("xikin_csrf")
        created = self.client.post("/watch/create",
                                   data={"query": "acme leak", "mode": "corporate",
                                         "interval_hours": "0", "csrf": csrf})
        self.assertEqual(created.status_code, 303)
        self.assertIn("/watch?created=", created.headers["location"])
        jobs = self.app.state.watch.list()
        self.assertEqual(len(jobs), 1)
        job_id = jobs[0]["id"]

        page = self.client.get("/watch")
        self.assertIn("acme leak", page.text)

        toggled = self.client.post("/watch/%s/toggle" % job_id,
                                   data={"csrf": csrf})
        self.assertEqual(toggled.status_code, 303)
        self.assertFalse(self.app.state.watch.get(job_id)["enabled"])

        deleted = self.client.post("/watch/%s/delete" % job_id,
                                   data={"csrf": csrf})
        self.assertEqual(deleted.status_code, 303)
        self.assertIsNone(self.app.state.watch.get(job_id))

    def test_watch_create_requires_csrf(self):
        self.login()
        response = self.client.post("/watch/create",
                                    data={"query": "acme leak",
                                          "mode": "threat_intel"})
        self.assertEqual(response.status_code, 400)

    def test_watch_run_uses_scheduler(self):
        self.login()
        csrf = self.client.cookies.get("xikin_csrf")
        job = self.app.state.watch.create("acme leak", "corporate", 0)
        with patch.object(self.app.state.scheduler, "request_run",
                          return_value=True) as request_run:
            response = self.client.post("/watch/%s/run" % job["id"],
                                        data={"csrf": csrf})
        self.assertEqual(response.status_code, 303)
        self.assertIn("started=", response.headers["location"])
        request_run.assert_called_once()
        with patch.object(self.app.state.scheduler, "request_run",
                          return_value=False):
            busy = self.client.post("/watch/%s/run" % job["id"],
                                    data={"csrf": csrf})
        self.assertIn("error=busy", busy.headers["location"])

    def test_bulk_delete(self):
        self.login()
        csrf = self.client.cookies.get("xikin_csrf")
        other = "b" * 32
        other_dir = self.root / other
        other_dir.mkdir()
        (other_dir / "meta.json").write_text(json.dumps({
            "id": other, "query": "second", "mode": "threat_intel",
            "status": "done", "created": 1700000000}), encoding="utf-8")
        response = self.client.post(
            "/runs/bulk-delete",
            data={"ids": [RUN_ID, other, "not-a-uuid"], "csrf": csrf})
        self.assertEqual(response.status_code, 303)
        self.assertIn("deleted_bulk=2", response.headers["location"])
        self.assertIn("skipped=1", response.headers["location"])
        self.assertFalse((self.root / RUN_ID).exists())
        self.assertFalse(other_dir.exists())

    def test_activity_helper(self):
        import time
        from xikin.web.app import _activity

        activity = _activity([{"created": time.time()}])
        self.assertEqual(len(activity), 14)
        self.assertEqual(activity[-1]["count"], 1)

    def test_dashboard_monitoring_and_activity(self):
        self.login()
        response = self.client.get("/")
        self.assertIn("Monitoring", response.text)
        self.assertIn("Activity", response.text)

    def _logout(self):
        csrf = self.client.cookies.get("xikin_csrf")
        return self.client.post("/logout", data={"csrf": csrf})

    def _login_user(self, username, password):
        page = self.client.get("/login")
        csrf = page.cookies.get("xikin_csrf") or self.client.cookies.get("xikin_csrf")
        return self.client.post("/login", data={"username": username,
                                                "token": password,
                                                "csrf": csrf, "next": "/"})

    def test_users_page_admin_only_and_create(self):
        self.login()
        page = self.client.get("/users")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Add user", page.text)
        csrf = self.client.cookies.get("xikin_csrf")
        created = self.client.post("/users/create",
                                   data={"username": "viewer1",
                                         "password": "viewerpass1",
                                         "role": "viewer", "csrf": csrf})
        self.assertEqual(created.status_code, 303)
        self.assertIn("created=viewer1", created.headers["location"])
        self.assertEqual(self.app.state.state.get_user("viewer1")["role"], "viewer")

    def test_viewer_is_read_only(self):
        self.login()
        csrf = self.client.cookies.get("xikin_csrf")
        self.client.post("/users/create", data={
            "username": "viewer2", "password": "viewerpass2",
            "role": "viewer", "csrf": csrf})
        self._logout()
        response = self._login_user("viewer2", "viewerpass2")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.client.get("/").status_code, 200)
        denied = self.client.post("/runs", data={
            "query": "acme leak", "mode": "threat_intel", "csrf": csrf})
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(self.client.get("/users").status_code, 403)
        delete = self.client.post("/runs/%s/delete" % RUN_ID,
                                  data={"csrf": csrf})
        self.assertEqual(delete.status_code, 403)
        self.assertEqual(self.client.post("/settings/cache/clear",
                                          data={"csrf": csrf}).status_code, 403)

    def test_analyst_can_ack_and_save_filters(self):
        self.login()
        csrf = self.client.cookies.get("xikin_csrf")
        self.client.post("/users/create", data={
            "username": "analyst1", "password": "analystpass1",
            "role": "analyst", "csrf": csrf})
        self._logout()
        self._login_user("analyst1", "analystpass1")
        ack = self.client.post("/alerts/ack", data={
            "key": "tor_down", "signature": "down", "csrf": csrf})
        self.assertEqual(ack.status_code, 303)
        saved = self.client.post("/filters/create", data={
            "name": "Acme", "q": "acme", "mode": "", "status": "",
            "csrf": csrf})
        self.assertEqual(saved.status_code, 303)
        page = self.client.get("/runs?q=acme")
        self.assertIn("Acme", page.text)
        self.assertIn("acme.com leak", page.text)

    def test_alert_acknowledge_hides_alert(self):
        self.login()
        csrf = self.client.cookies.get("xikin_csrf")
        with patch("xikin.web.app.tor_port_open", return_value=False):
            before = self.client.get("/")
            self.assertIn("Tor daemon is not listening", before.text)
            ack = self.client.post("/alerts/ack", data={
                "key": "tor_down", "signature": "down", "csrf": csrf})
            self.assertEqual(ack.status_code, 303)
            after = self.client.get("/")
        self.assertNotIn("Tor daemon is not listening", after.text)
        self.assertIn("acknowledged", after.text)

    def test_saved_filter_delete(self):
        self.login()
        csrf = self.client.cookies.get("xikin_csrf")
        self.client.post("/filters/create", data={
            "name": "Corp", "q": "acme", "mode": "corporate",
            "status": "done", "csrf": csrf})
        saved = self.app.state.state.list_filters("admin")
        self.assertEqual(len(saved), 1)
        deleted = self.client.post("/filters/%s/delete" % saved[0]["id"],
                                   data={"csrf": csrf})
        self.assertEqual(deleted.status_code, 303)
        self.assertEqual(self.app.state.state.list_filters("admin"), [])

    def test_dashboard_pdf_export(self):
        self.login()
        response = self.client.get("/dashboard.pdf")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/pdf")
        self.assertTrue(response.content.startswith(b"%PDF"))

    def test_login_page_has_username_field(self):
        page = self.client.get("/login")
        self.assertIn('name="username"', page.text)

    def test_check_run_partial(self):
        self.login()
        csrf = self.client.cookies.get("xikin_csrf")
        response = self.client.post("/partials/runs/%s/check" % RUN_ID,
                                    headers={"X-CSRF-Token": csrf})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Artifacts", response.text)
        self.assertIn("verified", response.text)
        self.assertIn("Top indicators", response.text)
        self.assertIn("http://abc.onion/leak", response.text)
        self.assertIn("Report SHA-256", response.text)

    def test_check_requires_csrf(self):
        self.login()
        response = self.client.post("/partials/runs/%s/check" % RUN_ID)
        self.assertEqual(response.status_code, 400)

    def test_check_live_recheck(self):
        self.login()
        csrf = self.client.cookies.get("xikin_csrf")

        def fake_fetch(url, **kwargs):
            return {"ok": True, "status": 200, "title": "Mock page",
                    "error": None}

        with patch("xikin.web.app.fetch", side_effect=fake_fetch):
            response = self.client.post(
                "/partials/runs/%s/check?live=1" % RUN_ID,
                headers={"X-CSRF-Token": csrf})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Live re-check", response.text)
        self.assertIn("Mock page", response.text)

    def test_dashboard_shows_check_button(self):
        self.login()
        response = self.client.get("/")
        self.assertIn('data-action="check-run"', response.text)
        self.assertIn('id="run-check-panel"', response.text)

    def test_delete_missing_returns_404(self):
        self.login()
        csrf = self.client.cookies.get("xikin_csrf")
        response = self.client.post("/runs/%s/delete" % ("b" * 32),
                                    data={"csrf": csrf})
        self.assertEqual(response.status_code, 404)

    def test_logout_clears_session(self):
        self.login()
        csrf = self.client.cookies.get("xikin_csrf")
        response = self.client.post("/logout", data={"csrf": csrf})
        self.assertEqual(response.status_code, 303)
        after = self.client.get("/")
        self.assertEqual(after.status_code, 303)


if __name__ == "__main__":
    unittest.main()
