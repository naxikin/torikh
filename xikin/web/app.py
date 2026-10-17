"""Xikin web platform — FastAPI application."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse,
                               RedirectResponse, Response, StreamingResponse)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import __version__, vt
from ..cache import clear_cache, get_cache
from ..config import settings
from ..engines import ENGINE_NAMES, check_search_engines
from ..evidence import get_log
from ..fetch import fetch
from ..filescan import MAX_BYTES, analyze as analyze_file
from ..iocs import (IOC_LABELS, extract as extract_iocs, mask_secret,
                    render as render_ioc_export)
from ..llm import MODES, llm_available, provider_summary
from ..safety import SAFETY_NOTE
from ..search import search_detailed
from ..textutil import utc_now_iso
from ..tor import check_tor, renew_identity, tor_port_open
from .pdf import build_dashboard_pdf
from .runs import RunManager
from .scheduler import WatchScheduler
from .state import ROLES, StateStore, verify_password
from .watch import WatchStore
from .security import (CSRF_COOKIE, SECURITY_HEADERS, SESSION_COOKIE,
                       SESSION_TTL_SECONDS, csrf_ok, is_loopback, new_csrf,
                       sign_session, verify_session)

WEB_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = WEB_DIR / "templates"
STATIC_DIR = WEB_DIR / "static"

_EXPORT_FORMATS = {
    "stix": ("application/json", "stix.json"),
    "misp": ("application/json", "misp.json"),
    "csv": ("text/csv", "iocs.csv"),
    "json": ("application/json", "iocs.json"),
}


def _engine_cache_key() -> str:
    return "check:" + ",".join(sorted(ENGINE_NAMES))


def _read_from(path: Path, offset: int):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            handle.seek(offset)
            text = handle.read()
            return text, handle.tell()
    except OSError:
        return "", offset


def _fmt_ts(value) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(float(value)))
    except (TypeError, ValueError, OSError):
        return "—"


def _alive_engine_names(limit: int = 4):
    report = get_cache().get(_engine_cache_key(), "engine",
                             settings.engine_cache_ttl)
    if report:
        alive = [row["name"] for row in report.get("results", [])
                 if row.get("status") == "up"]
        if alive:
            return alive[:limit]
    return ["Ahmia", "OnionLand", "Tor66"][:limit]


def _active_progress(manager) -> Optional[dict]:
    run_id = manager.active()
    if not run_id:
        return None
    meta = manager.meta(run_id) or {}
    progress, last_line = 0, ""
    try:
        with open(manager.events_path(run_id), "r", encoding="utf-8") as handle:
            tail = handle.readlines()[-1:]
        if tail:
            payload = json.loads(tail[0])
            progress = int(payload.get("progress") or 0)
            last_line = payload.get("line") or ""
    except (OSError, ValueError):
        pass
    return {"meta": meta, "progress": progress, "last_line": last_line}


def _activity(runs, days: int = 14):
    buckets = {}
    today = datetime.now(timezone.utc).date()
    for run in runs:
        try:
            day = datetime.fromtimestamp(float(run.get("created") or 0),
                                         tz=timezone.utc).date()
        except (TypeError, ValueError, OSError):
            continue
        buckets[day] = buckets.get(day, 0) + 1
    window = [today - timedelta(days=offset)
              for offset in range(days - 1, -1, -1)]
    peak = max((buckets.get(day, 0) for day in window), default=0) or 1
    return [{"label": day.strftime("%m-%d"), "count": buckets.get(day, 0),
             "pct": round(buckets.get(day, 0) / peak * 100)} for day in window]


def _ioc_overview(manager, limit: int = 20):
    counts = {}
    for meta in manager.list_runs(limit):
        result = manager.result(meta["id"]) or {}
        for ioc_type, items in (result.get("iocs") or {}).items():
            counts[ioc_type] = counts.get(ioc_type, 0) + len(items)
    ordered = sorted(counts.items(), key=lambda pair: pair[1], reverse=True)[:6]
    top = [{"label": IOC_LABELS.get(key, key), "count": value}
           for key, value in ordered]
    return top, sum(counts.values())


def _index_search(query: str) -> dict:
    try:
        return search_detailed(query, engines=_alive_engine_names(),
                               max_results=10, use_cache=True)
    except Exception as exc:  # noqa: BLE001 - surfaced in the UI
        return {"ok": False, "error": str(exc), "results": []}


def create_app(token: Optional[str] = None,
               runs_root: Optional[Path] = None,
               watch_db: Optional[Path] = None,
               state_db: Optional[Path] = None,
               start_scheduler: bool = True) -> FastAPI:
    """Build the FastAPI app. Overrides exist for tests."""
    token = settings.web_token if token is None else token
    state = StateStore(str(state_db or settings.web_state_db))
    if not is_loopback(settings.web_host) and not token and not state.users_exist():
        raise RuntimeError(
            "Refusing to start: XIKIN_WEB_HOST=%s is not loopback and neither "
            "XIKIN_WEB_TOKEN nor a web user is configured" % settings.web_host)

    app = FastAPI(title="Xikin", docs_url=None, redoc_url=None,
                  openapi_url=None)
    app.state.token = token
    app.state.state = state
    app.state.session_secret = settings.session_secret or state.get_secret()
    app.state.manager = RunManager(runs_root or Path(settings.web_runs_dir))
    app.state.watch = WatchStore(str(watch_db or settings.web_watch_db))
    app.state.scheduler = WatchScheduler(app.state.manager, app.state.watch)
    if start_scheduler:
        app.state.scheduler.start()

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    templates.env.filters["ts"] = _fmt_ts
    templates.env.filters["mask_secret"] = mask_secret
    templates.env.globals["IOC_LABELS"] = IOC_LABELS

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    def auth_enabled() -> bool:
        return bool(app.state.token) or state.users_exist()

    def render(request: Request, template: str, status_code: int = 200, **context):
        current_role = getattr(request.state, "role", None)
        payload = {
            "request": request,
            "csrf": getattr(request.state, "csrf", ""),
            "token_enabled": bool(request.app.state.token),
            "auth_enabled": auth_enabled(),
            "user": getattr(request.state, "user", None),
            "role": current_role,
            "can_write": current_role in ("admin", "analyst"),
            "is_admin": current_role == "admin",
            "version": __version__,
            "active": "",
            "settings": settings,
            "modes": MODES,
            "llm_ready": llm_available(),
            "provider": provider_summary(),
            "safety_note": SAFETY_NOTE,
            "generated_at": utc_now_iso(),
        }
        payload.update(context)
        return templates.TemplateResponse(
            request=request, name=template, context=payload,
            status_code=status_code)

    def check_csrf(request: Request, submitted: str = "") -> None:
        submitted = submitted or request.headers.get("X-CSRF-Token", "")
        if not csrf_ok(request.cookies.get(CSRF_COOKIE), submitted):
            raise HTTPException(status_code=400, detail="invalid CSRF token")

    def require_write(request: Request) -> None:
        if getattr(request.state, "role", None) not in ("admin", "analyst"):
            raise HTTPException(status_code=403, detail="write access required")

    def require_admin(request: Request) -> None:
        if getattr(request.state, "role", None) != "admin":
            raise HTTPException(status_code=403, detail="admin access required")

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        path = request.url.path
        public = (path in ("/login", "/healthz") or path.startswith("/static/"))
        enabled = bool(request.app.state.token) or state.users_exist()
        if enabled and not public:
            session = verify_session(request.cookies.get(SESSION_COOKIE),
                                     request.app.state.session_secret)
            valid = False
            if session and session.get("role") in ROLES:
                if session.get("user") == "admin" and request.app.state.token:
                    valid = True
                else:
                    stored = state.get_user(session["user"] or "")
                    if stored and stored["enabled"]:
                        session["role"] = stored["role"]
                        valid = True
            if not valid:
                if path.startswith(("/api/", "/partials/")):
                    return JSONResponse(
                        {"ok": False, "error": "authentication required"},
                        status_code=401)
                return RedirectResponse("/login?next=" + path, status_code=303)
            request.state.user = session["user"]
            request.state.role = session["role"]
        elif enabled:
            request.state.user = None
            request.state.role = None
        else:
            request.state.user = "local"
            request.state.role = "admin"

        csrf = request.cookies.get(CSRF_COOKIE) or new_csrf()
        request.state.csrf = csrf
        response = await call_next(request)
        if request.cookies.get(CSRF_COOKIE) != csrf:
            response.set_cookie(
                CSRF_COOKIE, csrf, httponly=True, samesite="strict",
                secure=request.url.scheme == "https", max_age=SESSION_TTL_SECONDS,
                path="/")
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        return response

    # ── auth ───────────────────────────────────────────────────────
    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request, next: str = "/"):
        if not auth_enabled():
            return RedirectResponse("/", status_code=303)
        return render(request, "login.html", next=next, error=None,
                      users_exist=state.users_exist())

    @app.post("/login")
    def login_submit(request: Request, username: str = Form(""),
                     token: str = Form(""), csrf: str = Form(""),
                     next: str = Form("/")):
        check_csrf(request, csrf)
        username = (username or "").strip()
        session_user = None
        if username:
            session_user = state.authenticate(username, token or "")
        elif request.app.state.token and hmac.compare_digest(
                token or "", request.app.state.token):
            session_user = {"username": "admin", "role": "admin"}
        if not session_user:
            return render(request, "login.html", next=next,
                          error="Invalid credentials", status_code=401,
                          users_exist=state.users_exist())
        target = next if next.startswith("/") and not next.startswith("//") else "/"
        response = RedirectResponse(target, status_code=303)
        response.set_cookie(
            SESSION_COOKIE,
            sign_session(request.app.state.session_secret,
                         session_user["username"], session_user["role"]),
            httponly=True, samesite="strict",
            secure=request.url.scheme == "https", max_age=SESSION_TTL_SECONDS,
            path="/")
        return response

    @app.post("/logout")
    def logout(request: Request, csrf: str = Form("")):
        check_csrf(request, csrf)
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    # ── users / account ────────────────────────────────────────────
    @app.get("/users", response_class=HTMLResponse)
    def users_page(request: Request, created: str = None, error: str = None):
        require_admin(request)
        return render(request, "users.html", active="users",
                      users=state.list_users(), created=created, error=error)

    @app.post("/users/create")
    def users_create(request: Request, username: str = Form(""),
                     password: str = Form(""), role: str = Form("viewer"),
                     csrf: str = Form("")):
        check_csrf(request, csrf)
        require_admin(request)
        ok = state.create_user(username, password, role)
        target = "/users?created=%s" % username if ok else "/users?error=invalid"
        return RedirectResponse(target, status_code=303)

    @app.post("/users/{username}/toggle")
    def users_toggle(request: Request, username: str, csrf: str = Form("")):
        check_csrf(request, csrf)
        require_admin(request)
        if username == getattr(request.state, "user", None):
            return RedirectResponse("/users?error=self", status_code=303)
        user = state.get_user(username)
        if not user:
            raise HTTPException(status_code=404)
        state.set_enabled(username, not user["enabled"])
        return RedirectResponse("/users", status_code=303)

    @app.post("/users/{username}/role")
    def users_role(request: Request, username: str, role: str = Form("viewer"),
                   csrf: str = Form("")):
        check_csrf(request, csrf)
        require_admin(request)
        user = state.get_user(username)
        if not user:
            raise HTTPException(status_code=404)
        if user["role"] == "admin" and role != "admin" and state.admin_count() <= 1:
            return RedirectResponse("/users?error=last_admin", status_code=303)
        state.set_role(username, role)
        return RedirectResponse("/users", status_code=303)

    @app.post("/users/{username}/delete")
    def users_delete(request: Request, username: str, csrf: str = Form("")):
        check_csrf(request, csrf)
        require_admin(request)
        if username == getattr(request.state, "user", None):
            return RedirectResponse("/users?error=self", status_code=303)
        user = state.get_user(username)
        if not user:
            raise HTTPException(status_code=404)
        if user["role"] == "admin" and state.admin_count() <= 1:
            return RedirectResponse("/users?error=last_admin", status_code=303)
        state.delete_user(username)
        return RedirectResponse("/users", status_code=303)

    @app.get("/account", response_class=HTMLResponse)
    def account_page(request: Request, changed: int = None, error: str = None):
        return render(request, "account.html", active="",
                      changed=changed, error=error,
                      legacy=bool(request.state.user == "admin"
                                  and request.app.state.token))

    @app.post("/account/password")
    def account_password(request: Request, current: str = Form(""),
                         new: str = Form(""), csrf: str = Form("")):
        check_csrf(request, csrf)
        user = getattr(request.state, "user", None)
        stored = state.get_user(user or "")
        if not stored:
            return RedirectResponse("/account?error=legacy", status_code=303)
        if not verify_password(current or "", stored["password_hash"]):
            return RedirectResponse("/account?error=invalid", status_code=303)
        if len(new or "") < 8:
            return RedirectResponse("/account?error=weak", status_code=303)
        state.set_password(user, new)
        return RedirectResponse("/account?changed=1", status_code=303)

    # ── alerts acknowledgement ─────────────────────────────────────
    @app.post("/alerts/ack")
    def alerts_ack(request: Request, key: str = Form(""),
                   signature: str = Form(""), csrf: str = Form("")):
        check_csrf(request, csrf)
        user = getattr(request.state, "user", "local") or "local"
        if key:
            state.ack_alert(user, key[:60], signature[:200])
        return RedirectResponse("/", status_code=303)

    @app.post("/alerts/reset")
    def alerts_reset(request: Request, csrf: str = Form("")):
        check_csrf(request, csrf)
        user = getattr(request.state, "user", "local") or "local"
        state.reset_acks(user)
        return RedirectResponse("/", status_code=303)

    # ── saved filters ──────────────────────────────────────────────
    @app.post("/filters/create")
    def filters_create(request: Request, name: str = Form(""),
                       q: str = Form(""), mode: str = Form(""),
                       status: str = Form(""), csrf: str = Form("")):
        check_csrf(request, csrf)
        user = getattr(request.state, "user", "local") or "local"
        job = state.create_filter(user, name, q, mode, status)
        return RedirectResponse(
            "/runs?filter_saved=1" if job else "/runs?filter_error=1",
            status_code=303)

    @app.post("/filters/{filter_id}/delete")
    def filters_delete(request: Request, filter_id: str, csrf: str = Form("")):
        check_csrf(request, csrf)
        user = getattr(request.state, "user", "local") or "local"
        state.delete_filter(filter_id, user)
        return RedirectResponse("/runs", status_code=303)

    # ── shared dashboard data ──────────────────────────────────────
    def dashboard_data(request: Request) -> dict:
        manager: RunManager = request.app.state.manager
        cache = get_cache()
        engine_report = cache.get(_engine_cache_key(), "engine",
                                  settings.engine_cache_ttl)
        runs_all = manager.list_runs(1000)
        evidence = get_log().verify()
        active = _active_progress(manager)
        ioc_top, ioc_total = _ioc_overview(manager)

        stats = {
            "runs": len(runs_all),
            "results": sum(int(run.get("results_count") or 0) for run in runs_all),
            "indicators": sum(int(run.get("indicator_count") or 0)
                              for run in runs_all),
            "evidence": evidence.get("entries", 0),
        }

        watch_jobs = request.app.state.watch.list()
        watch_enabled = sum(1 for job in watch_jobs if job.get("enabled"))
        watch_new_total = sum(int(job.get("last_new") or 0) for job in watch_jobs)
        watch_next = None
        for job in watch_jobs:
            if job.get("enabled") and float(job.get("interval_hours") or 0) > 0:
                base = job.get("last_run") or job.get("created") or time.time()
                candidate = float(base) + float(job["interval_hours"]) * 3600
                watch_next = candidate if watch_next is None \
                    else min(watch_next, candidate)
        activity = _activity(runs_all)

        failed = sum(1 for run in runs_all if run.get("status") == "error")
        alerts = []
        if not tor_port_open():
            alerts.append({"key": "tor_down", "signature": "down",
                           "level": "bad", "action": "Settings",
                           "href": "/settings",
                           "text": "Tor daemon is not listening on the SOCKS port."})
        if not evidence.get("ok"):
            alerts.append({"key": "evidence", "signature": "broken",
                           "level": "bad", "action": "Inspect",
                           "href": "/evidence",
                           "text": "Evidence chain verification failed."})
        if failed:
            alerts.append({"key": "failed_runs", "signature": str(failed),
                           "level": "warn", "action": "Review",
                           "href": "/runs",
                           "text": "%d investigation(s) ended with an error." % failed})
        if engine_report and engine_report.get("alive", 0) < engine_report.get("total", 0):
            down = engine_report["total"] - engine_report["alive"]
            alerts.append({"key": "engines_down", "signature": str(down),
                           "level": "warn", "action": "Details",
                           "href": "#engines-panel",
                           "text": "%d search engine(s) were down in the last check."
                                   % down})
        if watch_new_total:
            alerts.append({"key": "watch_new", "signature": str(watch_new_total),
                           "level": "warn", "action": "Review",
                           "href": "/watch",
                           "text": "Watch jobs found %d new result(s) in their last run."
                                   % watch_new_total})
        if not auth_enabled():
            alerts.append({"key": "auth_disabled", "signature": "disabled",
                           "level": "warn", "action": "Settings",
                           "href": "/settings",
                           "text": "Web authentication is disabled."})

        current_user = getattr(request.state, "user", "local") or "local"
        acked_count = request.app.state.state.acked_count(current_user)
        alerts = [alert for alert in alerts
                  if not request.app.state.state.is_acked(
                      current_user, alert["key"], alert["signature"])]

        return {
            "runs": manager.list_runs(6),
            "engine_report": engine_report,
            "evidence": evidence,
            "active_job": active,
            "active_run": manager.active(),
            "stats": stats,
            "alerts": alerts,
            "acked_count": acked_count,
            "ioc_top": ioc_top,
            "ioc_total": ioc_total,
            "watch_jobs": watch_jobs,
            "watch_enabled": watch_enabled,
            "watch_new_total": watch_new_total,
            "watch_next": watch_next,
            "activity": activity,
        }

    # ── pages ──────────────────────────────────────────────────────
    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        return render(request, "dashboard.html", active="dashboard",
                      **dashboard_data(request))

    @app.get("/dashboard.pdf")
    def dashboard_pdf(request: Request):
        data = dashboard_data(request)
        payload = build_dashboard_pdf(data, generated_at=utc_now_iso(),
                                      version=__version__)
        return Response(
            content=payload, media_type="application/pdf",
            headers={"Content-Disposition":
                     'attachment; filename="xikin-dashboard.pdf"'})

    @app.get("/runs", response_class=HTMLResponse)
    def runs_page(request: Request, deleted: str = None, error: str = None,
                  deleted_bulk: int = None, skipped: int = None,
                  q: str = "", mode: str = "", status: str = "",
                  filter_saved: int = None, filter_error: int = None):
        manager: RunManager = request.app.state.manager
        runs = manager.list_runs(200)
        if q:
            needle = q.lower()
            runs = [run for run in runs
                    if needle in str(run.get("query") or "").lower()]
        if mode:
            runs = [run for run in runs if run.get("mode") == mode]
        if status:
            runs = [run for run in runs if run.get("status") == status]
        user = getattr(request.state, "user", "local") or "local"
        return render(request, "runs.html", active="runs", runs=runs[:50],
                      deleted=deleted, error=error, deleted_bulk=deleted_bulk,
                      skipped=skipped, filters=state.list_filters(user),
                      q=q, mode=mode, status=status,
                      filter_saved=filter_saved, filter_error=filter_error)

    @app.get("/watch", response_class=HTMLResponse)
    def watch_page(request: Request, created: str = None, started: str = None,
                   error: str = None, deleted: str = None):
        store = request.app.state.watch
        return render(request, "watch.html", active="watch", jobs=store.list(),
                      webhook_configured=bool(settings.webhook_url),
                      created=created, started=started, error=error,
                      deleted=deleted,
                      active_run=request.app.state.manager.active())

    @app.post("/watch/create")
    def watch_create(request: Request, query: str = Form(""),
                     mode: str = Form("threat_intel"),
                     interval_hours: str = Form("0"), csrf: str = Form("")):
        check_csrf(request, csrf)
        require_write(request)
        query = (query or "").strip()
        if len(query) < 2 or mode not in MODES:
            return RedirectResponse("/watch?error=invalid", status_code=303)
        try:
            interval = float(interval_hours or 0)
        except ValueError:
            interval = 0.0
        interval = max(0.0, min(interval, 168.0))
        job = request.app.state.watch.create(query, mode, interval)
        return RedirectResponse("/watch?created=%s" % job["id"][:8],
                                status_code=303)

    @app.post("/watch/{job_id}/run")
    def watch_run_job(request: Request, job_id: str, csrf: str = Form("")):
        check_csrf(request, csrf)
        require_write(request)
        job = request.app.state.watch.get(job_id)
        if not job:
            raise HTTPException(status_code=404)
        started = request.app.state.scheduler.request_run(job)
        target = "/watch?started=%s" % job_id[:8] if started else "/watch?error=busy"
        return RedirectResponse(target, status_code=303)

    @app.post("/watch/{job_id}/toggle")
    def watch_toggle(request: Request, job_id: str, csrf: str = Form("")):
        check_csrf(request, csrf)
        require_write(request)
        job = request.app.state.watch.get(job_id)
        if not job:
            raise HTTPException(status_code=404)
        request.app.state.watch.update(job_id, enabled=not job.get("enabled"))
        return RedirectResponse("/watch", status_code=303)

    @app.post("/watch/{job_id}/delete")
    def watch_delete(request: Request, job_id: str, csrf: str = Form("")):
        check_csrf(request, csrf)
        require_write(request)
        request.app.state.watch.delete(job_id)
        return RedirectResponse("/watch?deleted=%s" % job_id[:8],
                                status_code=303)

    @app.post("/runs/bulk-delete")
    def bulk_delete(request: Request, ids: list = Form([]), csrf: str = Form("")):
        check_csrf(request, csrf)
        require_admin(request)
        manager: RunManager = request.app.state.manager
        removed = skipped = 0
        for run_id in ids:
            if not RunManager.valid_id(run_id) or not manager.meta(run_id):
                skipped += 1
                continue
            try:
                if manager.delete(run_id):
                    removed += 1
                else:
                    skipped += 1
            except RuntimeError:
                skipped += 1
        return RedirectResponse(
            "/runs?deleted_bulk=%d&skipped=%d" % (removed, skipped),
            status_code=303)

    @app.get("/new", response_class=HTMLResponse)
    def new_page(request: Request):
        return render(request, "new.html", active="new", error=None,
                      engine_names=ENGINE_NAMES,
                      active_run=request.app.state.manager.active())

    @app.post("/runs")
    def create_run(request: Request, query: str = Form(""),
                   mode: str = Form("threat_intel"),
                   engines: list = Form([]),
                   max_results: int = Form(0), scrape: int = Form(0),
                   csrf: str = Form("")):
        check_csrf(request, csrf)
        require_write(request)
        manager: RunManager = request.app.state.manager
        query = (query or "").strip()
        if len(query) < 2:
            return render(request, "new.html", active="new",
                          error="Enter an investigation query (at least 2 characters).",
                          engine_names=ENGINE_NAMES,
                          active_run=manager.active(), status_code=400)
        if mode not in MODES:
            mode = "threat_intel"
        selected = [name for name in (engines or []) if name in ENGINE_NAMES] or None
        max_results = max(0, min(int(max_results or 0), 200))
        scrape = max(0, min(int(scrape or 0), 50))
        try:
            run_id = manager.create(query, mode, selected, max_results, scrape)
        except RuntimeError as exc:
            return render(request, "new.html", active="new",
                          error=str(exc), engine_names=ENGINE_NAMES,
                          active_run=manager.active(), status_code=409)
        return RedirectResponse("/runs/" + run_id, status_code=303)

    @app.post("/runs/{run_id}/delete")
    def delete_run(request: Request, run_id: str, csrf: str = Form("")):
        check_csrf(request, csrf)
        require_admin(request)
        manager: RunManager = request.app.state.manager
        if not RunManager.valid_id(run_id) or not manager.meta(run_id):
            raise HTTPException(status_code=404)
        try:
            deleted = manager.delete(run_id)
        except RuntimeError:
            return RedirectResponse("/runs?error=running", status_code=303)
        if not deleted:
            return RedirectResponse("/runs?error=delete_failed", status_code=303)
        return RedirectResponse("/runs?deleted=%s" % run_id[:8], status_code=303)

    @app.get("/runs/{run_id}", response_class=HTMLResponse)
    def run_page(request: Request, run_id: str):
        manager: RunManager = request.app.state.manager
        if not RunManager.valid_id(run_id):
            raise HTTPException(status_code=404)
        meta = manager.meta(run_id)
        if not meta:
            raise HTTPException(status_code=404)
        result = manager.result(run_id) or {}
        iocs = result.get("iocs") or {}
        return render(request, "run.html", active="runs", run=meta,
                      result=result, iocs=iocs, ioc_labels=IOC_LABELS,
                      running=meta.get("status") in ("queued", "running"))

    @app.get("/tools", response_class=HTMLResponse)
    def tools_page(request: Request, url: str = ""):
        return render(request, "tools.html", active="tools", prefill_url=url,
                      vt_enabled=vt.enabled(), result=None, errors=[],
                      vt_result=None, index_report=None)

    @app.post("/tools/fetch", response_class=HTMLResponse)
    def tools_fetch(request: Request, url: str = Form(""),
                    enrich_vt: str = Form(""), search_indexes: str = Form(""),
                    csrf: str = Form("")):
        check_csrf(request, csrf)
        require_write(request)
        url = (url or "").strip()
        errors, result, vt_result, index_report = [], None, None, None
        if not url.startswith(("http://", "https://")):
            errors.append("URL must start with http:// or https://")
        else:
            fetched = fetch(url, extract_links=True)
            iocs = extract_iocs({url: fetched.get("text") or ""}) \
                if fetched.get("ok") else {}
            if enrich_vt and vt.enabled():
                try:
                    vt_result = vt.lookup_url(url)
                except vt.VTError as exc:
                    errors.append(str(exc))
            if search_indexes:
                index_report = _index_search(url)
            result = {"kind": "url", "url": url, "fetch": fetched, "iocs": iocs}
        return render(request, "tools.html", active="tools", prefill_url=url,
                      vt_enabled=vt.enabled(), result=result, errors=errors,
                      vt_result=vt_result, index_report=index_report)

    @app.post("/tools/file", response_class=HTMLResponse)
    async def tools_file(request: Request, file: UploadFile = File(...),
                         enrich_vt: str = Form(""),
                         search_indexes: str = Form(""),
                         csrf: str = Form("")):
        check_csrf(request, csrf)
        require_write(request)
        errors, result, vt_result, index_report = [], None, None, None
        data = await file.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            errors.append("File exceeds the %d MB limit"
                          % (MAX_BYTES // (1024 * 1024)))
        else:
            analysis = analyze_file(data, file.filename or "upload.bin")
            entry_hash = get_log().append({
                "kind": "file", "name": analysis["name"],
                "size": analysis["size"], "sha256": analysis["sha256"],
                "sha1": analysis["sha1"], "md5": analysis["md5"],
                "type": analysis["type"],
            })
            analysis["evidence_hash"] = entry_hash
            if enrich_vt and vt.enabled():
                try:
                    vt_result = vt.lookup_file(analysis["sha256"])
                except vt.VTError as exc:
                    errors.append(str(exc))
            if search_indexes:
                index_report = _index_search(analysis["sha256"])
            result = {"kind": "file", "analysis": analysis}
        return render(request, "tools.html", active="tools", prefill_url="",
                      vt_enabled=vt.enabled(), result=result, errors=errors,
                      vt_result=vt_result, index_report=index_report)

    @app.get("/evidence", response_class=HTMLResponse)
    def evidence_page(request: Request):
        log = get_log()
        return render(request, "evidence.html", active="evidence",
                      status=log.status(), verification=log.verify(),
                      entries=log.entries(60))

    @app.get("/settings", response_class=HTMLResponse)
    def settings_page(request: Request, cleared: int = None):
        cache = get_cache()
        return render(
            request, "settings.html", active="settings", cleared=cleared,
            key_state=("set" if settings.openai_api_key or
                       settings.anthropic_api_key or settings.gemini_api_key
                       else "not set"),
            evidence=get_log().status(),
            cache_path=cache.path,
            run_count=len(request.app.state.manager.list_runs(1000)),
        )

    @app.post("/settings/cache/clear")
    def settings_clear_cache(request: Request, csrf: str = Form("")):
        check_csrf(request, csrf)
        require_admin(request)
        removed = clear_cache()
        return RedirectResponse("/settings?cleared=%d" % removed, status_code=303)

    # ── partials (JS fetch) ────────────────────────────────────────
    @app.get("/partials/tor", response_class=HTMLResponse)
    def tor_partial(request: Request):
        return render(request, "partials/tor.html", tor=check_tor(),
                      renew=None)

    @app.post("/partials/tor/renew", response_class=HTMLResponse)
    def tor_renew(request: Request):
        check_csrf(request)
        require_write(request)
        result = renew_identity()
        return render(request, "partials/tor.html", tor=check_tor(),
                      renew=result)

    @app.get("/partials/engines", response_class=HTMLResponse)
    def engines_partial(request: Request):
        report = get_cache().get(_engine_cache_key(), "engine",
                                 settings.engine_cache_ttl)
        return render(request, "partials/engines.html", report=report,
                      fresh=False)

    @app.post("/partials/urlcheck", response_class=HTMLResponse)
    def urlcheck(request: Request, url: str = Form(""), csrf: str = Form("")):
        check_csrf(request, csrf)
        url = (url or "").strip()
        if not url.startswith(("http://", "https://")):
            return render(request, "partials/urlcheck.html", url=url,
                          result=None, iocs={}, error="URL must start with http:// or https://")
        fetched = fetch(url, extract_links=True, max_chars=1200,
                        use_cache=False, timeout=(8, 25))
        iocs = extract_iocs({url: fetched.get("text") or ""}) \
            if fetched.get("ok") else {}
        return render(request, "partials/urlcheck.html", url=url,
                      result=fetched, iocs=iocs, error=None,
                      ioc_total=sum(len(items) for items in iocs.values()))

    @app.post("/partials/engines/check", response_class=HTMLResponse)
    def engines_check(request: Request):
        check_csrf(request)
        report = check_search_engines(cached_minutes=0)
        return render(request, "partials/engines.html", report=report,
                      fresh=True)

    @app.post("/partials/runs/{run_id}/check", response_class=HTMLResponse)
    def check_run(request: Request, run_id: str, live: int = 0):
        check_csrf(request)
        manager: RunManager = request.app.state.manager
        meta = manager.meta(run_id)
        if not meta:
            raise HTTPException(status_code=404)
        result = manager.result(run_id) or {}

        report_path = manager.report_path(run_id)
        report = {"exists": report_path.is_file(), "bytes": 0, "sha256": None}
        if report["exists"]:
            try:
                payload = report_path.read_bytes()
                report["bytes"] = len(payload)
                report["sha256"] = hashlib.sha256(payload).hexdigest()
            except OSError:
                pass

        event_count = 0
        events_path = manager.events_path(run_id)
        if events_path.is_file():
            try:
                with open(events_path, "r", encoding="utf-8") as handle:
                    event_count = sum(1 for _ in handle)
            except OSError:
                pass

        evidence = get_log().verify()
        top_iocs = []
        for ioc_type, items in (result.get("iocs") or {}).items():
            for item in items[:2]:
                value = item["value"]
                if ioc_type == "secret":
                    value = mask_secret(value)
                top_iocs.append({"label": IOC_LABELS.get(ioc_type, ioc_type),
                                 "value": value})

        live_rows = []
        if live and meta.get("status") == "done":
            urls = [url for url in (result.get("scraped") or [])[:3] if url]
            if not urls:
                urls = [row.get("url") for row in (result.get("results") or [])[:3]
                        if row.get("url")]

            def _live(url: str) -> dict:
                fetched = fetch(url, use_cache=False, max_chars=300,
                                timeout=(8, 20))
                return {"url": url, "status": fetched.get("status"),
                        "ok": bool(fetched.get("ok")),
                        "title": fetched.get("title") or "",
                        "error": fetched.get("error")}

            if urls:
                with ThreadPoolExecutor(max_workers=3) as pool:
                    live_rows = list(pool.map(_live, urls))

        return render(request, "partials/run_check.html", run=meta,
                      result=result, report=report, event_count=event_count,
                      evidence=evidence, top_iocs=top_iocs,
                      live_rows=live_rows, live=bool(live))

    @app.get("/partials/evidence/verify", response_class=HTMLResponse)
    def evidence_verify(request: Request):
        log = get_log()
        return render(request, "partials/evidence.html",
                      verification=log.verify(), entries=log.entries(10))

    # ── run API ────────────────────────────────────────────────────
    @app.get("/api/runs/{run_id}")
    def run_json(request: Request, run_id: str):
        manager: RunManager = request.app.state.manager
        meta = manager.meta(run_id)
        if not meta:
            raise HTTPException(status_code=404)
        return {"meta": meta, "result": manager.result(run_id)}

    @app.get("/api/runs/{run_id}/events")
    def run_events(request: Request, run_id: str):
        manager: RunManager = request.app.state.manager
        if not manager.meta(run_id):
            raise HTTPException(status_code=404)
        path = manager.events_path(run_id)

        async def stream():
            offset = 0
            last_beat = time.time()
            while True:
                text, offset = await asyncio.to_thread(_read_from, path, offset)
                if text:
                    for line in text.splitlines():
                        if line.strip():
                            yield "data: " + line + "\n\n"
                    last_beat = time.time()
                meta = manager.meta(run_id) or {}
                if meta.get("status") in ("done", "error") and not text:
                    yield "event: done\ndata: {}\n\n"
                    break
                if time.time() - last_beat > 15:
                    yield ": heartbeat\n\n"
                    last_beat = time.time()
                await asyncio.sleep(0.6)

        return StreamingResponse(
            stream(), media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    # ── downloads ──────────────────────────────────────────────────
    @app.get("/runs/{run_id}/report.md")
    def download_report(run_id: str):
        manager: RunManager = app.state.manager
        path = manager.report_path(run_id)
        if not path.is_file():
            raise HTTPException(status_code=404)
        return FileResponse(path, media_type="text/markdown",
                            filename="xikin-%s.md" % run_id[:8])

    @app.get("/runs/{run_id}/export/{fmt}")
    def export_iocs(run_id: str, fmt: str):
        if fmt not in _EXPORT_FORMATS:
            raise HTTPException(status_code=404)
        result = app.state.manager.result(run_id)
        if not result:
            raise HTTPException(status_code=404)
        media_type, suffix = _EXPORT_FORMATS[fmt]
        body = render_ioc_export(result.get("iocs") or {}, fmt,
                                 query=result.get("refined_query")
                                 or result.get("query") or "xikin")
        return Response(
            content=body, media_type=media_type,
            headers={"Content-Disposition":
                     'attachment; filename="xikin-%s-%s"' % (run_id[:8], suffix)})

    # ── health ─────────────────────────────────────────────────────
    @app.get("/healthz")
    def healthz():
        return {"ok": True, "version": __version__}

    return app
