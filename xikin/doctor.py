"""Security preflight — Tor health, DNS-leak checks, isolation, evidence chain."""
from __future__ import annotations

import os
import socket
from typing import Dict, List, Optional

from .cache import get_cache
from .config import settings
from .evidence import get_log
from .llm import llm_available, provider_summary
from .safety import SAFETY_NOTE
from .tor import check_tor, tor_port_open

_CANARY_ONION = ("abcdefghijklmnop" * 3) + "abcdefgh" + ".onion"

_TORRC_CANDIDATES = (
    "/etc/xikin/torrc",
    "/tmp/xikin_torrc",
    "/opt/homebrew/etc/tor/torrc",
    "/usr/local/etc/tor/torrc",
    "/etc/tor/torrc",
    os.path.expanduser("~/.tor/torrc"),
)

_PROXY_ENV_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                   "http_proxy", "https_proxy", "all_proxy")


def _check(name: str, status: str, detail: str) -> Dict[str, str]:
    return {"name": name, "status": status, "detail": detail}


def check_socks_port() -> Dict[str, str]:
    if tor_port_open():
        return _check("tor.socks_port", "ok",
                      "%s:%d accepts connections"
                      % (settings.tor_socks_host, settings.tor_socks_port))
    return _check("tor.socks_port", "fail",
                  "no listener on %s:%d — start Tor"
                  % (settings.tor_socks_host, settings.tor_socks_port))


def check_identity() -> Dict[str, str]:
    status = check_tor()
    if status.get("tor_active") and status.get("is_tor"):
        return _check("tor.identity", "ok", "exit IP %s confirmed as Tor"
                      % status.get("exit_ip"))
    if status.get("tor_active"):
        return _check("tor.identity", "warn",
                      "exit IP %s not confirmed as a Tor node" % status.get("exit_ip"))
    return _check("tor.identity", "fail", str(status.get("error")))


def check_onion_dns() -> Dict[str, str]:
    """A .onion name must NOT resolve locally — if it does, DNS is leaking."""
    try:
        socket.getaddrinfo(_CANARY_ONION, 80)
    except (socket.gaierror, UnicodeError) as exc:
        return _check("leak.onion_dns", "ok",
                      "canary .onion does not resolve locally (remote DNS intact)")
    except OSError as exc:
        return _check("leak.onion_dns", "ok", "local resolution failed as expected (%s)" % exc)
    return _check("leak.onion_dns", "fail",
                  "a .onion name resolved through the local resolver — DNS leak risk")


def check_proxy_env() -> Dict[str, str]:
    found = [name for name in _PROXY_ENV_VARS if os.environ.get(name)]
    if found:
        return _check("leak.proxy_env", "warn",
                      "proxy env vars set (%s) — xikin pins its own SOCKS proxy, "
                      "but other tools may route around Tor" % ", ".join(sorted(set(
                          name.lower() for name in found))))
    return _check("leak.proxy_env", "ok", "no ambient proxy environment variables")


def check_control_port() -> Dict[str, str]:
    try:
        from stem.control import Controller
    except ImportError:
        return _check("tor.control_port", "warn",
                      "stem not installed — renew.py unavailable")
    try:
        with Controller.from_port(address=settings.tor_control_host,
                                  port=settings.tor_control_port) as controller:
            try:
                controller.authenticate()
            except Exception:
                from .tor import _read_cookie

                cookie = _read_cookie()
                if cookie is None:
                    raise
                controller.authenticate(cookie=cookie)
            version = controller.get_info("version", "unknown")
            circuits = controller.get_info("circuit-status", "")
            established = sum(1 for line in circuits.splitlines()
                              if " BUILT " in line or line.startswith("BUILT "))
            return _check("tor.control_port", "ok",
                          "%s — %d circuits built" % (version, established))
    except Exception as exc:
        return _check("tor.control_port", "warn",
                      "cannot authenticate (%s) — renew.py will not work" % str(exc)[:80])


def check_isolation() -> Dict[str, str]:
    if not settings.isolate_circuits:
        return _check("privacy.isolation", "warn",
                      "circuit isolation disabled (XIKIN_ISOLATE=0)")
    existing = []
    for path in _TORRC_CANDIDATES:
        if not os.path.isfile(path):
            continue
        existing.append(path)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                content = handle.read()
        except OSError:
            continue
        if "IsolateSOCKSAuth" in content:
            return _check("privacy.isolation", "ok",
                          "IsolateSOCKSAuth found in %s — per-query circuits enforced"
                          % path)
    if existing:
        return _check("privacy.isolation", "warn",
                      "IsolateSOCKSAuth missing in %s — isolation credentials are "
                      "ignored by Tor" % ", ".join(existing[:2]))
    return _check("privacy.isolation", "warn",
                  "no torrc found to verify IsolateSOCKSAuth — add it to SocksPort")


def check_cache() -> Dict[str, str]:
    try:
        cache = get_cache()
        cache.set("doctor-probe", "fetch", {"ok": True})
        probe = cache.get("doctor-probe", "fetch", 60)
        if probe:
            return _check("storage.cache", "ok", "SQLite cache writable (%s)" % cache.path)
        return _check("storage.cache", "warn", "cache write did not read back")
    except Exception as exc:
        return _check("storage.cache", "fail", "cache unavailable: %s" % str(exc)[:80])


def check_evidence() -> Dict[str, str]:
    if not settings.evidence_enabled:
        return _check("forensics.evidence", "warn",
                      "evidence log disabled (XIKIN_EVIDENCE=0)")
    report = get_log().verify()
    if report.get("ok"):
        return _check("forensics.evidence", "ok",
                      "hash chain intact — %d entries (%s)"
                      % (report.get("entries", 0), get_log().path))
    return _check("forensics.evidence", "fail",
                  "evidence chain broken: %s" % report.get("error"))


def check_llm() -> Dict[str, str]:
    if llm_available():
        return _check("analysis.llm", "ok", "provider ready: %s" % provider_summary())
    return _check("analysis.llm", "warn",
                  "no LLM provider configured (%s) — offline fallbacks will be used"
                  % provider_summary())


def run_all() -> Dict[str, object]:
    checks: List[Dict[str, str]] = [
        check_socks_port(),
        check_identity(),
        check_control_port(),
        check_onion_dns(),
        check_proxy_env(),
        check_isolation(),
        check_cache(),
        check_evidence(),
        check_llm(),
    ]
    failures = [item for item in checks if item["status"] == "fail"]
    warnings = [item for item in checks if item["status"] == "warn"]
    return {
        "checks": checks,
        "passed": len(checks) - len(failures) - len(warnings),
        "warnings": len(warnings),
        "failures": len(failures),
        "ok": not failures,
        "safety_note": SAFETY_NOTE,
    }
