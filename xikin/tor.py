"""Tor transport — SOCKS5 session, liveness check, circuit renewal."""
from __future__ import annotations

import logging
import os
import random
import re
import secrets
import socket
import time
from typing import Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import settings
from .textutil import friendly_error

for _noisy in ("urllib3", "urllib3.connectionpool", "stem", "stem.control",
               "stem.connection", "stem.socket", "stem.response", "stem.util"):
    logging.getLogger(_noisy).setLevel(logging.CRITICAL)

USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0",
)

_COOKIE_PATHS = (
    "control_auth_cookie",
    "control.authcookie",
)


def random_user_agent() -> str:
    return random.choice(USER_AGENTS)


def build_session(user_agent: Optional[str] = None,
                  isolate_tag: Optional[str] = None) -> requests.Session:
    """Create a Tor-routed session.

    With ``isolate_tag`` (and ``XIKIN_ISOLATE`` enabled) each session gets
    unique SOCKS credentials, which Tor maps to a separate circuit — so two
    queries cannot be correlated by circuit even on the same exit node.
    Requires ``SocksPort 9050 IsolateSOCKSAuth`` in torrc for enforcement.
    """
    session = requests.Session()
    retry = Retry(total=2, connect=2, read=1, backoff_factor=0.5,
                  status_forcelist=(502, 503, 504))
    adapter = HTTPAdapter(max_retries=retry, pool_connections=8, pool_maxsize=8)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    proxy = "socks5h://%s:%d" % (settings.tor_socks_host, settings.tor_socks_port)
    if isolate_tag and settings.isolate_circuits:
        username = "xikin-%s-%s" % (re.sub(r"[^a-z0-9]+", "-", isolate_tag.lower())[:24],
                                    secrets.token_hex(6))
        proxy = "socks5h://%s:x@%s:%d" % (username, settings.tor_socks_host,
                                          settings.tor_socks_port)
    session.proxies = {"http": proxy, "https": proxy}
    session.headers.update({
        "User-Agent": user_agent or random_user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close",
    })
    return session


def request_timeout():
    return (settings.tor_connect_timeout, settings.tor_timeout)


def tor_port_open(timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection(
            (settings.tor_socks_host, settings.tor_socks_port), timeout=timeout
        ):
            return True
    except OSError:
        return False


def require_tor() -> None:
    if not tor_port_open():
        raise RuntimeError(
            "Tor SOCKS port %s:%d is not reachable — start Tor first "
            "(e.g. `brew install tor && tor &`)."
            % (settings.tor_socks_host, settings.tor_socks_port)
        )


def exit_ip(session: Optional[requests.Session] = None) -> Optional[str]:
    session = session or build_session()
    try:
        response = session.get("https://check.torproject.org/api/ip",
                               timeout=request_timeout())
        payload = response.json()
        return payload.get("IP")
    except Exception:
        return None


def check_tor() -> Dict[str, Optional[str]]:
    """Return ``{"tor_active", "exit_ip", "is_tor", "error"}``."""
    if not tor_port_open():
        return {
            "tor_active": False,
            "exit_ip": None,
            "is_tor": False,
            "error": "Tor SOCKS port %s:%d is not reachable"
                     % (settings.tor_socks_host, settings.tor_socks_port),
        }
    session = build_session()
    try:
        response = session.get("https://check.torproject.org/api/ip",
                               timeout=request_timeout())
        payload = response.json()
        return {
            "tor_active": True,
            "exit_ip": payload.get("IP"),
            "is_tor": bool(payload.get("IsTor", False)),
            "error": None,
        }
    except Exception as exc:
        return {"tor_active": False, "exit_ip": None, "is_tor": False,
                "error": friendly_error(exc)}


def _cookie_candidates():
    roots = []
    if settings.tor_data_dir:
        roots.append(settings.tor_data_dir)
    roots.extend([
        "/tmp/tor_data",
        "/var/lib/tor",
        "/run/tor",
        os.path.expanduser("~/.tor"),
        "/opt/homebrew/var/lib/tor",
        "/opt/homebrew/var/db/tor",
        "/usr/local/var/lib/tor",
        "/usr/local/var/db/tor",
    ])
    for root in roots:
        for name in _COOKIE_PATHS:
            yield os.path.join(root, name)


def _read_cookie() -> Optional[bytes]:
    for path in _cookie_candidates():
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "rb") as handle:
                raw = handle.read().strip()
        except OSError:
            continue
        if not raw:
            continue
        if len(raw) == 64:
            try:
                return bytes.fromhex(raw.decode("ascii"))
            except (ValueError, UnicodeDecodeError):
                pass
        return raw
    return None


def renew_identity(verify: bool = True) -> Dict[str, object]:
    """Rotate the Tor circuit via the control port (NEWNYM)."""
    try:
        from stem import Signal
        from stem.control import Controller
    except ImportError:
        return {"success": False, "old_ip": None, "new_ip": None, "changed": None,
                "error": "stem is not installed — run: pip install stem"}

    old_ip = exit_ip() if verify else None
    try:
        with Controller.from_port(address=settings.tor_control_host,
                                  port=settings.tor_control_port) as controller:
            authenticated = False
            last_error = "all authentication methods failed"

            if settings.tor_control_password:
                try:
                    controller.authenticate(password=settings.tor_control_password)
                    authenticated = True
                except Exception as exc:
                    last_error = friendly_error(exc)

            if not authenticated:
                try:
                    controller.authenticate()
                    authenticated = True
                except Exception as exc:
                    last_error = friendly_error(exc)

            if not authenticated:
                cookie = _read_cookie()
                if cookie is not None:
                    try:
                        controller.authenticate(cookie=cookie)
                        authenticated = True
                    except Exception as exc:
                        last_error = friendly_error(exc)

            if not authenticated:
                return {"success": False, "old_ip": old_ip, "new_ip": None,
                        "changed": None, "error": last_error}

            controller.signal(Signal.NEWNYM)
    except Exception as exc:
        return {"success": False, "old_ip": old_ip, "new_ip": None, "changed": None,
                "error": friendly_error(exc)}

    time.sleep(1.5)
    new_ip = exit_ip() if verify else None
    changed = None if not verify else bool(new_ip and old_ip and new_ip != old_ip)
    return {"success": True, "old_ip": old_ip, "new_ip": new_ip, "changed": changed,
            "error": None}
