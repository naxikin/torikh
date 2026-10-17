"""Web security helpers: signed session cookies, CSRF and security headers."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Optional

SESSION_COOKIE = "xikin_session"
CSRF_COOKIE = "xikin_csrf"
SESSION_TTL_SECONDS = 12 * 3600

CSP = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "style-src 'self'; "
    "script-src 'self'; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
}


def _key(token: str) -> bytes:
    return hashlib.sha256(("xikin-web-session:" + token).encode("utf-8")).digest()


def sign_session(secret: str, username: str, role: str,
                 ttl: int = SESSION_TTL_SECONDS) -> str:
    payload = base64.urlsafe_b64encode(
        json.dumps({"u": username, "r": role,
                    "exp": int(time.time()) + ttl,
                    "nonce": secrets.token_hex(8)}).encode("utf-8")
    ).decode("ascii").rstrip("=")
    signature = hmac.new(_key(secret), payload.encode("ascii"),
                         hashlib.sha256).hexdigest()
    return payload + "." + signature


def verify_session(cookie: Optional[str], secret: Optional[str]) -> Optional[dict]:
    """Return ``{"user", "role", "exp"}`` for a valid signed session, else None."""
    if not cookie or not secret:
        return None
    try:
        payload, signature = cookie.split(".", 1)
    except ValueError:
        return None
    expected = hmac.new(_key(secret), payload.encode("ascii"),
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        padded = payload + "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, TypeError):
        return None
    try:
        if int(data.get("exp", 0)) <= time.time():
            return None
        return {"user": str(data.get("u")),
                "role": str(data.get("r")),
                "exp": int(data.get("exp", 0))}
    except (TypeError, ValueError):
        return None


def new_csrf() -> str:
    return secrets.token_urlsafe(24)


def csrf_ok(cookie_value: Optional[str], submitted: Optional[str]) -> bool:
    if not cookie_value or not submitted:
        return False
    return hmac.compare_digest(str(cookie_value), str(submitted))


def is_loopback(host: str) -> bool:
    return (host or "").strip().lower() in ("127.0.0.1", "localhost", "::1")
