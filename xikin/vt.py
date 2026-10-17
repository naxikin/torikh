"""VirusTotal enrichment — clearnet hash/URL lookups only, never uploads.

The file itself never leaves the machine; only the SHA-256 (or the URL) is
looked up. Enrichment is opt-in and requires VT_API_KEY.
"""
from __future__ import annotations

import base64
import time
from typing import Optional

import requests

from .config import settings

API_BASE = "https://www.virustotal.com/api/v3"


class VTError(RuntimeError):
    pass


def enabled() -> bool:
    return bool(settings.vt_api_key)


def url_id(url: str) -> str:
    """VirusTotal URL identifier: base64url of the URL without padding."""
    return base64.urlsafe_b64encode(
        (url or "").strip().encode("utf-8")).decode("ascii").rstrip("=")


def _fmt_ts(value) -> Optional[str]:
    try:
        return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(int(value)))
    except (TypeError, ValueError, OSError):
        return None


def _get(path: str) -> dict:
    if not settings.vt_api_key:
        raise VTError("VirusTotal API key is not configured")
    try:
        response = requests.get(
            API_BASE + path,
            headers={"x-apikey": settings.vt_api_key,
                     "Accept": "application/json"},
            timeout=20,
        )
    except requests.RequestException as exc:
        raise VTError("VirusTotal unreachable: %s" % exc) from exc
    if response.status_code == 404:
        return {"found": False}
    if response.status_code in (401, 403):
        raise VTError("VirusTotal rejected the API key")
    if response.status_code == 429:
        raise VTError("VirusTotal rate limit reached (free tier: 4 requests/min)")
    if response.status_code >= 400:
        raise VTError("VirusTotal HTTP %d" % response.status_code)
    try:
        return response.json()
    except ValueError as exc:
        raise VTError("VirusTotal returned invalid JSON") from exc


def _summarize(attributes: dict) -> dict:
    stats = attributes.get("last_analysis_stats") or {}
    return {
        "found": True,
        "malicious": int(stats.get("malicious", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "undetected": int(stats.get("undetected", 0) or 0),
        "harmless": int(stats.get("harmless", 0) or 0),
        "reputation": attributes.get("reputation"),
        "type_description": attributes.get("type_description"),
        "names": (attributes.get("names") or [])[:8],
        "tags": (attributes.get("tags") or [])[:10],
        "categories": dict(list((attributes.get("categories") or {}).items())[:8]),
        "first_submission": _fmt_ts(attributes.get("first_submission_date")),
        "last_analysis": _fmt_ts(attributes.get("last_analysis_date")),
        "permalink": None,
    }


def lookup_file(sha256: str) -> dict:
    payload = _get("/files/" + (sha256 or "").strip().lower())
    data = payload.get("data") or {}
    if not data:
        return {"found": False}
    result = _summarize(data.get("attributes") or {})
    result["permalink"] = "https://www.virustotal.com/gui/file/" + sha256.lower()
    return result


def lookup_url(url: str) -> dict:
    ident = url_id(url)
    payload = _get("/urls/" + ident)
    data = payload.get("data") or {}
    if not data:
        return {"found": False}
    result = _summarize(data.get("attributes") or {})
    result["permalink"] = "https://www.virustotal.com/gui/url/" + ident
    return result
