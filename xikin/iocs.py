"""Deterministic IOC extraction and CTI export (STIX 2.1 / MISP / CSV / JSON).

Works fully offline — no LLM needed. Secrets (API keys, private-key blocks,
password assignments) are detected and masked in human-readable output.
"""
from __future__ import annotations

import csv
import io
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple

from .safety import sanitize_untrusted

_SEP = r"[/?#][^\s\"'<>()\[\]{}]*"

PATTERNS: Dict[str, re.Pattern] = {
    "onion_url": re.compile(
        r"\bhttps?://(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion" + _SEP, re.IGNORECASE),
    "onion_host": re.compile(
        r"\b(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion\b", re.IGNORECASE),
    "url": re.compile(r"\bhttps?://[^\s\"'<>()\[\]{}]+", re.IGNORECASE),
    "email": re.compile(r"\b[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9-]{1,63}"
                        r"(?:\.[a-zA-Z0-9-]{1,63}){1,4}\b"),
    "btc": re.compile(r"\b(?:bc1[a-z0-9]{8,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "xmr": re.compile(r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
    "eth": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
                       r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"),
    "pgp_fingerprint": re.compile(r"\b(?:[0-9A-F]{4}[ ]){9}[0-9A-F]{4}\b"),
    "secret": re.compile(
        r"(?:\bAKIA[0-9A-Z]{16}\b|\bsk-[A-Za-z0-9]{20,}\b|\bghp_[A-Za-z0-9]{36}\b"
        r"|\bxox[baprs]-[A-Za-z0-9-]{10,}\b|-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----"
        r"|\b(?:password|passwd|pwd|pass)\s*[:=]\s*\S{4,64})", re.IGNORECASE),
}

_TYPE_ORDER = ("onion_url", "onion_host", "url", "ipv4", "email", "secret",
               "sha256", "sha1", "md5", "cve", "pgp_fingerprint",
               "btc", "xmr", "eth")

_MIN_LENGTHS = {"ipv4": 7, "onion_host": 20}
_HOST_URL_TRIM = ".,;:!?)]}'\""


def _normalise(ioc_type: str, value: str) -> str:
    value = value.rstrip(_HOST_URL_TRIM)
    if ioc_type in ("sha256", "sha1", "md5", "cve", "onion_url", "onion_host",
                    "pgp_fingerprint"):
        return value.lower() if ioc_type != "pgp_fingerprint" else value.upper()
    if ioc_type == "email":
        return value.lower()
    return value


def _is_subsumed(ioc_type: str, value: str, found: Dict[str, set]) -> bool:
    if ioc_type == "url" and value in found.get("onion_url", set()):
        return True
    if ioc_type == "sha1" and value in found.get("sha256", set()):
        return True
    if ioc_type == "onion_host":
        for url in found.get("onion_url", set()):
            if value in url:
                return True
    if ioc_type == "url":
        for url in found.get("onion_url", set()):
            if value == url:
                return True
    return False


def extract(texts: Dict[str, str]) -> Dict[str, List[dict]]:
    """Extract IOCs from ``{source: text}``; returns ``{type: [{value, count, sources}]}``.

    Counts merge duplicates across sources; ``sources`` lists up to 10 origins.
    """
    values: Dict[str, Dict[str, dict]] = {}

    for source, raw_text in (texts or {}).items():
        text = sanitize_untrusted(raw_text or "")
        if not text:
            continue
        for ioc_type, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                value = _normalise(ioc_type, match.group(0))
                if len(value) < _MIN_LENGTHS.get(ioc_type, 4):
                    continue
                bucket = values.setdefault(ioc_type, {})
                entry = bucket.setdefault(value, {"value": value, "count": 0,
                                                  "sources": []})
                entry["count"] += 1
                if source and source not in entry["sources"] and len(entry["sources"]) < 10:
                    entry["sources"].append(source)

    subsumed: Dict[str, set] = {
        key: {entry["value"] for entry in items.values()}
        for key, items in values.items()
    }
    for values_for_type in values.values():
        for entry in values_for_type.values():
            entry["sources"] = sorted(entry["sources"])[:10]

    result: Dict[str, List[dict]] = {}
    for ioc_type in _TYPE_ORDER:
        items = values.get(ioc_type, {})
        if not items:
            continue
        if ioc_type in ("url", "sha1", "onion_host"):
            items = {value: entry for value, entry in items.items()
                     if not _is_subsumed(ioc_type, value, subsumed)}
        ordered = sorted(items.values(), key=lambda item: (-item["count"], item["value"]))
        if ordered:
            result[ioc_type] = ordered
    return result


def total_count(iocs: Dict[str, List[dict]]) -> int:
    return sum(len(items) for items in (iocs or {}).values())


def value_set(iocs: Dict[str, List[dict]]) -> set:
    return {entry["value"] for items in (iocs or {}).values() for entry in items}


def mask_secret(value: str) -> str:
    if "-----BEGIN" in value:
        return "-----BEGIN PRIVATE KEY----- [masked]"
    match = re.match(r"(\w{0,12}\s*[:=]\s*)(\S+)", value)
    if match:
        return "%s%s[REDACTED]" % (match.group(1), match.group(2)[:2])
    if len(value) <= 8:
        return value[:2] + "[REDACTED]"
    return "%s…%s [REDACTED]" % (value[:4], value[-4:])


def render_markdown(iocs: Dict[str, List[dict]], redact: bool = True,
                    limit_per_type: int = 25) -> str:
    lines = ["### Extracted indicators", ""]
    if not iocs:
        return "\n".join(lines + ["_No indicators extracted._", ""])

    labels = {
        "onion_url": "Onion URLs", "onion_host": "Onion hosts", "url": "Clearnet URLs",
        "ipv4": "IPv4 addresses", "email": "Email addresses", "secret": "Secrets / credentials",
        "sha256": "SHA-256", "sha1": "SHA-1", "md5": "MD5", "cve": "CVEs",
        "pgp_fingerprint": "PGP fingerprints", "btc": "Bitcoin addresses",
        "xmr": "Monero addresses", "eth": "Ethereum addresses",
    }
    for ioc_type, items in iocs.items():
        label = labels.get(ioc_type, ioc_type)
        shown = items[:limit_per_type]
        lines.append("**%s** (%d)" % (label, len(items)))
        lines.append("")
        for entry in shown:
            value = entry["value"]
            if ioc_type == "secret" and redact:
                value = mask_secret(value)
            suffix = " ×%d" % entry["count"] if entry["count"] > 1 else ""
            lines.append("- `%s`%s" % (value, suffix))
        if len(items) > len(shown):
            lines.append("- _…and %d more_"
                         % (len(items) - len(shown)))
        lines.append("")
    return "\n".join(lines)


def render_csv(iocs: Dict[str, List[dict]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["type", "value", "count", "sources"])
    for ioc_type, items in (iocs or {}).items():
        for entry in items:
            writer.writerow([ioc_type, entry["value"], entry["count"],
                             " ".join(entry["sources"])])
    return buffer.getvalue()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


_STIX_PATTERN = {
    "onion_host": "[domain-name:value = '{v}']",
    "url": "[url:value = '{v}']",
    "ipv4": "[ipv4-addr:value = '{v}']",
    "email": "[email-addr:value = '{v}']",
    "sha256": "[file:hashes.'SHA-256' = '{v}']",
    "sha1": "[file:hashes.'SHA-1' = '{v}']",
    "md5": "[file:hashes.MD5 = '{v}']",
    "cve": "[vulnerability:name = '{v}']",
    "btc": "[cryptocurrency-wallet:value = '{v}']",
    "xmr": "[cryptocurrency-wallet:value = '{v}']",
    "eth": "[cryptocurrency-wallet:value = '{v}']",
    "secret": "[user-account:credential = '{v}']",
    "pgp_fingerprint": "[user-account:user_id = '{v}']",
}


def to_stix(iocs: Dict[str, List[dict]], query: str = "xikin investigation") -> dict:
    """Build a STIX 2.1 bundle of indicator SDOs (onion URLs map to domains)."""
    bundle_id = "bundle--%s" % uuid.uuid4()
    objects: List[dict] = [{
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--%s" % uuid.uuid4(),
        "created": _now_iso(),
        "modified": _now_iso(),
        "name": "xikin",
        "identity_class": "system",
        "description": "xikin dark-web OSINT toolkit",
    }]
    for ioc_type, items in (iocs or {}).items():
        pattern_key = "onion_host" if ioc_type == "onion_url" else ioc_type
        template = _STIX_PATTERN.get(pattern_key)
        if not template:
            continue
        for entry in items:
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--%s" % uuid.uuid4(),
                "created": _now_iso(),
                "modified": _now_iso(),
                "created_by_ref": objects[0]["id"],
                "name": "%s (%s)" % (entry["value"][:80], ioc_type),
                "description": "Extracted by xikin from: %s | query: %s"
                               % (", ".join(entry["sources"]) or "n/a", query),
                "indicator_types": ["anomalous-activity"],
                "pattern": template.format(v=entry["value"].replace("'", "")),
                "pattern_type": "stix",
                "valid_from": _now_iso(),
                "labels": [ioc_type],
            })
    return {"type": "bundle", "id": bundle_id, "objects": objects}


_MISP_MAP = {
    "onion_host": ("Network activity", "domain"), "url": ("Network activity", "url"),
    "ipv4": ("Network activity", "ip-src"), "email": ("Payload delivery", "email-src"),
    "sha256": ("Payload delivery", "sha256"), "sha1": ("Payload delivery", "sha1"),
    "md5": ("Payload delivery", "md5"), "cve": ("External analysis", "vulnerability"),
    "btc": ("Financial fraud", "btc"), "xmr": ("Financial fraud", "xmr"),
    "eth": ("Financial fraud", "eth"), "secret": ("Payload delivery", "text"),
    "pgp_fingerprint": ("Other", "pgp-fingerprint"),
}


def to_misp(iocs: Dict[str, List[dict]], query: str = "xikin investigation") -> dict:
    attributes = []
    for ioc_type, items in (iocs or {}).items():
        mapping = _MISP_MAP.get("onion_host" if ioc_type == "onion_url" else ioc_type)
        if not mapping:
            continue
        category, misp_type = mapping
        for entry in items:
            attributes.append({
                "type": misp_type,
                "category": category,
                "to_ids": True,
                "value": entry["value"],
                "comment": "xikin | sources: %s" % ", ".join(entry["sources"][:3]),
            })
    return {"Event": {
        "info": query,
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "distribution": "0",
        "threat_level_id": "3",
        "analysis": "1",
        "Attribute": attributes,
    }}


def render(iocs: Dict[str, List[dict]], fmt: str, query: str = "xikin investigation",
           redact: bool = True) -> str:
    if fmt == "json":
        return json.dumps(iocs, indent=2, ensure_ascii=False)
    if fmt == "stix":
        return json.dumps(to_stix(iocs, query), indent=2, ensure_ascii=False)
    if fmt == "misp":
        return json.dumps(to_misp(iocs, query), indent=2, ensure_ascii=False)
    if fmt == "csv":
        return render_csv(iocs)
    return render_markdown(iocs, redact=redact)


def find_secret_hits(texts: Dict[str, str]) -> List[Tuple[str, str]]:
    """Return ``(value, source)`` for detected secrets — used for warn banners."""
    hits: List[Tuple[str, str]] = []
    for source, raw_text in (texts or {}).items():
        text = sanitize_untrusted(raw_text or "")
        for match in PATTERNS["secret"].finditer(text):
            hits.append((match.group(0)[:120], source))
    return hits
