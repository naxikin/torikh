"""Static, non-executing file analysis: hashes, type, entropy, strings, IOCs.

The uploaded bytes are processed in memory only — never written to disk, never
executed. Output is display-safe: if the extracted strings trip the content
safety filter, they and any derived indicators are withheld.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from typing import Dict, Optional

from .iocs import extract
from .safety import is_safe_text

MAX_BYTES = 25 * 1024 * 1024
_MAX_STRINGS = 4000
_MAX_TEXT = 300_000

_STRINGS_RE = re.compile(rb"[\x20-\x7e]{6,}")

_MAGIC = (
    (b"MZ", "PE executable"),
    (b"\x7fELF", "ELF executable"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\xd0\xcf\x11\xe0", "OLE document"),
    (b"\x89PNG", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF8", "GIF image"),
    (b"SQLite format 3", "SQLite database"),
    (b"\xca\xfe\xba\xbe", "Mach-O / Java class"),
    (b"\xfe\xed\xfa\xce", "Mach-O executable"),
    (b"\xfe\xed\xfa\xcf", "Mach-O executable"),
)


def detect_type(data: bytes) -> str:
    for magic, label in _MAGIC:
        if data.startswith(magic):
            return label
    sample = data[:4096]
    if sample:
        printable = sum(1 for byte in sample if 32 <= byte < 127 or byte in (9, 10, 13))
        if printable / len(sample) > 0.9:
            return "text"
    return "binary"


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return round(entropy, 3)


def extract_strings(data: bytes) -> str:
    found = []
    for match in _STRINGS_RE.finditer(data):
        found.append(match.group(0).decode("ascii", "replace"))
        if len(found) >= _MAX_STRINGS:
            break
    text = "\n".join(found)
    return text[:_MAX_TEXT]


def analyze(data: bytes, filename: str = "upload.bin") -> Dict[str, object]:
    if len(data) > MAX_BYTES:
        raise ValueError("file exceeds the %d MB limit" % (MAX_BYTES // (1024 * 1024)))
    sha256 = hashlib.sha256(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()  # noqa: S324 - identification only
    md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
    file_type = detect_type(data)
    strings_text = extract_strings(data)
    safe = is_safe_text(strings_text)
    iocs = extract({"file:%s" % (filename or "upload"): strings_text}) if safe else {}
    preview = strings_text[:6000] if safe else ""
    return {
        "name": (filename or "upload.bin")[:200],
        "size": len(data),
        "type": file_type,
        "sha256": sha256,
        "sha1": sha1,
        "md5": md5,
        "entropy": shannon_entropy(data),
        "iocs": iocs,
        "strings_preview": preview,
        "strings_total": len(strings_text.splitlines()),
        "blocked": not safe,
        "is_text": file_type == "text",
    }
