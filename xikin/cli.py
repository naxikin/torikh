"""Shared CLI helpers: JSON output, tables, preflight checks."""
from __future__ import annotations

import json
import sys
from typing import Dict, Iterable, List

from .llm import MODES
from .tor import check_tor


def emit(payload) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))


def eprint(*parts) -> None:
    print(*parts, file=sys.stderr)


def mode_choices() -> List[str]:
    return list(MODES.keys())


def latency_bar(latency_ms) -> str:
    if not latency_ms:
        return ""
    blocks = min(max(int(latency_ms / 300), 1), 10)
    return "█" * blocks


def check_table(checks: Iterable[Dict[str, object]]) -> str:
    checks = list(checks)
    alive = [row for row in checks if row.get("status") == "up"]
    down = [row for row in checks if row.get("status") != "up"]
    lines = ["ALIVE  %d/%d" % (len(alive), len(checks)),
             "─" * 46]
    for row in alive:
        lines.append("  ✓  %-18s %6sms  %s"
                     % (row.get("name"), row.get("latency_ms") or "-",
                        latency_bar(row.get("latency_ms"))))
    if down:
        lines.append("DOWN   %d/%d" % (len(down), len(checks)))
        for row in down:
            lines.append("  ✗  %-18s %s" % (row.get("name"),
                                            (row.get("error") or "unreachable")[:40]))
    return "\n".join(lines)


def result_table(results: Iterable[Dict[str, object]], limit: int = 0) -> str:
    rows = list(results)
    if limit:
        rows = rows[:limit]
    width = max((len(str(row.get("title", ""))) for row in rows), default=20)
    width = min(width, 70)
    lines = ["  #  ENGINE              CR  %-*s  URL" % (width, "TITLE"),
             "─" * 104]
    for index, row in enumerate(rows, start=1):
        title = str(row.get("title", ""))[:width]
        lines.append("  %-2d %-19s %-3s %-*s  %s"
                     % (index, str(row.get("engine", "?"))[:19],
                        row.get("corroboration", "-"), width, title,
                        row.get("url", "")))
    return "\n".join(lines)


def tor_preflight(quiet: bool = False) -> bool:
    status = check_tor()
    if status.get("tor_active"):
        if not quiet:
            eprint("[i] Tor active — exit IP %s" % status.get("exit_ip"))
        return True
    eprint("[!] Tor is not available: %s" % status.get("error"))
    eprint("    Start Tor, e.g.:  brew install tor && tor &")
    return False
