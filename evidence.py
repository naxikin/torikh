#!/usr/bin/env python3
"""Verify the tamper-evident evidence log (sha256 hash chain)."""
from __future__ import annotations

import argparse
import sys

from xikin.cli import emit
from xikin.evidence import EvidenceLog


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="evidence.py",
        description="Verify or inspect the hash-chained fetch evidence log.")
    parser.add_argument("--path", help="log file (default: XIKIN_EVIDENCE_LOG)")
    parser.add_argument("--verify", action="store_true",
                        help="verify the hash chain (default action)")
    parser.add_argument("--status", action="store_true",
                        help="show log location and entry count instead of verifying")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    log = EvidenceLog(args.path)

    if args.status:
        status = log.status()
        if args.json:
            emit(status)
        else:
            print("Evidence log : %s" % status["path"])
            print("Entries      : %s" % status["entries"])
            print("Last hash    : %s" % status["last_hash"])
            if status.get("error"):
                print("Error        : %s" % status["error"])
        return 0 if not status.get("error") else 1

    report = log.verify()
    if args.json:
        emit(report)
    elif report.get("ok"):
        print("✓ Evidence chain intact — %d entries" % report.get("entries", 0))
        print("  Last hash : %s" % report.get("last_hash"))
    else:
        print("✗ Evidence chain INVALID")
        print("  Error     : %s" % report.get("error"))
        if report.get("broken_at"):
            print("  Broken at : line %s" % report["broken_at"])
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
