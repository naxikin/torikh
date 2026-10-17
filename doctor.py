#!/usr/bin/env python3
"""Security preflight — Tor health, leak checks, isolation and evidence chain."""
from __future__ import annotations

import argparse
import sys

from xikin.cli import emit
from xikin.doctor import run_all

_SYMBOLS = {"ok": "✓", "warn": "!", "fail": "✗"}


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="doctor.py",
        description="Check the Tor setup for leaks, isolation and integrity issues.")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    report = run_all()
    if args.json:
        emit(report)
    else:
        for item in report["checks"]:
            print("%s  %-22s %s" % (_SYMBOLS.get(item["status"], "?"),
                                    item["name"], item["detail"]))
        print()
        print("%d ok · %d warning(s) · %d failure(s)"
              % (report["passed"], report["warnings"], report["failures"]))
        if not report["ok"]:
            print("Fix the failures before running investigations.")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
