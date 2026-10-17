#!/usr/bin/env python3
"""Ping every dark-web search engine and report status and latency."""
from __future__ import annotations

import argparse
import sys

from xikin.cli import check_table, emit, tor_preflight
from xikin.engines import ENGINE_NAMES, check_search_engines


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="check_engines.py",
        description="Ping all registered dark-web search engines over Tor.")
    parser.add_argument("--cached", type=int, default=0, metavar="MINUTES",
                        help="reuse the last check if it is younger than MINUTES")
    parser.add_argument("--engines", nargs="+", metavar="NAME",
                        help="only check these engines (default: all)")
    parser.add_argument("--query", default="onion", help="test query (default: onion)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--list", action="store_true", help="list engine names and exit")
    args = parser.parse_args()

    if args.list:
        for name in ENGINE_NAMES:
            print(name)
        return 0

    if not args.cached and not tor_preflight():
        return 1

    report = check_search_engines(cached_minutes=args.cached,
                                  names=args.engines,
                                  test_query=args.query)
    if args.json:
        emit(report)
    else:
        if report.get("cached"):
            print("[i] showing cached result")
        print(check_table(report["results"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
