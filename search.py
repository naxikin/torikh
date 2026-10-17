#!/usr/bin/env python3
"""Search multiple dark-web engines simultaneously and print de-duplicated results."""
from __future__ import annotations

import argparse
import sys

from xikin.cli import eprint, emit, result_table, tor_preflight
from xikin.engines import ENGINE_NAMES
from xikin.search import search_detailed


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="search.py",
        description="Query up to %d dark-web search engines and merge the results."
                    % len(ENGINE_NAMES))
    parser.add_argument("--query", "-q", required=True, help="keywords (3-5 words work best)")
    parser.add_argument("--engines", nargs="+", metavar="NAME",
                        help="engine subset (default: all) — see check_engines.py --list")
    parser.add_argument("--max", type=int, default=0, metavar="N",
                        help="cap the number of returned results")
    parser.add_argument("--workers", type=int, default=0, help="parallel engine queries")
    parser.add_argument("--no-cache", action="store_true", help="bypass the result cache")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    if not tor_preflight():
        return 1

    report = search_detailed(args.query, engines=args.engines, max_results=args.max,
                             workers=args.workers or None, use_cache=not args.no_cache)
    if not report.get("ok"):
        if args.json:
            emit(report)
        else:
            eprint("[!] %s" % report.get("error"))
        return 1

    if args.json:
        emit(report)
        return 0

    eprint("[i] %d unique results from %d engines in %ss%s"
           % (report["count"], len(report["engines"]),
              report.get("elapsed_s", "?"), " (cached)" if report.get("cached") else ""))
    for name, info in sorted(report["per_engine"].items()):
        if info["status"] != "up":
            eprint("    ✗ %-18s %s" % (name, (info.get("error") or "down")[:60]))
    if report["results"]:
        print(result_table(report["results"]))
    else:
        eprint("[!] No results — run check_engines.py to find alive engines.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
