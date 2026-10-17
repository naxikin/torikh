#!/usr/bin/env python3
"""Full investigation pipeline: verify Tor, check engines, refine, search,
filter, scrape and analyse — in one command."""
from __future__ import annotations

import argparse
import sys

from xikin import __version__
from xikin.cli import eprint, emit, mode_choices
from xikin.pipeline import run_pipeline


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="pipeline.py",
        description="Run the complete dark-web investigation pipeline.")
    parser.add_argument("--query", "-q", required=True, help="investigation query")
    parser.add_argument("--mode", choices=mode_choices(), default="threat_intel",
                        help="analysis mode (default: threat_intel)")
    parser.add_argument("--max", type=int, default=0, metavar="N",
                        help="max results kept after filtering (mode default otherwise)")
    parser.add_argument("--scrape", type=int, default=0, metavar="N",
                        help="pages to scrape (mode default otherwise; 0 = skip scraping)")
    parser.add_argument("--engines", nargs="+", metavar="NAME",
                        help="engine subset (default: alive engines)")
    parser.add_argument("--custom", help="extra analyst focus for the LLM prompt")
    parser.add_argument("--out", metavar="FILE", help="write the markdown report to FILE")
    parser.add_argument("--clear-cache", action="store_true",
                        help="clear cached fetches/search results before running")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable summary (report text omitted unless --out)")
    parser.add_argument("--version", action="version", version="xikin %s" % __version__)
    args = parser.parse_args()

    result = run_pipeline(
        args.query,
        mode=args.mode,
        max_results=args.max,
        scrape=args.scrape,
        custom=args.custom,
        out=args.out,
        engines=args.engines,
        clear_cache_first=args.clear_cache,
        log=lambda line: eprint(line),
    )

    if not result.get("ok"):
        if args.json:
            emit(result)
        else:
            eprint("[!] Pipeline aborted: %s" % result.get("error"))
        return 1

    if args.json:
        emit({key: value for key, value in result.items() if key != "report"})
    elif not args.out:
        print(result["report"])
    else:
        eprint("[i] Done — report saved to %s" % result.get("path"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
