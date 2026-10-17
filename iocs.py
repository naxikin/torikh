#!/usr/bin/env python3
"""Extract indicators of compromise from scraped text and export STIX / MISP / CSV."""
from __future__ import annotations

import argparse
import sys

from xikin.cli import eprint, emit
from xikin.iocs import extract, render, total_count


def _read_sources(args) -> dict:
    sources = {}
    if args.text:
        sources["<inline>"] = args.text
    for path in args.file or []:
        if path == "-":
            sources["<stdin>"] = sys.stdin.read()
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                sources[path] = handle.read()
        except OSError as exc:
            eprint("[!] Cannot read %s: %s" % (path, exc))
            sys.exit(1)
    return sources


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="iocs.py",
        description="Deterministic IOC extraction (onions, wallets, emails, hashes, "
                    "CVEs, secrets) with STIX 2.1 / MISP / CSV export.")
    parser.add_argument("--file", "-f", nargs="+", metavar="PATH",
                        help="text file(s) to scan ('-' reads stdin)")
    parser.add_argument("--text", "-t", help="scan an inline string")
    parser.add_argument("--format", choices=("md", "json", "stix", "misp", "csv"),
                        default="md", help="output format (default: md)")
    parser.add_argument("--query", default="xikin investigation",
                        help="query/info string used in STIX and MISP exports")
    parser.add_argument("--no-redact", action="store_true",
                        help="show secrets in full in markdown output")
    parser.add_argument("--out", metavar="FILE", help="write output to FILE")
    args = parser.parse_args()

    sources = _read_sources(args)
    if not sources:
        eprint("[!] Nothing to scan — pass --file or --text.")
        return 1

    iocs = extract(sources)
    output = render(iocs, args.format, query=args.query, redact=not args.no_redact)

    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as handle:
                handle.write(output)
        except OSError as exc:
            eprint("[!] Cannot write %s: %s" % (args.out, exc))
            return 1
        eprint("[i] %d indicators written to %s" % (total_count(iocs), args.out))
    else:
        print(output)
        eprint("[i] %d indicators" % total_count(iocs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
