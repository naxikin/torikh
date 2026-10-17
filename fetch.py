#!/usr/bin/env python3
"""Fetch any .onion or clearnet URL through Tor and extract readable content."""
from __future__ import annotations

import argparse
import sys

from xikin.cli import eprint, emit, tor_preflight
from xikin.fetch import fetch


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="fetch.py",
        description="Fetch a page through Tor: title, text and (optionally) links.")
    parser.add_argument("--url", "-u", required=True, help=".onion or clearnet URL")
    parser.add_argument("--links", action="store_true", help="also extract page links")
    parser.add_argument("--iocs", action="store_true",
                        help="extract indicators of compromise from the page text")
    parser.add_argument("--max-chars", type=int, default=0, metavar="N",
                        help="truncate extracted text to N characters")
    parser.add_argument("--no-cache", action="store_true", help="bypass the fetch cache")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    if not tor_preflight():
        return 1

    result = fetch(args.url, extract_links=args.links,
                   max_chars=args.max_chars or None, use_cache=not args.no_cache)

    iocs = None
    if args.iocs and result.get("text"):
        from xikin.iocs import extract, render_markdown, total_count

        iocs = extract({result["url"]: result["text"]})
        eprint("[i] %d indicator(s) extracted" % total_count(iocs))

    if args.json:
        payload = dict(result)
        if iocs is not None:
            payload["iocs"] = iocs
        emit(payload)
    else:
        if not result.get("ok"):
            print("✗ Fetch failed (status %s)" % result.get("status"))
            print("  Error   : %s" % result.get("error"))
            return 1
        print("✓ %s" % (result.get("title") or "(no title)"))
        print("  Status  : %s" % result.get("status"))
        print("  URL     : %s" % result.get("url"))
        if result.get("sha256"):
            print("  SHA-256 : %s" % result.get("sha256"))
        print()
        print(result.get("text") or "(no text content)")
        if args.links:
            links = result.get("links") or []
            print()
            print("Links (%d):" % len(links))
            for link in links:
                print("  - %s" % link)
        if iocs is not None:
            print()
            print(render_markdown(iocs, redact=True))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
