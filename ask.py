#!/usr/bin/env python3
"""LLM OSINT analysis of scraped dark-web content (4 analysis modes)."""
from __future__ import annotations

import argparse
import sys

from xikin.cli import eprint, emit, mode_choices
from xikin.llm import LLMError, ask, llm_available, provider_summary


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="ask.py",
        description="Analyse scraped content with an LLM and print a report.")
    parser.add_argument("--query", "-q", required=True, help="the investigation query")
    parser.add_argument("--mode", choices=mode_choices(), default="threat_intel",
                        help="analysis mode (default: threat_intel)")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--content", help="inline scraped text")
    source.add_argument("--file", help="file containing scraped text")
    parser.add_argument("--custom", help="extra analyst focus for the prompt")
    parser.add_argument("--max-chars", type=int, default=0, metavar="N",
                        help="cap the content characters sent to the LLM")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    if not llm_available():
        eprint("[!] No LLM provider configured (LLM_PROVIDER=%s)." % provider_summary())
        eprint("    Set an API key in .env or run a local model "
               "(LLM_PROVIDER=ollama).")
        return 1

    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="replace") as handle:
                content = handle.read()
        except OSError as exc:
            eprint("[!] Cannot read %s: %s" % (args.file, exc))
            return 1
    else:
        content = args.content or ""
    if not content.strip():
        eprint("[!] No content supplied.")
        return 1

    try:
        report = ask(args.query, content, mode=args.mode, custom=args.custom,
                     max_chars=args.max_chars or None)
    except LLMError as exc:
        eprint("[!] LLM error: %s" % exc)
        return 1

    if args.json:
        emit({"ok": True, "query": args.query, "mode": args.mode,
              "provider": provider_summary(), "report": report})
    else:
        print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
