#!/usr/bin/env python3
"""Rotate the Tor circuit — new exit node, new identity."""
from __future__ import annotations

import argparse
import sys

from xikin.cli import emit
from xikin.tor import renew_identity


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="renew.py",
        description="Rotate the Tor circuit via the control port (NEWNYM).")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--no-verify", action="store_true",
                        help="skip the before/after exit-IP comparison")
    args = parser.parse_args()

    result = renew_identity(verify=not args.no_verify)
    if args.json:
        emit(result)
    elif result.get("success"):
        print("Rotating Tor circuit...")
        print("✓ Identity renewed — new Tor circuit established")
        if result.get("old_ip") or result.get("new_ip"):
            print("  Exit IP : %s → %s" % (result.get("old_ip"), result.get("new_ip")))
        if result.get("changed") is False:
            print("  Note    : exit IP unchanged (same exit node chosen; rerun to retry)")
    else:
        print("✗ Circuit rotation failed")
        print("  Error   : %s" % result.get("error"))
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    sys.exit(main())
