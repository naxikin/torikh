#!/usr/bin/env python3
"""Verify Tor is running and show the current exit IP."""
from __future__ import annotations

import argparse
import sys

from xikin.cli import emit
from xikin.tor import check_tor


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="check_tor.py",
        description="Verify Tor is active, show the current exit IP.")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    status = check_tor()
    if args.json:
        emit(status)
    elif status.get("tor_active"):
        print("✓ Tor active")
        print("  Exit IP : %s" % status.get("exit_ip"))
        print("  Is Tor  : %s" % status.get("is_tor"))
    else:
        print("✗ Tor NOT active")
        print("  Error   : %s" % status.get("error"))
    return 0 if status.get("tor_active") else 1


if __name__ == "__main__":
    sys.exit(main())
