#!/usr/bin/env python3
"""Verify canonical JSON vectors match PIN.json."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PIN_PATH = REPO_ROOT / "testdata" / "canonical-json" / "v1" / "PIN.json"
VECTORS_PATH = REPO_ROOT / "testdata" / "canonical-json" / "v1" / "vectors.json"


def check_vectors() -> int:
    if not PIN_PATH.is_file():
        print(f"ERROR: missing PIN.json at {PIN_PATH}", file=sys.stderr)
        return 1
    if not VECTORS_PATH.is_file():
        print(f"ERROR: missing vectors.json at {VECTORS_PATH}", file=sys.stderr)
        return 1

    with PIN_PATH.open("r", encoding="utf-8") as f:
        pin = json.load(f)

    expected_sha256 = pin.get("sha256")
    if not expected_sha256:
        print("ERROR: PIN.json missing 'sha256' field", file=sys.stderr)
        return 1

    data = VECTORS_PATH.read_bytes()
    actual_sha256 = hashlib.sha256(data).hexdigest()

    if actual_sha256 != expected_sha256:
        print(
            f"ERROR: vectors.json sha256 mismatch!\n"
            f"  expected: {expected_sha256}\n"
            f"  actual:   {actual_sha256}",
            file=sys.stderr,
        )
        return 1

    print(f"OK: canonical vectors sha256 verified ({actual_sha256})")
    return 0


def main() -> int:
    subcommand = sys.argv[1] if len(sys.argv) > 1 else "check"
    if subcommand in ("check", "refresh-check"):
        return check_vectors()
    print(f"Unknown subcommand: {subcommand}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
