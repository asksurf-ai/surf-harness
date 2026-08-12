#!/usr/bin/env python3
"""Deterministic worktree secret canary used in addition to gitleaks."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

PATTERNS = {
    "synthetic-test-canary": re.compile(r"NANO_TEST_SECRET_[A-Z0-9]{24,}"),
    "private-key-header": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    ),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "aws-access-key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
}


def scan_text(text: str) -> list[str]:
    return [name for name, pattern in PATTERNS.items() if pattern.search(text)]


def tracked_and_untracked(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [root / item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def scan_tree(root: Path) -> list[str]:
    errors: list[str] = []
    for path in tracked_and_untracked(root):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for finding in scan_text(text):
            errors.append(f"{path.relative_to(root)}: {finding}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args()
    try:
        errors = scan_tree(args.root.resolve())
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"secret scan failed: {error}", file=sys.stderr)
        return 1
    for error in errors:
        print(f"secret scan: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
