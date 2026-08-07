#!/usr/bin/env python3
"""Validate exact local bootstrap tool versions."""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def output(*command: str) -> str:
    return subprocess.run(
        command, cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()


def main() -> int:
    if os.environ.get("NANO_STATIC_PREFLIGHT_PASSED") != "1":
        print(
            "bootstrap: invoke system `python3 scripts/check.py`; "
            "static preflight must run before dependency tools",
            file=sys.stderr,
        )
        return 1
    versions = json.loads((ROOT / "tools/tool-versions.json").read_text())
    expected = {
        "rustc": versions["rust"]["version"],
        "cargo": versions["rust"]["version"],
        "uv": versions["uv"]["version"],
        "python": versions["python"]["version"],
    }
    actual = {
        "rustc": output("rustc", "--version").split()[1],
        "cargo": output("cargo", "--version").split()[1],
        "uv": output("uv", "--version").split()[1],
        "python": platform.python_version(),
    }
    errors = [
        f"{tool}: expected {expected[tool]}, got {actual[tool]}"
        for tool in expected
        if actual[tool] != expected[tool]
    ]
    if errors:
        for error in errors:
            print(f"bootstrap: {error}", file=sys.stderr)
        return 1
    output("cargo", "metadata", "--locked", "--format-version", "1")
    output("uv", "lock", "--check")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
