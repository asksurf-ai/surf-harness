#!/usr/bin/env python3
"""Prove the pinned gitleaks binary rejects a constructed fake canary."""

from __future__ import annotations

import argparse
import subprocess
import tempfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gitleaks", default="gitleaks")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="nano-gitleaks-canary.") as tmp:
        canary_file = Path(tmp) / "synthetic.txt"
        header = "-----BEGIN " + "PRIVATE KEY-----"
        footer = "-----END " + "PRIVATE KEY-----"
        body = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=" * 3
        canary_file.write_text(
            f"{header}\n{body}\n{footer}\n",
            encoding="utf-8",
        )
        result = subprocess.run(
            [
                args.gitleaks,
                "dir",
                "--redact",
                "--no-banner",
                "--exit-code",
                "23",
                tmp,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    if result.returncode != 23:
        print(result.stdout)
        print(result.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
