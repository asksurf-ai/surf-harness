#!/usr/bin/env python3
"""Scan source candidates without including ignored build/runtime artifacts."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

BENCHMARK_CHECKSUM_PATH = Path("evaluation/tb21-2-1-task-checksums.json")
BENCHMARK_RULE_ID = "generic-api-key"
BENCHMARK_INTRODUCTION_COMMIT = "8c49d3ec7bbe6150d2bef7cadb9d4181068d3bf0"
BENCHMARK_FINGERPRINT_LINES = {
    26: (
        b'    "terminal-bench/count-dataset-tokens": '
        b'"0ab655881a4827d9ec8f9930d4c4c8827729b20c978c20ff9cc6317f90660b5c",\n'
    ),
    67: (
        b'    "terminal-bench/password-recovery": '
        b'"a8b12d116b3a8e03e946f0db92b77e789cfa26ecb49a56be5723ff47a03a532d",\n'
    ),
    97: (
        b'    "terminal-bench/vulnerable-secret": '
        b'"08ff9cb3cd416576bed330e9b92191ce0acbf5322f64714b6955ea6638361256",\n'
    ),
}


def benchmark_fingerprints() -> set[str]:
    path = BENCHMARK_CHECKSUM_PATH.as_posix()
    worktree = {
        f"{path}:{BENCHMARK_RULE_ID}:{line_number}"
        for line_number in BENCHMARK_FINGERPRINT_LINES
    }
    historical = {
        f"{BENCHMARK_INTRODUCTION_COMMIT}:{fingerprint}" for fingerprint in worktree
    }
    return worktree | historical


def validate_benchmark_fingerprint_contract(ignore_root: Path, scan_root: Path) -> None:
    """Bind narrow location fingerprints to the exact official source bytes."""

    expected_fingerprints = benchmark_fingerprints()
    ignore_entries = {
        line.strip()
        for line in (ignore_root / ".gitleaksignore")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    benchmark_marker = f"{BENCHMARK_CHECKSUM_PATH.as_posix()}:{BENCHMARK_RULE_ID}:"
    actual_fingerprints = {
        entry for entry in ignore_entries if benchmark_marker in entry
    }
    if actual_fingerprints != expected_fingerprints:
        raise RuntimeError("benchmark checksum fingerprint set mismatch")

    manifest_lines = (
        (scan_root / BENCHMARK_CHECKSUM_PATH).read_bytes().splitlines(keepends=True)
    )
    for line_number, expected_line in BENCHMARK_FINGERPRINT_LINES.items():
        if (
            len(manifest_lines) < line_number
            or manifest_lines[line_number - 1] != expected_line
        ):
            raise RuntimeError(
                f"benchmark checksum fingerprint bytes mismatch at line {line_number}"
            )


def source_candidates(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [Path(os.fsdecode(item)) for item in result.stdout.split(b"\0") if item]


def materialize_scan_tree(root: Path, destination: Path) -> None:
    for relative in source_candidates(root):
        source = root / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            target.symlink_to(os.readlink(source))
        elif source.is_file():
            shutil.copyfile(source, target)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gitleaks", default="gitleaks")
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args()
    root = args.root.resolve()

    with tempfile.TemporaryDirectory(prefix="nano-gitleaks-worktree.") as tmp:
        scan_root = Path(tmp) / "source"
        scan_root.mkdir()
        materialize_scan_tree(root, scan_root)
        validate_benchmark_fingerprint_contract(scan_root, scan_root)
        subprocess.run(
            [
                args.gitleaks,
                "dir",
                "--redact",
                "--no-banner",
                "--gitleaks-ignore-path",
                str(scan_root),
                ".",
            ],
            cwd=scan_root,
            check=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
