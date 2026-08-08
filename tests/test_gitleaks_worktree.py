from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from scripts.check_gitleaks_worktree import (
    BENCHMARK_CHECKSUM_PATH,
    BENCHMARK_FINGERPRINT_LINES,
    materialize_scan_tree,
    validate_benchmark_fingerprint_contract,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def run(*command: str, root: Path) -> None:
    subprocess.run(command, cwd=root, check=True, capture_output=True)


def test_materialized_scan_tree_contains_source_candidates_only(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    run("git", "init", root=root)
    (root / ".gitignore").write_text("ignored.txt\n__pycache__/\n")
    (root / "tracked.txt").write_text("original")
    run("git", "add", ".gitignore", "tracked.txt", root=root)

    (root / "tracked.txt").write_text("modified")
    (root / "untracked.txt").write_text("untracked")
    (root / "ignored.txt").write_text("ignored")
    cache = root / "__pycache__"
    cache.mkdir()
    (cache / "generated.pyc").write_bytes(b"generated")

    destination = tmp_path / "scan"
    destination.mkdir()
    materialize_scan_tree(root, destination)

    assert (destination / "tracked.txt").read_text() == "modified"
    assert (destination / "untracked.txt").read_text() == "untracked"
    assert not (destination / "ignored.txt").exists()
    assert not (destination / "__pycache__").exists()


def copy_benchmark_fingerprint_contract(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "repo"
    scan_root = tmp_path / "scan"
    manifest = scan_root / BENCHMARK_CHECKSUM_PATH
    manifest.parent.mkdir(parents=True)
    root.mkdir()
    shutil.copyfile(REPOSITORY_ROOT / ".gitleaksignore", root / ".gitleaksignore")
    shutil.copyfile(REPOSITORY_ROOT / BENCHMARK_CHECKSUM_PATH, manifest)
    return root, scan_root


def test_benchmark_fingerprint_contract_accepts_only_pinned_manifest_lines(
    tmp_path: Path,
) -> None:
    root, scan_root = copy_benchmark_fingerprint_contract(tmp_path)

    validate_benchmark_fingerprint_contract(root, scan_root)


@pytest.mark.parametrize("line_number", sorted(BENCHMARK_FINGERPRINT_LINES))
def test_benchmark_fingerprint_contract_rejects_changed_ignored_value(
    tmp_path: Path,
    line_number: int,
) -> None:
    root, scan_root = copy_benchmark_fingerprint_contract(tmp_path)
    manifest = scan_root / BENCHMARK_CHECKSUM_PATH
    lines = manifest.read_bytes().splitlines()
    original = lines[line_number - 1]
    replacement = b"0" if original[-3:-2] != b"0" else b"1"
    lines[line_number - 1] = original[:-3] + replacement + original[-2:]
    manifest.write_bytes(b"\n".join(lines) + b"\n")

    with pytest.raises(RuntimeError, match=f"line {line_number}"):
        validate_benchmark_fingerprint_contract(root, scan_root)


def test_benchmark_fingerprint_contract_rejects_neighbor_or_new_ignore(
    tmp_path: Path,
) -> None:
    root, scan_root = copy_benchmark_fingerprint_contract(tmp_path)
    neighbor = min(BENCHMARK_FINGERPRINT_LINES) + 1
    with (root / ".gitleaksignore").open("a", encoding="utf-8") as ignore_file:
        ignore_file.write(f"{BENCHMARK_CHECKSUM_PATH}:generic-api-key:{neighbor}\n")

    with pytest.raises(RuntimeError, match="fingerprint set mismatch"):
        validate_benchmark_fingerprint_contract(root, scan_root)


def test_gitleaks_rejects_new_secret_on_neighboring_manifest_line(
    tmp_path: Path,
) -> None:
    gitleaks = shutil.which("gitleaks")
    if gitleaks is None:
        pytest.skip("gitleaks is not installed")
    root, scan_root = copy_benchmark_fingerprint_contract(tmp_path)
    manifest = scan_root / BENCHMARK_CHECKSUM_PATH
    lines = manifest.read_bytes().splitlines()
    neighbor = min(BENCHMARK_FINGERPRINT_LINES) + 1
    lines[neighbor - 1] = (
        b'    "terminal-bench/new-api-key": '
        b'"0ab655881a4827d9ec8f9930d4c4c8827729b20c978c20ff9cc6317f90660b5c",'
    )
    manifest.write_bytes(b"\n".join(lines) + b"\n")

    validate_benchmark_fingerprint_contract(root, scan_root)
    result = subprocess.run(
        [
            gitleaks,
            "dir",
            "--redact",
            "--no-banner",
            "--exit-code",
            "23",
            "--gitleaks-ignore-path",
            str(root),
            ".",
        ],
        cwd=scan_root,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 23
