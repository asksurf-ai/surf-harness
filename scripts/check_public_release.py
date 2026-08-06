#!/usr/bin/env python3
"""Validate the exported Surf Harness release without network access."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
import tomllib
from pathlib import Path

EXPECTED_VERSION = "0.4.5"
PUBLIC_PROTECTED_POLICY = "policy/protected-targets-v1.json"
PUBLIC_HISTORY_POLICY = "policy/tb21-git-history-capability-v2.json"
PUBLIC_POLICY_PATHS = {PUBLIC_PROTECTED_POLICY, PUBLIC_HISTORY_POLICY}
EXPECTED_APPROVED_ARTIFACTS = {
    "NOTICE": (648, "48f7687551795354b316162b0bdf189a6bb57d6e5e9e6db4bf7a4ad79ea8426d"),
    "THIRD_PARTY_NOTICES.md": (
        1365,
        "3345d8ae98ca7826a8b51d95add738fcf9480eaf04620e8bce350004e7df5151",
    ),
    "contracts/nano-v1/agent-profile.json": (
        2973,
        "5adf3039a92472629119db9c5ed17aa9177118e2996423e9e5bfbe3b88940bb4",
    ),
    "contracts/nano-v1/contract-delta.json": (
        757520,
        "b335ed6dc62b39ea874db78a4dd2c454cbb538a6c6ac6677d30f6de1ee233b99",
    ),
    "contracts/nano-v1/effective-contract.json": (
        17424,
        "1a22d7cbc7f20fb2e48aee2ca0fa30157e99c83db96c572c187be3f8412576e9",
    ),
    "contracts/nano-v1/normalization-manifest.json": (
        13226,
        "61d6b31e06b0a39f0f3c1d929689a63e3580e8b273efc9321636be952d82e983",
    ),
    "contracts/nano-v1/renderer-goldens.json": (
        9218,
        "6336c1b9682fe250c6f15c0fa301b9b403ca620019f57ea9109248f5dbee3e07",
    ),
    "contracts/nano-v1/user-wrapper-goldens.json": (
        698,
        "998cd1ce4e542482fb113be18e18a41105772121d5851ac669ac37cec4532ab4",
    ),
}
REQUIRED_PATHS = {
    "README.md",
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_NOTICES.md",
    "SOURCE-MANIFEST.json",
    "SBOM.spdx.json",
    *PUBLIC_POLICY_PATHS,
    *EXPECTED_APPROVED_ARTIFACTS,
}
FORBIDDEN_PREFIXES = (
    ".review/",
    "docs/tb21/",
    "policy/",
    "provenance/",
    "release/",
    "tools/upstream-export/",
)
FORBIDDEN_PATHS = {
    "SUMMARY-C4-WORKSPACE.md",
    "docs/DESIGN.md",
    "docs/IMPLEMENTATION_PLAN.md",
    "docs/ISSUES.md",
    "docs/R4_MECHANICAL.md",
    "docs/RIGHTS.md",
    "docs/STATUS.md",
}
IGNORED_PARTS = {
    ".git",
    ".local-tools",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "coverage",
    "dist",
    "target",
}
DISCLAIMER = (
    "This independent community project is not affiliated with, endorsed by, "
    "or sponsored by xAI."
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _payload_paths(root: Path) -> set[str]:
    paths: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if any(part in IGNORED_PARTS for part in relative.parts):
            continue
        if path.is_symlink():
            paths.add(relative.as_posix())
        elif path.is_file():
            paths.add(relative.as_posix())
    return paths


def _check_versions(root: Path, manifest: dict[str, object]) -> list[str]:
    errors: list[str] = []
    try:
        pyproject = tomllib.loads((root / "pyproject.toml").read_text())
        cargo = tomllib.loads((root / "Cargo.toml").read_text())
        package_version = str(pyproject["project"]["version"])
        workspace_version = str(cargo["workspace"]["package"]["version"])
        init_scope: dict[str, object] = {}
        exec((root / "src/nano_grok_build/__init__.py").read_text(), init_scope)
        import_version = str(init_scope["__version__"])
        source_version = str(manifest["release"]["version"])
    except (KeyError, OSError, SyntaxError, tomllib.TOMLDecodeError) as error:
        return [f"cannot read release versions: {error}"]
    versions = {
        package_version,
        workspace_version,
        import_version,
        source_version,
        EXPECTED_VERSION,
    }
    if len(versions) != 1:
        errors.append(f"release versions disagree: {sorted(versions)}")
    return errors


def check_public_release(root: Path) -> list[str]:
    """Return integrity and release-boundary errors for an exported tree."""
    root = root.resolve()
    errors: list[str] = []
    actual_paths = _payload_paths(root)
    for required in sorted(REQUIRED_PATHS - actual_paths):
        errors.append(f"required public path missing: {required}")
    for path in sorted(actual_paths):
        candidate = root / path
        if candidate.is_symlink():
            errors.append(f"public release contains symlink: {path}")
        if path in FORBIDDEN_PATHS or (
            path.startswith(FORBIDDEN_PREFIXES) and path not in PUBLIC_POLICY_PATHS
        ):
            errors.append(f"internal-only path exported: {path}")

    for path, (expected_length, expected_hash) in EXPECTED_APPROVED_ARTIFACTS.items():
        candidate = root / path
        if not candidate.is_file():
            continue
        data = candidate.read_bytes()
        if len(data) != expected_length or _sha256(data) != expected_hash:
            errors.append(f"approved artifact bytes changed: {path}")

    notice = root / "NOTICE"
    if notice.is_file() and DISCLAIMER not in notice.read_text():
        errors.append("NOTICE is missing the required non-affiliation disclaimer")

    manifest_path = root / "SOURCE-MANIFEST.json"
    if not manifest_path.is_file():
        return errors
    try:
        manifest = json.loads(manifest_path.read_text())
        if manifest["schema_version"] != "surf-harness-source-manifest-v1":
            errors.append("SOURCE-MANIFEST.json has an unsupported schema")
        release = manifest["release"]
        if release["agent"]["name"] != "nano-grok-build":
            errors.append("SOURCE-MANIFEST.json agent identity changed")
        if release["model"]["name"] != "xai/grok-4.5":
            errors.append("SOURCE-MANIFEST.json model identity changed")
        if release["model"]["reasoning_effort"] != "high":
            errors.append("SOURCE-MANIFEST.json reasoning effort changed")
        readiness = release["readiness"]
        reason = (
            readiness.get("reason", "release-readiness-invalid")
            if isinstance(readiness, dict)
            else "release-readiness-invalid"
        )
        if readiness != {"reason": "", "status": "ready"}:
            errors.append(f"contract approval pending: {reason}")
        listed = manifest["files"]
    except (KeyError, json.JSONDecodeError, TypeError) as error:
        errors.append(f"invalid SOURCE-MANIFEST.json: {error}")
        return errors

    listed_paths: set[str] = set()
    for row in listed:
        try:
            path = str(row["path"])
            expected_length = int(row["byte_length"])
            expected_hash = str(row["sha256"])
            expected_mode = str(row["mode"])
        except (KeyError, TypeError, ValueError) as error:
            errors.append(f"invalid SOURCE-MANIFEST.json file row: {error}")
            continue
        if expected_mode not in {"100644", "100755"}:
            errors.append(f"invalid manifested mode for {path}: {expected_mode}")
            continue
        if path in listed_paths:
            errors.append(f"duplicate SOURCE-MANIFEST.json file row: {path}")
            continue
        listed_paths.add(path)
        candidate = root / path
        if not candidate.is_file() or candidate.is_symlink():
            errors.append(f"manifested payload missing or not regular: {path}")
            continue
        data = candidate.read_bytes()
        if len(data) != expected_length or _sha256(data) != expected_hash:
            errors.append(f"manifested payload bytes changed: {path}")
        is_executable = bool(candidate.stat().st_mode & stat.S_IXUSR)
        if is_executable != (expected_mode == "100755"):
            errors.append(f"manifested payload mode changed: {path}")

    expected_paths = actual_paths - {"SOURCE-MANIFEST.json"}
    if listed_paths != expected_paths:
        for path in sorted(expected_paths - listed_paths):
            errors.append(f"unmanifested public payload: {path}")
        for path in sorted(listed_paths - expected_paths):
            errors.append(f"manifest lists absent public payload: {path}")

    errors.extend(_check_versions(root, manifest))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args()
    errors = check_public_release(args.root)
    for error in errors:
        print(f"public release: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
