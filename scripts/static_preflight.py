#!/usr/bin/env python3
"""Pure-stdlib, no-network policy gate that must run before uv or Cargo."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.check_architecture_boundaries import (  # noqa: E402
    check_architecture_boundaries,
)
from scripts.check_dependency_policy import (  # noqa: E402
    check_cargo_lock,
    check_manifests,
    check_python_lock,
    check_python_project,
)
from scripts.check_secrets import PATTERNS  # noqa: E402

IGNORED_PARTS = {
    ".git",
    ".cache",
    ".local-tools",
    ".pytest_cache",
    ".review",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "coverage",
    "dist",
    "target",
}


def check_static_secrets(root: Path) -> list[str]:
    """Scan source bytes directly; do not invoke Git or any other executable."""
    errors: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in IGNORED_PARTS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for name, pattern in PATTERNS.items():
            if pattern.search(text):
                errors.append(f"{path.relative_to(root)}: {name}")
    return errors


def static_errors(root: Path) -> list[str]:
    """Return all static policy failures without executing dependency tools."""
    resolved = root.resolve()
    errors = [
        *check_manifests(resolved),
        *check_cargo_lock(resolved / "Cargo.lock"),
        *check_python_project(resolved),
        *check_python_lock(resolved / "uv.lock"),
        *check_architecture_boundaries(resolved),
        *check_static_secrets(resolved),
    ]
    if (resolved / "tools/upstream-export").is_dir():
        from scripts.check_exporter_policy import check_exporter_policy

        errors.extend(check_exporter_policy(resolved, tracked_paths=[]))
    if (resolved / "scripts/check_provenance.py").is_file():
        from scripts.check_notices import check_notices
        from scripts.check_provenance import check_fixtures

        fixtures = resolved / "fixtures"
        errors.extend(check_fixtures(fixtures))
        errors.extend(check_notices(resolved, fixtures))
    if (resolved / "policy/contracts/nano-v1-promotion.json").is_file():
        from scripts.stage_contract import validate_policy_static

        errors.extend(validate_policy_static(resolved))
    if (resolved / "scripts/check_public_release.py").is_file():
        from scripts.check_public_release import check_public_release

        errors.extend(check_public_release(resolved))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args()
    errors = static_errors(args.root)
    for error in errors:
        print(f"static preflight: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
