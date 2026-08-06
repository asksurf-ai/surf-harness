from __future__ import annotations

from pathlib import Path

from scripts.check_public_release import check_public_release

ROOT = Path(__file__).resolve().parents[1]


def test_public_release_is_hash_bound_and_complete() -> None:
    assert check_public_release(ROOT) == []
