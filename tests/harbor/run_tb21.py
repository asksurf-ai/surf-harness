"""Run or collect the pinned Terminal-Bench 2.1 diagnostic baseline."""

from __future__ import annotations

import sys
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY / "src"))

from nano_grok_build.harbor.tb21 import main  # noqa: E402, I001


if __name__ == "__main__":
    raise SystemExit(main())
