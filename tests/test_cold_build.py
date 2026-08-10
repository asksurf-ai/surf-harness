from __future__ import annotations

import hashlib
import shutil
import unittest
from pathlib import Path

from scripts.check_cold_build import run_cold_build

ROOT = Path(__file__).resolve().parents[1]


class ColdBuildTests(unittest.TestCase):
    def test_cold_sync_then_build_has_no_dynamic_resolution(self) -> None:
        uv = shutil.which("uv")
        self.assertIsNotNone(uv)
        before = hashlib.sha256((ROOT / "uv.lock").read_bytes()).hexdigest()
        evidence = run_cold_build(ROOT, Path(uv))
        after = hashlib.sha256((ROOT / "uv.lock").read_bytes()).hexdigest()

        self.assertEqual(evidence["network_requests_during_flow"], 0)
        self.assertEqual(evidence["tests_passed"], 1)
        self.assertEqual(evidence["wheel_imported"], 1)
        self.assertEqual(evidence["lock_sha256_before"], before)
        self.assertEqual(evidence["lock_sha256_after"], before)
        self.assertEqual(after, before)
        self.assertEqual(evidence["distributions"], 2)


if __name__ == "__main__":
    unittest.main()
