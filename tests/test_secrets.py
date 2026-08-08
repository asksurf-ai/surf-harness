from __future__ import annotations

import unittest
from pathlib import Path

from scripts.check_secrets import scan_text


class SecretScannerTests(unittest.TestCase):
    def test_synthetic_canary_is_detected(self) -> None:
        canary = "NANO_TEST_" + "SECRET_" + ("A" * 24)
        self.assertTrue(scan_text(canary))

    def test_normal_source_text_passes(self) -> None:
        self.assertEqual(scan_text("model = 'grok-4.5'\nretry = 0\n"), [])

    def test_root_environment_files_are_ignored_but_example_is_trackable(self) -> None:
        root = Path(__file__).resolve().parents[1]
        lines = (root / ".gitignore").read_text(encoding="utf-8").splitlines()
        self.assertIn("/.env", lines)
        self.assertIn("/.env.*", lines)
        self.assertIn("!/.env.example", lines)


if __name__ == "__main__":
    unittest.main()
