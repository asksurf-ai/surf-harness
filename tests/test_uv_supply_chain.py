from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.install_uv import IntegrityError, verify_download

ROOT = Path(__file__).resolve().parents[1]
OFFICIAL_UV_ASSETS = {
    "linux-x86_64": (
        "uv-x86_64-unknown-linux-gnu.tar.gz",
        "df54b274e99b7ef26030dc21d105ce115bc21a644fc6a321bde9222cb1616de6",
    ),
    "macos-aarch64": (
        "uv-aarch64-apple-darwin.tar.gz",
        "b5f4cb27a3002d6590c3681377c6d826db0b52e2a9529c7144fcd53fec89ba79",
    ),
    "macos-x86_64": (
        "uv-x86_64-apple-darwin.tar.gz",
        "97980b067dc3fea16534371b030eaf38554d701de5058004edcfd542a88a2e84",
    ),
}


class UvSupplyChainTests(unittest.TestCase):
    def test_official_asset_names_urls_and_hashes_are_exact(self) -> None:
        versions = json.loads((ROOT / "tools/tool-versions.json").read_text())
        uv = versions["uv"]
        self.assertEqual(uv["version"], "0.7.11")
        self.assertEqual(
            uv["release_url"],
            "https://github.com/astral-sh/uv/releases/download/0.7.11",
        )
        actual = {
            platform_key: (entry["name"], entry["sha256"])
            for platform_key, entry in uv["assets"].items()
        }
        self.assertEqual(actual, OFFICIAL_UV_ASSETS)

    def test_wrong_pinned_hash_fails_before_install(self) -> None:
        payload = b"synthetic uv archive"
        actual_hash = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "uv-test.tar.gz"
            sidecar = Path(tmp) / "uv-test.tar.gz.sha256"
            archive.write_bytes(payload)
            sidecar.write_text(f"{actual_hash}  {archive.name}\n")
            with self.assertRaises(IntegrityError):
                verify_download(archive, sidecar, "0" * 64)

    def test_corrupted_archive_fails_official_sidecar_check(self) -> None:
        expected_hash = hashlib.sha256(b"expected").hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "uv-test.tar.gz"
            sidecar = Path(tmp) / "uv-test.tar.gz.sha256"
            archive.write_bytes(b"corrupt")
            sidecar.write_text(f"{expected_hash}  {archive.name}\n")
            with self.assertRaises(IntegrityError):
                verify_download(archive, sidecar, expected_hash)

    def test_ci_uses_verified_installer_and_never_pip_installs_uv(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertNotIn("pip install", workflow.lower())
        self.assertGreaterEqual(workflow.count("scripts/install_uv.py"), 3)
        self.assertIn("--platform linux-x86_64", workflow)
        self.assertIn("--platform macos-aarch64", workflow)
        for _, sha256 in OFFICIAL_UV_ASSETS.values():
            if sha256 == OFFICIAL_UV_ASSETS["macos-x86_64"][1]:
                continue
            self.assertIn(sha256, workflow)


if __name__ == "__main__":
    unittest.main()
