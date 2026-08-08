from __future__ import annotations

import http.server
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from scripts import check as unified_check

ROOT = Path(__file__).resolve().parents[1]


class CountingHandler(http.server.BaseHTTPRequestHandler):
    requests = 0

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        type(self).requests += 1
        self.send_response(500)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        del format, args


def copy_policy_fixture(destination: Path) -> None:
    for name in (
        "Cargo.toml",
        "Cargo.lock",
        "pyproject.toml",
        "uv.lock",
        "NOTICE",
        "THIRD_PARTY_NOTICES.md",
    ):
        shutil.copy2(ROOT / name, destination / name)
    shutil.copytree(ROOT / "crates", destination / "crates")


class StaticPreflightOrderingTests(unittest.TestCase):
    def test_repository_cargo_wrapper_is_rejected_before_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            copy_policy_fixture(root)
            marker = root / "CARGO_WRAPPER_EXECUTED"
            wrapper = root / "wrapper.sh"
            wrapper.write_text(f'#!/bin/sh\ntouch {marker.as_posix()!r}\nexec "$@"\n')
            wrapper.chmod(0o755)
            cargo = root / ".cargo"
            cargo.mkdir()
            (cargo / "config.toml").write_text(
                f'[build]\nrustc-wrapper = "{wrapper.as_posix()}"\n'
            )

            result = subprocess.run(
                ["python3", str(ROOT / "scripts/check.py"), "--root", str(root)],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("repository-local Cargo config forbidden", result.stderr)
            self.assertFalse(marker.exists())

    def test_unified_entry_rejects_build_code_and_url_before_execution(self) -> None:
        CountingHandler.requests = 0
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CountingHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                copy_policy_fixture(root)
                marker = root / "BUILD_RS_EXECUTED"
                evil = root / "evil"
                (evil / "src").mkdir(parents=True)
                (evil / "Cargo.toml").write_text(
                    "[package]\n"
                    'name = "evil"\n'
                    'version = "0.0.0"\n'
                    'edition = "2024"\n'
                    'build = "build.rs"\n'
                    "[lib]\n"
                    'path = "src/lib.rs"\n'
                )
                (evil / "src/lib.rs").write_text("")
                (evil / "build.rs").write_text(
                    "fn main() { std::fs::write("
                    f'{marker.as_posix()!r}, "executed").unwrap(); }}\n'
                )
                nano_types = root / "crates/nano-types/Cargo.toml"
                nano_types.write_text(
                    nano_types.read_text()
                    + '\nevil = { path = "../../evil", version = "=0.0.0" }\n'
                )
                url = f"http://127.0.0.1:{server.server_port}/hatchling.whl"
                pyproject = root / "pyproject.toml"
                pyproject.write_text(
                    pyproject.read_text().replace(
                        'requires = ["hatchling==1.27.0"]',
                        f'requires = ["hatchling @ {url}"]',
                    )
                )

                result = subprocess.run(
                    [
                        "python3",
                        str(ROOT / "scripts/check.py"),
                        "--root",
                        str(root),
                        "--preflight-only",
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("static preflight", result.stderr.lower())
                self.assertFalse(marker.exists())
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        self.assertEqual(CountingHandler.requests, 0)

    def test_ci_preflight_precedes_every_uv_or_cargo_command(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        jobs_text = workflow.split("\njobs:\n", 1)[1]
        starts = list(re.finditer(r"(?m)^  (?P<name>[a-z0-9-]+):\n", jobs_text))
        checked = 0
        for index, start in enumerate(starts):
            end = starts[index + 1].start() if index + 1 < len(starts) else None
            job = jobs_text[start.start() : end]
            checked += 1
            preflight = job.find("python3 scripts/static_preflight.py")
            self.assertGreaterEqual(preflight, 0)
            command_positions = [
                position
                for token in (
                    '\n          "$nano_uv" ',
                    "\n          uv ",
                    "\n          cargo ",
                    "\n        run: uv ",
                )
                if (position := job.find(token)) >= 0
            ]
            self.assertTrue(command_positions)
            self.assertLess(preflight, min(command_positions))
        self.assertGreaterEqual(checked, 3)

    def test_documented_entry_never_requires_sync_before_preflight(self) -> None:
        readme = (ROOT / "README.md").read_text()
        headings = ("## Fastest local path", "## Local bootstrap")
        heading = next(candidate for candidate in headings if candidate in readme)
        local_bootstrap = readme.split(heading, 1)[1].split("## ", 1)[0]
        commands = local_bootstrap.split("```sh", 1)[1].split("```", 1)[0]
        self.assertIn("python3 scripts/check.py", commands)
        self.assertNotIn("uv sync", commands)
        self.assertNotIn("uv run", commands)

    def test_every_build_disables_isolation(self) -> None:
        checker = (ROOT / "scripts/check.py").read_text()
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        for text in (checker, workflow):
            for line in text.splitlines():
                if "uv build" in line:
                    self.assertIn("--no-build-isolation", line)

    def test_unified_entry_never_installs_or_implicitly_syncs_project(self) -> None:
        commands: list[tuple[str, ...]] = []

        def record(*command: str, **kwargs: object) -> None:
            del kwargs
            commands.append(command)

        with (
            mock.patch.object(sys, "argv", ["check.py"]),
            mock.patch.object(unified_check, "run", side_effect=record),
            mock.patch.object(
                unified_check, "exact_uv", return_value=Path("/verified/uv")
            ),
            mock.patch.object(unified_check, "wheel_smoke"),
            mock.patch.object(unified_check.shutil, "which", return_value=None),
        ):
            self.assertEqual(unified_check.main(), 0)

        syncs = [command for command in commands if command[1:2] == ("sync",)]
        self.assertEqual(len(syncs), 1)
        self.assertIn("--no-install-project", syncs[0])
        runs = [command for command in commands if command[1:2] == ("run",)]
        self.assertTrue(runs)
        for command in runs:
            self.assertIn("--no-sync", command)

    def test_ci_never_uses_implicit_project_install_or_sync(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        for line in workflow.splitlines():
            if "uv sync" in line:
                self.assertIn("--no-install-project", line)
            if "uv run" in line:
                self.assertIn("--no-sync", line)


if __name__ == "__main__":
    unittest.main()
