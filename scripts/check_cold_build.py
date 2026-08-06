#!/usr/bin/env python3
"""Observe a cold locked sync followed by a zero-resolution package build."""

from __future__ import annotations

import hashlib
import http.server
import os
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

IGNORED = shutil.ignore_patterns(
    ".git",
    ".review",
    ".local-tools",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "dist",
    "*.egg-info",
    "target",
)


class _CountingHandler(http.server.BaseHTTPRequestHandler):
    requests = 0

    def _reject(self) -> None:
        type(self).requests += 1
        self.send_response(500)
        self.end_headers()

    do_GET = _reject  # noqa: N815 - stdlib callback names
    do_HEAD = _reject  # noqa: N815 - stdlib callback names

    def log_message(self, format: str, *args: object) -> None:
        del format, args


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(
    command: list[str], root: Path, *, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=root,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )


def run_cold_build(root: Path, uv: Path) -> dict[str, int | str]:
    """Observe a cold no-project sync, source tests, build, and wheel smoke."""
    source_root = root.resolve()
    with tempfile.TemporaryDirectory(prefix="nano-cold-build.") as tmp:
        temporary_root = Path(tmp)
        checkout = temporary_root / "checkout"
        shutil.copytree(source_root, checkout, ignore=IGNORED)
        lock_path = checkout / "uv.lock"
        before = _sha256(lock_path)
        _CountingHandler.requests = 0
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _CountingHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            canary_index = f"http://127.0.0.1:{server.server_port}/simple"
            env = dict(os.environ)
            env.update(
                {
                    "PIP_INDEX_URL": canary_index,
                    "UV_DEFAULT_INDEX": canary_index,
                    "UV_INDEX_URL": canary_index,
                    "UV_NO_PROGRESS": "1",
                }
            )
            env.pop("UV_EXTRA_INDEX_URL", None)
            env["PYTHONPATH"] = os.pathsep.join([str(checkout / "src"), str(checkout)])
            _run(
                [
                    str(uv),
                    "sync",
                    "--frozen",
                    "--all-groups",
                    "--no-install-project",
                    "--no-python-downloads",
                    "--cache-dir",
                    str(temporary_root / "cold-sync-cache"),
                ],
                checkout,
                env=env,
            )

            python = checkout / ".venv/bin/python"
            if not python.is_file():
                python = checkout / ".venv/Scripts/python.exe"
            if not python.is_file():
                raise RuntimeError(
                    "cold sync did not create the locked Python environment"
                )

            _run(
                [
                    str(uv),
                    "run",
                    "--no-sync",
                    "--frozen",
                    "pytest",
                    "--ignore",
                    "tests/test_cold_build.py",
                ],
                checkout,
                env=env,
            )

            cache = temporary_root / "empty-build-cache"
            cache.mkdir()
            _run(
                [
                    str(uv),
                    "build",
                    "--no-build-isolation",
                    "--offline",
                    "--python",
                    str(python),
                    "--cache-dir",
                    str(cache),
                    "--out-dir",
                    str(checkout / "dist"),
                ],
                checkout,
                env=env,
            )

            wheels = sorted((checkout / "dist").glob("*.whl"))
            if len(wheels) != 1:
                raise RuntimeError(f"expected one built wheel, found {len(wheels)}")
            smoke_root = temporary_root / "wheel-smoke"
            _run(
                [
                    str(uv),
                    "venv",
                    "--python",
                    str(python),
                    "--no-python-downloads",
                    str(smoke_root),
                ],
                checkout,
                env=env,
            )
            smoke_python = smoke_root / "bin/python"
            _run(
                [
                    str(uv),
                    "pip",
                    "install",
                    "--python",
                    str(smoke_python),
                    "--no-index",
                    "--no-deps",
                    str(wheels[0]),
                ],
                checkout,
                env=env,
            )
            smoke_env = dict(env)
            smoke_env.pop("PYTHONPATH", None)
            _run(
                [str(smoke_python), "-I", "-c", "import nano_grok_build"],
                checkout,
                env=smoke_env,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

        after = _sha256(lock_path)
        distributions = sum(
            path.name.endswith((".whl", ".tar.gz"))
            for path in (checkout / "dist").iterdir()
        )
        return {
            "network_requests_during_flow": _CountingHandler.requests,
            "lock_sha256_before": before,
            "lock_sha256_after": after,
            "distributions": distributions,
            "tests_passed": 1,
            "wheel_imported": 1,
        }
