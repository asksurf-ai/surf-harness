#!/usr/bin/env python3
"""Unified bootstrap/check entry with a mandatory static first gate."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1]


def run(*command: str, root: Path, env: dict[str, str] | None = None) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=root, env=env, check=True)


def output(*command: str, root: Path) -> str:
    return subprocess.run(
        command,
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def exact_uv(root: Path) -> Path:
    versions = json.loads((root / "tools/tool-versions.json").read_text())
    expected = str(versions["uv"]["version"])
    candidates = [root / ".local-tools/bin/uv"]
    discovered = shutil.which("uv")
    if discovered:
        candidates.append(Path(discovered))
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            fields = output(str(candidate), "--version", root=root).split()
        except (OSError, subprocess.CalledProcessError):
            continue
        if fields[:2] == ["uv", expected]:
            return candidate.resolve()

    install_dir = root / ".local-tools/bin"
    run(
        sys.executable,
        str(SOURCE_ROOT / "scripts/install_uv.py"),
        "--install-dir",
        str(install_dir),
        root=root,
    )
    uv = install_dir / "uv"
    fields = output(str(uv), "--version", root=root).split()
    if fields[:2] != ["uv", expected]:
        raise RuntimeError("verified uv installer returned an unexpected version")
    return uv.resolve()


def wheel_smoke(
    root: Path,
    uv: Path,
    env: dict[str, str],
    distribution_dir: Path,
) -> None:
    wheels = sorted(distribution_dir.glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected one built wheel, found {len(wheels)}")
    with tempfile.TemporaryDirectory(prefix="nano-wheel-smoke.") as tmp:
        smoke_root = Path(tmp) / "venv"
        run(
            str(uv),
            "venv",
            "--python",
            str(root / ".venv/bin/python"),
            "--no-python-downloads",
            str(smoke_root),
            root=root,
            env=env,
        )
        smoke_python = smoke_root / "bin/python"
        run(
            str(uv),
            "pip",
            "install",
            "--python",
            str(smoke_python),
            "--no-index",
            "--no-deps",
            str(wheels[0]),
            root=root,
            env=env,
        )
        smoke_env = dict(env)
        smoke_env.pop("PYTHONPATH", None)
        run(
            str(smoke_python),
            "-I",
            "-c",
            "import nano_grok_build",
            root=root,
            env=smoke_env,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="run only the static, no-network gate",
    )
    parser.add_argument(
        "--require-external-scanners",
        action="store_true",
        help="fail unless pinned cargo-deny and gitleaks are installed",
    )
    args = parser.parse_args()
    root = args.root.resolve()

    # This must remain the first subprocess: no installer, uv, Cargo, or metadata
    # command may run until static policy has rejected executable dependency forms.
    run(
        sys.executable,
        str(SOURCE_ROOT / "scripts/static_preflight.py"),
        "--root",
        str(root),
        root=root,
    )
    if args.preflight_only:
        return 0

    uv = exact_uv(root)
    versions = json.loads((root / "tools/tool-versions.json").read_text())
    python_version = str(versions["python"]["version"])
    env = dict(os.environ)
    env["PATH"] = f"{uv.parent}{os.pathsep}{env.get('PATH', '')}"
    env["NANO_STATIC_PREFLIGHT_PASSED"] = "1"
    python_path = [str(root / "src"), str(root)]
    if env.get("PYTHONPATH"):
        python_path.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(python_path)

    run(str(uv), "python", "install", python_version, root=root, env=env)
    run(
        str(uv),
        "sync",
        "--frozen",
        "--all-groups",
        "--no-install-project",
        root=root,
        env=env,
    )

    with tempfile.TemporaryDirectory(prefix="nano-build-dist.") as tmp:
        distribution_dir = Path(tmp)
        commands = [
            (
                str(uv),
                "run",
                "--no-sync",
                "--frozen",
                "python",
                "scripts/bootstrap.py",
            ),
            ("cargo", "fmt", "--all", "--check"),
            (
                "cargo",
                "clippy",
                "--locked",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ),
            (
                "cargo",
                "test",
                "--locked",
                "--workspace",
                "--all-targets",
                "--all-features",
            ),
        ]
        if (root / "scripts/check_contract_approval_v2.py").is_file():
            commands.append(
                (
                    str(uv),
                    "run",
                    "--no-sync",
                    "--frozen",
                    "python",
                    "scripts/check_contract_approval_v2.py",
                    "policy",
                    "--approval-policy",
                    "policy/contracts/nano-v1-approval-v2.json",
                )
            )
        commands.extend(
            [
                (
                    str(uv),
                    "run",
                    "--no-sync",
                    "--frozen",
                    "ruff",
                    "format",
                    "--check",
                    ".",
                ),
                (str(uv), "run", "--no-sync", "--frozen", "ruff", "check", "."),
                (str(uv), "run", "--no-sync", "--frozen", "pytest"),
                (
                    str(uv),
                    "build",
                    "--no-build-isolation",
                    "--offline",
                    "--python",
                    str(root / ".venv/bin/python"),
                    "--out-dir",
                    str(distribution_dir),
                ),
            ]
        )
        for optional in (
            "check_exporter_policy.py",
            "check_provenance.py",
            "check_notices.py",
            "check_public_release.py",
        ):
            if (root / "scripts" / optional).is_file():
                commands.append(
                    (
                        str(uv),
                        "run",
                        "--no-sync",
                        "--frozen",
                        "python",
                        f"scripts/{optional}",
                    )
                )
        commands.extend(
            [
                (
                    str(uv),
                    "run",
                    "--no-sync",
                    "--frozen",
                    "python",
                    "scripts/check_dependency_policy.py",
                ),
                (
                    str(uv),
                    "run",
                    "--no-sync",
                    "--frozen",
                    "python",
                    "scripts/check_secrets.py",
                ),
            ]
        )
        for command in commands:
            run(*command, root=root, env=env)
            if command[1:2] == ("build",):
                wheel_smoke(root, uv, env, distribution_dir)

    cargo_deny = shutil.which("cargo-deny", path=env["PATH"])
    gitleaks = shutil.which("gitleaks", path=env["PATH"])
    if args.require_external_scanners and not cargo_deny:
        raise SystemExit("cargo-deny is required")
    if args.require_external_scanners and not gitleaks:
        raise SystemExit("gitleaks is required")
    if cargo_deny:
        run(cargo_deny, "check", root=root, env=env)
    if gitleaks:
        run(
            str(uv),
            "run",
            "--no-sync",
            "--frozen",
            "python",
            "scripts/check_gitleaks_canary.py",
            "--gitleaks",
            gitleaks,
            root=root,
            env=env,
        )
        run(
            str(uv),
            "run",
            "--no-sync",
            "--frozen",
            "python",
            "scripts/check_gitleaks_worktree.py",
            "--gitleaks",
            gitleaks,
            "--root",
            str(root),
            root=root,
            env=env,
        )
        run(gitleaks, "git", "--redact", "--no-banner", root=root, env=env)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        if isinstance(error, subprocess.CalledProcessError):
            raise SystemExit(error.returncode) from error
        raise SystemExit(str(error)) from error
