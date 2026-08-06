from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tomllib
from pathlib import Path
from types import ModuleType

from nano_grok_build.adapter.deadline import (
    DeadlineReservesV1,
    RunDeadlineReceiptV1,
    RunDeadlineV1,
)

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tests" / "harbor" / "run_background_service.py"
TASK = ROOT / "tests" / "harbor" / "background-task"


def load_runner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("run_background_service", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_fixture_is_shared_and_script_starts_background_tcp_service() -> None:
    task_config = (TASK / "task.toml").read_text(encoding="utf-8")
    parsed_config = tomllib.loads(task_config)
    verifier = (TASK / "tests" / "test.sh").read_text(encoding="utf-8")
    provider = json.loads((TASK / "scripted-provider.json").read_bytes())
    first = provider["steps"][0]["response"]["output"][0]
    arguments = json.loads(first["arguments_json"])

    assert 'environment_mode = "shared"' in task_config
    assert first["name"] == "run_terminal_command"
    assert arguments["background"] is True
    assert "IO::Socket::INET" in arguments["command"]
    assert "NANO_BACKGROUND_OK" in arguments["command"]
    assert "IO::Socket::INET" in verifier
    assert "NANO_BACKGROUND_OK" in verifier
    timeout_ms = int(parsed_config["agent"]["timeout_sec"] * 1_000)
    assert timeout_ms == 120_000
    reserves = DeadlineReservesV1()
    assert timeout_ms > reserves.total_ms
    receipt = RunDeadlineReceiptV1.bind(
        deadline=RunDeadlineV1.mint(
            source="test_host_phase",
            agent_timeout_ms=timeout_ms,
            now_monotonic_ns=1_000_000_000,
        ),
        run_id="background-service-preflight",
        trial_id="background-service-preflight",
        attempt_id="attempt-0",
        run_spec_sha256="a" * 64,
        reserves=reserves,
    )
    assert receipt.cutoffs.actor_done_monotonic_ns > 1_000_000_000


def test_plan_only_is_machine_readable_and_does_not_start_docker(
    tmp_path: Path,
) -> None:
    module = load_runner()
    checkout = tmp_path / "harbor"
    checkout.mkdir()
    binary = tmp_path / "nano-cli"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(0o700)
    output = tmp_path / "must-not-exist"
    commands: list[list[str]] = []

    def fake_run(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        assert command[:3] == ["git", "-C", str(checkout.resolve())]
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=module.HARBOR_COMMIT + "\n",
            stderr="",
        )

    summary = module.plan(
        harbor_checkout=checkout,
        binary=binary,
        output_dir=output,
        command_runner=fake_run,
    )

    assert summary == {
        "binary": str(binary.resolve()),
        "docker_calls": 0,
        "harbor_commit": module.HARBOR_COMMIT,
        "network_calls": 0,
        "output_dir": str(output.resolve()),
        "provider": "scripted",
        "retry_count": 0,
        "status": "plan-only",
        "task": "nano-grok-build/background-service",
        "tool_count": 8,
        "verifier_mode": "shared",
    }
    assert commands and all(command[0] != "docker" for command in commands)
    assert not output.exists()


def test_help_does_not_require_harbor_or_docker() -> None:
    result = subprocess.run(
        [sys.executable, str(RUNNER), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "--plan-only" in result.stdout
    assert "--harbor-checkout" in result.stdout
    assert "--binary" in result.stdout
