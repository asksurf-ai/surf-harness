from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from nano_grok_build.harbor.dispatch import (
    create_bound_job,
    load_runtime_inputs,
    validate_job_config,
)
from nano_grok_build.harbor.provider import HostProviderLaunch


def config(tmp_path: Path):
    agent = SimpleNamespace(
        include_logs=[],
        exclude_logs=[],
        resume_trajectory=False,
    )
    return SimpleNamespace(
        n_attempts=1,
        retry=SimpleNamespace(max_retries=0),
        timeout_multiplier=1.0,
        agent_timeout_multiplier=None,
        verifier_timeout_multiplier=None,
        agent_setup_timeout_multiplier=None,
        environment_build_timeout_multiplier=None,
        environment=SimpleNamespace(delete=True),
        agents=[agent],
        jobs_dir=tmp_path,
        job_name="fresh-job",
    )


def test_dispatch_rejects_retry_resume_and_existing_job(tmp_path: Path) -> None:
    value = config(tmp_path)
    validate_job_config(value)
    value.retry.max_retries = 1
    with pytest.raises(ValueError, match="retry=0"):
        validate_job_config(value)
    value.retry.max_retries = 0
    value.agents[0].resume_trajectory = True
    with pytest.raises(ValueError, match="unsupported"):
        validate_job_config(value)
    value.agents[0].resume_trajectory = False
    (tmp_path / value.job_name).mkdir()
    with pytest.raises(FileExistsError, match="fresh"):
        asyncio.run(create_bound_job(value, SimpleNamespace()))


def test_runtime_inputs_accept_an_ordinary_runtime_profile(tmp_path: Path) -> None:
    binary = tmp_path / "nano-cli"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(0o700)
    contract = tmp_path / "contract"
    contract.mkdir()
    effective = {
        "schema_version": "effective-contract-v1",
        "contract_id": "synthetic-v1",
    }
    profile = {
        "schema_version": "agent-profile-v1",
        "profile_id": "synthetic-profile-v1",
        "contract_id": "synthetic-v1",
        "provider": {
            "provider_id": "scripted",
            "model": "synthetic-model",
            "reasoning_effort": "high",
        },
        "context": {"max_provider_turns": 4},
    }
    delta: dict[str, object] = {}
    for name, value in (
        ("effective-contract.json", effective),
        ("agent-profile.json", profile),
        ("contract-delta.json", delta),
    ):
        (contract / name).write_text(
            json.dumps(value, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    script = tmp_path / "script.json"
    script.write_text(
        '{"schema_version":"scripted-provider-v1","steps":[]}\n',
        encoding="utf-8",
    )
    inputs = load_runtime_inputs(
        binary_path=binary.resolve(),
        contract_dir=contract.resolve(),
        provider_script_path=script.resolve(),
    )
    assert inputs.contract_id == "synthetic-v1"
    assert inputs.provider_model == "synthetic-model"
    assert inputs.reasoning_effort == "high"

    profile["provider"] = {
        "provider_id": "xai",
        "model": "grok-4.5",
        "reasoning_effort": "high",
        "retry_max": 0,
    }
    (contract / "agent-profile.json").write_text(
        json.dumps(profile, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    live_inputs = load_runtime_inputs(
        binary_path=binary.resolve(),
        contract_dir=contract.resolve(),
        provider_launch=HostProviderLaunch.xai(),
        max_turns=2,
        active_tools=(
            "run_terminal_command",
            "read_file",
            "search_replace",
            "write",
            "list_dir",
            "grep",
        ),
    )
    assert live_inputs.provider_launch == HostProviderLaunch.xai()
    assert live_inputs.provider_model == "grok-4.5"
    assert live_inputs.reasoning_effort == "high"
    assert live_inputs.max_turns == 2
    assert live_inputs.active_tools == (
        "run_terminal_command",
        "read_file",
        "search_replace",
        "write",
        "list_dir",
        "grep",
    )

    profile["provider"]["model"] = "future-xai-model"
    (contract / "agent-profile.json").write_text(
        json.dumps(profile, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="reviewed xai provider contract"):
        load_runtime_inputs(
            binary_path=binary.resolve(),
            contract_dir=contract.resolve(),
            provider_launch=HostProviderLaunch.xai(),
        )


def test_runtime_inputs_do_not_accept_governance_selectors(tmp_path: Path) -> None:
    binary = tmp_path / "nano-cli"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(0o700)
    contract = tmp_path / "runtime-profile"
    contract.mkdir()
    effective = {
        "schema_version": "effective-contract-v1",
        "contract_id": "runtime-profile",
    }
    profile = {
        "schema_version": "agent-profile-v1",
        "profile_id": "runtime-profile-xai",
        "contract_id": "runtime-profile",
        "provider": {
            "provider_id": "xai",
            "model": "grok-4.5",
            "reasoning_effort": "high",
            "retry_max": 0,
        },
        "context": {"max_provider_turns": 64},
    }
    delta: dict[str, object] = {}
    for name, value in (
        ("effective-contract.json", effective),
        ("agent-profile.json", profile),
        ("contract-delta.json", delta),
    ):
        (contract / name).write_text(
            json.dumps(value, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    inputs = load_runtime_inputs(
        binary_path=binary.resolve(),
        contract_dir=contract.resolve(),
        provider_launch=HostProviderLaunch.xai(),
    )
    assert inputs.contract_id == "runtime-profile"
    assert inputs.profile_id == "runtime-profile-xai"

    with pytest.raises(TypeError, match="approved_r2"):
        load_runtime_inputs(
            binary_path=binary.resolve(),
            contract_dir=contract.resolve(),
            provider_launch=HostProviderLaunch.xai(),
            approved_r2=True,
        )

    with pytest.raises(TypeError, match="approved_binding"):
        load_runtime_inputs(
            binary_path=binary.resolve(),
            contract_dir=contract.resolve(),
            provider_launch=HostProviderLaunch.xai(),
            approved_binding=SimpleNamespace(),
        )
