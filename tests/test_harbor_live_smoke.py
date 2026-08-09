from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from nano_grok_build.harbor import live_smoke
from nano_grok_build.harbor.live_smoke import (
    LIVE_TASK_FIXTURE_SHA256,
    LiveSmokeError,
    build_dry_run_metadata,
    expected_runtime_capabilities,
    live_fixture_profile_binding,
    prepare_live_smoke,
    probe_runtime_binary,
    runtime_source_identity,
    xai_credential_present,
)
from nano_grok_build.harbor.provider import HostProviderLaunch, runtime_command


def _write_runtime_profile(root: Path) -> None:
    (root / "effective-contract.json").write_text("{}\n")
    (root / "contract-delta.json").write_text("{}\n")
    (root / "agent-profile.json").write_text(
        json.dumps(
            {
                "schema_version": "agent-profile-v1",
                "profile_id": "ordinary-runtime-profile",
                "contract_id": "compatibility-receipt",
                "tools": {"model_tool_output_bytes_per_call": 65_536},
                "scheduler": {
                    "max_function_calls_per_run": 64,
                    "max_function_calls_per_response": 8,
                },
            },
            separators=(",", ":"),
        )
        + "\n"
    )


def test_provider_launch_is_typed_and_never_accepts_credentials(
    tmp_path: Path,
) -> None:
    xai = HostProviderLaunch.xai()
    assert xai.to_config() == {"kind": "xai"}
    assert HostProviderLaunch.from_config({"kind": "xai"}) == xai
    with pytest.raises(ValueError):
        HostProviderLaunch.from_config(
            {"kind": "xai", "api_key": "synthetic-credential-marker"}
        )

    command = runtime_command(
        binary_path=tmp_path / "nano-cli",
        spec_path=tmp_path / "run-spec.json",
        contract_dir=tmp_path / "contract",
        provider=xai,
    )
    assert command[-3:] == ("xai", "--executor", "external-stdio")
    assert "--completion-review" not in command
    assert "--expected-contract-id" not in command
    encoded = json.dumps({"launch": xai.to_config(), "command": command})
    assert "api_key" not in encoded
    assert "XAI_API_KEY" not in encoded


def test_runtime_command_rejects_governance_binding_arguments(
    tmp_path: Path,
) -> None:
    with pytest.raises(TypeError, match="expected_contract_binding"):
        runtime_command(
            binary_path=tmp_path / "nano-cli",
            spec_path=tmp_path / "run-spec.json",
            contract_dir=tmp_path / "contract",
            provider=HostProviderLaunch.xai(),
            expected_contract_binding=object(),
        )


def test_credential_check_is_boolean_only() -> None:
    marker = "synthetic-" + "credential-marker"
    assert xai_credential_present({}) is False
    assert xai_credential_present({"XAI_API_KEY": ""}) is False
    assert xai_credential_present({"XAI_API_KEY": marker}) is True


def test_ordinary_runtime_profile_prepares_without_governance_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkout = tmp_path / "harbor"
    checkout.mkdir()
    binary = tmp_path / "nano-cli"
    binary.write_bytes(b"#!/bin/sh\n")
    binary.chmod(0o700)
    contract = tmp_path / "contract"
    contract.mkdir()
    _write_runtime_profile(contract)
    output = tmp_path / "output"
    monkeypatch.setattr(live_smoke, "LIVE_TASK_FIXTURE_SHA256", "f" * 64)
    monkeypatch.setattr(
        "nano_grok_build.harbor.live_smoke.assert_harbor_pin",
        lambda _: None,
    )
    monkeypatch.setattr(
        live_smoke,
        "select_runtime_binary",
        lambda *_args, **_kwargs: (binary.resolve(), "a" * 64, "b" * 40),
    )
    monkeypatch.setattr(
        live_smoke,
        "_live_fixture_sha256",
        lambda _task_dir: "f" * 64,
    )
    monkeypatch.setattr(
        live_smoke,
        "load_runtime_inputs",
        lambda **_kwargs: SimpleNamespace(
            binary_path=binary.resolve(),
            contract_dir=contract.resolve(),
            provider_launch=HostProviderLaunch.xai(),
            contract_id="compatibility-receipt",
            contract_set_sha256="c" * 64,
            profile_id="ordinary-runtime-profile",
            provider_model=live_smoke.LIVE_MODEL,
            max_turns=live_smoke.LIVE_MAX_TURNS,
        ),
    )

    plan = prepare_live_smoke(
        harbor_checkout=checkout,
        binary_path=binary,
        contract_dir=contract,
        output_dir=output,
        repository=Path(__file__).resolve().parents[1],
    )

    assert plan.inputs.profile_id == "ordinary-runtime-profile"
    assert not output.exists()


def test_dry_run_metadata_is_redacted_and_one_trial_only() -> None:
    marker = "synthetic-" + "credential-marker"
    metadata = build_dry_run_metadata(
        task_timeout_sec=45,
        max_turns=4,
        credential_present=True,
    )
    encoded = json.dumps(metadata, sort_keys=True)
    assert metadata["status"] == "dry-run-passed"
    assert metadata["trial_count"] == 1
    assert metadata["retry_count"] == 0
    assert metadata["network_calls"] == 0
    assert metadata["docker_calls"] == 0
    assert "contract_id" not in metadata
    assert "contract_set_sha256" not in metadata
    assert marker not in encoded
    assert "XAI_API_KEY" not in encoded


def test_live_toy_instruction_requires_the_verifier_transport_exercise() -> None:
    instruction = (
        Path(__file__).parent / "harbor" / "toy-task" / "instruction.md"
    ).read_text(encoding="utf-8")
    assert "nano-sentinel.txt" in instruction
    assert "4,096" in instruction


def test_live_fixture_is_separate_from_synthetic_cap_regression() -> None:
    root = Path(__file__).parent / "harbor"
    synthetic = (root / "toy-task" / "tests" / "test.sh").read_text()
    live = (root / "live-task" / "tests" / "test.sh").read_text()
    assert "4096" in synthetic
    assert "stdout.size" in synthetic
    assert "4096" not in live
    assert "stdout.size" not in live


def test_preserved_successful_attempt_facts_reward_corrected_live_verifier(
    tmp_path: Path,
) -> None:
    root = Path(__file__).parent / "harbor" / "live-task"
    workspace = tmp_path / "workspace"
    logs = tmp_path / "logs"
    workspace.mkdir()
    logs.mkdir()
    (workspace / "nano-sentinel.txt").write_text(
        "NANO_REMOTE_OK",
        encoding="utf-8",
    )
    # Attempt 2 retained 20,000 bytes under the reviewed 65,536-byte cap.
    (workspace / "preserved-stdout.bin").write_bytes(b"\0" * 20_000)
    environment = {
        name: value for name, value in os.environ.items() if "KEY" not in name.upper()
    }
    environment["NANO_LIVE_WORKSPACE"] = str(workspace)
    environment["NANO_LIVE_LOGS"] = str(logs)
    result = subprocess.run(
        [str(root / "tests" / "test.sh")],
        check=False,
        capture_output=True,
        env=environment,
    )
    assert result.returncode == 0
    assert (logs / "reward.txt").read_text(encoding="utf-8") == "1\n"


def test_live_fixture_and_reviewed_profile_are_digest_bound(
    tmp_path: Path,
) -> None:
    source = Path(__file__).parent / "harbor" / "live-task"
    binding = live_fixture_profile_binding(
        source,
        model_output_cap_bytes=65_536,
    )
    assert binding.fixture_sha256 == LIVE_TASK_FIXTURE_SHA256

    changed = tmp_path / "live-task"
    shutil.copytree(source, changed)
    with (changed / "instruction.md").open("a", encoding="utf-8") as handle:
        handle.write("\ndrift\n")
    with pytest.raises(LiveSmokeError, match="live_fixture_mismatch"):
        live_fixture_profile_binding(
            changed,
            model_output_cap_bytes=65_536,
        )


def test_stale_pre_external_stdio_binary_fails_capability_probe(
    tmp_path: Path,
) -> None:
    stale = tmp_path / "nano-cli"
    stale.write_text(
        "#!/bin/sh\nprintf '%s\\n' 'nano run failed: usage_invalid' >&2\nexit 1\n",
        encoding="utf-8",
    )
    stale.chmod(0o700)
    with pytest.raises(LiveSmokeError, match="runtime_capability_probe_failed"):
        probe_runtime_binary(
            stale,
        )


def test_capability_probe_treats_source_and_git_as_record_only(tmp_path: Path) -> None:
    expected = {
        **expected_runtime_capabilities(
            source_tree_sha256="a" * 64,
            git_head="b" * 40,
        ),
        "event_schema": "event-v3",
        "run_record_schema": "nano-run-record-v2",
    }
    binary = tmp_path / "nano-cli"
    payload = json.dumps(expected, separators=(",", ":"))
    binary.write_text(
        f"#!/bin/sh\nprintf '%s\\n' '{payload}'\n",
        encoding="utf-8",
    )
    binary.chmod(0o700)
    assert (
        probe_runtime_binary(
            binary,
        )
        == binary
    )

    wrong = {**expected, "source_tree_sha256": "c" * 64}
    payload = json.dumps(wrong, separators=(",", ":"))
    binary.write_text(
        f"#!/bin/sh\nprintf '%s\\n' '{payload}'\n",
        encoding="utf-8",
    )
    assert probe_runtime_binary(binary) == binary


def test_external_binary_selection_uses_only_binary_capability_records(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability = expected_runtime_capabilities(
        source_tree_sha256="a" * 64,
        git_head="b" * 40,
    )
    binary = tmp_path / "nano-cli"
    payload = json.dumps(capability, separators=(",", ":"))
    binary.write_text(
        f"#!/bin/sh\nprintf '%s\\n' '{payload}'\n",
        encoding="utf-8",
    )
    binary.chmod(0o700)
    monkeypatch.setattr(
        live_smoke,
        "runtime_source_identity",
        lambda _repository: (_ for _ in ()).throw(
            AssertionError("external binary inspected host source")
        ),
    )
    monkeypatch.setattr(
        live_smoke,
        "runtime_git_head",
        lambda _repository: (_ for _ in ()).throw(
            AssertionError("external binary inspected host Git")
        ),
    )

    selected, source_sha256, git_head = live_smoke.select_runtime_binary(
        tmp_path,
        binary_path=binary,
        cargo="cargo",
    )

    assert selected == binary
    assert source_sha256 == "a" * 64
    assert git_head == "b" * 40


@pytest.mark.parametrize(
    "mutation",
    (
        "missing_event_schema",
        "wrong_event_schema",
        "missing_run_record_schema",
        "wrong_run_record_schema",
        "unknown_field",
    ),
)
def test_capability_probe_rejects_schema_drift(
    tmp_path: Path,
    mutation: str,
) -> None:
    capability = {
        **expected_runtime_capabilities(
            source_tree_sha256="a" * 64,
            git_head="b" * 40,
        ),
        "event_schema": "event-v3",
        "run_record_schema": "nano-run-record-v2",
    }
    if mutation.startswith("missing_"):
        capability.pop(mutation.removeprefix("missing_"))
    elif mutation.startswith("wrong_"):
        capability[mutation.removeprefix("wrong_")] = "wrong-v0"
    else:
        capability["unknown_field"] = "forbidden"
    binary = tmp_path / "nano-cli"
    payload = json.dumps(capability, separators=(",", ":"))
    binary.write_text(
        f"#!/bin/sh\nprintf '%s\\n' '{payload}'\n",
        encoding="utf-8",
    )
    binary.chmod(0o700)

    with pytest.raises(LiveSmokeError, match="runtime_capability_mismatch"):
        probe_runtime_binary(
            binary,
        )


def test_runtime_source_identity_is_stable_and_covers_external_stdio() -> None:
    repository = Path(__file__).resolve().parents[1]
    first = runtime_source_identity(repository)
    second = runtime_source_identity(repository)
    assert first == second
    assert len(first) == 64
