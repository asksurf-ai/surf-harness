"""Fresh-job launcher with retry/no-resume invariants."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nano_grok_build.harbor.compat_v020 import (
    RuntimeInputs,
    bind_run_specs,
    install_resolved_package_task_cache_seam,
)
from nano_grok_build.harbor.provider import HostProviderKind, HostProviderLaunch


@dataclass(frozen=True)
class BoundJob:
    job: Any
    run_specs: tuple[dict[str, Any], ...]


def _regular(path: Path) -> bytes:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError("runtime input must be an absolute regular file")
    return path.read_bytes()


def load_runtime_inputs(
    *,
    binary_path: Path,
    contract_dir: Path,
    provider_script_path: Path | None = None,
    provider_launch: HostProviderLaunch | None = None,
    max_turns: int | None = None,
    active_tools: tuple[str, ...] | None = None,
) -> RuntimeInputs:
    """Read one runtime profile and bind a host-only provider.

    The three basenames remain stable for compatibility. Governance content in
    ``contract-delta.json`` is deliberately not an admission input.
    """

    if (
        not binary_path.is_absolute()
        or binary_path.is_symlink()
        or not binary_path.is_file()
        or not binary_path.stat().st_mode & 0o111
    ):
        raise ValueError("runtime binary must be an absolute executable file")
    if (
        not contract_dir.is_absolute()
        or contract_dir.is_symlink()
        or not contract_dir.is_dir()
    ):
        raise ValueError("contract directory must be absolute")
    if provider_launch is not None and provider_script_path is not None:
        raise ValueError("provider selector is ambiguous")
    if provider_launch is None:
        if provider_script_path is None:
            raise ValueError("provider selector is required")
        provider_launch = HostProviderLaunch.scripted(provider_script_path)
    if provider_launch.kind is HostProviderKind.SCRIPTED:
        assert provider_launch.script_path is not None
        script = _regular(provider_launch.script_path)
        try:
            script_value = json.loads(script)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("provider script is invalid") from error
        if script_value.get("schema_version") != "scripted-provider-v1":
            raise ValueError("provider script schema mismatch")

    names = [
        "agent-profile.json",
        "contract-delta.json",
        "effective-contract.json",
    ]
    files = {name: _regular(contract_dir / name) for name in names}
    rows = [
        {
            "path": name,
            "byte_length": len(files[name]),
            "file_sha256": hashlib.sha256(files[name]).hexdigest(),
        }
        for name in names
    ]
    contract_set_sha256 = hashlib.sha256(
        json.dumps(rows, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    try:
        effective = json.loads(files["effective-contract.json"])
        profile = json.loads(files["agent-profile.json"])
        delta = json.loads(files["contract-delta.json"])
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("contract JSON is invalid") from error
    if not isinstance(effective, dict) or not isinstance(profile, dict):
        raise ValueError("runtime profile is invalid")
    contract_id = effective.get("contract_id")
    profile_provider = profile.get("provider")
    profile_context = profile.get("context")
    if (
        effective.get("schema_version") != "effective-contract-v1"
        or profile.get("schema_version") != "agent-profile-v1"
        or not isinstance(contract_id, str)
        or not contract_id
        or profile.get("contract_id") != contract_id
        or not isinstance(profile.get("profile_id"), str)
        or not profile["profile_id"]
        or not isinstance(profile_provider, dict)
        or profile_provider.get("provider_id") != provider_launch.kind.value
        or not isinstance(profile_context, dict)
        or not isinstance(delta, dict)
    ):
        raise ValueError("runtime profile mismatch")
    profile_max_turns = profile_context.get("max_provider_turns")
    if (
        isinstance(profile_max_turns, bool)
        or not isinstance(profile_max_turns, int)
        or profile_max_turns <= 0
    ):
        raise ValueError("contract provider turn limit is invalid")
    selected_max_turns = profile_max_turns if max_turns is None else max_turns
    if (
        isinstance(selected_max_turns, bool)
        or not isinstance(selected_max_turns, int)
        or selected_max_turns <= 0
        or selected_max_turns > profile_max_turns
    ):
        raise ValueError("selected provider turn limit is invalid")
    provider_model = profile_provider.get("model")
    if not isinstance(provider_model, str) or not provider_model:
        raise ValueError("contract provider model is invalid")
    reasoning_effort = profile_provider.get("reasoning_effort")
    if reasoning_effort is not None and (
        not isinstance(reasoning_effort, str) or not reasoning_effort
    ):
        raise ValueError("contract provider reasoning effort is invalid")
    if provider_launch.kind is HostProviderKind.XAI and (
        provider_model != "grok-4.6"
        or reasoning_effort != "high"
        or profile_provider.get("retry_max") != 0
    ):
        raise ValueError("reviewed xai provider contract is invalid")
    return RuntimeInputs(
        binary_path=binary_path.resolve(),
        contract_dir=contract_dir.resolve(),
        provider_launch=provider_launch,
        contract_id=contract_id,
        contract_set_sha256=contract_set_sha256,
        profile_id=profile["profile_id"],
        provider_model=provider_model,
        max_turns=selected_max_turns,
        active_tools=active_tools,
        reasoning_effort=reasoning_effort,
    )


def validate_job_config(config: Any) -> None:
    """Reject Harbor features that would change diagnostic cohort identity."""

    if config.n_attempts != 1:
        raise ValueError("nano baseline requires n_attempts=1")
    if config.retry.max_retries != 0:
        raise ValueError("nano baseline requires retry=0")
    if config.timeout_multiplier != 1.0:
        raise ValueError("task native timeout multiplier must remain 1")
    if any(
        value not in (None, 1.0)
        for value in (
            config.agent_timeout_multiplier,
            config.verifier_timeout_multiplier,
            config.agent_setup_timeout_multiplier,
            config.environment_build_timeout_multiplier,
        )
    ):
        raise ValueError("phase timeout multipliers must remain unset or 1")
    if not config.environment.delete:
        raise ValueError("Harbor environment deletion must remain enabled")
    if len(config.agents) != 1:
        raise ValueError("nano jobs require exactly one agent")
    agent = config.agents[0]
    if agent.include_logs or agent.exclude_logs or agent.resume_trajectory:
        raise ValueError("log filtering and resume are unsupported")


async def create_bound_job(config: Any, inputs: RuntimeInputs) -> BoundJob:
    """Create a truly fresh Job, then prebind all RunSpecs before execution."""

    validate_job_config(config)
    target = (Path(config.jobs_dir) / config.job_name).resolve()
    if target.exists():
        raise FileExistsError("fresh nano job path already exists")
    from harbor.job import Job

    job = await Job.create(config)
    if job.is_resuming:
        raise RuntimeError("Harbor unexpectedly entered resume mode")
    specs = bind_run_specs(job, inputs)
    install_resolved_package_task_cache_seam()
    return BoundJob(job=job, run_specs=tuple(specs))
