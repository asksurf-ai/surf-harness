"""One-trial xAI + Harbor smoke preparation and execution."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import stat
import subprocess
import sys
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from nano_grok_build import __version__
from nano_grok_build.adapter.stdio_bridge import REMOTE_ENVIRONMENT_ALLOWLIST
from nano_grok_build.harbor.compat_v020 import RuntimeInputs
from nano_grok_build.harbor.dispatch import create_bound_job, load_runtime_inputs
from nano_grok_build.harbor.provider import HostProviderLaunch, runtime_command

HARBOR_COMMIT = "459ff6ec99417589b7f679d14ddf3b3f0ae4f1dc"
LIVE_MODEL = "grok-4.6"
LIVE_MAX_TURNS = 4
LIVE_TASK_FIXTURE_SHA256 = (
    "dce7208e343c9f4a8d062fa9a9f88ca656d4f7b5a38557a58d7f201cf6e33c55"
)
CAPABILITIES_SCHEMA = "nano-cli-capabilities-v2"
_MAX_CAPABILITY_BYTES = 16 * 1024
_RUNTIME_SOURCE_ROOTS = ("Cargo.lock", "Cargo.toml", "rust-toolchain.toml")
_KNOWN_TOOLS = (
    "run_terminal_command",
    "read_file",
    "search_replace",
    "write",
    "list_dir",
    "grep",
    "kill_terminal_command",
    "get_terminal_command_output",
)
_LIVE_TASK_FILES = (
    "environment/Dockerfile",
    "instruction.md",
    "task.toml",
    "tests/test.sh",
)


class LiveSmokeError(RuntimeError):
    """A generic fail-closed live-smoke error safe to print."""


@dataclass(frozen=True)
class LiveSmokePlan:
    repository: Path
    harbor_checkout: Path
    output_dir: Path
    task_dir: Path
    inputs: RuntimeInputs
    task_timeout_sec: int
    tool_call_limit: int
    runtime_source_sha256: str
    runtime_git_head: str
    runtime_binary_sha256: str
    live_fixture_sha256: str
    profile_output_cap_bytes: int


@dataclass(frozen=True)
class LiveFixtureBinding:
    fixture_sha256: str
    model_output_cap_bytes: int


def _read_regular(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise LiveSmokeError("required_input_unavailable") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise LiveSmokeError("required_input_unavailable")
    try:
        return path.read_bytes()
    except OSError as error:
        raise LiveSmokeError("required_input_unavailable") from error


def _live_fixture_sha256(task_dir: Path) -> str:
    if not task_dir.is_absolute() or task_dir.is_symlink() or not task_dir.is_dir():
        raise LiveSmokeError("live_fixture_unavailable")
    files = sorted(
        path.relative_to(task_dir).as_posix()
        for path in task_dir.rglob("*")
        if path.is_file()
    )
    if files != list(_LIVE_TASK_FILES):
        raise LiveSmokeError("live_fixture_mismatch")
    rows = []
    for name in files:
        raw = _read_regular(task_dir / name)
        rows.append(
            {
                "path": name,
                "byte_length": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    encoded = json.dumps(rows, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def live_fixture_profile_binding(
    task_dir: Path,
    *,
    model_output_cap_bytes: int,
) -> LiveFixtureBinding:
    fixture_sha256 = _live_fixture_sha256(task_dir.resolve())
    if (
        fixture_sha256 != LIVE_TASK_FIXTURE_SHA256
        or isinstance(model_output_cap_bytes, bool)
        or not isinstance(model_output_cap_bytes, int)
        or model_output_cap_bytes <= 0
    ):
        raise LiveSmokeError("live_fixture_mismatch")
    return LiveFixtureBinding(
        fixture_sha256=fixture_sha256,
        model_output_cap_bytes=model_output_cap_bytes,
    )


def assert_harbor_pin(checkout: Path) -> None:
    if not checkout.is_absolute() or checkout.is_symlink() or not checkout.is_dir():
        raise LiveSmokeError("harbor_checkout_invalid")
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=checkout,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as error:
        raise LiveSmokeError("harbor_checkout_invalid") from error
    if head != HARBOR_COMMIT:
        raise LiveSmokeError("harbor_pin_mismatch")


def xai_credential_present(environment: Mapping[str, str]) -> bool:
    """Return presence only; never return, transform, or log credential bytes."""

    return bool(environment.get("XAI_API_KEY"))


def runtime_source_identity(repository: Path) -> str:
    """Hash the complete local Rust workspace source used for this binary."""

    repository = repository.resolve()
    paths = [repository / name for name in _RUNTIME_SOURCE_ROOTS]
    crates = repository / "crates"
    if not crates.is_dir() or crates.is_symlink():
        raise LiveSmokeError("runtime_source_unavailable")
    paths.extend(
        path
        for path in crates.rglob("*")
        if path.is_file() and (path.name == "Cargo.toml" or path.suffix == ".rs")
    )
    rows = []
    for path in sorted(paths, key=lambda item: item.relative_to(repository).as_posix()):
        raw = _read_regular(path)
        rows.append(
            {
                "path": path.relative_to(repository).as_posix(),
                "byte_length": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    if not rows:
        raise LiveSmokeError("runtime_source_unavailable")
    encoded = json.dumps(rows, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def runtime_git_head(repository: Path) -> str:
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as error:
        raise LiveSmokeError("runtime_git_identity_unavailable") from error
    if len(head) != 40 or any(
        not (character.isdigit() or "a" <= character <= "f") for character in head
    ):
        raise LiveSmokeError("runtime_git_identity_unavailable")
    return head


def expected_runtime_capabilities(
    *, source_tree_sha256: str, git_head: str
) -> dict[str, object]:
    return {
        "schema_version": CAPABILITIES_SCHEMA,
        "binary_version": __version__,
        "source_tree_sha256": source_tree_sha256,
        "git_head": git_head,
        "run_spec_schema": "nano-run-spec-alpha-2",
        "event_schema": "event-v3",
        "run_record_schema": "nano-run-record-v2",
        "external_tool_schema": "external-tool-stdio-v2",
        "providers": ["scripted", "xai"],
        "executors": ["default", "external-stdio"],
        "provider_model_source": "contract-profile",
        "known_tools": list(_KNOWN_TOOLS),
        "dispatchable_tools": list(_KNOWN_TOOLS),
    }


def _non_secret_environment() -> dict[str, str]:
    forbidden = ("KEY", "TOKEN", "SECRET", "AUTHORIZATION")
    return {
        name: value
        for name, value in os.environ.items()
        if not any(fragment in name.upper() for fragment in forbidden)
    }


def _probe_runtime_binary(binary_path: Path) -> tuple[Path, str, str]:
    """Require one exact capability document from the selected host binary."""

    binary_path = binary_path.resolve()
    try:
        metadata = binary_path.lstat()
    except OSError as error:
        raise LiveSmokeError("runtime_binary_unavailable") from error
    if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111:
        raise LiveSmokeError("runtime_binary_unavailable")
    try:
        result = subprocess.run(
            [str(binary_path), "capabilities"],
            check=False,
            capture_output=True,
            timeout=10,
            env=_non_secret_environment(),
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise LiveSmokeError("runtime_capability_probe_failed") from error
    if (
        result.returncode != 0
        or result.stderr
        or not result.stdout.endswith(b"\n")
        or len(result.stdout) > _MAX_CAPABILITY_BYTES
        or len(result.stdout.splitlines()) != 1
    ):
        raise LiveSmokeError("runtime_capability_probe_failed")
    try:
        capability = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LiveSmokeError("runtime_capability_probe_failed") from error
    source_tree_sha256 = (
        capability.get("source_tree_sha256") if isinstance(capability, dict) else None
    )
    git_head = capability.get("git_head") if isinstance(capability, dict) else None
    if (
        not isinstance(source_tree_sha256, str)
        or len(source_tree_sha256) != 64
        or any(character not in "0123456789abcdef" for character in source_tree_sha256)
        or not isinstance(git_head, str)
        or len(git_head) != 40
        or any(character not in "0123456789abcdef" for character in git_head)
    ):
        raise LiveSmokeError("runtime_capability_mismatch")
    expected = expected_runtime_capabilities(
        source_tree_sha256=source_tree_sha256,
        git_head=git_head,
    )
    if capability != expected:
        raise LiveSmokeError("runtime_capability_mismatch")
    return binary_path, source_tree_sha256, git_head


def probe_runtime_binary(binary_path: Path) -> Path:
    """Validate runtime capabilities without host source/Git admission."""

    selected, _source_tree_sha256, _git_head = _probe_runtime_binary(binary_path)
    return selected


def build_workspace_runtime(
    repository: Path,
    *,
    cargo: str,
    source_tree_sha256: str,
    git_head: str,
) -> Path:
    """Offline-build the current workspace into an isolated live-smoke target."""

    if not cargo or "\x00" in cargo:
        raise LiveSmokeError("cargo_command_invalid")
    target_dir = repository / "target" / "live-smoke"
    environment = _non_secret_environment()
    cargo_path = Path(cargo)
    if cargo_path.is_absolute():
        environment["PATH"] = (
            str(cargo_path.parent) + os.pathsep + environment.get("PATH", "")
        )
    environment["NANO_SOURCE_TREE_SHA256"] = source_tree_sha256
    environment["NANO_BUILD_GIT_HEAD"] = git_head
    try:
        result = subprocess.run(
            [
                cargo,
                "build",
                "--release",
                "--locked",
                "--offline",
                "--target-dir",
                str(target_dir),
                "-p",
                "nano-cli",
                "--bin",
                "nano-cli",
            ],
            cwd=repository,
            env=environment,
            check=False,
            capture_output=True,
            timeout=600,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise LiveSmokeError("runtime_offline_build_failed") from error
    if result.returncode != 0:
        raise LiveSmokeError("runtime_offline_build_failed")
    suffix = ".exe" if os.name == "nt" else ""
    return probe_runtime_binary(target_dir / "release" / f"nano-cli{suffix}")


def select_runtime_binary(
    repository: Path,
    *,
    binary_path: Path | None,
    cargo: str,
) -> tuple[Path, str, str]:
    if binary_path is None:
        source_tree_sha256 = runtime_source_identity(repository)
        git_head = runtime_git_head(repository)
        selected = build_workspace_runtime(
            repository,
            cargo=cargo,
            source_tree_sha256=source_tree_sha256,
            git_head=git_head,
        )
    else:
        selected = binary_path
    return _probe_runtime_binary(selected)


def _task_timeout(task_dir: Path) -> int:
    raw = _read_regular(task_dir / "task.toml")
    try:
        task = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise LiveSmokeError("live_task_bounds_invalid") from error
    timeout = task.get("agent", {}).get("timeout_sec")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, int | float)
        or timeout <= 0
        or timeout > 180
        or not float(timeout).is_integer()
    ):
        raise LiveSmokeError("live_task_bounds_invalid")
    return int(timeout)


def prepare_live_smoke(
    *,
    harbor_checkout: Path,
    binary_path: Path | None,
    cargo: str = "cargo",
    contract_dir: Path,
    output_dir: Path,
    repository: Path,
) -> LiveSmokePlan:
    """Validate every local input without creating output, Docker, or network."""

    repository = repository.resolve()
    harbor_checkout = harbor_checkout.resolve()
    if (
        not contract_dir.is_absolute()
        or contract_dir.is_symlink()
        or not contract_dir.is_dir()
    ):
        raise LiveSmokeError("runtime_profile_unavailable")
    contract_dir = contract_dir.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists() or output_dir.is_symlink():
        raise LiveSmokeError("fresh_output_required")
    assert_harbor_pin(harbor_checkout)
    profile = json.loads(_read_regular(contract_dir / "agent-profile.json"))
    profile_output_cap = profile.get("tools", {}).get(
        "model_tool_output_bytes_per_call"
    )
    if (
        isinstance(profile_output_cap, bool)
        or not isinstance(profile_output_cap, int)
        or profile_output_cap <= 0
    ):
        raise LiveSmokeError("live_fixture_profile_mismatch")
    task_dir = repository / "tests" / "harbor" / "live-task"
    fixture_binding = live_fixture_profile_binding(
        task_dir,
        model_output_cap_bytes=profile_output_cap,
    )
    task_timeout = _task_timeout(task_dir)
    (
        selected_binary,
        source_tree_sha256,
        git_head,
    ) = select_runtime_binary(
        repository,
        binary_path=binary_path,
        cargo=cargo,
    )
    inputs = load_runtime_inputs(
        binary_path=selected_binary,
        contract_dir=contract_dir,
        provider_launch=HostProviderLaunch.xai(),
        max_turns=LIVE_MAX_TURNS,
    )
    if inputs.provider_model != LIVE_MODEL or inputs.max_turns != LIVE_MAX_TURNS:
        raise LiveSmokeError("runtime_profile_binding_invalid")
    scheduler = profile.get("scheduler", {})
    per_run_limit = scheduler.get("max_function_calls_per_run")
    per_response_limit = scheduler.get("max_function_calls_per_response")
    if (
        isinstance(per_run_limit, bool)
        or not isinstance(per_run_limit, int)
        or per_run_limit <= 0
        or per_run_limit > 256
        or isinstance(per_response_limit, bool)
        or not isinstance(per_response_limit, int)
        or per_response_limit <= 0
        or per_response_limit > 16
    ):
        raise LiveSmokeError("live_tool_bounds_invalid")
    tool_call_limit = min(
        per_run_limit,
        per_response_limit * inputs.max_turns,
    )
    forbidden = ("KEY", "TOKEN", "SECRET", "AUTHORIZATION")
    if any(
        fragment in name.upper()
        for name in REMOTE_ENVIRONMENT_ALLOWLIST
        for fragment in forbidden
    ):
        raise LiveSmokeError("container_environment_allowlist_invalid")
    preview = runtime_command(
        binary_path=inputs.binary_path,
        spec_path=output_dir / "run-spec.json",
        contract_dir=inputs.contract_dir,
        provider=inputs.provider_launch,
    )
    if preview[-3:] != ("xai", "--executor", "external-stdio"):
        raise LiveSmokeError("live_command_invalid")
    return LiveSmokePlan(
        repository=repository,
        harbor_checkout=harbor_checkout,
        output_dir=output_dir,
        task_dir=task_dir,
        inputs=inputs,
        task_timeout_sec=task_timeout,
        tool_call_limit=tool_call_limit,
        runtime_source_sha256=source_tree_sha256,
        runtime_git_head=git_head,
        runtime_binary_sha256=hashlib.sha256(
            _read_regular(selected_binary)
        ).hexdigest(),
        live_fixture_sha256=fixture_binding.fixture_sha256,
        profile_output_cap_bytes=fixture_binding.model_output_cap_bytes,
    )


def build_dry_run_metadata(
    *,
    task_timeout_sec: int,
    max_turns: int,
    tool_call_limit: int = 64,
    credential_present: bool,
) -> dict[str, object]:
    return {
        "status": "dry-run-passed",
        "provider": "xai",
        "model": LIVE_MODEL,
        "task_timeout_sec": task_timeout_sec,
        "max_turns": max_turns,
        "tool_call_limit": tool_call_limit,
        "trial_count": 1,
        "retry_count": 0,
        "resume": False,
        "credential_present": credential_present,
        "network_calls": 0,
        "docker_calls": 0,
    }


def dry_run_metadata(
    plan: LiveSmokePlan, *, credential_present: bool
) -> dict[str, object]:
    metadata = build_dry_run_metadata(
        task_timeout_sec=plan.task_timeout_sec,
        max_turns=plan.inputs.max_turns,
        tool_call_limit=plan.tool_call_limit,
        credential_present=credential_present,
    )
    metadata["runtime_source_sha256"] = plan.runtime_source_sha256
    metadata["runtime_git_head"] = plan.runtime_git_head
    metadata["runtime_binary_sha256"] = plan.runtime_binary_sha256
    metadata["live_fixture_sha256"] = plan.live_fixture_sha256
    metadata["profile_output_cap_bytes"] = plan.profile_output_cap_bytes
    return metadata


def _residual_containers(project: str) -> list[str]:
    result = subprocess.run(
        [
            "docker",
            "ps",
            "-aq",
            "--filter",
            f"label=com.docker.compose.project={project}",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return [line for line in result.stdout.splitlines() if line]


async def run_live_smoke(plan: LiveSmokePlan) -> dict[str, object]:
    """Run exactly one fresh Harbor trial; no retry or resume path exists."""

    sys.path.insert(0, str(plan.harbor_checkout / "src"))
    from harbor.models.job.config import JobConfig, RetryConfig
    from harbor.models.trial.config import (
        AgentConfig,
        EnvironmentConfig,
        TaskConfig,
    )

    plan.output_dir.mkdir(parents=True, exist_ok=False)
    config = JobConfig(
        job_name="nano-xai-live-smoke",
        jobs_dir=plan.output_dir / "jobs",
        n_attempts=1,
        n_concurrent_trials=1,
        quiet=True,
        retry=RetryConfig(max_retries=0),
        environment=EnvironmentConfig(type="docker", delete=True),
        agents=[
            AgentConfig(
                import_path="nano_grok_build.adapter.harbor:NanoGrokBuildAgent",
                model_name=LIVE_MODEL,
            )
        ],
        tasks=[TaskConfig(path=plan.task_dir.resolve())],
    )
    bound = await create_bound_job(config, plan.inputs)
    if len(bound.run_specs) != 1:
        raise LiveSmokeError("live_trial_count_invalid")
    result = await bound.job.run()
    if not result.trial_results or len(result.trial_results) != 1:
        raise LiveSmokeError("live_trial_count_invalid")
    trial = result.trial_results[0]
    if trial.exception_info is not None:
        raise LiveSmokeError("live_trial_failed")
    rewards = trial.verifier_result.rewards if trial.verifier_result else {}
    if rewards.get("reward") != 1:
        raise LiveSmokeError("live_verifier_failed")
    retries = getattr(result.stats, "n_retries", 0)
    if retries != 0:
        raise LiveSmokeError("live_retry_invariant_failed")
    logs_dir = bound.job.job_dir / trial.trial_name / "agent"
    marker = _read_regular(logs_dir / "agent-run.json")
    trajectory = _read_regular(logs_dir / "trajectory.json")
    project = f"{trial.trial_name}__env"
    if _residual_containers(project):
        raise LiveSmokeError("live_container_cleanup_failed")
    return {
        "status": "passed",
        "provider": "xai",
        "model": LIVE_MODEL,
        "contract_id": plan.inputs.contract_id,
        "trial_count": 1,
        "retry_count": 0,
        "reward": 1,
        "marker_sha256": hashlib.sha256(marker).hexdigest(),
        "trajectory_sha256": hashlib.sha256(trajectory).hexdigest(),
        "residual_containers": 0,
    }


def parse_args(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--harbor-checkout", type=Path, required=True)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--contract-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    args = parse_args(arguments)
    repository = Path(__file__).resolve().parents[3]
    try:
        plan = prepare_live_smoke(
            harbor_checkout=args.harbor_checkout,
            binary_path=args.binary,
            cargo=args.cargo,
            contract_dir=args.contract_dir,
            output_dir=args.output_dir,
            repository=repository,
        )
        present = xai_credential_present(os.environ)
        if args.dry_run:
            result = dry_run_metadata(plan, credential_present=present)
        else:
            if not present:
                raise LiveSmokeError("xai_credential_unavailable")
            result = asyncio.run(run_live_smoke(plan))
    except Exception:
        print(json.dumps({"status": "failed", "error": "live_smoke_failed"}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0
