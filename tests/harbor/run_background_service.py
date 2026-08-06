"""Exercise background-service handoff through pinned Harbor and real Docker."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any
from uuid import uuid4

HARBOR_COMMIT = "459ff6ec99417589b7f679d14ddf3b3f0ae4f1dc"
TOOL_ORDER = (
    "run_terminal_command",
    "read_file",
    "search_replace",
    "write",
    "list_dir",
    "grep",
    "kill_terminal_command",
    "get_terminal_command_output",
)
TASK_NAME = "nano-grok-build/background-service"


class BackgroundServiceError(RuntimeError):
    """The synthetic lifecycle did not prove the required invariant."""


def _assert_regular_executable(path: Path) -> Path:
    resolved = path.resolve()
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not resolved.is_file()
        or not resolved.stat().st_mode & 0o111
    ):
        raise BackgroundServiceError("binary must be an absolute executable file")
    return resolved


def _harbor_head(
    checkout: Path,
    command_runner: Callable[..., subprocess.CompletedProcess[str]],
) -> str:
    resolved = checkout.resolve()
    if not checkout.is_absolute() or checkout.is_symlink() or not resolved.is_dir():
        raise BackgroundServiceError("Harbor checkout must be an absolute directory")
    result = command_runner(
        ["git", "-C", str(resolved), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    head = result.stdout.strip()
    if head != HARBOR_COMMIT:
        raise BackgroundServiceError(f"Harbor checkout is not pinned: {head}")
    return head


def plan(
    *,
    harbor_checkout: Path,
    binary: Path,
    output_dir: Path,
    command_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, object]:
    """Validate local inputs without importing Harbor or touching Docker."""

    checkout = harbor_checkout.resolve()
    binary = _assert_regular_executable(binary)
    output = output_dir.resolve()
    if output.exists():
        raise FileExistsError("fresh output directory already exists")
    task_dir = Path(__file__).resolve().parent / "background-task"
    required = (
        task_dir / "task.toml",
        task_dir / "instruction.md",
        task_dir / "environment" / "Dockerfile",
        task_dir / "tests" / "test.sh",
        task_dir / "scripted-provider.json",
    )
    if not all(path.is_file() and not path.is_symlink() for path in required):
        raise BackgroundServiceError("background task fixture is incomplete")
    head = _harbor_head(checkout, command_runner)
    return {
        "binary": str(binary),
        "docker_calls": 0,
        "harbor_commit": head,
        "network_calls": 0,
        "output_dir": str(output),
        "provider": "scripted",
        "retry_count": 0,
        "status": "plan-only",
        "task": TASK_NAME,
        "tool_count": len(TOOL_ORDER),
        "verifier_mode": "shared",
    }


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


def _docker_version() -> str:
    result = subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        check=True,
        capture_output=True,
        text=True,
    )
    value = result.stdout.strip()
    if not value:
        raise BackgroundServiceError("Docker server version is unavailable")
    return value


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise BackgroundServiceError(f"expected JSON object: {path}")
    return value


async def _run_background_cleanup_probe(
    *,
    output_root: Path,
    environment_dir: Path,
) -> dict[str, object]:
    """Model the bridge's failure cleanup after one retained background task."""

    from harbor.environments.docker.docker import DockerEnvironment
    from harbor.models.task.config import EnvironmentConfig as TaskEnvironmentConfig
    from harbor.models.trial.paths import TrialPaths

    from nano_grok_build.adapter.stdio_bridge import parse_tool_request
    from nano_grok_build.adapter.terminal_actor import RemoteTerminalActor

    session_id = f"nano-background-cleanup-{uuid4().hex[:8]}"
    trial_paths = TrialPaths(output_root / "background-cleanup-probe-trial")
    trial_paths.mkdir()
    environment = DockerEnvironment(
        environment_dir=environment_dir,
        environment_name="nano-background-cleanup-probe",
        session_id=session_id,
        trial_paths=trial_paths,
        task_env_config=TaskEnvironmentConfig(workdir="/workspace"),
    )
    await environment.start(force_build=False)
    try:
        actor = RemoteTerminalActor(environment)
        await actor.setup()
        arguments = {
            "command": (
                "exec -a nano-background-cleanup-probe "
                "perl -MIO::Socket::INET -e "
                '\'$socket = IO::Socket::INET->new(LocalAddr => "127.0.0.1", '
                "LocalPort => 18766, Listen => 5, ReuseAddr => 1) or die $!; "
                "while ($client = $socket->accept) { "
                'print $client "NANO_CLEANUP_PROBE_OK\\\\n"; close $client; }\''
            ),
            "description": "retain a service before failure cleanup",
            "timeout": 0,
            "background": True,
        }
        request_value = {
            "schema_version": "external-tool-stdio-v2",
            "message_type": "tool.request",
            "seq": 0,
            "run_id": "background-cleanup-probe",
            "trial_id": "background-cleanup-probe",
            "attempt_id": "attempt-0",
            "call_id": "call-background-cleanup",
            "tool_name": "run_terminal_command",
            "arguments_json": json.dumps(arguments, separators=(",", ":")),
            "logical_cwd": "/workspace",
            "timeout_ms": 5000,
            "term_grace_ms": 100,
            "kill_confirmation_timeout_ms": 1000,
            "stdout_cap_bytes": 4096,
            "stderr_cap_bytes": 4096,
            "environment": {
                "clear": True,
                "inherit_remote": [
                    "HOME",
                    "LANG",
                    "LC_ALL",
                    "PATH",
                    "TERM",
                    "TMPDIR",
                    "USER",
                ],
            },
            "limits": {
                "arguments_cap_bytes": 1048576,
                "max_path_bytes": 4096,
                "max_read_or_write_bytes": 4194304,
                "max_directory_entries": 10000,
                "max_grep_matches": 10000,
                "max_replacements": 10000,
                "max_background_processes": 8,
                "process_spool_bytes_per_process": 8192,
                "process_spool_bytes_per_run": 16384,
                "background_output_wait_max_ms": 100,
            },
        }
        request = parse_tool_request(
            json.dumps(request_value, separators=(",", ":")).encode()
        )
        execution = await actor.execute(request)
        before = await actor.background_manifest()
        if (
            execution.process_disposition.value != "background_retained"
            or execution.survivor_count != 1
            or len(before) != 1
            or before[0]["state"] != "running"
        ):
            raise BackgroundServiceError("cleanup probe did not retain one service")
        if not await actor.cleanup_active():
            raise BackgroundServiceError("cleanup_active did not confirm termination")
        if await actor.background_manifest():
            raise BackgroundServiceError("cleanup_active left a registered background")
        census = await environment.exec(
            "for value in /proc/[0-9]*/cmdline; do "
            "text=$(tr '\\0' ' ' < \"$value\" 2>/dev/null || true); "
            'case "$text" in *[n]ano-background-cleanup-probe*) exit 1;; esac; '
            "done; exit 0",
            timeout_sec=10,
        )
        if census.return_code != 0:
            raise BackgroundServiceError("cleanup_active left a remote survivor")
    finally:
        await environment.stop(delete=True)
    if _residual_containers(session_id):
        raise BackgroundServiceError("cleanup probe container survived deletion")
    return {
        "background_task_count_before_cleanup": 1,
        "cleanup_active": "passed",
        "remote_survivors": 0,
        "residual_containers": 0,
    }


async def run_e2e(args: argparse.Namespace) -> dict[str, object]:
    """Run the successful handoff plus a cancellation cleanup probe."""

    repository = Path(__file__).resolve().parents[2]
    task_dir = Path(__file__).resolve().parent / "background-task"
    output_root = args.output_dir.resolve()
    plan(
        harbor_checkout=args.harbor_checkout,
        binary=args.binary,
        output_dir=output_root,
    )
    sys.path.insert(0, str(args.harbor_checkout.resolve() / "src"))
    sys.path.insert(0, str(repository / "src"))
    sys.path.insert(0, str(Path(__file__).resolve().parent))

    from harbor.models.job.config import JobConfig, RetryConfig
    from harbor.models.trial.config import (
        AgentConfig,
        EnvironmentConfig,
        TaskConfig,
    )
    from harbor.utils.trajectory_validator import TrajectoryValidator
    from run_synthetic import write_synthetic_contract

    from nano_grok_build.adapter.artifactizer import canonical_json
    from nano_grok_build.harbor.dispatch import (
        create_bound_job,
        load_runtime_inputs,
    )

    output_root.mkdir(parents=True, exist_ok=False)
    contract_dir = output_root / "contract"
    write_synthetic_contract(contract_dir)
    inputs = load_runtime_inputs(
        binary_path=args.binary.resolve(),
        contract_dir=contract_dir.resolve(),
        provider_script_path=(task_dir / "scripted-provider.json").resolve(),
        active_tools=TOOL_ORDER,
    )
    job_name = f"nano-background-service-{uuid4().hex[:10]}"
    config = JobConfig(
        job_name=job_name,
        jobs_dir=output_root / "jobs",
        n_attempts=1,
        n_concurrent_trials=1,
        quiet=True,
        retry=RetryConfig(max_retries=0),
        environment=EnvironmentConfig(type="docker", delete=True),
        agents=[
            AgentConfig(
                import_path=("nano_grok_build.adapter.harbor:NanoGrokBuildAgent"),
                model_name="synthetic-model",
            )
        ],
        tasks=[TaskConfig(path=task_dir.resolve())],
    )
    bound = await create_bound_job(config, inputs)
    if len(bound.run_specs) != 1:
        raise BackgroundServiceError("expected exactly one bound RunSpec")
    run_spec = bound.run_specs[0]
    if tuple(run_spec.get("active_tools", ())) != TOOL_ORDER:
        raise BackgroundServiceError("RunSpec did not bind all eight tools")

    result = await bound.job.run()
    if not result.trial_results or len(result.trial_results) != 1:
        raise BackgroundServiceError("Harbor did not return exactly one trial")
    trial = result.trial_results[0]
    if trial.exception_info is not None:
        raise BackgroundServiceError(
            "Harbor trial failed: " + trial.exception_info.exception_type
        )
    rewards = trial.verifier_result.rewards if trial.verifier_result else {}
    if rewards.get("reward") != 1:
        raise BackgroundServiceError(f"shared verifier reward was not 1: {rewards}")
    retries = getattr(result.stats, "n_retries", 0)
    if retries != 0:
        raise BackgroundServiceError(f"Harbor retried unexpectedly: {retries}")

    trial_dir = bound.job.job_dir / trial.trial_name
    logs_dir = trial_dir / "agent"
    marker_path = logs_dir / "agent-run.json"
    trajectory_path = logs_dir / "trajectory.json"
    manifest_path = logs_dir / "runtime-background-manifest.json"
    marker = _load_json(marker_path)
    manifest_raw = manifest_path.read_bytes()
    manifest = json.loads(manifest_raw)
    if (
        not isinstance(manifest, dict)
        or manifest_raw != canonical_json(manifest)
        or not isinstance(manifest.get("tasks"), list)
        or len(manifest["tasks"]) != 1
        or manifest["tasks"][0].get("state") != "running"
    ):
        raise BackgroundServiceError("background handoff manifest is invalid")
    manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
    if (
        marker.get("background_manifest_sha256") != manifest_sha256
        or marker.get("background_task_count") != 1
        or any(
            marker.get(field) != run_spec[field]
            for field in ("run_id", "trial_id", "attempt_id")
        )
    ):
        raise BackgroundServiceError("artifact marker identity is invalid")
    validator = TrajectoryValidator()
    if not validator.validate(trajectory_path):
        raise BackgroundServiceError(
            "pinned ATIF validation failed: " + "|".join(validator.errors)
        )
    reachability_path = trial_dir / "verifier" / "reachability.json"
    reachability = _load_json(reachability_path)
    if reachability != {
        "reachable": True,
        "response": "NANO_BACKGROUND_OK",
        "service_running": True,
    }:
        raise BackgroundServiceError(
            f"shared verifier reachability evidence is invalid: {reachability}"
        )

    project = f"{trial.trial_name}__env"
    residual = _residual_containers(project)
    if residual:
        raise BackgroundServiceError(
            "successful trial containers survived deletion: " + ",".join(residual)
        )
    cleanup_probe = await _run_background_cleanup_probe(
        output_root=output_root,
        environment_dir=task_dir / "environment",
    )

    summary: dict[str, object] = {
        "artifact": {
            "background_manifest_sha256": manifest_sha256,
            "background_task_count": 1,
            "marker": str(marker_path),
            "result_identity": "matched",
            "trajectory": str(trajectory_path),
        },
        "failure_cleanup": cleanup_probe,
        "docker": {
            "residual_containers": 0,
            "server_version": _docker_version(),
        },
        "harbor_commit": HARBOR_COMMIT,
        "provider": "scripted",
        "reachability": reachability,
        "retry_count": 0,
        "reward": 1,
        "status": "passed",
        "task": TASK_NAME,
        "tool_count": len(TOOL_ORDER),
        "trial_name": trial.trial_name,
        "verifier_mode": "shared",
    }
    (output_root / "summary.json").write_bytes(canonical_json(summary))
    return summary


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run a fake-provider background TCP service through pinned Harbor."
        )
    )
    parser.add_argument("--harbor-checkout", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="validate inputs and print a zero-network, zero-Docker plan",
    )
    args = parser.parse_args(argv)
    args.harbor_checkout = args.harbor_checkout.resolve()
    args.binary = args.binary.resolve()
    if args.output_dir is None:
        temporary = Path(tempfile.mkdtemp(prefix="nano-background-service."))
        temporary.rmdir()
        args.output_dir = temporary
    else:
        args.output_dir = args.output_dir.resolve()
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.plan_only:
        value = plan(
            harbor_checkout=args.harbor_checkout,
            binary=args.binary,
            output_dir=args.output_dir,
        )
    else:
        value = asyncio.run(run_e2e(args))
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
