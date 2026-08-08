"""Run the pinned real-Docker Harbor integration without provider credentials."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from uuid import uuid4

HARBOR_COMMIT = "459ff6ec99417589b7f679d14ddf3b3f0ae4f1dc"
TOOL_ORDER = [
    "run_terminal_command",
    "read_file",
    "search_replace",
    "write",
    "list_dir",
    "grep",
    "kill_terminal_command",
    "get_terminal_command_output",
]


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def write_synthetic_contract(
    directory: Path,
    *,
    background_output_wait_max_ms: int = 100,
) -> None:
    directory.mkdir(parents=True)
    prompt = "You are a synthetic first-party terminal agent."
    wrapper = "<user_query>\n{{USER_QUERY}}\n</user_query>"
    tools = []
    for ordinal, name in enumerate(TOOL_ORDER):
        if name == "run_terminal_command":
            input_schema = {
                "additionalProperties": False,
                "properties": {
                    "background": {"default": False, "type": "boolean"},
                    "command": {"type": "string"},
                    "description": {"type": "string"},
                    "timeout": {
                        "default": 1000,
                        "maximum": 5000,
                        "minimum": 0,
                        "type": ["integer", "null"],
                    },
                },
                "required": ["command", "description"],
                "type": "object",
            }
        elif name == "get_terminal_command_output":
            input_schema = {
                "additionalProperties": False,
                "properties": {
                    "timeout_ms": {
                        "maximum": background_output_wait_max_ms,
                        "minimum": 0,
                        "type": "integer",
                    }
                },
                "required": [],
                "type": "object",
            }
        else:
            input_schema = {
                "additionalProperties": False,
                "properties": {},
                "required": [],
                "type": "object",
            }
        effect = (
            "read_only"
            if name in {"read_file", "list_dir", "grep", "get_terminal_command_output"}
            else "mutating"
        )
        tools.append(
            {
                "ordinal": ordinal,
                "contract_tool_id": f"synthetic:{name}",
                "provider_name": name,
                "description": {
                    "run_terminal_command": (
                        "Synthetic terminal; timeout values default to 1000 ms and "
                        "are at most 5000 ms. It owns descendants including setsid "
                        "and nohup descendants and returns at most 1024 bytes per call."
                    ),
                    "get_terminal_command_output": (
                        "Synthetic background wait; omitted or zero is nonblocking "
                        "and positive waits are capped at "
                        f"{background_output_wait_max_ms} ms."
                    ),
                    "read_file": (
                        "Read normal text files and PNG and JPEG image files only."
                    ),
                }.get(name, f"Synthetic definition for {name}."),
                "input_schema": input_schema,
                "effect_class": effect,
                "compatibility_aliases": [],
                "result_policy": {
                    "renderer_contract_id": "synthetic-terminal-v1",
                    "truncation_policy": "synthetic-head-tail-v1",
                    "max_model_output_bytes": 1024,
                },
            }
        )
    effective_value = {
        "schema_version": "effective-contract-v1",
        "contract_id": "synthetic-v1",
        "prompt_context": {
            "current_date": "2026-07-23",
            "is_non_interactive": True,
            "memory_enabled": False,
            "os_name": "linux",
            "shell_path": "/bin/bash",
            "system_prompt_label": "Synthetic",
            "working_directory": "/workspace",
        },
        "system_prompt": {"text": prompt, "utf8_sha256": sha256(prompt.encode())},
        "user_wrapper": {
            "template": wrapper,
            "payload_slot": "{{USER_QUERY}}",
            "utf8_sha256": sha256(wrapper.encode()),
        },
        "tools": tools,
    }
    effective = canonical(effective_value)
    delta = canonical(
        {"schema_version": "contract-delta-v1", "contract_id": "synthetic-v1"}
    )
    profile = {
        "schema_version": "agent-profile-v1",
        "profile_id": "synthetic-profile-v1",
        "contract_id": "synthetic-v1",
        "provider": {
            "provider_id": "scripted",
            "api": "responses-v1",
            "endpoint": "https://example.invalid/v1/responses",
            "model": "synthetic-model",
            "reasoning_effort": "high",
            "store": False,
            "stream": True,
            "include": ["reasoning.encrypted_content"],
            "parallel_tool_calls": True,
            "tool_choice": "auto",
            "service_tier": "default",
            "retry_max": 0,
        },
        "contract_bindings": {
            "effective_contract_file_sha256": sha256(effective),
            "system_prompt_utf8_sha256": sha256(prompt.encode()),
            "ordered_tools_value_sha256": sha256(
                json.dumps(
                    tools,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ),
            "contract_delta_file_sha256": sha256(delta),
        },
        "context": {
            "policy": "fail_closed_no_compaction",
            "counting_rule": "synthetic",
            "provider_context_window_tokens": 500000,
            "request_input_upper_tokens": 199000,
            "max_output_tokens_per_request": 256,
            "max_provider_turns": 4,
            "max_input_tokens_per_run": 450000,
            "max_output_tokens_per_run": 1024,
            "max_history_items": 64,
            "max_request_body_bytes": 1048576,
        },
        "transport": {
            "max_function_arguments_bytes": 1048576,
            "max_sse_events_per_response": 1024,
            "max_sse_event_bytes": 1048576,
            "max_sse_response_bytes": 4194304,
            "max_json_depth": 64,
        },
        "scheduler": {
            "read_only_parallelism": 1,
            "max_function_calls_per_response": 8,
            "max_function_calls_per_run": 16,
            "mutation_batches_serialized": True,
        },
        "deadlines": {
            "source": "run_spec_task_native",
            # Test-only profile values mirror the frozen signed deadline
            # receipt, while leaving enough launch headroom for the 90-second
            # V10 final-response reserve.
            "absolute_run_wall_cap_sec": 180,
            "terminalization_reserve_sec": 15,
            "min_provider_send_window_sec": 30,
            "provider_connect_timeout_sec": 2,
            "provider_first_event_timeout_sec": 2,
            "provider_inter_event_timeout_sec": 2,
            "provider_total_timeout_sec": 5,
            "filesystem_operation_timeout_sec": 2,
            "search_operation_timeout_sec": 2,
            "process_control_timeout_sec": 10,
            "artifactization_timeout_sec": 2,
        },
        "tools": {
            "terminal_default_timeout_ms": 1000,
            "terminal_max_timeout_ms": 5000,
            "background_output_wait_max_ms": background_output_wait_max_ms,
            "max_command_bytes": 65536,
            "max_path_bytes": 4096,
            "max_read_or_write_bytes": 1048576,
            "max_directory_entries": 100,
            "max_grep_matches": 100,
            "max_replacements": 100,
            "model_tool_output_bytes_per_call": 1024,
            "model_tool_output_bytes_per_run": 8192,
        },
        "process": {
            "max_background_processes": 8,
            "term_grace_ms": 5000,
            "kill_confirmation_timeout_ms": 5000,
            "process_spool_bytes_per_process": 8192,
            "process_spool_bytes_per_run": 16384,
        },
        "artifacts": {
            "max_events_per_run": 128,
            "max_event_line_bytes": 1048576,
            "max_event_log_bytes": 8388608,
            "max_blobs_per_run": 0,
            "max_blob_bytes": 1048576,
            "max_blob_bytes_per_run": 1048576,
            "max_agent_run_record_bytes": 1048576,
            "max_trajectory_bytes": 1048576,
            "max_published_agent_bytes": 8388608,
            "max_live_stdout_mirror_bytes": 1048576,
        },
        "schema_versions": {
            "contract_manifest": "contract-manifest-v1",
            "effective_contract": "effective-contract-v1",
            "agent_profile": "agent-profile-v1",
            "contract_delta": "contract-delta-v1",
        },
    }
    (directory / "effective-contract.json").write_bytes(effective)
    (directory / "agent-profile.json").write_bytes(canonical(profile))
    (directory / "contract-delta.json").write_bytes(delta)


def assert_pin(checkout: Path) -> None:
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=checkout,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if head != HARBOR_COMMIT:
        raise RuntimeError(f"Harbor checkout is not pinned: {head}")


def residual_containers(project: str) -> list[str]:
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


async def run_cancellation_probe(
    *,
    output_root: Path,
    environment_dir: Path,
) -> None:
    from harbor.environments.docker.docker import DockerEnvironment
    from harbor.models.task.config import EnvironmentConfig as TaskEnvironmentConfig
    from harbor.models.trial.paths import TrialPaths

    from nano_grok_build.adapter.stdio_bridge import parse_tool_request
    from nano_grok_build.adapter.terminal_actor import RemoteTerminalActor

    session_id = f"nano-cancel-probe-{uuid4().hex[:8]}"
    trial_paths = TrialPaths(output_root / "cancel-probe-trial")
    trial_paths.mkdir()
    environment = DockerEnvironment(
        environment_dir=environment_dir,
        environment_name="nano-cancel-probe",
        session_id=session_id,
        trial_paths=trial_paths,
        task_env_config=TaskEnvironmentConfig(workdir="/workspace"),
    )
    await environment.start(force_build=False)
    try:
        actor = RemoteTerminalActor(environment)
        await actor.setup()
        request_value = {
            "schema_version": "external-tool-stdio-v2",
            "message_type": "tool.request",
            "seq": 0,
            "run_id": "cancel-probe",
            "trial_id": "cancel-probe",
            "attempt_id": "attempt-0",
            "call_id": "call-cancel",
            "tool_name": "run_terminal_command",
            "arguments_json": json.dumps(
                {
                    "command": (
                        "trap '' TERM; exec -a nano-cancel-probe-survivor sleep 30"
                    ),
                    "description": "exercise cancellation cleanup",
                    "timeout": 30000,
                    "background": False,
                },
                separators=(",", ":"),
            ),
            "logical_cwd": "/workspace",
            "timeout_ms": 30000,
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
        raw = json.dumps(request_value, separators=(",", ":")).encode()
        request = parse_tool_request(raw)
        request_dir = (
            "/tmp/nano-grok-build-terminal-v1/requests/" + request.request_sha256[:32]
        )
        execution = asyncio.create_task(actor.execute(request))
        for _ in range(100):
            ready = await environment.exec(
                f"test -f {request_dir}/pgid",
                timeout_sec=2,
            )
            if ready.return_code == 0:
                break
            await asyncio.sleep(0.05)
        else:
            execution.cancel()
            await asyncio.gather(execution, return_exceptions=True)
            raise RuntimeError("cancellation probe never published a PGID")
        execution.cancel()
        try:
            await execution
        except asyncio.CancelledError:
            pass
        else:
            raise RuntimeError("cancellation probe did not cancel")
        if not await actor.cleanup_active():
            raise RuntimeError("cancellation probe cleanup remained active")
        census = await environment.exec(
            "for value in /proc/[0-9]*/cmdline; do "
            "text=$(tr '\\0' ' ' < \"$value\" 2>/dev/null || true); "
            'case "$text" in *[n]ano-cancel-probe-survivor*) exit 1;; esac; '
            "done; exit 0",
            timeout_sec=10,
        )
        if census.return_code != 0:
            raise RuntimeError("cancellation probe left a remote survivor")
    finally:
        await environment.stop(delete=True)
    if residual_containers(session_id):
        raise RuntimeError("cancellation probe container survived deletion")


async def run(args: argparse.Namespace) -> dict[str, object]:
    repo = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(args.harbor_checkout / "src"))
    sys.path.insert(0, str(repo / "src"))
    from harbor.models.job.config import JobConfig, RetryConfig
    from harbor.models.trial.config import (
        AgentConfig,
        EnvironmentConfig,
        TaskConfig,
    )
    from harbor.utils.trajectory_validator import TrajectoryValidator

    from nano_grok_build.adapter.artifactizer import publish_artifacts
    from nano_grok_build.harbor.dispatch import (
        create_bound_job,
        load_runtime_inputs,
    )

    output_root = args.output_dir.resolve()
    output_root.mkdir(parents=True, exist_ok=False)
    contract_dir = output_root / "contract"
    write_synthetic_contract(contract_dir)
    task_dir = repo / "tests" / "harbor" / "toy-task"
    script_path = repo / "tests" / "harbor" / "scripted-provider.json"
    inputs = load_runtime_inputs(
        binary_path=args.binary.resolve(),
        contract_dir=contract_dir.resolve(),
        provider_script_path=script_path.resolve(),
    )
    job_name = f"nano-synthetic-{uuid4().hex[:10]}"
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
    result = await bound.job.run()
    if not result.trial_results or len(result.trial_results) != 1:
        raise RuntimeError("synthetic Job did not return exactly one trial")
    trial = result.trial_results[0]
    if trial.exception_info is not None:
        raise RuntimeError(
            "synthetic trial failed: " + trial.exception_info.exception_type
        )
    rewards = trial.verifier_result.rewards if trial.verifier_result else {}
    if rewards.get("reward") != 1:
        raise RuntimeError(f"synthetic verifier reward was not 1: {rewards}")
    trial_dir = bound.job.job_dir / trial.trial_name
    logs_dir = trial_dir / "agent"
    marker_before = (logs_dir / "agent-run.json").read_bytes()
    publication = publish_artifacts(
        logs_dir=logs_dir,
        run_spec=bound.run_specs[0],
        instruction=bound.run_specs[0]["task"]["instruction"],
        agent_name="nano-grok-build",
        agent_version="0.1.0",
        model_name="synthetic-model",
        require_harbor_validator=True,
    )
    if publication.marker_path.read_bytes() != marker_before:
        raise RuntimeError("duplicate post-run publication changed marker bytes")
    validator = TrajectoryValidator()
    if not validator.validate(publication.trajectory_path):
        raise RuntimeError(
            "pinned ATIF validation failed: " + "|".join(validator.errors)
        )
    project = f"{trial.trial_name}__env"
    if residual_containers(project):
        raise RuntimeError("synthetic Harbor containers survived deletion")
    retries = getattr(result.stats, "n_retries", 0)
    if retries != 0:
        raise RuntimeError(f"synthetic Job retried unexpectedly: {retries}")
    await run_cancellation_probe(
        output_root=output_root,
        environment_dir=task_dir / "environment",
    )
    return {
        "status": "passed",
        "cancellation_cleanup": "passed",
        "reward": 1,
        "retry_count": 0,
        "trial_name": trial.trial_name,
        "trajectory": str(publication.trajectory_path),
        "marker": str(publication.marker_path),
        "residual_containers": 0,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--harbor-checkout", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if args.output_dir is None:
        args.output_dir = Path(tempfile.mkdtemp(prefix="nano-harbor-synthetic."))
        args.output_dir.rmdir()
    assert_pin(args.harbor_checkout.resolve())
    return args


if __name__ == "__main__":
    print(json.dumps(asyncio.run(run(parse_args())), sort_keys=True))
