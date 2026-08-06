#!/usr/bin/env python3
"""Offline four-image workspace capture through pinned Harbor Docker Compose."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import subprocess
import sys
import time
import tomllib
from pathlib import Path
from typing import Any
from uuid import uuid4

HARBOR_COMMIT = "459ff6ec99417589b7f679d14ddf3b3f0ae4f1dc"
TB21_COMMIT = "5c8eadf1f393183288fa08b8f73ca9a469cc5e00"
CASES = (
    (
        "adaptive-rejection-sampler",
        "alexgshaw/adaptive-rejection-sampler",
        "985bed39e8448bc95f138b5f766b59003a95c4be171c96af8e76448338f3dd8f",
    ),
    (
        "caffe-cifar-10",
        "alexgshaw/caffe-cifar-10",
        "929a6d631b592c82e0d0f5d4a65cf03c946dc554cfc9bb09916e82076e7d3215",
    ),
    (
        "compile-compcert",
        "alexgshaw/compile-compcert",
        "f60236a4fe55bbb3c573210fe0fcd91551f4ee97c417453cd4985be074b35411",
    ),
    (
        "custom-memory-heap-crash",
        "alexgshaw/custom-memory-heap-crash",
        "1895d7d6240d5fb2ec774d6bfdd1057d170f8d199c15c582e4585d3c63802557",
    ),
)
EXPECTED_RESOURCES = {
    "adaptive-rejection-sampler": (1, 2048, 10240, 0),
    "caffe-cifar-10": (4, 8192, 10240, 0),
    "compile-compcert": (2, 4096, 10240, 0),
    "custom-memory-heap-crash": (1, 2048, 10240, 0),
}


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()


def git_head(path: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def image_ref(repository: str, digest: str) -> str:
    reference = f"{repository}@sha256:{digest}"
    image_id = subprocess.run(
        ["docker", "image", "inspect", reference, "--format", "{{.Id}}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if image_id != f"sha256:{digest}":
        raise RuntimeError(f"cached image identity mismatch: {repository}")
    return reference


def residual_containers(session_id: str) -> list[str]:
    result = subprocess.run(
        [
            "docker",
            "ps",
            "-aq",
            "--filter",
            f"label=com.docker.compose.project={session_id}",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.split()


def main_container(session_id: str) -> str:
    result = subprocess.run(
        [
            "docker",
            "ps",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={session_id}",
            "--filter",
            "label=com.docker.compose.service=main",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    containers = result.stdout.split()
    if len(containers) != 1:
        raise RuntimeError(f"expected one main container: {session_id}")
    return containers[0]


def observed_resources(container: str) -> tuple[int, int]:
    value = subprocess.run(
        [
            "docker",
            "inspect",
            container,
            "--format",
            "{{.HostConfig.NanoCpus}} {{.HostConfig.Memory}}",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()
    if len(value) != 2:
        raise RuntimeError("container resource inspection failed")
    return int(value[0]) // 1_000_000_000, int(value[1]) // (1024 * 1024)


def task_resources(task_dir: Path) -> tuple[int, int, int, int]:
    value = tomllib.loads((task_dir / "task.toml").read_text())
    environment = value.get("environment")
    if not isinstance(environment, dict):
        raise RuntimeError(f"task environment missing: {task_dir.name}")
    resources = (
        environment.get("cpus"),
        environment.get("memory_mb"),
        environment.get("storage_mb"),
        environment.get("gpus"),
    )
    if (
        any(isinstance(item, bool) or not isinstance(item, int) for item in resources)
        or resources != EXPECTED_RESOURCES[task_dir.name]
    ):
        raise RuntimeError(f"task resource mismatch: {task_dir.name}")
    return resources


def tool_request(
    *,
    seq: int,
    task_name: str,
    tool_name: str,
    arguments: dict[str, Any],
) -> bytes:
    actor_done = time.clock_gettime_ns(time.CLOCK_MONOTONIC) + 45_000_000_000
    tool_settled = actor_done + 10_000_000_000
    runtime_final = tool_settled + 30_000_000_000
    cleanup_start = runtime_final + 15_000_000_000
    hard_deadline = cleanup_start + 20_000_000_000
    value = {
        "schema_version": "external-tool-stdio-v3",
        "message_type": "tool.request",
        "seq": seq,
        "run_id": f"c4-shakedown-{task_name}",
        "trial_id": f"c4-shakedown-{task_name}",
        "attempt_id": "attempt-0",
        "call_id": f"call-{seq}",
        "tool_name": tool_name,
        "arguments_json": json.dumps(arguments, separators=(",", ":")),
        "logical_cwd": "/workspace",
        "operation_timeout_ms": 10_000,
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
            "background_output_wait_max_ms": 10_000,
        },
        "actor_done_monotonic_ns": actor_done,
        "tool_settled_monotonic_ns": tool_settled,
        "last_send_monotonic_ns": runtime_final,
        "runtime_final_monotonic_ns": runtime_final,
        "cleanup_start_monotonic_ns": cleanup_start,
        "hard_deadline_monotonic_ns": hard_deadline,
        "cleanup_reserve_ms": 20_000,
        "terminalization_reserve_ms": 15_000,
        "provider_send_reserve_ms": 30_000,
        "process_settlement_reserve_ms": 10_000,
        "deadline_receipt_sha256": "d" * 64,
    }
    return json.dumps(value, separators=(",", ":")).encode()


async def run(args: argparse.Namespace) -> dict[str, object]:
    repository = Path(__file__).resolve().parents[2]
    harbor = args.harbor_checkout.resolve()
    tb21 = args.tb21_checkout.resolve()
    output = args.output_dir.resolve()
    if git_head(harbor) != HARBOR_COMMIT or git_head(tb21) != TB21_COMMIT:
        raise RuntimeError("Harbor or TB2.1 checkout pin mismatch")
    output.mkdir(parents=True, exist_ok=False)
    sys.path[:0] = [str(harbor / "src"), str(repository / "src")]

    from harbor.environments.docker.docker import DockerEnvironment
    from harbor.models.task.config import EnvironmentConfig
    from harbor.models.trial.paths import TrialPaths

    from nano_grok_build.adapter.harbor import _HarborEnvironmentProxy
    from nano_grok_build.adapter.stdio_bridge import parse_tool_request
    from nano_grok_build.adapter.terminal_actor import RemoteTerminalActor
    from nano_grok_build.adapter.workspace_snapshot import (
        SnapshotPolicy,
        SnapshotTarget,
        capture_after,
        capture_before,
    )

    no_network = (
        harbor / "src/harbor/environments/docker/docker-compose-no-network.yaml"
    )
    environments: list[tuple[str, str, DockerEnvironment]] = []
    for name, repository_name, digest in CASES:
        cpus, memory_mb, storage_mb, gpus = task_resources(tb21 / "tasks" / name)
        session_id = f"nano-c4-workspace-{name[:12]}-{uuid4().hex[:8]}"
        paths = TrialPaths(output / name / "trial")
        paths.mkdir()
        environment = DockerEnvironment(
            environment_dir=tb21 / "tasks" / name / "environment",
            environment_name=f"nano-c4-{name}",
            session_id=session_id,
            trial_paths=paths,
            task_env_config=EnvironmentConfig(
                docker_image=image_ref(repository_name, digest),
                cpus=cpus,
                memory_mb=memory_mb,
                storage_mb=storage_mb,
                gpus=gpus,
            ),
            extra_docker_compose=[no_network],
        )
        environments.append((name, session_id, environment))

    async def lane(
        name: str,
        session_id: str,
        environment: DockerEnvironment,
    ) -> dict[str, object]:
        await environment.start(force_build=False)
        containers = residual_containers(session_id)
        if not containers or any(
            subprocess.run(
                [
                    "docker",
                    "inspect",
                    container,
                    "--format",
                    "{{.HostConfig.NetworkMode}}",
                ],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            != "none"
            for container in containers
        ):
            raise RuntimeError(f"no-network Compose overlay failed: {name}")
        declared = task_resources(tb21 / "tasks" / name)
        actual = observed_resources(main_container(session_id))
        if actual != declared[:2]:
            raise RuntimeError(f"container resource limit mismatch: {name}")
        actor = RemoteTerminalActor(_HarborEnvironmentProxy(environment))
        await actor.setup()
        artifacts = output / name / "artifacts"
        artifacts.mkdir()
        target = SnapshotTarget(actor=actor, artifact_dir=artifacts)
        before = await capture_before(target, SnapshotPolicy())
        foreground = await actor.execute(
            parse_tool_request(
                tool_request(
                    seq=0,
                    task_name=name,
                    tool_name="run_terminal_command",
                    arguments={
                        "command": (
                            "printf 'foreground-ok\\n'; "
                            "printf '%s\\n' foreground > .nano-c4-foreground"
                        ),
                        "description": "exercise foreground settlement",
                        "timeout": 5000,
                        "background": False,
                    },
                )
            )
        )
        if (
            foreground.return_code != 0
            or foreground.timed_out
            or foreground.stdout != b"foreground-ok\n"
            or foreground.survivor_count != 0
        ):
            raise RuntimeError(f"foreground lifecycle failed: {name}")
        background = await actor.execute(
            parse_tool_request(
                tool_request(
                    seq=1,
                    task_name=name,
                    tool_name="run_terminal_command",
                    arguments={
                        "command": (
                            "printf 'background-started\\n'; sleep 1; "
                            "printf '%s\\n' background > .nano-c4-background"
                        ),
                        "description": "exercise background settlement",
                        "timeout": 5000,
                        "background": True,
                    },
                )
            )
        )
        task_id = background.target_task_id
        if (
            background.process_disposition.value != "background_retained"
            or background.survivor_count != 1
            or not task_id
        ):
            raise RuntimeError(f"background start failed: {name}")
        status = await actor.execute(
            parse_tool_request(
                tool_request(
                    seq=2,
                    task_name=name,
                    tool_name="get_terminal_command_output",
                    arguments={"task_ids": [task_id], "timeout_ms": 5000},
                )
            )
        )
        if (
            status.return_code != 0
            or b"Status: completed" not in status.stdout
            or b"Exit Code: 0" not in status.stdout
            or b"background-started" not in status.stdout
            or await actor.background_manifest()
        ):
            raise RuntimeError(f"background completion failed: {name}")
        receipt = await capture_after(target, before)
        if receipt.status != "complete":
            raise RuntimeError(f"workspace capture failed: {name}")
        if {path.name for path in artifacts.iterdir()} != {
            "workspace-before.json",
            "workspace-after.json",
            "workspace-delta.json",
            "workspace-diff.patch",
            "workspace-changed.tar",
            "workspace-receipt.json",
        }:
            raise RuntimeError(f"workspace artifact inventory failed: {name}")
        delta = json.loads((artifacts / "workspace-delta.json").read_bytes())
        changed = {row["path"] for key in ("created", "modified") for row in delta[key]}
        if not {".nano-c4-foreground", ".nano-c4-background"} <= changed:
            raise RuntimeError(f"workspace delta failed: {name}")
        before_raw = (artifacts / "workspace-before.json").read_bytes()
        receipt_raw = (artifacts / "workspace-receipt.json").read_bytes()
        return {
            "task": f"terminal-bench/{name}",
            "declared_resources": {
                "cpus": declared[0],
                "memory_mb": declared[1],
                "storage_mb": declared[2],
                "gpus": declared[3],
            },
            "observed_limits": {
                "cpus": actual[0],
                "memory_mb": actual[1],
            },
            "foreground": "completed",
            "background": "completed",
            "before_sha256": hashlib.sha256(before_raw).hexdigest(),
            "receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
            "workspace_mapping": actor.diagnostic_metadata()["workspace_mapping"],
        }

    try:
        rows = await asyncio.gather(
            *(
                lane(name, session, environment)
                for name, session, environment in environments
            )
        )
    finally:
        await asyncio.gather(
            *(environment.stop(delete=True) for _, _, environment in environments),
            return_exceptions=True,
        )
    residual = {
        session_id: residual_containers(session_id) for _, session_id, _ in environments
    }
    if any(residual.values()):
        raise RuntimeError("Harbor Compose container survived deletion")
    return {
        "schema_version": "nano-c4-workspace-shakedown-v1",
        "status": "passed",
        "network_mode": "none",
        "environment_proxy": "_HarborEnvironmentProxy",
        "concurrency": 4,
        "declared_resource_totals": {
            "cpus": sum(value[0] for value in EXPECTED_RESOURCES.values()),
            "memory_mb": sum(value[1] for value in EXPECTED_RESOURCES.values()),
            "storage_mb": sum(value[2] for value in EXPECTED_RESOURCES.values()),
            "gpus": sum(value[3] for value in EXPECTED_RESOURCES.values()),
        },
        "provider_calls": 0,
        "captures_complete": len(rows),
        "foreground_completed": len(rows),
        "background_completed": len(rows),
        "residual_containers": 0,
        "rows": rows,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--harbor-checkout", type=Path, required=True)
    parser.add_argument("--tb21-checkout", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    outcome = asyncio.run(run(parse_args()))
    sys.stdout.buffer.write(canonical(outcome))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
