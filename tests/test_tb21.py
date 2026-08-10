from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import textwrap
import types
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from nano_grok_build.adapter.artifactizer import publish_artifacts
from nano_grok_build.adapter.atif import project_trajectory, validate_minimal_trajectory
from nano_grok_build.adapter.deadline import (
    DeadlineReservesV1,
    RunDeadlineReceiptV1,
    RunDeadlineV1,
)
from nano_grok_build.adapter.workspace_snapshot import (
    SnapshotPolicy,
    capture_after,
    capture_before,
)
from nano_grok_build.harbor import protected_target, tb21
from nano_grok_build.harbor.git_history_capability import (
    compile_git_history_capability,
)
from nano_grok_build.harbor.git_history_receipt import (
    HISTORY_BASELINE_POLICY,
    HISTORY_BASELINE_SCHEMA,
)
from nano_grok_build.harbor.runtime_entry import write_not_started


@pytest.fixture
def pinned_collector_validator(monkeypatch: pytest.MonkeyPatch) -> None:
    def validate(trajectory: object) -> None:
        assert isinstance(trajectory, dict)
        validate_minimal_trajectory(trajectory)

    monkeypatch.setattr(tb21, "validate_with_pinned_harbor", validate)


def _write_task(
    tasks_root: Path,
    short_name: str,
    *,
    task_name: str | None = None,
    image: str | None = None,
    cpus: int = 1,
    memory_mb: int = 2048,
) -> Path:
    task_dir = tasks_root / short_name
    (task_dir / "environment").mkdir(parents=True)
    (task_dir / "tests").mkdir()
    name = task_name or f"terminal-bench/{short_name}"
    image = image or f"example/{short_name}:pinned"
    (task_dir / "task.toml").write_text(
        "\n".join(
            (
                'schema_version = "1.1"',
                "[task]",
                f'name = "{name}"',
                "[agent]",
                "timeout_sec = 900.0",
                "[verifier]",
                "timeout_sec = 900.0",
                "[environment]",
                f'docker_image = "{image}"',
                f"cpus = {cpus}",
                f"memory_mb = {memory_mb}",
                "storage_mb = 10240",
                "gpus = 0",
                "",
            )
        )
    )
    (task_dir / "instruction.md").write_text(f"Solve {short_name}.\n")
    (task_dir / "environment" / "Dockerfile").write_text("FROM scratch\n")
    (task_dir / "tests" / "test.sh").write_text("#!/bin/sh\nexit 0\n")
    return task_dir


def _run_spec(trial: str, task: str, digest: str) -> dict[str, object]:
    return {
        "schema_version": "nano-run-spec-alpha-1",
        "run_id": f"job-id:{trial}",
        "trial_id": trial,
        "attempt_id": "attempt-0",
        "task": {
            "id": f"terminal-bench/{task}",
            "digest": digest,
            "instruction": f"Solve {task}.",
        },
        "contract": {
            "id": "nano-v1",
            "contract_set_sha256": "c" * 64,
            "profile_id": "nano-v1-grok-4-5-high-v1",
        },
        "provider": {
            "kind": "xai",
            "model": "grok-4.5",
            "max_turns": 64,
            "retry_max": 0,
        },
        "workspace_dir": "/workspace",
        "artifact_dir": f"/jobs/{trial}/agent/runtime",
        "agent_timeout_sec": 900,
        "active_tools": list(tb21.ACTIVE_TOOLS),
    }


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()


def _official_checksum_manifest(
    checksums: dict[str, str],
) -> dict[str, object]:
    return {
        "schema_version": tb21.OFFICIAL_TASK_CHECKSUMS_SCHEMA,
        "dataset_name": tb21.TB21_DATASET,
        "dataset_digest": tb21.TB21_DATASET_REF,
        "harbor_version": tb21.HARBOR_VERSION,
        "harbor_commit": tb21.HARBOR_COMMIT,
        "terminal_bench_commit": tb21.TB21_SOURCE_COMMIT,
        "task_count": tb21.TB21_TASK_COUNT,
        "checksums_sha256": hashlib.sha256(_canonical(checksums)).hexdigest(),
        "checksums": checksums,
    }


def _commit_upstream_checkout(path: Path, remote: str) -> tuple[str, str]:
    subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True)
    subprocess.run(["git", "remote", "add", "origin", remote], cwd=path, check=True)
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-qm",
            "fixture",
        ],
        cwd=path,
        check=True,
    )
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"],
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return commit, tree


def _write_pricing(path: Path, *, input_rate: float = 2.0) -> tb21.Pricing:
    path.write_bytes(
        _canonical(
            {
                "schema_version": "nano-token-pricing-v1",
                "as_of": "2026-07-24",
                "currency": "USD",
                "model": "grok-4.5",
                "input_per_million_usd": input_rate,
                "cached_input_per_million_usd": 0.5,
                "output_per_million_usd": 10.0,
            }
        )
    )
    return tb21.load_pricing(path)


def _write_dispatch(job_dir: Path, specs: list[dict[str, object]]) -> None:
    manifest = {
        "schema_version": "nano-harbor-dispatch-v1",
        "harbor_version": "0.20.0",
        "job_id": "job-id",
        "retry_max": 0,
        "n_attempts": 1,
        "run_specs": specs,
    }
    manifest_bytes = _canonical(manifest)
    envelope = {
        "manifest": manifest,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    }
    (job_dir / "nano-dispatch.json").write_bytes(_canonical(envelope))


def _alpha2(spec: dict[str, object]) -> dict[str, object]:
    spec = json.loads(json.dumps(spec))
    spec["schema_version"] = "nano-run-spec-alpha-2"
    task = spec["task"]
    assert isinstance(task, dict)
    task["git_history_capability"] = compile_git_history_capability(
        str(task["instruction"]), str(task["digest"])
    )
    return spec


def _write_history_baseline(agent_dir: Path, spec: dict[str, object]) -> None:
    task = spec["task"]
    assert isinstance(task, dict)
    capability = task["git_history_capability"]
    assert isinstance(capability, dict)
    tree = "1" * 40
    agent_dir.mkdir(parents=True, exist_ok=True)
    (agent_dir / "git-history-baseline.json").write_bytes(
        _canonical(
            {
                "schema_version": HISTORY_BASELINE_SCHEMA,
                "policy_version": HISTORY_BASELINE_POLICY,
                "run_spec_sha256": tb21.rust_run_spec_sha256(spec),
                "capability_instruction_sha256": capability[
                    "canonical_instruction_sha256"
                ],
                "trusted_manifest_sha256": capability["trusted_manifest_sha256"],
                "topology_before": "root",
                "topology_after": "root",
                "admitted_repo_relative_path": ".",
                "status": "isolated",
                "census_before_sha256": "4" * 64,
                "census_after_sha256": "5" * 64,
                "filesystem_manifest_before_sha256": "6" * 64,
                "filesystem_manifest_after_sha256": "6" * 64,
                "source_commit_oid": "2" * 40,
                "source_tree_oid": tree,
                "root_commit_oid": "3" * 40,
                "root_tree_oid": tree,
                "preexisting_commit_count": 1,
                "root_commit_count": 1,
                "ref_count": 1,
                "remote_count": 0,
                "alternate_count": 0,
                "old_metadata_removed": True,
            }
        )
    )


def _write_valid_result(
    job_dir: Path,
    spec: dict[str, object],
    *,
    reward: float,
    raw_usage: list[dict[str, object]] | None = None,
    background_tasks: list[dict[str, object]] | None = None,
    started_at: str = "2026-07-24T00:00:00Z",
    finished_at: str = "2026-07-24T00:00:02Z",
) -> None:
    trial = str(spec["trial_id"])
    task = dict(spec["task"])
    trial_dir = job_dir / trial
    runtime_dir = trial_dir / "agent" / "runtime"
    runtime_dir.mkdir(parents=True)
    events = b'{"event":"fixture"}\n'
    events_sha256 = hashlib.sha256(events).hexdigest()
    run_spec_sha256 = tb21.rust_run_spec_sha256(spec)
    if raw_usage is None:
        raw_usage = [
            {
                "input_tokens": 100,
                "input_tokens_details": {"cached_tokens": 40},
                "output_tokens": 20,
            }
        ]
    run_record = {
        "schema_version": "nano-run-record-alpha-1",
        "run_id": spec["run_id"],
        "trial_id": trial,
        "attempt_id": "attempt-0",
        "run_spec_sha256": run_spec_sha256,
        "contract_id": "nano-v1",
        "contract_set_sha256": "c" * 64,
        "profile_id": "nano-v1-grok-4-5-high-v1",
        "terminal_status": "success",
        "terminal_code": "completed",
        "final_event_seq": 0,
        "provider_turn_count": len(raw_usage),
        "tool_call_count": 1,
        "raw_usage": raw_usage,
        "start_elapsed_ms": 0,
        "end_elapsed_ms": 1000,
        "events_sha256": events_sha256,
    }
    (runtime_dir / "events.jsonl").write_bytes(events)
    (runtime_dir / "run.json").write_bytes(_canonical(run_record))
    manifest = {
        "schema_version": "nano-background-manifest-v1",
        "run_id": spec["run_id"],
        "trial_id": trial,
        "attempt_id": "attempt-0",
        "run_spec_sha256": run_spec_sha256,
        "tasks": background_tasks or [],
    }
    manifest_bytes = _canonical(manifest)
    (trial_dir / "agent" / "runtime-background-manifest.json").write_bytes(
        manifest_bytes
    )
    trajectory = {"schema_version": "ATIF-v1.7", "fixture": trial}
    trajectory_bytes = _canonical(trajectory)
    (trial_dir / "agent" / "trajectory.json").write_bytes(trajectory_bytes)
    marker = {
        "schema_version": "nano-agent-run-v1",
        "run_id": spec["run_id"],
        "trial_id": trial,
        "attempt_id": "attempt-0",
        "run_spec_sha256": run_spec_sha256,
        "events_sha256": events_sha256,
        "trajectory_sha256": hashlib.sha256(trajectory_bytes).hexdigest(),
        "background_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "background_task_count": len(manifest["tasks"]),
    }
    (trial_dir / "agent" / "agent-run.json").write_bytes(_canonical(marker))
    result = {
        "task_name": task["id"],
        "trial_name": trial,
        "task_checksum": task["digest"],
        "verifier_result": {"rewards": {"reward": reward}},
        "exception_info": None,
        "started_at": started_at,
        "finished_at": finished_at,
    }
    (trial_dir / "result.json").write_bytes(_canonical(result))


def _rewrite_trial_result(
    job_dir: Path,
    spec: dict[str, object],
    **updates: object,
) -> None:
    result_path = job_dir / str(spec["trial_id"]) / "result.json"
    result = json.loads(result_path.read_bytes())
    result.update(updates)
    result_path.write_bytes(_canonical(result))


def _rewrite_provider_failure_runtime(
    job_dir: Path,
    spec: dict[str, object],
    *,
    code: str,
) -> None:
    trial_dir = job_dir / str(spec["trial_id"])
    runtime_dir = trial_dir / "agent" / "runtime"
    events = [
        {
            "schema_version": "event-v1",
            "run_id": spec["run_id"],
            "trial_id": spec["trial_id"],
            "attempt_id": "attempt-0",
            "seq": 0,
            "elapsed_ms": 0,
            "type": "run.started",
            "data": {},
        },
        {
            "schema_version": "event-v1",
            "run_id": spec["run_id"],
            "trial_id": spec["trial_id"],
            "attempt_id": "attempt-0",
            "seq": 1,
            "elapsed_ms": 10,
            "type": "provider.requested",
            "data": {"turn_index": 0},
        },
        {
            "schema_version": "event-v1",
            "run_id": spec["run_id"],
            "trial_id": spec["trial_id"],
            "attempt_id": "attempt-0",
            "seq": 2,
            "elapsed_ms": 20,
            "type": "provider.failed",
            "data": {"turn_index": 0, "code": code},
        },
        {
            "schema_version": "event-v1",
            "run_id": spec["run_id"],
            "trial_id": spec["trial_id"],
            "attempt_id": "attempt-0",
            "seq": 3,
            "elapsed_ms": 30,
            "type": "run.failed",
            "data": {"code": code},
        },
    ]
    event_bytes = b"".join(_canonical(event) for event in events)
    (runtime_dir / "events.jsonl").write_bytes(event_bytes)
    run_path = runtime_dir / "run.json"
    run = json.loads(run_path.read_bytes())
    run.update(
        {
            "terminal_status": "provider_failure",
            "terminal_code": code,
            "final_event_seq": 3,
            "provider_turn_count": 1,
            "raw_usage": [],
            "start_elapsed_ms": 0,
            "end_elapsed_ms": 30,
            "events_sha256": hashlib.sha256(event_bytes).hexdigest(),
        }
    )
    run_path.write_bytes(_canonical(run))


def _rewrite_valid_v1_success_runtime(
    job_dir: Path,
    spec: dict[str, object],
) -> None:
    trial_dir = job_dir / str(spec["trial_id"])
    logs_dir = trial_dir / "agent"
    runtime_dir = logs_dir / "runtime"
    run_path = runtime_dir / "run.json"
    run = json.loads(run_path.read_bytes())
    events = [
        {
            "schema_version": "event-v1",
            "run_id": spec["run_id"],
            "trial_id": spec["trial_id"],
            "attempt_id": spec["attempt_id"],
            "seq": 0,
            "elapsed_ms": 0,
            "type": "run.started",
            "data": {},
        },
        {
            "schema_version": "event-v1",
            "run_id": spec["run_id"],
            "trial_id": spec["trial_id"],
            "attempt_id": spec["attempt_id"],
            "seq": 1,
            "elapsed_ms": 10,
            "type": "provider.requested",
            "data": {"turn_index": 0},
        },
        {
            "schema_version": "event-v1",
            "run_id": spec["run_id"],
            "trial_id": spec["trial_id"],
            "attempt_id": spec["attempt_id"],
            "seq": 2,
            "elapsed_ms": 20,
            "type": "provider.completed",
            "data": {"turn_index": 0, "usage": run["raw_usage"][0]},
        },
        {
            "schema_version": "event-v1",
            "run_id": spec["run_id"],
            "trial_id": spec["trial_id"],
            "attempt_id": spec["attempt_id"],
            "seq": 3,
            "elapsed_ms": 30,
            "type": "assistant.final",
            "data": {"text": "done"},
        },
        {
            "schema_version": "event-v1",
            "run_id": spec["run_id"],
            "trial_id": spec["trial_id"],
            "attempt_id": spec["attempt_id"],
            "seq": 4,
            "elapsed_ms": 40,
            "type": "run.completed",
            "data": {"code": "completed"},
        },
    ]
    event_bytes = b"".join(_canonical(event) for event in events)
    (runtime_dir / "events.jsonl").write_bytes(event_bytes)
    run["final_event_seq"] = len(events) - 1
    run["events_sha256"] = hashlib.sha256(event_bytes).hexdigest()
    run_path.write_bytes(_canonical(run))
    marker_path = logs_dir / "agent-run.json"
    marker = json.loads(marker_path.read_bytes())
    marker["events_sha256"] = run["events_sha256"]
    marker_path.write_bytes(_canonical(marker))


def _write_one_job(
    tmp_path: Path,
    *,
    background_tasks: list[dict[str, object]] | None = None,
) -> tuple[Path, dict[str, object]]:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    spec = _run_spec("alpha__trial", "alpha", "a" * 64)
    _write_dispatch(job_dir, [spec])
    _write_valid_result(
        job_dir,
        spec,
        reward=1.0,
        background_tasks=background_tasks,
    )
    (job_dir / "result.json").write_bytes(
        _canonical(
            {
                "finished_at": "2026-07-24T00:00:02Z",
                "stats": {"n_retries": 0},
            }
        )
    )
    return job_dir, spec


def _mark_job_drained_but_unfinished(
    job_dir: Path,
    *,
    total: int,
    cancelled: int = 1,
    errored: int | None = None,
    running: int = 0,
    pending: int = 0,
    retries: int = 0,
) -> None:
    (job_dir / "result.json").write_bytes(
        _canonical(
            {
                "id": "00000000-0000-0000-0000-000000000001",
                "started_at": "2026-07-24T00:00:00Z",
                "updated_at": "2026-07-24T00:00:02Z",
                "finished_at": None,
                "n_total_trials": total,
                "stats": {
                    "n_completed_trials": total - pending - running,
                    "n_errored_trials": cancelled if errored is None else errored,
                    "n_running_trials": running,
                    "n_pending_trials": pending,
                    "n_cancelled_trials": cancelled,
                    "n_retries": retries,
                },
            }
        )
    )


def _collect_one_cost_row(
    tmp_path: Path,
    *,
    raw_usage: list[dict[str, object]],
    pricing: tb21.Pricing | None,
) -> tuple[dict[str, object], dict[str, object]]:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    spec = _run_spec("alpha__trial", "alpha", "a" * 64)
    _write_dispatch(job_dir, [spec])
    _write_valid_result(job_dir, spec, reward=1.0, raw_usage=raw_usage)
    (job_dir / "result.json").write_bytes(
        _canonical(
            {
                "finished_at": "2026-07-24T00:00:02Z",
                "stats": {"n_retries": 0},
            }
        )
    )
    summary = tb21.collect_job(job_dir, pricing=pricing)
    row = json.loads((job_dir / "rows.jsonl").read_text())
    return row, summary


def _collected_row(job_dir: Path) -> dict[str, object]:
    tb21.collect_job(job_dir)
    return json.loads((job_dir / "rows.jsonl").read_text())


def test_collector_sums_fractional_official_rewards_canonically(tmp_path: Path) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    first = _run_spec("alpha__trial", "alpha", "a" * 64)
    second = _run_spec("beta__trial", "beta", "b" * 64)
    _write_dispatch(job_dir, [first, second])
    _write_valid_result(job_dir, first, reward=0.1)
    _write_valid_result(job_dir, second, reward=0.2)
    (job_dir / "result.json").write_bytes(
        _canonical({"finished_at": "2026-07-24T00:00:02Z", "stats": {"n_retries": 0}})
    )

    summary = tb21.collect_job(job_dir)

    assert summary["collector_accuracy"] == {
        "numerator": 0.3,
        "denominator": 2,
        "percent": 15.0,
    }
    assert summary["rewarded_atif_coverage"]["denominator"] == 2
    assert summary["gates"]["official_results"] is True


@pytest.mark.parametrize(
    "mutation", ["bool", "nan", "negative", "too_large", "duplicate"]
)
def test_collector_blocks_invalid_official_reward_evidence(
    tmp_path: Path,
    mutation: str,
) -> None:
    job_dir, spec = _write_one_job(tmp_path)
    result_path = job_dir / str(spec["trial_id"]) / "result.json"
    result = json.loads(result_path.read_bytes())
    if mutation == "bool":
        result["verifier_result"]["rewards"]["reward"] = True
        result_path.write_bytes(_canonical(result))
    elif mutation == "nan":
        result["verifier_result"]["rewards"]["reward"] = 0
        raw = _canonical(result).replace(b'"reward":0', b'"reward":NaN')
        result_path.write_bytes(raw)
    elif mutation == "negative":
        result["verifier_result"]["rewards"]["reward"] = -0.1
        result_path.write_bytes(_canonical(result))
    elif mutation == "too_large":
        result["verifier_result"]["rewards"]["reward"] = 1.1
        result_path.write_bytes(_canonical(result))
    else:
        raw = _canonical(result)
        result_path.write_bytes(b'{"task_name":"duplicate",' + raw[1:])

    summary = tb21.collect_job(job_dir)
    row = json.loads((job_dir / "rows.jsonl").read_bytes())

    assert row["raw_score_valid"] is False
    assert row["collector_pass"] is False
    assert summary["collector_accuracy"] == {
        "numerator": None,
        "denominator": 1,
        "percent": None,
        "availability": "unavailable",
    }
    assert summary["gates"]["official_results"] is False


def test_not_started_writer_drives_collector_audit_not_applicable(
    tmp_path: Path,
) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    spec = _alpha2(_run_spec("alpha__trial", "alpha", "a" * 64))
    _write_dispatch(job_dir, [spec])
    trial_dir = job_dir / str(spec["trial_id"])
    agent_dir = trial_dir / "agent"
    agent_dir.mkdir(parents=True)
    _write_history_baseline(agent_dir, spec)
    emergency = {
        "schema_version": "nano-runtime-emergency-v1",
        "run_id": spec["run_id"],
        "trial_id": spec["trial_id"],
        "attempt_id": spec["attempt_id"],
        "run_spec_sha256": tb21.rust_run_spec_sha256(spec),
        "status": "runtime_record_missing",
        "code": "deadline_before_dispatch",
        "bridge_completed": False,
        "events_sha256": None,
        "events_byte_length": None,
    }
    emergency_path = agent_dir / "runtime-emergency.json"
    emergency_path.write_bytes(_canonical(emergency))
    write_not_started(
        agent_dir,
        spec,
        terminalization_path=emergency_path,
        terminal_code="deadline_before_dispatch",
    )
    task = spec["task"]
    assert isinstance(task, dict)
    (trial_dir / "result.json").write_bytes(
        _canonical(
            {
                "task_name": task["id"],
                "trial_name": spec["trial_id"],
                "task_checksum": task["digest"],
                "verifier_result": None,
                "exception_info": {
                    "exception_type": "BridgeError",
                    "exception_message": "deadline_before_dispatch",
                },
                "started_at": "2026-07-24T00:00:00Z",
                "finished_at": "2026-07-24T00:00:01Z",
            }
        )
    )
    (job_dir / "result.json").write_bytes(
        _canonical({"finished_at": "2026-07-24T00:00:01Z", "stats": {"n_retries": 0}})
    )

    summary = tb21.collect_job(job_dir)
    row = json.loads((job_dir / "rows.jsonl").read_bytes())

    assert row["runtime_entry_state"] == "not_started"
    assert row["contamination_audit_state"] == "not_applicable"
    assert row["git_history_audit_state"] == "not_applicable"
    assert row["submission_integrity_blocking"] is False
    assert row["git_history_submission_blocking"] is False
    assert summary["collector_accuracy"] == {
        "numerator": 0.0,
        "denominator": 1,
        "percent": 0.0,
    }
    assert summary["rewarded_atif_coverage"] == {
        "numerator": 0,
        "denominator": 0,
        "percent": 100.0,
    }

    runtime_entry_path = agent_dir / "runtime-entry.json"
    runtime_entry = json.loads(runtime_entry_path.read_bytes())
    runtime_entry["run_spec_sha256"] = "f" * 64
    runtime_entry_path.write_bytes(_canonical(runtime_entry))
    tampered = tb21.collect_job(job_dir)
    tampered_row = json.loads((job_dir / "rows.jsonl").read_bytes())
    assert tampered_row["runtime_entry_state"] == "invalid"
    assert tampered_row["contamination_audit_state"] == "unavailable"
    assert tampered_row["submission_integrity_blocking"] is True
    assert tampered["gates"]["submission_integrity_clean"] is False


def _write_event_prefix(
    runtime_dir: Path,
    spec: dict[str, object],
    bodies: list[tuple[str, dict[str, object]]],
    *,
    schema: str = "event-v1",
) -> bytes:
    runtime_dir.mkdir(parents=True, exist_ok=True)
    events = [
        {
            "schema_version": schema,
            "run_id": spec["run_id"],
            "trial_id": spec["trial_id"],
            "attempt_id": spec["attempt_id"],
            "seq": sequence,
            "elapsed_ms": sequence * 10,
            "type": event_type,
            "data": data,
        }
        for sequence, (event_type, data) in enumerate(bodies)
    ]
    raw = b"".join(_canonical(event) for event in events)
    (runtime_dir / "events.jsonl").write_bytes(raw)
    return raw


def _compact_tool_receipt(
    call_id: str = "call-0",
    provider_name: str = "run_terminal_command",
) -> dict[str, object]:
    identity = json.dumps(
        {"call_id": call_id, "provider_name": provider_name},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return {
        "schema_version": "nano-tool-receipt-telemetry-v1",
        "coverage": "complete",
        "owner": "tool",
        "source": "actor_receipt",
        "phase": "cleanup",
        "origin": "transport",
        "primary_subtype": "run_transport_timeout",
        "recovery_subtype": "meta_invalid",
        "receipt_digest_sha256": "d" * 64,
        "relation": "settles",
        "tool_identity_sha256": hashlib.sha256(identity).hexdigest(),
        "tool_call_ordinal": 1,
    }


_ABSENT = object()


def _tool_receipt_prefix_raw(
    spec: dict[str, object],
    *,
    receipt: dict[str, object] | None,
    omitted_samples: object = _ABSENT,
    after_receipt: list[tuple[str, dict[str, object]]] | None = None,
) -> bytes:
    bodies: list[tuple[str, dict[str, object]]] = [
        ("run.started", {}),
        (
            "tool.registered",
            {
                "call_id": "call-0",
                "provider_name": "run_terminal_command",
                "known": True,
                "arguments_json": "{}",
            },
        ),
        (
            "tool.failed",
            {
                "call_id": "call-0",
                "provider_name": "run_terminal_command",
                "code": "terminal_actor_cleanup_unverified",
                "execution_may_have_started": True,
                "cleanup_verified": False,
                "census_verified": True,
                "recoverability": "fatal",
            },
        ),
    ]
    if receipt is not None:
        bodies.append(("tool.receipt", receipt))
    bodies.extend(after_receipt or [])
    terminal: dict[str, object] = {"code": "terminal_actor_cleanup_unverified"}
    if omitted_samples is not _ABSENT:
        terminal["tool_receipt_telemetry_omitted_samples"] = omitted_samples
    bodies.append(("run.failed", terminal))
    return b"".join(
        _canonical(
            {
                "schema_version": "event-v2",
                "run_id": spec["run_id"],
                "trial_id": spec["trial_id"],
                "attempt_id": spec["attempt_id"],
                "seq": sequence,
                "elapsed_ms": sequence,
                "type": event_type,
                "data": data,
            }
        )
        for sequence, (event_type, data) in enumerate(bodies)
    )


def test_event_prefix_accepts_compact_tool_receipt_as_advisory_coverage() -> None:
    spec = _run_spec("receipt__trial", "receipt", "a" * 64)
    raw = b"".join(
        _canonical(
            {
                "schema_version": "event-v2",
                "run_id": spec["run_id"],
                "trial_id": spec["trial_id"],
                "attempt_id": spec["attempt_id"],
                "seq": sequence,
                "elapsed_ms": sequence,
                "type": event_type,
                "data": data,
            }
        )
        for sequence, (event_type, data) in enumerate(
            [
                ("run.started", {}),
                (
                    "tool.registered",
                    {
                        "call_id": "call-0",
                        "provider_name": "run_terminal_command",
                        "known": True,
                        "arguments_json": "{}",
                    },
                ),
                (
                    "tool.failed",
                    {
                        "call_id": "call-0",
                        "provider_name": "run_terminal_command",
                        "code": "terminal_actor_cleanup_unverified",
                        "execution_may_have_started": True,
                        "cleanup_verified": False,
                        "census_verified": True,
                        "recoverability": "fatal",
                    },
                ),
                ("tool.receipt", _compact_tool_receipt()),
                (
                    "run.failed",
                    {"code": "terminal_actor_cleanup_unverified"},
                ),
            ]
        )
    )

    prefix, invalid = tb21._event_prefix_from_raw(raw, spec)

    assert invalid is False
    assert prefix is not None
    assert getattr(prefix, "tool_receipt_coverage") == "complete"


@pytest.mark.parametrize(
    ("receipt", "omitted_samples", "coverage", "signal"),
    [
        (_compact_tool_receipt(), _ABSENT, "complete", True),
        (_compact_tool_receipt(), 2, "partial", True),
        (None, 2, "partial", True),
        (None, _ABSENT, "unavailable", False),
        ({**_compact_tool_receipt(), "unknown": True}, _ABSENT, "invalid", True),
        (None, 0, "invalid", True),
    ],
)
def test_event_prefix_derives_advisory_tool_receipt_coverage(
    receipt: dict[str, object] | None,
    omitted_samples: object,
    coverage: str,
    signal: bool,
) -> None:
    spec = _run_spec("receipt__trial", "receipt", "a" * 64)

    prefix, invalid = tb21._event_prefix_from_raw(
        _tool_receipt_prefix_raw(
            spec,
            receipt=receipt,
            omitted_samples=omitted_samples,
        ),
        spec,
    )

    assert invalid is False
    assert prefix is not None
    assert prefix.tool_receipt_coverage == coverage
    assert prefix.tool_receipt_signal is signal
    assert len(prefix.tool_receipt_samples) == (
        1 if coverage in {"complete", "partial"} and receipt is not None else 0
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "terminal-actor-receipt-v1"),
        ("coverage", "partial"),
        ("owner", "runtime"),
        ("source", "transport"),
        ("phase", "unknown"),
        ("origin", "unknown"),
        ("primary_subtype", "recovered_settled"),
        ("recovery_subtype", None),
        ("receipt_digest_sha256", "D" * 64),
        ("relation", "tool.failed"),
        ("tool_identity_sha256", "e" * 64),
        ("tool_call_ordinal", 0),
        ("tool_call_ordinal", 2),
    ],
)
def test_event_prefix_contains_malformed_tool_receipt_to_telemetry_only(
    field: str,
    value: object,
) -> None:
    spec = _run_spec("receipt__trial", "receipt", "a" * 64)
    receipt = _compact_tool_receipt()
    receipt[field] = value

    prefix, invalid = tb21._event_prefix_from_raw(
        _tool_receipt_prefix_raw(spec, receipt=receipt),
        spec,
    )

    assert invalid is False
    assert prefix is not None
    assert prefix.tool_receipt_coverage == "invalid"
    assert prefix.tool_receipt_samples == ()


def test_event_prefix_rejects_duplicate_and_non_suffix_receipts_advisory_only() -> None:
    spec = _run_spec("receipt__trial", "receipt", "a" * 64)
    duplicate_raw = _tool_receipt_prefix_raw(
        spec,
        receipt=_compact_tool_receipt(),
    ).replace(
        b'"coverage":"complete"',
        b'"coverage":"complete","coverage":"complete"',
        1,
    )
    suffix_raw = _tool_receipt_prefix_raw(
        spec,
        receipt=_compact_tool_receipt(),
        after_receipt=[("assistant.final", {"text": "late mandatory event"})],
    )

    for raw in (duplicate_raw, suffix_raw):
        prefix, invalid = tb21._event_prefix_from_raw(raw, spec)
        assert invalid is False
        assert prefix is not None
        assert prefix.tool_receipt_coverage == "invalid"


def _write_v2_failure_publication(
    job_dir: Path,
    spec: dict[str, object],
    *,
    terminal_status: str = "tool_failure",
    terminal_phase: str = "bridge",
    terminal_code: str = "terminal_actor_cleanup_unverified",
    complete_workspace: bool = False,
    workspace_policy: SnapshotPolicy | None = None,
    successful: bool = False,
    tool_receipt: dict[str, object] | None = None,
    tool_receipt_omitted_samples: int | None = None,
) -> None:
    trial_dir = job_dir / str(spec["trial_id"])
    logs = trial_dir / "agent"
    runtime = logs / "runtime"
    event_bodies: list[tuple[str, dict[str, object]]] = [
        (
            "run.started",
            {
                "task_id": dict(spec["task"])["id"],
                "contract_id": "nano-v1",
                "profile_id": "nano-v1-grok-4-5-high-v1",
                "contract_set_sha256": "c" * 64,
                "model": "grok-4.5",
                "run_spec_sha256": tb21.rust_run_spec_sha256(spec),
            },
        ),
        (
            "provider.requested",
            {
                "turn_index": 0,
                "history_item_count": 2,
                "tool_count": 8,
                "function_output_call_ids": [],
            },
        ),
        (
            "provider.completed",
            {
                "turn_index": 0,
                "response_id": "response-0",
                "model": "grok-4.5",
                "call_ids": [] if successful else ["call-0"],
                "has_final_text": successful,
                "usage": _usage_value(cost_ticks=None),
            },
        ),
    ]
    if successful:
        event_bodies.extend(
            [
                ("assistant.final", {"text": "done"}),
                ("run.completed", {"code": "completed"}),
            ]
        )
        terminal_status = "success"
        terminal_phase = None
        terminal_code = "completed"
    else:
        event_bodies.extend(
            [
                (
                    "tool.registered",
                    {
                        "call_id": "call-0",
                        "provider_name": "run_terminal_command",
                        "known": True,
                        "arguments_json": '{"command":"sleep 60"}',
                    },
                ),
                (
                    "tool.dispatched",
                    {
                        "call_id": "call-0",
                        "provider_name": "run_terminal_command",
                    },
                ),
                (
                    "tool.failed",
                    {
                        "call_id": "call-0",
                        "provider_name": "run_terminal_command",
                        "code": terminal_code,
                        "execution_may_have_started": True,
                        "cleanup_verified": False,
                        "census_verified": False,
                        "recoverability": "fatal",
                    },
                ),
            ]
        )
        if tool_receipt is not None:
            event_bodies.append(("tool.receipt", tool_receipt))
        terminal_data: dict[str, object] = {"code": terminal_code}
        if tool_receipt_omitted_samples is not None:
            terminal_data["tool_receipt_telemetry_omitted_samples"] = (
                tool_receipt_omitted_samples
            )
        event_bodies.append(("run.failed", terminal_data))
    event_bytes = _write_event_prefix(
        runtime,
        spec,
        event_bodies,
        schema="event-v2",
    )
    record = {
        "schema_version": "nano-run-record-v2",
        "run_id": spec["run_id"],
        "trial_id": spec["trial_id"],
        "attempt_id": spec["attempt_id"],
        "run_spec_sha256": tb21.rust_run_spec_sha256(spec),
        "contract_id": "nano-v1",
        "contract_set_sha256": "c" * 64,
        "profile_id": "nano-v1-grok-4-5-high-v1",
        "terminal_status": terminal_status,
        "terminal_phase": terminal_phase,
        "terminal_code": terminal_code,
        "final_event_seq": len(event_bodies) - 1,
        "provider_turn_count": 1,
        "tool_call_count": 0 if successful else 1,
        "provider_call_coverage": {
            "requested": 1,
            "completed": 1,
            "failed": 0,
            "in_flight": 0,
            "usage_present": 1,
            "usage_absent": 0,
            "usage_covered": 1,
            "cost_present": 0,
            "cost_absent": 1,
            "state": "complete",
        },
        "usage_totals": {
            "input_tokens": 100,
            "cached_input_tokens": 40,
            "output_tokens": 20,
            "provider_cost_ticks": None,
        },
        "start_elapsed_ms": 0,
        "end_elapsed_ms": (len(event_bodies) - 1) * 10,
        "events_sha256": hashlib.sha256(event_bytes).hexdigest(),
    }
    (runtime / "run.json").write_bytes(_canonical(record))
    background = {
        "schema_version": "nano-background-manifest-v1",
        "run_id": spec["run_id"],
        "trial_id": spec["trial_id"],
        "attempt_id": spec["attempt_id"],
        "run_spec_sha256": tb21.rust_run_spec_sha256(spec),
        "tasks": [],
    }
    (logs / "runtime-background-manifest.json").write_bytes(_canonical(background))
    if complete_workspace:
        workspace = trial_dir / "workspace"
        workspace.mkdir()
        actor = SimpleNamespace(workspace=workspace, artifacts=logs)
        selected_policy = workspace_policy or SnapshotPolicy()
        before = asyncio.run(capture_before(actor, selected_policy))
        (workspace / "answer.txt").write_text("answer\n")
        receipt = asyncio.run(capture_after(actor, before))
        assert receipt.status == "complete"
    else:
        workspace_receipt = {
            "schema_version": "nano-workspace-receipt-v2",
            "status": "failed",
            "code": "workspace_after_capture_failed",
            "policy": {"version": "nano-workspace-snapshot-policy-v1"},
            "truncated": False,
            "omitted_count": 0,
            "artifacts": {},
            "failure": {
                "stage": "publish",
                "category": "publish",
                "errno": None,
                "return_code": None,
                "attempt": 1,
            },
        }
        (logs / "workspace-receipt.json").write_bytes(_canonical(workspace_receipt))
    publish_artifacts(
        logs_dir=logs,
        run_spec=spec,
        instruction=dict(spec["task"])["instruction"],
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="grok-4.5",
        # This collector fixture also runs in the dependency-cold checkout,
        # where Harbor is intentionally not installed. Pinned-validator
        # integration is covered separately; keep this helper provider-free.
        require_harbor_validator=False,
        require_background_manifest=True,
    )
    (job_dir / "result.json").write_bytes(
        _canonical(
            {
                "finished_at": "2026-07-24T00:00:01Z",
                "stats": {"n_retries": 0},
            }
        )
    )


def _write_collectible_v2_failure(
    tmp_path: Path,
    *,
    tool_receipt: dict[str, object] | None = None,
    tool_receipt_omitted_samples: int | None = None,
) -> tuple[Path, Path]:
    job_dir = tmp_path / "job"
    job_dir.mkdir(parents=True)
    spec = _run_spec("failure__trial", "failure", "a" * 64)
    _write_dispatch(job_dir, [spec])
    _write_v2_failure_publication(
        job_dir,
        spec,
        complete_workspace=True,
        tool_receipt=tool_receipt,
        tool_receipt_omitted_samples=tool_receipt_omitted_samples,
    )
    trial_dir = job_dir / str(spec["trial_id"])
    (trial_dir / "result.json").write_bytes(
        _canonical(
            {
                "task_name": "terminal-bench/failure",
                "trial_name": spec["trial_id"],
                "task_checksum": "a" * 64,
                "verifier_result": None,
                "exception_info": {
                    "exception_type": "BridgeError",
                    "exception_message": "external bridge failed",
                },
                "started_at": "2026-07-24T00:00:00Z",
                "finished_at": "2026-07-24T00:00:01Z",
            }
        )
    )
    return job_dir, trial_dir / "agent" / "runtime" / "run.json"


def test_collect_job_reports_receipt_coverage_without_score_or_runtime_drift(
    tmp_path: Path,
) -> None:
    baseline_job, _ = _write_collectible_v2_failure(tmp_path / "baseline")
    partial_job, _ = _write_collectible_v2_failure(
        tmp_path / "partial",
        tool_receipt=_compact_tool_receipt(),
        tool_receipt_omitted_samples=2,
    )
    invalid_receipt = {
        **_compact_tool_receipt(),
        "tool_identity_sha256": "e" * 64,
    }
    invalid_job, _ = _write_collectible_v2_failure(
        tmp_path / "invalid",
        tool_receipt=invalid_receipt,
    )

    baseline_summary = tb21.collect_job(baseline_job)
    partial_summary = tb21.collect_job(partial_job)
    invalid_summary = tb21.collect_job(invalid_job)
    baseline_row = json.loads((baseline_job / "rows.jsonl").read_bytes())
    partial_row = json.loads((partial_job / "rows.jsonl").read_bytes())
    invalid_row = json.loads((invalid_job / "rows.jsonl").read_bytes())

    assert "tool_receipt_telemetry" not in baseline_row
    assert "tool_receipt_telemetry" not in baseline_summary["terminal_evidence"]
    assert partial_row["tool_receipt_telemetry"] == {
        "coverage": "partial",
        "sample_count": 1,
        "omitted_samples": 2,
        "samples": [_compact_tool_receipt()],
    }
    assert invalid_row["tool_receipt_telemetry"] == {
        "coverage": "invalid",
        "sample_count": 0,
        "omitted_samples": 0,
        "samples": [],
    }
    assert partial_summary["terminal_evidence"]["tool_receipt_telemetry"] == {
        "coverage_counts": {
            "complete": 0,
            "partial": 1,
            "unavailable": 0,
            "invalid": 0,
        },
        "sample_count": 1,
        "omitted_samples": 2,
        "owner_counts": {"tool": 1},
        "phase_counts": {
            phase: int(phase == "cleanup")
            for phase in sorted(tb21._TOOL_RECEIPT_PHASES)
        },
    }

    for observed in (partial_row, invalid_row):
        observed_without_telemetry = dict(observed)
        observed_without_telemetry.pop("tool_receipt_telemetry")
        assert observed_without_telemetry == baseline_row
    for observed in (partial_summary, invalid_summary):
        observed_without_telemetry = json.loads(json.dumps(observed))
        del observed_without_telemetry["terminal_evidence"]["tool_receipt_telemetry"]
        assert observed_without_telemetry == baseline_summary


def test_collector_accepts_first_event_after_run_clock_origin(tmp_path: Path) -> None:
    job_dir, run_path = _write_collectible_v2_failure(tmp_path)
    runtime_dir = run_path.parent
    events_path = runtime_dir / "events.jsonl"
    events = [json.loads(line) for line in events_path.read_bytes().splitlines()]
    events[0]["elapsed_ms"] = 1
    event_bytes = b"".join(_canonical(event) for event in events)
    events_path.write_bytes(event_bytes)
    record = json.loads(run_path.read_bytes())
    assert record["start_elapsed_ms"] == 0
    record["events_sha256"] = hashlib.sha256(event_bytes).hexdigest()
    run_path.write_bytes(_canonical(record))
    spec = _run_spec("failure__trial", "failure", "a" * 64)

    parsed = tb21._parse_run_record(runtime_dir, spec)

    assert parsed is not None
    assert parsed.runtime is not None
    assert parsed.runtime.terminal_code == "terminal_actor_cleanup_unverified"


def _write_collectible_emergency_prefix(
    tmp_path: Path,
) -> tuple[Path, dict[str, object]]:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    spec = _run_spec("emergency__trial", "emergency", "a" * 64)
    _write_dispatch(job_dir, [spec])
    trial_dir = job_dir / str(spec["trial_id"])
    logs = trial_dir / "agent"
    (logs / "runtime").mkdir(parents=True)
    run_spec_sha256 = tb21.rust_run_spec_sha256(spec)
    (logs / "runtime-emergency.json").write_bytes(
        _canonical(
            {
                "schema_version": "nano-runtime-emergency-v1",
                "run_id": spec["run_id"],
                "trial_id": spec["trial_id"],
                "attempt_id": spec["attempt_id"],
                "run_spec_sha256": run_spec_sha256,
                "status": "runtime_record_missing",
                "code": "runtime_record_missing_after_bridge_completion",
                "bridge_completed": True,
                "events_sha256": None,
                "events_byte_length": None,
            }
        )
    )
    (logs / "runtime-background-manifest.json").write_bytes(
        _canonical(
            {
                "schema_version": "nano-background-manifest-v1",
                "run_id": spec["run_id"],
                "trial_id": spec["trial_id"],
                "attempt_id": spec["attempt_id"],
                "run_spec_sha256": run_spec_sha256,
                "tasks": [],
            }
        )
    )
    publish_artifacts(
        logs_dir=logs,
        run_spec=spec,
        instruction=dict(spec["task"])["instruction"],
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="grok-4.5",
        require_harbor_validator=False,
        require_background_manifest=True,
    )
    (trial_dir / "result.json").write_bytes(
        _canonical(
            {
                "task_name": "terminal-bench/emergency",
                "trial_name": spec["trial_id"],
                "task_checksum": "a" * 64,
                "verifier_result": None,
                "exception_info": {
                    "exception_type": "NanoRunFailure",
                    "exception_message": (
                        "runtime_record_missing_after_bridge_completion"
                    ),
                },
                "started_at": "2026-07-24T00:00:00Z",
                "finished_at": "2026-07-24T00:00:01Z",
            }
        )
    )
    (job_dir / "result.json").write_bytes(
        _canonical({"finished_at": "2026-07-24T00:00:01Z"})
    )
    return job_dir, spec


@pytest.mark.parametrize("publication", ["failure_atif", "emergency_atif"])
def test_terminal_atif_v4_is_valid_collector_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    publication: str,
) -> None:
    monkeypatch.setattr(
        "nano_grok_build.adapter.artifactizer.validate_with_pinned_harbor",
        lambda _trajectory: None,
    )
    if publication == "failure_atif":
        job_dir, _run_path = _write_collectible_v2_failure(tmp_path)
        spec = _run_spec("failure__trial", "failure", "a" * 64)
    else:
        job_dir, spec = _write_collectible_emergency_prefix(tmp_path)
    trial_dir = job_dir / str(spec["trial_id"])

    artifacts = tb21._artifact_evidence(trial_dir, spec)

    assert artifacts.publication_kind == publication
    assert artifacts.publication_valid is True
    assert artifacts.trajectory_valid is True
    assert artifacts.diagnostic_valid is True
    assert artifacts.success_valid is False
    assert artifacts.usage_receipt_valid is True
    assert artifacts.terminal_status != "success"
    assert (trial_dir / "agent" / "trajectory.json").is_file()


@pytest.mark.parametrize(
    "mutation",
    [
        "trajectory_hash",
        "diagnostic_hash",
        "diagnostic_path",
        "terminal_success",
        "unknown_field",
    ],
)
def test_terminal_atif_v4_marker_tamper_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    monkeypatch.setattr(
        "nano_grok_build.adapter.artifactizer.validate_with_pinned_harbor",
        lambda _trajectory: None,
    )
    job_dir, _run_path = _write_collectible_v2_failure(tmp_path)
    spec = _run_spec("failure__trial", "failure", "a" * 64)
    trial_dir = job_dir / str(spec["trial_id"])
    marker_path = trial_dir / "agent" / "agent-run.json"
    marker = json.loads(marker_path.read_bytes())
    assert marker["schema_version"] == "nano-agent-run-v4"
    if mutation == "trajectory_hash":
        marker["trajectory_sha256"] = "0" * 64
    elif mutation == "diagnostic_hash":
        marker["diagnostic_sha256"] = "0" * 64
    elif mutation == "diagnostic_path":
        marker["diagnostic_path"] = "trajectory.json"
    elif mutation == "terminal_success":
        marker["terminal_status"] = "success"
        marker["terminal_phase"] = None
        marker["terminal_code"] = "completed"
    else:
        marker["future_field"] = True
    marker_path.write_bytes(_canonical(marker))

    artifacts = tb21._artifact_evidence(trial_dir, spec)

    assert artifacts.publication_kind == "failure_atif"
    assert artifacts.publication_valid is False
    assert artifacts.trajectory_valid is False
    assert artifacts.diagnostic_valid is False
    assert artifacts.success_valid is False


def _rust_ordered_v2_run(record: dict[str, object]) -> bytes:
    field_order = (
        "schema_version",
        "run_id",
        "trial_id",
        "attempt_id",
        "run_spec_sha256",
        "contract_id",
        "contract_set_sha256",
        "profile_id",
        "terminal_status",
        "terminal_phase",
        "terminal_code",
        "final_event_seq",
        "provider_turn_count",
        "tool_call_count",
        "provider_call_coverage",
        "usage_totals",
        "start_elapsed_ms",
        "end_elapsed_ms",
        "events_sha256",
    )
    assert set(record) == set(field_order)
    ordered = {field: record[field] for field in field_order}
    assert list(ordered) != sorted(ordered)
    return (
        json.dumps(ordered, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode()


def _deadline_receipt(spec: dict[str, object]) -> dict[str, object]:
    reserves = DeadlineReservesV1(
        cleanup_ms=10_000,
        process_settlement_ms=5_000,
        provider_send_ms=2_000,
        terminalization_ms=5_000,
    )
    receipt = RunDeadlineReceiptV1.bind(
        deadline=RunDeadlineV1(
            hard_deadline_monotonic_ns=1_000_000_000_000,
            source="test_host_phase",
            agent_timeout_ms=900_000,
        ),
        run_id=str(spec["run_id"]),
        trial_id=str(spec["trial_id"]),
        attempt_id=str(spec["attempt_id"]),
        run_spec_sha256=tb21.rust_run_spec_sha256(spec),
        reserves=reserves,
    )
    return receipt.as_dict()


def _bind_deadline_to_run(
    runtime_dir: Path,
    spec: dict[str, object],
    *,
    schema_version: str,
) -> str:
    receipt_raw = _canonical(_deadline_receipt(spec))
    (runtime_dir / "deadline.json").write_bytes(receipt_raw)
    digest = hashlib.sha256(receipt_raw).hexdigest()
    events_path = runtime_dir / "events.jsonl"
    events = [json.loads(line) for line in events_path.read_bytes().splitlines()]
    events[0]["data"]["deadline_receipt_sha256"] = digest
    event_raw = b"".join(_canonical(event) for event in events)
    events_path.write_bytes(event_raw)
    run_path = runtime_dir / "run.json"
    record = json.loads(run_path.read_bytes())
    record["schema_version"] = schema_version
    record["deadline_receipt_sha256"] = digest
    record["events_sha256"] = hashlib.sha256(event_raw).hexdigest()
    run_path.write_bytes(_canonical(record))
    return digest


def _rebind_deadline_bytes(
    runtime_dir: Path,
    raw: bytes,
) -> str:
    deadline_path = runtime_dir / "deadline.json"
    deadline_path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    events_path = runtime_dir / "events.jsonl"
    events = [json.loads(line) for line in events_path.read_bytes().splitlines()]
    events[0]["data"]["deadline_receipt_sha256"] = digest
    event_raw = b"".join(_canonical(event) for event in events)
    events_path.write_bytes(event_raw)
    run_path = runtime_dir / "run.json"
    record = json.loads(run_path.read_bytes())
    record["deadline_receipt_sha256"] = digest
    record["events_sha256"] = hashlib.sha256(event_raw).hexdigest()
    run_path.write_bytes(_canonical(record))
    return digest


def _upgrade_v2_publication_reader_fixture(
    job_dir: Path,
    spec: dict[str, object],
    *,
    schema_version: str,
) -> Path:
    logs_dir = job_dir / str(spec["trial_id"]) / "agent"
    runtime_dir = logs_dir / "runtime"
    _bind_deadline_to_run(
        runtime_dir,
        spec,
        schema_version=schema_version,
    )
    record = json.loads((runtime_dir / "run.json").read_bytes())
    events_sha256 = record["events_sha256"]
    usage_path = logs_dir / "runtime-usage-receipt.json"
    usage = json.loads(usage_path.read_bytes())
    usage["events_sha256"] = events_sha256
    usage_path.write_bytes(_canonical(usage))
    trajectory_path = logs_dir / "trajectory.json"
    trajectory = json.loads(trajectory_path.read_bytes())
    trajectory["extra"]["events_sha256"] = events_sha256
    trajectory_path.write_bytes(_canonical(trajectory))
    diagnostic_path = logs_dir / "partial-trajectory.json"
    diagnostic = json.loads(diagnostic_path.read_bytes())
    diagnostic["extra"]["events_sha256"] = events_sha256
    diagnostic_path.write_bytes(_canonical(diagnostic))
    marker_path = logs_dir / "agent-run.json"
    marker = json.loads(marker_path.read_bytes())
    marker["events_sha256"] = events_sha256
    marker["run_record_schema"] = schema_version
    marker["usage_receipt_sha256"] = hashlib.sha256(usage_path.read_bytes()).hexdigest()
    marker["trajectory_sha256"] = hashlib.sha256(
        trajectory_path.read_bytes()
    ).hexdigest()
    marker["diagnostic_sha256"] = hashlib.sha256(
        diagnostic_path.read_bytes()
    ).hexdigest()
    if schema_version == "nano-run-record-v3":
        marker["deadline_receipt_sha256"] = record["deadline_receipt_sha256"]
    else:
        marker.pop("deadline_receipt_sha256", None)
    marker_path.write_bytes(_canonical(marker))
    return runtime_dir / "run.json"


def _reader_variant_fixture(
    tmp_path: Path,
    shape: str,
) -> tuple[Path, dict[str, object], Path, Path]:
    if shape == "legacy_v1":
        job_dir, spec = _write_one_job(tmp_path)
        _rewrite_valid_v1_success_runtime(job_dir, spec)
        runtime_dir = job_dir / str(spec["trial_id"]) / "agent" / "runtime"
        return job_dir, spec, runtime_dir, runtime_dir / "run.json"
    job_dir, run_path = _write_collectible_v2_failure(tmp_path)
    spec = _run_spec("failure__trial", "failure", "a" * 64)
    runtime_dir = run_path.parent
    if shape in {"v2_deadline_compat", "v3"}:
        _bind_deadline_to_run(
            runtime_dir,
            spec,
            schema_version=(
                "nano-run-record-v3" if shape == "v3" else "nano-run-record-v2"
            ),
        )
    return job_dir, spec, runtime_dir, run_path


def _usage_value(
    *,
    input_tokens: int = 100,
    cache_tokens: int = 40,
    output_tokens: int = 20,
    cost_ticks: int | None = 123_000_000,
) -> dict[str, object]:
    value: dict[str, object] = {
        "input_tokens": input_tokens,
        "input_tokens_details": {"cached_tokens": cache_tokens},
        "output_tokens": output_tokens,
    }
    if cost_ticks is not None:
        value["cost_in_usd_ticks"] = cost_ticks
    return value


def test_inventory_is_sorted_digested_and_selection_is_strict(tmp_path: Path) -> None:
    tasks = tmp_path / "tasks"
    _write_task(tasks, "z-task", cpus=2, memory_mb=4096)
    _write_task(tasks, "a-task")

    inventory = tb21.load_inventory(tasks, expected_count=2)

    assert [row.task_id for row in inventory] == [
        "terminal-bench/a-task",
        "terminal-bench/z-task",
    ]
    assert inventory[1].docker_image == "example/z-task:pinned"
    assert inventory[1].cpus == 2
    assert inventory[1].memory_mb == 4096
    assert len(inventory[0].source_sha256) == 64
    assert tb21.select_tasks(inventory, ["z-task", "a-task"]) == (
        inventory[0],
        inventory[1],
    )
    with pytest.raises(tb21.TB21Error, match="duplicate_task_selector"):
        tb21.select_tasks(inventory, ["a-task", "terminal-bench/a-task"])
    with pytest.raises(tb21.TB21Error, match="unknown_task_selector"):
        tb21.select_tasks(inventory, ["missing"])


def test_inventory_digest_reads_only_public_task_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tasks = tmp_path / "tasks"
    task_dir = _write_task(tasks, "safe-boundary")
    for relative in (
        "solution/answer.sh",
        "reference/answer.txt",
        "hidden/tests.json",
    ):
        path = task_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("sentinel-answer-bytes\n")
    original = tb21._read_regular
    opened: list[str] = []

    def guarded(path: Path, *args: object, **kwargs: object) -> bytes:
        relative = path.relative_to(task_dir).as_posix()
        opened.append(relative)
        if relative not in {
            "task.toml",
            "instruction.md",
            "environment/Dockerfile",
        }:
            raise AssertionError(f"forbidden pre-solve read: {relative}")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(tb21, "_read_regular", guarded)
    before = tb21.load_inventory(tasks, expected_count=1)[0]
    (task_dir / "solution" / "answer.sh").write_text("changed-hidden-bytes\n")
    after_hidden_change = tb21.load_inventory(tasks, expected_count=1)[0]
    (task_dir / "instruction.md").write_text("Changed public instruction.\n")
    after_public_change = tb21.load_inventory(tasks, expected_count=1)[0]

    assert set(opened) == {
        "task.toml",
        "instruction.md",
        "environment/Dockerfile",
    }
    assert before.task_digest == after_hidden_change.task_digest
    assert before.source_sha256 == after_hidden_change.source_sha256
    assert after_public_change.task_digest != before.task_digest
    assert after_public_change.source_sha256 != before.source_sha256


@pytest.mark.parametrize(
    "remote",
    [
        "https://github.com/harbor-framework/terminal-bench-2-1.git",
        "git@github.com:harbor-framework/terminal-bench-2-1.git",
        "ssh://git@github.com/harbor-framework/terminal-bench-2-1.git",
    ],
)
def test_upstream_identity_accepts_only_complete_canonical_checkout_forms(
    tmp_path: Path,
    remote: str,
) -> None:
    checkout = tmp_path / "upstream"
    checkout.mkdir()
    (checkout / "tracked.txt").write_text("complete\n")
    commit, tree = _commit_upstream_checkout(checkout, remote)

    assert tb21._verified_upstream_identity(
        checkout,
        repository="https://github.com/harbor-framework/terminal-bench-2-1.git",
        commit=commit,
        tree=tree,
        code="upstream_invalid",
    ) == {
        "repository": "https://github.com/harbor-framework/terminal-bench-2-1.git",
        "commit": commit,
        "tree": tree,
        "worktree": "complete_clean",
    }


@pytest.mark.parametrize("mutation", ["fork", "tree", "dirty", "sparse", "skip"])
def test_upstream_identity_fails_closed_on_incomplete_or_untrusted_checkout(
    tmp_path: Path,
    mutation: str,
) -> None:
    checkout = tmp_path / "upstream"
    checkout.mkdir()
    tracked = checkout / "tracked.txt"
    tracked.write_text("complete\n")
    commit, tree = _commit_upstream_checkout(
        checkout,
        "https://github.com/harbor-framework/terminal-bench-2-1.git",
    )
    expected_tree = tree
    if mutation == "fork":
        subprocess.run(
            ["git", "remote", "set-url", "origin", "https://github.com/fork/repo.git"],
            cwd=checkout,
            check=True,
        )
    elif mutation == "tree":
        expected_tree = "0" * 40
    elif mutation == "dirty":
        tracked.write_text("changed\n")
    elif mutation == "sparse":
        subprocess.run(
            ["git", "config", "core.sparseCheckout", "true"],
            cwd=checkout,
            check=True,
        )
    else:
        subprocess.run(
            ["git", "update-index", "--skip-worktree", "tracked.txt"],
            cwd=checkout,
            check=True,
        )

    with pytest.raises(tb21.TB21Error, match="^upstream_invalid$"):
        tb21._verified_upstream_identity(
            checkout,
            repository="https://github.com/harbor-framework/terminal-bench-2-1.git",
            commit=commit,
            tree=expected_tree,
            code="upstream_invalid",
        )


def test_inventory_rejects_duplicate_declared_task_names(tmp_path: Path) -> None:
    tasks = tmp_path / "tasks"
    _write_task(tasks, "one", task_name="terminal-bench/same")
    _write_task(tasks, "two", task_name="terminal-bench/same")

    with pytest.raises(tb21.TB21Error, match="duplicate_inventory_task"):
        tb21.load_inventory(tasks, expected_count=2)


def test_official_task_checksums_bind_all_pinned_identities(tmp_path: Path) -> None:
    checksums = {
        f"terminal-bench/task-{index:03d}": hashlib.sha256(
            f"official-{index}".encode()
        ).hexdigest()
        for index in range(tb21.TB21_TASK_COUNT)
    }
    inventory = tuple(SimpleNamespace(task_id=task_id) for task_id in sorted(checksums))
    path = tmp_path / tb21.OFFICIAL_TASK_CHECKSUMS_PATH
    path.parent.mkdir(parents=True)
    baseline = _official_checksum_manifest(checksums)
    path.write_bytes(_canonical(baseline))

    assert tb21.load_official_task_checksums(tmp_path, inventory) == checksums

    invalid_values: list[dict[str, object]] = []
    wrong_dataset = dict(baseline)
    wrong_dataset["dataset_digest"] = "sha256:" + "0" * 64
    invalid_values.append(wrong_dataset)
    wrong_harbor = dict(baseline)
    wrong_harbor["harbor_commit"] = "0" * 40
    invalid_values.append(wrong_harbor)
    wrong_count = dict(baseline)
    wrong_count["task_count"] = tb21.TB21_TASK_COUNT - 1
    invalid_values.append(wrong_count)
    tampered_checksums = dict(checksums)
    tampered_checksums[next(iter(tampered_checksums))] = "f" * 64
    wrong_hash = dict(baseline)
    wrong_hash["checksums"] = tampered_checksums
    invalid_values.append(wrong_hash)
    missing_checksum = dict(checksums)
    missing_checksum.pop(next(iter(missing_checksum)))
    missing = _official_checksum_manifest(missing_checksum)
    invalid_values.append(missing)

    for value in invalid_values:
        path.write_bytes(_canonical(value))
        with pytest.raises(tb21.TB21Error, match="official_task_checksums_invalid"):
            tb21.load_official_task_checksums(tmp_path, inventory)

    path.write_bytes(_canonical(baseline))
    mismatched_inventory = (
        *inventory[:-1],
        SimpleNamespace(task_id="terminal-bench/x"),
    )
    with pytest.raises(tb21.TB21Error, match="official_task_checksums_invalid"):
        tb21.load_official_task_checksums(tmp_path, mismatched_inventory)


def test_checked_in_official_task_checksum_manifest_is_canonical() -> None:
    repository = Path(__file__).resolve().parents[1]
    path = repository / tb21.OFFICIAL_TASK_CHECKSUMS_PATH
    value = json.loads(path.read_bytes())
    checksums = value["checksums"]
    inventory = tuple(SimpleNamespace(task_id=task_id) for task_id in sorted(checksums))

    assert len(checksums) == tb21.TB21_TASK_COUNT
    assert (
        hashlib.sha256(_canonical(checksums)).hexdigest()
        == "e2c68e04fd0270254c9e657211a66ea98932101a5feb62a0e89941c6a29d5ee7"
    )
    assert tb21.load_official_task_checksums(repository, inventory) == checksums


def test_task_file_supports_comments_and_combines_with_repeat_selectors(
    tmp_path: Path,
) -> None:
    tasks = tmp_path / "tasks"
    _write_task(tasks, "alpha")
    _write_task(tasks, "beta")
    inventory = tb21.load_inventory(tasks, expected_count=2)
    task_file = tmp_path / "tasks.txt"
    task_file.write_text("# frozen mini cohort\n\nbeta\n")

    selectors = ("alpha", *tb21.read_task_file(task_file))

    assert tb21.select_tasks(inventory, selectors) == inventory


def test_plan_payload_freezes_all_eight_tools_and_full_resources(
    tmp_path: Path,
) -> None:
    tasks = tmp_path / "tasks"
    _write_task(tasks, "b")
    _write_task(tasks, "a")
    inventory = tb21.load_inventory(tasks, expected_count=2)

    payload = tb21.plan_payload(
        inventory=inventory,
        selected=(inventory[0],),
        concurrency=4,
        source_checkout=tmp_path,
    )

    assert payload["active_tools"] == list(tb21.ACTIVE_TOOLS)
    assert payload["n_attempts"] == 1
    assert payload["retry_max"] == 0
    assert payload["selected_task_ids"] == ["terminal-bench/a"]
    assert len(payload["inventory"]) == 2
    assert payload["inventory"][1]["memory_mb"] == 2048
    assert payload["capability_manifest"]["capture_state"] == "missing"
    assert (
        payload["capability_manifest_sha256"]
        == hashlib.sha256(_canonical(payload["capability_manifest"])).hexdigest()
    )


def test_authoritative_89_task_plan_is_upstream_bound_and_capability_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "terminal-bench-2-1"
    tasks = source / "tasks"
    task_names = [f"task-{index:03d}" for index in range(tb21.TB21_TASK_COUNT)]
    task_names[32] = "git-leak-recovery"
    for name in task_names:
        task_dir = _write_task(tasks, name)
        hidden = task_dir / "solution" / "answer.sh"
        hidden.parent.mkdir()
        hidden.write_text("never-open-this-answer\n")
    git_instruction = (
        "A secret was accidentally committed and then removed by rewriting history.\n"
        "Please recover the secret and write it to /app/secret.txt.\n"
    )
    (tasks / "git-leak-recovery" / "instruction.md").write_text(git_instruction)
    source_commit, source_tree = _commit_upstream_checkout(
        source,
        "https://github.com/harbor-framework/terminal-bench-2-1.git",
    )
    harbor = tmp_path / "harbor"
    harbor.mkdir()
    (harbor / "README.md").write_text("Harbor fixture.\n")
    harbor_commit, harbor_tree = _commit_upstream_checkout(
        harbor,
        "git@github.com:harbor-framework/harbor.git",
    )
    monkeypatch.setattr(tb21, "TB21_SOURCE_COMMIT", source_commit)
    monkeypatch.setattr(tb21, "TB21_SOURCE_TREE", source_tree)
    monkeypatch.setattr(tb21, "HARBOR_COMMIT", harbor_commit)
    monkeypatch.setattr(tb21, "HARBOR_TREE", harbor_tree)
    checksums = {
        f"terminal-bench/{name}": hashlib.sha256(name.encode()).hexdigest()
        for name in task_names
    }
    repository = tmp_path / "runner"
    manifest_path = repository / tb21.OFFICIAL_TASK_CHECKSUMS_PATH
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_bytes(_canonical(_official_checksum_manifest(checksums)))
    original = tb21._read_regular

    def guarded(path: Path, *args: object, **kwargs: object) -> bytes:
        if path.is_relative_to(tasks):
            relative = path.relative_to(tasks)
            task_relative = Path(*relative.parts[1:]).as_posix()
            if task_relative not in {
                "task.toml",
                "instruction.md",
                "environment/Dockerfile",
            }:
                raise AssertionError(f"forbidden pre-solve read: {relative}")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(tb21, "_read_regular", guarded)
    args = tb21.parse_args(
        [
            "--plan-only",
            "--harbor-checkout",
            str(harbor),
            "--tb21-checkout",
            str(source),
            "--all",
            "--concurrency",
            "2",
        ]
    )

    _harbor, _source, inventory, selected, payload = tb21._prepare_inventory(
        args,
        repository=repository,
    )

    assert len(inventory) == len(selected) == tb21.TB21_TASK_COUNT
    authority = payload["inventory_authority"]
    assert authority == {
        "schema_version": tb21.INVENTORY_AUTHORITY_SCHEMA,
        "state": "verified",
        "official_task_checksums_sha256": hashlib.sha256(
            _canonical(checksums)
        ).hexdigest(),
        "inventory": {
            "task_count": tb21.TB21_TASK_COUNT,
            "digest_scope": tb21.PUBLIC_TASK_METADATA_SCHEMA,
            "sha256": payload["inventory_sha256"],
        },
        "upstreams": {
            "harbor": {
                "repository": tb21.HARBOR_REPOSITORY,
                "commit": harbor_commit,
                "tree": harbor_tree,
                "worktree": "complete_clean",
            },
            "terminal_bench": {
                "repository": tb21.TB21_SOURCE_REPOSITORY,
                "commit": source_commit,
                "tree": source_tree,
                "worktree": "complete_clean",
            },
        },
    }
    capabilities = payload["git_history_capabilities"]
    assert len(capabilities) == tb21.TB21_TASK_COUNT
    required = [row for row in capabilities if row["git_history_access"] == "required"]
    assert [row["task_id"] for row in required] == ["terminal-bench/git-leak-recovery"]
    assert required[0]["supporting_span_sha256"] is not None
    assert (
        payload["git_history_capabilities_sha256"]
        == hashlib.sha256(_canonical(capabilities)).hexdigest()
    )
    assert all(
        row["digest_scope"] == tb21.PUBLIC_TASK_METADATA_SCHEMA
        for row in payload["inventory"]
    )


def _write_capability_probe(path: Path, facts: object) -> bytes:
    receipt = {
        "schema_version": "nano-generic-capability-probe-v1",
        "facts": facts,
        "facts_sha256": hashlib.sha256(_canonical(facts)).hexdigest(),
    }
    raw = _canonical(receipt)
    path.write_bytes(raw)
    return raw


def test_capability_fixture_normalizes_only_fixed_allowlisted_facts(
    tmp_path: Path,
) -> None:
    fixture = json.loads(
        (
            Path(__file__).parent
            / "fixtures"
            / "tb21"
            / "capability-manifest-cases-v1.json"
        ).read_bytes()
    )
    assert fixture["schema_version"] == "nano-tb21-capability-fixtures-v1"

    for case in fixture["cases"]:
        probe = tmp_path / f"{case['name']}.json"
        raw = _write_capability_probe(probe, case["facts"])
        manifest = tb21.capture_capability_manifest(probe)

        assert manifest["schema_version"] == tb21.CAPABILITY_MANIFEST_SCHEMA
        assert manifest["capture_state"] == case["facts"]["capture_state"]
        assert manifest["source"] == {
            "probe": "generic-v1",
            "byte_length": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        assert manifest["dependencies"] == sorted(
            case["facts"]["dependencies"], key=lambda row: row["name"]
        )
        assert manifest["runtimes"] == sorted(
            case["facts"]["runtimes"], key=lambda row: row["name"]
        )
        if manifest["cpu"] is not None:
            assert manifest["cpu"]["features"] == sorted(
                case["facts"]["cpu"]["features"]
            )
        assert tb21.validate_capability_manifest(manifest)


def test_capability_missing_and_invalid_evidence_are_advisory(
    tmp_path: Path,
) -> None:
    missing = tb21.capture_capability_manifest(None)
    absent = tb21.capture_capability_manifest(tmp_path / "absent.json")
    assert missing == absent
    assert missing["capture_state"] == "missing"
    assert missing["source"] is None
    assert tb21.validate_capability_manifest(missing)

    facts = {
        "capture_state": "present",
        "cpu": None,
        "dependencies": [],
        "runtimes": [],
    }
    probe = tmp_path / "probe.json"
    raw = _write_capability_probe(probe, facts)
    receipt = json.loads(raw)
    receipt["facts_sha256"] = "0" * 64
    probe.write_bytes(_canonical(receipt))
    invalid = tb21.capture_capability_manifest(probe)
    assert invalid["capture_state"] == "invalid"
    assert invalid["source"]["sha256"] == hashlib.sha256(probe.read_bytes()).hexdigest()
    assert tb21.validate_capability_manifest(invalid)


@pytest.mark.parametrize(
    ("section", "row"),
    [
        (
            "dependencies",
            {"name": "AWS_SECRET_ACCESS_KEY", "state": "present", "version": "secret"},
        ),
        (
            "dependencies",
            {"name": "hostname", "state": "present", "version": "runner-1"},
        ),
        (
            "dependencies",
            {"name": "git", "state": "present", "version": "secret"},
        ),
        (
            "runtimes",
            {"name": "/usr/bin/python", "state": "present", "version": "3.13"},
        ),
        ("runtimes", {"name": "task_name", "state": "present", "version": "answer"}),
        (
            "runtimes",
            {"name": "docker_image", "state": "present", "version": "task-specific"},
        ),
    ],
)
def test_capability_probe_rejects_secret_path_host_task_and_image_fields(
    tmp_path: Path,
    section: str,
    row: dict[str, object],
) -> None:
    facts = {
        "capture_state": "present",
        "cpu": None,
        "dependencies": [],
        "runtimes": [],
    }
    facts[section] = [row]
    probe = tmp_path / "probe.json"
    _write_capability_probe(probe, facts)

    manifest = tb21.capture_capability_manifest(probe)

    assert manifest["capture_state"] == "invalid"
    assert manifest["cpu"] is None
    assert manifest["dependencies"] == []
    assert manifest["runtimes"] == []


def test_capability_unknown_keys_noncanonical_and_oversized_are_invalid(
    tmp_path: Path,
) -> None:
    base = {
        "capture_state": "present",
        "cpu": None,
        "dependencies": [],
        "runtimes": [],
    }
    probe = tmp_path / "probe.json"
    bad = dict(base, answer="never publish")
    _write_capability_probe(probe, bad)
    assert tb21.capture_capability_manifest(probe)["capture_state"] == "invalid"

    raw = _write_capability_probe(probe, base)
    probe.write_bytes(b" " + raw)
    assert tb21.capture_capability_manifest(probe)["capture_state"] == "invalid"

    probe.write_bytes(b"x" * (tb21.CAPABILITY_PROBE_MAX_BYTES + 1))
    oversized = tb21.capture_capability_manifest(probe)
    assert oversized["capture_state"] == "invalid"
    assert oversized["source"] is None


@pytest.mark.parametrize(
    "facts",
    [
        [],
        {
            "capture_state": [],
            "cpu": None,
            "dependencies": [],
            "runtimes": [],
        },
        {
            "capture_state": {},
            "cpu": None,
            "dependencies": [],
            "runtimes": [],
        },
        {
            "capture_state": "present",
            "cpu": {"state": [], "architecture": None, "features": []},
            "dependencies": [],
            "runtimes": [],
        },
        {
            "capture_state": "present",
            "cpu": {"state": "present", "architecture": {}, "features": []},
            "dependencies": [],
            "runtimes": [],
        },
        {
            "capture_state": "present",
            "cpu": {
                "state": "present",
                "architecture": "x86_64",
                "features": ["avx", {}],
            },
            "dependencies": [],
            "runtimes": [],
        },
        {
            "capture_state": "present",
            "cpu": None,
            "dependencies": [{"name": "git", "state": [], "version": None}],
            "runtimes": [],
        },
        {
            "capture_state": "present",
            "cpu": None,
            "dependencies": [["nested"]],
            "runtimes": [],
        },
        {
            "capture_state": "present",
            "cpu": None,
            "dependencies": [],
            "runtimes": [
                {"name": "rust", "state": "present", "version": {"nested": "1"}}
            ],
        },
    ],
)
def test_capability_arbitrary_bounded_json_closes_to_invalid(
    tmp_path: Path,
    facts: object,
) -> None:
    probe = tmp_path / "probe.json"
    _write_capability_probe(probe, facts)

    manifest = tb21.capture_capability_manifest(probe)

    assert manifest["capture_state"] == "invalid"
    assert manifest["cpu"] is None
    assert manifest["dependencies"] == []
    assert manifest["runtimes"] == []
    assert tb21.validate_capability_manifest(manifest)


def test_capability_version_cannot_publish_secret_like_arbitrary_bytes(
    tmp_path: Path,
) -> None:
    secret_like = "".join(("1", "AKIA", "_SECRET", "_EXFIL"))
    facts = {
        "capture_state": "present",
        "cpu": None,
        "dependencies": [{"name": "git", "state": "present", "version": secret_like}],
        "runtimes": [],
    }
    probe = tmp_path / "probe.json"
    _write_capability_probe(probe, facts)

    manifest = tb21.capture_capability_manifest(probe)
    payload = tb21.plan_payload(
        inventory=(),
        selected=(),
        concurrency=4,
        source_checkout=tmp_path,
        capability_manifest=manifest,
    )

    assert manifest["capture_state"] == "invalid"
    assert secret_like not in _canonical(manifest).decode()
    assert secret_like not in _canonical(payload).decode()


def test_capability_probe_rejects_unstable_fd_identity_without_growth_allocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = tmp_path / "probe.json"
    _write_capability_probe(
        probe,
        {
            "capture_state": "present",
            "cpu": None,
            "dependencies": [],
            "runtimes": [],
        },
    )
    original_fstat = os.fstat
    calls = 0

    def unstable(fd: int) -> object:
        nonlocal calls
        calls += 1
        value = original_fstat(fd)
        if calls == 1:
            return value
        return SimpleNamespace(
            st_mode=value.st_mode,
            st_dev=value.st_dev,
            st_ino=value.st_ino,
            st_size=value.st_size + 1,
            st_mtime_ns=value.st_mtime_ns,
            st_ctime_ns=value.st_ctime_ns,
        )

    monkeypatch.setattr(os, "fstat", unstable)

    manifest = tb21.capture_capability_manifest(probe)

    assert calls == 2
    assert manifest["capture_state"] == "invalid"
    assert manifest["source"] is None


@pytest.mark.parametrize(
    ("field", "malformed"),
    [
        ("capture_state", []),
        ("capture_state", {}),
        ("cpu", {"state": [], "architecture": None, "features": []}),
        ("dependencies", [{"name": "git", "state": [], "version": None}]),
        ("runtimes", [["nested"]]),
    ],
)
def test_capability_collector_keeps_malformed_manifest_advisory(
    tmp_path: Path,
    field: str,
    malformed: object,
) -> None:
    job_dir, _spec = _write_one_job(tmp_path)
    baseline = tb21.collect_job(job_dir)
    manifest = tb21.capture_capability_manifest(None)
    manifest[field] = malformed
    (job_dir / "nano-capability-manifest.json").write_bytes(_canonical(manifest))

    observed = tb21.collect_job(job_dir)

    assert observed["capabilities"]["capture_state"] == "invalid"
    assert observed["capabilities"]["evidence_state"] == "invalid"
    assert observed["gates"] == baseline["gates"]
    assert observed["strict_accuracy"] == baseline["strict_accuracy"]


def test_capability_unsorted_cpu_features_fail_plan_write_and_bound_collect(
    tmp_path: Path,
) -> None:
    manifest = {
        "schema_version": tb21.CAPABILITY_MANIFEST_SCHEMA,
        "capture_state": "present",
        "source": {
            "probe": "generic-v1",
            "byte_length": 1,
            "sha256": "0" * 64,
        },
        "cpu": {
            "state": "present",
            "architecture": "x86_64",
            "features": ["sse4_2", "avx"],
        },
        "dependencies": [],
        "runtimes": [],
    }
    assert not tb21.validate_capability_manifest(manifest)
    with pytest.raises(tb21.TB21Error, match="capability_manifest_invalid"):
        tb21.plan_payload(
            inventory=(),
            selected=(),
            concurrency=4,
            source_checkout=tmp_path,
            capability_manifest=manifest,
        )
    with pytest.raises(tb21.TB21Error, match="capability_manifest_invalid"):
        tb21._write_capability_manifest(tmp_path / "refused.json", manifest)

    job_dir = tmp_path / "job"
    job_dir.mkdir()
    raw = _canonical(manifest)
    (job_dir / "nano-capability-manifest.json").write_bytes(raw)
    observed = tb21._capability_summary(
        job_dir,
        {
            "capability_capture_state": "present",
            "capability_manifest_sha256": hashlib.sha256(raw).hexdigest(),
        },
    )
    assert observed["capture_state"] == "invalid"
    assert observed["evidence_state"] == "invalid"


def test_capability_manifest_binding_never_changes_run_spec_or_score_gates(
    tmp_path: Path,
) -> None:
    job_dir, spec = _write_one_job(tmp_path)
    before_spec = _canonical(spec)
    baseline = tb21.collect_job(job_dir)

    manifest = tb21.capture_capability_manifest(None)
    tb21._write_capability_manifest(
        job_dir / "nano-capability-manifest.json",
        manifest,
    )
    observed = tb21.collect_job(job_dir)

    assert _canonical(spec) == before_spec
    for key in (
        "accuracy",
        "strict_accuracy",
        "collector_accuracy",
        "reliability",
        "measurement_completeness",
        "gates",
        "failure_buckets",
        "tokens",
        "cost_usd",
    ):
        assert observed[key] == baseline[key]
    assert observed["capabilities"] == {
        "capture_state": "missing",
        "evidence_state": "unbound",
        "manifest_sha256": hashlib.sha256(_canonical(manifest)).hexdigest(),
    }
    assert "capabilities" not in spec

    (job_dir / "nano-capability-manifest.json").write_bytes(b'{"tampered":true}\n')
    tampered = tb21.collect_job(job_dir)
    for key in (
        "accuracy",
        "strict_accuracy",
        "collector_accuracy",
        "reliability",
        "measurement_completeness",
        "gates",
        "failure_buckets",
        "tokens",
        "cost_usd",
    ):
        assert tampered[key] == baseline[key]
    assert tampered["capabilities"]["capture_state"] == "invalid"
    assert tampered["capabilities"]["evidence_state"] == "invalid"

    (job_dir / "nano-capability-manifest.json").write_bytes(_canonical(manifest))
    digest = hashlib.sha256(_canonical(manifest)).hexdigest()
    bound = tb21._capability_summary(
        job_dir,
        {
            "capability_capture_state": "missing",
            "capability_manifest_sha256": digest,
        },
    )
    partial = tb21._capability_summary(
        job_dir,
        {"capability_manifest_sha256": digest},
    )
    wrong_sha = tb21._capability_summary(
        job_dir,
        {
            "capability_capture_state": "missing",
            "capability_manifest_sha256": "f" * 64,
        },
    )
    unbound = tb21._capability_summary(job_dir, {})
    assert bound["evidence_state"] == "present"
    assert partial["evidence_state"] == "invalid"
    assert wrong_sha["evidence_state"] == "invalid"
    assert unbound["evidence_state"] == "unbound"


def test_capability_cohort_binding_is_digest_only_and_run_spec_free(
    tmp_path: Path,
) -> None:
    tasks = tmp_path / "tasks"
    _write_task(tasks, "alpha")
    selected = tb21.load_inventory(tasks, expected_count=1)
    official_task_digest = "f" * 64
    spec = _run_spec("alpha__trial", "alpha", official_task_digest)
    manifest = tb21.capture_capability_manifest(None)
    prepared = SimpleNamespace(
        selected=selected,
        runtime_git_head="a" * 40,
        runtime_source_sha256="b" * 64,
        runtime_binary_sha256="c" * 64,
        inputs=SimpleNamespace(
            contract_set_sha256="c" * 64,
            profile_id="nano-v1-grok-4-5-high-v1",
            provider_model="grok-4.5",
            max_turns=64,
        ),
        concurrency=4,
        official_task_checksums={
            selected[0].task_id: official_task_digest,
        },
        capability_manifest=manifest,
    )
    job = SimpleNamespace(
        id="job-id",
        config=SimpleNamespace(job_name="nano-tb21-baseline"),
    )
    before_spec = _canonical(spec)

    cohort = tb21._cohort_receipt(
        prepared=prepared,
        job=job,
        specs=[spec],
    )

    assert _canonical(spec) == before_spec
    assert cohort["capability_capture_state"] == "missing"
    assert (
        cohort["capability_manifest_sha256"]
        == hashlib.sha256(_canonical(manifest)).hexdigest()
    )
    assert "capability_manifest" not in cohort
    assert "capability_manifest" not in spec
    assert cohort["tasks"][0]["task_digest"] == official_task_digest
    assert cohort["tasks"][0]["source_task_digest"] == selected[0].task_digest


def test_main_plan_only_never_prepares_runtime_or_creates_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    tasks = tmp_path / "tasks"
    _write_task(tasks, "only")
    inventory = tb21.load_inventory(tasks, expected_count=1)
    output = tmp_path / "must-not-exist"
    payload = tb21.plan_payload(
        inventory=inventory,
        selected=inventory,
        concurrency=4,
        source_checkout=tmp_path,
    )
    monkeypatch.setattr(
        tb21,
        "_prepare_inventory",
        lambda _args: (tmp_path, tmp_path, inventory, inventory, payload),
    )

    def forbidden(**_kwargs: object) -> tb21.PreparedRun:
        raise AssertionError("plan-only reached runtime or Harbor preparation")

    monkeypatch.setattr(tb21, "prepare_run", forbidden)

    assert tb21.main(["--plan-only", "--all", "--output-dir", str(output)]) == 0
    encoded = capsys.readouterr().out
    assert json.loads(encoded)["schema_version"] == "nano-tb21-plan-v1"
    assert not output.exists()


def test_main_reports_generic_runner_exception_type_without_message(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        tb21,
        "_validate_prelaunch_arguments",
        lambda _args: (_ for _ in ()).throw(RuntimeError("sensitive detail")),
    )

    assert tb21.main(["--plan-only", "--all"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "status": "failed",
        "error": "tb21_failed",
        "exception_type": "builtins.RuntimeError",
    }


def test_prelaunch_cli_is_explicit_and_mutually_exclusive_with_plan_only(
    tmp_path: Path,
) -> None:
    args = tb21.parse_args(
        [
            "--prelaunch-only",
            "--all",
            "--runtime-python",
            str(tmp_path / "python"),
            "--runtime-python-sha256",
            "a" * 64,
            "--harbor-lock-sha256",
            "b" * 64,
            "--carrier",
            "foreground",
            "--controller-pid-file",
            str(tmp_path / "controller.pid"),
        ]
    )
    assert args.prelaunch_only is True
    assert args.carrier == "foreground"

    with pytest.raises(SystemExit):
        tb21.parse_args(["--prelaunch-only", "--plan-only", "--all"])


def test_plan_only_rejects_operational_prelaunch_arguments() -> None:
    assert (
        tb21.main(
            [
                "--plan-only",
                "--all",
                "--runtime-python",
                "/runtime/python",
                "--runtime-python-sha256",
                "a" * 64,
                "--harbor-lock-sha256",
                "b" * 64,
                "--carrier",
                "foreground",
                "--controller-pid-file",
                "/tmp/controller.pid",
                "--binary",
                "/runtime/nano-cli",
                "--output-dir",
                "/tmp/output",
            ]
        )
        == 1
    )


def test_full_live_run_requires_operational_prelaunch_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        tb21,
        "_prepare_inventory",
        lambda _args: (_ for _ in ()).throw(
            AssertionError("unadmitted full run reached inventory")
        ),
    )
    assert tb21.main(["--all"]) == 1


def test_prelaunch_only_runs_full_admission_before_credentials_without_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    tasks = tmp_path / "tasks"
    _write_task(tasks, "only")
    inventory = tb21.load_inventory(tasks, expected_count=1)
    payload = tb21.plan_payload(
        inventory=inventory,
        selected=inventory,
        concurrency=2,
        source_checkout=tmp_path,
    )
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    binary = tmp_path / "nano-cli"
    binary.write_bytes(b"synthetic")
    binary.chmod(0o700)
    runtime_python = tmp_path / "runtime-python"
    runtime_python.write_bytes(b"python")
    output = tmp_path / "fresh-output"
    pid_file = tmp_path / "controller.pid"
    calls: list[str] = []
    monkeypatch.setattr(
        tb21,
        "_prepare_inventory",
        lambda _args: (tmp_path, tmp_path, inventory, inventory, payload),
    )

    def prepare(**_kwargs: object) -> object:
        calls.append("prepare")
        return SimpleNamespace(
            inputs=SimpleNamespace(
                binary_path=binary.resolve(),
                contract_dir=contract_dir.resolve(),
            )
        )

    monkeypatch.setattr(tb21, "prepare_run", prepare)

    def admit(**kwargs: object) -> dict[str, object]:
        calls.append("admit")
        assert "expected_contract_binding" not in kwargs
        assert kwargs["docker_images"] == ("example/only:pinned",)
        assert kwargs["selected_storage_mb"] == (10240,)
        return {
            "schema_version": "nano-tb21-prelaunch-admission-v1",
            "status": "passed",
            "network_calls": 0,
            "provider_calls": 0,
            "output_created": False,
        }

    monkeypatch.setattr(tb21, "admit_prelaunch", admit)
    monkeypatch.setattr(
        tb21,
        "load_xai_key",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("prelaunch-only reached credential loader")
        ),
    )

    assert (
        tb21.main(
            [
                "--prelaunch-only",
                "--all",
                "--concurrency",
                "2",
                "--harbor-checkout",
                str(tmp_path),
                "--tb21-checkout",
                str(tmp_path),
                "--contract-dir",
                str(contract_dir),
                "--binary",
                str(binary),
                "--output-dir",
                str(output),
                "--runtime-python",
                str(runtime_python),
                "--runtime-python-sha256",
                "a" * 64,
                "--harbor-lock-sha256",
                "b" * 64,
                "--carrier",
                "foreground",
                "--controller-pid-file",
                str(pid_file),
            ]
        )
        == 0
    )
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["status"] == "prelaunch-passed"
    assert receipt["admission"]["provider_calls"] == 0
    assert calls == ["prepare", "admit"]
    assert not output.exists()
    assert not pid_file.exists()


def test_prelaunch_only_rejects_incomplete_admission_arguments_before_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        tb21,
        "_prepare_inventory",
        lambda _args: (_ for _ in ()).throw(
            AssertionError("incomplete admission reached inventory")
        ),
    )
    monkeypatch.setattr(
        tb21,
        "load_xai_key",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("incomplete admission reached credential loader")
        ),
    )

    assert (
        tb21.main(
            [
                "--prelaunch-only",
                "--task",
                "only",
                "--contract-dir",
                str(tmp_path / "contract"),
            ]
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out)["error"] == (
        "prelaunch_arguments_required"
    )


def test_live_prelaunch_reverifies_admitted_images_before_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    tasks = tmp_path / "tasks"
    _write_task(tasks, "only")
    inventory = tb21.load_inventory(tasks, expected_count=1)
    payload = tb21.plan_payload(
        inventory=inventory,
        selected=inventory,
        concurrency=2,
        source_checkout=tmp_path,
    )
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    binary = tmp_path / "nano-cli"
    binary.write_bytes(b"synthetic")
    binary.chmod(0o700)
    runtime_python = tmp_path / "runtime-python"
    runtime_python.write_bytes(b"python")
    output = tmp_path / "output"
    pid_file = tmp_path / "controller.pid"
    bindings = [
        {
            "image_ref": "example/only:pinned",
            "image_id": f"sha256:{'1' * 64}",
        }
    ]
    calls: list[str] = []
    monkeypatch.setattr(
        tb21,
        "_prepare_inventory",
        lambda _args: (tmp_path, tmp_path, inventory, inventory, payload),
    )
    monkeypatch.setattr(
        tb21,
        "prepare_run",
        lambda **_kwargs: SimpleNamespace(
            inputs=SimpleNamespace(
                binary_path=binary.resolve(),
                contract_dir=contract_dir.resolve(),
            )
        ),
    )
    monkeypatch.setattr(
        tb21,
        "admit_prelaunch",
        lambda **_kwargs: {
            "schema_version": "nano-tb21-prelaunch-admission-v1",
            "status": "passed",
            "operations": {"image_bindings": bindings},
        },
    )

    def reject_drift(observed: object) -> None:
        calls.append("verify")
        assert observed == bindings
        raise tb21.PrelaunchError("docker_image_binding_drift")

    monkeypatch.setattr(tb21, "verify_docker_image_bindings", reject_drift)
    monkeypatch.setattr(
        tb21,
        "load_xai_key",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("image drift reached credential loader")
        ),
    )

    assert (
        tb21.main(
            [
                "--task",
                "only",
                "--concurrency",
                "2",
                "--harbor-checkout",
                str(tmp_path),
                "--tb21-checkout",
                str(tmp_path),
                "--contract-dir",
                str(contract_dir),
                "--binary",
                str(binary),
                "--output-dir",
                str(output),
                "--runtime-python",
                str(runtime_python),
                "--runtime-python-sha256",
                "a" * 64,
                "--harbor-lock-sha256",
                "b" * 64,
                "--carrier",
                "foreground",
                "--controller-pid-file",
                str(pid_file),
            ]
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out)["error"] == (
        "docker_image_binding_drift"
    )
    assert calls == ["verify"]
    assert not output.exists()


def test_live_path_requires_binary_contract_admission_before_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    tasks = tmp_path / "tasks"
    _write_task(tasks, "only")
    inventory = tb21.load_inventory(tasks, expected_count=1)
    payload = tb21.plan_payload(
        inventory=inventory,
        selected=inventory,
        concurrency=2,
        source_checkout=tmp_path,
    )
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    binary = tmp_path / "nano-cli"
    binary.write_bytes(b"synthetic")
    binary.chmod(0o700)
    output = tmp_path / "output"
    calls: list[str] = []
    monkeypatch.setattr(
        tb21,
        "_prepare_inventory",
        lambda _args: (tmp_path, tmp_path, inventory, inventory, payload),
    )
    monkeypatch.setattr(
        tb21,
        "prepare_run",
        lambda **_kwargs: SimpleNamespace(
            inputs=SimpleNamespace(
                binary_path=binary.resolve(),
                contract_dir=contract_dir.resolve(),
                contract_id="candidate",
                profile_id="candidate-profile",
                contract_set_sha256="f" * 64,
            )
        ),
    )

    def reject(**_kwargs: object) -> None:
        calls.append("contract")
        raise tb21.PrelaunchError("contract_admission_rejected")

    monkeypatch.setattr(tb21, "admit_contract", reject)
    monkeypatch.setattr(
        tb21,
        "load_xai_key",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("contract rejection reached credential loader")
        ),
    )

    assert (
        tb21.main(
            [
                "--task",
                "only",
                "--concurrency",
                "2",
                "--harbor-checkout",
                str(tmp_path),
                "--tb21-checkout",
                str(tmp_path),
                "--contract-dir",
                str(contract_dir),
                "--binary",
                str(binary),
                "--output-dir",
                str(output),
            ]
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out)["error"] == (
        "contract_admission_rejected"
    )
    assert calls == ["contract"]
    assert not output.exists()


def test_dispatch_legacy_contract_tuple_is_display_only(tmp_path: Path) -> None:
    first = _run_spec("alpha__trial", "alpha", "a" * 64)
    second = _run_spec("beta__trial", "beta", "b" * 64)
    second["contract"] = {
        "id": "legacy-other-contract",
        "contract_set_sha256": "f" * 64,
        "profile_id": "legacy-other-profile",
    }
    _write_dispatch(tmp_path, [first, second])

    loaded = tb21._load_dispatch(tmp_path)

    assert [spec["trial_id"] for spec in loaded] == [
        "alpha__trial",
        "beta__trial",
    ]


def test_dispatch_alpha2_capability_is_mandatory_exact_and_source_bound(
    tmp_path: Path,
) -> None:
    spec = _run_spec("alpha__trial", "alpha", "a" * 64)
    spec["schema_version"] = "nano-run-spec-alpha-2"
    task = spec["task"]
    assert isinstance(task, dict)
    task["git_history_capability"] = compile_git_history_capability(
        str(task["instruction"]), str(task["digest"])
    )
    _write_dispatch(tmp_path, [spec])
    assert tb21._load_dispatch(tmp_path)[0] == spec

    for mutation in ("missing", "malformed", "instruction", "manifest", "span"):
        changed = json.loads(json.dumps(spec))
        changed_task = changed["task"]
        capability = changed_task["git_history_capability"]
        if mutation == "missing":
            del changed_task["git_history_capability"]
        elif mutation == "malformed":
            changed_task["git_history_capability"] = ["not", "a", "record"]
        elif mutation == "instruction":
            changed_task["instruction"] += " changed"
        elif mutation == "manifest":
            capability["trusted_manifest_sha256"] = "b" * 64
        else:
            capability["supporting_span_sha256"] = "c" * 64
        _write_dispatch(tmp_path, [changed])
        with pytest.raises(tb21.TB21Error, match="^dispatch_invalid$"):
            tb21._load_dispatch(tmp_path)


def test_dispatch_alpha1_replay_is_byte_identical_and_never_upgraded(
    tmp_path: Path,
) -> None:
    spec = _run_spec("alpha__trial", "alpha", "a" * 64)
    _write_dispatch(tmp_path, [spec])
    path = tmp_path / "nano-dispatch.json"
    before = path.read_bytes()

    loaded = tb21._load_dispatch(tmp_path)

    assert loaded[0] == spec
    assert "git_history_capability" not in loaded[0]["task"]
    assert path.read_bytes() == before
    assert hashlib.sha256(path.read_bytes()).digest() == hashlib.sha256(before).digest()


def test_run_record_legacy_contract_tuple_is_display_only() -> None:
    spec = _run_spec("alpha__trial", "alpha", "a" * 64)
    record = {
        "run_id": spec["run_id"],
        "trial_id": spec["trial_id"],
        "attempt_id": spec["attempt_id"],
        "run_spec_sha256": tb21.rust_run_spec_sha256(spec),
        "contract_id": "legacy-other-contract",
        "contract_set_sha256": "f" * 64,
        "profile_id": "legacy-other-profile",
    }

    assert tb21._record_identity_valid(record, spec)


def test_prepare_run_accepts_ordinary_safe_profile_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    binary = tmp_path / "nano-cli"
    binary.write_bytes(b"synthetic-binary")
    binary.chmod(0o700)
    monkeypatch.setattr(
        tb21,
        "select_runtime_binary",
        lambda *_args, **_kwargs: (binary, "a" * 64, "b" * 40),
    )

    def load(**kwargs: object) -> object:
        assert kwargs["contract_dir"] == contract_dir
        return SimpleNamespace(
            contract_id="ordinary-contract-receipt",
            profile_id="ordinary-runtime-profile",
            contract_set_sha256="f" * 64,
            provider_model=tb21.LIVE_MODEL,
            reasoning_effort="high",
            max_turns=tb21.TB21_MAX_TURNS,
            active_tools=tb21.ACTIVE_TOOLS,
        )

    monkeypatch.setattr(tb21, "load_runtime_inputs", load)
    monkeypatch.setattr(tb21, "load_official_task_checksums", lambda *_args: {})
    prepared = tb21.prepare_run(
        repository=tmp_path,
        harbor_checkout=tmp_path / "harbor",
        source_checkout=tmp_path / "tb21",
        output_dir=tmp_path / "output",
        contract_dir=contract_dir,
        inventory=(),
        selected=(),
        concurrency=2,
        binary_path=binary,
        cargo="cargo",
    )
    assert prepared.inputs.profile_id == "ordinary-runtime-profile"
    assert prepared.official_task_checksums == {}


def test_legacy_receipt_field_is_display_only(tmp_path: Path) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    spec = _run_spec("alpha__trial", "alpha", "a" * 64)
    _write_dispatch(job_dir, [spec])
    _write_valid_result(job_dir, spec, reward=1.0)
    (job_dir / "result.json").write_bytes(
        _canonical({"finished_at": "2026-07-24T00:00:02Z"})
    )
    legacy_identity = {"legacy": "untrusted-and-non-admitting"}
    cohort = {
        "schema_version": tb21.COHORT_SCHEMA,
        "label": "full-eight-tool internal diagnostic; not a leaderboard claim",
        "dataset": tb21.TB21_DATASET,
        "dataset_ref": tb21.TB21_DATASET_REF,
        "source_commit": tb21.TB21_SOURCE_COMMIT,
        "harbor_commit": tb21.HARBOR_COMMIT,
        "job_id": "job-id",
        "job_name": "nano-tb21-baseline",
        "n_attempts": 1,
        "retry_max": 0,
        "concurrency": 2,
        "active_tools": list(tb21.ACTIVE_TOOLS),
        "runtime": {
            "git_head": "a" * 40,
            "source_sha256": "b" * 64,
            "binary_sha256": "c" * 64,
            "contract_set_sha256": "c" * 64,
            "profile_id": "nano-v1-grok-4-5-high-v1",
            "model": "grok-4.5",
            "max_provider_turns": 64,
            "approved_contract": legacy_identity,
        },
        "tasks": [
            {
                "task_id": "terminal-bench/alpha",
                "task_digest": "a" * 64,
                "source_sha256": "0" * 64,
                "trial_id": spec["trial_id"],
                "run_spec_sha256": tb21.rust_run_spec_sha256(spec),
                "resources": {},
            }
        ],
    }
    tb21._write_cohort(job_dir / "nano-tb21-cohort.json", cohort)
    summary = tb21.collect_job(job_dir)
    assert summary["pins"]["approved_contract"] == legacy_identity


def test_dotenv_loader_reads_only_xai_key_and_process_env_wins(
    tmp_path: Path,
) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_text(
        "UNRELATED=do-not-import\n"
        "XAI_API_KEY='from-file'\n"
        "SECOND_SECRET=do-not-import\n"
    )
    environment = {"PATH": "/bin"}

    assert tb21.load_xai_key(dotenv, environment)
    assert environment == {"PATH": "/bin", "XAI_API_KEY": "from-file"}

    environment = {"XAI_API_KEY": "from-process"}
    assert tb21.load_xai_key(dotenv, environment)
    assert environment["XAI_API_KEY"] == "from-process"


def test_run_baseline_uses_pinned_leaderboard_dataset_and_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tasks_root = tmp_path / "tasks"
    _write_task(tasks_root, "alpha")
    selected = tb21.load_inventory(tasks_root, expected_count=1)

    class FakeConfig:
        def __init__(self, **kwargs: object) -> None:
            self.__dict__.update(kwargs)

    class FakeTaskConfig(FakeConfig):
        def __init__(self, **kwargs: object) -> None:
            super().__init__(**kwargs)
            self.source = kwargs.get("source")

    job_config_module = types.ModuleType("harbor.models.job.config")
    job_config_module.DatasetConfig = FakeConfig  # type: ignore[attr-defined]
    job_config_module.JobConfig = FakeConfig  # type: ignore[attr-defined]
    job_config_module.RetryConfig = FakeConfig  # type: ignore[attr-defined]
    trial_config_module = types.ModuleType("harbor.models.trial.config")
    trial_config_module.AgentConfig = FakeConfig  # type: ignore[attr-defined]
    trial_config_module.EnvironmentConfig = FakeConfig  # type: ignore[attr-defined]
    trial_config_module.TaskConfig = FakeTaskConfig  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, job_config_module.__name__, job_config_module)
    monkeypatch.setitem(sys.modules, trial_config_module.__name__, trial_config_module)

    prepared = SimpleNamespace(
        harbor_checkout=tmp_path / "harbor",
        output_dir=tmp_path / "output",
        selected=selected,
        concurrency=1,
        inputs=SimpleNamespace(
            contract_set_sha256="c" * 64,
            profile_id="profile",
            reasoning_effort="high",
        ),
        capability_manifest=tb21.capture_capability_manifest(None),
    )
    captured: dict[str, object] = {}

    async def fake_create_bound_job(config: object, _inputs: object) -> object:
        captured["config"] = config
        job_dir = prepared.output_dir / "jobs" / "nano-tb21-baseline"
        job_dir.mkdir(parents=True)

        async def run() -> None:
            return None

        return SimpleNamespace(
            job=SimpleNamespace(
                id="job-id",
                config=SimpleNamespace(job_name="nano-tb21-baseline"),
                job_dir=job_dir,
                run=run,
            ),
            run_specs=[{"task": {"id": selected[0].task_id}}],
        )

    monkeypatch.setattr(tb21, "create_bound_job", fake_create_bound_job)
    monkeypatch.setattr(tb21, "_cohort_receipt", lambda **_kwargs: {})
    monkeypatch.setattr(tb21, "_write_cohort", lambda *_args: None)
    monkeypatch.setattr(tb21, "collect_job", lambda *_args, **_kwargs: {})
    original_sys_path = list(sys.path)
    try:
        asyncio.run(tb21.run_baseline(prepared))  # type: ignore[arg-type]
    finally:
        sys.path[:] = original_sys_path

    config = captured["config"]
    assert isinstance(config, FakeConfig)
    assert config.tasks == []
    assert len(config.datasets) == 1
    assert config.datasets[0].name == tb21.TB21_DATASET
    assert config.datasets[0].ref == tb21.TB21_DATASET_REF
    assert config.datasets[0].task_names == ["terminal-bench/alpha"]
    assert len(config.agents) == 1
    assert config.agents[0].name == tb21.LEADERBOARD_AGENT
    assert config.agents[0].model_name == tb21.LEADERBOARD_MODEL
    assert config.agents[0].kwargs == {"reasoning_effort": "high"}
    capability_path = (
        prepared.output_dir
        / "jobs"
        / "nano-tb21-baseline"
        / "nano-capability-manifest.json"
    )
    assert json.loads(capability_path.read_bytes()) == prepared.capability_manifest


def test_drained_interruption_terminalizes_once_then_collects_once(
    tmp_path: Path,
) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    spec = _run_spec("alpha__trial", "alpha", "a" * 64)
    _write_dispatch(job_dir, [spec])
    _write_valid_result(job_dir, spec, reward=0.0)
    _mark_job_drained_but_unfinished(job_dir, total=1)

    assert tb21._terminalize_drained_interruption(  # type: ignore[attr-defined]
        job_dir,
        [spec],
        asyncio.CancelledError(),
    )
    receipt_path = job_dir / "nano-terminalization.json"
    first = receipt_path.read_bytes()
    first_inode = receipt_path.stat().st_ino
    assert not tb21._terminalize_drained_interruption(  # type: ignore[attr-defined]
        job_dir,
        [spec],
        asyncio.CancelledError(),
    )
    assert receipt_path.read_bytes() == first
    assert receipt_path.stat().st_ino == first_inode
    receipt = json.loads(first)
    assert receipt["schema_version"] == "nano-tb21-terminalization-v2"
    assert receipt["status"] == "interrupted"
    assert receipt["reason"] == "operator_interrupted"
    assert receipt["finished_at"] is not None
    assert receipt["census"] == {
        "n_total_trials": 1,
        "n_started_trials": 1,
        "n_terminal_trials": 1,
        "n_not_started_trials": 0,
        "n_incomplete_trials": 0,
        "n_pending_trials": 0,
        "n_cancelled_trials": 1,
        "n_errored_trials": 1,
        "n_retries": 0,
    }
    assert [
        {
            key: trial[key]
            for key in (
                "trial_id",
                "task_id",
                "task_digest",
                "state",
                "result_sha256",
                "finished_at",
            )
        }
        for trial in receipt["trials"]
    ] == [
        {
            "trial_id": "alpha__trial",
            "task_id": "terminal-bench/alpha",
            "task_digest": "a" * 64,
            "state": "terminal",
            "result_sha256": hashlib.sha256(
                (job_dir / "alpha__trial" / "result.json").read_bytes()
            ).hexdigest(),
            "finished_at": "2026-07-24T00:00:02Z",
        }
    ]
    assert json.loads((job_dir / "result.json").read_bytes())["finished_at"] is None

    summary = tb21.collect_job(job_dir)

    assert summary["counts"]["expected"] == 1
    assert summary["counts"]["observed"] == 1
    assert summary["counts"]["retries"] == 0


def test_interruption_terminalizes_pending_and_running_without_fabricating_scores(
    tmp_path: Path,
) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    terminal_spec = _run_spec("terminal__trial", "terminal", "a" * 64)
    incomplete_spec = _run_spec("incomplete__trial", "incomplete", "b" * 64)
    not_started_spec = _run_spec("not-started__trial", "not-started", "c" * 64)
    specs = [terminal_spec, incomplete_spec, not_started_spec]
    _write_dispatch(job_dir, specs)
    _write_valid_result(job_dir, terminal_spec, reward=1.0)
    incomplete_dir = job_dir / str(incomplete_spec["trial_id"])
    incomplete_dir.mkdir()
    (incomplete_dir / "result.json").write_bytes(
        _canonical(
            {
                "task_name": "terminal-bench/incomplete",
                "trial_name": incomplete_spec["trial_id"],
                "task_checksum": "b" * 64,
                "verifier_result": None,
                "exception_info": {
                    "exception_type": "CancelledError",
                    "exception_message": "operator interrupted",
                },
                "started_at": "2026-07-24T00:00:01Z",
                "finished_at": None,
            }
        )
    )
    _mark_job_drained_but_unfinished(
        job_dir,
        total=3,
        cancelled=0,
        running=1,
        pending=1,
    )
    pricing = _write_pricing(tmp_path / "pricing.json")

    assert tb21._terminalize_interruption(  # type: ignore[attr-defined]
        job_dir,
        specs,
        KeyboardInterrupt(),
        pricing=pricing,
    )
    receipt_path = job_dir / "nano-terminalization.json"
    first = receipt_path.read_bytes()
    receipt = json.loads(first)
    assert receipt["schema_version"] == "nano-tb21-terminalization-v2"
    assert receipt["status"] == "interrupted"
    assert receipt["reason"] == "operator_interrupted"
    assert receipt["census"] == {
        "n_total_trials": 3,
        "n_started_trials": 2,
        "n_terminal_trials": 1,
        "n_not_started_trials": 1,
        "n_incomplete_trials": 1,
        "n_pending_trials": 1,
        "n_cancelled_trials": 0,
        "n_errored_trials": 0,
        "n_retries": 0,
    }
    assert {trial["trial_id"]: trial["state"] for trial in receipt["trials"]} == {
        "terminal__trial": "terminal",
        "incomplete__trial": "incomplete",
        "not-started__trial": "not_started",
    }
    assert receipt["evidence"]["usage_state_counts"] == {
        "complete": 1,
        "partial": 0,
        "unavailable": 2,
        "invalid": 0,
    }
    assert receipt["evidence"]["trajectory_coverage"] == "1/2"
    assert receipt["evidence"]["workspace_snapshot_coverage"] == "0/2"
    assert receipt["evidence"]["cost_usd_observed_lower_bound"] == pytest.approx(
        0.00034
    )
    assert receipt["evidence"]["cost_task_coverage"] == "1/3"

    assert not tb21._terminalize_interruption(  # type: ignore[attr-defined]
        job_dir,
        specs,
        KeyboardInterrupt(),
        pricing=pricing,
    )
    assert receipt_path.read_bytes() == first

    summary = tb21.collect_job(job_dir, pricing=pricing)
    rows = {
        row["trial"]: row
        for row in map(json.loads, (job_dir / "rows.jsonl").read_text().splitlines())
    }
    assert len(rows) == 3
    assert rows["terminal__trial"]["interruption_state"] == "terminal"
    assert rows["terminal__trial"]["reward"] == 1.0
    assert rows["not-started__trial"]["interruption_state"] == "not_started"
    assert rows["not-started__trial"]["reward"] is None
    assert rows["not-started__trial"]["raw_score_valid"] is False
    assert rows["not-started__trial"]["collector_pass"] is False
    assert rows["not-started__trial"]["strict_pass"] is False
    assert rows["not-started__trial"]["reliable"] is False
    assert rows["not-started__trial"]["measurement_complete"] is False
    assert rows["incomplete__trial"]["interruption_state"] == "incomplete"
    assert rows["incomplete__trial"]["reward"] is None
    assert rows["incomplete__trial"]["raw_score_valid"] is False
    assert summary["run_outcome"] == {
        "status": "interrupted",
        "reason": "operator_interrupted",
        "complete": False,
        "receipt_schema": "nano-tb21-terminalization-v2",
    }
    for key in (
        "accuracy",
        "strict_accuracy",
        "collector_accuracy",
        "reliability",
        "measurement_completeness",
    ):
        assert summary[key] == {
            "numerator": None,
            "denominator": 3,
            "percent": None,
            "availability": "unavailable",
        }
    assert summary["counts"]["expected"] == 3
    assert summary["counts"]["observed"] == 2
    assert summary["counts"]["completed"] == 1
    assert summary["counts"]["not_started"] == 1
    assert summary["counts"]["incomplete"] == 1
    assert summary["gates"]["job_terminal"] is True
    assert summary["gates"]["run_complete"] is False
    assert summary["gates"]["interruption_receipt"] is True
    assert summary["cost_usd"]["observed_lower_bound"] == pytest.approx(0.00034)
    rows_first = (job_dir / "rows.jsonl").read_bytes()
    summary_first = (job_dir / "summary.json").read_bytes()
    assert tb21.collect_job(job_dir, pricing=pricing) == summary
    assert (job_dir / "rows.jsonl").read_bytes() == rows_first
    assert (job_dir / "summary.json").read_bytes() == summary_first


def test_interruption_receipt_rejects_job_result_and_started_evidence_drift(
    tmp_path: Path,
) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    started = _run_spec("started__trial", "started", "a" * 64)
    pending = _run_spec("pending__trial", "pending", "b" * 64)
    specs = [started, pending]
    _write_dispatch(job_dir, specs)
    _write_valid_result(job_dir, started, reward=0.0)
    _mark_job_drained_but_unfinished(
        job_dir,
        total=2,
        cancelled=0,
        pending=1,
    )
    tb21._terminalize_interruption(  # type: ignore[attr-defined]
        job_dir,
        specs,
        RuntimeError("safe runner failure"),
    )
    receipt_raw = (job_dir / "nano-terminalization.json").read_bytes()
    assert b"safe runner failure" not in receipt_raw
    assert json.loads(receipt_raw)["reason"] == "runner_exception"
    tb21.collect_job(job_dir)
    rows = {
        row["trial"]: row
        for row in map(json.loads, (job_dir / "rows.jsonl").read_text().splitlines())
    }
    pending_row = rows["pending__trial"]
    assert pending_row["interruption_state"] == "not_started"
    assert pending_row["interruption_reason"] == "runner_exception"
    assert pending_row["failure_bucket"] == "environment_infra"
    assert pending_row["failure_phase"] == "runtime"
    assert pending_row["failure_code"] == "runner_exception_not_started"
    assert pending_row["failure_recoverability"] == "recoverable"
    assert pending_row["reward"] is None
    assert pending_row["raw_score_valid"] is False
    assert pending_row["collector_pass"] is False
    assert pending_row["strict_pass"] is False
    assert pending_row["reliable"] is False
    assert pending_row["measurement_complete"] is False

    result_path = job_dir / "started__trial" / "result.json"
    original = result_path.read_bytes()
    result_path.write_bytes(original + b" ")
    with pytest.raises(tb21.TB21Error, match="job_terminalization_invalid"):
        tb21.collect_job(job_dir)

    result_path.write_bytes(original)
    job_result_path = job_dir / "result.json"
    job_result = json.loads(job_result_path.read_bytes())
    job_result["stats"]["n_pending_trials"] = 0
    job_result_path.write_bytes(_canonical(job_result))
    with pytest.raises(tb21.TB21Error, match="job_terminalization_invalid"):
        tb21.collect_job(job_dir)


def test_exact_89_interruption_projects_14_terminal_and_75_not_started_rows(
    tmp_path: Path,
) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    specs = [
        _run_spec(
            f"task-{index:02d}__trial",
            f"task-{index:02d}",
            f"{index:064x}",
        )
        for index in range(89)
    ]
    _write_dispatch(job_dir, specs)
    for spec in specs[:14]:
        _write_valid_result(job_dir, spec, reward=0.0)
    _mark_job_drained_but_unfinished(
        job_dir,
        total=89,
        cancelled=0,
        errored=14,
        pending=75,
    )

    tb21._terminalize_interruption(  # type: ignore[attr-defined]
        job_dir,
        specs,
        KeyboardInterrupt(),
    )
    summary = tb21.collect_job(job_dir)
    rows = [
        json.loads(line) for line in (job_dir / "rows.jsonl").read_text().splitlines()
    ]

    assert len(rows) == 89
    assert sum(row["interruption_state"] == "terminal" for row in rows) == 14
    assert sum(row["interruption_state"] == "not_started" for row in rows) == 75
    assert all(
        row["reward"] is None
        and row["raw_score_valid"] is False
        and row["collector_pass"] is False
        and row["strict_pass"] is False
        and row["reliable"] is False
        and row["measurement_complete"] is False
        for row in rows[14:]
    )
    assert summary["counts"]["expected"] == 89
    assert summary["counts"]["observed"] == 14
    assert summary["counts"]["completed"] == 14
    assert summary["counts"]["not_started"] == 75
    assert summary["counts"]["incomplete"] == 0
    assert summary["accuracy"]["availability"] == "unavailable"
    assert summary["strict_accuracy"]["availability"] == "unavailable"
    assert summary["reliability"]["availability"] == "unavailable"
    assert summary["measurement_completeness"]["availability"] == "unavailable"
    assert summary["cost_usd"]["value"] is None
    assert summary["cost_usd"]["is_lower_bound"] is True
    assert summary["gates"]["run_complete"] is False


def test_legacy_v1_terminalization_receipt_remains_collectible(
    tmp_path: Path,
) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    spec = _run_spec("alpha__trial", "alpha", "a" * 64)
    _write_dispatch(job_dir, [spec])
    _write_valid_result(job_dir, spec, reward=0.0)
    _mark_job_drained_but_unfinished(job_dir, total=1)
    legacy = tb21._terminalization_value(  # type: ignore[attr-defined]
        job_dir,
        [spec],
        finished_at="2026-07-24T00:00:03Z",
    )
    (job_dir / "nano-terminalization.json").write_bytes(_canonical(legacy))

    summary = tb21.collect_job(job_dir)
    row = json.loads((job_dir / "rows.jsonl").read_bytes())

    assert legacy["schema_version"] == "nano-tb21-terminalization-v1"
    assert "run_outcome" not in summary
    assert "interruption_state" not in row
    assert summary["accuracy"] == {
        "numerator": 0,
        "denominator": 1,
        "percent": 0.0,
    }


def test_interruption_with_retry_count_fails_closed(tmp_path: Path) -> None:
    job_dir = tmp_path / "retry"
    job_dir.mkdir()
    spec = _run_spec("alpha__trial", "alpha", "a" * 64)
    _write_dispatch(job_dir, [spec])
    _write_valid_result(job_dir, spec, reward=0.0)
    _mark_job_drained_but_unfinished(job_dir, total=1, retries=1)

    with pytest.raises(tb21.TB21Error, match="job_not_terminal"):
        tb21._terminalize_drained_interruption(  # type: ignore[attr-defined]
            job_dir,
            [spec],
            KeyboardInterrupt(),
        )
    assert not (job_dir / "nano-terminalization.json").exists()


def test_terminalization_tamper_is_rejected_by_collect_only(tmp_path: Path) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    spec = _run_spec("alpha__trial", "alpha", "a" * 64)
    _write_dispatch(job_dir, [spec])
    _write_valid_result(job_dir, spec, reward=0.0)
    _mark_job_drained_but_unfinished(job_dir, total=1)
    tb21._terminalize_drained_interruption(  # type: ignore[attr-defined]
        job_dir,
        [spec],
        KeyboardInterrupt(),
    )
    result_path = job_dir / "alpha__trial" / "result.json"
    result_path.write_bytes(result_path.read_bytes() + b" ")

    with pytest.raises(tb21.TB21Error, match="job_terminalization_invalid"):
        tb21.collect_job(job_dir)


def test_interruption_receipt_content_tamper_is_rejected_by_collect_only(
    tmp_path: Path,
) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    spec = _run_spec("alpha__trial", "alpha", "a" * 64)
    _write_dispatch(job_dir, [spec])
    _write_valid_result(job_dir, spec, reward=0.0)
    _mark_job_drained_but_unfinished(job_dir, total=1)
    tb21._terminalize_interruption(  # type: ignore[attr-defined]
        job_dir,
        [spec],
        KeyboardInterrupt(),
    )
    receipt_path = job_dir / "nano-terminalization.json"
    receipt = json.loads(receipt_path.read_bytes())
    receipt["trials"][0]["state"] = "not_started"
    receipt_path.write_bytes(_canonical(receipt))

    with pytest.raises(tb21.TB21Error, match="job_terminalization_invalid"):
        tb21.collect_job(job_dir)
    assert not (job_dir / "rows.jsonl").exists()
    assert not (job_dir / "summary.json").exists()


def test_abort_collect_preserves_partial_usage_trajectory_and_cleanup_failure(
    tmp_path: Path,
) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    cleanup_spec = _run_spec("cleanup__trial", "cleanup", "a" * 64)
    partial_spec = _run_spec("partial__trial", "partial", "b" * 64)
    specs = [cleanup_spec, partial_spec]
    _write_dispatch(job_dir, specs)
    _write_v2_failure_publication(job_dir, cleanup_spec)
    cleanup_dir = job_dir / "cleanup__trial"
    (cleanup_dir / "result.json").write_bytes(
        _canonical(
            {
                "task_name": "terminal-bench/cleanup",
                "trial_name": "cleanup__trial",
                "task_checksum": "a" * 64,
                "verifier_result": None,
                "exception_info": {
                    "exception_type": "BridgeError",
                    "exception_message": "terminal_actor_cleanup_unverified",
                },
                "started_at": "2026-07-24T00:00:00Z",
                "finished_at": "2026-07-24T00:00:01Z",
            }
        )
    )
    partial_dir = job_dir / "partial__trial"
    runtime = partial_dir / "agent" / "runtime"
    _write_event_prefix(
        runtime,
        partial_spec,
        [
            (
                "run.started",
                {
                    "task_id": "terminal-bench/partial",
                    "contract_id": "nano-v1",
                    "profile_id": "nano-v1-grok-4-5-high-v1",
                    "contract_set_sha256": "c" * 64,
                    "model": "grok-4.5",
                    "run_spec_sha256": tb21.rust_run_spec_sha256(partial_spec),
                },
            ),
            (
                "provider.requested",
                {
                    "turn_index": 0,
                    "history_item_count": 2,
                    "tool_count": 8,
                    "function_output_call_ids": [],
                },
            ),
            (
                "provider.completed",
                {
                    "turn_index": 0,
                    "response_id": "response-0",
                    "model": "grok-4.5",
                    "call_ids": [],
                    "has_final_text": False,
                    "usage": _usage_value(),
                },
            ),
            (
                "provider.requested",
                {
                    "turn_index": 1,
                    "history_item_count": 3,
                    "tool_count": 8,
                    "function_output_call_ids": [],
                },
            ),
        ],
    )
    partial_dir.mkdir(parents=True, exist_ok=True)
    (partial_dir / "result.json").write_bytes(
        _canonical(
            {
                "task_name": "terminal-bench/partial",
                "trial_name": "partial__trial",
                "task_checksum": "b" * 64,
                "verifier_result": None,
                "exception_info": {
                    "exception_type": "CancelledError",
                    "exception_message": "operator interrupted",
                },
                "started_at": "2026-07-24T00:00:00Z",
                "finished_at": "2026-07-24T00:00:01Z",
            }
        )
    )
    _mark_job_drained_but_unfinished(job_dir, total=2)
    evidence_before = {
        path.relative_to(job_dir): hashlib.sha256(path.read_bytes()).hexdigest()
        for trial_dir in (cleanup_dir, partial_dir)
        for path in trial_dir.rglob("*")
        if path.is_file()
    }

    tb21._terminalize_drained_interruption(
        job_dir,
        specs,
        KeyboardInterrupt(),
    )
    summary = tb21.collect_job(job_dir)

    rows = {
        row["task"]: row
        for row in map(json.loads, (job_dir / "rows.jsonl").read_text().splitlines())
    }
    cleanup = rows["terminal-bench/cleanup"]
    partial = rows["terminal-bench/partial"]
    assert cleanup["publication_kind"] == "failure_atif"
    assert cleanup["runtime_terminal_code"] == "terminal_actor_cleanup_unverified"
    assert (cleanup_dir / "agent" / "partial-trajectory.json").is_file()
    assert partial["usage_state"] == "partial"
    assert partial["provider_calls_requested"] == 2
    assert partial["provider_calls_completed"] == 1
    assert partial["provider_calls_in_flight"] == 1
    assert summary["cost_usd"]["observed_lower_bound"] == pytest.approx(0.0123)
    assert evidence_before == {
        path.relative_to(job_dir): hashlib.sha256(path.read_bytes()).hexdigest()
        for trial_dir in (cleanup_dir, partial_dir)
        for path in trial_dir.rglob("*")
        if path.is_file()
    }


def test_run_baseline_drained_cancel_preserves_cancel_and_skips_internal_collect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tasks_root = tmp_path / "tasks"
    _write_task(tasks_root, "alpha")
    selected = tb21.load_inventory(tasks_root, expected_count=1)

    class FakeConfig:
        def __init__(self, **kwargs: object) -> None:
            self.__dict__.update(kwargs)

    job_config_module = types.ModuleType("harbor.models.job.config")
    job_config_module.DatasetConfig = FakeConfig  # type: ignore[attr-defined]
    job_config_module.JobConfig = FakeConfig  # type: ignore[attr-defined]
    job_config_module.RetryConfig = FakeConfig  # type: ignore[attr-defined]
    trial_config_module = types.ModuleType("harbor.models.trial.config")
    trial_config_module.AgentConfig = FakeConfig  # type: ignore[attr-defined]
    trial_config_module.EnvironmentConfig = FakeConfig  # type: ignore[attr-defined]
    trial_config_module.TaskConfig = FakeConfig  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, job_config_module.__name__, job_config_module)
    monkeypatch.setitem(sys.modules, trial_config_module.__name__, trial_config_module)

    prepared = SimpleNamespace(
        harbor_checkout=tmp_path / "harbor",
        output_dir=tmp_path / "output",
        selected=selected,
        concurrency=1,
        inputs=SimpleNamespace(
            contract_set_sha256="c" * 64,
            profile_id="profile",
            reasoning_effort="high",
        ),
    )
    collect_calls = 0
    run_calls = 0
    run_error: BaseException = asyncio.CancelledError()
    allow_collect = False

    async def fake_create_bound_job(_config: object, _inputs: object) -> object:
        job_dir = prepared.output_dir / "jobs" / "nano-tb21-baseline"
        job_dir.mkdir(parents=True)
        spec = _run_spec(
            "alpha__trial",
            "alpha",
            selected[0].task_digest,
        )
        _write_dispatch(job_dir, [spec])
        _write_valid_result(job_dir, spec, reward=0.0)
        _mark_job_drained_but_unfinished(job_dir, total=1)

        async def run() -> None:
            nonlocal run_calls
            run_calls += 1
            raise run_error

        return SimpleNamespace(
            job=SimpleNamespace(
                id="job-id",
                config=SimpleNamespace(job_name="nano-tb21-baseline"),
                job_dir=job_dir,
                run=run,
            ),
            run_specs=[spec],
        )

    def tracked_collect(*_args: object, **_kwargs: object) -> dict[str, object]:
        nonlocal collect_calls
        collect_calls += 1
        if not allow_collect:
            raise AssertionError("abort path must not collect internally")
        return {}

    monkeypatch.setattr(tb21, "create_bound_job", fake_create_bound_job)
    monkeypatch.setattr(tb21, "_cohort_receipt", lambda **_kwargs: {})
    monkeypatch.setattr(tb21, "_write_cohort", lambda *_args: None)
    monkeypatch.setattr(tb21, "collect_job", tracked_collect)
    original_sys_path = list(sys.path)
    try:
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(tb21.run_baseline(prepared))  # type: ignore[arg-type]
    finally:
        sys.path[:] = original_sys_path

    job_dir = prepared.output_dir / "jobs" / "nano-tb21-baseline"
    assert run_calls == 1
    assert collect_calls == 0
    assert (job_dir / "nano-terminalization.json").is_file()
    assert json.loads((job_dir / "result.json").read_bytes())["stats"]["n_retries"] == 0

    prepared.output_dir = tmp_path / "noncancel-output"
    run_error = RuntimeError("synthetic job failure")
    allow_collect = True
    with pytest.raises(RuntimeError, match="synthetic job failure"):
        asyncio.run(tb21.run_baseline(prepared))  # type: ignore[arg-type]
    noncancel_job = prepared.output_dir / "jobs" / "nano-tb21-baseline"
    assert run_calls == 2
    assert collect_calls == 0
    noncancel_receipt = json.loads(
        (noncancel_job / "nano-terminalization.json").read_bytes()
    )
    assert noncancel_receipt["status"] == "interrupted"
    assert noncancel_receipt["reason"] == "runner_exception"

    prepared.output_dir = tmp_path / "finalizer-failure-output"
    run_error = RuntimeError("original runner stage")

    def fail_finalization(*_args: object, **_kwargs: object) -> bool:
        raise tb21.TB21Error("synthetic_finalizer_failure")

    monkeypatch.setattr(tb21, "_terminalize_interruption", fail_finalization)
    with pytest.raises(
        tb21.TB21Error,
        match="interruption_finalization_failed",
    ) as captured:
        asyncio.run(tb21.run_baseline(prepared))  # type: ignore[arg-type]
    assert isinstance(captured.value.__cause__, tb21.TB21Error)
    assert str(captured.value.__cause__) == "synthetic_finalizer_failure"
    assert isinstance(captured.value.__cause__.__context__, RuntimeError)
    assert str(captured.value.__cause__.__context__) == "original runner stage"


def test_pinned_harbor_two_task_finalization_path_is_container_free(
    tmp_path: Path,
) -> None:
    harbor_checkout = Path(
        os.environ.get("NANO_HARBOR_CHECKOUT", "/private/tmp/harbor-rights-audit")
    )
    harbor_python = Path(
        os.environ.get(
            "NANO_HARBOR_PYTHON",
            "/private/tmp/nano-harbor-bridge.Imwx92/harbor/.venv/bin/python",
        )
    )
    if not harbor_checkout.is_dir() or not harbor_python.is_file():
        pytest.skip("pinned Harbor checkout/runtime is not available")
    harbor_head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=harbor_checkout,
        capture_output=True,
        text=True,
    )
    if harbor_head.returncode != 0:
        pytest.skip("pinned Harbor checkout is not a valid Git worktree")
    assert harbor_head.stdout.strip() == tb21.HARBOR_COMMIT

    script = textwrap.dedent(
        """
        import asyncio
        import json
        import sys
        from datetime import datetime, timezone
        from pathlib import Path

        from harbor.environments.factory import EnvironmentFactory
        from harbor.job import Job
        from harbor.models.job.config import JobConfig, RetryConfig
        from harbor.models.trial.config import TaskConfig
        from harbor.models.trial.result import AgentInfo, ModelInfo, TrialResult
        from harbor.models.verifier.result import VerifierResult
        from harbor.tasks.client import TaskDownloadResult
        from harbor.trial.hooks import TrialEvent, TrialHookEvent


        async def main(root: Path) -> None:
            task_configs = []
            for name in ("alpha", "beta"):
                task_dir = root / "tasks" / name
                task_dir.mkdir(parents=True)
                (task_dir / "instruction.md").write_text(f"Solve {name}.\\n")
                task_configs.append(TaskConfig(path=task_dir))

            config = JobConfig(
                job_name="offline-finalization",
                jobs_dir=root / "jobs",
                n_attempts=1,
                n_concurrent_trials=2,
                quiet=True,
                retry=RetryConfig(max_retries=0),
                tasks=task_configs,
            )
            metrics = await Job._resolve_metrics(config, task_configs)
            downloads = {
                task.get_task_id(): TaskDownloadResult(
                    path=task.get_local_path(),
                    download_time_sec=0.0,
                    cached=True,
                )
                for task in task_configs
            }
            job = Job(
                config,
                _task_configs=task_configs,
                _metrics=metrics,
                _task_download_results=downloads,
            )
            environment_calls = 0

            def forbidden_environment(cls, *args, **kwargs):
                nonlocal environment_calls
                environment_calls += 1
                raise AssertionError("offline finalization test created an environment")

            EnvironmentFactory.create_environment = classmethod(forbidden_environment)

            async def execute(config, index):
                assert job._job_lock is not None
                now = datetime.now(timezone.utc)
                task_name = config.task.get_task_id().get_name()
                trial_dir = job.job_dir / config.trial_name
                result = TrialResult(
                    task_name=task_name,
                    trial_name=config.trial_name,
                    trial_uri=trial_dir.as_uri(),
                    task_id=config.task.get_task_id(),
                    source=config.task.source,
                    task_checksum=f"digest-{index}",
                    config=config,
                    agent_info=AgentInfo(
                        name="offline-fake",
                        version="1.0",
                        model_info=ModelInfo(name="offline-model"),
                    ),
                    verifier_result=VerifierResult(rewards={"reward": float(index)}),
                    started_at=now,
                    finished_at=now,
                )
                event = TrialHookEvent(
                    event=TrialEvent.END,
                    task_name=task_name,
                    config=config,
                    result=result,
                    lock=job._job_lock.trials[index],
                )
                for hook in list(job._trial_queue._hooks[TrialEvent.END]):
                    await hook(event)
                trial_dir.mkdir(parents=True, exist_ok=True)
                (trial_dir / "result.json").write_text(
                    result.model_dump_json(indent=2)
                )
                return result

            def submit_batch(configs):
                return [execute(config, index) for index, config in enumerate(configs)]

            job._trial_queue.submit_batch = submit_batch
            result = await job.run()
            persisted = json.loads((job.job_dir / "result.json").read_text())
            trial_results = sorted(job.job_dir.glob("*/result.json"))
            assert list(metrics) == ["adhoc"]
            assert len(metrics["adhoc"]) == 1
            assert all(task.source is None for task in task_configs)
            assert len(result.trial_results) == 2
            assert len(trial_results) == 2
            assert result.finished_at is not None
            assert persisted["finished_at"] is not None
            assert environment_calls == 0
            print(
                json.dumps(
                    {
                        "finished_at": persisted["finished_at"],
                        "trial_results": len(trial_results),
                        "environment_calls": environment_calls,
                    },
                    sort_keys=True,
                )
            )


        asyncio.run(main(Path(sys.argv[1]).resolve()))
        """
    )
    environment = os.environ.copy()
    python_path = str(harbor_checkout / "src")
    if environment.get("PYTHONPATH"):
        python_path += os.pathsep + environment["PYTHONPATH"]
    environment["PYTHONPATH"] = python_path
    completed = subprocess.run(
        [str(harbor_python), "-c", script, str(tmp_path / "pinned-harbor")],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=60,
    )

    assert completed.returncode == 0, completed.stderr
    assert "IndexError" not in completed.stderr
    outcome = json.loads(completed.stdout.strip().splitlines()[-1])
    assert outcome["trial_results"] == 2
    assert outcome["finished_at"] is not None
    assert outcome["environment_calls"] == 0


def test_collector_keeps_reward_zero_reliable_and_missing_in_denominator(
    tmp_path: Path,
) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    specs = [
        _run_spec("alpha__trial", "alpha", "a" * 64),
        _run_spec("beta__trial", "beta", "b" * 64),
    ]
    _write_dispatch(job_dir, specs)
    _write_valid_result(job_dir, specs[0], reward=0.0)
    (job_dir / "result.json").write_bytes(
        _canonical(
            {
                "finished_at": "2026-07-24T00:00:02Z",
                "stats": {"n_retries": 0},
            }
        )
    )
    pricing_path = tmp_path / "pricing.json"
    pricing_path.write_bytes(
        _canonical(
            {
                "schema_version": "nano-token-pricing-v1",
                "as_of": "2026-07-24",
                "currency": "USD",
                "model": "grok-4.5",
                "input_per_million_usd": 2.0,
                "cached_input_per_million_usd": 0.5,
                "output_per_million_usd": 10.0,
            }
        )
    )
    pricing = tb21.load_pricing(pricing_path)

    summary = tb21.collect_job(job_dir, pricing=pricing)

    rows = [
        json.loads(line) for line in (job_dir / "rows.jsonl").read_text().splitlines()
    ]
    assert len(rows) == 2
    assert rows[0]["task"] == "terminal-bench/alpha"
    assert rows[0]["digest"] == "a" * 64
    assert rows[0]["pins"]["active_tools"] == list(tb21.ACTIVE_TOOLS)
    assert rows[0]["reward"] == 0.0
    assert rows[0]["pass"] is False
    assert rows[0]["raw_score_valid"] is True
    assert rows[0]["reliable"] is False
    assert rows[0]["failure_bucket"] == "agent_semantic"
    assert rows[0]["artifacts_valid"] is True
    assert rows[0]["input_tokens"] == 100
    assert rows[0]["cache_tokens"] == 40
    assert rows[0]["output_tokens"] == 20
    assert rows[0]["cost_usd"] == pytest.approx(0.00034)
    assert rows[1]["failure_bucket"] == "missing"
    assert summary["counts"] == {
        "expected": 2,
        "observed": 1,
        "passed": 0,
        "reliable": 0,
        "missing": 1,
        "duplicates": 0,
        "unexpected": 0,
        "retries": 0,
    }
    assert summary["accuracy"] == {
        "numerator": 0,
        "denominator": 2,
        "percent": 0.0,
    }
    assert summary["duration_ms"]["total"] == 2000
    assert summary["tokens"]["coverage"] == "1/2"
    assert summary["cost_usd"]["coverage"] == "1/2"
    assert summary["cost_usd"]["value"] is None
    assert summary["cost_usd"]["complete_rows_subtotal"] == pytest.approx(0.00034)
    assert summary["cost_usd"]["observed_lower_bound"] == pytest.approx(0.00034)

    first_rows = (job_dir / "rows.jsonl").read_bytes()
    first_summary = (job_dir / "summary.json").read_bytes()
    assert tb21.collect_job(job_dir, pricing=pricing) == summary
    assert (job_dir / "rows.jsonl").read_bytes() == first_rows
    assert (job_dir / "summary.json").read_bytes() == first_summary


def test_cost_uses_complete_provider_ticks_instead_of_pricing(
    tmp_path: Path,
) -> None:
    pricing = _write_pricing(tmp_path / "pricing.json", input_rate=999_999.0)
    row, summary = _collect_one_cost_row(
        tmp_path,
        raw_usage=[
            {
                "input_tokens": 100,
                "input_tokens_details": {"cached_tokens": 40},
                "output_tokens": 20,
                "cost_in_usd_ticks": 123_456_789,
            },
            {
                "input_tokens": 50,
                "input_tokens_details": {"cached_tokens": 0},
                "output_tokens": 10,
                "cost_in_usd_ticks": 876_543_211,
            },
        ],
        pricing=pricing,
    )

    assert row["provider_cost_ticks"] == 1_000_000_000
    assert row["provider_cost_ticks_coverage"] == "2/2"
    assert row["cost_source"] == "provider_ticks"
    assert row["cost_usd"] == pytest.approx(0.1)
    assert row["cost_coverage"] is True
    assert summary["cost_usd"]["provider_cost_ticks"] == 1_000_000_000
    assert summary["cost_usd"]["provider_ticks_coverage"] == "2/2"
    assert summary["cost_usd"]["value"] == pytest.approx(0.1)
    assert summary["cost_usd"]["sources"]["provider_ticks"] == 1
    assert summary["cost_usd"]["sources"]["dated_pricing_fallback"] == 0


def test_partial_priced_usage_is_only_a_lower_bound(tmp_path: Path) -> None:
    usage = replace(
        tb21._unavailable_usage(),
        input_tokens=100,
        cache_tokens=40,
        output_tokens=20,
        call_count=2,
        usage_covered_calls=1,
        state="partial",
        provider_cost_ticks_valid=True,
    )
    cost = tb21._cost(
        pricing=_write_pricing(tmp_path / "pricing.json"),
        model="grok-4.5",
        usage=usage,
    )

    assert cost.value_usd == pytest.approx(0.00034)
    assert cost.source == "dated_pricing_fallback"
    assert cost.covered is False


def test_partial_provider_ticks_are_reported_but_not_mixed_with_pricing(
    tmp_path: Path,
) -> None:
    pricing = _write_pricing(tmp_path / "pricing.json", input_rate=999_999.0)
    row, summary = _collect_one_cost_row(
        tmp_path,
        raw_usage=[
            {
                "input_tokens": 100,
                "input_tokens_details": {"cached_tokens": 40},
                "output_tokens": 20,
                "cost_in_usd_ticks": 100_000_000,
            },
            {
                "input_tokens": 50,
                "input_tokens_details": {"cached_tokens": 0},
                "output_tokens": 10,
            },
        ],
        pricing=pricing,
    )

    assert row["provider_cost_ticks"] == 100_000_000
    assert row["provider_cost_ticks_coverage"] == "1/2"
    assert row["provider_cost_usd_observed"] == pytest.approx(0.01)
    assert row["cost_source"] == "partial_provider_ticks"
    assert row["cost_usd"] is None
    assert row["cost_coverage"] is False
    assert summary["cost_usd"]["value"] is None
    assert summary["cost_usd"]["coverage"] == "0/1"
    assert summary["cost_usd"]["provider_cost_ticks"] == 100_000_000
    assert summary["cost_usd"]["provider_ticks_coverage"] == "1/2"


def test_pricing_is_fallback_when_provider_ticks_are_absent(
    tmp_path: Path,
) -> None:
    pricing = _write_pricing(tmp_path / "pricing.json")
    row, summary = _collect_one_cost_row(
        tmp_path,
        raw_usage=[
            {
                "input_tokens": 100,
                "input_tokens_details": {"cached_tokens": 0},
                "output_tokens": 20,
            }
        ],
        pricing=pricing,
    )

    assert row["provider_cost_ticks"] == 0
    assert row["provider_cost_ticks_coverage"] == "0/1"
    assert row["cost_source"] == "dated_pricing_fallback"
    assert row["cost_usd"] == pytest.approx(0.0004)
    assert summary["cost_usd"]["value"] == pytest.approx(0.0004)
    assert summary["cost_usd"]["sources"]["dated_pricing_fallback"] == 1


def test_pricing_fallback_charges_only_cached_subset_at_cached_rate(
    tmp_path: Path,
) -> None:
    pricing = _write_pricing(tmp_path / "pricing.json")
    row, _summary = _collect_one_cost_row(
        tmp_path,
        raw_usage=[
            {
                "input_tokens": 100,
                "input_tokens_details": {"cached_tokens": 40},
                "output_tokens": 20,
            },
            {
                "input_tokens": 50,
                "output_tokens": 10,
            },
        ],
        pricing=pricing,
    )

    assert row["input_tokens"] == 150
    assert row["cache_tokens"] == 40
    assert row["output_tokens"] == 30
    assert row["provider_cost_ticks_coverage"] == "0/2"
    assert row["cost_source"] == "dated_pricing_fallback"
    assert row["cost_usd"] == pytest.approx(0.00054)


def test_provider_failure_run_record_overrides_generic_bridge_error(
    tmp_path: Path,
) -> None:
    job_dir, spec = _write_one_job(tmp_path)
    _rewrite_provider_failure_runtime(
        job_dir,
        spec,
        code="provider_max_turns_exceeded",
    )
    _rewrite_trial_result(
        job_dir,
        spec,
        verifier_result=None,
        exception_info={
            "exception_type": "BridgeError",
            "exception_message": "external_runtime_nonzero",
            "exception_traceback": "BridgeError: external_runtime_nonzero",
            "occurred_at": "2026-07-24T00:00:01Z",
        },
    )

    row = _collected_row(job_dir)

    assert row["runtime_terminal_status"] == "provider_failure"
    assert row["runtime_terminal_code"] == "provider_max_turns_exceeded"
    assert row["failure_bucket"] == "provider"
    assert row["artifacts_valid"] is False


@pytest.mark.parametrize(
    ("exception_type", "expected_bucket", "expected_kind"),
    [
        ("VerifierOutputParseError", "verifier_runtime", "runtime_failed"),
        ("VerifierTimeoutError", "verifier_timeout", "timed_out"),
    ],
)
def test_harbor_verifier_exceptions_keep_verifier_phase(
    tmp_path: Path,
    exception_type: str,
    expected_bucket: str,
    expected_kind: str,
) -> None:
    job_dir, spec = _write_one_job(tmp_path)
    _rewrite_trial_result(
        job_dir,
        spec,
        verifier_result=None,
        verifier={
            "started_at": "2026-07-24T00:00:01Z",
            "finished_at": "2026-07-24T00:00:01.500000Z",
        },
        exception_info={
            "exception_type": exception_type,
            "exception_message": "verifier failed",
            "exception_traceback": "harbor.verifier.verifier failure",
            "occurred_at": "2026-07-24T00:00:01.500001Z",
        },
    )

    row = _collected_row(job_dir)

    assert row["failure_bucket"] == expected_bucket
    assert row["verifier_result_kind"] == expected_kind


def test_verifier_result_kind_closed_matrix() -> None:
    for expected in tb21._VERIFIER_RESULT_KINDS:
        reward = (
            1.0
            if expected == "passed"
            else (
                0.0
                if expected in {"assertion_failed", "completed_negative_unknown"}
                else None
            )
        )
        assert (
            tb21._classify_verifier_result_kind(
                invalid=expected == "invalid",
                reward=reward,
                verifier_started=expected != "not_run",
                typed_timeout=expected == "timed_out",
                ctrf_kind="assertion_failed"
                if expected == "assertion_failed"
                else None,
                stdout_kind="setup_failed" if expected == "setup_failed" else None,
            )
            == expected
        )


@pytest.mark.parametrize(
    ("stdout", "expected_bucket"),
    [
        (
            "curl: (22) The requested URL returned error: 504\n"
            "/bin/bash: uvx: command not found\n",
            "verifier_setup_network",
        ),
        (
            "selenium.common.exceptions.SessionNotCreatedException: "
            "Chrome instance exited\n",
            "verifier_runtime",
        ),
        (
            "FAILED tests/test_answer.py::test_answer - AssertionError\n",
            "agent_semantic",
        ),
        (
            "Traceback (most recent call last):\nRuntimeError: frobnicator exploded\n",
            "uncertain",
        ),
    ],
)
def test_reward_zero_uses_phase_aware_verifier_evidence(
    tmp_path: Path,
    stdout: str,
    expected_bucket: str,
) -> None:
    job_dir, spec = _write_one_job(tmp_path)
    _rewrite_trial_result(
        job_dir,
        spec,
        verifier_result={"rewards": {"reward": 0.0}},
    )
    verifier_dir = job_dir / str(spec["trial_id"]) / "verifier"
    verifier_dir.mkdir()
    (verifier_dir / "test-stdout.txt").write_text(stdout)

    row = _collected_row(job_dir)

    assert row["failure_bucket"] == expected_bucket


def test_ctrf_assertion_precedes_timeout_and_browser_stdout_noise(
    tmp_path: Path,
) -> None:
    job_dir, spec = _write_one_job(tmp_path)
    _rewrite_trial_result(
        job_dir,
        spec,
        verifier_result={"rewards": {"reward": 0.0}},
    )
    trial_dir = job_dir / str(spec["trial_id"])
    verifier_dir = trial_dir / "verifier"
    verifier_dir.mkdir()
    (verifier_dir / "ctrf.json").write_text(
        json.dumps(
            {
                "results": {
                    "tests": [
                        {
                            "status": "failed",
                            "message": "due to an assertion error",
                        }
                    ]
                }
            }
        )
    )
    (verifier_dir / "test-stdout.txt").write_text("chromedriver timeout warning\n")

    assert (
        tb21._verifier_result_kind(
            trial_dir=trial_dir,
            value={"verifier_result": {"rewards": {"reward": 0.0}}},
            missing=False,
            duplicate=False,
            candidate_error=None,
            result_binding_valid=True,
            reward=0.0,
        )
        == "assertion_failed"
    )
    row = _collected_row(job_dir)
    assert row["failure_bucket"] == "agent_semantic"
    assert row["verifier_result_kind"] == "assertion_failed"


def test_contamination_audit_reads_only_model_tool_arguments_and_stays_advisory(
    tmp_path: Path,
) -> None:
    job_dir, spec = _write_one_job(tmp_path)
    trial_dir = job_dir / str(spec["trial_id"])
    trajectory_path = trial_dir / "agent" / "trajectory.json"
    trajectory = json.loads(trajectory_path.read_bytes())
    trajectory["steps"] = [
        {
            "source": "user",
            "message": (
                "A quoted URL in user text is not an observed access: "
                "https://raw.githubusercontent.com/laude-institute/terminal-bench/main"
            ),
        }
    ]

    def publish_trajectory() -> None:
        trajectory_bytes = _canonical(trajectory)
        trajectory_path.write_bytes(trajectory_bytes)
        marker_path = trial_dir / "agent" / "agent-run.json"
        marker = json.loads(marker_path.read_bytes())
        marker["trajectory_sha256"] = hashlib.sha256(trajectory_bytes).hexdigest()
        marker_path.write_bytes(_canonical(marker))

    publish_trajectory()
    unobserved = _collected_row(job_dir)
    assert unobserved["contamination_signal"] is False

    trajectory["steps"].append(
        {
            "source": "agent",
            "tool_calls": [
                {
                    "tool_call_id": "official-repository-call",
                    "function_name": "run_terminal_command",
                    "arguments": {
                        "command": (
                            "curl https://raw.githubusercontent.com/"
                            "laude-institute/terminal-bench/main/tasks/example/solution.sh"
                        )
                    },
                }
            ],
            "observation": {
                "results": [
                    {
                        "source_call_id": "official-repository-call",
                        "content": "clone output",
                    }
                ]
            },
        }
    )
    publish_trajectory()

    summary = tb21.collect_job(job_dir)
    row = json.loads((job_dir / "rows.jsonl").read_text())

    assert row["collector_pass"] is True
    assert row["contamination_audit_state"] == "available"
    assert row["contamination_signals"] == ["official_benchmark_repository_access"]
    assert row["contamination_signal"] is True
    assert summary["contamination"] == {
        "schema_version": protected_target.AUDIT_SCHEMA,
        "finding_schema_version": protected_target.FINDING_SCHEMA,
        "policy_schema_version": protected_target.POLICY_SCHEMA,
        "policy_sha256": protected_target.POLICY_SHA256,
        "audit_available": 1,
        "audit_denominator": 1,
        "finding_trial_count": 1,
        "finding_trial_passes": 1,
        "strong_signal_count": 1,
        "strong_signal_passes": 1,
        "finding_counts": {
            "findings": 1,
            "strong": 1,
            "attempted": 0,
            "access_blocked": 0,
            "dispatched": 1,
            "bytes_returned": 1,
            "causal_benefit": 1,
        },
        "submission_blocking_trial_count": 1,
        "submission_blocking_finding_count": 1,
        "submission_warning_trial_count": 0,
        "submission_warning_finding_count": 0,
        "signal_adjusted_collector_numerator": 0,
        "signal_adjusted_collector_denominator": 1,
        "signal_adjusted_collector_percent": 0.0,
    }
    assert summary["gates"]["contamination_clean"] is False
    assert summary["gates"]["submission_integrity_clean"] is False


def test_protected_target_policy_parity_uses_versioned_fixture_cases() -> None:
    fixture = json.loads(
        (
            Path(__file__).parent
            / "fixtures"
            / "p0p1"
            / "collector-classification-cases.json"
        ).read_bytes()
    )

    for case in fixture["protected_target_cases"]:
        finding = protected_target.match_protected_target(
            case["tool_name"], case["arguments"]
        )
        expected = case["expected_kind"]
        assert (finding["target_kind"] if finding else None) == expected, case["name"]


@pytest.mark.parametrize(
    "command",
    [
        'p=/logs; cat "$p/agent/input/run-spec.json"',
        "cat /proc/self/root/logs/agent/input/run-spec.json",
        "cat /proc/123/root/logs/verifier/reward.txt",
        "cat /tmp/../proc/456/root/logs/reward/value",
        r"cat /proc/self/root%2flogs%2fjudge%2fresult.json",
    ],
)
def test_protected_target_matcher_covers_split_and_proc_root_aliases(
    command: str,
) -> None:
    finding = protected_target.match_protected_target(
        "run_terminal_command", {"command": command}
    )

    assert finding == {
        "target_kind": "protected_path",
        "target_field": "command",
        "policy_value": "/logs",
    }


@pytest.mark.parametrize(
    "command",
    [
        "cat /workspace/logs/agent-notes",
        "cat /var/logs/agent",
        "echo ordinary logs word",
        "cat /proc/self/root/workspace/logs/agent-notes",
    ],
)
def test_protected_target_matcher_keeps_benign_logs_controls(command: str) -> None:
    assert (
        protected_target.match_protected_target(
            "run_terminal_command", {"command": command}
        )
        is None
    )


@pytest.mark.parametrize(
    "command",
    [
        'p=/logs; cat "$p/agent/input/run-spec.json"',
        "cat /proc/self/root/logs/agent/input/run-spec.json",
    ],
)
def test_protected_target_audit_finds_split_and_proc_root_attempts(
    tmp_path: Path,
    command: str,
) -> None:
    agent_dir = tmp_path / "agent"
    agent_dir.mkdir()
    (agent_dir / "trajectory.json").write_bytes(
        _canonical(
            {
                "schema_version": "ATIF-v1.7",
                "steps": [
                    {
                        "source": "agent",
                        "tool_calls": [
                            {
                                "tool_call_id": "call-protected-alias",
                                "function_name": "run_terminal_command",
                                "arguments": {"command": command},
                            }
                        ],
                        "observation": {
                            "results": [
                                {
                                    "source_call_id": "call-protected-alias",
                                    "content": "ordinary command failure",
                                }
                            ]
                        },
                    }
                ],
            }
        )
    )

    audit = protected_target.audit_trial(tmp_path, rewarded=True)

    assert audit["state"] == "available"
    assert audit["signals"] == ["protected_harness_material_access"]
    assert audit["counts"]["findings"] == 1
    assert audit["counts"]["dispatched"] == 1
    assert audit["findings"][0]["policy_value"] == "/logs"


def test_protected_target_audit_deduplicates_atif_and_events_as_strong(
    tmp_path: Path,
) -> None:
    agent_dir = tmp_path / "agent"
    runtime_dir = agent_dir / "runtime"
    runtime_dir.mkdir(parents=True)
    arguments = {"command": "cat /logs/agent/input/run-spec.json"}
    trajectory = {
        "schema_version": "ATIF-v1.7",
        "steps": [
            {
                "source": "agent",
                "tool_calls": [
                    {
                        "tool_call_id": "call-1",
                        "function_name": "run_terminal_command",
                        "arguments": arguments,
                    }
                ],
                "observation": {
                    "results": [
                        {"source_call_id": "call-1", "content": "private bytes"}
                    ]
                },
            }
        ],
    }
    trajectory_raw = _canonical(trajectory)
    (agent_dir / "trajectory.json").write_bytes(trajectory_raw)
    events = [
        {
            "type": "tool.registered",
            "data": {
                "call_id": "call-1",
                "provider_name": "run_terminal_command",
                "arguments_json": json.dumps(arguments),
            },
        },
        {
            "type": "tool.dispatched",
            "data": {
                "call_id": "call-1",
                "provider_name": "run_terminal_command",
            },
        },
        {
            "type": "tool.completed",
            "data": {
                "call_id": "call-1",
                "provider_name": "run_terminal_command",
                "output": "private bytes",
            },
        },
    ]
    event_raw = b"".join(_canonical(event) for event in events)
    (runtime_dir / "events.jsonl").write_bytes(event_raw)
    (agent_dir / "agent-run.json").write_bytes(
        _canonical(
            {
                "schema_version": "nano-agent-run-v3",
                "publication_kind": "success_atif",
                "terminal_status": "success",
                "terminal_phase": None,
                "terminal_code": "completed",
                "trajectory_path": "trajectory.json",
                "trajectory_sha256": hashlib.sha256(trajectory_raw).hexdigest(),
                "events_sha256": hashlib.sha256(event_raw).hexdigest(),
            }
        )
    )

    audit = protected_target.audit_trial(tmp_path, rewarded=True)

    assert audit["state"] == "available"
    assert audit["signals"] == ["protected_harness_material_access"]
    assert audit["counts"] == {
        "findings": 1,
        "strong": 1,
        "attempted": 0,
        "access_blocked": 0,
        "dispatched": 1,
        "bytes_returned": 1,
        "causal_benefit": 1,
    }
    assert audit["findings"][0]["classification"] == "strong"
    assert audit["findings"][0]["causal_benefit"] is True


def test_protected_denial_success_atif_and_events_remain_warning_only(
    tmp_path: Path,
) -> None:
    agent_dir = tmp_path / "agent"
    runtime_dir = agent_dir / "runtime"
    runtime_dir.mkdir(parents=True)
    arguments = {"command": "cat /logs/agent/private-token"}
    common = {
        "schema_version": "event-v1",
        "run_id": "run-protected-denial",
        "trial_id": "trial-protected-denial",
        "attempt_id": "attempt-0",
        "elapsed_ms": 0,
    }
    bodies = [
        ("run.started", {}),
        (
            "tool.registered",
            {
                "call_id": "call-denied",
                "provider_name": "run_terminal_command",
                "known": True,
                "arguments_json": json.dumps(arguments),
            },
        ),
        (
            "tool.completed",
            {
                "call_id": "call-denied",
                "provider_name": "run_terminal_command",
                "execution_attempted": False,
                "outcome": "rejected",
                "output": "permission_denied",
            },
        ),
        ("assistant.final", {"text": "continued safely"}),
        ("run.completed", {"code": "completed"}),
    ]
    events = [
        {**common, "seq": seq, "type": event_type, "data": data}
        for seq, (event_type, data) in enumerate(bodies)
    ]
    run_record = {
        "run_id": common["run_id"],
        "trial_id": common["trial_id"],
        "attempt_id": common["attempt_id"],
        "run_spec_sha256": "a" * 64,
        "events_sha256": "b" * 64,
        "terminal_status": "success",
        "raw_usage": [],
    }
    trajectory = project_trajectory(
        instruction="Finish without protected data.",
        events=events,
        run_record=run_record,
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
    )
    validate_minimal_trajectory(trajectory)
    trajectory_raw = _canonical(trajectory)
    (agent_dir / "trajectory.json").write_bytes(trajectory_raw)
    event_raw = b"".join(_canonical(event) for event in events)
    (runtime_dir / "events.jsonl").write_bytes(event_raw)
    (agent_dir / "agent-run.json").write_bytes(
        _canonical(
            {
                "schema_version": "nano-agent-run-v3",
                "publication_kind": "success_atif",
                "terminal_status": "success",
                "terminal_phase": None,
                "terminal_code": "completed",
                "trajectory_path": "trajectory.json",
                "trajectory_sha256": hashlib.sha256(trajectory_raw).hexdigest(),
                "events_sha256": hashlib.sha256(event_raw).hexdigest(),
            }
        )
    )

    audit = protected_target.audit_trial(tmp_path, rewarded=True)

    assert audit["state"] == "available"
    assert audit["signals"] == ["protected_harness_material_access_blocked"]
    assert audit["counts"] == {
        "findings": 1,
        "strong": 0,
        "attempted": 0,
        "access_blocked": 1,
        "dispatched": 0,
        "bytes_returned": 0,
        "causal_benefit": 0,
    }
    finding = audit["findings"][0]
    assert finding["classification"] == "access_blocked"
    assert finding["attempted"] is True
    assert finding["dispatched"] is False
    assert finding["bytes_returned"] is False
    assert finding["causal_benefit"] is False
    assert finding["access_blocked"] is True
    assert protected_target.submission_blocking_finding(finding) is False


def test_protected_target_audit_reads_v4_failure_atif_and_block_marker(
    tmp_path: Path,
) -> None:
    agent_dir = tmp_path / "agent"
    agent_dir.mkdir()
    trajectory = {
        "schema_version": "ATIF-v1.7",
        "steps": [
            {
                "source": "agent",
                "tool_calls": [
                    {
                        "tool_call_id": "call-blocked",
                        "function_name": "read_file",
                        "arguments": {"target_file": "/logs/verifier/reward.txt"},
                    }
                ],
            }
        ],
    }
    diagnostic = {"terminal_code": "protected_harness_material_access_blocked"}
    trajectory_raw = _canonical(trajectory)
    diagnostic_raw = _canonical(diagnostic)
    (agent_dir / "trajectory.json").write_bytes(trajectory_raw)
    (agent_dir / "failure-diagnostic.json").write_bytes(diagnostic_raw)
    (agent_dir / "agent-run.json").write_bytes(
        _canonical(
            {
                "schema_version": "nano-agent-run-v4",
                "publication_kind": "failure_atif",
                "terminal_status": "tool_failure",
                "terminal_phase": "tool",
                "terminal_code": "protected_harness_material_access_blocked",
                "trajectory_path": "trajectory.json",
                "trajectory_sha256": hashlib.sha256(trajectory_raw).hexdigest(),
                "diagnostic_path": "failure-diagnostic.json",
                "diagnostic_sha256": hashlib.sha256(diagnostic_raw).hexdigest(),
            }
        )
    )

    audit = protected_target.audit_trial(tmp_path, rewarded=False)

    assert audit["state"] == "available"
    assert audit["signals"] == ["protected_harness_material_access_blocked"]
    assert audit["counts"]["access_blocked"] == 1
    finding = audit["findings"][0]
    assert finding["classification"] == "access_blocked"
    assert finding["attempted"] is True
    assert finding["dispatched"] is False
    assert finding["bytes_returned"] is False
    assert finding["causal_benefit"] is False


def test_protected_target_audit_classifies_registered_only_as_attempted(
    tmp_path: Path,
) -> None:
    agent_dir = tmp_path / "agent"
    agent_dir.mkdir()
    (agent_dir / "partial-trajectory.json").write_bytes(
        _canonical(
            {
                "schema_version": "nano-partial-trajectory-v1",
                "tool_calls": [
                    {
                        "call_id": "call-registered",
                        "function_name": "list_dir",
                        "arguments": {"target_directory": "/logs/reward"},
                        "state": "in_flight",
                        "dispatched": False,
                    }
                ],
            }
        )
    )

    audit = protected_target.audit_trial(tmp_path, rewarded=False)

    assert audit["signals"] == ["protected_harness_material_access_attempted"]
    assert audit["counts"]["attempted"] == 1
    assert audit["findings"][0]["classification"] == "attempted"


def test_submission_blocking_projection_is_official_aligned_and_fail_closed() -> None:
    def finding(**overrides: object) -> dict[str, object]:
        value: dict[str, object] = {
            "schema_version": protected_target.FINDING_SCHEMA,
            "call_id": "call-1",
            "tool_name": "run_terminal_command",
            "target_kind": "protected_path",
            "target_field": "command",
            "policy_value": "/logs",
            "classification": "attempted",
            "attempted": True,
            "dispatched": False,
            "bytes_returned": False,
            "causal_benefit": False,
            "access_blocked": False,
            "evidence_sources": [
                {"kind": "atif", "path": "trajectory.json", "sha256": "a" * 64}
            ],
        }
        value.update(overrides)
        return value

    cases = (
        (finding(), False),
        (
            finding(classification="access_blocked", access_blocked=True),
            False,
        ),
        (finding(classification="strong"), True),
        (finding(dispatched=True), True),
        (finding(bytes_returned=True), True),
        (finding(causal_benefit=True), True),
        (finding(attempted=False), True),
        (finding(classification="unknown"), True),
        ({"classification": "access_blocked"}, True),
    )

    for value, expected in cases:
        assert protected_target.submission_blocking_finding(value) is expected


def test_protected_target_audit_fails_closed_on_malformed_surface(
    tmp_path: Path,
) -> None:
    agent_dir = tmp_path / "agent"
    agent_dir.mkdir()
    (agent_dir / "trajectory.json").write_bytes(b"{\n")

    audit = protected_target.audit_trial(tmp_path, rewarded=False)

    assert audit["state"] == "invalid"
    assert audit["findings"] == []


@pytest.mark.parametrize(
    "command",
    [
        "git clone https://github.com/harbor-framework/terminal-bench",
        "git clone https://GITHUB.COM/LAUDE-INSTITUTE/TERMINAL-BENCH",
        "curl https://api.github.com/repos/harbor-framework%2Fterminal-bench",
        (
            r"curl https:\/\/raw.githubusercontent.com\/laude-institute"
            r"\/terminal-bench\/main"
        ),
        r"curl https://github.com/harbor-framework\u002fterminal-bench",
    ],
)
def test_contamination_audit_normalizes_official_repository_slugs(
    tmp_path: Path,
    command: str,
) -> None:
    agent_dir = tmp_path / "agent"
    agent_dir.mkdir()
    (agent_dir / "trajectory.json").write_text(
        json.dumps(
            {
                "steps": [
                    {
                        "source": "agent",
                        "tool_calls": [
                            {
                                "tool_call_id": "call-1",
                                "function_name": "run_terminal_command",
                                "arguments": {"command": command},
                            }
                        ],
                        "observation": {
                            "results": [
                                {"source_call_id": "call-1", "content": "output"}
                            ]
                        },
                    }
                ]
            }
        )
    )

    audit = tb21._contamination_audit(tmp_path)
    assert audit["state"] == "available"
    assert audit["signals"] == ["official_benchmark_repository_access"]
    assert audit["findings"][0]["target_kind"] == "official_benchmark_repository"


def test_contamination_audit_keeps_ordinary_github_clean(tmp_path: Path) -> None:
    agent_dir = tmp_path / "agent"
    agent_dir.mkdir()
    (agent_dir / "trajectory.json").write_text(
        json.dumps(
            {
                "steps": [
                    {
                        "source": "agent",
                        "tool_calls": [
                            {
                                "function_name": "run_terminal_command",
                                "arguments": {
                                    "command": (
                                        "git clone https://github.com/rust-lang/cargo"
                                    )
                                },
                            }
                        ],
                    }
                ]
            }
        )
    )

    audit = tb21._contamination_audit(tmp_path)
    assert audit["state"] == "available"
    assert audit["signals"] == []
    assert audit["findings"] == []


def test_missing_reward_is_verifier_runtime_never_semantic(
    tmp_path: Path,
) -> None:
    job_dir, spec = _write_one_job(tmp_path)
    _rewrite_trial_result(
        job_dir,
        spec,
        verifier_result=None,
        exception_info=None,
    )

    row = _collected_row(job_dir)

    assert row["failure_bucket"] == "verifier_runtime"
    assert row["verifier_result_kind"] == "not_run"


@pytest.mark.parametrize(
    "background_tasks",
    [
        [],
        [
            {
                "task_id": "018f22d6-9f04-7cc0-8000-000000000001",
                "pgid": 123,
                "monitor_pgid": 124,
                "output_path": (
                    "/workspace/.terminals/018f22d6-9f04-7cc0-8000-000000000001.log"
                ),
                "state": "running",
            }
        ],
    ],
    ids=("empty", "running"),
)
def test_artifacts_accept_bound_empty_and_running_background_manifests(
    tmp_path: Path,
    background_tasks: list[dict[str, object]],
) -> None:
    job_dir, _spec = _write_one_job(
        tmp_path,
        background_tasks=background_tasks,
    )

    row = _collected_row(job_dir)

    assert row["diagnostic_package_valid"] is True
    assert row["artifacts_valid"] is True
    assert row["reliable"] is False


def test_artifacts_require_background_manifest(tmp_path: Path) -> None:
    job_dir, spec = _write_one_job(tmp_path)
    manifest_path = (
        job_dir / str(spec["trial_id"]) / "agent" / "runtime-background-manifest.json"
    )
    manifest_path.unlink()

    row = _collected_row(job_dir)

    assert row["artifacts_valid"] is False
    assert row["failure_bucket"] == "artifact"


@pytest.mark.parametrize("mutation", ["identity", "state", "invalid_json"])
def test_artifacts_reject_invalid_background_manifest(
    tmp_path: Path,
    mutation: str,
) -> None:
    running = [
        {
            "task_id": "018f22d6-9f04-7cc0-8000-000000000001",
            "pgid": 123,
            "monitor_pgid": 124,
            "output_path": (
                "/workspace/.terminals/018f22d6-9f04-7cc0-8000-000000000001.log"
            ),
            "state": "running",
        }
    ]
    job_dir, spec = _write_one_job(tmp_path, background_tasks=running)
    manifest_path = (
        job_dir / str(spec["trial_id"]) / "agent" / "runtime-background-manifest.json"
    )
    if mutation == "invalid_json":
        manifest_path.write_bytes(b"{invalid\n")
    else:
        manifest = json.loads(manifest_path.read_bytes())
        if mutation == "identity":
            manifest["run_id"] = "wrong-run"
        else:
            manifest["tasks"][0]["state"] = "completed"
        manifest_path.write_bytes(_canonical(manifest))

    row = _collected_row(job_dir)

    assert row["artifacts_valid"] is False
    assert row["failure_bucket"] == "artifact"


def test_artifacts_reject_background_manifest_marker_count_mismatch(
    tmp_path: Path,
) -> None:
    job_dir, spec = _write_one_job(tmp_path)
    marker_path = job_dir / str(spec["trial_id"]) / "agent" / "agent-run.json"
    marker = json.loads(marker_path.read_bytes())
    marker["background_task_count"] = 1
    marker_path.write_bytes(_canonical(marker))

    row = _collected_row(job_dir)

    assert row["artifacts_valid"] is False


def test_artifacts_reject_background_manifest_marker_digest_mismatch(
    tmp_path: Path,
) -> None:
    job_dir, spec = _write_one_job(tmp_path)
    marker_path = job_dir / str(spec["trial_id"]) / "agent" / "agent-run.json"
    marker = json.loads(marker_path.read_bytes())
    marker["background_manifest_sha256"] = "0" * 64
    marker_path.write_bytes(_canonical(marker))

    row = _collected_row(job_dir)

    assert row["artifacts_valid"] is False


def test_v2_failure_package_is_diagnostic_not_success_artifact(
    tmp_path: Path,
) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    spec = _run_spec("failure__trial", "failure", "a" * 64)
    _write_dispatch(job_dir, [spec])
    _write_v2_failure_publication(job_dir, spec)
    trial_dir = job_dir / str(spec["trial_id"])
    result = {
        "task_name": "terminal-bench/failure",
        "trial_name": spec["trial_id"],
        "task_checksum": "a" * 64,
        "verifier_result": None,
        "exception_info": {
            "exception_type": "BridgeError",
            "exception_message": "external bridge failed",
        },
        "started_at": "2026-07-24T00:00:00Z",
        "finished_at": "2026-07-24T00:00:01Z",
    }
    (trial_dir / "result.json").write_bytes(_canonical(result))

    row = _collected_row(job_dir)

    assert row["success_artifact_valid"] is False
    assert row["diagnostic_package_valid"] is True
    assert row["artifacts_valid"] is False
    assert row["publication_kind"] == "failure_atif"
    assert row["workspace_receipt_valid"] is True
    assert row["workspace_snapshot_complete"] is False
    assert row["runtime_terminal_status"] == "tool_failure"
    assert row["runtime_terminal_phase"] == "bridge"
    assert row["runtime_terminal_code"] == ("terminal_actor_cleanup_unverified")
    assert row["failure_bucket"] == "tool_transport"
    assert row["measurement_complete"] is False


def test_v2_marker_hash_mutation_breaks_diagnostic_gate(
    tmp_path: Path,
) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    spec = _run_spec("failure__trial", "failure", "a" * 64)
    _write_dispatch(job_dir, [spec])
    _write_v2_failure_publication(job_dir, spec)
    trial_dir = job_dir / str(spec["trial_id"])
    receipt_path = trial_dir / "agent" / "workspace-receipt.json"
    receipt = json.loads(receipt_path.read_bytes())
    receipt["code"] = "mutated_after_marker"
    receipt_path.write_bytes(_canonical(receipt))
    result = {
        "task_name": "terminal-bench/failure",
        "trial_name": spec["trial_id"],
        "task_checksum": "a" * 64,
        "verifier_result": None,
        "exception_info": {
            "exception_type": "BridgeError",
            "exception_message": "external bridge failed",
        },
        "started_at": "2026-07-24T00:00:00Z",
        "finished_at": "2026-07-24T00:00:01Z",
    }
    (trial_dir / "result.json").write_bytes(_canonical(result))

    row = _collected_row(job_dir)

    assert row["diagnostic_package_valid"] is False
    assert row["workspace_receipt_valid"] is False
    assert row["measurement_complete"] is False


def test_v2_complete_workspace_snapshot_completes_measurement_gate(
    tmp_path: Path,
) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    spec = _run_spec("failure__trial", "failure", "a" * 64)
    _write_dispatch(job_dir, [spec])
    _write_v2_failure_publication(job_dir, spec, complete_workspace=True)
    trial_dir = job_dir / str(spec["trial_id"])
    (trial_dir / "result.json").write_bytes(
        _canonical(
            {
                "task_name": "terminal-bench/failure",
                "trial_name": spec["trial_id"],
                "task_checksum": "a" * 64,
                "verifier_result": None,
                "exception_info": {
                    "exception_type": "BridgeError",
                    "exception_message": "external bridge failed",
                },
                "started_at": "2026-07-24T00:00:00Z",
                "finished_at": "2026-07-24T00:00:01Z",
            }
        )
    )

    row = _collected_row(job_dir)

    assert row["diagnostic_package_valid"] is True
    assert row["workspace_receipt_valid"] is True
    assert row["workspace_snapshot_complete"] is True
    assert row["usage_receipt_valid"] is True
    assert row["measurement_complete"] is True


def test_partial_workspace_snapshot_is_reliable_but_measurement_is_incomplete(
    tmp_path: Path,
    pinned_collector_validator: None,
) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    spec = _run_spec("partial__trial", "partial", "a" * 64)
    _write_dispatch(job_dir, [spec])
    _write_v2_failure_publication(
        job_dir,
        spec,
        complete_workspace=True,
        workspace_policy=SnapshotPolicy(
            max_files=10,
            max_total_bytes=1,
            max_file_bytes=1,
            max_patch_bytes=100,
        ),
        successful=True,
    )
    trial_dir = job_dir / str(spec["trial_id"])
    (trial_dir / "result.json").write_bytes(
        _canonical(
            {
                "task_name": "terminal-bench/partial",
                "trial_name": spec["trial_id"],
                "task_checksum": "a" * 64,
                "verifier_result": {"rewards": {"reward": 1.0}},
                "exception_info": None,
                "started_at": "2026-07-24T00:00:00Z",
                "finished_at": "2026-07-24T00:00:01Z",
            }
        )
    )

    row = _collected_row(job_dir)

    assert row["workspace_receipt_valid"] is True
    assert row["workspace_snapshot_complete"] is False
    assert row["workspace_status"] == "partial_valid"
    assert row["success_artifact_valid"] is True
    assert row["reliable"] is True
    assert row["strict_pass"] is True
    assert row["measurement_complete"] is False


@pytest.mark.parametrize(
    "task_id",
    ("synthetic-alpha", "synthetic-beta", "synthetic-gamma"),
)
def test_positive_reward_with_hash_valid_failed_workspace_preserves_strict_score(
    tmp_path: Path,
    pinned_collector_validator: None,
    task_id: str,
) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    spec = _run_spec(f"{task_id}__trial", task_id, "a" * 64)
    _write_dispatch(job_dir, [spec])
    _write_v2_failure_publication(job_dir, spec, successful=True)
    _write_result = {
        "task_name": f"terminal-bench/{task_id}",
        "trial_name": spec["trial_id"],
        "task_checksum": "a" * 64,
        "verifier_result": {"rewards": {"reward": 1.0}},
        "exception_info": None,
        "started_at": "2026-07-24T00:00:00Z",
        "finished_at": "2026-07-24T00:00:01Z",
    }
    (job_dir / str(spec["trial_id"]) / "result.json").write_bytes(
        _canonical(_write_result)
    )
    logs = job_dir / str(spec["trial_id"]) / "agent"
    receipt_path = logs / "workspace-receipt.json"
    failed = json.loads(receipt_path.read_bytes())
    failed["failure"]["stage"] = "archive-parse"
    failed["failure"]["category"] = "parse"
    receipt_path.write_bytes(_canonical(failed))
    marker_path = logs / "agent-run.json"
    marker = json.loads(marker_path.read_bytes())
    marker["workspace_receipt_sha256"] = hashlib.sha256(
        receipt_path.read_bytes()
    ).hexdigest()
    marker_path.write_bytes(_canonical(marker))

    row = _collected_row(job_dir)

    assert row["reward"] > 0
    assert row["raw_score_valid"] is True
    assert row["collector_pass"] is True
    assert row["workspace_receipt_valid"] is True
    assert row["workspace_snapshot_complete"] is False
    assert row["workspace_status"] == "failed"
    assert row["workspace_failure_stage"] == "archive-parse"
    assert row["workspace_failure_category"] == "parse"
    assert row["success_artifact_valid"] is False
    assert row["artifacts_valid"] is False
    assert row["direct_atif_valid"] is True
    assert row["rewarded_atif_valid"] is True
    assert row["reliable"] is False
    assert row["strict_pass"] is True
    assert row["measurement_complete"] is False
    assert row["failure_bucket"] == "artifact"

    first_rows = (job_dir / "rows.jsonl").read_bytes()
    first_summary = (job_dir / "summary.json").read_bytes()
    summary = tb21.collect_job(job_dir)
    assert (job_dir / "rows.jsonl").read_bytes() == first_rows
    assert (job_dir / "summary.json").read_bytes() == first_summary
    assert summary["counts"]["passed"] == 1
    assert summary["counts"]["reliable"] == 0
    assert summary["collector_accuracy"]["numerator"] == 1
    assert summary["rewarded_atif_coverage"] == {
        "numerator": 1,
        "denominator": 1,
        "percent": 100.0,
    }
    assert summary["gates"]["rewarded_atif"] is True
    assert summary["measurement_completeness"]["numerator"] == 0

    for verifier_result, expected_raw_score_valid in (
        ({"rewards": {"reward": 0.0}}, True),
        (None, False),
    ):
        nonrewarded_result = dict(_write_result)
        nonrewarded_result["verifier_result"] = verifier_result
        (job_dir / str(spec["trial_id"]) / "result.json").write_bytes(
            _canonical(nonrewarded_result)
        )
        nonrewarded = _collected_row(job_dir)
        assert nonrewarded["raw_score_valid"] is expected_raw_score_valid
        assert nonrewarded["collector_pass"] is False
        assert nonrewarded["success_artifact_valid"] is False
        assert nonrewarded["artifacts_valid"] is False
        assert nonrewarded["direct_atif_valid"] is True
        assert nonrewarded["rewarded_atif_valid"] is False
        assert nonrewarded["reliable"] is False
        assert nonrewarded["strict_pass"] is False

    (job_dir / str(spec["trial_id"]) / "result.json").write_bytes(
        _canonical(_write_result)
    )
    failed["failure"]["category"] = "internal"
    receipt_path.write_bytes(_canonical(failed))
    tampered = _collected_row(job_dir)
    assert tampered["raw_score_valid"] is True
    assert tampered["collector_pass"] is True
    assert tampered["workspace_receipt_valid"] is False
    assert tampered["workspace_snapshot_complete"] is False
    assert tampered["success_artifact_valid"] is False
    assert tampered["direct_atif_valid"] is False
    assert tampered["rewarded_atif_valid"] is False
    assert tampered["reliable"] is False
    assert tampered["strict_pass"] is False
    assert tampered["measurement_complete"] is False


def test_v3_failed_workspace_preserves_raw_reward_and_tamper_fails_closed(
    tmp_path: Path,
    pinned_collector_validator: None,
) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    spec = _run_spec("failure__trial", "failure", "a" * 64)
    _write_dispatch(job_dir, [spec])
    _write_v2_failure_publication(job_dir, spec, successful=True)
    trial_dir = job_dir / str(spec["trial_id"])
    (trial_dir / "result.json").write_bytes(
        _canonical(
            {
                "task_name": "terminal-bench/failure",
                "trial_name": spec["trial_id"],
                "task_checksum": "a" * 64,
                "verifier_result": {"rewards": {"reward": 1.0}},
                "exception_info": None,
                "started_at": "2026-07-24T00:00:00Z",
                "finished_at": "2026-07-24T00:00:01Z",
            }
        )
    )
    logs = trial_dir / "agent"
    receipt_path = logs / "workspace-receipt.json"
    marker_path = logs / "agent-run.json"
    base = json.loads(receipt_path.read_bytes())
    base["schema_version"] = "nano-workspace-receipt-v3"
    base["failure"] = {
        "stage": "host-evidence",
        "category": "evidence",
        "subtype": "host_evidence_materialization_failed",
        "timeout_origin": "not_a_timeout",
        "errno": 28,
        "return_code": None,
        "attempt": 1,
        "stage_validated": True,
        "termination_verified": True,
        "cleanup_verified": True,
        "zero_census_verified": True,
    }

    def publish_receipt(value: dict[str, object]) -> None:
        receipt_path.write_bytes(_canonical(value))
        marker = json.loads(marker_path.read_bytes())
        marker["workspace_receipt_sha256"] = hashlib.sha256(
            receipt_path.read_bytes()
        ).hexdigest()
        marker_path.write_bytes(_canonical(marker))

    publish_receipt(base)
    row = _collected_row(job_dir)
    assert row["reward"] == 1.0
    assert row["raw_score_valid"] is True
    assert row["collector_pass"] is True
    assert row["workspace_receipt_valid"] is True
    assert row["workspace_snapshot_complete"] is False
    assert row["workspace_failure_subtype"] == "host_evidence_materialization_failed"
    assert row["workspace_failure_timeout_origin"] == "not_a_timeout"
    assert row["workspace_failure_stage_validated"] is True
    assert row["workspace_failure_termination_verified"] is True
    assert row["workspace_failure_cleanup_verified"] is True
    assert row["workspace_failure_zero_census_verified"] is True
    assert row["workspace_failure_execution_binding_verified"] is None
    assert row["success_artifact_valid"] is False
    assert row["artifacts_valid"] is False
    assert row["direct_atif_valid"] is True
    assert row["rewarded_atif_valid"] is True
    assert row["reliable"] is False
    assert row["strict_pass"] is True
    assert row["measurement_complete"] is False

    tampered_receipts = []
    missing_proof = json.loads(json.dumps(base))
    del missing_proof["failure"]["zero_census_verified"]
    tampered_receipts.append(missing_proof)
    unknown_subtype = json.loads(json.dumps(base))
    unknown_subtype["failure"]["subtype"] = "future_unknown"
    tampered_receipts.append(unknown_subtype)
    contradictory = json.loads(json.dumps(base))
    contradictory["failure"]["stage_validated"] = False
    tampered_receipts.append(contradictory)
    contradictory_cleanup = json.loads(json.dumps(base))
    contradictory_cleanup["failure"].update(
        {
            "stage": "cleanup",
            "category": "command",
            "subtype": "stage_cleanup_failed",
            "errno": None,
            "termination_verified": False,
            "cleanup_verified": True,
            "zero_census_verified": False,
        }
    )
    tampered_receipts.append(contradictory_cleanup)
    extra_key = json.loads(json.dumps(base))
    extra_key["failure"]["raw_stderr"] = "secret"
    tampered_receipts.append(extra_key)

    for tampered_receipt in tampered_receipts:
        publish_receipt(tampered_receipt)
        tampered_row = _collected_row(job_dir)
        assert tampered_row["raw_score_valid"] is True
        assert tampered_row["collector_pass"] is True
        assert tampered_row["workspace_receipt_valid"] is False
        assert tampered_row["workspace_failure_subtype"] is None
        assert tampered_row["workspace_snapshot_complete"] is False
        assert tampered_row["strict_pass"] is False
        assert tampered_row["measurement_complete"] is False


def test_v5_execution_binding_projects_without_changing_raw_score_formula(
    tmp_path: Path,
) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    spec = _run_spec("failure__trial", "failure", "a" * 64)
    _write_dispatch(job_dir, [spec])
    _write_v2_failure_publication(job_dir, spec)
    trial_dir = job_dir / str(spec["trial_id"])
    (trial_dir / "result.json").write_bytes(
        _canonical(
            {
                "task_name": "terminal-bench/failure",
                "trial_name": spec["trial_id"],
                "task_checksum": "a" * 64,
                "verifier_result": {"rewards": {"reward": 1.0}},
                "exception_info": {
                    "exception_type": "BridgeError",
                    "exception_message": "terminalized",
                },
                "started_at": "2026-07-24T00:00:00Z",
                "finished_at": "2026-07-24T00:00:01Z",
            }
        )
    )
    logs = trial_dir / "agent"
    receipt_path = logs / "workspace-receipt.json"
    marker_path = logs / "agent-run.json"
    receipt = json.loads(receipt_path.read_bytes())
    receipt["schema_version"] = "nano-workspace-receipt-v5"
    receipt["baseline_state"] = "available"
    receipt["failure"] = {
        "stage": "remote-exec",
        "category": "internal",
        "subtype": "wait_response_invalid",
        "timeout_origin": "not_a_timeout",
        "errno": None,
        "return_code": 92,
        "attempt": 1,
        "stage_validated": True,
        "termination_verified": True,
        "cleanup_verified": True,
        "zero_census_verified": True,
        "reason": "outer_return_code_nonzero",
        "execution_binding_verified": True,
    }

    def publish(value: dict[str, object], *, marker_hash: str | None = None) -> None:
        receipt_path.write_bytes(_canonical(value))
        marker = json.loads(marker_path.read_bytes())
        marker["workspace_receipt_sha256"] = (
            marker_hash or hashlib.sha256(receipt_path.read_bytes()).hexdigest()
        )
        marker_path.write_bytes(_canonical(marker))

    publish(receipt)
    row = _collected_row(job_dir)
    score_projection = {
        key: row[key]
        for key in (
            "raw_score_valid",
            "collector_pass",
            "reliable",
            "strict_pass",
            "measurement_complete",
        )
    }
    assert score_projection == {
        "raw_score_valid": True,
        "collector_pass": True,
        "reliable": False,
        "strict_pass": False,
        "measurement_complete": False,
    }
    assert row["workspace_receipt_valid"] is True
    assert row["workspace_failure_execution_binding_verified"] is True

    unbound = json.loads(json.dumps(receipt))
    unbound["failure"]["execution_binding_verified"] = False
    publish(unbound)
    unbound_row = _collected_row(job_dir)
    assert unbound_row["workspace_receipt_valid"] is True
    assert unbound_row["workspace_failure_execution_binding_verified"] is False
    assert {key: unbound_row[key] for key in score_projection} == score_projection

    missing_proof = json.loads(json.dumps(receipt))
    del missing_proof["failure"]["execution_binding_verified"]
    publish(missing_proof)
    invalid_row = _collected_row(job_dir)
    assert invalid_row["raw_score_valid"] is True
    assert invalid_row["collector_pass"] is True
    assert invalid_row["workspace_receipt_valid"] is False
    assert invalid_row["workspace_failure_execution_binding_verified"] is None
    assert invalid_row["reliable"] is False
    assert invalid_row["strict_pass"] is False
    assert invalid_row["measurement_complete"] is False

    publish(receipt, marker_hash="0" * 64)
    hash_tampered = _collected_row(job_dir)
    assert hash_tampered["raw_score_valid"] is True
    assert hash_tampered["collector_pass"] is True
    assert hash_tampered["workspace_receipt_valid"] is False
    assert hash_tampered["workspace_failure_execution_binding_verified"] is None
    assert hash_tampered["strict_pass"] is False
    assert hash_tampered["measurement_complete"] is False


def test_positive_reward_with_missing_workspace_receipt_is_raw_only(
    tmp_path: Path,
) -> None:
    job_dir, _spec = _write_one_job(tmp_path)

    row = _collected_row(job_dir)

    assert row["reward"] > 0
    assert row["raw_score_valid"] is True
    assert row["collector_pass"] is True
    assert row["workspace_receipt_valid"] is False
    assert row["workspace_snapshot_complete"] is False
    assert row["workspace_status"] is None
    assert row["workspace_failure_stage"] is None
    assert row["workspace_failure_category"] is None
    assert row["workspace_failure_execution_binding_verified"] is None
    assert row["success_artifact_valid"] is False
    assert row["reliable"] is False
    assert row["strict_pass"] is False
    assert row["measurement_complete"] is False
    assert row["failure_bucket"] == "artifact"


def test_size_plan_failure_receipt_is_raw_neutral_and_strict_false(
    tmp_path: Path,
) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    spec = _run_spec("failure__trial", "failure", "a" * 64)
    _write_dispatch(job_dir, [spec])
    _write_v2_failure_publication(job_dir, spec)
    trial_dir = job_dir / str(spec["trial_id"])
    (trial_dir / "result.json").write_bytes(
        _canonical(
            {
                "task_name": "terminal-bench/failure",
                "trial_name": spec["trial_id"],
                "task_checksum": "a" * 64,
                "verifier_result": {"rewards": {"reward": 1.0}},
                "exception_info": None,
                "started_at": "2026-07-24T00:00:00Z",
                "finished_at": "2026-07-24T00:00:01Z",
            }
        )
    )
    logs = trial_dir / "agent"
    receipt_path = logs / "workspace-receipt.json"
    marker_path = logs / "agent-run.json"
    receipt = json.loads(receipt_path.read_bytes())
    receipt.update(
        {
            "schema_version": "nano-workspace-receipt-v5",
            "baseline_state": "available",
            "code": "workspace_after_exact_plan_exceeded",
            "failure": {
                "stage": "inventory-parse",
                "category": "policy",
                "subtype": "unknown_internal",
                "timeout_origin": "not_a_timeout",
                "errno": None,
                "return_code": None,
                "attempt": 1,
                "stage_validated": False,
                "termination_verified": False,
                "cleanup_verified": False,
                "zero_census_verified": False,
                "reason": "not_applicable",
                "execution_binding_verified": False,
            },
        }
    )
    receipt_path.write_bytes(_canonical(receipt))
    marker = json.loads(marker_path.read_bytes())
    marker["workspace_receipt_sha256"] = hashlib.sha256(
        receipt_path.read_bytes()
    ).hexdigest()
    marker_path.write_bytes(_canonical(marker))

    row = _collected_row(job_dir)

    assert row["raw_score_valid"] is True
    assert row["collector_pass"] is True
    assert row["workspace_receipt_valid"] is True
    assert row["workspace_snapshot_complete"] is False
    assert row["strict_pass"] is False
    assert row["measurement_complete"] is False


def test_v2_run_record_accepts_rust_field_order(tmp_path: Path) -> None:
    job_dir, run_path = _write_collectible_v2_failure(tmp_path)
    record = json.loads(run_path.read_bytes())
    run_path.write_bytes(_rust_ordered_v2_run(record))

    row = _collected_row(job_dir)

    assert row["terminal_record_valid"] is True
    assert row["usage_receipt_valid"] is True
    assert row["workspace_receipt_valid"] is True
    assert row["diagnostic_package_valid"] is True
    assert row["measurement_complete"] is True


@pytest.mark.parametrize(
    ("shape", "expected_variant", "expected_schema"),
    [
        (
            "legacy_v1",
            "legacy_v1",
            "nano-run-record-alpha-1",
        ),
        (
            "legacy_v2",
            "legacy_v2",
            "nano-run-record-v2",
        ),
        (
            "v2_deadline_compat",
            "v2_deadline_compat",
            "nano-run-record-v2",
        ),
        (
            "v3",
            "v3",
            "nano-run-record-v3",
        ),
    ],
)
def test_versioned_run_record_parser_accepts_only_named_exact_shapes(
    tmp_path: Path,
    shape: str,
    expected_variant: str,
    expected_schema: str,
) -> None:
    _job_dir, spec, runtime_dir, run_path = _reader_variant_fixture(tmp_path, shape)
    record = json.loads(run_path.read_bytes())
    run_path.write_bytes(
        (
            json.dumps(
                dict(reversed(list(record.items()))),
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
    )

    parsed = tb21._parse_run_record(runtime_dir, spec)

    assert parsed is not None
    assert parsed.variant == expected_variant
    assert parsed.schema_version == expected_schema
    assert parsed.usage.record_valid is True
    assert parsed.runtime.terminal_code


def test_legacy_v1_keeps_structural_usage_without_terminal_authority(
    tmp_path: Path,
) -> None:
    job_dir, spec = _write_one_job(tmp_path)
    trial_dir = job_dir / str(spec["trial_id"])
    runtime_dir = trial_dir / "agent" / "runtime"

    opaque_usage = tb21._usage(runtime_dir, spec)
    opaque_runtime = tb21._runtime_evidence(runtime_dir, spec)
    opaque_artifacts = tb21._artifact_evidence(trial_dir, spec)

    assert opaque_usage.source == "run_record_v1"
    assert opaque_usage.record_valid is True
    assert opaque_runtime is None
    assert opaque_artifacts.diagnostic_valid is True

    (runtime_dir / "events.jsonl").unlink()
    absent_usage = tb21._usage(runtime_dir, spec)
    absent_runtime = tb21._runtime_evidence(runtime_dir, spec)
    absent_artifacts = tb21._artifact_evidence(trial_dir, spec)

    assert absent_usage == opaque_usage
    assert absent_runtime is None
    assert absent_artifacts.diagnostic_valid is False


def test_valid_legacy_v1_provider_failure_has_typed_runtime(
    tmp_path: Path,
) -> None:
    job_dir, spec = _write_one_job(tmp_path)
    code = "provider_max_turns_exceeded"
    _rewrite_provider_failure_runtime(job_dir, spec, code=code)
    runtime_dir = job_dir / str(spec["trial_id"]) / "agent" / "runtime"

    runtime = tb21._runtime_evidence(runtime_dir, spec)
    usage = tb21._usage(runtime_dir, spec)

    assert runtime is not None
    assert runtime.terminal_status == "provider_failure"
    assert runtime.terminal_phase == "provider"
    assert runtime.terminal_code == code
    assert runtime.provider_failure_code == code
    assert usage.source == "run_record_v1"
    assert usage.record_valid is True


@pytest.mark.parametrize(
    "mutation",
    ["terminal_kind", "provider_code", "missing_terminal"],
)
def test_legacy_v1_terminal_mismatch_fails_closed_with_one_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    job_dir, spec = _write_one_job(tmp_path)
    code = "provider_max_turns_exceeded"
    _rewrite_provider_failure_runtime(job_dir, spec, code=code)
    runtime_dir = job_dir / str(spec["trial_id"]) / "agent" / "runtime"
    events_path = runtime_dir / "events.jsonl"
    events = [json.loads(line) for line in events_path.read_bytes().splitlines()]
    if mutation == "terminal_kind":
        events[-1]["type"] = "run.completed"
    elif mutation == "provider_code":
        events[-2]["data"]["code"] = "provider_rate_limited"
    else:
        events.pop()
    event_bytes = b"".join(_canonical(event) for event in events)
    events_path.write_bytes(event_bytes)
    run_path = runtime_dir / "run.json"
    record = json.loads(run_path.read_bytes())
    record["final_event_seq"] = len(events) - 1
    record["events_sha256"] = hashlib.sha256(event_bytes).hexdigest()
    run_path.write_bytes(_canonical(record))
    counts = {"events": 0, "record": 0}
    original_event_reader = tb21._read_event_prefix_outcome
    original_record_reader = tb21._run_record_mapping

    def counted_event_reader(
        selected_runtime_dir: Path,
        selected_spec: dict[str, object],
    ) -> object:
        counts["events"] += 1
        return original_event_reader(selected_runtime_dir, selected_spec)

    def counted_record_reader(
        path: Path,
        *,
        limit: int = 64 * 1024 * 1024,
    ) -> object:
        counts["record"] += 1
        return original_record_reader(path, limit=limit)

    monkeypatch.setattr(
        tb21,
        "_read_event_prefix_outcome",
        counted_event_reader,
    )
    monkeypatch.setattr(tb21, "_run_record_mapping", counted_record_reader)

    runtime = tb21._runtime_evidence(runtime_dir, spec)

    assert runtime is None
    assert counts == {"events": 1, "record": 1}


@pytest.mark.parametrize(
    "shape",
    ["legacy_v1", "legacy_v2", "v2_deadline_compat", "v3"],
)
@pytest.mark.parametrize(
    "mutation",
    [
        "missing_required",
        "unknown_keys",
        "duplicate_key",
        "trailing_document",
        "invalid_json",
        "invalid_constant",
        "non_object",
    ],
)
def test_each_run_record_variant_has_a_closed_document_shape(
    tmp_path: Path,
    shape: str,
    mutation: str,
) -> None:
    _job_dir, spec, runtime_dir, run_path = _reader_variant_fixture(tmp_path, shape)
    record = json.loads(run_path.read_bytes())
    if mutation == "missing_required":
        del record["run_spec_sha256"]
        raw = _canonical(record)
    elif mutation == "unknown_keys":
        record["future_authoritative_key"] = True
        record["second_future_key"] = {"value": 1}
        raw = _canonical(record)
    elif mutation == "duplicate_key":
        raw = (
            b'{"schema_version":'
            + json.dumps(record["schema_version"]).encode()
            + b","
            + _canonical(record)[1:]
        )
    elif mutation == "trailing_document":
        raw = run_path.read_bytes() + b"{}\n"
    elif mutation == "invalid_json":
        raw = b'{"schema_version":\n'
    elif mutation == "invalid_constant":
        raw = b'{"schema_version":NaN}\n'
    else:
        raw = b"[]\n"
    run_path.write_bytes(raw)

    assert tb21._parse_run_record(runtime_dir, spec) is None


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_required",
        "second_unknown",
        "duplicate_key",
        "trailing_document",
        "bad_deadline_digest",
    ],
)
def test_versioned_run_record_parser_keeps_closed_json_shape(
    tmp_path: Path,
    mutation: str,
) -> None:
    job_dir, run_path = _write_collectible_v2_failure(tmp_path)
    spec = _run_spec("failure__trial", "failure", "a" * 64)
    runtime_dir = run_path.parent
    schema = (
        "nano-run-record-v2" if mutation == "second_unknown" else "nano-run-record-v3"
    )
    _bind_deadline_to_run(runtime_dir, spec, schema_version=schema)
    record = json.loads(run_path.read_bytes())
    if mutation == "missing_required":
        del record["deadline_receipt_sha256"]
        raw = _canonical(record)
    elif mutation == "second_unknown":
        record["future_authoritative_key"] = True
        raw = _canonical(record)
    elif mutation == "duplicate_key":
        raw = b'{"schema_version":"nano-run-record-v3",' + run_path.read_bytes()[1:]
    elif mutation == "trailing_document":
        raw = run_path.read_bytes() + b"{}\n"
    else:
        record["deadline_receipt_sha256"] = "NOT-A-SHA256"
        raw = _canonical(record)
    run_path.write_bytes(raw)

    assert tb21._parse_run_record(runtime_dir, spec) is None
    assert tb21._runtime_evidence(runtime_dir, spec) is None
    usage = tb21._usage(runtime_dir, spec)
    assert usage.source == "event_prefix"
    assert usage.record_valid is False


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_file",
        "receipt_tamper",
        "receipt_unknown_key",
        "run_started_mismatch",
        "cross_trial_replay",
    ],
)
def test_deadline_compat_requires_file_record_and_run_started_binding(
    tmp_path: Path,
    mutation: str,
) -> None:
    job_dir, run_path = _write_collectible_v2_failure(tmp_path)
    spec = _run_spec("failure__trial", "failure", "a" * 64)
    runtime_dir = run_path.parent
    _bind_deadline_to_run(
        runtime_dir,
        spec,
        schema_version="nano-run-record-v2",
    )
    deadline_path = runtime_dir / "deadline.json"
    deadline = json.loads(deadline_path.read_bytes())
    record = json.loads(run_path.read_bytes())
    events_path = runtime_dir / "events.jsonl"
    events = [json.loads(line) for line in events_path.read_bytes().splitlines()]
    if mutation == "missing_file":
        deadline_path.unlink()
    elif mutation == "receipt_tamper":
        deadline["cutoffs"]["actor_done_monotonic_ns"] += 1
        deadline_path.write_bytes(_canonical(deadline))
    else:
        if mutation == "receipt_unknown_key":
            deadline["future"] = True
        elif mutation == "cross_trial_replay":
            deadline["trial_id"] = "other__trial"
        deadline_raw = _canonical(deadline)
        deadline_path.write_bytes(deadline_raw)
        digest = hashlib.sha256(deadline_raw).hexdigest()
        record["deadline_receipt_sha256"] = digest
        events[0]["data"]["deadline_receipt_sha256"] = (
            "0" * 64 if mutation == "run_started_mismatch" else digest
        )
        event_raw = b"".join(_canonical(event) for event in events)
        events_path.write_bytes(event_raw)
        record["events_sha256"] = hashlib.sha256(event_raw).hexdigest()
        run_path.write_bytes(_canonical(record))

    assert tb21._parse_run_record(runtime_dir, spec) is None
    assert tb21._runtime_evidence(runtime_dir, spec) is None


@pytest.mark.parametrize(
    "mutation",
    [
        "noncanonical_rebind",
        "semantic_rebind",
        "duplicate_key_rebind",
        "trailing_document_rebind",
    ],
)
def test_deadline_receipt_tamper_fails_after_all_reader_bindings_are_rebound(
    tmp_path: Path,
    mutation: str,
) -> None:
    _job_dir, spec, runtime_dir, _run_path = _reader_variant_fixture(
        tmp_path,
        "v3",
    )
    receipt = json.loads((runtime_dir / "deadline.json").read_bytes())
    if mutation == "noncanonical_rebind":
        raw = (
            json.dumps(
                dict(reversed(list(receipt.items()))),
                ensure_ascii=False,
                separators=(", ", ": "),
            )
            + "\n"
        ).encode()
    elif mutation == "semantic_rebind":
        receipt["cutoffs"]["actor_done_monotonic_ns"] += 1
        raw = _canonical(receipt)
    elif mutation == "duplicate_key_rebind":
        raw = (
            b'{"schema_version":"nano-run-deadline-receipt-v1",'
            + _canonical(receipt)[1:]
        )
    else:
        raw = _canonical(receipt) + b"{}\n"
    _rebind_deadline_bytes(runtime_dir, raw)

    assert tb21._parse_run_record(runtime_dir, spec) is None
    assert tb21._runtime_evidence(runtime_dir, spec) is None


@pytest.mark.parametrize(
    "schema_version",
    ["nano-run-record-v2", "nano-run-record-v3"],
)
@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("run_id", "other-run"),
        ("trial_id", "other__trial"),
        ("attempt_id", "attempt-other"),
        ("run_spec_sha256", "0" * 64),
        ("events_sha256", "0" * 64),
        ("run_record_schema", "nano-run-record-alpha-1"),
        ("terminal_status", "provider_failure"),
        ("terminal_phase", "tool"),
        ("terminal_code", "other_terminal_code"),
        ("deadline_receipt_sha256", "0" * 64),
    ],
)
def test_versioned_publication_marker_binding_fails_closed(
    tmp_path: Path,
    schema_version: str,
    field: str,
    replacement: object,
) -> None:
    job_dir, _run_path = _write_collectible_v2_failure(tmp_path)
    spec = _run_spec("failure__trial", "failure", "a" * 64)
    _upgrade_v2_publication_reader_fixture(
        job_dir,
        spec,
        schema_version=schema_version,
    )
    marker_path = job_dir / str(spec["trial_id"]) / "agent" / "agent-run.json"
    marker = json.loads(marker_path.read_bytes())
    if field == "deadline_receipt_sha256" and schema_version == "nano-run-record-v2":
        pytest.skip("v2 marker has no deadline field")
    marker[field] = replacement
    marker_path.write_bytes(_canonical(marker))

    parsed = tb21._parse_run_record(marker_path.parent / "runtime", spec)
    row = _collected_row(job_dir)

    assert parsed is not None
    assert row["diagnostic_package_valid"] is False
    assert row["success_artifact_valid"] is False
    assert row["measurement_complete"] is False


@pytest.mark.parametrize(
    ("shape", "expected_variant"),
    [
        ("legacy_v1", "legacy_v1"),
        ("legacy_v2", "legacy_v2"),
        ("v2_deadline_compat", "v2_deadline_compat"),
        ("v3", "v3"),
    ],
)
def test_usage_runtime_and_artifact_share_one_normalized_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    shape: str,
    expected_variant: str,
) -> None:
    if shape == "legacy_v1":
        job_dir, spec = _write_one_job(tmp_path)
        _rewrite_valid_v1_success_runtime(job_dir, spec)
    else:
        job_dir, _run_path = _write_collectible_v2_failure(tmp_path)
        spec = _run_spec("failure__trial", "failure", "a" * 64)
        if shape in {"v2_deadline_compat", "v3"}:
            _upgrade_v2_publication_reader_fixture(
                job_dir,
                spec,
                schema_version=(
                    "nano-run-record-v3" if shape == "v3" else "nano-run-record-v2"
                ),
            )
    record_reads: list[object] = []
    original = tb21._read_run_record

    def counted_reader(
        runtime_dir: Path,
        run_spec: dict[str, object],
    ) -> object:
        read = original(runtime_dir, run_spec)
        record_reads.append(read)
        return read

    monkeypatch.setattr(tb21, "_read_run_record", counted_reader)

    trial_dir = job_dir / str(spec["trial_id"])
    artifacts = tb21._artifact_evidence(trial_dir, spec)
    candidates = tuple(
        candidate
        for candidate in tb21._scan_results(job_dir)
        if candidate.trial_name == spec["trial_id"]
    )
    row = tb21._row(
        job_dir=job_dir,
        spec=spec,
        candidates=candidates,
        pricing=None,
        source=None,
        artifacts=artifacts,
    )

    assert len(record_reads) == 1
    read = record_reads[0]
    parsed = read.parsed
    assert parsed is not None
    stored = artifacts.run_record_read
    assert stored is not None
    assert stored.parsed is parsed
    assert stored.record is None
    assert stored.events_raw is None
    assert not hasattr(stored, "events")
    assert not hasattr(parsed, "raw")
    assert not hasattr(parsed, "record")
    assert parsed.variant == expected_variant
    assert (
        parsed.run_id,
        parsed.trial_id,
        parsed.attempt_id,
        parsed.run_spec_sha256,
    ) == (
        spec["run_id"],
        spec["trial_id"],
        spec["attempt_id"],
        tb21.rust_run_spec_sha256(spec),
    )
    assert (
        row["runtime_terminal_status"],
        row["runtime_terminal_phase"],
        row["runtime_terminal_code"],
    ) == (
        parsed.runtime.terminal_status,
        parsed.runtime.terminal_phase,
        parsed.runtime.terminal_code,
    )
    assert (
        row["input_tokens"],
        row["cache_tokens"],
        row["output_tokens"],
        row["usage_call_count"],
        row["provider_cost_ticks"],
        row["usage_state"],
        row["usage_source"],
        row["usage_record_valid"],
    ) == (
        parsed.usage.input_tokens,
        parsed.usage.cache_tokens,
        parsed.usage.output_tokens,
        parsed.usage.call_count,
        parsed.usage.provider_cost_ticks,
        parsed.usage.state,
        parsed.usage.source,
        parsed.usage.record_valid,
    )
    assert row["terminal_record_valid"] is True


def test_artifact_outcome_retains_only_compact_run_record_projection(
    tmp_path: Path,
) -> None:
    job_dir, spec = _write_one_job(tmp_path)
    _rewrite_valid_v1_success_runtime(job_dir, spec)
    trial_dir = job_dir / str(spec["trial_id"])
    run_path = trial_dir / "agent" / "runtime" / "run.json"
    record = json.loads(run_path.read_bytes())
    padding_marker = "must-not-be-retained:"
    record["raw_usage"][0]["opaque_provider_payload"] = padding_marker + (
        "x" * (2 * 1024 * 1024)
    )
    run_path.write_bytes(_canonical(record))
    assert run_path.stat().st_size > 2 * 1024 * 1024

    artifacts = tb21._artifact_evidence(trial_dir, spec)

    assert artifacts.diagnostic_valid is True
    stored = artifacts.run_record_read
    assert stored is not None
    assert stored.record is None
    assert stored.events_raw is None
    parsed = stored.parsed
    assert parsed is not None
    assert set(vars(parsed)) == {
        "variant",
        "schema_version",
        "run_id",
        "trial_id",
        "attempt_id",
        "run_spec_sha256",
        "events_sha256",
        "deadline_receipt_sha256",
        "usage",
        "runtime",
        "tool_receipt_samples",
        "tool_receipt_coverage",
        "tool_receipt_omitted_samples",
        "tool_receipt_signal",
    }
    assert parsed.tool_receipt_samples == ()
    assert parsed.tool_receipt_coverage == "unavailable"
    assert parsed.tool_receipt_omitted_samples == 0
    assert parsed.tool_receipt_signal is False
    retained = repr(stored)
    assert padding_marker not in retained
    assert len(retained) < 10_000


@pytest.mark.parametrize(
    (
        "initial_state",
        "expected_source",
        "expected_record_valid",
        "expected_terminal_valid",
    ),
    [
        ("valid", "run_record_v2", True, True),
        ("invalid", "event_prefix", False, False),
        ("absent", "event_prefix", True, False),
    ],
)
def test_artifact_row_uses_one_immutable_run_record_read_outcome(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    initial_state: str,
    expected_source: str,
    expected_record_valid: bool,
    expected_terminal_valid: bool,
) -> None:
    job_dir, run_path = _write_collectible_v2_failure(tmp_path)
    spec = _run_spec("failure__trial", "failure", "a" * 64)
    valid_raw = run_path.read_bytes()
    if initial_state == "invalid":
        invalid = json.loads(valid_raw)
        invalid["future_authoritative_key"] = True
        run_path.write_bytes(_canonical(invalid))
    elif initial_state == "absent":
        run_path.unlink()

    record_reads: list[object] = []
    original = tb21._read_run_record
    mapping_calls = 0
    original_mapping = tb21._run_record_mapping
    event_read_calls = 0
    original_event_reader = tb21._read_event_prefix_outcome

    def counted_reader(
        runtime_dir: Path,
        run_spec: dict[str, object],
    ) -> object:
        read = original(runtime_dir, run_spec)
        record_reads.append(read)
        return read

    def counted_mapping(
        path: Path,
        *,
        limit: int = tb21._MAX_JSON_BYTES,
    ) -> object:
        nonlocal mapping_calls
        mapping_calls += 1
        return original_mapping(path, limit=limit)

    def counted_event_reader(
        runtime_dir: Path,
        run_spec: dict[str, object],
    ) -> object:
        nonlocal event_read_calls
        event_read_calls += 1
        return original_event_reader(runtime_dir, run_spec)

    monkeypatch.setattr(tb21, "_read_run_record", counted_reader)
    monkeypatch.setattr(tb21, "_run_record_mapping", counted_mapping)
    monkeypatch.setattr(tb21, "_read_event_prefix_outcome", counted_event_reader)
    trial_dir = job_dir / str(spec["trial_id"])
    artifacts = tb21._artifact_evidence(trial_dir, spec)

    if initial_state == "valid":
        run_path.write_bytes(b"{}\n")
        (run_path.parent / "events.jsonl").write_bytes(b"{invalid\n")
    else:
        run_path.write_bytes(valid_raw)
    candidates = tuple(
        candidate
        for candidate in tb21._scan_results(job_dir)
        if candidate.trial_name == spec["trial_id"]
    )
    row = tb21._row(
        job_dir=job_dir,
        spec=spec,
        candidates=candidates,
        pricing=None,
        source=None,
        artifacts=artifacts,
    )

    assert len(record_reads) == 1
    read = record_reads[0]
    stored = artifacts.run_record_read
    assert stored is not None
    assert stored.parsed is read.parsed
    assert stored.events_raw is None
    assert read.state == initial_state
    assert mapping_calls == (0 if initial_state == "absent" else 1)
    assert event_read_calls == 1
    assert row["usage_source"] == expected_source
    assert row["usage_record_valid"] is expected_record_valid
    assert row["terminal_record_valid"] is expected_terminal_valid
    assert row["runtime_entry_state"] == "started"
    if initial_state == "valid":
        assert row["diagnostic_package_valid"] is True
        assert row["measurement_complete"] is True


def test_old_v2_compat_and_v3_have_identical_row_projection(
    tmp_path: Path,
) -> None:
    job_dir, _run_path = _write_collectible_v2_failure(tmp_path)
    spec = _run_spec("failure__trial", "failure", "a" * 64)

    old_v2 = _collected_row(job_dir)
    _upgrade_v2_publication_reader_fixture(
        job_dir,
        spec,
        schema_version="nano-run-record-v2",
    )
    compat_v2 = _collected_row(job_dir)
    _upgrade_v2_publication_reader_fixture(
        job_dir,
        spec,
        schema_version="nano-run-record-v3",
    )
    v3 = _collected_row(job_dir)

    assert old_v2 == compat_v2 == v3


@pytest.mark.parametrize(
    ("shape", "expected_row", "expected_summary"),
    [
        (
            "legacy_v1",
            {
                "reward": 1.0,
                "raw_score_valid": True,
                "collector_pass": True,
                "strict_pass": False,
                "reliable": False,
                "measurement_complete": False,
                "failure_bucket": "artifact",
                "runtime_terminal_status": "success",
                "runtime_terminal_phase": None,
                "runtime_terminal_code": "completed",
                "input_tokens": 100,
                "cache_tokens": 40,
                "output_tokens": 20,
                "usage_source": "run_record_v1",
                "usage_record_valid": True,
            },
            {
                "strict": 0,
                "collector": 1,
                "reliable": 0,
                "measurement": 0,
                "failure_bucket": "artifact",
            },
        ),
        (
            "legacy_v2",
            {
                "reward": None,
                "raw_score_valid": False,
                "collector_pass": False,
                "strict_pass": False,
                "reliable": False,
                "measurement_complete": True,
                "failure_bucket": "tool_transport",
                "runtime_terminal_status": "tool_failure",
                "runtime_terminal_phase": "bridge",
                "runtime_terminal_code": "terminal_actor_cleanup_unverified",
                "input_tokens": 100,
                "cache_tokens": 40,
                "output_tokens": 20,
                "usage_source": "run_record_v2",
                "usage_record_valid": True,
            },
            {
                "strict": 0,
                "collector": 0,
                "reliable": 0,
                "measurement": 1,
                "failure_bucket": "tool_transport",
            },
        ),
    ],
)
def test_legacy_reader_outputs_remain_pinned(
    tmp_path: Path,
    shape: str,
    expected_row: dict[str, object],
    expected_summary: dict[str, object],
) -> None:
    if shape == "legacy_v1":
        job_dir, _spec = _write_one_job(tmp_path)
    else:
        job_dir, _run_path = _write_collectible_v2_failure(tmp_path)

    summary = tb21.collect_job(job_dir)
    row = json.loads((job_dir / "rows.jsonl").read_bytes())
    row_projection = {key: row[key] for key in expected_row}
    summary_projection = {
        "strict": summary["strict_accuracy"]["numerator"],
        "collector": summary["collector_accuracy"]["numerator"],
        "reliable": summary["reliability"]["numerator"],
        "measurement": summary["measurement_completeness"]["numerator"],
        "failure_bucket": next(
            bucket for bucket, count in summary["failure_buckets"].items() if count
        ),
    }

    assert row_projection == expected_row
    assert summary_projection == expected_summary


def test_terminal_evidence_rejects_mutated_bound_failure_diagnostic(
    tmp_path: Path,
) -> None:
    job_dir, run_path = _write_collectible_v2_failure(tmp_path)
    trial_dir = run_path.parents[2]
    (trial_dir / "result.json").unlink()

    summary = tb21.collect_job(job_dir)
    row = json.loads((job_dir / "rows.jsonl").read_bytes())
    assert row["verifier_result_kind"] == "invalid"
    assert row["diagnostic_package_valid"] is True
    assert summary["terminal_evidence"]["terminalized_started"] == 1

    (trial_dir / "agent" / "partial-trajectory.json").write_bytes(b"{}\n")
    summary = tb21.collect_job(job_dir)
    assert summary["terminal_evidence"]["terminalized_started"] == 0
    assert summary["terminal_evidence"]["valid_usage_receipts_for_started"] == 0
    assert "valid_trajectories_for_started" not in summary["terminal_evidence"]
    assert "trajectories_for_runtime_starts" not in summary["gates"]


@pytest.mark.parametrize(
    "mutation",
    ["duplicate_key", "trailing_document", "invalid_json", "unknown_field", "tamper"],
)
def test_v2_run_record_order_relaxation_keeps_strict_validation(
    tmp_path: Path,
    mutation: str,
) -> None:
    job_dir, run_path = _write_collectible_v2_failure(tmp_path)
    record = json.loads(run_path.read_bytes())
    raw = _rust_ordered_v2_run(record)
    if mutation == "duplicate_key":
        raw = b'{"schema_version":"nano-run-record-v2",' + raw[1:]
    elif mutation == "trailing_document":
        raw += b"{}\n"
    elif mutation == "invalid_json":
        raw = b"{invalid\n"
    elif mutation == "unknown_field":
        record["unknown"] = True
        raw = (
            json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode()
    else:
        record["events_sha256"] = "0" * 64
        raw = _rust_ordered_v2_run(record)
    run_path.write_bytes(raw)

    row = _collected_row(job_dir)

    assert row["result_binding_valid"] is True
    assert row["diagnostic_package_valid"] is False
    assert row["measurement_complete"] is False


def test_emergency_atif_without_event_file_remains_collectible(
    tmp_path: Path,
) -> None:
    job_dir, _spec = _write_collectible_emergency_prefix(tmp_path)

    row = _collected_row(job_dir)

    assert row["publication_kind"] == "emergency_atif"
    assert row["diagnostic_package_valid"] is True
    assert row["success_artifact_valid"] is False
    assert row["runtime_terminal_status"] == "runtime_failure"
    assert row["runtime_terminal_phase"] == "artifact"
    assert row["failure_bucket"] == "artifact"
    assert row["usage_source"] == "usage_receipt_v2"
    assert row["usage_state"] == "unavailable"
    assert row["runtime_entry_state"] == "not_observed"


def test_emergency_atif_rejects_unbound_v3_marker_relabel(
    tmp_path: Path,
) -> None:
    job_dir, spec = _write_collectible_emergency_prefix(tmp_path)
    trial_dir = job_dir / str(spec["trial_id"])
    marker_path = trial_dir / "agent" / "agent-run.json"
    marker = json.loads(marker_path.read_bytes())
    assert marker["schema_version"] == "nano-agent-run-v4"
    assert marker["publication_kind"] == "emergency_atif"
    marker["schema_version"] = "nano-agent-run-v3"
    marker["deadline_receipt_sha256"] = "f" * 64
    marker_path.write_bytes(_canonical(marker))

    artifacts = tb21._artifact_evidence(trial_dir, spec)
    row = _collected_row(job_dir)

    assert artifacts.diagnostic_valid is False
    assert artifacts.usage_fallback is None
    assert row["publication_kind"] == "emergency_atif"
    assert row["diagnostic_package_valid"] is False
    assert row["usage_receipt_valid"] is False
    assert row["runtime_terminal_status"] is None
    assert row["measurement_complete"] is False


def test_emergency_artifact_outcome_is_single_read_and_mutation_stable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job_dir, spec = _write_collectible_emergency_prefix(tmp_path)
    trial_dir = job_dir / str(spec["trial_id"])
    logs_dir = trial_dir / "agent"
    runtime_dir = logs_dir / "runtime"
    counts = {"events": 0, "marker": 0, "usage": 0}
    original_event_reader = tb21._read_event_prefix_outcome
    original_mapping_reader = tb21._canonical_mapping

    def counted_event_reader(
        selected_runtime_dir: Path,
        selected_spec: dict[str, object],
    ) -> object:
        counts["events"] += 1
        return original_event_reader(selected_runtime_dir, selected_spec)

    def counted_mapping_reader(
        path: Path,
        *,
        limit: int = 64 * 1024 * 1024,
    ) -> object:
        if path.name == "agent-run.json":
            counts["marker"] += 1
        elif path.name == "runtime-usage-receipt.json":
            counts["usage"] += 1
        return original_mapping_reader(path, limit=limit)

    monkeypatch.setattr(
        tb21,
        "_read_event_prefix_outcome",
        counted_event_reader,
    )
    monkeypatch.setattr(tb21, "_canonical_mapping", counted_mapping_reader)

    artifacts = tb21._artifact_evidence(trial_dir, spec)
    assert counts == {"events": 1, "marker": 1, "usage": 1}
    assert artifacts.diagnostic_valid is True
    assert artifacts.usage_fallback is not None
    assert artifacts.usage_fallback.source == "usage_receipt_v2"

    (runtime_dir / "events.jsonl").write_bytes(b"{tampered\n")
    (logs_dir / "agent-run.json").write_bytes(b"{tampered\n")
    (logs_dir / "runtime-usage-receipt.json").write_bytes(b"{tampered\n")
    candidates = tuple(
        candidate
        for candidate in tb21._scan_results(job_dir)
        if candidate.trial_name == spec["trial_id"]
    )
    row = tb21._row(
        job_dir=job_dir,
        spec=spec,
        candidates=candidates,
        pricing=None,
        source=None,
        artifacts=artifacts,
    )

    assert counts == {"events": 1, "marker": 1, "usage": 1}
    assert row["diagnostic_package_valid"] is True
    assert row["runtime_entry_state"] == "not_observed"
    assert row["runtime_terminal_status"] == "runtime_failure"
    assert row["usage_source"] == "usage_receipt_v2"
    assert row["usage_state"] == "unavailable"


def test_collector_rejects_dispatch_without_exact_active_tools(
    tmp_path: Path,
) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    spec = _run_spec("alpha__trial", "alpha", "a" * 64)
    spec["active_tools"] = ["run_terminal_command"]
    _write_dispatch(job_dir, [spec])
    (job_dir / "result.json").write_bytes(
        _canonical({"finished_at": "2026-07-24T00:00:01Z"})
    )

    with pytest.raises(tb21.TB21Error, match="dispatch_active_tools_mismatch"):
        tb21.collect_job(job_dir)


def test_pricing_requires_explicit_date_and_exact_model(tmp_path: Path) -> None:
    pricing = tmp_path / "pricing.json"
    pricing.write_bytes(
        _canonical(
            {
                "schema_version": "nano-token-pricing-v1",
                "as_of": "not-a-date",
                "currency": "USD",
                "model": "grok-4.5",
                "input_per_million_usd": 1,
                "cached_input_per_million_usd": 1,
                "output_per_million_usd": 1,
            }
        )
    )

    with pytest.raises(tb21.TB21Error, match="pricing_invalid"):
        tb21.load_pricing(pricing)


def test_historic_event_prefix_anchor_freezes_lower_bound_totals() -> None:
    fixture_path = (
        Path(__file__).parent
        / "fixtures"
        / "tb21"
        / "historic-a43d5fd-event-prefix-anchor.json"
    )
    raw = fixture_path.read_bytes()
    fixture = json.loads(raw)

    assert raw == _canonical(fixture)
    assert fixture["schema_version"] == ("nano-tb21-historic-event-prefix-anchor-v1")
    prefixes = fixture["exception_prefixes"]
    assert len(prefixes) == 12
    assert len({row["trial"] for row in prefixes}) == 12
    assert all(len(row["events_sha256"]) == 64 for row in prefixes)

    prefix_totals = {
        field: sum(row[field] for row in prefixes)
        for field in (
            "requested",
            "completed",
            "input_tokens",
            "cache_tokens",
            "output_tokens",
            "cost_ticks",
        )
    }
    assert prefix_totals == fixture["prefix_totals"]
    terminal = fixture["terminal_record_totals"]
    expected = fixture["expected"]
    assert terminal["requested"] + prefix_totals["requested"] == 1377
    assert terminal["completed"] + prefix_totals["completed"] == 1369
    assert expected == {
        "cache_tokens": 33_502_720,
        "completed": 1369,
        "cost_ticks_lower_bound": 238_573_980_000,
        "cost_usd_lower_bound": "23.8573980",
        "in_flight": 8,
        "input_tokens": 37_430_517,
        "output_tokens": 991_981,
        "requested": 1377,
        "usage_state": "partial",
    }


def test_historic_raw_anchor_recovery_when_explicitly_enabled() -> None:
    raw_anchor = os.environ.get("NANO_TB21_HISTORIC_ANCHOR")
    if raw_anchor is None:
        pytest.skip("set NANO_TB21_HISTORIC_ANCHOR for immutable integration anchor")

    job_dir = Path(raw_anchor).resolve()
    before = {
        path.relative_to(job_dir).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in sorted(job_dir.rglob("*"))
        if path.is_file() and path.name not in {"rows.jsonl", "summary.json"}
    }
    summary = tb21.collect_job(job_dir)
    rows = [
        json.loads(line) for line in (job_dir / "rows.jsonl").read_text().splitlines()
    ]
    after = {
        path.relative_to(job_dir).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in sorted(job_dir.rglob("*"))
        if path.is_file() and path.name not in {"rows.jsonl", "summary.json"}
    }

    assert before == after
    assert sum(row["provider_calls_requested"] for row in rows) == 1377
    assert sum(row["provider_calls_completed"] for row in rows) == 1369
    assert summary["usage"]["state_counts"] == {
        "complete": 81,
        "partial": 8,
        "unavailable": 0,
        "invalid": 0,
    }
    assert summary["cost_usd"]["observed_lower_bound"] == pytest.approx(23.8573980)


def test_usage_recovers_partial_event_prefix_without_run_record(
    tmp_path: Path,
) -> None:
    spec = _run_spec("partial__trial", "partial", "a" * 64)
    runtime = tmp_path / "runtime"
    _write_event_prefix(
        runtime,
        spec,
        [
            (
                "run.started",
                {
                    "task_id": "terminal-bench/partial",
                    "contract_id": "nano-v1",
                    "profile_id": "nano-v1-grok-4-5-high-v1",
                    "contract_set_sha256": "c" * 64,
                    "model": "grok-4.5",
                    "run_spec_sha256": tb21.rust_run_spec_sha256(spec),
                },
            ),
            (
                "provider.requested",
                {
                    "turn_index": 0,
                    "history_item_count": 2,
                    "tool_count": 8,
                    "function_output_call_ids": [],
                },
            ),
            (
                "provider.completed",
                {
                    "turn_index": 0,
                    "response_id": "response-0",
                    "model": "grok-4.5",
                    "call_ids": [],
                    "has_final_text": False,
                    "usage": _usage_value(),
                },
            ),
            (
                "provider.requested",
                {
                    "turn_index": 1,
                    "history_item_count": 3,
                    "tool_count": 8,
                    "function_output_call_ids": [],
                },
            ),
        ],
    )

    usage = tb21._usage(runtime, spec)

    assert usage.source == "event_prefix"
    assert usage.state == "partial"
    assert usage.requested_count == 2
    assert usage.completed_count == 1
    assert usage.failed_count == 0
    assert usage.in_flight_count == 1
    assert usage.usage_covered_calls == 1
    assert usage.input_tokens == 100
    assert usage.cache_tokens == 40
    assert usage.output_tokens == 20
    assert usage.provider_cost_ticks == 123_000_000
    assert usage.provider_cost_ticks_covered_calls == 1


def test_usage_prefix_counts_rejected_response_usage_as_settled_coverage(
    tmp_path: Path,
) -> None:
    spec = _run_spec("rejected__trial", "rejected", "a" * 64)
    runtime = tmp_path / "runtime"
    _write_event_prefix(
        runtime,
        spec,
        [
            (
                "run.started",
                {
                    "task_id": "terminal-bench/rejected",
                    "contract_id": "nano-v1",
                    "profile_id": "nano-v1-grok-4-5-high-v1",
                    "contract_set_sha256": "c" * 64,
                    "model": "grok-4.5",
                    "run_spec_sha256": tb21.rust_run_spec_sha256(spec),
                },
            ),
            (
                "provider.requested",
                {
                    "turn_index": 0,
                    "history_item_count": 2,
                    "tool_count": 8,
                    "function_output_call_ids": [],
                },
            ),
            (
                "provider.failed",
                {
                    "turn_index": 0,
                    "code": "provider_call_limit_exceeded",
                    "rejected_call_count": 9,
                    "response_usage": {
                        "input_tokens": 11,
                        "output_tokens": 3,
                        "input_tokens_details": {"cached_tokens": 2},
                        "cost_in_usd_ticks": 123_000_000,
                        "provider_cost_ticks": 123_000_000,
                    },
                },
            ),
            ("run.failed", {"code": "provider_call_limit_exceeded"}),
        ],
    )

    usage = tb21._usage(runtime, spec)

    assert usage.source == "event_prefix"
    assert usage.state == "complete"
    assert usage.requested_count == 1
    assert usage.completed_count == 0
    assert usage.failed_count == 1
    assert usage.usage_present_count == 1
    assert usage.usage_absent_count == 0
    assert usage.usage_covered_calls == 1
    assert usage.input_tokens == 11
    assert usage.cache_tokens == 2
    assert usage.output_tokens == 3
    assert usage.provider_cost_ticks == 123_000_000
    assert usage.provider_cost_ticks_covered_calls == 1


def test_collector_exposes_partial_usage_coverage_and_cost_lower_bound(
    tmp_path: Path,
) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    spec = _run_spec("partial__trial", "partial", "a" * 64)
    _write_dispatch(job_dir, [spec])
    trial_dir = job_dir / str(spec["trial_id"])
    runtime = trial_dir / "agent" / "runtime"
    _write_event_prefix(
        runtime,
        spec,
        [
            (
                "run.started",
                {
                    "task_id": "terminal-bench/partial",
                    "contract_id": "nano-v1",
                    "profile_id": "nano-v1-grok-4-5-high-v1",
                    "contract_set_sha256": "c" * 64,
                    "model": "grok-4.5",
                    "run_spec_sha256": tb21.rust_run_spec_sha256(spec),
                },
            ),
            (
                "provider.requested",
                {
                    "turn_index": 0,
                    "history_item_count": 2,
                    "tool_count": 8,
                    "function_output_call_ids": [],
                },
            ),
            (
                "provider.completed",
                {
                    "turn_index": 0,
                    "response_id": "response-0",
                    "model": "grok-4.5",
                    "call_ids": [],
                    "has_final_text": False,
                    "usage": _usage_value(),
                },
            ),
            (
                "provider.requested",
                {
                    "turn_index": 1,
                    "history_item_count": 3,
                    "tool_count": 8,
                    "function_output_call_ids": [],
                },
            ),
        ],
    )
    result = {
        "task_name": "terminal-bench/partial",
        "trial_name": spec["trial_id"],
        "task_checksum": "a" * 64,
        "verifier_result": None,
        "exception_info": {
            "exception_type": "AgentTimeoutError",
            "exception_message": "agent timed out",
        },
        "started_at": "2026-07-24T00:00:00Z",
        "finished_at": "2026-07-24T00:00:01Z",
    }
    trial_dir.mkdir(parents=True, exist_ok=True)
    (trial_dir / "result.json").write_bytes(_canonical(result))
    (job_dir / "result.json").write_bytes(
        _canonical({"finished_at": "2026-07-24T00:00:01Z"})
    )

    summary = tb21.collect_job(job_dir)
    row = json.loads((job_dir / "rows.jsonl").read_text())

    assert row["usage_state"] == "partial"
    assert row["usage_source"] == "event_prefix"
    assert row["provider_calls_requested"] == 2
    assert row["provider_calls_completed"] == 1
    assert row["provider_calls_failed"] == 0
    assert row["provider_calls_in_flight"] == 1
    assert row["provider_calls_usage_covered"] == 1
    assert row["provider_cost_ticks_coverage"] == "1/2"
    assert row["provider_cost_usd_observed"] == pytest.approx(0.0123)
    assert row["cost_usd"] is None
    assert summary["usage"]["state_counts"]["partial"] == 1
    assert summary["usage"]["provider_calls"] == {
        "requested": 2,
        "completed": 1,
        "failed": 0,
        "in_flight": 1,
        "usage_present": 1,
        "usage_absent": 0,
        "usage_covered": 1,
    }
    assert summary["cost_usd"]["observed_lower_bound"] == pytest.approx(0.0123)


def test_usage_prefers_matching_v2_record_and_cost_aliases_fail_closed(
    tmp_path: Path,
) -> None:
    spec = _run_spec("v2__trial", "v2", "a" * 64)
    runtime = tmp_path / "runtime"
    event_bytes = _write_event_prefix(
        runtime,
        spec,
        [
            (
                "run.started",
                {
                    "task_id": "terminal-bench/v2",
                    "contract_id": "nano-v1",
                    "profile_id": "nano-v1-grok-4-5-high-v1",
                    "contract_set_sha256": "c" * 64,
                    "model": "grok-4.5",
                    "run_spec_sha256": tb21.rust_run_spec_sha256(spec),
                },
            ),
            (
                "provider.requested",
                {
                    "turn_index": 0,
                    "history_item_count": 2,
                    "tool_count": 8,
                    "function_output_call_ids": [],
                },
            ),
            (
                "provider.completed",
                {
                    "turn_index": 0,
                    "response_id": "response-0",
                    "model": "grok-4.5",
                    "call_ids": [],
                    "has_final_text": True,
                    "usage": _usage_value(),
                },
            ),
            ("assistant.final", {"text": "done"}),
            ("run.completed", {"code": "completed"}),
        ],
        schema="event-v2",
    )
    record = {
        "schema_version": "nano-run-record-v2",
        "run_id": spec["run_id"],
        "trial_id": spec["trial_id"],
        "attempt_id": spec["attempt_id"],
        "run_spec_sha256": tb21.rust_run_spec_sha256(spec),
        "contract_id": "nano-v1",
        "contract_set_sha256": "c" * 64,
        "profile_id": "nano-v1-grok-4-5-high-v1",
        "terminal_status": "success",
        "terminal_phase": None,
        "terminal_code": "completed",
        "final_event_seq": 4,
        "provider_turn_count": 1,
        "tool_call_count": 0,
        "provider_call_coverage": {
            "requested": 1,
            "completed": 1,
            "failed": 0,
            "in_flight": 0,
            "usage_present": 1,
            "usage_absent": 0,
            "usage_covered": 1,
            "cost_present": 1,
            "cost_absent": 0,
            "state": "complete",
        },
        "usage_totals": {
            "input_tokens": 100,
            "cached_input_tokens": 40,
            "output_tokens": 20,
            "provider_cost_ticks": 123_000_000,
        },
        "start_elapsed_ms": 0,
        "end_elapsed_ms": 40,
        "events_sha256": hashlib.sha256(event_bytes).hexdigest(),
    }
    run_path = runtime / "run.json"
    run_path.write_bytes(_canonical(record))

    usage = tb21._usage(runtime, spec)

    assert usage.source == "run_record_v2"
    assert usage.state == "complete"
    assert usage.requested_count == usage.completed_count == 1
    assert usage.in_flight_count == 0
    assert usage.usage_covered_calls == 1
    assert usage.provider_cost_ticks_covered_calls == 1

    events_path = runtime / "events.jsonl"
    events = [json.loads(line) for line in events_path.read_bytes().splitlines()]
    native_usage = events[2]["data"]["usage"]
    native_usage["provider_cost_ticks"] = 123_000_001
    event_bytes = b"".join(_canonical(event) for event in events)
    events_path.write_bytes(event_bytes)
    record["events_sha256"] = hashlib.sha256(event_bytes).hexdigest()
    run_path.write_bytes(_canonical(record))
    assert tb21._parse_run_record(runtime, spec) is None
    assert tb21._usage(runtime, spec).state == "invalid"

    del native_usage["cost_in_usd_ticks"]
    native_usage["provider_cost_ticks"] = 123_000_000
    event_bytes = b"".join(_canonical(event) for event in events)
    events_path.write_bytes(event_bytes)
    record["events_sha256"] = hashlib.sha256(event_bytes).hexdigest()
    run_path.write_bytes(_canonical(record))
    alias_only = tb21._usage(runtime, spec)
    assert tb21._parse_run_record(runtime, spec) is None
    assert alias_only.source == "event_prefix"
    assert alias_only.provider_cost_ticks_covered_calls == 0


def test_usage_keeps_v1_compatibility_when_event_log_is_historic_fixture(
    tmp_path: Path,
) -> None:
    job_dir, spec = _write_one_job(tmp_path)

    usage = tb21._usage(
        job_dir / str(spec["trial_id"]) / "agent" / "runtime",
        spec,
    )

    assert usage.source == "run_record_v1"
    assert usage.state == "complete"
    assert usage.requested_count == usage.completed_count == 1
    assert usage.usage_covered_calls == 1


@pytest.mark.parametrize(
    "mutation",
    ["sequence", "identity", "elapsed", "pairing"],
)
def test_usage_rejects_invalid_event_prefix(
    tmp_path: Path,
    mutation: str,
) -> None:
    spec = _run_spec("invalid__trial", "invalid", "a" * 64)
    runtime = tmp_path / "runtime"
    raw = _write_event_prefix(
        runtime,
        spec,
        [
            (
                "run.started",
                {
                    "task_id": "terminal-bench/invalid",
                    "contract_id": "nano-v1",
                    "profile_id": "nano-v1-grok-4-5-high-v1",
                    "contract_set_sha256": "c" * 64,
                    "model": "grok-4.5",
                    "run_spec_sha256": tb21.rust_run_spec_sha256(spec),
                },
            ),
            (
                "provider.requested",
                {
                    "turn_index": 0,
                    "history_item_count": 2,
                    "tool_count": 8,
                    "function_output_call_ids": [],
                },
            ),
            (
                "provider.completed",
                {
                    "turn_index": 0,
                    "response_id": "response-0",
                    "model": "grok-4.5",
                    "call_ids": [],
                    "has_final_text": False,
                    "usage": _usage_value(),
                },
            ),
        ],
    )
    events = [json.loads(line) for line in raw.splitlines()]
    if mutation == "sequence":
        events[1]["seq"] = 9
    elif mutation == "identity":
        events[1]["trial_id"] = "another-trial"
    elif mutation == "elapsed":
        events[2]["elapsed_ms"] = 1
    else:
        events[2]["data"]["turn_index"] = 7
    (runtime / "events.jsonl").write_bytes(
        b"".join(_canonical(event) for event in events)
    )

    usage = tb21._usage(runtime, spec)

    assert usage.source == "event_prefix"
    assert usage.state == "invalid"
    assert usage.requested_count == usage.completed_count == 0
    assert usage.input_tokens is None


_HISTORICAL_FIXTURE = (
    Path(__file__).parent / "fixtures/tb21/historical-v2-deadline-synthetic-v1"
)  # noqa: E501
_HISTORICAL_RECIPE = _HISTORICAL_FIXTURE / "reconstruct.py"
_HISTORICAL_GOLDEN = _HISTORICAL_FIXTURE / "golden.json"


def _historical_recipe() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(
        "_historical_fixture", _HISTORICAL_RECIPE
    )  # noqa: E501
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_historical_v2_deadline_synthetic_double_regeneration_matches_golden() -> None:
    assert _HISTORICAL_GOLDEN.is_file(), "Commit B must add reviewed golden.json"
    source = os.environ.get("NANO_PR2_HISTORICAL_SOURCE_TREE")
    if source is None:
        pytest.skip("set NANO_PR2_HISTORICAL_SOURCE_TREE for release evidence")
    subprocess.run((sys.executable, _HISTORICAL_RECIPE, "verify", source), check=True)


def test_historical_v2_deadline_synthetic_is_current_compatible(tmp_path: Path) -> None:
    assert _HISTORICAL_GOLDEN.is_file(), "Commit B must add reviewed golden.json"
    recipe, agent = _historical_recipe(), tmp_path / "agent"
    recipe.materialize(agent)
    spec = json.loads((_HISTORICAL_FIXTURE / "input.json").read_bytes())["run_spec"]
    event_lines = (agent / "runtime/events.jsonl").read_bytes().splitlines()
    events = list(map(json.loads, event_lines))
    usage = events[2]["data"]["usage"]
    assert usage["cost_in_usd_ticks"] == usage["provider_cost_ticks"] == 17
    record = json.loads((agent / "runtime/run.json").read_bytes())
    assert record["usage_totals"] == {
        "input_tokens": 13,
        "cached_input_tokens": 2,
        "output_tokens": 5,
        "provider_cost_ticks": 17,
    }
    parsed = tb21._parse_run_record(agent / "runtime", spec)
    assert parsed is not None and parsed.variant == "v2_deadline_compat"
    assert parsed.usage.record_valid and parsed.usage.provider_cost_ticks == 17
    names = ("agent-run.json", "runtime-usage-receipt.json", "trajectory.json")
    expected = {name: (agent / name).read_bytes() for name in names}
    for name in names:
        (agent / name).unlink()
    publish_artifacts(
        logs_dir=agent,
        run_spec=spec,
        instruction=spec["task"]["instruction"],
        agent_name="nano-grok-build-synthetic-historical-compat",
        agent_version="d0c4c8c3d268",
        model_name=spec["provider"]["model"],
        require_harbor_validator=False,
    )
    assert {name: (agent / name).read_bytes() for name in names} == expected


@pytest.mark.parametrize(
    "case",
    (
        "producer",
        "metadata",
        "recipe",
        "row",
        "payload",
        "hash",
        "length",
        "destination",
    ),
)  # noqa: E501
def test_historical_v2_deadline_recipe_rejects_tampering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:  # noqa: E501
    recipe = _historical_recipe()
    if case == "producer" and not (Path(__file__).parent.parent / ".git").exists():
        pytest.skip("real wrong-source pin check requires a Git worktree")
    monkeypatch.setattr(recipe, "HERE", tmp_path)
    for name in recipe.RECIPE_FILES:
        (tmp_path / name).write_bytes(b"x")
    metadata = (
        "0" * 40,
        {name: recipe.hashlib.sha256(b"x").hexdigest() for name in recipe.RECIPE_FILES},
    )  # noqa: E501
    value = recipe._envelope(metadata, {name: b"x" for name in recipe.EXPECTED_FILES})
    with pytest.raises(ValueError):
        if case == "recipe":
            (tmp_path / recipe.RECIPE_FILES[0]).write_bytes(b"changed")
            recipe._recipe(metadata)
        elif case == "producer":
            recipe._source(Path(__file__).parent.parent)
        elif case == "destination":
            recipe._empty(tmp_path)
        else:
            if case == "metadata":
                value["recipe_commit"] = "A" * 40
            elif case == "row":
                value["files"][0] = None
            else:
                key, changed = {
                    "payload": ("base64", "eB=="),
                    "hash": ("sha256", "1" * 64),
                    "length": ("byte_length", 2),
                }[case]  # noqa: E501
                value["files"][0][key] = changed
            recipe._decode(value)


def _workspace_receipt_fixture(tmp_path: Path) -> tuple[Path, bytes]:
    workspace = tmp_path / "workspace"
    logs = tmp_path / "agent"
    workspace.mkdir()
    logs.mkdir()
    actor = SimpleNamespace(workspace=workspace, artifacts=logs)
    before = asyncio.run(capture_before(actor, SnapshotPolicy()))
    (workspace / "answer.txt").write_text("answer\n", encoding="utf-8")
    asyncio.run(capture_after(actor, before))
    return logs, (logs / "workspace-receipt.json").read_bytes()


def test_workspace_receipt_marker_file_disagreement_is_fatal(
    tmp_path: Path,
) -> None:
    logs, payload = _workspace_receipt_fixture(tmp_path)

    valid = tb21._workspace_receipt_evidence(
        logs,
        hashlib.sha256(payload).hexdigest(),
    )
    disagreeing = tb21._workspace_receipt_evidence(logs, "0" * 64)

    assert valid.receipt_valid is True
    assert valid.snapshot_complete is True
    assert disagreeing.receipt_valid is False
    assert disagreeing.snapshot_complete is False


def test_workspace_receipt_noncanonical_tamper_and_duplicate_key_are_fatal(
    tmp_path: Path,
) -> None:
    logs, canonical = _workspace_receipt_fixture(tmp_path)
    receipt_path = logs / "workspace-receipt.json"

    noncanonical = canonical.removesuffix(b"\n")
    receipt_path.write_bytes(noncanonical)
    assert (
        tb21._workspace_receipt_evidence(
            logs,
            hashlib.sha256(noncanonical).hexdigest(),
        ).receipt_valid
        is False
    )

    duplicate = canonical.replace(
        b'{"artifacts":',
        b'{"artifacts":{},"artifacts":',
        1,
    )
    receipt_path.write_bytes(duplicate)
    assert (
        tb21._workspace_receipt_evidence(
            logs,
            hashlib.sha256(duplicate).hexdigest(),
        ).receipt_valid
        is False
    )


def _local_failfast_event(
    trial_id: str,
    *,
    exception_type: str = "RuntimeError",
    exception_message: str = "git_history_baseline_failed",
    setup_started: bool = True,
    agent_execution: object = None,
    agent_result: object = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        result=SimpleNamespace(
            trial_name=trial_id,
            exception_info=SimpleNamespace(
                exception_type=exception_type,
                exception_message=exception_message,
            ),
            agent_setup=(
                SimpleNamespace(started_at="2026-08-06T00:00:00Z")
                if setup_started
                else None
            ),
            agent_execution=agent_execution,
            agent_result=agent_result,
        )
    )


def test_local_failfast_n1_continues_and_n2_writes_canonical_receipt(
    tmp_path: Path,
) -> None:
    hook = tb21._SystematicSetupFailFastHook(
        job_dir=tmp_path,
        selected_count=89,
        concurrency=2,
    )

    asyncio.run(hook(_local_failfast_event("trial-1")))
    assert not (tmp_path / "nano-local-failfast.json").exists()
    with pytest.raises(tb21._SystematicSetupFailFast):
        asyncio.run(hook(_local_failfast_event("trial-2")))

    raw = (tmp_path / "nano-local-failfast.json").read_bytes()
    receipt = json.loads(raw)
    assert raw == _canonical(receipt)
    assert receipt == {
        "schema_version": "nano-tb21-local-failfast-v1",
        "status": "triggered",
        "threshold": 2,
        "signature": {
            "exception_type": "RuntimeError",
            "exception_message": "git_history_baseline_failed",
        },
        "matched_trial_ids": ["trial-1", "trial-2"],
        "selected_count": 89,
        "concurrency": 2,
        "provider_started": 0,
        "attempt": 1,
        "retry": 0,
        "triggered_at": receipt["triggered_at"],
    }


@pytest.mark.parametrize(
    "event",
    [
        _local_failfast_event("unknown", exception_message="task_specific_failure"),
        _local_failfast_event("different", exception_type="BridgeError"),
        _local_failfast_event("no-setup", setup_started=False),
        _local_failfast_event("provider-started", agent_execution=object()),
        _local_failfast_event("agent-result", agent_result=object()),
    ],
)
def test_local_failfast_non_setup_provider0_cases_never_trigger(
    tmp_path: Path, event: SimpleNamespace
) -> None:
    hook = tb21._SystematicSetupFailFastHook(
        job_dir=tmp_path,
        selected_count=89,
        concurrency=2,
    )

    asyncio.run(hook(event))
    asyncio.run(hook(event))

    assert not (tmp_path / "nano-local-failfast.json").exists()


@pytest.mark.parametrize(
    ("exception_type", "exception_message"),
    [
        ("ProviderError", "provider_final_deadline_exceeded"),
        ("ToolError", "tool_settlement_deadline_exceeded"),
        ("BridgeError", "terminal_actor_cleanup_unverified"),
        ("BridgeError", "external_bridge_cleanup_unverified"),
        ("BridgeError", "external_runtime_nonzero"),
    ],
)
def test_repeated_typed_terminal_errors_are_denominator_results_not_failfast(
    tmp_path: Path,
    exception_type: str,
    exception_message: str,
) -> None:
    hook = tb21._SystematicSetupFailFastHook(
        job_dir=tmp_path,
        selected_count=89,
        concurrency=2,
    )

    for index in range(3):
        result = {
            "exception_info": {
                "exception_type": exception_type,
                "exception_message": exception_message,
            }
        }
        assert tb21._official_result_classification(
            result,
            candidate_error=None,
            identity_valid=True,
        ) == ("errored", None)
        asyncio.run(
            hook(
                _local_failfast_event(
                    f"family-{index}__trial-{index}",
                    exception_type=exception_type,
                    exception_message=exception_message,
                )
            )
        )

    assert not (tmp_path / "nano-local-failfast.json").exists()


def test_local_failfast_concurrent_end_race_triggers_once(tmp_path: Path) -> None:
    hook = tb21._SystematicSetupFailFastHook(
        job_dir=tmp_path,
        selected_count=89,
        concurrency=2,
    )

    async def race() -> list[object]:
        return await asyncio.gather(
            hook(_local_failfast_event("trial-a")),
            hook(_local_failfast_event("trial-b")),
            return_exceptions=True,
        )

    results = asyncio.run(race())

    assert (
        sum(isinstance(result, tb21._SystematicSetupFailFast) for result in results)
        == 1
    )
    receipt = json.loads((tmp_path / "nano-local-failfast.json").read_bytes())
    assert receipt["matched_trial_ids"] == ["trial-a", "trial-b"]


def test_local_failfast_exception_group_selects_dedicated_terminal_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    specs = [{"trial_id": "trial-1"}]
    captured: dict[str, object] = {}
    error = ExceptionGroup(
        "harbor task group",
        [RuntimeError("sibling cancelled"), tb21._SystematicSetupFailFast()],
    )
    monkeypatch.setattr(tb21, "_load_dispatch", lambda _path: specs)

    def interruption_value(*_args: object, **kwargs: object) -> dict[str, object]:
        captured["reason"] = kwargs["reason"]
        return {"status": "interrupted"}

    monkeypatch.setattr(tb21, "_interruption_value", interruption_value)
    monkeypatch.setattr(
        tb21,
        "_atomic_write",
        lambda path, payload: captured.update(path=path, payload=payload),
    )

    assert tb21._terminalize_interruption(tmp_path, specs, error)
    assert captured["reason"] == "systematic_setup_failfast"
    assert captured["path"] == tmp_path / "nano-terminalization.json"


def test_local_failfast_agent_start_before_second_end_latches_cohort(
    tmp_path: Path,
) -> None:
    hook = tb21._SystematicSetupFailFastHook(
        job_dir=tmp_path,
        selected_count=89,
        concurrency=3,
    )

    asyncio.run(hook(_local_failfast_event("trial-1")))
    asyncio.run(hook.agent_started(SimpleNamespace(task_name="provider-trial")))
    asyncio.run(hook(_local_failfast_event("trial-2")))

    assert not (tmp_path / "nano-local-failfast.json").exists()


def test_local_failfast_requires_two_distinct_trial_ids(tmp_path: Path) -> None:
    hook = tb21._SystematicSetupFailFastHook(
        job_dir=tmp_path,
        selected_count=89,
        concurrency=2,
    )
    event = _local_failfast_event("trial-1")

    asyncio.run(hook(event))
    asyncio.run(hook(event))

    assert not (tmp_path / "nano-local-failfast.json").exists()


def test_controller_harbor_taskgroup_failfast_cancels_and_cleans(
    tmp_path: Path,
) -> None:
    repository = Path(__file__).resolve().parents[1]
    image = "sha256:85ad69caf106c8bef40c16969ed92f089acffcca5c4e306f9a58c8d276a3781f"
    try:
        inspected = subprocess.run(
            ["docker", "image", "inspect", image],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pytest.skip("Docker is unavailable for the cached Harbor integration")
    if inspected.returncode != 0:
        pytest.skip("exact cached Harbor controller image is unavailable")

    script = textwrap.dedent(
        """
        import asyncio
        import json
        import sys
        from datetime import datetime, timezone
        from pathlib import Path

        from harbor.job import Job
        from harbor.models.job.config import JobConfig, RetryConfig
        from harbor.models.trial.config import TaskConfig
        from harbor.models.trial.result import (
            AgentInfo,
            ExceptionInfo,
            ModelInfo,
            TimingInfo,
            TrialResult,
        )
        from harbor.tasks.client import TaskDownloadResult
        from harbor.trial.hooks import TrialEvent, TrialHookEvent
        from nano_grok_build.harbor import tb21


        async def main(root: Path) -> None:
            task_configs = []
            for name in ("alpha", "beta", "live-sibling"):
                task_dir = root / "tasks" / name
                task_dir.mkdir(parents=True)
                (task_dir / "instruction.md").write_text(f"Solve {name}.\\n")
                task_configs.append(TaskConfig(path=task_dir))
            config = JobConfig(
                job_name="offline-systematic-failfast",
                jobs_dir=root / "jobs",
                n_attempts=1,
                n_concurrent_trials=3,
                quiet=True,
                retry=RetryConfig(max_retries=0),
                tasks=task_configs,
            )
            metrics = await Job._resolve_metrics(config, task_configs)
            downloads = {
                task.get_task_id(): TaskDownloadResult(
                    path=task.get_local_path(), download_time_sec=0.0, cached=True
                )
                for task in task_configs
            }
            job = Job(
                config,
                _task_configs=task_configs,
                _metrics=metrics,
                _task_download_results=downloads,
            )
            hook = tb21._SystematicSetupFailFastHook(
                job_dir=job.job_dir, selected_count=3, concurrency=3
            )
            job.add_hook(TrialEvent.AGENT_START, hook.agent_started)
            job.add_hook(TrialEvent.END, hook)
            lifecycle = []
            provider_events = 0
            sibling_ready = asyncio.Event()
            first_done = asyncio.Event()

            async def count_provider(_event):
                nonlocal provider_events
                provider_events += 1

            async def record_cancel(event):
                lifecycle.append([event.trial_name, "CANCEL"])

            job.add_hook(TrialEvent.AGENT_START, count_provider)
            job.add_hook(TrialEvent.CANCEL, record_cancel)

            async def emit(event_type, trial_config, result, index):
                event = TrialHookEvent(
                    event=event_type,
                    task_name=result.task_name,
                    config=trial_config,
                    result=result,
                    lock=job._job_lock.trials[index],
                )
                for callback in list(job._trial_queue._hooks[event_type]):
                    await callback(event)
                return event

            async def finalize(trial_config, result, index):
                lifecycle.append([trial_config.trial_name, "FINALIZE"])
                lifecycle.append([trial_config.trial_name, "ENV_STOP"])
                result.finished_at = datetime.now(timezone.utc)
                trial_dir = job.job_dir / trial_config.trial_name
                trial_dir.mkdir(parents=True, exist_ok=True)
                (trial_dir / "result.json").write_text(
                    result.model_dump_json(indent=2)
                )
                await emit(TrialEvent.END, trial_config, result, index)

            async def execute(trial_config, index):
                now = datetime.now(timezone.utc)
                task_name = trial_config.task.get_task_id().get_name()
                failed_setup = index < 2
                result = TrialResult(
                    task_name=task_name,
                    trial_name=trial_config.trial_name,
                    trial_uri=(job.job_dir / trial_config.trial_name).as_uri(),
                    task_id=trial_config.task.get_task_id(),
                    source=trial_config.task.source,
                    task_checksum=f"digest-{index}",
                    config=trial_config,
                    agent_info=AgentInfo(
                        name="offline-fake",
                        version="1.0",
                        model_info=ModelInfo(name="offline-model"),
                    ),
                    exception_info=(
                        ExceptionInfo(
                            exception_type="RuntimeError",
                            exception_message="git_history_baseline_failed",
                            exception_traceback="redacted",
                            occurred_at=now,
                        )
                        if failed_setup
                        else None
                    ),
                    agent_setup=(
                        TimingInfo(started_at=now, finished_at=now)
                        if failed_setup
                        else None
                    ),
                    started_at=now,
                )
                if index == 2:
                    sibling_ready.set()
                    try:
                        await asyncio.Event().wait()
                    except asyncio.CancelledError:
                        await emit(TrialEvent.CANCEL, trial_config, result, index)
                        lifecycle.append([trial_config.trial_name, "RECOVER"])
                        raise
                    finally:
                        await finalize(trial_config, result, index)
                await sibling_ready.wait()
                if index == 1:
                    await first_done.wait()
                try:
                    await finalize(trial_config, result, index)
                finally:
                    if index == 0:
                        first_done.set()
                return result

            def submit_batch(configs):
                return [execute(item, index) for index, item in enumerate(configs)]

            job._trial_queue.submit_batch = submit_batch
            try:
                await job.run()
            except ExceptionGroup as error:
                assert tb21._is_systematic_setup_failfast(error)
                group = error
            else:
                raise AssertionError("systematic setup failure did not propagate")

            specs = tuple(
                {"trial_id": item.trial_name} for item in job._trial_configs
            )
            tb21._load_dispatch = lambda _job_dir: specs
            tb21._interruption_value = lambda *_args, **kwargs: {
                "schema_version": tb21.INTERRUPTION_TERMINALIZATION_SCHEMA,
                "status": "interrupted",
                "reason": kwargs["reason"],
                "artifact_state": "complete",
            }
            assert tb21._terminalize_interruption(job.job_dir, specs, group)

            receipt_path = job.job_dir / "nano-local-failfast.json"
            receipt_raw = receipt_path.read_bytes()
            receipt = json.loads(receipt_raw)
            terminal_path = job.job_dir / "nano-terminalization.json"
            terminal_raw = terminal_path.read_bytes()
            terminal = json.loads(terminal_raw)
            assert receipt_raw == tb21._canonical(receipt)
            assert terminal_raw == tb21._canonical(terminal)
            assert receipt["provider_started"] == 0
            assert len(set(receipt["matched_trial_ids"])) == 2
            assert terminal["reason"] == "systematic_setup_failfast"
            assert terminal["artifact_state"] == "complete"
            sibling_name = job._trial_configs[2].trial_name
            assert [sibling_name, "CANCEL"] in lifecycle
            assert [sibling_name, "RECOVER"] in lifecycle
            assert {name for name, event in lifecycle if event == "FINALIZE"} == {
                item.trial_name for item in job._trial_configs
            }
            assert {name for name, event in lifecycle if event == "ENV_STOP"} == {
                item.trial_name for item in job._trial_configs
            }
            assert provider_events == 0

            mixed_dir = root / "mixed"
            mixed_dir.mkdir()
            mixed = tb21._SystematicSetupFailFastHook(
                job_dir=mixed_dir, selected_count=3, concurrency=3
            )
            first_path = (
                job.job_dir / job._trial_configs[0].trial_name / "result.json"
            )
            second_path = (
                job.job_dir / job._trial_configs[1].trial_name / "result.json"
            )
            first_result = json.loads(
                first_path.read_text()
            )
            second_result = json.loads(
                second_path.read_text()
            )
            await mixed(type("Event", (), {"result": first_result})())
            await mixed.agent_started(object())
            await mixed(type("Event", (), {"result": second_result})())
            assert not (mixed_dir / "nano-local-failfast.json").exists()
            print(json.dumps({
                "cancel": True,
                "recover": True,
                "finalized": 3,
                "stopped": 3,
                "provider_events": provider_events,
                "receipt": receipt["status"],
                "terminal": terminal["artifact_state"],
            }, sort_keys=True))


        asyncio.run(main(Path(sys.argv[1]).resolve()))
        """
    )
    completed = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--mount",
            f"type=bind,src={repository},dst=/workspace,readonly",
            "--mount",
            f"type=bind,src={tmp_path},dst=/out",
            "--env",
            "PYTHONPATH=/workspace/src",
            "--entrypoint",
            "/opt/harbor/.venv/bin/python",
            image,
            "-c",
            script,
            "/out/controller-integration",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert completed.returncode == 0, completed.stderr
    outcome = json.loads(completed.stdout.strip().splitlines()[-1])
    assert outcome == {
        "cancel": True,
        "finalized": 3,
        "provider_events": 0,
        "receipt": "triggered",
        "recover": True,
        "stopped": 3,
        "terminal": "complete",
    }
