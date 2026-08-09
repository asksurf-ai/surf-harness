"""Independent black-box acceptance fixtures for the TB2.1 P0/P1 gate.

These tests intentionally use only public adapter/collector entry points.  They
encode cross-layer invariants from the P0/P1 specification rather than
reaching into the implementation helpers owned by Tracks A, B, or C.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import shlex
import shutil
import tarfile
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from nano_grok_build.adapter.artifactizer import (
    BACKGROUND_MANIFEST_SCHEMA,
    ArtifactError,
    publish_artifacts,
    rust_run_spec_sha256,
)
from nano_grok_build.adapter.stdio_bridge import (
    BACKGROUND_START_PROOF_VERSION,
    LIVE_SCHEMA_VERSION,
    REMOTE_ENVIRONMENT_ALLOWLIST,
    BackgroundStartKind,
    BackgroundStartObservation,
    ProcessDisposition,
    TerminalActorOriginV1,
    TerminalActorPhaseV1,
    TerminalActorReceiptV1,
    TerminalActorSubtypeV1,
    ToolExecution,
    ToolFailure,
    ToolRequest,
    encode_tool_response,
    parse_tool_request,
)
from nano_grok_build.adapter.workspace_snapshot import (
    FAILURE_RECEIPT_SCHEMA_V4,
    SnapshotPolicy,
    SnapshotTarget,
    WorkspaceBaselineStateV1,
    capture_after,
    capture_before,
    workspace_failure_disposition,
)
from nano_grok_build.harbor import tb21

FIXTURES = Path(__file__).parent / "fixtures" / "p0p1"
TERMINAL_FIXTURES = json.loads((FIXTURES / "terminal-phase-cases.json").read_bytes())[
    "cases"
]
TOOL_FIXTURES = json.loads((FIXTURES / "tool-boundary-cases.json").read_bytes())[
    "cases"
]
CLASSIFIER_FIXTURES = json.loads(
    (FIXTURES / "collector-classification-cases.json").read_bytes()
)["cases"]
WORKSPACE_FIXTURE = json.loads((FIXTURES / "workspace-cases.json").read_bytes())


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def run_spec(logs_dir: Path, name: str) -> dict[str, Any]:
    return {
        "schema_version": "nano-run-spec-alpha-1",
        "run_id": f"run-{name}",
        "trial_id": f"{name}__trial",
        "attempt_id": "attempt-0",
        "task": {
            "id": f"terminal-bench/{name}",
            "digest": hashlib.sha256(name.encode()).hexdigest(),
            "instruction": f"Solve the synthetic {name} fixture.",
        },
        "contract": {
            "id": "synthetic-v2",
            "contract_set_sha256": "b" * 64,
            "profile_id": "synthetic-profile-v2",
        },
        "provider": {
            "kind": "xai",
            "model": "grok-4.5",
            "max_turns": 64,
            "retry_max": 0,
        },
        "workspace_dir": "/workspace",
        "artifact_dir": str((logs_dir / "runtime").resolve()),
        "agent_timeout_sec": 60,
        "active_tools": list(tb21.ACTIVE_TOOLS),
    }


def event(
    spec: dict[str, Any],
    sequence: int,
    event_type: str,
    data: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": "event-v2",
        "run_id": spec["run_id"],
        "trial_id": spec["trial_id"],
        "attempt_id": spec["attempt_id"],
        "seq": sequence,
        "elapsed_ms": sequence * 10,
        "type": event_type,
        "data": data,
    }


def provider_requested(turn: int) -> tuple[str, dict[str, Any]]:
    return (
        "provider.requested",
        {
            "turn_index": turn,
            "history_item_count": 2 + turn,
            "tool_count": len(tb21.ACTIVE_TOOLS),
            "function_output_call_ids": [],
        },
    )


def provider_completed(
    turn: int, *, call_ids: list[str], usage: dict[str, Any] | None
) -> tuple[str, dict[str, Any]]:
    return (
        "provider.completed",
        {
            "turn_index": turn,
            "response_id": f"response-{turn}",
            "model": "grok-4.5",
            "call_ids": call_ids,
            "has_final_text": False,
            "usage": usage,
        },
    )


OBSERVED_USAGE = {
    "input_tokens": 11,
    "input_tokens_details": {"cached_tokens": 7},
    "output_tokens": 3,
    "cost_in_usd_ticks": 123_000_000,
}
OBSERVED_TOTALS = {
    "input_tokens": 11,
    "cached_input_tokens": 7,
    "output_tokens": 3,
    "provider_cost_ticks": 123_000_000,
}
ABSENT_TOTALS = {
    "input_tokens": None,
    "cached_input_tokens": None,
    "output_tokens": None,
    "provider_cost_ticks": None,
}


def failure_bodies(
    spec: dict[str, Any], scenario: dict[str, Any]
) -> tuple[list[tuple[str, dict[str, Any]]], dict[str, Any], dict[str, Any], int]:
    bodies: list[tuple[str, dict[str, Any]]] = [
        (
            "run.started",
            {
                "task_id": spec["task"]["id"],
                "contract_id": spec["contract"]["id"],
                "profile_id": spec["contract"]["profile_id"],
                "contract_set_sha256": spec["contract"]["contract_set_sha256"],
                "model": spec["provider"]["model"],
                "run_spec_sha256": rust_run_spec_sha256(spec),
            },
        )
    ]
    shape = scenario["shape"]
    tool_count = 0
    if shape == "provider_failed":
        bodies.extend(
            [
                provider_requested(0),
                (
                    "provider.failed",
                    {"turn_index": 0, "code": scenario["code"]},
                ),
            ]
        )
        coverage = {
            "requested": 1,
            "completed": 0,
            "failed": 1,
            "in_flight": 0,
            "usage_present": 0,
            "usage_absent": 0,
            "usage_covered": 0,
            "cost_present": 0,
            "cost_absent": 0,
            "state": "partial",
        }
        totals = dict(ABSENT_TOTALS)
    elif shape == "provider_in_flight":
        bodies.extend(
            [
                provider_requested(0),
                provider_completed(0, call_ids=[], usage=OBSERVED_USAGE),
                provider_requested(1),
            ]
        )
        coverage = {
            "requested": 2,
            "completed": 1,
            "failed": 0,
            "in_flight": 1,
            "usage_present": 1,
            "usage_absent": 0,
            "usage_covered": 1,
            "cost_present": 1,
            "cost_absent": 0,
            "state": "partial",
        }
        totals = dict(OBSERVED_TOTALS)
    elif shape in {"fatal_tool", "in_flight_tool"}:
        call_id = "call-1"
        bodies.extend(
            [
                provider_requested(0),
                provider_completed(0, call_ids=[call_id], usage=OBSERVED_USAGE),
                (
                    "tool.registered",
                    {
                        "call_id": call_id,
                        "provider_name": "run_terminal_command",
                        "known": True,
                        "arguments_json": '{"command":"sleep 60"}',
                    },
                ),
                (
                    "tool.dispatched",
                    {
                        "call_id": call_id,
                        "provider_name": "run_terminal_command",
                    },
                ),
            ]
        )
        if shape == "fatal_tool":
            bodies.append(
                (
                    "tool.failed",
                    {
                        "call_id": call_id,
                        "provider_name": "run_terminal_command",
                        "code": scenario["code"],
                        "execution_may_have_started": True,
                        "cleanup_verified": False,
                        "census_verified": False,
                        "recoverability": "fatal",
                    },
                )
            )
        coverage = {
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
        }
        totals = dict(OBSERVED_TOTALS)
        tool_count = 1
    else:
        assert shape == "no_calls"
        coverage = {
            "requested": 0,
            "completed": 0,
            "failed": 0,
            "in_flight": 0,
            "usage_present": 0,
            "usage_absent": 0,
            "usage_covered": 0,
            "cost_present": 0,
            "cost_absent": 0,
            "state": "complete",
        }
        totals = dict(ABSENT_TOTALS)
    bodies.append(("run.failed", {"code": scenario["code"]}))
    return bodies, coverage, totals, tool_count


def write_failure_runtime(
    logs_dir: Path, spec: dict[str, Any], scenario: dict[str, Any]
) -> tuple[bytes, dict[str, Any]]:
    runtime_dir = logs_dir / "runtime"
    runtime_dir.mkdir(parents=True)
    bodies, coverage, totals, tool_count = failure_bodies(spec, scenario)
    events = [
        event(spec, sequence, event_type, data)
        for sequence, (event_type, data) in enumerate(bodies)
    ]
    event_bytes = b"".join(canonical_json(row) for row in events)
    (runtime_dir / "events.jsonl").write_bytes(event_bytes)
    record = {
        "schema_version": "nano-run-record-v2",
        "run_id": spec["run_id"],
        "trial_id": spec["trial_id"],
        "attempt_id": spec["attempt_id"],
        "run_spec_sha256": rust_run_spec_sha256(spec),
        "contract_id": spec["contract"]["id"],
        "contract_set_sha256": spec["contract"]["contract_set_sha256"],
        "profile_id": spec["contract"]["profile_id"],
        "terminal_status": scenario["status"],
        "terminal_phase": scenario["phase"],
        "terminal_code": scenario["code"],
        "final_event_seq": len(events) - 1,
        "provider_turn_count": coverage["requested"],
        "tool_call_count": tool_count,
        "provider_call_coverage": coverage,
        "usage_totals": totals,
        "start_elapsed_ms": 0,
        "end_elapsed_ms": (len(events) - 1) * 10,
        "events_sha256": sha256(event_bytes),
    }
    (runtime_dir / "run.json").write_bytes(canonical_json(record))
    return event_bytes, record


@dataclass
class LocalSnapshotActor:
    workspace: Path
    artifacts: Path
    fail_phase: str | None = None


async def capture_workspace(logs_dir: Path, workspace: Path) -> bytes:
    workspace.mkdir()
    actor = LocalSnapshotActor(workspace=workspace, artifacts=logs_dir)
    before = await capture_before(actor, SnapshotPolicy())
    (workspace / "answer.txt").write_text("synthetic answer\n", encoding="utf-8")
    receipt = await capture_after(actor, before)
    assert receipt.status == "complete"
    return (logs_dir / "workspace-receipt.json").read_bytes()


def test_near_cap_snapshot_publishes_through_private_control_and_replays(
    tmp_path: Path,
) -> None:
    from nano_grok_build.adapter.artifact_limits import (
        DEFAULT_PUBLICATION_FILE_MAX_BYTES,
        WORKSPACE_CHANGED_TAR_MAX_BYTES,
    )
    from nano_grok_build.adapter.control_plane import ControlPlane

    trial = tmp_path / "trial"
    public = trial / "agent"
    public.mkdir(parents=True)
    private = trial / ".nano-control-v2"
    spec = run_spec(private, "archive-boundary")
    plane = ControlPlane.create(
        public,
        run_spec_sha256=rust_run_spec_sha256(spec),
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    actor = LocalSnapshotActor(workspace=workspace, artifacts=plane.root)
    before = asyncio.run(capture_before(actor, SnapshotPolicy()))
    for index in range(8):
        with (workspace / f"chunk-{index}.bin").open("wb") as handle:
            handle.truncate(8 * 1024 * 1024)
    workspace_receipt = asyncio.run(capture_after(actor, before))
    archive = plane.root / "workspace-changed.tar"
    archive_bytes = archive.read_bytes()
    assert len(archive_bytes) > DEFAULT_PUBLICATION_FILE_MAX_BYTES
    assert len(archive_bytes) <= WORKSPACE_CHANGED_TAR_MAX_BYTES
    assert workspace_receipt.artifact_byte_lengths[archive.name] == len(archive_bytes)
    assert workspace_receipt.artifact_hashes[archive.name] == sha256(archive_bytes)

    scenario = TERMINAL_FIXTURES[0]
    write_failure_runtime(plane.root, spec, scenario)
    write_background_manifest(plane.root, spec)
    first = publish_artifacts(
        logs_dir=plane.root,
        publication_dir=public,
        run_spec=spec,
        instruction=spec["task"]["instruction"],
        agent_name="nano-grok-build",
        agent_version="acceptance",
        model_name=str(spec["provider"]["model"]),
        require_harbor_validator=False,
        require_background_manifest=True,
    )
    second = publish_artifacts(
        logs_dir=plane.root,
        publication_dir=public,
        run_spec=spec,
        instruction=spec["task"]["instruction"],
        agent_name="nano-grok-build",
        agent_version="acceptance",
        model_name=str(spec["provider"]["model"]),
        require_harbor_validator=False,
        require_background_manifest=True,
    )

    assert second.marker_bytes == first.marker_bytes
    assert (public / archive.name).read_bytes() == archive_bytes
    assert (
        first.marker_path.stat().st_mtime_ns
        >= (public / archive.name).stat().st_mtime_ns
    )
    plane.cleanup()
    assert not private.exists()
    assert first.marker_path.is_file()


def write_background_manifest(logs_dir: Path, spec: dict[str, Any]) -> bytes:
    payload = canonical_json(
        {
            "schema_version": BACKGROUND_MANIFEST_SCHEMA,
            "run_id": spec["run_id"],
            "trial_id": spec["trial_id"],
            "attempt_id": spec["attempt_id"],
            "run_spec_sha256": rust_run_spec_sha256(spec),
            "tasks": [],
        }
    )
    (logs_dir / "runtime-background-manifest.json").write_bytes(payload)
    return payload


def write_dispatch(job_dir: Path, specs: list[dict[str, Any]]) -> None:
    manifest = {
        "schema_version": "nano-harbor-dispatch-v1",
        "harbor_version": "0.20.0",
        "job_id": "synthetic-p0p1-job",
        "retry_max": 0,
        "n_attempts": 1,
        "run_specs": specs,
    }
    (job_dir / "nano-dispatch.json").write_bytes(
        canonical_json(
            {
                "manifest": manifest,
                "manifest_sha256": sha256(canonical_json(manifest)),
            }
        )
    )


def write_trial_result(
    trial_dir: Path,
    spec: dict[str, Any],
    *,
    reward: float | None,
    exception: dict[str, Any] | None,
) -> None:
    verifier_result = {"rewards": {"reward": reward}} if reward is not None else None
    (trial_dir / "result.json").write_bytes(
        canonical_json(
            {
                "task_name": spec["task"]["id"],
                "trial_name": spec["trial_id"],
                "task_checksum": spec["task"]["digest"],
                "verifier_result": verifier_result,
                "exception_info": exception,
                "started_at": "2026-07-24T00:00:00Z",
                "finished_at": "2026-07-24T00:00:01Z",
            }
        )
    )


def mark_job_terminal(job_dir: Path) -> None:
    (job_dir / "result.json").write_bytes(
        canonical_json(
            {
                "finished_at": "2026-07-24T00:00:01Z",
                "stats": {"n_retries": 0},
            }
        )
    )


def make_v2_failure_job(
    tmp_path: Path, scenario: dict[str, Any]
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    job_dir = tmp_path / "job"
    trial_dir = job_dir / f"{scenario['name']}__trial"
    logs_dir = trial_dir / "agent"
    logs_dir.mkdir(parents=True)
    spec = run_spec(logs_dir, str(scenario["name"]))
    write_dispatch(job_dir, [spec])
    _event_bytes, record = write_failure_runtime(logs_dir, spec, scenario)
    asyncio.run(capture_workspace(logs_dir, tmp_path / "workspace"))
    write_background_manifest(logs_dir, spec)
    publish_artifacts(
        logs_dir=logs_dir,
        run_spec=spec,
        instruction=spec["task"]["instruction"],
        agent_name="nano-grok-build",
        agent_version="acceptance",
        model_name=str(spec["provider"]["model"]),
        require_harbor_validator=False,
        require_background_manifest=True,
    )
    write_trial_result(
        trial_dir,
        spec,
        reward=None,
        exception={
            "exception_type": "NanoRunFailure",
            "exception_message": scenario["code"],
        },
    )
    mark_job_terminal(job_dir)
    return job_dir, spec, record


@pytest.mark.parametrize(
    "scenario",
    TERMINAL_FIXTURES,
    ids=[str(case["name"]) for case in TERMINAL_FIXTURES],
)
def test_all_controlled_failures_publish_one_truthful_terminal_package(
    tmp_path: Path, scenario: dict[str, Any]
) -> None:
    logs_dir = tmp_path / "agent"
    logs_dir.mkdir()
    spec = run_spec(logs_dir, str(scenario["name"]))
    event_bytes, record = write_failure_runtime(logs_dir, spec, scenario)
    workspace_receipt = asyncio.run(capture_workspace(logs_dir, tmp_path / "workspace"))
    background_manifest = write_background_manifest(logs_dir, spec)

    publication = publish_artifacts(
        logs_dir=logs_dir,
        run_spec=spec,
        instruction=spec["task"]["instruction"],
        agent_name="nano-grok-build",
        agent_version="acceptance",
        model_name=str(spec["provider"]["model"]),
        require_harbor_validator=False,
        require_background_manifest=True,
    )

    events = [json.loads(line) for line in event_bytes.splitlines()]
    terminal_events = [
        row for row in events if row["type"] in {"run.completed", "run.failed"}
    ]
    assert len(terminal_events) == 1
    assert terminal_events[0] == events[-1]
    assert terminal_events[0]["type"] == "run.failed"
    assert not any(row["type"] == "tool.completed" for row in events)
    assert list(logs_dir.glob("agent-run.json")) == [logs_dir / "agent-run.json"]

    trajectory_bytes = publication.trajectory_path.read_bytes()
    trajectory = json.loads(trajectory_bytes)
    diagnostic_path = logs_dir / "partial-trajectory.json"
    partial_bytes = diagnostic_path.read_bytes()
    partial = json.loads(partial_bytes)
    assert publication.publication_kind == "failure_atif"
    assert publication.success_artifact_valid is False
    assert publication.diagnostic_package_valid is True
    assert publication.trajectory_path.name == "trajectory.json"
    assert trajectory["schema_version"] == "ATIF-v1.7"
    assert trajectory["extra"]["terminal_failure"] == {
        "status": scenario["status"],
        "phase": scenario["phase"],
        "code": scenario["code"],
        "event_seq": len(events) - 1,
        "elapsed_ms": (len(events) - 1) * 10,
    }
    assert partial["assistant_final"] is None
    assert partial["terminal_failure"] == {
        "status": scenario["status"],
        "phase": scenario["phase"],
        "code": scenario["code"],
        "event_seq": len(events) - 1,
        "elapsed_ms": (len(events) - 1) * 10,
    }
    for call in partial["tool_calls"]:
        if call["state"] != "completed":
            assert "observation" not in call
    if scenario["shape"] == "fatal_tool":
        assert partial["tool_calls"][0]["state"] == "failed"
        assert partial["tool_calls"][0]["failure"]["code"] == scenario["code"]
    if scenario["shape"] == "in_flight_tool":
        assert partial["tool_calls"][0]["state"] == "in_flight"

    usage_bytes = (logs_dir / "runtime-usage-receipt.json").read_bytes()
    usage = json.loads(usage_bytes)
    assert usage["provider_call_coverage"] == record["provider_call_coverage"]
    assert usage["usage_totals"] == record["usage_totals"]
    marker = json.loads(publication.marker_bytes)
    assert marker["schema_version"] == "nano-agent-run-v4"
    assert "deadline_receipt_sha256" not in record
    assert "deadline_receipt_sha256" not in marker
    assert marker["publication_kind"] == "failure_atif"
    assert marker["events_sha256"] == sha256(event_bytes)
    assert marker["trajectory_path"] == "trajectory.json"
    assert marker["trajectory_sha256"] == sha256(trajectory_bytes)
    assert marker["diagnostic_path"] == "partial-trajectory.json"
    assert marker["diagnostic_sha256"] == sha256(partial_bytes)
    assert marker["usage_receipt_sha256"] == sha256(usage_bytes)
    assert marker["workspace_receipt_sha256"] == sha256(workspace_receipt)
    assert marker["background_manifest_sha256"] == sha256(background_manifest)

    receipt = json.loads(workspace_receipt)
    for name, artifact in receipt["artifacts"].items():
        payload = (logs_dir / name).read_bytes()
        assert artifact == {"byte_length": len(payload), "sha256": sha256(payload)}

    before = {
        path.name: path.read_bytes() for path in logs_dir.iterdir() if path.is_file()
    }
    second = publish_artifacts(
        logs_dir=logs_dir,
        run_spec=spec,
        instruction=spec["task"]["instruction"],
        agent_name="nano-grok-build",
        agent_version="acceptance",
        model_name=str(spec["provider"]["model"]),
        require_harbor_validator=False,
        require_background_manifest=True,
    )
    after = {
        path.name: path.read_bytes() for path in logs_dir.iterdir() if path.is_file()
    }
    assert after == before
    assert second.marker_bytes == publication.marker_bytes


@pytest.mark.parametrize(
    "scenario",
    TERMINAL_FIXTURES,
    ids=[str(case["name"]) for case in TERMINAL_FIXTURES],
)
def test_collector_accepts_failure_diagnostics_and_preserves_typed_truth(
    tmp_path: Path, scenario: dict[str, Any]
) -> None:
    job_dir, _spec, record = make_v2_failure_job(tmp_path, scenario)

    tb21.collect_job(job_dir)
    row = json.loads((job_dir / "rows.jsonl").read_bytes())

    assert row["runtime_terminal_status"] == scenario["status"]
    assert row["runtime_terminal_phase"] == scenario["phase"]
    assert row["runtime_terminal_code"] == scenario["code"]
    assert row["diagnostic_package_valid"] is True
    assert row["success_artifact_valid"] is False
    assert row["failure_bucket"] == scenario["expected_bucket"]
    assert row["failure_bucket"] not in {"agent_semantic", "semantic"}
    if scenario["phase"] != "artifact":
        assert row["failure_bucket"] != "artifact"
    coverage = record["provider_call_coverage"]
    assert row["provider_calls_requested"] == coverage["requested"]
    assert row["provider_calls_completed"] == coverage["completed"]
    assert row["provider_calls_failed"] == coverage["failed"]
    assert row["provider_calls_in_flight"] == coverage["in_flight"]
    assert row["provider_calls_usage_covered"] == coverage["usage_covered"]
    assert row["usage_state"] == coverage["state"]
    if scenario["shape"] == "provider_in_flight":
        assert row["provider_cost_usd_observed"] == pytest.approx(0.0123)
        assert row["cost_usd"] is None
        assert row["cost_coverage"] is False


def test_provider_inflight_usage_is_reported_as_an_observed_lower_bound(
    tmp_path: Path,
) -> None:
    scenario = next(
        case for case in TERMINAL_FIXTURES if case["shape"] == "provider_in_flight"
    )
    job_dir, _spec, _record = make_v2_failure_job(tmp_path, scenario)

    summary = tb21.collect_job(job_dir)
    row = json.loads((job_dir / "rows.jsonl").read_bytes())

    assert row["usage_state"] == "partial"
    assert row["provider_calls_requested"] == 2
    assert row["provider_calls_completed"] == 1
    assert row["provider_calls_failed"] == 0
    assert row["provider_calls_in_flight"] == 1
    assert row["provider_calls_usage_covered"] == 1
    assert row["input_tokens"] == 11
    assert row["cache_tokens"] == 7
    assert row["output_tokens"] == 3
    assert row["provider_cost_ticks"] == 123_000_000
    assert row["provider_cost_usd_observed"] == pytest.approx(0.0123)
    assert row["cost_usd"] is None
    assert row["cost_coverage"] is False
    assert summary["cost_usd"]["observed_lower_bound"] == pytest.approx(0.0123)
    assert summary["cost_usd"]["is_lower_bound"] is True
    assert summary["terminal_evidence"]["runtime_entry_states"]["started"] == 1
    assert summary["terminal_evidence"]["terminalized_started"] == 1
    assert summary["terminal_evidence"]["valid_usage_receipts_for_started"] == 1


def tool_request(tool_name: str, *, background: bool) -> bytes:
    if tool_name == "get_terminal_command_output":
        arguments: dict[str, Any] = {
            "task_ids": ["018f22d6-9f04-7cc0-8000-000000000001"],
            "timeout_ms": 1000,
        }
    else:
        arguments = {
            "command": "sleep 1",
            "description": "synthetic boundary",
            "timeout": 1000,
            "background": background,
        }
    value = {
        "schema_version": LIVE_SCHEMA_VERSION,
        "message_type": "tool.request",
        "seq": 0,
        "run_id": "run-tool-boundary",
        "trial_id": "trial-tool-boundary",
        "attempt_id": "attempt-0",
        "call_id": "call-tool-boundary",
        "tool_name": tool_name,
        "arguments_json": json.dumps(arguments, separators=(",", ":")),
        "logical_cwd": "/workspace",
        "operation_timeout_ms": 1000,
        "term_grace_ms": 100,
        "kill_confirmation_timeout_ms": 1000,
        "stdout_cap_bytes": 4096,
        "stderr_cap_bytes": 4096,
        "environment": {
            "clear": True,
            "inherit_remote": list(REMOTE_ENVIRONMENT_ALLOWLIST),
        },
        "limits": {
            "arguments_cap_bytes": 1024 * 1024,
            "max_path_bytes": 4096,
            "max_read_or_write_bytes": 4 * 1024 * 1024,
            "max_directory_entries": 10_000,
            "max_grep_matches": 10_000,
            "max_replacements": 10_000,
            "max_background_processes": 8,
            "process_spool_bytes_per_process": 16 * 1024 * 1024,
            "process_spool_bytes_per_run": 128 * 1024 * 1024,
            "background_output_wait_max_ms": 600_000,
        },
        "actor_done_monotonic_ns": 20_000_000_000,
        "tool_settled_monotonic_ns": 30_000_000_000,
        "last_send_monotonic_ns": 60_000_000_000,
        "runtime_final_monotonic_ns": 60_000_000_000,
        "cleanup_start_monotonic_ns": 75_000_000_000,
        "hard_deadline_monotonic_ns": 95_000_000_000,
        "cleanup_reserve_ms": 20_000,
        "terminalization_reserve_ms": 15_000,
        "provider_send_reserve_ms": 30_000,
        "process_settlement_reserve_ms": 10_000,
        "deadline_receipt_sha256": "d" * 64,
    }
    return json.dumps(value, separators=(",", ":")).encode()


def tool_fixture_actor_receipt(
    request: ToolRequest,
    scenario: dict[str, Any],
) -> TerminalActorReceiptV1 | None:
    if (
        request.tool_name != "run_terminal_command"
        or request.arguments.get("background", False) is True
    ):
        return None
    cutoff_ns = request.actor_done_monotonic_ns
    assert cutoff_ns is not None
    if scenario["expected_settlement"] == "completed":
        timed_out = bool(scenario["timed_out"])
        return TerminalActorReceiptV1.create(
            phase=TerminalActorPhaseV1.META_VALIDATE,
            origin=(
                TerminalActorOriginV1.SEMANTIC
                if timed_out
                else TerminalActorOriginV1.ACTOR
            ),
            primary_subtype=(
                TerminalActorSubtypeV1.SEMANTIC_EXECUTION_TIMED_OUT
                if timed_out
                else TerminalActorSubtypeV1.COMPLETED
            ),
            recovery_subtype=None,
            execution_may_have_started=True,
            effective_cutoff_monotonic_ns=cutoff_ns,
            cleanup_verified=bool(scenario["cleanup_verified"]),
            census_verified=bool(scenario["census_verified"]),
        )
    assert scenario["code"] == "terminal_actor_cleanup_unverified"
    return TerminalActorReceiptV1.create(
        phase=TerminalActorPhaseV1.CLEANUP,
        origin=TerminalActorOriginV1.ACTOR,
        primary_subtype=TerminalActorSubtypeV1.CLEANUP_UNVERIFIED,
        recovery_subtype=None,
        execution_may_have_started=bool(scenario["execution_may_have_started"]),
        effective_cutoff_monotonic_ns=cutoff_ns,
        cleanup_verified=scenario["cleanup_verified"],
        census_verified=scenario["census_verified"],
    )


@pytest.mark.parametrize(
    "scenario",
    TOOL_FIXTURES,
    ids=[str(case["name"]) for case in TOOL_FIXTURES],
)
def test_foreground_and_background_recoverable_fatal_boundary_is_typed(
    scenario: dict[str, Any],
) -> None:
    raw = tool_request(
        str(scenario["tool_name"]),
        background="background" in str(scenario["name"]),
    )
    request = parse_tool_request(raw, allow_legacy_v2=False)
    if scenario["expected_settlement"] == "fatal":
        result: ToolExecution | ToolFailure = ToolFailure(
            code=str(scenario["code"]),
            execution_may_have_started=bool(scenario["execution_may_have_started"]),
            cleanup_verified=scenario["cleanup_verified"],
            census_verified=scenario["census_verified"],
            actor_receipt=tool_fixture_actor_receipt(request, scenario),
        )
    else:
        output = (
            b"<status>status_unavailable</status>"
            if "status_unavailable" in str(scenario["name"])
            else b"synthetic partial output"
        )
        result = ToolExecution(
            return_code=int(scenario["return_code"]),
            timed_out=bool(scenario["timed_out"]),
            stdout=output,
            stderr=b"",
            stdout_truncated=False,
            stderr_truncated=False,
            cleanup_attempted=bool(scenario["cleanup_attempted"]),
            term_sent=bool(scenario["timed_out"]),
            kill_sent=False,
            cleanup_verified=bool(scenario["cleanup_verified"]),
            census_verified=bool(scenario["census_verified"]),
            survivor_count=int(scenario["survivor_count"]),
            process_disposition=ProcessDisposition(scenario["process_disposition"]),
            target_task_id=scenario["target_task_id"],
            background_start_observation=(
                None
                if scenario.get("background_start_kind") is None
                else BackgroundStartObservation(
                    proof_version=BACKGROUND_START_PROOF_VERSION,
                    kind=BackgroundStartKind(scenario["background_start_kind"]),
                    task_id_published=bool(scenario["task_id_published"]),
                    child_exit_code=scenario["child_exit_code"],
                )
            ),
            actor_receipt=tool_fixture_actor_receipt(request, scenario),
        )

    response = json.loads(encode_tool_response(request, result))

    assert response["settlement"] == scenario["expected_settlement"]
    assert response["request_sha256"] == sha256(raw)
    assert response["call_id"] == request.call_id
    if response["settlement"] == "fatal":
        assert "result" not in response
        assert response["failure"]["recoverability"] == "fatal"
        assert response["failure"]["cleanup_verified"] is scenario["cleanup_verified"]
        assert response["failure"]["census_verified"] is scenario["census_verified"]
    else:
        assert "failure" not in response
        encoded = response["result"]
        assert encoded["timed_out"] is scenario["timed_out"]
        assert encoded["process_disposition"] == scenario["process_disposition"]
        assert encoded["census"]["owned_processes_alive"] == scenario["survivor_count"]
        if scenario.get("background_start_kind") is not None:
            assert encoded["background_start_observation"] == {
                "proof_version": BACKGROUND_START_PROOF_VERSION,
                "kind": scenario["background_start_kind"],
                "task_id_published": scenario["task_id_published"],
                "child_exit_code": scenario["child_exit_code"],
            }


def test_workspace_success_is_hash_bound_and_sensitive_file_is_not_archived(
    tmp_path: Path,
) -> None:
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    artifacts.mkdir()
    workspace.mkdir()
    actor = LocalSnapshotActor(workspace=workspace, artifacts=artifacts)
    before = asyncio.run(capture_before(actor, SnapshotPolicy()))
    ordinary_content = WORKSPACE_FIXTURE["ordinary_content"].encode()
    sensitive_content = WORKSPACE_FIXTURE["sensitive_content"].encode()
    (workspace / WORKSPACE_FIXTURE["ordinary_path"]).write_bytes(ordinary_content)
    (workspace / WORKSPACE_FIXTURE["sensitive_path"]).write_bytes(sensitive_content)

    receipt = asyncio.run(capture_after(actor, before))

    assert receipt.status == "complete"
    receipt_bytes = (artifacts / "workspace-receipt.json").read_bytes()
    value = json.loads(receipt_bytes)
    assert receipt.canonical_sha256 == sha256(receipt_bytes)
    for name, metadata in value["artifacts"].items():
        payload = (artifacts / name).read_bytes()
        assert metadata == {"byte_length": len(payload), "sha256": sha256(payload)}
    delta_bytes = (artifacts / "workspace-delta.json").read_bytes()
    assert sensitive_content not in delta_bytes
    omission = next(
        row
        for row in json.loads(delta_bytes)["omitted"]
        if row["path"] == WORKSPACE_FIXTURE["sensitive_path"]
    )
    assert omission["reason"] == "sensitive_path"
    with tarfile.open(artifacts / "workspace-changed.tar", "r:") as archive:
        assert WORKSPACE_FIXTURE["ordinary_path"] in archive.getnames()
        assert WORKSPACE_FIXTURE["sensitive_path"] not in archive.getnames()
        extracted = archive.extractfile(WORKSPACE_FIXTURE["ordinary_path"])
        assert extracted is not None and extracted.read() == ordinary_content

    first = {
        path.name: path.read_bytes() for path in artifacts.iterdir() if path.is_file()
    }
    second = asyncio.run(capture_after(actor, before))
    assert second.canonical_sha256 == receipt.canonical_sha256
    assert {
        path.name: path.read_bytes() for path in artifacts.iterdir() if path.is_file()
    } == first


def test_workspace_failure_publishes_stable_receipt_without_payload(
    tmp_path: Path,
) -> None:
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    artifacts.mkdir()
    workspace.mkdir()
    actor = LocalSnapshotActor(workspace=workspace, artifacts=artifacts)
    before = asyncio.run(capture_before(actor, SnapshotPolicy()))
    actor.fail_phase = "after"

    receipt = asyncio.run(capture_after(actor, before))

    payload = (artifacts / "workspace-receipt.json").read_bytes()
    assert receipt.status == "failed"
    assert receipt.code == "workspace_after_capture_failed"
    assert json.loads(payload)["artifacts"] == {}
    assert b"Traceback" not in payload
    assert not (artifacts / "workspace-changed.tar").exists()


class BlockingSnapshotActor:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir()
        self.stage_count = 0
        self.capture_count = 0
        self.capture_started = asyncio.Event()
        self.stages: dict[str, Path] = {}

    def snapshot_workspace_root(self) -> str:
        return "/workspace"

    async def exec_snapshot(
        self, command: str, *, timeout_sec: float
    ) -> SimpleNamespace:
        assert timeout_sec > 0
        if command.startswith("rm -rf -- "):
            stage_name = shlex.split(command)[3]
            stage = self.stages.pop(stage_name)
            shutil.rmtree(stage)
            return SimpleNamespace(return_code=0, stdout="", stderr="")
        if "mktemp -d " in command and "inventory=" not in command:
            self.stage_count += 1
            stage_name = f"/tmp/nano-workspace-snapshot-v1.acceptance{self.stage_count}"
            stage = self.root / f"stage-{self.stage_count}"
            stage.mkdir()
            self.stages[stage_name] = stage
            return SimpleNamespace(
                return_code=0,
                stdout=f"{stage_name}\n",
                stderr="",
            )
        self.capture_count += 1
        if self.capture_count > 1:
            self.capture_started.set()
            await asyncio.Event().wait()
        assert len(self.stages) == 1
        stage = next(iter(self.stages.values()))
        (stage / "inventory.tsv").write_bytes(b"")
        with tarfile.open(stage / "safe.tar", "w:"):
            pass
        return SimpleNamespace(
            return_code=0,
            stdout="",
            stderr="",
        )

    async def exec_snapshot_owned(
        self,
        command: str,
        *,
        stage: str,
        timeout_sec: float,
    ) -> SimpleNamespace:
        assert stage in self.stages
        try:
            result = await self.exec_snapshot(command, timeout_sec=timeout_sec)
        except BaseException as error:
            error.termination_verified = True
            error.census_verified = True
            error.zero_census_verified = True
            error.survivor_count = 0
            raise
        return SimpleNamespace(
            return_code=result.return_code,
            stdout=result.stdout,
            stderr=result.stderr,
            termination_verified=True,
            census_verified=True,
            zero_census_verified=True,
            survivor_count=0,
        )

    async def download_snapshot(
        self, source_path: str, target_path: Path | str
    ) -> None:
        stage_name, name = source_path.rsplit("/", 1)
        shutil.copyfile(self.stages[stage_name] / name, target_path)


def test_workspace_cancel_publishes_failure_receipt_before_propagating(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        artifacts = tmp_path / "artifacts"
        artifacts.mkdir()
        actor = BlockingSnapshotActor(tmp_path / "remote")
        target = SnapshotTarget(actor=actor, artifact_dir=artifacts)
        before = await capture_before(target, SnapshotPolicy())
        task = asyncio.create_task(capture_after(target, before))
        await actor.capture_started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        receipt = json.loads((artifacts / "workspace-receipt.json").read_bytes())
        assert receipt["status"] == "failed"
        assert receipt["code"] == "workspace_after_capture_cancelled"
        assert receipt["artifacts"] == {}
        assert actor.stages == {}

    asyncio.run(scenario())


def write_v1_success(logs_dir: Path, spec: dict[str, Any], *, instruction: str) -> None:
    runtime_dir = logs_dir / "runtime"
    runtime_dir.mkdir(parents=True)
    bodies = [
        ("run.started", {}),
        ("assistant.final", {"text": "synthetic done"}),
        ("run.completed", {"code": "completed"}),
    ]
    events = b"".join(
        canonical_json(
            {
                "schema_version": "event-v1",
                "run_id": spec["run_id"],
                "trial_id": spec["trial_id"],
                "attempt_id": spec["attempt_id"],
                "seq": sequence,
                "elapsed_ms": sequence * 10,
                "type": event_type,
                "data": data,
            }
        )
        for sequence, (event_type, data) in enumerate(bodies)
    )
    (runtime_dir / "events.jsonl").write_bytes(events)
    (runtime_dir / "run.json").write_bytes(
        canonical_json(
            {
                "schema_version": "nano-run-record-alpha-1",
                "run_id": spec["run_id"],
                "trial_id": spec["trial_id"],
                "attempt_id": spec["attempt_id"],
                "run_spec_sha256": rust_run_spec_sha256(spec),
                "contract_id": spec["contract"]["id"],
                "contract_set_sha256": spec["contract"]["contract_set_sha256"],
                "profile_id": spec["contract"]["profile_id"],
                "terminal_status": "success",
                "terminal_code": "completed",
                "final_event_seq": 2,
                "provider_turn_count": 1,
                "tool_call_count": 0,
                "raw_usage": [
                    {
                        "input_tokens": 5,
                        "input_tokens_details": {"cached_tokens": 2},
                        "output_tokens": 1,
                    }
                ],
                "start_elapsed_ms": 0,
                "end_elapsed_ms": 20,
                "events_sha256": sha256(events),
            }
        )
    )
    write_background_manifest(logs_dir, spec)
    publish_artifacts(
        logs_dir=logs_dir,
        run_spec=spec,
        instruction=instruction,
        agent_name="nano-grok-build",
        agent_version="acceptance",
        model_name=str(spec["provider"]["model"]),
        require_harbor_validator=False,
        require_background_manifest=True,
    )


def make_v1_job(
    tmp_path: Path,
    name: str,
    *,
    reward: float = 1.0,
    verifier_output: str | None = None,
    terminal: bool = True,
) -> tuple[Path, dict[str, Any]]:
    job_dir = tmp_path / f"job-{name}"
    trial_dir = job_dir / f"{name}__trial"
    logs_dir = trial_dir / "agent"
    logs_dir.mkdir(parents=True)
    spec = run_spec(logs_dir, name)
    write_dispatch(job_dir, [spec])
    write_v1_success(logs_dir, spec, instruction=str(spec["task"]["instruction"]))
    write_trial_result(trial_dir, spec, reward=reward, exception=None)
    if verifier_output is not None:
        verifier_dir = trial_dir / "verifier"
        verifier_dir.mkdir()
        (verifier_dir / "test-stdout.txt").write_text(verifier_output, encoding="utf-8")
    if terminal:
        mark_job_terminal(job_dir)
    return job_dir, spec


@pytest.mark.parametrize(
    "scenario",
    CLASSIFIER_FIXTURES,
    ids=[str(case["name"]) for case in CLASSIFIER_FIXTURES],
)
def test_collector_separates_verifier_failures_from_agent_semantics(
    tmp_path: Path, scenario: dict[str, Any]
) -> None:
    job_dir, _spec = make_v1_job(
        tmp_path,
        str(scenario["name"]),
        reward=float(scenario["reward"]),
        verifier_output=str(scenario["verifier_output"]),
    )

    tb21.collect_job(job_dir)
    row = json.loads((job_dir / "rows.jsonl").read_bytes())

    assert row["failure_bucket"] == scenario["expected_bucket"]
    assert (
        row["verifier_result_kind"]
        == {
            "dependency_download_504": "setup_failed",
            "browser_launch_failure": "setup_failed",
            "assertion_failure": "assertion_failed",
            "unknown_verifier_traceback": "completed_negative_unknown",
        }[scenario["name"]]
    )


def test_collect_before_job_terminal_is_rejected(tmp_path: Path) -> None:
    job_dir, _spec = make_v1_job(tmp_path, "not-terminal", terminal=False)

    with pytest.raises(tb21.TB21Error, match="job_not_terminal"):
        tb21.collect_job(job_dir)
    assert not (job_dir / "rows.jsonl").exists()
    assert not (job_dir / "summary.json").exists()


def test_collect_twice_is_byte_idempotent_and_v1_remains_collectible(
    tmp_path: Path,
) -> None:
    job_dir, _spec = make_v1_job(tmp_path, "legacy")

    first_summary = tb21.collect_job(job_dir)
    first_rows = (job_dir / "rows.jsonl").read_bytes()
    first_summary_bytes = (job_dir / "summary.json").read_bytes()
    second_summary = tb21.collect_job(job_dir)

    assert second_summary == first_summary
    assert (job_dir / "rows.jsonl").read_bytes() == first_rows
    assert (job_dir / "summary.json").read_bytes() == first_summary_bytes
    row = json.loads(first_rows)
    assert row["schema_version"] == "nano-tb21-row-v7"
    assert first_summary["schema_version"] == "nano-tb21-baseline-summary-v7"
    assert row["submission_integrity_blocking"] is False
    assert row["submission_integrity_blocking_count"] == 0
    assert row["submission_integrity_warning_count"] == 0
    assert first_summary["gates"]["submission_integrity_clean"] is False
    assert row["git_history_audit_state"] == "invalid"
    assert row["git_history_submission_blocking"] is True
    assert first_summary["gates"]["git_history_integrity_clean"] is False
    assert row["runtime_entry_state"] == "started"
    assert first_summary["terminal_evidence"]["valid_usage_receipts_for_started"] == 1
    assert row["runtime_terminal_status"] == "success"
    assert row["artifacts_valid"] is True
    assert row["usage_source"] == "run_record_v1"
    assert row["usage_state"] == "complete"


def test_artifact_publication_refuses_an_unterminated_event_prefix(
    tmp_path: Path,
) -> None:
    logs_dir = tmp_path / "agent"
    runtime_dir = logs_dir / "runtime"
    runtime_dir.mkdir(parents=True)
    spec = run_spec(logs_dir, "unterminated")
    prefix = canonical_json(
        event(
            spec,
            0,
            "run.started",
            {
                "task_id": spec["task"]["id"],
                "contract_id": spec["contract"]["id"],
                "profile_id": spec["contract"]["profile_id"],
                "contract_set_sha256": spec["contract"]["contract_set_sha256"],
                "model": spec["provider"]["model"],
                "run_spec_sha256": rust_run_spec_sha256(spec),
            },
        )
    )
    (runtime_dir / "events.jsonl").write_bytes(prefix)

    with pytest.raises(ArtifactError):
        publish_artifacts(
            logs_dir=logs_dir,
            run_spec=spec,
            instruction=str(spec["task"]["instruction"]),
            agent_name="nano-grok-build",
            agent_version="acceptance",
            model_name="synthetic-model",
            require_harbor_validator=False,
        )
    assert not (logs_dir / "agent-run.json").exists()
    assert not (logs_dir / "trajectory.json").exists()
    assert not (logs_dir / "partial-trajectory.json").exists()


def _load_harbor_adapter_for_workspace_acceptance(
    monkeypatch: pytest.MonkeyPatch,
):
    import importlib
    import sys
    from types import ModuleType

    for name in (
        "harbor",
        "harbor.agents",
        "harbor.agents.base",
        "harbor.environments",
        "harbor.environments.base",
        "harbor.models",
        "harbor.models.agent",
        "harbor.models.agent.context",
    ):
        module = ModuleType(name)
        if name.rsplit(".", 1)[-1] not in {"base", "context"}:
            module.__path__ = []
        monkeypatch.setitem(sys.modules, name, module)
    sys.modules["harbor.agents.base"].BaseAgent = object
    sys.modules["harbor.environments.base"].BaseEnvironment = object
    sys.modules["harbor.models.agent.context"].AgentContext = object
    monkeypatch.delitem(sys.modules, "nano_grok_build.adapter.harbor", raising=False)
    return importlib.import_module("nano_grok_build.adapter.harbor")


def test_workspace_receipt_single_truth_before_after_four_proof_matrix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nano_grok_build.adapter.workspace_snapshot as workspace_snapshot

    workspace = tmp_path / "workspace"
    logs = tmp_path / "agent"
    workspace.mkdir()
    logs.mkdir()
    policy = SnapshotPolicy().as_dict()

    class Actor:
        artifacts = logs

        def __init__(self) -> None:
            self.workspace = workspace

    actor = Actor()
    before = asyncio.run(capture_before(actor, SnapshotPolicy()))
    (workspace / "answer.txt").write_text("answer\n", encoding="utf-8")
    captured = asyncio.run(capture_after(actor, before))
    harbor_adapter = _load_harbor_adapter_for_workspace_acceptance(monkeypatch)
    harbor_agent = object.__new__(harbor_adapter.NanoGrokBuildAgent)
    harbor_agent.logs_dir = logs

    bound = harbor_agent._load_bound_workspace_receipt(captured)
    collected = tb21._workspace_receipt_evidence(
        logs,
        captured.canonical_sha256,
    )

    assert bound == captured
    assert bound is not captured
    assert collected.receipt_valid is True
    assert collected.snapshot_complete is True
    assert collected.status == "complete"

    matrix_logs = tmp_path / "failure-matrix"
    matrix_logs.mkdir()
    assert len(WORKSPACE_FIXTURE["failure_cases"]) == 10
    for case in WORKSPACE_FIXTURE["failure_cases"]:
        proofs = case["proofs"]
        receipt_value = {
            "schema_version": FAILURE_RECEIPT_SCHEMA_V4,
            "status": "failed",
            "code": case["code"],
            "baseline_state": case["baseline_state"],
            "policy": policy,
            "truncated": False,
            "omitted_count": 0,
            "artifacts": {},
            "failure": {
                "stage": case["stage"],
                "category": case["category"],
                "subtype": case["subtype"],
                "timeout_origin": case["timeout_origin"],
                "errno": None,
                "return_code": None,
                "attempt": 1,
                **proofs,
                "reason": case["reason"],
                "observed_byte_length": None,
                "observed_sha256": None,
            },
        }
        payload = canonical_json(receipt_value)
        case_logs = matrix_logs / case["id"]
        case_logs.mkdir()
        receipt_path = case_logs / "workspace-receipt.json"

        producer_projection = workspace_snapshot._write_workspace_receipt(
            receipt_path,
            payload,
        )
        persisted_projection = workspace_snapshot.load_workspace_receipt(receipt_path)
        harbor_agent.logs_dir = case_logs
        harbor_projection = harbor_agent._load_bound_workspace_receipt(
            producer_projection
        )
        collector_projection = tb21._workspace_receipt_evidence(
            case_logs,
            producer_projection.canonical_sha256,
        )
        disposition = workspace_failure_disposition(
            case["code"],
            case["stage"],
            case["category"],
            subtype=case["subtype"],
            timeout_origin=case["timeout_origin"],
            **proofs,
        )

        assert producer_projection == persisted_projection, case["id"]
        assert harbor_projection == producer_projection, case["id"]
        assert harbor_projection is not producer_projection, case["id"]
        assert producer_projection.baseline_state is WorkspaceBaselineStateV1(
            case["baseline_state"]
        ), case["id"]
        assert producer_projection.continuable is (
            case["disposition"] == "diagnostic_failed_continue"
        ), case["id"]
        assert disposition == case["disposition"], case["id"]
        assert collector_projection.receipt_valid is True, case["id"]
        assert collector_projection.status == "failed", case["id"]
        assert collector_projection.failure_stage == case["stage"], case["id"]
        assert collector_projection.failure_category == case["category"], case["id"]
        assert not (case_logs / "workspace-delta.json").exists(), case["id"]
