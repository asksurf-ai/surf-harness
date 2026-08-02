from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from nano_grok_build.adapter import artifactizer
from nano_grok_build.adapter.artifactizer import (
    BACKGROUND_FAILURE_MANIFEST_SCHEMA,
    BACKGROUND_MANIFEST_SCHEMA,
    ArtifactError,
    canonical_json,
    publish_artifacts,
    rust_run_spec_sha256,
    validate_background_manifest,
    validate_verifier_terminal_runtime,
)
from nano_grok_build.adapter.deadline import (
    RunDeadlineReceiptV1,
    RunDeadlineV1,
)

MEDIA_HISTORY_POLICY_SHA256 = (
    "b34dc9dd4f9d37c53e98fbf2fd3a3d816ba3e1071dd3e981161f23d16ffb6cd6"
)


def _tool_identity_sha256(call_id: str, provider_name: str) -> str:
    value = json.dumps(
        {"call_id": call_id, "provider_name": provider_name},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(value).hexdigest()


def _compact_tool_receipt() -> dict[str, object]:
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
        "tool_identity_sha256": _tool_identity_sha256("call-1", "run_terminal_command"),
        "tool_call_ordinal": 1,
    }


def _runtime_tool_receipt() -> dict[str, object]:
    previous = _compact_tool_receipt()
    return {
        key: value
        for key, value in previous.items()
        if key not in {"coverage", "owner", "source", "relation"}
    } | {"schema_version": "nano-tool-receipt-v1"}


def run_spec(logs_dir: Path) -> dict[str, object]:
    return {
        "schema_version": "nano-run-spec-alpha-1",
        "run_id": "run-1",
        "trial_id": "trial-1",
        "attempt_id": "attempt-0",
        "task": {
            "id": "synthetic-task",
            "digest": "a" * 64,
            "instruction": "Create the sentinel.",
        },
        "contract": {
            "id": "synthetic-v1",
            "contract_set_sha256": "b" * 64,
            "profile_id": "synthetic-profile-v1",
        },
        "provider": {
            "kind": "scripted",
            "model": "synthetic-model",
            "max_turns": 4,
            "retry_max": 0,
        },
        "workspace_dir": "/workspace",
        "artifact_dir": str((logs_dir / "runtime").resolve()),
        "agent_timeout_sec": 60,
    }


def write_committed_runtime(logs_dir: Path, spec: dict[str, object]) -> None:
    runtime = logs_dir / "runtime"
    runtime.mkdir(parents=True)
    common = {
        "schema_version": "event-v1",
        "run_id": "run-1",
        "trial_id": "trial-1",
        "attempt_id": "attempt-0",
        "elapsed_ms": 0,
    }
    bodies = [
        ("run.started", {}),
        (
            "tool.registered",
            {
                "call_id": "call-1",
                "provider_name": "run_terminal_command",
                "known": True,
                "arguments_json": (
                    '{"command":"printf proof","description":"synthetic"}'
                ),
            },
        ),
        (
            "tool.dispatched",
            {"call_id": "call-1", "provider_name": "run_terminal_command"},
        ),
        (
            "tool.completed",
            {
                "call_id": "call-1",
                "provider_name": "run_terminal_command",
                "execution_attempted": True,
                "outcome": "succeeded",
                "output": "proof\nexit: 0",
            },
        ),
        ("assistant.final", {"text": "finished"}),
        ("run.completed", {"code": "completed"}),
    ]
    event_bytes = b"".join(
        canonical_json({**common, "seq": seq, "type": event_type, "data": data})
        for seq, (event_type, data) in enumerate(bodies)
    )
    (runtime / "events.jsonl").write_bytes(event_bytes)
    record = {
        "schema_version": "nano-run-record-alpha-1",
        "run_id": "run-1",
        "trial_id": "trial-1",
        "attempt_id": "attempt-0",
        "run_spec_sha256": rust_run_spec_sha256(spec),
        "contract_id": "synthetic-v1",
        "contract_set_sha256": "b" * 64,
        "profile_id": "synthetic-profile-v1",
        "terminal_status": "success",
        "terminal_code": "completed",
        "final_event_seq": len(bodies) - 1,
        "provider_turn_count": 2,
        "tool_call_count": 1,
        "raw_usage": [None, None],
        "start_elapsed_ms": 0,
        "end_elapsed_ms": 0,
        "events_sha256": hashlib.sha256(event_bytes).hexdigest(),
    }
    (runtime / "run.json").write_bytes(canonical_json(record))


def write_failed_runtime_v2(logs_dir: Path, spec: dict[str, object]) -> None:
    runtime = logs_dir / "runtime"
    runtime.mkdir(parents=True)
    common = {
        "schema_version": "event-v2",
        "run_id": "run-1",
        "trial_id": "trial-1",
        "attempt_id": "attempt-0",
    }
    bodies = [
        (
            "run.started",
            {
                "task_id": "synthetic-task",
                "contract_id": "synthetic-v1",
                "profile_id": "synthetic-profile-v1",
                "contract_set_sha256": "b" * 64,
                "model": "synthetic-model",
                "run_spec_sha256": rust_run_spec_sha256(spec),
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
                "response_id": "response-1",
                "model": "synthetic-model",
                "call_ids": ["call-1"],
                "has_final_text": False,
                "usage": {
                    "input_tokens": 11,
                    "output_tokens": 3,
                    "input_tokens_details": {"cached_tokens": 7},
                },
            },
        ),
        (
            "tool.registered",
            {
                "call_id": "call-1",
                "provider_name": "run_terminal_command",
                "known": True,
                "arguments_json": '{"command":"sleep 60"}',
            },
        ),
        (
            "tool.dispatched",
            {
                "call_id": "call-1",
                "provider_name": "run_terminal_command",
            },
        ),
        (
            "tool.failed",
            {
                "call_id": "call-1",
                "provider_name": "run_terminal_command",
                "code": "terminal_actor_cleanup_unverified",
                "execution_may_have_started": True,
                "cleanup_verified": False,
                "census_verified": False,
                "recoverability": "fatal",
            },
        ),
        ("run.failed", {"code": "terminal_actor_cleanup_unverified"}),
    ]
    event_bytes = b"".join(
        canonical_json(
            {
                **common,
                "seq": seq,
                "elapsed_ms": seq,
                "type": event_type,
                "data": data,
            }
        )
        for seq, (event_type, data) in enumerate(bodies)
    )
    (runtime / "events.jsonl").write_bytes(event_bytes)
    record = {
        "schema_version": "nano-run-record-v2",
        "run_id": "run-1",
        "trial_id": "trial-1",
        "attempt_id": "attempt-0",
        "run_spec_sha256": rust_run_spec_sha256(spec),
        "contract_id": "synthetic-v1",
        "contract_set_sha256": "b" * 64,
        "profile_id": "synthetic-profile-v1",
        "terminal_status": "tool_failure",
        "terminal_phase": "bridge",
        "terminal_code": "terminal_actor_cleanup_unverified",
        "final_event_seq": len(bodies) - 1,
        "provider_turn_count": 1,
        "tool_call_count": 1,
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
            "input_tokens": 11,
            "cached_input_tokens": 7,
            "output_tokens": 3,
            "provider_cost_ticks": None,
        },
        "start_elapsed_ms": 0,
        "end_elapsed_ms": len(bodies) - 1,
        "events_sha256": hashlib.sha256(event_bytes).hexdigest(),
    }
    (runtime / "run.json").write_bytes(canonical_json(record))


def write_success_runtime_v2(logs_dir: Path, spec: dict[str, object]) -> None:
    runtime = logs_dir / "runtime"
    runtime.mkdir(parents=True)
    common = {
        "schema_version": "event-v2",
        "run_id": "run-1",
        "trial_id": "trial-1",
        "attempt_id": "attempt-0",
    }
    bodies = [
        (
            "run.started",
            {
                "task_id": "synthetic-task",
                "contract_id": "synthetic-v1",
                "profile_id": "synthetic-profile-v1",
                "contract_set_sha256": "b" * 64,
                "model": "synthetic-model",
                "run_spec_sha256": rust_run_spec_sha256(spec),
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
                "response_id": "response-1",
                "model": "synthetic-model",
                "call_ids": [],
                "has_final_text": True,
                "usage": {
                    "input_tokens": 13,
                    "output_tokens": 5,
                    "input_tokens_details": {"cached_tokens": 2},
                    "provider_cost_ticks": 17,
                },
            },
        ),
        ("assistant.final", {"text": "finished"}),
        ("run.completed", {"code": "completed"}),
    ]
    event_bytes = b"".join(
        canonical_json(
            {
                **common,
                "seq": seq,
                "elapsed_ms": seq,
                "type": event_type,
                "data": data,
            }
        )
        for seq, (event_type, data) in enumerate(bodies)
    )
    (runtime / "events.jsonl").write_bytes(event_bytes)
    record = {
        "schema_version": "nano-run-record-v2",
        "run_id": "run-1",
        "trial_id": "trial-1",
        "attempt_id": "attempt-0",
        "run_spec_sha256": rust_run_spec_sha256(spec),
        "contract_id": "synthetic-v1",
        "contract_set_sha256": "b" * 64,
        "profile_id": "synthetic-profile-v1",
        "terminal_status": "success",
        "terminal_phase": None,
        "terminal_code": "completed",
        "final_event_seq": len(bodies) - 1,
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
            "input_tokens": 13,
            "cached_input_tokens": 2,
            "output_tokens": 5,
            "provider_cost_ticks": 17,
        },
        "start_elapsed_ms": 0,
        "end_elapsed_ms": len(bodies) - 1,
        "events_sha256": hashlib.sha256(event_bytes).hexdigest(),
    }
    (runtime / "run.json").write_bytes(canonical_json(record))


def write_provider_deadline_runtime_v2(
    logs_dir: Path,
    spec: dict[str, object],
    *,
    terminal_status: str = "deadline_failure",
    terminal_phase: str = "deadline",
    terminal_code: str = "provider_final_deadline_exceeded",
) -> None:
    """Shape a rewarded-largest-eigenval-style failed runtime prefix."""

    write_success_runtime_v2(logs_dir, spec)
    runtime = logs_dir / "runtime"
    events = [
        json.loads(line)
        for line in (runtime / "events.jsonl").read_bytes().splitlines()
    ][:3]
    events[-1]["data"]["has_final_text"] = False
    common = {
        key: events[0][key]
        for key in ("schema_version", "run_id", "trial_id", "attempt_id")
    }
    events.extend(
        [
            {
                **common,
                "seq": 3,
                "elapsed_ms": 3,
                "type": "provider.requested",
                "data": {
                    "turn_index": 1,
                    "history_item_count": 4,
                    "tool_count": 8,
                    "function_output_call_ids": [],
                },
            },
            {
                **common,
                "seq": 4,
                "elapsed_ms": 4,
                "type": "run.failed",
                "data": {"code": terminal_code},
            },
        ]
    )
    event_bytes = b"".join(canonical_json(event) for event in events)
    (runtime / "events.jsonl").write_bytes(event_bytes)
    record = json.loads((runtime / "run.json").read_bytes())
    record.update(
        {
            "terminal_status": terminal_status,
            "terminal_phase": terminal_phase,
            "terminal_code": terminal_code,
            "final_event_seq": 4,
            "provider_turn_count": 2,
            "provider_call_coverage": {
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
            },
            "end_elapsed_ms": 4,
            "events_sha256": hashlib.sha256(event_bytes).hexdigest(),
        }
    )
    (runtime / "run.json").write_bytes(canonical_json(record))


def test_verifier_terminal_runtime_validator_is_read_only_and_bound(
    tmp_path: Path,
) -> None:
    logs = tmp_path / "logs"
    spec = run_spec(logs)
    write_failed_runtime_v2(logs, spec)
    before = {
        path.relative_to(logs): path.read_bytes()
        for path in logs.rglob("*")
        if path.is_file()
    }

    projection = validate_verifier_terminal_runtime(
        runtime_dir=logs / "runtime",
        run_spec=spec,
    )

    assert projection.schema_version == "nano-run-record-v2"
    assert projection.run_id == "run-1"
    assert projection.trial_id == "trial-1"
    assert projection.attempt_id == "attempt-0"
    assert projection.terminal_status == "tool_failure"
    assert projection.terminal_phase == "bridge"
    assert projection.terminal_code == "terminal_actor_cleanup_unverified"
    assert projection.run_spec_sha256 == rust_run_spec_sha256(spec)
    assert (
        projection.events_sha256
        == hashlib.sha256((logs / "runtime" / "events.jsonl").read_bytes()).hexdigest()
    )
    assert len(projection.run_record_sha256) == 64
    assert before == {
        path.relative_to(logs): path.read_bytes()
        for path in logs.rglob("*")
        if path.is_file()
    }
    assert not (logs / "agent-run.json").exists()


@pytest.mark.parametrize("runtime_kind", ["legacy", "success"])
def test_verifier_terminal_runtime_validator_rejects_non_failure_runtime(
    tmp_path: Path,
    runtime_kind: str,
) -> None:
    logs = tmp_path / runtime_kind
    spec = run_spec(logs)
    if runtime_kind == "legacy":
        write_committed_runtime(logs, spec)
    else:
        write_success_runtime_v2(logs, spec)

    with pytest.raises(ArtifactError, match="^verifier_terminal_runtime_ineligible$"):
        validate_verifier_terminal_runtime(
            runtime_dir=logs / "runtime",
            run_spec=spec,
        )


@pytest.mark.parametrize("attack", ["symlink", "post_open_swap"])
def test_verifier_terminal_runtime_reader_fails_closed_on_path_attack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
) -> None:
    import nano_grok_build.adapter.artifactizer as artifactizer

    logs = tmp_path / attack
    spec = run_spec(logs)
    write_failed_runtime_v2(logs, spec)
    run_path = logs / "runtime" / "run.json"
    original_path = logs / "runtime" / "run.original.json"
    malicious_path = logs / "runtime" / "run.malicious.json"
    malicious_path.write_bytes(run_path.read_bytes())

    if attack == "symlink":
        run_path.rename(original_path)
        run_path.symlink_to(malicious_path)
    else:
        real_open = artifactizer.os.open
        swapped = False

        def swap_after_open(path, flags, *args):
            nonlocal swapped
            descriptor = real_open(path, flags, *args)
            if not swapped and Path(path) == run_path:
                swapped = True
                run_path.rename(original_path)
                run_path.symlink_to(malicious_path)
            return descriptor

        monkeypatch.setattr(artifactizer.os, "open", swap_after_open)

    with pytest.raises(ArtifactError, match="^run_marker_missing_or_invalid$"):
        validate_verifier_terminal_runtime(
            runtime_dir=logs / "runtime",
            run_spec=spec,
        )
    assert not (logs / "agent-run.json").exists()


def bind_deadline_receipt(
    logs_dir: Path,
    spec: dict[str, object],
    *,
    receipt_run_id: str = "run-1",
    canonical: bool = True,
) -> tuple[bytes, str]:
    runtime = logs_dir / "runtime"
    receipt = RunDeadlineReceiptV1.bind(
        deadline=RunDeadlineV1.mint(
            source="test_host_phase",
            agent_timeout_ms=int(spec["agent_timeout_sec"]) * 1_000,
            now_monotonic_ns=1_000_000_000,
        ),
        run_id=receipt_run_id,
        trial_id=str(spec["trial_id"]),
        attempt_id=str(spec["attempt_id"]),
        run_spec_sha256=rust_run_spec_sha256(spec),
    )
    raw = receipt.to_bytes()
    if not canonical:
        raw = json.dumps(receipt.as_dict(), indent=2).encode("utf-8") + b"\n"
    digest = hashlib.sha256(raw).hexdigest()
    (runtime / "deadline.json").write_bytes(raw)

    events = [
        json.loads(line)
        for line in (runtime / "events.jsonl").read_bytes().splitlines()
    ]
    events[0]["data"]["deadline_receipt_sha256"] = digest
    event_bytes = b"".join(canonical_json(event) for event in events)
    (runtime / "events.jsonl").write_bytes(event_bytes)

    record = json.loads((runtime / "run.json").read_bytes())
    record["deadline_receipt_sha256"] = digest
    record["events_sha256"] = hashlib.sha256(event_bytes).hexdigest()
    (runtime / "run.json").write_bytes(canonical_json(record))
    return raw, digest


def upgrade_runtime_to_v3(logs_dir: Path) -> None:
    run_path = logs_dir / "runtime" / "run.json"
    record = json.loads(run_path.read_bytes())
    assert record.get("deadline_receipt_sha256") is not None
    record["schema_version"] = "nano-run-record-v3"
    run_path.write_bytes(canonical_json(record))


def bind_media_history_policy(
    logs_dir: Path,
    *,
    event_sha256: str = MEDIA_HISTORY_POLICY_SHA256,
) -> None:
    runtime = logs_dir / "runtime"
    events = [
        json.loads(line)
        for line in (runtime / "events.jsonl").read_bytes().splitlines()
    ]
    events[0]["data"]["media_history_policy_version"] = (
        "rolling-media-history-latest-suffix-v1"
    )
    events[0]["data"]["media_history_policy_sha256"] = event_sha256
    for event in events:
        if event["type"] == "provider.requested":
            event["data"]["media_history_receipt"] = {
                "history_sha256": "c" * 64,
                "retained_count": 0,
                "retained_bytes": 0,
                "evicted_total": 0,
            }
    event_bytes = b"".join(canonical_json(event) for event in events)
    (runtime / "events.jsonl").write_bytes(event_bytes)

    record = json.loads((runtime / "run.json").read_bytes())
    record["events_sha256"] = hashlib.sha256(event_bytes).hexdigest()
    (runtime / "run.json").write_bytes(canonical_json(record))


def test_marker_last_publication_is_byte_idempotent(tmp_path: Path) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    write_committed_runtime(logs, spec)
    first = publish_artifacts(
        logs_dir=logs,
        run_spec=spec,
        instruction="Create the sentinel.",
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
        require_harbor_validator=False,
    )
    trajectory_bytes = first.trajectory_path.read_bytes()
    marker_bytes = first.marker_path.read_bytes()
    second = publish_artifacts(
        logs_dir=logs,
        run_spec=spec,
        instruction="Create the sentinel.",
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
        require_harbor_validator=False,
    )
    assert second.trajectory_path.read_bytes() == trajectory_bytes
    assert second.marker_path.read_bytes() == marker_bytes
    marker = json.loads(marker_bytes)
    assert marker["trajectory_sha256"] == hashlib.sha256(trajectory_bytes).hexdigest()


def test_v2_success_keeps_atif_and_publishes_v2_usage_marker(tmp_path: Path) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    write_success_runtime_v2(logs, spec)

    publication = publish_artifacts(
        logs_dir=logs,
        run_spec=spec,
        instruction="Create the sentinel.",
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
        require_harbor_validator=False,
    )

    assert publication.publication_kind == "success_atif"
    assert publication.success_artifact_valid is True
    assert publication.diagnostic_package_valid is True
    assert publication.trajectory["schema_version"] == "ATIF-v1.7"
    assert publication.context == {
        "n_input_tokens": 13,
        "n_cache_tokens": 2,
        "n_output_tokens": 5,
    }
    marker = json.loads(publication.marker_bytes)
    assert marker["schema_version"] == "nano-agent-run-v2"
    assert marker["publication_kind"] == "success_atif"
    assert marker["terminal_phase"] is None
    assert marker["trajectory_path"] == "trajectory.json"
    assert (
        marker["usage_receipt_sha256"]
        == hashlib.sha256(
            (logs / "runtime-usage-receipt.json").read_bytes()
        ).hexdigest()
    )
    assert not (logs / "partial-trajectory.json").exists()


def test_success_publication_exposes_pinned_atif_eligibility_and_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    write_success_runtime_v2(logs, spec)
    validated: list[object] = []
    monkeypatch.setattr(
        artifactizer,
        "validate_with_pinned_harbor",
        lambda trajectory: validated.append(trajectory),
    )

    publication = publish_artifacts(
        logs_dir=logs,
        run_spec=spec,
        instruction="Create the sentinel.",
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
        require_harbor_validator=True,
    )

    trajectory_bytes = publication.trajectory_path.read_bytes()
    trajectory_sha256 = hashlib.sha256(trajectory_bytes).hexdigest()
    marker = json.loads(publication.marker_bytes)
    assert validated == [publication.trajectory]
    assert publication.atif_eligibility.leaderboard_eligible is True
    assert publication.atif_eligibility.conformance == "pinned_harbor_valid"
    assert publication.atif_eligibility.trajectory_path == "trajectory.json"
    assert publication.atif_eligibility.trajectory_sha256 == trajectory_sha256
    assert publication.atif_eligibility.ineligibility_reason is None
    assert marker["publication_kind"] == "success_atif"
    assert marker["trajectory_path"] == publication.atif_eligibility.trajectory_path
    assert marker["trajectory_sha256"] == trajectory_sha256


def test_unvalidated_success_is_explicitly_not_leaderboard_eligible(
    tmp_path: Path,
) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    write_success_runtime_v2(logs, spec)

    publication = publish_artifacts(
        logs_dir=logs,
        run_spec=spec,
        instruction="Create the sentinel.",
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
        require_harbor_validator=False,
    )

    assert publication.success_artifact_valid is True
    assert publication.atif_eligibility.leaderboard_eligible is False
    assert publication.atif_eligibility.conformance == "minimal_atif_only"
    assert publication.atif_eligibility.trajectory_path is None
    assert publication.atif_eligibility.trajectory_sha256 is None
    assert (
        publication.atif_eligibility.ineligibility_reason
        == "pinned_harbor_validation_not_requested"
    )


def test_compact_tool_receipt_is_accepted_without_entering_partial_trajectory(
    tmp_path: Path,
) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    write_failed_runtime_v2(logs, spec)
    runtime = logs / "runtime"
    events_path = runtime / "events.jsonl"
    events = [json.loads(line) for line in events_path.read_bytes().splitlines()]
    terminal = events.pop()
    events.append(
        {
            **{
                key: terminal[key]
                for key in (
                    "schema_version",
                    "run_id",
                    "trial_id",
                    "attempt_id",
                )
            },
            "seq": len(events),
            "elapsed_ms": len(events),
            "type": "tool.receipt",
            "data": _compact_tool_receipt(),
        }
    )
    terminal["seq"] = len(events)
    terminal["elapsed_ms"] = len(events)
    events.append(terminal)
    event_bytes = b"".join(canonical_json(event) for event in events)
    events_path.write_bytes(event_bytes)
    run_path = runtime / "run.json"
    record = json.loads(run_path.read_bytes())
    record["final_event_seq"] = len(events) - 1
    record["end_elapsed_ms"] = len(events) - 1
    record["events_sha256"] = hashlib.sha256(event_bytes).hexdigest()
    run_path.write_bytes(canonical_json(record))

    publication = publish_artifacts(
        logs_dir=logs,
        run_spec=spec,
        instruction="Create the sentinel.",
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
        require_harbor_validator=False,
    )

    assert publication.publication_kind == "failure_partial"
    assert "tool_receipt" not in json.dumps(publication.trajectory)


def test_event_v3_receipt_is_projected_only_in_the_integration_layer(
    tmp_path: Path,
) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    write_failed_runtime_v2(logs, spec)
    runtime = logs / "runtime"
    events_path = runtime / "events.jsonl"
    events = [json.loads(line) for line in events_path.read_bytes().splitlines()]
    terminal = events.pop()
    for event in events:
        event["schema_version"] = "event-v3"
    events.append(
        {
            **{key: terminal[key] for key in ("run_id", "trial_id", "attempt_id")},
            "schema_version": "event-v3",
            "seq": len(events),
            "elapsed_ms": len(events),
            "type": "tool.receipt",
            "data": _runtime_tool_receipt(),
        }
    )
    terminal["schema_version"] = "event-v3"
    terminal["seq"] = len(events)
    terminal["elapsed_ms"] = len(events)
    terminal["data"]["tool_receipt_omitted_count"] = 1
    events.append(terminal)
    event_bytes = b"".join(canonical_json(event) for event in events)
    events_path.write_bytes(event_bytes)
    run_path = runtime / "run.json"
    record = json.loads(run_path.read_bytes())
    record["final_event_seq"] = len(events) - 1
    record["end_elapsed_ms"] = len(events) - 1
    record["events_sha256"] = hashlib.sha256(event_bytes).hexdigest()
    run_path.write_bytes(canonical_json(record))

    publication = publish_artifacts(
        logs_dir=logs,
        run_spec=spec,
        instruction="Create the sentinel.",
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
        require_harbor_validator=False,
    )

    telemetry = publication.tool_receipt_telemetry
    assert telemetry is not None
    assert telemetry["coverage"] == "partial"
    assert telemetry["sample_count"] == 1
    assert telemetry["omitted_samples"] == 1
    sample = telemetry["samples"][0]
    assert sample["schema_version"] == "nano-tool-receipt-telemetry-v1"
    assert sample["coverage"] == "complete"
    assert sample["owner"] == "tool"
    assert sample["source"] == "actor_receipt"
    assert sample["relation"] == "settles"


def test_v2_conflicting_cost_aliases_fail_after_events_hash_rebound(
    tmp_path: Path,
) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    write_success_runtime_v2(logs, spec)
    runtime = logs / "runtime"
    events_path = runtime / "events.jsonl"
    events = [json.loads(line) for line in events_path.read_bytes().splitlines()]
    events[2]["data"]["usage"]["cost_in_usd_ticks"] = 18
    event_bytes = b"".join(canonical_json(event) for event in events)
    events_path.write_bytes(event_bytes)
    run_path = runtime / "run.json"
    record = json.loads(run_path.read_bytes())
    record["events_sha256"] = hashlib.sha256(event_bytes).hexdigest()
    run_path.write_bytes(canonical_json(record))

    with pytest.raises(ArtifactError, match="event_data_invalid"):
        publish_artifacts(
            logs_dir=logs,
            run_spec=spec,
            instruction="Create the sentinel.",
            agent_name="nano-grok-build",
            agent_version="test",
            model_name="synthetic-model",
            require_harbor_validator=False,
        )


def test_provider_failure_accepts_usage_from_semantically_rejected_response() -> None:
    valid = {
        "turn_index": 3,
        "code": "provider_call_limit_exceeded",
        "rejected_call_count": 17,
        "response_usage": {
            "input_tokens": 11,
            "output_tokens": 3,
            "provider_cost_ticks": 123_000_000,
        },
        "attempt_count": 1,
    }
    artifactizer._validate_v2_event_data("provider.failed", valid)

    for patch in (
        {"code": "provider_transport_failed"},
        {"rejected_call_count": 0},
        {"response_usage": []},
    ):
        invalid = {**valid, **patch}
        with pytest.raises(ArtifactError):
            artifactizer._validate_v2_event_data("provider.failed", invalid)

    semantic_rejection = {
        key: value for key, value in valid.items() if key != "rejected_call_count"
    }
    semantic_rejection["code"] = "provider_model_drift"
    artifactizer._validate_v2_event_data("provider.failed", semantic_rejection)


@pytest.mark.parametrize(
    ("event_type", "data"),
    [
        (
            "provider.requested",
            {
                "turn_index": 0,
                "history_item_count": 3,
                "tool_count": 8,
                "function_output_call_ids": [],
                "budget_observation": {
                    "phase": "action_open",
                    "budget_notice_visible": True,
                    "action_remaining_ms": 1_000,
                    "settlement_remaining_ms": 2_000,
                    "last_send_remaining_ms": 3_000,
                },
            },
        ),
        (
            "tool.registered",
            {
                "call_id": "call-1",
                "provider_name": "run_terminal_command",
                "known": True,
                "arguments_json": "{}",
                "budget_observation": {
                    "dispatch_open_at_registration": True,
                    "action_remaining_ms": 1_000,
                    "settlement_remaining_ms": 2_000,
                    "last_send_remaining_ms": 3_000,
                },
            },
        ),
    ],
)
def test_budget_observation_is_typed_and_optional(
    event_type: str,
    data: dict[str, object],
) -> None:
    artifactizer._validate_v2_event_data(event_type, data)

    invalid = copy.deepcopy(data)
    observation = invalid["budget_observation"]
    assert isinstance(observation, dict)
    observation["settlement_remaining_ms"] = "unknown"
    with pytest.raises(ArtifactError, match="event_data_invalid"):
        artifactizer._validate_v2_event_data(event_type, invalid)

    legacy = {key: value for key, value in data.items() if key != "budget_observation"}
    artifactizer._validate_v2_event_data(event_type, legacy)


def test_emergency_usage_aggregates_rejected_response_usage() -> None:
    events = [
        {"type": "provider.requested", "data": {}},
        {
            "type": "provider.failed",
            "data": {
                "response_usage": {
                    "input_tokens": 11,
                    "output_tokens": 3,
                    "input_tokens_details": {"cached_tokens": 2},
                    "provider_cost_ticks": 123_000_000,
                }
            },
        },
    ]

    coverage, totals = artifactizer._emergency_usage(events)

    assert coverage == {
        "requested": 1,
        "completed": 0,
        "failed": 1,
        "in_flight": 0,
        "usage_present": 1,
        "usage_absent": 0,
        "usage_covered": 1,
        "cost_present": 1,
        "cost_absent": 0,
        "state": "complete",
    }
    assert totals == {
        "input_tokens": 11,
        "cached_input_tokens": 2,
        "output_tokens": 3,
        "provider_cost_ticks": 123_000_000,
    }


def test_v2_marker_wire_golden_is_unchanged(tmp_path: Path) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    spec["artifact_dir"] = "/logs/agent/runtime"
    write_success_runtime_v2(logs, spec)

    publication = publish_artifacts(
        logs_dir=logs,
        run_spec=spec,
        instruction="Create the sentinel.",
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
        require_harbor_validator=False,
    )

    expected = (
        b'{"attempt_id":"attempt-0","events_sha256":'
        b'"b61d90f9a0dcdcc3f113bf973872a674c07ad8307c062503a1e294bd17f1c3bb",'
        b'"publication_kind":"success_atif","run_id":"run-1",'
        b'"run_record_schema":"nano-run-record-v2",'
        b'"run_spec_sha256":'
        b'"cad5b27eaa9aca2ea232656a2b5689cd11e5c22e7b97d490b3d86c48a636561f",'
        b'"schema_version":"nano-agent-run-v2","terminal_code":"completed",'
        b'"terminal_phase":null,"terminal_status":"success",'
        b'"trajectory_path":"trajectory.json","trajectory_sha256":'
        b'"0b7e2396cede47b7be6b93957284465f31d6498546ec5c63a448b7972a893532",'
        b'"trial_id":"trial-1","usage_receipt_sha256":'
        b'"532b5dca00d7a9bf3f971862eeaa10a537534522420d01a00ad5d90af0e4f086"}\n'
    )
    assert publication.marker_bytes == expected
    assert hashlib.sha256(expected).hexdigest() == (
        "5c85146929f2977638611f8d54897bc818ab7256453aaeaa35225fb69cdbd1d5"
    )


def test_v2_deadline_receipt_is_hash_identity_and_run_spec_bound(
    tmp_path: Path,
) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    spec["agent_timeout_sec"] = 120
    write_success_runtime_v2(logs, spec)
    raw, digest = bind_deadline_receipt(logs, spec)

    publication = publish_artifacts(
        logs_dir=logs,
        run_spec=spec,
        instruction="Create the sentinel.",
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
        require_harbor_validator=False,
    )

    assert hashlib.sha256(raw).hexdigest() == digest
    event_lines = (logs / "runtime" / "events.jsonl").read_bytes().splitlines()
    started = json.loads(event_lines[0])
    record = json.loads((logs / "runtime" / "run.json").read_bytes())
    assert started["data"]["deadline_receipt_sha256"] == digest
    assert record["deadline_receipt_sha256"] == digest
    assert publication.success_artifact_valid is True


def test_v3_valid_publication_is_four_way_bound_marker_last_and_idempotent(
    tmp_path: Path,
) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    spec["agent_timeout_sec"] = 120
    write_success_runtime_v2(logs, spec)
    raw, digest = bind_deadline_receipt(logs, spec)
    upgrade_runtime_to_v3(logs)

    first = publish_artifacts(
        logs_dir=logs,
        run_spec=spec,
        instruction="Create the sentinel.",
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
        require_harbor_validator=False,
    )

    started = json.loads(
        (logs / "runtime" / "events.jsonl").read_bytes().splitlines()[0]
    )
    record = json.loads((logs / "runtime" / "run.json").read_bytes())
    marker = json.loads(first.marker_bytes)
    assert hashlib.sha256(raw).hexdigest() == digest
    assert started["data"]["deadline_receipt_sha256"] == digest
    assert record["deadline_receipt_sha256"] == digest
    assert record["schema_version"] == "nano-run-record-v3"
    assert marker["schema_version"] == "nano-agent-run-v3"
    assert marker["run_record_schema"] == "nano-run-record-v3"
    assert marker["deadline_receipt_sha256"] == digest
    marker_stat = first.marker_path.stat()
    assert marker_stat.st_mtime_ns >= first.trajectory_path.stat().st_mtime_ns
    assert (
        marker_stat.st_mtime_ns
        >= (logs / "runtime-usage-receipt.json").stat().st_mtime_ns
    )

    second = publish_artifacts(
        logs_dir=logs,
        run_spec=spec,
        instruction="Create the sentinel.",
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
        require_harbor_validator=False,
    )
    assert second.marker_bytes == first.marker_bytes
    assert second.trajectory_path.read_bytes() == first.trajectory_path.read_bytes()


def test_complete_media_batch_preserves_marker_last_binding(tmp_path: Path) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    spec["agent_timeout_sec"] = 120
    write_success_runtime_v2(logs, spec)
    runtime = logs / "runtime"
    events_path = runtime / "events.jsonl"
    original = [json.loads(line) for line in events_path.read_bytes().splitlines()]
    common = {
        key: original[0][key]
        for key in ("schema_version", "run_id", "trial_id", "attempt_id")
    }
    call_ids = [f"media-{index}" for index in range(6)]
    bodies: list[tuple[str, dict[str, object]]] = [
        ("run.started", original[0]["data"]),
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
                **original[2]["data"],
                "call_ids": call_ids,
                "has_final_text": False,
            },
        ),
    ]
    for call_id in call_ids:
        bodies.extend(
            [
                (
                    "tool.registered",
                    {
                        "call_id": call_id,
                        "provider_name": "read_file",
                        "known": True,
                        "arguments_json": '{"path":"/workspace/frame.png"}',
                    },
                ),
                (
                    "tool.dispatched",
                    {"call_id": call_id, "provider_name": "read_file"},
                ),
                (
                    "tool.completed",
                    {
                        "call_id": call_id,
                        "provider_name": "read_file",
                        "execution_attempted": True,
                        "outcome": "succeeded",
                        "output": "read_file returned an attached image",
                    },
                ),
            ]
        )
    bodies.extend(
        [
            (
                "provider.requested",
                {
                    "turn_index": 1,
                    "history_item_count": 20,
                    "tool_count": 8,
                    "function_output_call_ids": call_ids,
                },
            ),
            (
                "provider.completed",
                {**original[2]["data"], "turn_index": 1},
            ),
            ("assistant.final", {"text": "finished"}),
            ("run.completed", {"code": "completed"}),
        ]
    )
    event_bytes = b"".join(
        canonical_json(
            {
                **common,
                "seq": seq,
                "elapsed_ms": seq,
                "type": event_type,
                "data": data,
            }
        )
        for seq, (event_type, data) in enumerate(bodies)
    )
    events_path.write_bytes(event_bytes)
    run_path = runtime / "run.json"
    record = json.loads(run_path.read_bytes())
    record.update(
        {
            "final_event_seq": len(bodies) - 1,
            "provider_turn_count": 2,
            "tool_call_count": 6,
            "provider_call_coverage": {
                "requested": 2,
                "completed": 2,
                "failed": 0,
                "in_flight": 0,
                "usage_present": 2,
                "usage_absent": 0,
                "usage_covered": 2,
                "cost_present": 2,
                "cost_absent": 0,
                "state": "complete",
            },
            "usage_totals": {
                "input_tokens": 26,
                "cached_input_tokens": 4,
                "output_tokens": 10,
                "provider_cost_ticks": 34,
            },
            "end_elapsed_ms": len(bodies) - 1,
            "events_sha256": hashlib.sha256(event_bytes).hexdigest(),
        }
    )
    run_path.write_bytes(canonical_json(record))
    bind_media_history_policy(logs)
    events = [json.loads(line) for line in events_path.read_bytes().splitlines()]
    requests = [event for event in events if event["type"] == "provider.requested"]
    requests[1]["data"]["media_history_receipt"] = {
        "history_sha256": "d" * 64,
        "retained_count": 4,
        "retained_bytes": 24,
        "evicted_total": 2,
    }
    event_bytes = b"".join(canonical_json(event) for event in events)
    events_path.write_bytes(event_bytes)
    record = json.loads(run_path.read_bytes())
    record["events_sha256"] = hashlib.sha256(event_bytes).hexdigest()
    run_path.write_bytes(canonical_json(record))
    bind_deadline_receipt(logs, spec)
    upgrade_runtime_to_v3(logs)

    first = publish_artifacts(
        logs_dir=logs,
        run_spec=spec,
        instruction="Create the sentinel.",
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
        require_harbor_validator=False,
    )
    marker = json.loads(first.marker_bytes)
    assert marker["events_sha256"] == json.loads(run_path.read_bytes())["events_sha256"]
    assert (
        marker["trajectory_sha256"]
        == hashlib.sha256(first.trajectory_path.read_bytes()).hexdigest()
    )
    assert (
        first.marker_path.stat().st_mtime_ns >= first.trajectory_path.stat().st_mtime_ns
    )
    second = publish_artifacts(
        logs_dir=logs,
        run_spec=spec,
        instruction="Create the sentinel.",
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
        require_harbor_validator=False,
    )
    assert second.marker_bytes == first.marker_bytes


@pytest.mark.parametrize(
    ("mutation", "error_code"),
    [
        ("record", "run_started_binding_invalid"),
        ("run_started", "run_started_binding_invalid"),
        ("deadline_file", "deadline_receipt_invalid"),
        ("cross_trial", "deadline_receipt_identity_mismatch"),
    ],
)
def test_v3_binding_mismatch_writes_no_publication_files(
    tmp_path: Path,
    mutation: str,
    error_code: str,
) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    spec["agent_timeout_sec"] = 120
    write_success_runtime_v2(logs, spec)
    bind_deadline_receipt(
        logs,
        spec,
        receipt_run_id="replayed-run" if mutation == "cross_trial" else "run-1",
    )
    upgrade_runtime_to_v3(logs)
    runtime = logs / "runtime"
    run_path = runtime / "run.json"
    events_path = runtime / "events.jsonl"
    if mutation == "record":
        record = json.loads(run_path.read_bytes())
        record["deadline_receipt_sha256"] = "f" * 64
        run_path.write_bytes(canonical_json(record))
    elif mutation == "run_started":
        events = [json.loads(line) for line in events_path.read_bytes().splitlines()]
        events[0]["data"]["deadline_receipt_sha256"] = "f" * 64
        event_bytes = b"".join(canonical_json(event) for event in events)
        events_path.write_bytes(event_bytes)
        record = json.loads(run_path.read_bytes())
        record["events_sha256"] = hashlib.sha256(event_bytes).hexdigest()
        run_path.write_bytes(canonical_json(record))
    elif mutation == "deadline_file":
        deadline_path = runtime / "deadline.json"
        receipt = json.loads(deadline_path.read_bytes())
        receipt["cutoffs"]["actor_done_monotonic_ns"] += 1
        deadline_path.write_bytes(canonical_json(receipt))

    with pytest.raises(ArtifactError, match=f"^{error_code}$"):
        publish_artifacts(
            logs_dir=logs,
            run_spec=spec,
            instruction="Create the sentinel.",
            agent_name="nano-grok-build",
            agent_version="test",
            model_name="synthetic-model",
            require_harbor_validator=False,
        )
    assert not (logs / "trajectory.json").exists()
    assert not (logs / "partial-trajectory.json").exists()
    assert not (logs / "runtime-usage-receipt.json").exists()
    assert not (logs / "agent-run.json").exists()


def test_v2_media_history_policy_is_run_started_and_request_receipt_bound(
    tmp_path: Path,
) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    write_success_runtime_v2(logs, spec)
    bind_media_history_policy(logs)

    publication = publish_artifacts(
        logs_dir=logs,
        run_spec=spec,
        instruction="Create the sentinel.",
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
        require_harbor_validator=False,
    )

    assert publication.success_artifact_valid is True
    started = json.loads(
        (logs / "runtime" / "events.jsonl").read_bytes().splitlines()[0]
    )
    assert (
        started["data"]["media_history_policy_version"]
        == "rolling-media-history-latest-suffix-v1"
    )
    record = json.loads((logs / "runtime" / "run.json").read_bytes())
    assert "media_history_policy_version" not in record
    assert "media_history_policy_sha256" not in record


def test_v2_media_history_policy_rejects_missing_request_receipt(
    tmp_path: Path,
) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    write_success_runtime_v2(logs, spec)
    bind_media_history_policy(logs)
    runtime = logs / "runtime"
    events = [
        json.loads(line)
        for line in (runtime / "events.jsonl").read_bytes().splitlines()
    ]
    requested = next(event for event in events if event["type"] == "provider.requested")
    del requested["data"]["media_history_receipt"]
    event_bytes = b"".join(canonical_json(event) for event in events)
    (runtime / "events.jsonl").write_bytes(event_bytes)
    record = json.loads((runtime / "run.json").read_bytes())
    record["events_sha256"] = hashlib.sha256(event_bytes).hexdigest()
    (runtime / "run.json").write_bytes(canonical_json(record))

    with pytest.raises(ArtifactError, match="^media_history_request_binding_invalid$"):
        publish_artifacts(
            logs_dir=logs,
            run_spec=spec,
            instruction="Create the sentinel.",
            agent_name="nano-grok-build",
            agent_version="test",
            model_name="synthetic-model",
            require_harbor_validator=False,
        )


def test_v2_media_history_policy_rejects_wrong_config_sha(tmp_path: Path) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    write_success_runtime_v2(logs, spec)
    bind_media_history_policy(logs, event_sha256="f" * 64)

    with pytest.raises(ArtifactError, match="^event_data_invalid$"):
        publish_artifacts(
            logs_dir=logs,
            run_spec=spec,
            instruction="Create the sentinel.",
            agent_name="nano-grok-build",
            agent_version="test",
            model_name="synthetic-model",
            require_harbor_validator=False,
        )


def test_v2_deadline_receipt_rejects_event_record_mismatch(tmp_path: Path) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    spec["agent_timeout_sec"] = 120
    write_success_runtime_v2(logs, spec)
    bind_deadline_receipt(logs, spec)

    runtime = logs / "runtime"
    event_lines = (runtime / "events.jsonl").read_bytes().splitlines()
    events = [json.loads(line) for line in event_lines]
    events[0]["data"]["deadline_receipt_sha256"] = "f" * 64
    event_bytes = b"".join(canonical_json(event) for event in events)
    (runtime / "events.jsonl").write_bytes(event_bytes)
    record = json.loads((runtime / "run.json").read_bytes())
    record["events_sha256"] = hashlib.sha256(event_bytes).hexdigest()
    (runtime / "run.json").write_bytes(canonical_json(record))

    with pytest.raises(ArtifactError, match="^run_started_binding_invalid$"):
        publish_artifacts(
            logs_dir=logs,
            run_spec=spec,
            instruction="Create the sentinel.",
            agent_name="nano-grok-build",
            agent_version="test",
            model_name="synthetic-model",
            require_harbor_validator=False,
        )


@pytest.mark.parametrize(
    ("receipt_run_id", "canonical", "error_code"),
    [
        ("replayed-run", True, "deadline_receipt_identity_mismatch"),
        ("run-1", False, "deadline_receipt_canonical_invalid"),
    ],
)
def test_v2_deadline_receipt_rejects_replay_and_noncanonical_bytes(
    tmp_path: Path,
    receipt_run_id: str,
    canonical: bool,
    error_code: str,
) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    spec["agent_timeout_sec"] = 120
    write_success_runtime_v2(logs, spec)
    bind_deadline_receipt(
        logs,
        spec,
        receipt_run_id=receipt_run_id,
        canonical=canonical,
    )

    with pytest.raises(ArtifactError, match=f"^{error_code}$"):
        publish_artifacts(
            logs_dir=logs,
            run_spec=spec,
            instruction="Create the sentinel.",
            agent_name="nano-grok-build",
            agent_version="test",
            model_name="synthetic-model",
            require_harbor_validator=False,
        )


def test_v2_deadline_receipt_file_cannot_remain_unbound(tmp_path: Path) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    spec["agent_timeout_sec"] = 120
    write_success_runtime_v2(logs, spec)
    receipt = RunDeadlineReceiptV1.bind(
        deadline=RunDeadlineV1.mint(
            source="test_host_phase",
            agent_timeout_ms=120_000,
            now_monotonic_ns=1_000_000_000,
        ),
        run_id=str(spec["run_id"]),
        trial_id=str(spec["trial_id"]),
        attempt_id=str(spec["attempt_id"]),
        run_spec_sha256=rust_run_spec_sha256(spec),
    )
    (logs / "runtime" / "deadline.json").write_bytes(receipt.to_bytes())

    with pytest.raises(ArtifactError, match="^deadline_receipt_unbound$"):
        publish_artifacts(
            logs_dir=logs,
            run_spec=spec,
            instruction="Create the sentinel.",
            agent_name="nano-grok-build",
            agent_version="test",
            model_name="synthetic-model",
            require_harbor_validator=False,
        )


def test_v2_failure_publishes_truthful_partial_and_marker_last(
    tmp_path: Path,
) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    write_failed_runtime_v2(logs, spec)
    manifest = {
        "schema_version": BACKGROUND_MANIFEST_SCHEMA,
        "run_id": spec["run_id"],
        "trial_id": spec["trial_id"],
        "attempt_id": spec["attempt_id"],
        "run_spec_sha256": rust_run_spec_sha256(spec),
        "tasks": [],
    }
    (logs / "runtime-background-manifest.json").write_bytes(canonical_json(manifest))
    workspace_receipt = canonical_json(
        {
            "schema_version": "nano-workspace-receipt-v1",
            "status": "failed",
            "code": "workspace_after_capture_failed",
            "policy": {"version": "nano-workspace-snapshot-policy-v1"},
            "truncated": False,
            "omitted_count": 0,
            "artifacts": {},
        }
    )
    (logs / "workspace-receipt.json").write_bytes(workspace_receipt)

    first = publish_artifacts(
        logs_dir=logs,
        run_spec=spec,
        instruction="Create the sentinel.",
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
        require_harbor_validator=True,
        require_background_manifest=True,
    )

    assert first.publication_kind == "failure_partial"
    assert first.success_artifact_valid is False
    assert first.diagnostic_package_valid is True
    assert first.trajectory_path.name == "partial-trajectory.json"
    assert not (logs / "trajectory.json").exists()
    partial_bytes = first.trajectory_path.read_bytes()
    partial = json.loads(partial_bytes)
    assert partial["schema_version"] == "nano-partial-trajectory-v1"
    assert partial["instruction"] == "Create the sentinel."
    assert partial["assistant_final"] is None
    assert partial["terminal_failure"] == {
        "status": "tool_failure",
        "phase": "bridge",
        "code": "terminal_actor_cleanup_unverified",
        "event_seq": 6,
        "elapsed_ms": 6,
    }
    assert partial["provider_turns"][0]["state"] == "completed"
    assert partial["tool_calls"] == [
        {
            "call_id": "call-1",
            "function_name": "run_terminal_command",
            "arguments": {"command": "sleep 60"},
            "known": True,
            "state": "failed",
            "dispatched": True,
            "failure": {
                "code": "terminal_actor_cleanup_unverified",
                "execution_may_have_started": True,
                "cleanup_verified": False,
                "census_verified": False,
                "recoverability": "fatal",
            },
        }
    ]
    marker = json.loads(first.marker_bytes)
    assert marker["schema_version"] == "nano-agent-run-v2"
    assert marker["publication_kind"] == "failure_partial"
    assert marker["trajectory_path"] == "partial-trajectory.json"
    assert marker["trajectory_sha256"] == hashlib.sha256(partial_bytes).hexdigest()
    assert (
        marker["usage_receipt_sha256"]
        == hashlib.sha256(
            (logs / "runtime-usage-receipt.json").read_bytes()
        ).hexdigest()
    )
    assert (
        marker["background_manifest_sha256"]
        == hashlib.sha256(canonical_json(manifest)).hexdigest()
    )
    assert (
        marker["workspace_receipt_sha256"]
        == hashlib.sha256(workspace_receipt).hexdigest()
    )

    second = publish_artifacts(
        logs_dir=logs,
        run_spec=spec,
        instruction="Create the sentinel.",
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
        require_harbor_validator=True,
        require_background_manifest=True,
    )
    assert second.marker_bytes == first.marker_bytes
    assert second.trajectory_path.read_bytes() == partial_bytes


@pytest.mark.parametrize(
    ("terminal_status", "terminal_phase", "terminal_code"),
    [
        (
            "deadline_failure",
            "deadline",
            "provider_final_deadline_exceeded",
        ),
        ("provider_failure", "provider", "provider_max_turns_exceeded"),
        ("provider_failure", "provider", "provider_transport_timeout"),
        ("tool_failure", "bridge", "terminal_actor_cleanup_unverified"),
    ],
)
def test_rewarded_failed_runtime_remains_diagnostic_and_atif_ineligible(
    tmp_path: Path,
    terminal_status: str,
    terminal_phase: str,
    terminal_code: str,
) -> None:
    logs = tmp_path / terminal_code
    spec = run_spec(logs)
    write_provider_deadline_runtime_v2(
        logs,
        spec,
        terminal_status=terminal_status,
        terminal_phase=terminal_phase,
        terminal_code=terminal_code,
    )
    external_verifier_reward = 1

    first = publish_artifacts(
        logs_dir=logs,
        run_spec=spec,
        instruction="Find the largest eigenvalue.",
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
        require_harbor_validator=True,
    )

    assert external_verifier_reward == 1
    assert first.publication_kind == "failure_partial"
    assert first.success_artifact_valid is False
    assert first.atif_eligibility.leaderboard_eligible is False
    assert first.atif_eligibility.conformance == "diagnostic_only"
    assert first.atif_eligibility.trajectory_path is None
    assert first.atif_eligibility.trajectory_sha256 is None
    assert first.atif_eligibility.ineligibility_reason == (
        f"runtime_not_success:{terminal_status}:{terminal_code}"
    )
    partial = first.trajectory
    assert partial["schema_version"] == "nano-partial-trajectory-v1"
    assert partial["assistant_final"] is None
    assert partial["provider_turns"][-1]["state"] == "in_flight"
    assert not (logs / "trajectory.json").exists()
    marker = json.loads(first.marker_bytes)
    assert marker["publication_kind"] == "failure_partial"
    assert marker["terminal_status"] == terminal_status
    assert marker["terminal_code"] == terminal_code
    assert marker["trajectory_path"] == "partial-trajectory.json"
    assert (
        marker["trajectory_sha256"]
        == hashlib.sha256(first.trajectory_path.read_bytes()).hexdigest()
    )

    second = publish_artifacts(
        logs_dir=logs,
        run_spec=spec,
        instruction="Find the largest eigenvalue.",
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
        require_harbor_validator=True,
    )
    assert second.marker_bytes == first.marker_bytes
    assert second.trajectory_path.read_bytes() == first.trajectory_path.read_bytes()


def test_missing_record_publishes_validated_emergency_prefix(
    tmp_path: Path,
) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    write_success_runtime_v2(logs, spec)
    (logs / "runtime" / "run.json").unlink()
    event_path = logs / "runtime" / "events.jsonl"
    valid_lines = event_path.read_bytes().splitlines(keepends=True)[:3]
    source_events = b"".join(valid_lines) + b'{"schema_version":"event-v2"'
    event_path.write_bytes(source_events)
    emergency = {
        "schema_version": "nano-runtime-emergency-v1",
        "run_id": spec["run_id"],
        "trial_id": spec["trial_id"],
        "attempt_id": spec["attempt_id"],
        "run_spec_sha256": rust_run_spec_sha256(spec),
        "status": "runtime_record_missing",
        "code": "runtime_record_missing_after_bridge_completion",
        "bridge_completed": True,
        "events_sha256": hashlib.sha256(source_events).hexdigest(),
        "events_byte_length": len(source_events),
    }
    (logs / "runtime-emergency.json").write_bytes(canonical_json(emergency))
    manifest = {
        "schema_version": BACKGROUND_MANIFEST_SCHEMA,
        "run_id": spec["run_id"],
        "trial_id": spec["trial_id"],
        "attempt_id": spec["attempt_id"],
        "run_spec_sha256": rust_run_spec_sha256(spec),
        "tasks": [],
    }
    (logs / "runtime-background-manifest.json").write_bytes(canonical_json(manifest))

    publication = publish_artifacts(
        logs_dir=logs,
        run_spec=spec,
        instruction="Create the sentinel.",
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
        require_harbor_validator=True,
        require_background_manifest=True,
    )

    assert publication.publication_kind == "emergency_prefix"
    assert publication.success_artifact_valid is False
    assert publication.diagnostic_package_valid is True
    assert publication.atif_eligibility.leaderboard_eligible is False
    assert publication.atif_eligibility.conformance == "diagnostic_only"
    assert publication.atif_eligibility.trajectory_path is None
    assert publication.atif_eligibility.trajectory_sha256 is None
    assert publication.atif_eligibility.ineligibility_reason == (
        "runtime_not_success:runtime_failure:"
        "runtime_record_missing_after_bridge_completion"
    )
    assert publication.context == {
        "n_input_tokens": 13,
        "n_cache_tokens": 2,
        "n_output_tokens": 5,
    }
    prefix = publication.trajectory
    assert prefix["schema_version"] == "nano-emergency-prefix-v1"
    assert prefix["assistant_final"] is None
    assert prefix["event_prefix"]["last_valid_seq"] == 2
    assert prefix["event_prefix"]["stop_reason"] == "incomplete_event_line"
    assert prefix["terminal_failure"] == {
        "status": "runtime_failure",
        "phase": "artifact",
        "code": "runtime_record_missing_after_bridge_completion",
        "event_seq": 2,
        "elapsed_ms": 2,
        "evidence": "adapter_emergency",
    }
    marker = json.loads(publication.marker_bytes)
    assert marker["publication_kind"] == "emergency_prefix"
    assert marker["run_record_schema"] is None
    assert marker["events_sha256"] == hashlib.sha256(source_events).hexdigest()
    assert marker["trajectory_path"] == "emergency-prefix.json"
    assert publication.usage_coverage is not None
    assert publication.usage_coverage["state"] == "complete"


def test_background_manifest_is_canonical_bounded_and_digest_bound(
    tmp_path: Path,
) -> None:
    logs = tmp_path / "agent"
    logs.mkdir()
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    manifest = {
        "schema_version": BACKGROUND_MANIFEST_SCHEMA,
        "run_id": "run-1",
        "trial_id": "trial-1",
        "attempt_id": "attempt-0",
        "run_spec_sha256": rust_run_spec_sha256(run_spec(logs)),
        "tasks": [
            {
                "task_id": task_id,
                "pgid": 123,
                "monitor_pgid": 124,
                "output_path": f"/workspace/.terminals/{task_id}.log",
                "state": "running",
            }
        ],
    }
    raw = canonical_json(manifest)
    (logs / "runtime-background-manifest.json").write_bytes(raw)
    receipt = validate_background_manifest(logs_dir=logs, run_spec=run_spec(logs))
    assert receipt.task_count == 1
    assert receipt.sha256 == hashlib.sha256(raw).hexdigest()

    manifest["tasks"][0]["output_path"] = (
        f"/workspace/.terminals/{task_id}.log.uncommitted"
    )
    (logs / "runtime-background-manifest.json").write_bytes(canonical_json(manifest))
    with pytest.raises(ArtifactError, match="background_manifest_invalid"):
        validate_background_manifest(logs_dir=logs, run_spec=run_spec(logs))

    manifest["tasks"][0]["output_path"] = f"/workspace/.terminals/{task_id}.log"
    manifest["tasks"][0]["state"] = "completed"
    (logs / "runtime-background-manifest.json").write_bytes(canonical_json(manifest))
    with pytest.raises(ArtifactError, match="background_manifest_invalid"):
        validate_background_manifest(logs_dir=logs, run_spec=run_spec(logs))


def test_background_failure_manifest_preserves_runtime_diagnostics(
    tmp_path: Path,
) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    write_failed_runtime_v2(logs, spec)
    manifest = {
        "schema_version": BACKGROUND_FAILURE_MANIFEST_SCHEMA,
        "run_id": spec["run_id"],
        "trial_id": spec["trial_id"],
        "attempt_id": spec["attempt_id"],
        "run_spec_sha256": rust_run_spec_sha256(spec),
        "status": "unavailable",
        "code": "external_bridge_cleanup_unverified",
        "cleanup_attempted": True,
        "cleanup_verified": False,
    }
    raw = canonical_json(manifest)
    (logs / "runtime-background-manifest.json").write_bytes(raw)

    receipt = validate_background_manifest(logs_dir=logs, run_spec=spec)
    assert receipt.status == "unavailable"
    assert receipt.failure_code == "external_bridge_cleanup_unverified"
    assert receipt.task_count == 0

    publication = publish_artifacts(
        logs_dir=logs,
        run_spec=spec,
        instruction="Create the sentinel.",
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
        require_harbor_validator=False,
        require_background_manifest=True,
    )

    assert publication.publication_kind == "failure_partial"
    assert publication.diagnostic_package_valid is True
    assert publication.background_manifest == receipt
    assert publication.usage_receipt_path is not None
    marker = json.loads(publication.marker_bytes)
    assert marker["background_manifest_sha256"] == hashlib.sha256(raw).hexdigest()
    assert marker["background_task_count"] == 0


def test_background_manifest_is_validated_before_publication_marker(
    tmp_path: Path,
) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    write_committed_runtime(logs, spec)
    arguments = {
        "logs_dir": logs,
        "run_spec": spec,
        "instruction": "Create the sentinel.",
        "agent_name": "nano-grok-build",
        "agent_version": "test",
        "model_name": "synthetic-model",
        "require_harbor_validator": False,
        "require_background_manifest": True,
    }
    with pytest.raises(ArtifactError, match="background_manifest_missing"):
        publish_artifacts(**arguments)
    assert not (logs / "trajectory.json").exists()
    assert not (logs / "agent-run.json").exists()

    manifest = {
        "schema_version": BACKGROUND_MANIFEST_SCHEMA,
        "run_id": spec["run_id"],
        "trial_id": spec["trial_id"],
        "attempt_id": spec["attempt_id"],
        "run_spec_sha256": rust_run_spec_sha256(spec),
        "tasks": [],
    }
    raw = canonical_json(manifest)
    (logs / "runtime-background-manifest.json").write_bytes(raw)
    publication = publish_artifacts(**arguments)
    marker = json.loads(publication.marker_bytes)
    assert marker["background_manifest_sha256"] == hashlib.sha256(raw).hexdigest()
    assert marker["background_task_count"] == 0

    invalid_logs = tmp_path / "invalid-agent"
    invalid_spec = run_spec(invalid_logs)
    write_committed_runtime(invalid_logs, invalid_spec)
    manifest["run_id"] = "wrong"
    (invalid_logs / "runtime-background-manifest.json").write_bytes(
        canonical_json(manifest)
    )
    with pytest.raises(ArtifactError, match="background_manifest_invalid"):
        publish_artifacts(
            **{
                **arguments,
                "logs_dir": invalid_logs,
                "run_spec": invalid_spec,
            }
        )
    assert not (invalid_logs / "trajectory.json").exists()
    assert not (invalid_logs / "agent-run.json").exists()


def test_run_spec_hash_mirror_commits_selector_only_when_present(
    tmp_path: Path,
) -> None:
    spec = run_spec(tmp_path / "agent")
    spec["artifact_dir"] = "/logs/agent"
    assert (
        rust_run_spec_sha256(spec)
        == "47034171b4517e2729d7aa135cae70fa94be17a64e2a2a6e4be30be65f1d911c"
    )
    spec["active_tools"] = ["run_terminal_command", "read_file", "write"]
    assert (
        rust_run_spec_sha256(spec)
        == "a68f309dccfc2bb6513d0aa38f1016c7b5b54e9023b39a6928e9243e6d209bac"
    )


def test_trajectory_without_marker_is_uncommitted_and_not_repaired(
    tmp_path: Path,
) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    write_committed_runtime(logs, spec)
    (logs / "trajectory.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ArtifactError, match="uncommitted_trajectory_exists"):
        publish_artifacts(
            logs_dir=logs,
            run_spec=spec,
            instruction="Create the sentinel.",
            agent_name="nano-grok-build",
            agent_version="test",
            model_name="synthetic-model",
            require_harbor_validator=False,
        )
    assert not (logs / "agent-run.json").exists()


def test_missing_or_corrupt_runtime_never_publishes_marker(tmp_path: Path) -> None:
    logs = tmp_path / "agent"
    spec = run_spec(logs)
    with pytest.raises(ArtifactError):
        publish_artifacts(
            logs_dir=logs,
            run_spec=spec,
            instruction="Create the sentinel.",
            agent_name="nano-grok-build",
            agent_version="test",
            model_name="synthetic-model",
            require_harbor_validator=False,
        )
    assert not (logs / "agent-run.json").exists()

    write_committed_runtime(logs, spec)
    events = logs / "runtime" / "events.jsonl"
    events.write_bytes(events.read_bytes() + b"{}\n")
    with pytest.raises(ArtifactError, match="event_log_hash_mismatch"):
        publish_artifacts(
            logs_dir=logs,
            run_spec=spec,
            instruction="Create the sentinel.",
            agent_name="nano-grok-build",
            agent_version="test",
            model_name="synthetic-model",
            require_harbor_validator=False,
        )
    assert not (logs / "agent-run.json").exists()
