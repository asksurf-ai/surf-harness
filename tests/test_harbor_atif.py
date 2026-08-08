from __future__ import annotations

import sys
import types

import pytest

from nano_grok_build.adapter import atif
from nano_grok_build.adapter.atif import (
    AtifError,
    project_emergency_trajectory,
    project_failure_trajectory,
    project_partial_trajectory,
    project_trajectory,
    validate_minimal_trajectory,
    validate_with_pinned_harbor,
)


def events():
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
                "arguments_json": '{"command":"printf ok","description":"test"}',
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
                "output": "ok\nexit: 0",
            },
        ),
        ("assistant.final", {"text": "done"}),
        ("run.completed", {"code": "completed"}),
    ]
    return [
        {**common, "seq": seq, "type": event_type, "data": data}
        for seq, (event_type, data) in enumerate(bodies)
    ]


def run_record():
    return {
        "run_id": "run-1",
        "trial_id": "trial-1",
        "attempt_id": "attempt-0",
        "run_spec_sha256": "a" * 64,
        "events_sha256": "b" * 64,
        "terminal_status": "success",
        "raw_usage": [
            {
                "input_tokens": 10,
                "output_tokens": 3,
                "input_tokens_details": {"cached_tokens": 2},
            }
        ],
    }


def test_projects_instruction_tool_result_and_final() -> None:
    trajectory = project_trajectory(
        instruction="Create the proof.",
        events=events(),
        run_record=run_record(),
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
    )
    validate_minimal_trajectory(trajectory)
    assert [step["source"] for step in trajectory["steps"]] == [
        "user",
        "agent",
        "agent",
    ]
    tool = trajectory["steps"][1]
    assert tool["tool_calls"][0]["tool_call_id"] == "call-1"
    assert tool["observation"]["results"][0]["content"] == "ok\nexit: 0"
    assert trajectory["final_metrics"]["total_prompt_tokens"] == 10


def test_projects_bounded_semantic_checkpoint_audit_receipts() -> None:
    checkpoint_events = events()
    checkpoint_events[-2:-2] = [
        {
            **checkpoint_events[0],
            "seq": 4,
            "type": "context.checkpointed",
            "data": {
                "policy_version": "semantic-context-checkpoint-v1",
                "provider_turn_count": 16,
                "prepare_turn_index": 15,
                "source_history_sha256": "a" * 64,
                "prepare_history_sha256": "b" * 64,
                "checkpoint_history_sha256": "c" * 64,
                "capsule_schema_version": "semantic-checkpoint-capsule-v1",
                "capsule_sha256": "d" * 64,
                "capsule_bytes": 1024,
                "action_turn_cutoff": 40,
                "action_lease_ms": 299_000,
                "tail_reserve_ms": 900_000,
            },
        },
        {
            **checkpoint_events[0],
            "seq": 5,
            "type": "context.checkpoint_rejected",
            "data": {
                "policy_version": "semantic-context-checkpoint-v1",
                "provider_turn_count": 17,
                "prepare_turn_index": 16,
                "source_history_sha256": "e" * 64,
                "prepare_history_sha256": "f" * 64,
                "reason": "semantic_checkpoint_capsule_json_invalid",
                "request_emitted": True,
                "response_received": True,
                "capsule_content_sha256": "1" * 64,
                "capsule_content_bytes": 3,
                "capsule_content_excerpt": "bad",
            },
        },
    ]
    for seq, event in enumerate(checkpoint_events):
        event["seq"] = seq

    trajectory = project_trajectory(
        instruction="Create the proof.",
        events=checkpoint_events,
        run_record=run_record(),
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
    )

    receipts = trajectory["extra"]["semantic_checkpoint_receipts"]
    assert [receipt["outcome"] for receipt in receipts] == ["accepted", "rejected"]
    assert receipts[0]["capsule_sha256"] == "d" * 64
    assert receipts[1]["capsule_content_sha256"] == "1" * 64
    assert "capsule_content_excerpt" not in receipts[1]


def test_refuses_incomplete_call() -> None:
    incomplete = [event for event in events() if event["type"] != "tool.completed"]
    try:
        project_trajectory(
            instruction="Create the proof.",
            events=incomplete,
            run_record=run_record(),
            agent_name="nano-grok-build",
            agent_version="test",
            model_name="synthetic-model",
        )
    except AtifError as error:
        assert str(error) == "atif_incomplete_tool_call"
    else:
        raise AssertionError("incomplete calls must not project")


def test_success_projection_refuses_in_flight_provider_operation() -> None:
    unfinished = events()
    terminal = unfinished[-1]
    unfinished.insert(
        -1,
        {
            **{
                key: terminal[key]
                for key in (
                    "schema_version",
                    "run_id",
                    "trial_id",
                    "attempt_id",
                    "elapsed_ms",
                )
            },
            "seq": terminal["seq"],
            "type": "provider.requested",
            "data": {
                "turn_index": 9,
                "history_item_count": 1,
                "tool_count": 1,
                "function_output_call_ids": [],
            },
        },
    )
    unfinished[-1] = {**terminal, "seq": terminal["seq"] + 1}

    with pytest.raises(AtifError, match="^atif_incomplete_provider_call$"):
        project_trajectory(
            instruction="Create the proof.",
            events=unfinished,
            run_record=run_record(),
            agent_name="nano-grok-build",
            agent_version="test",
            model_name="synthetic-model",
        )


def test_success_projection_accepts_only_event_bound_checkpoint_prepare_timeout() -> (
    None
):
    recovered = events()
    terminal = recovered[-1]
    common = {
        key: terminal[key]
        for key in (
            "schema_version",
            "run_id",
            "trial_id",
            "attempt_id",
            "elapsed_ms",
        )
    }
    recovered[-1:-1] = [
        {
            **common,
            "seq": terminal["seq"],
            "type": "provider.requested",
            "data": {
                "turn_index": 9,
                "history_item_count": 12,
                "tool_count": 0,
                "function_output_call_ids": [],
            },
        },
        {
            **common,
            "seq": terminal["seq"] + 1,
            "type": "provider.failed",
            "data": {
                "turn_index": 9,
                "code": "provider_semantic_checkpoint_deadline_exceeded",
            },
        },
        {
            **common,
            "seq": terminal["seq"] + 2,
            "type": "context.checkpoint_rejected",
            "data": {
                "policy_version": "semantic-context-checkpoint-v1",
                "prepare_turn_index": 9,
                "provider_turn_count": 10,
                "reason": "provider_semantic_checkpoint_deadline_exceeded",
                "request_emitted": True,
                "response_received": False,
            },
        },
    ]
    recovered[-1] = {**terminal, "seq": terminal["seq"] + 3}

    trajectory = project_trajectory(
        instruction="Create the proof.",
        events=recovered,
        run_record=run_record(),
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
    )

    assert trajectory["extra"]["recoverable_provider_failures"] == [
        {
            "turn_index": 9,
            "code": "provider_semantic_checkpoint_deadline_exceeded",
            "checkpoint_policy_version": "semantic-context-checkpoint-v1",
        }
    ]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("policy_version", "fresh-context-checkpoint-v1"),
        ("prepare_turn_index", 8),
        ("provider_turn_count", 9),
        ("reason", "provider_total_timeout"),
        ("request_emitted", False),
        ("response_received", True),
    ],
)
def test_success_projection_rejects_unbound_checkpoint_failure(
    field: str, value: object
) -> None:
    recovered = events()
    terminal = recovered[-1]
    common = {
        key: terminal[key]
        for key in (
            "schema_version",
            "run_id",
            "trial_id",
            "attempt_id",
            "elapsed_ms",
        )
    }
    rejection = {
        "policy_version": "semantic-context-checkpoint-v1",
        "prepare_turn_index": 9,
        "provider_turn_count": 10,
        "reason": "provider_semantic_checkpoint_deadline_exceeded",
        "request_emitted": True,
        "response_received": False,
    }
    rejection[field] = value
    recovered[-1:-1] = [
        {
            **common,
            "seq": terminal["seq"],
            "type": "provider.requested",
            "data": {
                "turn_index": 9,
                "history_item_count": 12,
                "tool_count": 0,
                "function_output_call_ids": [],
            },
        },
        {
            **common,
            "seq": terminal["seq"] + 1,
            "type": "provider.failed",
            "data": {
                "turn_index": 9,
                "code": "provider_semantic_checkpoint_deadline_exceeded",
            },
        },
        {
            **common,
            "seq": terminal["seq"] + 2,
            "type": "context.checkpoint_rejected",
            "data": rejection,
        },
    ]
    recovered[-1] = {**terminal, "seq": terminal["seq"] + 3}

    with pytest.raises(AtifError, match="^atif_failed_provider_call$"):
        project_trajectory(
            instruction="Create the proof.",
            events=recovered,
            run_record=run_record(),
            agent_name="nano-grok-build",
            agent_version="test",
            model_name="synthetic-model",
        )


def test_failed_projection_preserves_in_flight_operations_without_invention() -> None:
    prefix = events()[:2]
    prefix.insert(
        1,
        {
            **{
                key: prefix[0][key]
                for key in (
                    "schema_version",
                    "run_id",
                    "trial_id",
                    "attempt_id",
                    "elapsed_ms",
                )
            },
            "seq": 1,
            "type": "provider.requested",
            "data": {
                "turn_index": 0,
                "history_item_count": 1,
                "tool_count": 1,
                "function_output_call_ids": [],
            },
        },
    )
    prefix[2] = {**prefix[2], "seq": 2}
    prefix.append(
        {
            **{
                key: prefix[0][key]
                for key in (
                    "schema_version",
                    "run_id",
                    "trial_id",
                    "attempt_id",
                    "elapsed_ms",
                )
            },
            "seq": 3,
            "type": "run.failed",
            "data": {"code": "provider_final_deadline_exceeded"},
        }
    )
    failed_record = {
        **run_record(),
        "terminal_status": "deadline_failure",
        "terminal_phase": "deadline",
        "terminal_code": "provider_final_deadline_exceeded",
        "provider_call_coverage": {
            "requested": 1,
            "completed": 0,
            "failed": 0,
            "in_flight": 1,
            "usage_present": 0,
            "usage_absent": 0,
            "usage_covered": 0,
            "cost_present": 0,
            "cost_absent": 0,
            "state": "partial",
        },
        "usage_totals": {
            "input_tokens": None,
            "cached_input_tokens": None,
            "output_tokens": None,
            "provider_cost_ticks": None,
        },
    }

    trajectory = project_partial_trajectory(
        instruction="Create the proof.",
        events=prefix,
        run_record=failed_record,
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
    )

    assert trajectory["provider_turns"] == [
        {
            "turn_index": 0,
            "state": "in_flight",
            "requested": {
                "history_item_count": 1,
                "tool_count": 1,
                "function_output_call_ids": [],
            },
        }
    ]
    assert trajectory["tool_calls"][0]["state"] == "in_flight"
    assert "observation" not in trajectory["tool_calls"][0]
    assert trajectory["assistant_final"] is None


@pytest.mark.parametrize(
    ("terminal_status", "terminal_phase", "terminal_code", "settlement"),
    [
        ("provider_failure", "provider", "provider_transport_timeout", "provider"),
        ("tool_failure", "tool", "terminal_actor_cleanup_unverified", "tool"),
        ("deadline_failure", "deadline", "run_deadline_exceeded", "registered"),
    ],
)
def test_failure_atif_is_truthful_for_provider_tool_deadline_and_registered_only(
    terminal_status: str,
    terminal_phase: str,
    terminal_code: str,
    settlement: str,
) -> None:
    common = {
        "schema_version": "event-v2",
        "run_id": "run-1",
        "trial_id": "trial-1",
        "attempt_id": "attempt-0",
        "elapsed_ms": 0,
    }
    bodies: list[tuple[str, dict[str, object]]] = [("run.started", {})]
    if settlement == "provider":
        bodies.extend(
            [
                (
                    "provider.requested",
                    {
                        "turn_index": 0,
                        "history_item_count": 1,
                        "tool_count": 1,
                        "function_output_call_ids": [],
                    },
                ),
                (
                    "provider.failed",
                    {"turn_index": 0, "code": terminal_code},
                ),
            ]
        )
    else:
        bodies.extend(
            [
                (
                    "tool.registered",
                    {
                        "call_id": "call-1",
                        "provider_name": "run_terminal_command",
                        "known": True,
                        "arguments_json": '{"command":"sleep 60"}',
                    },
                ),
            ]
        )
        if settlement == "tool":
            bodies.extend(
                [
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
                            "code": terminal_code,
                            "execution_may_have_started": True,
                            "cleanup_verified": False,
                            "census_verified": False,
                            "recoverability": "fatal",
                        },
                    ),
                ]
            )
    bodies.append(("run.failed", {"code": terminal_code}))
    prefix = [
        {**common, "seq": seq, "type": event_type, "data": data}
        for seq, (event_type, data) in enumerate(bodies)
    ]
    failed_record = {
        **run_record(),
        "terminal_status": terminal_status,
        "terminal_phase": terminal_phase,
        "terminal_code": terminal_code,
        "provider_call_coverage": {},
        "usage_totals": {},
    }

    trajectory = project_failure_trajectory(
        instruction="Create the proof.",
        events=prefix,
        run_record=failed_record,
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
    )

    validate_minimal_trajectory(trajectory)
    assert trajectory["schema_version"] == "ATIF-v1.7"
    assert trajectory["extra"]["terminal_failure"] == {
        "status": terminal_status,
        "phase": terminal_phase,
        "code": terminal_code,
        "event_seq": len(prefix) - 1,
        "elapsed_ms": 0,
    }
    assert all(step["message"] != "done" for step in trajectory["steps"])
    if settlement == "provider":
        assert trajectory["steps"] == [
            {"step_id": 1, "source": "user", "message": "Create the proof."}
        ]
    else:
        tool_step = trajectory["steps"][1]
        assert tool_step["tool_calls"][0]["tool_call_id"] == "call-1"
        assert "observation" not in tool_step
        assert tool_step["tool_calls"][0]["extra"]["state"] == (
            "failed" if settlement == "tool" else "in_flight"
        )


def test_empty_emergency_prefix_is_valid_atif_without_fabricated_agent_step() -> None:
    trajectory = project_emergency_trajectory(
        instruction="Create the proof.",
        events=[],
        identity={
            "run_id": "run-1",
            "trial_id": "trial-1",
            "attempt_id": "attempt-0",
            "run_spec_sha256": "a" * 64,
        },
        terminal_status="runtime_failure",
        terminal_phase="runtime",
        terminal_code="runtime_record_missing",
        usage_coverage={},
        usage_totals={},
        source_events_sha256="b" * 64,
        source_events_byte_length=0,
        validated_prefix_sha256="b" * 64,
        validated_prefix_byte_length=0,
        stop_reason="event_log_missing",
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
    )

    validate_minimal_trajectory(trajectory)
    assert trajectory["steps"] == [
        {"step_id": 1, "source": "user", "message": "Create the proof."}
    ]
    assert trajectory["extra"]["terminal_failure"]["evidence"] == ("adapter_emergency")


def test_pinned_harbor_conformance_uses_exact_version_and_validator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validated: list[dict[str, object]] = []

    class FakeValidator:
        errors: list[str] = []

        def validate(self, trajectory, *, validate_images):
            assert validate_images is True
            validated.append(trajectory)
            return True

    harbor = types.ModuleType("harbor")
    utils = types.ModuleType("harbor.utils")
    validator_module = types.ModuleType("harbor.utils.trajectory_validator")
    validator_module.TrajectoryValidator = FakeValidator
    monkeypatch.setitem(sys.modules, "harbor", harbor)
    monkeypatch.setitem(sys.modules, "harbor.utils", utils)
    monkeypatch.setitem(
        sys.modules,
        "harbor.utils.trajectory_validator",
        validator_module,
    )
    monkeypatch.setattr(atif.importlib.metadata, "version", lambda name: "0.20.0")
    trajectory = project_trajectory(
        instruction="Create the proof.",
        events=events(),
        run_record=run_record(),
        agent_name="nano-grok-build",
        agent_version="test",
        model_name="synthetic-model",
    )

    validate_with_pinned_harbor(trajectory)

    assert validated == [trajectory]
