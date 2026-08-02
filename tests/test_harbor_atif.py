from __future__ import annotations

import sys
import types

import pytest

from nano_grok_build.adapter import atif
from nano_grok_build.adapter.atif import (
    AtifError,
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
