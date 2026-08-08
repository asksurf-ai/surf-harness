"""ATIF-v1.7 projection from the runtime's committed event grammar."""

from __future__ import annotations

import importlib.metadata
import json
from collections.abc import Mapping, Sequence
from typing import Any

ATIF_VERSION = "ATIF-v1.7"
PARTIAL_TRAJECTORY_VERSION = "nano-partial-trajectory-v1"
HARBOR_VERSION = "0.20.0"
SEMANTIC_CHECKPOINT_POLICY_VERSION = "semantic-context-checkpoint-v1"
RECOVERABLE_SEMANTIC_CHECKPOINT_FAILURE = (
    "provider_semantic_checkpoint_deadline_exceeded"
)


class AtifError(ValueError):
    """A committed event prefix cannot be represented as minimal ATIF."""


def _recoverable_checkpoint_provider_failures(
    events: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Return fail-open checkpoint settlements that are fully event-bound.

    A semantic-checkpoint prepare timeout is internal control-plane work: the
    actor never observes a response, the runtime retains the source history,
    and the next normal provider request continues the run.  ATIF has no step
    shape for that invisible failed call, so a successful trajectory may omit
    it only when the committed event stream proves the exact typed recovery.
    """

    recovered: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        if event.get("type") != "provider.failed":
            continue
        data = event.get("data")
        if not isinstance(data, Mapping):
            continue
        turn_index = data.get("turn_index")
        code = data.get("code")
        if (
            not isinstance(turn_index, int)
            or isinstance(turn_index, bool)
            or code != RECOVERABLE_SEMANTIC_CHECKPOINT_FAILURE
            or index + 1 >= len(events)
        ):
            continue
        rejection = events[index + 1]
        rejection_data = rejection.get("data")
        if (
            rejection.get("type") != "context.checkpoint_rejected"
            or not isinstance(rejection_data, Mapping)
            or rejection_data.get("policy_version")
            != SEMANTIC_CHECKPOINT_POLICY_VERSION
            or rejection_data.get("prepare_turn_index") != turn_index
            or rejection_data.get("provider_turn_count") != turn_index + 1
            or rejection_data.get("reason") != code
            or rejection_data.get("request_emitted") is not True
            or rejection_data.get("response_received") is not False
        ):
            continue
        recovered.append(
            {
                "turn_index": turn_index,
                "code": code,
                "checkpoint_policy_version": SEMANTIC_CHECKPOINT_POLICY_VERSION,
            }
        )
    return recovered


def _semantic_checkpoint_receipts(
    events: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Expose bounded, event-bound checkpoint evidence for submission audit."""

    receipts: list[dict[str, Any]] = []
    common_fields = (
        "policy_version",
        "provider_turn_count",
        "prepare_turn_index",
        "source_history_sha256",
        "prepare_history_sha256",
    )
    accepted_fields = common_fields + (
        "checkpoint_history_sha256",
        "capsule_schema_version",
        "capsule_sha256",
        "capsule_bytes",
        "action_turn_cutoff",
        "action_lease_ms",
        "tail_reserve_ms",
    )
    rejected_fields = common_fields + (
        "reason",
        "request_emitted",
        "response_received",
        "capsule_content_sha256",
        "capsule_content_bytes",
    )
    for event in events:
        event_type = event.get("type")
        data = event.get("data")
        if (
            event_type not in {"context.checkpointed", "context.checkpoint_rejected"}
            or not isinstance(data, Mapping)
            or data.get("policy_version") != SEMANTIC_CHECKPOINT_POLICY_VERSION
        ):
            continue
        outcome = "accepted" if event_type == "context.checkpointed" else "rejected"
        fields = accepted_fields if outcome == "accepted" else rejected_fields
        receipts.append(
            {
                "outcome": outcome,
                **{field: data[field] for field in fields if field in data},
            }
        )
    return receipts


def _tool_step(step_id: int, event: Mapping[str, Any]) -> dict[str, Any]:
    data = event["data"]
    try:
        arguments = json.loads(data["arguments_json"])
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise AtifError("atif_tool_arguments_invalid") from error
    if not isinstance(arguments, dict):
        raise AtifError("atif_tool_arguments_invalid")
    completion = data["completion"]
    return {
        "step_id": step_id,
        "source": "agent",
        "model_name": event["model_name"],
        "message": "",
        "tool_calls": [
            {
                "tool_call_id": data["call_id"],
                "function_name": data["provider_name"],
                "arguments": arguments,
            }
        ],
        "observation": {
            "results": [
                {
                    "source_call_id": data["call_id"],
                    "content": completion["output"],
                    "extra": {
                        "execution_attempted": completion["execution_attempted"],
                        "outcome": completion["outcome"],
                    },
                }
            ]
        },
        "llm_call_count": 1,
    }


def project_trajectory(
    *,
    instruction: str,
    events: Sequence[Mapping[str, Any]],
    run_record: Mapping[str, Any],
    agent_name: str,
    agent_version: str,
    model_name: str,
) -> dict[str, Any]:
    """Project a completed successful runtime; never infer missing events."""

    if not instruction:
        raise AtifError("atif_instruction_missing")
    if run_record.get("terminal_status") != "success":
        raise AtifError("atif_run_not_successful")
    if not events or events[-1].get("type") != "run.completed":
        raise AtifError("atif_success_terminal_missing")
    provider_states: dict[int, str] = {}
    provider_failures: dict[int, str] = {}
    registered: dict[str, Mapping[str, Any]] = {}
    completed: dict[str, Mapping[str, Any]] = {}
    final_text: str | None = None
    for event in events:
        event_type = event["type"]
        data = event["data"]
        if event_type == "provider.requested":
            turn_index = data["turn_index"]
            if turn_index in provider_states:
                raise AtifError("atif_duplicate_provider_request")
            provider_states[turn_index] = "in_flight"
        elif event_type in {"provider.completed", "provider.failed"}:
            turn_index = data["turn_index"]
            if provider_states.get(turn_index) != "in_flight":
                raise AtifError("atif_orphan_provider_settlement")
            provider_states[turn_index] = event_type.removeprefix("provider.")
            if event_type == "provider.failed":
                provider_failures[turn_index] = data["code"]
        elif event_type == "tool.registered":
            call_id = data["call_id"]
            if call_id in registered:
                raise AtifError("atif_duplicate_tool_registration")
            registered[call_id] = event
        elif event_type == "tool.completed":
            call_id = data["call_id"]
            if call_id not in registered or call_id in completed:
                raise AtifError("atif_orphan_tool_completion")
            completed[call_id] = event
        elif event_type == "assistant.final":
            if final_text is not None:
                raise AtifError("atif_duplicate_final")
            final_text = data["text"]
    if any(state == "in_flight" for state in provider_states.values()):
        raise AtifError("atif_incomplete_provider_call")
    recovered_provider_failures = _recoverable_checkpoint_provider_failures(events)
    semantic_checkpoint_receipts = _semantic_checkpoint_receipts(events)
    recovered_turns = {
        recovery["turn_index"]: recovery["code"]
        for recovery in recovered_provider_failures
    }
    if provider_failures != recovered_turns:
        raise AtifError("atif_failed_provider_call")
    if final_text is None:
        raise AtifError("atif_final_missing")
    if set(registered) != set(completed):
        raise AtifError("atif_incomplete_tool_call")

    steps: list[dict[str, Any]] = [
        {"step_id": 1, "source": "user", "message": instruction}
    ]
    for call_id, registration in registered.items():
        completion = completed[call_id]
        joined = {
            **registration,
            "model_name": model_name,
            "data": {
                **registration["data"],
                "completion": completion["data"],
            },
        }
        steps.append(_tool_step(len(steps) + 1, joined))
    steps.append(
        {
            "step_id": len(steps) + 1,
            "source": "agent",
            "model_name": model_name,
            "message": final_text,
            "llm_call_count": 1,
        }
    )
    usage = _usage_totals(run_record)
    trajectory = {
        "schema_version": ATIF_VERSION,
        "session_id": run_record["run_id"],
        "agent": {
            "name": agent_name,
            "version": agent_version,
            "model_name": model_name,
        },
        "steps": steps,
        "final_metrics": {
            **usage,
            "total_steps": len(steps),
        },
        "extra": {
            "trial_id": run_record["trial_id"],
            "attempt_id": run_record["attempt_id"],
            "run_spec_sha256": run_record["run_spec_sha256"],
            "events_sha256": run_record["events_sha256"],
            **(
                {"recoverable_provider_failures": recovered_provider_failures}
                if recovered_provider_failures
                else {}
            ),
            **(
                {"semantic_checkpoint_receipts": semantic_checkpoint_receipts}
                if semantic_checkpoint_receipts
                else {}
            ),
        },
    }
    validate_minimal_trajectory(trajectory)
    return trajectory


def _usage_totals(run_record: Mapping[str, Any]) -> dict[str, int]:
    totals = {
        "total_prompt_tokens": 0,
        "total_completion_tokens": 0,
        "total_cached_tokens": 0,
    }
    v2_totals = run_record.get("usage_totals")
    if isinstance(v2_totals, dict):
        for target, source in (
            ("total_prompt_tokens", "input_tokens"),
            ("total_completion_tokens", "output_tokens"),
            ("total_cached_tokens", "cached_input_tokens"),
        ):
            value = v2_totals.get(source)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                totals[target] = value
        return totals

    raw_usage = run_record.get("raw_usage", [])
    if not isinstance(raw_usage, list):
        return totals
    for usage in raw_usage:
        if not isinstance(usage, dict):
            continue
        prompt = usage.get("input_tokens", 0)
        completion = usage.get("output_tokens", 0)
        details = usage.get("input_tokens_details", {})
        cached = details.get("cached_tokens", 0) if isinstance(details, dict) else 0
        for target, value in (
            ("total_prompt_tokens", prompt),
            ("total_completion_tokens", completion),
            ("total_cached_tokens", cached),
        ):
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                totals[target] += value
    return totals


def _arguments_object(raw: object) -> dict[str, Any]:
    if not isinstance(raw, str):
        raise AtifError("partial_tool_arguments_invalid")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise AtifError("partial_tool_arguments_duplicate_field")
            value[key] = item
        return value

    try:
        value = json.loads(raw, object_pairs_hook=no_duplicates)
    except AtifError:
        raise
    except (TypeError, json.JSONDecodeError) as error:
        raise AtifError("partial_tool_arguments_invalid") from error
    if not isinstance(value, dict):
        raise AtifError("partial_tool_arguments_invalid")
    return value


def _prefix_projection(
    events: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str | None]:
    provider_turns: dict[int, dict[str, Any]] = {}
    tool_calls: dict[str, dict[str, Any]] = {}
    assistant_final: str | None = None

    for event in events:
        event_type = event["type"]
        data = event["data"]
        if event_type == "provider.requested":
            turn_index = data["turn_index"]
            if turn_index in provider_turns:
                raise AtifError("partial_duplicate_provider_request")
            provider_turns[turn_index] = {
                "turn_index": turn_index,
                "state": "in_flight",
                "requested": {
                    "history_item_count": data["history_item_count"],
                    "tool_count": data["tool_count"],
                    "function_output_call_ids": data["function_output_call_ids"],
                },
            }
        elif event_type == "provider.completed":
            turn_index = data["turn_index"]
            turn = provider_turns.get(turn_index)
            if turn is None or turn["state"] != "in_flight":
                raise AtifError("partial_orphan_provider_completion")
            turn["state"] = "completed"
            turn["completion"] = {
                "response_id": data["response_id"],
                "model": data["model"],
                "call_ids": data["call_ids"],
                "has_final_text": data["has_final_text"],
                "usage_present": data["usage"] is not None,
            }
        elif event_type == "provider.failed":
            turn_index = data["turn_index"]
            turn = provider_turns.get(turn_index)
            if turn is None or turn["state"] != "in_flight":
                raise AtifError("partial_orphan_provider_failure")
            turn["state"] = "failed"
            turn["failure"] = {"code": data["code"]}
        elif event_type == "tool.registered":
            call_id = data["call_id"]
            if call_id in tool_calls:
                raise AtifError("partial_duplicate_tool_registration")
            tool_calls[call_id] = {
                "call_id": call_id,
                "function_name": data["provider_name"],
                "arguments": _arguments_object(data["arguments_json"]),
                "known": data["known"],
                "state": "in_flight",
                "dispatched": False,
            }
        elif event_type == "tool.dispatched":
            call_id = data["call_id"]
            call = tool_calls.get(call_id)
            if (
                call is None
                or call["function_name"] != data["provider_name"]
                or call["dispatched"]
                or call["state"] != "in_flight"
            ):
                raise AtifError("partial_orphan_tool_dispatch")
            call["dispatched"] = True
        elif event_type == "tool.completed":
            call_id = data["call_id"]
            call = tool_calls.get(call_id)
            if (
                call is None
                or call["function_name"] != data["provider_name"]
                or call["state"] != "in_flight"
            ):
                raise AtifError("partial_orphan_tool_completion")
            call["state"] = "completed"
            call["observation"] = {
                "execution_attempted": data["execution_attempted"],
                "outcome": data["outcome"],
                "output": data["output"],
            }
        elif event_type == "tool.failed":
            call_id = data["call_id"]
            call = tool_calls.get(call_id)
            if (
                call is None
                or call["function_name"] != data["provider_name"]
                or call["state"] != "in_flight"
            ):
                raise AtifError("partial_orphan_tool_failure")
            call["state"] = "failed"
            call["failure"] = {
                "code": data["code"],
                "execution_may_have_started": data["execution_may_have_started"],
                "cleanup_verified": data["cleanup_verified"],
                "census_verified": data["census_verified"],
                "recoverability": data["recoverability"],
            }
        elif event_type == "assistant.final":
            if assistant_final is not None:
                raise AtifError("partial_duplicate_final")
            assistant_final = data["text"]
    return list(provider_turns.values()), list(tool_calls.values()), assistant_final


def _prefix_atif_steps(
    *,
    instruction: str,
    tool_calls: Sequence[Mapping[str, Any]],
    assistant_final: str | None,
    model_name: str,
) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = [
        {"step_id": 1, "source": "user", "message": instruction}
    ]
    for call in tool_calls:
        tool_call: dict[str, Any] = {
            "tool_call_id": call["call_id"],
            "function_name": call["function_name"],
            "arguments": call["arguments"],
            "extra": {
                "known": call["known"],
                "state": call["state"],
                "dispatched": call["dispatched"],
            },
        }
        failure = call.get("failure")
        if isinstance(failure, dict):
            tool_call["extra"]["failure"] = dict(failure)
        step: dict[str, Any] = {
            "step_id": len(steps) + 1,
            "source": "agent",
            "model_name": model_name,
            "message": "",
            "tool_calls": [tool_call],
        }
        observation = call.get("observation")
        if isinstance(observation, dict):
            step["observation"] = {
                "results": [
                    {
                        "source_call_id": call["call_id"],
                        "content": observation["output"],
                        "extra": {
                            "execution_attempted": observation["execution_attempted"],
                            "outcome": observation["outcome"],
                        },
                    }
                ]
            }
        steps.append(step)
    if assistant_final is not None:
        steps.append(
            {
                "step_id": len(steps) + 1,
                "source": "agent",
                "model_name": model_name,
                "message": assistant_final,
            }
        )
    return steps


def _prefix_atif_trajectory(
    *,
    instruction: str,
    events: Sequence[Mapping[str, Any]],
    identity: Mapping[str, Any],
    terminal_failure: Mapping[str, Any],
    usage_source: Mapping[str, Any],
    agent_name: str,
    agent_version: str,
    model_name: str,
    source_kind: str,
    event_prefix: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not instruction:
        raise AtifError("atif_instruction_missing")
    provider_turns, tool_calls, assistant_final = _prefix_projection(events)
    steps = _prefix_atif_steps(
        instruction=instruction,
        tool_calls=tool_calls,
        assistant_final=assistant_final,
        model_name=model_name,
    )
    extra: dict[str, Any] = {
        "trial_id": identity["trial_id"],
        "attempt_id": identity["attempt_id"],
        "run_spec_sha256": identity["run_spec_sha256"],
        "source_kind": source_kind,
        "terminal_failure": dict(terminal_failure),
        "provider_turns": provider_turns,
    }
    events_sha256 = identity.get("events_sha256")
    if isinstance(events_sha256, str):
        extra["events_sha256"] = events_sha256
    if event_prefix is not None:
        extra["event_prefix"] = dict(event_prefix)
    trajectory = {
        "schema_version": ATIF_VERSION,
        "session_id": identity["run_id"],
        "agent": {
            "name": agent_name,
            "version": agent_version,
            "model_name": model_name,
        },
        "steps": steps,
        "final_metrics": {
            **_usage_totals(usage_source),
            "total_steps": len(steps),
        },
        "extra": extra,
    }
    validate_minimal_trajectory(trajectory)
    return trajectory


def project_failure_trajectory(
    *,
    instruction: str,
    events: Sequence[Mapping[str, Any]],
    run_record: Mapping[str, Any],
    agent_name: str,
    agent_version: str,
    model_name: str,
) -> dict[str, Any]:
    """Project a committed terminal failure into truthful uploader-valid ATIF."""

    if run_record.get("terminal_status") == "success":
        raise AtifError("atif_failure_run_is_successful")
    if not events or events[-1].get("type") != "run.failed":
        raise AtifError("atif_failure_terminal_missing")
    terminal = events[-1]
    return _prefix_atif_trajectory(
        instruction=instruction,
        events=events,
        identity=run_record,
        terminal_failure={
            "status": run_record["terminal_status"],
            "phase": run_record["terminal_phase"],
            "code": run_record["terminal_code"],
            "event_seq": terminal["seq"],
            "elapsed_ms": terminal["elapsed_ms"],
        },
        usage_source=run_record,
        agent_name=agent_name,
        agent_version=agent_version,
        model_name=model_name,
        source_kind="committed_failure",
    )


def project_emergency_trajectory(
    *,
    instruction: str,
    events: Sequence[Mapping[str, Any]],
    identity: Mapping[str, Any],
    terminal_status: str,
    terminal_phase: str,
    terminal_code: str,
    usage_coverage: Mapping[str, Any],
    usage_totals: Mapping[str, Any],
    source_events_sha256: str,
    source_events_byte_length: int,
    validated_prefix_sha256: str,
    validated_prefix_byte_length: int,
    stop_reason: str,
    agent_name: str,
    agent_version: str,
    model_name: str,
) -> dict[str, Any]:
    """Project a validated emergency prefix without inventing a terminal turn."""

    last = events[-1] if events else None
    return _prefix_atif_trajectory(
        instruction=instruction,
        events=events,
        identity=identity,
        terminal_failure={
            "status": terminal_status,
            "phase": terminal_phase,
            "code": terminal_code,
            "event_seq": last["seq"] if last is not None else None,
            "elapsed_ms": last["elapsed_ms"] if last is not None else None,
            "evidence": "adapter_emergency",
        },
        usage_source={"usage_totals": dict(usage_totals)},
        agent_name=agent_name,
        agent_version=agent_version,
        model_name=model_name,
        source_kind="emergency_prefix",
        event_prefix={
            "source_sha256": source_events_sha256,
            "source_byte_length": source_events_byte_length,
            "validated_sha256": validated_prefix_sha256,
            "validated_byte_length": validated_prefix_byte_length,
            "last_valid_seq": last["seq"] if last is not None else None,
            "stop_reason": stop_reason,
            "usage_coverage": dict(usage_coverage),
        },
    )


def project_partial_trajectory(
    *,
    instruction: str,
    events: Sequence[Mapping[str, Any]],
    run_record: Mapping[str, Any],
    agent_name: str,
    agent_version: str,
    model_name: str,
) -> dict[str, Any]:
    """Project only evidence present in a committed failed event prefix.

    A partial trajectory is deliberately not ATIF: unresolved provider/tool
    operations remain unresolved and never receive invented observations or a
    fabricated assistant final.
    """

    if not instruction:
        raise AtifError("partial_instruction_missing")
    if run_record.get("terminal_status") == "success":
        raise AtifError("partial_run_not_failed")

    terminal = events[-1]
    if terminal["type"] != "run.failed":
        raise AtifError("partial_terminal_event_missing")
    provider_turns, tool_calls, assistant_final = _prefix_projection(events)
    return {
        "schema_version": PARTIAL_TRAJECTORY_VERSION,
        "session_id": run_record["run_id"],
        "agent": {
            "name": agent_name,
            "version": agent_version,
            "model_name": model_name,
        },
        "instruction": instruction,
        "provider_turns": provider_turns,
        "tool_calls": tool_calls,
        "assistant_final": assistant_final,
        "terminal_failure": {
            "status": run_record["terminal_status"],
            "phase": run_record["terminal_phase"],
            "code": run_record["terminal_code"],
            "event_seq": terminal["seq"],
            "elapsed_ms": terminal["elapsed_ms"],
        },
        "usage": {
            "provider_call_coverage": run_record["provider_call_coverage"],
            "usage_totals": run_record["usage_totals"],
        },
        "extra": {
            "trial_id": run_record["trial_id"],
            "attempt_id": run_record["attempt_id"],
            "run_spec_sha256": run_record["run_spec_sha256"],
            "events_sha256": run_record["events_sha256"],
        },
    }


def project_emergency_prefix(
    *,
    instruction: str,
    events: Sequence[Mapping[str, Any]],
    identity: Mapping[str, Any],
    terminal_status: str,
    terminal_phase: str,
    terminal_code: str,
    usage_coverage: Mapping[str, Any],
    usage_totals: Mapping[str, Any],
    source_events_sha256: str,
    source_events_byte_length: int,
    validated_prefix_sha256: str,
    validated_prefix_byte_length: int,
    stop_reason: str,
    agent_name: str,
    agent_version: str,
    model_name: str,
) -> dict[str, Any]:
    """Publish a truthful diagnostic prefix when no committed run record exists."""

    if not instruction:
        raise AtifError("emergency_instruction_missing")
    provider_turns, tool_calls, assistant_final = _prefix_projection(events)
    last = events[-1] if events else None
    return {
        "schema_version": "nano-emergency-prefix-v1",
        "session_id": identity["run_id"],
        "agent": {
            "name": agent_name,
            "version": agent_version,
            "model_name": model_name,
        },
        "instruction": instruction,
        "provider_turns": provider_turns,
        "tool_calls": tool_calls,
        "assistant_final": assistant_final,
        "terminal_failure": {
            "status": terminal_status,
            "phase": terminal_phase,
            "code": terminal_code,
            "event_seq": last["seq"] if last is not None else None,
            "elapsed_ms": last["elapsed_ms"] if last is not None else None,
            "evidence": "adapter_emergency",
        },
        "event_prefix": {
            "source_sha256": source_events_sha256,
            "source_byte_length": source_events_byte_length,
            "validated_sha256": validated_prefix_sha256,
            "validated_byte_length": validated_prefix_byte_length,
            "last_valid_seq": last["seq"] if last is not None else None,
            "stop_reason": stop_reason,
        },
        "usage": {
            "provider_call_coverage": dict(usage_coverage),
            "usage_totals": dict(usage_totals),
        },
        "extra": {
            "trial_id": identity["trial_id"],
            "attempt_id": identity["attempt_id"],
            "run_spec_sha256": identity["run_spec_sha256"],
        },
    }


def validate_minimal_trajectory(trajectory: Mapping[str, Any]) -> None:
    """Nano semantic checks in addition to Harbor's pinned Pydantic model."""

    if trajectory.get("schema_version") != ATIF_VERSION:
        raise AtifError("atif_schema_mismatch")
    if set(trajectory) != {
        "schema_version",
        "session_id",
        "agent",
        "steps",
        "final_metrics",
        "extra",
    }:
        raise AtifError("atif_root_fields_invalid")
    agent = trajectory.get("agent")
    if not isinstance(agent, dict) or not all(
        isinstance(agent.get(field), str) and agent[field]
        for field in ("name", "version", "model_name")
    ):
        raise AtifError("atif_agent_invalid")
    steps = trajectory.get("steps")
    if not isinstance(steps, list) or not steps:
        raise AtifError("atif_steps_invalid")
    extra = trajectory.get("extra")
    terminal_failure = (
        extra.get("terminal_failure") if isinstance(extra, dict) else None
    )
    for index, step in enumerate(steps, start=1):
        if not isinstance(step, dict) or step.get("step_id") != index:
            raise AtifError("atif_step_sequence_invalid")
        if step.get("source") not in {"user", "agent"}:
            raise AtifError("atif_step_source_invalid")
        if not isinstance(step.get("message"), str):
            raise AtifError("atif_step_message_invalid")
        calls = step.get("tool_calls", [])
        observation = step.get("observation")
        if calls:
            if not isinstance(calls, list) or len(calls) != 1:
                raise AtifError("atif_tool_calls_invalid")
            if not isinstance(observation, dict):
                call_extra = calls[0].get("extra")
                if (
                    terminal_failure is None
                    or not isinstance(call_extra, dict)
                    or call_extra.get("state") not in {"failed", "in_flight"}
                ):
                    raise AtifError("atif_tool_observation_missing")
                continue
            results = observation.get("results")
            if (
                not isinstance(results, list)
                or len(results) != 1
                or results[0].get("source_call_id") != calls[0].get("tool_call_id")
            ):
                raise AtifError("atif_tool_observation_invalid")
    if steps[0]["source"] != "user":
        raise AtifError("atif_boundary_steps_invalid")
    if terminal_failure is None and steps[-1]["source"] != "agent":
        raise AtifError("atif_boundary_steps_invalid")


def validate_with_pinned_harbor(trajectory: Mapping[str, Any]) -> None:
    """Require the exact pinned Harbor validator in the integration process."""

    try:
        version = importlib.metadata.version("harbor")
        from harbor.utils.trajectory_validator import TrajectoryValidator
    except (ImportError, importlib.metadata.PackageNotFoundError) as error:
        raise AtifError("atif_harbor_validator_unavailable") from error
    if version != HARBOR_VERSION:
        raise AtifError("atif_harbor_version_mismatch")
    validator = TrajectoryValidator()
    if not validator.validate(dict(trajectory), validate_images=True):
        raise AtifError("atif_harbor_validation_failed:" + "|".join(validator.errors))


def usage_context(trajectory: Mapping[str, Any]) -> dict[str, int]:
    metrics = trajectory.get("final_metrics")
    if isinstance(metrics, dict):
        return {
            "n_input_tokens": int(metrics.get("total_prompt_tokens", 0)),
            "n_cache_tokens": int(metrics.get("total_cached_tokens", 0)),
            "n_output_tokens": int(metrics.get("total_completion_tokens", 0)),
        }
    usage = trajectory.get("usage")
    totals = usage.get("usage_totals") if isinstance(usage, dict) else None
    if not isinstance(totals, dict):
        return {
            "n_input_tokens": 0,
            "n_cache_tokens": 0,
            "n_output_tokens": 0,
        }

    def known_nonnegative(name: str) -> int:
        value = totals.get(name)
        return (
            value
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0
            else 0
        )

    return {
        "n_input_tokens": known_nonnegative("input_tokens"),
        "n_cache_tokens": known_nonnegative("cached_input_tokens"),
        "n_output_tokens": known_nonnegative("output_tokens"),
    }
