from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from nano_grok_build.adapter import stdio_bridge as stdio_bridge_module
from nano_grok_build.adapter.artifactizer import (
    canonical_json,
    rust_run_spec_sha256,
)
from nano_grok_build.adapter.deadline import (
    DeadlineContractError,
    RunDeadlineReceiptV1,
    RunDeadlineV1,
    host_monotonic,
    host_monotonic_ns,
)
from nano_grok_build.adapter.stdio_bridge import (
    LIVE_SCHEMA_VERSION,
    MAX_REQUEST_LINE_BYTES,
    BridgeError,
    ProcessDisposition,
    SettlementStageCutoffsV1,
    ToolExecution,
    ToolRequest,
    _preflight_response_serialization,
    _response_line_limit_bytes,
    _strict_remaining_sec,
    _validate_live_request_binding,
    _write_response_before_drain_cutoff,
    parse_tool_request,
    run_stdio_bridge,
)
from nano_grok_build.adapter.terminal_actor import BackgroundTask, RemoteTerminalActor
from nano_grok_build.harbor.git_history_capability import (
    compile_git_history_capability,
)


def _v3_request_value(
    *,
    hard_deadline_monotonic_ns: int = 95_000_000_000,
) -> dict[str, object]:
    cleanup_start = hard_deadline_monotonic_ns - 20_000_000_000
    runtime_final = cleanup_start - 15_000_000_000
    tool_settled = runtime_final - 30_000_000_000
    actor_done = tool_settled - 10_000_000_000
    return {
        "schema_version": LIVE_SCHEMA_VERSION,
        "message_type": "tool.request",
        "seq": 0,
        "run_id": "run",
        "trial_id": "trial",
        "attempt_id": "attempt",
        "call_id": "call",
        "tool_name": "get_terminal_command_output",
        "arguments_json": '{"task_ids":["task"],"timeout_ms":300000}',
        "logical_cwd": "/workspace",
        "operation_timeout_ms": 300_000,
        "term_grace_ms": 5_000,
        "kill_confirmation_timeout_ms": 5_000,
        "stdout_cap_bytes": 1024,
        "stderr_cap_bytes": 1024,
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
            "arguments_cap_bytes": 1024 * 1024,
            "max_path_bytes": 4096,
            "max_read_or_write_bytes": 1024 * 1024,
            "max_directory_entries": 100,
            "max_grep_matches": 100,
            "max_replacements": 100,
            "max_background_processes": 8,
            "process_spool_bytes_per_process": 1024 * 1024,
            "process_spool_bytes_per_run": 8 * 1024 * 1024,
            "background_output_wait_max_ms": 600_000,
        },
        "actor_done_monotonic_ns": actor_done,
        "tool_settled_monotonic_ns": tool_settled,
        "last_send_monotonic_ns": runtime_final,
        "runtime_final_monotonic_ns": runtime_final,
        "cleanup_start_monotonic_ns": cleanup_start,
        "hard_deadline_monotonic_ns": hard_deadline_monotonic_ns,
        "cleanup_reserve_ms": 20_000,
        "terminalization_reserve_ms": 15_000,
        "provider_send_reserve_ms": 30_000,
        "process_settlement_reserve_ms": 10_000,
        "deadline_receipt_sha256": hashlib.sha256(b"receipt").hexdigest(),
    }


def _parse(value: dict[str, object]) -> ToolRequest:
    return parse_tool_request(
        json.dumps(value, separators=(",", ":")).encode(),
        allow_legacy_v2=False,
    )


def test_wire_deadline_clock_is_the_os_clock_monotonic_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    observed = host_monotonic_ns()
    assert abs(observed - expected) < 100_000_000

    def unavailable(_clock_id: int) -> int:
        raise OSError("unsupported")

    monkeypatch.setattr(time, "clock_gettime_ns", unavailable)
    with pytest.raises(DeadlineContractError, match="deadline_clock_unavailable"):
        host_monotonic_ns()


def test_v3_request_separates_semantic_cap_from_absolute_envelope() -> None:
    request = _parse(_v3_request_value())
    assert request.timeout_ms == 300_000
    assert request.actor_done_monotonic_ns == 20_000_000_000
    assert request.tool_settled_monotonic_ns == 30_000_000_000
    assert request.runtime_final_monotonic_ns == 60_000_000_000


@pytest.mark.parametrize("settlement_ms", [6, 7, 10_000, 10_003])
def test_settlement_v1_derives_one_ordered_nonborrowable_stage_vector(
    settlement_ms: int,
) -> None:
    actor_done = 11_000_000_000
    tool_settled = actor_done + settlement_ms * 1_000_000
    stages = SettlementStageCutoffsV1.derive(
        actor_done_monotonic_ns=actor_done,
        tool_settled_monotonic_ns=tool_settled,
        process_settlement_reserve_ms=settlement_ms,
    )

    ordered = (
        stages.probe_monotonic_ns,
        stages.output_monotonic_ns,
        stages.encode_monotonic_ns,
        stages.drain_monotonic_ns,
        stages.parse_monotonic_ns,
        stages.history_commit_monotonic_ns,
    )
    assert ordered == tuple(
        actor_done + (tool_settled - actor_done) * index // 6 for index in range(1, 7)
    )
    assert actor_done < ordered[0] < ordered[1] < ordered[2]
    assert ordered[2] < ordered[3] < ordered[4] < ordered[5]
    assert ordered[-1] == tool_settled


def test_settlement_v1_rejects_too_small_or_unbound_span() -> None:
    with pytest.raises(BridgeError, match="external_request_settlement_budget_invalid"):
        SettlementStageCutoffsV1.derive(
            actor_done_monotonic_ns=1_000_000_000,
            tool_settled_monotonic_ns=1_005_000_000,
            process_settlement_reserve_ms=5,
        )
    with pytest.raises(BridgeError, match="external_request_settlement_budget_invalid"):
        SettlementStageCutoffsV1.derive(
            actor_done_monotonic_ns=1_000_000_000,
            tool_settled_monotonic_ns=1_007_000_001,
            process_settlement_reserve_ms=7,
        )


def test_live_deadline_fields_accept_u64_and_reject_reserve_nanosecond_overflow() -> (
    None
):
    maximum = 2**64 - 1
    value = _v3_request_value(hard_deadline_monotonic_ns=maximum)
    request = _parse(value)
    assert request.hard_deadline_monotonic_ns == maximum
    assert request.actor_done_monotonic_ns == maximum - 75_000_000_000

    overflowing_reserve = maximum // 1_000_000 + 1
    with pytest.raises(
        BridgeError,
        match="external_request_settlement_budget_invalid",
    ):
        SettlementStageCutoffsV1.derive(
            actor_done_monotonic_ns=1,
            tool_settled_monotonic_ns=1 + overflowing_reserve * 1_000_000,
            process_settlement_reserve_ms=overflowing_reserve,
        )


@pytest.mark.parametrize("stage_index", range(1, 7))
def test_settlement_shared_boundaries_are_strict_at_minus_zero_plus_one_ms(
    stage_index: int,
) -> None:
    stages = SettlementStageCutoffsV1.derive(
        actor_done_monotonic_ns=20_000_000_000,
        tool_settled_monotonic_ns=30_000_000_000,
        process_settlement_reserve_ms=10_000,
    )
    cutoff = (
        stages.probe_monotonic_ns,
        stages.output_monotonic_ns,
        stages.encode_monotonic_ns,
        stages.drain_monotonic_ns,
        stages.parse_monotonic_ns,
        stages.history_commit_monotonic_ns,
    )[stage_index - 1]
    assert _strict_remaining_sec(cutoff, cutoff - 1_000_000) == pytest.approx(0.001)
    assert _strict_remaining_sec(cutoff, cutoff) == 0.0
    assert _strict_remaining_sec(cutoff, cutoff + 1_000_000) == 0.0


@pytest.mark.parametrize(
    ("offset_ns", "expected_writes"),
    [(-1, 1), (0, 0), (1, 0)],
)
def test_response_write_is_strictly_before_drain_cutoff(
    offset_ns: int,
    expected_writes: int,
) -> None:
    class RecordingStdin:
        def __init__(self) -> None:
            self.writes: list[bytes] = []

        def write(self, value: bytes) -> None:
            self.writes.append(value)

    cutoff = 50_000_000_000
    stdin = RecordingStdin()
    if expected_writes:
        _write_response_before_drain_cutoff(
            stdin,
            b"response",
            drain_cutoff_monotonic_ns=cutoff,
            monotonic_ns=lambda: cutoff + offset_ns,
        )
    else:
        with pytest.raises(
            BridgeError,
            match="response_serialization_deadline_exceeded",
        ):
            _write_response_before_drain_cutoff(
                stdin,
                b"response",
                drain_cutoff_monotonic_ns=cutoff,
                monotonic_ns=lambda: cutoff + offset_ns,
            )
    assert len(stdin.writes) == expected_writes


def test_response_write_postcheck_fails_if_sync_write_reaches_drain_cutoff() -> None:
    class RecordingStdin:
        def __init__(self) -> None:
            self.writes: list[bytes] = []

        def write(self, value: bytes) -> None:
            self.writes.append(value)

    cutoff = 50_000_000_000
    readings = iter((cutoff - 1, cutoff))
    stdin = RecordingStdin()
    with pytest.raises(
        BridgeError,
        match="response_serialization_deadline_exceeded",
    ):
        _write_response_before_drain_cutoff(
            stdin,
            b"response",
            drain_cutoff_monotonic_ns=cutoff,
            monotonic_ns=lambda: next(readings),
        )
    assert stdin.writes == [b"response\n"]


def test_v3_request_is_bound_to_the_one_immutable_receipt() -> None:
    deadline = RunDeadlineV1.mint(
        source="test_host_phase",
        agent_timeout_ms=95_000,
        now_monotonic_ns=10_000_000_000,
    )
    receipt = RunDeadlineReceiptV1.bind(
        deadline=deadline,
        run_id="run",
        trial_id="trial",
        attempt_id="attempt",
        run_spec_sha256="a" * 64,
    )
    value = _v3_request_value(
        hard_deadline_monotonic_ns=deadline.hard_deadline_monotonic_ns
    )
    value["deadline_receipt_sha256"] = receipt.sha256()
    request = _parse(value)

    _validate_live_request_binding(request, receipt)

    value["trial_id"] = "replayed-trial"
    with pytest.raises(
        BridgeError,
        match="external_request_deadline_binding_invalid",
    ):
        _validate_live_request_binding(_parse(value), receipt)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.pop("actor_done_monotonic_ns"),
        lambda value: value.update({"unknown": True}),
        lambda value: value.update({"provider_send_reserve_ms": 29_999}),
        lambda value: value.update(
            {"actor_done_monotonic_ns": value["tool_settled_monotonic_ns"]}
        ),
    ],
)
def test_v3_request_rejects_missing_unknown_or_inconsistent_deadline(
    mutation,
) -> None:
    value = _v3_request_value()
    mutation(value)
    with pytest.raises(BridgeError):
        _parse(value)


class _NoopRemote:
    async def exec(self, *_args, **_kwargs):
        raise AssertionError("deadline fixture overrides remote access")

    async def upload_file(self, *_args, **_kwargs):
        raise AssertionError("unexpected upload")

    async def download_file(self, *_args, **_kwargs):
        raise AssertionError("unexpected download")


class _StepClock:
    def __init__(self, value: float, step: float = 0.025) -> None:
        self.value = value
        self.step = step

    def __call__(self) -> float:
        current = self.value
        self.value += self.step
        return current


class _RunningStatusActor(RemoteTerminalActor):
    async def _prepare_request(self, _request: ToolRequest) -> None:
        return None

    async def _refresh_background_remote(
        self,
        task: BackgroundTask,
        request: ToolRequest | None = None,
    ) -> bool:
        task.status_fresh = True
        return True

    async def _render_single_background(
        self,
        task: BackgroundTask,
        request: ToolRequest,
    ) -> str:
        return f"Task {task.task_id} still running"


class _SlowDownloadRemote(_NoopRemote):
    async def download_file(self, *_args, **_kwargs):
        await asyncio.Event().wait()


class _SlowOutputActor(RemoteTerminalActor):
    async def _prepare_request(self, _request: ToolRequest) -> None:
        return None


def _local_contract_set_sha256(directory: Path) -> str:
    rows = []
    for name in (
        "agent-profile.json",
        "contract-delta.json",
        "effective-contract.json",
    ):
        raw = (directory / name).read_bytes()
        rows.append(
            {
                "path": name,
                "byte_length": len(raw),
                "file_sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    encoded = json.dumps(rows, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _write_live_composition_contract(directory: Path) -> None:
    helper_path = Path(__file__).parent / "harbor" / "run_synthetic.py"
    module_spec = importlib.util.spec_from_file_location(
        "_nano_test_run_synthetic",
        helper_path,
    )
    assert module_spec is not None and module_spec.loader is not None
    helper = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(helper)
    helper.write_synthetic_contract(
        directory,
        background_output_wait_max_ms=600_000,
    )

    profile_path = directory / "agent-profile.json"
    profile = json.loads(profile_path.read_bytes())
    profile["deadlines"].update(
        {
            "absolute_run_wall_cap_sec": 120,
            "terminalization_reserve_sec": 15,
            "min_provider_send_window_sec": 30,
            "process_control_timeout_sec": 10,
        }
    )
    profile["process"].update(
        {
            "term_grace_ms": 5_000,
            "kill_confirmation_timeout_ms": 5_000,
        }
    )
    profile_path.write_bytes(canonical_json(profile))


class _CompositionRemote:
    async def exec(self, *_args, **_kwargs):
        return SimpleNamespace(return_code=0, stdout="", stderr="")

    async def upload_file(self, *_args, **_kwargs):
        raise AssertionError("composition output poll must not upload")

    async def download_file(self, *_args, **_kwargs):
        await asyncio.Event().wait()


class _RecordingActorHandler:
    def __init__(self, actor: RemoteTerminalActor) -> None:
        self.actor = actor
        self.requests: list[ToolRequest] = []

    async def execute(self, request: ToolRequest):
        self.requests.append(request)
        return await self.actor.execute(request)

    async def cleanup_active(self) -> bool:
        return await self.actor.cleanup_active()

    async def cleanup_active_until(self, deadline_ns: int) -> bool:
        return await self.actor.cleanup_active_until(deadline_ns)


async def _run_real_slow_output_composition(tmp_path: Path) -> dict[str, object]:
    repo = Path(__file__).parents[1]
    binary = Path(
        os.environ.get(
            "NANO_GROK_BUILD_TEST_RUNTIME",
            str(repo / "target" / "debug" / "nano-cli"),
        )
    )
    if "NANO_GROK_BUILD_TEST_RUNTIME" not in os.environ:
        subprocess.run(
            ["cargo", "build", "-q", "-p", "nano-cli"],
            cwd=repo,
            check=True,
        )
    assert binary.is_file() and os.access(binary, os.X_OK)

    contract_dir = tmp_path / "contract"
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    _write_live_composition_contract(contract_dir)

    run_id = "run-live-composition-001"
    trial_id = "trial-live-composition-001"
    attempt_id = "attempt-0"
    spec = {
        "schema_version": "nano-run-spec-alpha-2",
        "run_id": run_id,
        "trial_id": trial_id,
        "attempt_id": attempt_id,
        "task": {
            "id": "synthetic-live-composition",
            "digest": "f" * 64,
            "instruction": "Poll the completed background task and finish.",
            "git_history_capability": compile_git_history_capability(
                "Poll the completed background task and finish.", "f" * 64
            ),
        },
        "contract": {
            "id": "synthetic-v1",
            "contract_set_sha256": _local_contract_set_sha256(contract_dir),
            "profile_id": "synthetic-profile-v1",
        },
        "provider": {
            "kind": "scripted",
            "model": "synthetic-model",
            "max_turns": 4,
            "retry_max": 0,
        },
        "workspace_dir": "/workspace",
        "artifact_dir": str(artifact_dir),
        "agent_timeout_sec": 120,
    }
    spec_path = tmp_path / "run-spec.json"
    spec_path.write_bytes(canonical_json(spec))

    task_id = "task-live-composition-001"
    call_id = "call-live-composition-001"
    script = {
        "schema_version": "scripted-provider-v1",
        "steps": [
            {
                "type": "completed",
                "response": {
                    "response_id": "response-live-composition-tool",
                    "model": "synthetic-model",
                    "output": [
                        {
                            "type": "function_call",
                            "call_id": call_id,
                            "name": "get_terminal_command_output",
                            "arguments_json": json.dumps(
                                {"task_ids": [task_id], "timeout_ms": 0},
                                separators=(",", ":"),
                            ),
                        }
                    ],
                    "usage": None,
                },
            },
            {
                "type": "completed",
                "response": {
                    "response_id": "response-live-composition-final",
                    "model": "synthetic-model",
                    "output": [
                        {
                            "type": "assistant_message",
                            "text": "live composition complete",
                        }
                    ],
                    "usage": None,
                },
            },
        ],
    }
    script_path = tmp_path / "script.json"
    script_path.write_bytes(canonical_json(script))

    actor = RemoteTerminalActor(_CompositionRemote())
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/workspace",
        "default_cwd": "/workspace",
        "logical_cwd": "/workspace",
        "mode": "existing_directory",
    }
    actor._background[task_id] = BackgroundTask(
        task_id=task_id,
        request_dir=f"/tmp/{task_id}",
        command="compile",
        logical_cwd="/workspace",
        output_path=f".nano/tasks/{task_id}.log",
        start_wall=time.time() - 1,
        start_monotonic=host_monotonic() - 1,
        runtime_timeout_ms=None,
        spool_cap_bytes=1024,
        term_grace_ms=5_000,
        kill_confirmation_timeout_ms=5_000,
        state="completed",
        exit_code=0,
        end_wall=time.time(),
        end_monotonic=host_monotonic(),
        leader_exited=True,
        census_verified=True,
    )
    handler = _RecordingActorHandler(actor)
    deadline = RunDeadlineV1.mint(
        source="test_host_phase",
        agent_timeout_ms=120_000,
        now_monotonic_ns=host_monotonic_ns(),
    )
    receipt = RunDeadlineReceiptV1.bind(
        deadline=deadline,
        run_id=run_id,
        trial_id=trial_id,
        attempt_id=attempt_id,
        run_spec_sha256=rust_run_spec_sha256(spec),
    )
    (artifact_dir / "deadline.json").write_bytes(receipt.to_bytes())
    outcome = await run_stdio_bridge(
        [
            str(binary),
            "run",
            "--spec",
            str(spec_path),
            "--contract-dir",
            str(contract_dir),
            "--provider",
            f"scripted:{script_path}",
            "--executor",
            "external-stdio",
            "--deadline-monotonic-ns",
            str(deadline.hard_deadline_monotonic_ns),
        ],
        handler,
        deadline_receipt=receipt,
    )
    events = [
        json.loads(line)
        for line in (artifact_dir / "events.jsonl").read_text().splitlines()
    ]
    assert len(handler.requests) == 1
    return {
        "request_count": outcome.request_count,
        "events": events,
        "run": json.loads((artifact_dir / "run.json").read_bytes()),
        "request": handler.requests[0],
        "deadline_receipt_sha256": receipt.sha256(),
    }


class _ConcurrentCleanupActor(RemoteTerminalActor):
    def __init__(self) -> None:
        super().__init__(_NoopRemote())
        self.entered = 0
        self.all_entered = asyncio.Event()
        self.release = asyncio.Event()
        self.phases: list[str] = []

    async def _wait_for_batch(self) -> None:
        self.entered += 1
        if self.entered == 9:
            self.all_entered.set()
        await self.release.wait()

    async def _signal_cleanup_process(
        self,
        _process_kind: str,
        _request_dir: str,
        signal_name: str,
        _cutoff_monotonic_ns: int,
        *,
        background_task: BackgroundTask | None = None,
    ) -> bool:
        del background_task
        self.phases.append(signal_name)
        if signal_name == "TERM":
            await self._wait_for_batch()
        return True

    async def _census_cleanup_process(
        self,
        _process_kind: str,
        _request_dir: str,
        _cutoff_monotonic_ns: int,
        *,
        background_task: BackgroundTask | None = None,
    ) -> bool:
        del background_task
        self.phases.append("CENSUS")
        return True


def test_95s_remaining_300s_status_wait_is_runtime_clamped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", no_sleep)
    clock = _StepClock(10.0)
    actor = _RunningStatusActor(_NoopRemote(), monotonic=clock)
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/workspace",
        "default_cwd": "/workspace",
        "logical_cwd": "/workspace",
        "mode": "existing_directory",
    }
    task = BackgroundTask(
        task_id="task",
        request_dir="/tmp/task",
        command="compile",
        logical_cwd="/workspace",
        output_path=".nano/tasks/task.log",
        start_wall=0.0,
        start_monotonic=10.0,
        runtime_timeout_ms=None,
        spool_cap_bytes=1024,
        term_grace_ms=5_000,
        kill_confirmation_timeout_ms=5_000,
    )
    actor._background[task.task_id] = task
    value = _v3_request_value(hard_deadline_monotonic_ns=105_000_000_000)
    request = _parse(value)

    result = asyncio.run(actor.execute(request))

    assert result.process_disposition is ProcessDisposition.NO_PROCESS
    assert result.wait_clamped is True
    assert result.wait_reason == "runtime_budget"
    assert b"still running" in result.stdout


def test_slow_output_download_returns_status_instead_of_transport_fatal() -> None:
    actor = _SlowOutputActor(_SlowDownloadRemote())
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/workspace",
        "default_cwd": "/workspace",
        "logical_cwd": "/workspace",
        "mode": "existing_directory",
    }
    task = BackgroundTask(
        task_id="task",
        request_dir="/tmp/task",
        command="compile",
        logical_cwd="/workspace",
        output_path=".nano/tasks/task.log",
        start_wall=0.0,
        start_monotonic=host_monotonic(),
        runtime_timeout_ms=None,
        spool_cap_bytes=1024,
        term_grace_ms=5_000,
        kill_confirmation_timeout_ms=5_000,
        state="completed",
        exit_code=0,
        leader_exited=True,
        census_verified=True,
    )
    actor._background[task.task_id] = task
    # tool_settled is 50ms away; actor_done is already past. A poll with no
    # semantic wait still gets a fresh terminal status and bounded output fallback.
    value = _v3_request_value(
        hard_deadline_monotonic_ns=host_monotonic_ns() + 65_050_000_000
    )
    value["arguments_json"] = '{"task_ids":["task"],"timeout_ms":0}'
    request = _parse(value)

    result = asyncio.run(actor.execute(request))

    assert result.wait_clamped is True
    assert result.wait_reason == "runtime_budget"
    assert b"Status: completed" in result.stdout
    assert b"output unavailable: runtime budget" in result.stdout


def test_real_bridge_actor_and_rust_slow_output_commits_history_then_final_once(
    tmp_path,
) -> None:
    result = asyncio.run(_run_real_slow_output_composition(tmp_path))

    assert result["request_count"] == 1
    events = result["events"]
    completed_index = next(
        index for index, event in enumerate(events) if event["type"] == "tool.completed"
    )
    requested_indexes = [
        index
        for index, event in enumerate(events)
        if event["type"] == "provider.requested"
    ]
    final_index = next(
        index
        for index, event in enumerate(events)
        if event["type"] == "assistant.final"
    )
    assert len(requested_indexes) == 2
    assert requested_indexes[0] < completed_index < requested_indexes[1] < final_index
    completed = events[completed_index]
    assert "Status: completed" in completed["data"]["output"]
    assert "output unavailable: runtime budget" in completed["data"]["output"]
    assert events[requested_indexes[1]]["data"]["function_output_call_ids"] == [
        "call-live-composition-001"
    ]
    assert result["run"]["terminal_status"] == "success"
    assert result["run"]["deadline_receipt_sha256"] == result["deadline_receipt_sha256"]
    request = result["request"]
    assert request.deadline_receipt_sha256 == result["deadline_receipt_sha256"]
    assert request.settlement_stages == SettlementStageCutoffsV1.derive(
        actor_done_monotonic_ns=request.actor_done_monotonic_ns,
        tool_settled_monotonic_ns=request.tool_settled_monotonic_ns,
        process_settlement_reserve_ms=request.process_settlement_reserve_ms,
    )


def test_cleanup_all_starts_one_active_and_eight_backgrounds_concurrently() -> None:
    async def scenario() -> _ConcurrentCleanupActor:
        actor = _ConcurrentCleanupActor()
        request_value = _v3_request_value()
        request_value["term_grace_ms"] = 1
        request = _parse(request_value)
        actor._active["/tmp/active"] = request
        for index in range(8):
            task_id = f"task-{index}"
            actor._background[task_id] = BackgroundTask(
                task_id=task_id,
                request_dir=f"/tmp/{task_id}",
                command="sleep",
                logical_cwd="/workspace",
                output_path=f".nano/tasks/{task_id}.log",
                start_wall=0.0,
                start_monotonic=0.0,
                runtime_timeout_ms=None,
                spool_cap_bytes=1024,
                term_grace_ms=1,
                kill_confirmation_timeout_ms=5_000,
            )
        cleanup = asyncio.create_task(
            actor.cleanup_active_until(host_monotonic_ns() + 20_000_000_000)
        )
        await asyncio.wait_for(actor.all_entered.wait(), timeout=1)
        assert not cleanup.done()
        actor.release.set()
        assert await cleanup is True
        return actor

    actor = asyncio.run(scenario())
    assert actor.entered == 9
    assert actor.phases == ["TERM"] * 9 + ["KILL"] * 9 + ["CENSUS"] * 9
    assert actor._active == {}
    assert actor._background == {}


def test_cleanup_all_unknown_proof_is_bounded_and_false() -> None:
    class StuckCleanupActor(RemoteTerminalActor):
        async def _signal_cleanup_process(
            self,
            _process_kind: str,
            _request_dir: str,
            _signal_name: str,
            _cutoff_monotonic_ns: int,
        ) -> bool:
            await asyncio.Event().wait()
            return True

    async def scenario() -> tuple[bool, float]:
        actor = StuckCleanupActor(_NoopRemote())
        actor._active["/tmp/active"] = _parse(_v3_request_value())
        started = time.monotonic()
        result = await actor.cleanup_active_until(host_monotonic_ns() + 20_000_000)
        return result, time.monotonic() - started

    result, elapsed = asyncio.run(scenario())
    assert result is False
    assert elapsed < 0.5


def test_cleanup_all_cancel_swallowers_do_not_escape_the_root_or_report_clean() -> None:
    class CancelSwallowingCleanupActor(RemoteTerminalActor):
        async def _signal_cleanup_process(
            self,
            _process_kind: str,
            _request_dir: str,
            _signal_name: str,
            _cutoff_monotonic_ns: int,
        ) -> bool:
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                await asyncio.sleep(0.5)
                return True

    async def scenario() -> tuple[CancelSwallowingCleanupActor, bool, float]:
        actor = CancelSwallowingCleanupActor(_NoopRemote())
        request = _parse(_v3_request_value())
        for index in range(3):
            actor._active[f"/tmp/active-{index}"] = request
        started = time.monotonic()
        result = await actor.cleanup_active_until(host_monotonic_ns() + 20_000_000)
        return actor, result, time.monotonic() - started

    actor, result, elapsed = asyncio.run(scenario())
    assert result is False
    assert elapsed < 0.2
    assert set(actor._active) == {
        "/tmp/active-0",
        "/tmp/active-1",
        "/tmp/active-2",
    }


def test_cleanup_all_final_census_separates_zero_from_unknown_survivor() -> None:
    class MixedCensusActor(RemoteTerminalActor):
        async def _signal_cleanup_process(
            self,
            _process_kind: str,
            _request_dir: str,
            _signal_name: str,
            _cutoff_monotonic_ns: int,
        ) -> bool:
            return True

        async def _census_cleanup_process(
            self,
            _process_kind: str,
            request_dir: str,
            _cutoff_monotonic_ns: int,
        ) -> bool:
            return request_dir == "/tmp/proven-zero"

    async def scenario() -> tuple[MixedCensusActor, bool]:
        actor = MixedCensusActor(_NoopRemote())
        value = _v3_request_value()
        value["term_grace_ms"] = 1
        request = _parse(value)
        actor._active["/tmp/proven-zero"] = request
        actor._active["/tmp/unknown-survivor"] = request
        clean = await actor.cleanup_active_until(host_monotonic_ns() + 200_000_000)
        return actor, clean

    actor, clean = asyncio.run(scenario())
    assert clean is False
    assert set(actor._active) == {"/tmp/unknown-survivor"}


def test_cleanup_all_final_census_cannot_extend_root_when_cancel_is_swallowed() -> None:
    class StubbornCensusActor(RemoteTerminalActor):
        def __init__(self) -> None:
            super().__init__(_NoopRemote())
            self.release = asyncio.Event()
            self.census_entered = asyncio.Event()

        async def _signal_cleanup_process(
            self,
            _process_kind: str,
            _request_dir: str,
            _signal_name: str,
            _cutoff_monotonic_ns: int,
        ) -> bool:
            return True

        async def _census_cleanup_process(
            self,
            _process_kind: str,
            _request_dir: str,
            _cutoff_monotonic_ns: int,
        ) -> bool:
            self.census_entered.set()
            while not self.release.is_set():
                try:
                    await self.release.wait()
                except asyncio.CancelledError:
                    continue
            return True

    async def scenario() -> tuple[StubbornCensusActor, bool, float, bool]:
        actor = StubbornCensusActor()
        value = _v3_request_value()
        value["term_grace_ms"] = 1
        actor._active["/tmp/unknown-census"] = _parse(value)
        started = time.monotonic()
        clean = await actor.cleanup_active_until(host_monotonic_ns() + 20_000_000)
        elapsed = time.monotonic() - started
        census_entered = actor.census_entered.is_set()
        actor.release.set()
        await asyncio.sleep(0)
        return actor, clean, elapsed, census_entered

    actor, clean, elapsed, census_entered = asyncio.run(scenario())
    assert clean is False
    assert census_entered is True
    assert elapsed < 0.03
    assert set(actor._active) == {"/tmp/unknown-census"}


def test_live_bridge_sends_root_deadline_frame_before_stopping_runtime(
    tmp_path,
) -> None:
    now_ns = host_monotonic_ns()
    deadline = RunDeadlineV1.mint(
        source="test_host_phase",
        agent_timeout_ms=75_200,
        now_monotonic_ns=now_ns,
    )
    receipt = RunDeadlineReceiptV1.bind(
        deadline=deadline,
        run_id="run",
        trial_id="trial",
        attempt_id="attempt",
        run_spec_sha256="a" * 64,
    )
    value = _v3_request_value(
        hard_deadline_monotonic_ns=deadline.hard_deadline_monotonic_ns
    )
    value.update(
        {
            "tool_name": "run_terminal_command",
            "arguments_json": (
                '{"command":"true","description":"publication proof",'
                '"timeout":1000,"background":false}'
            ),
            "deadline_receipt_sha256": receipt.sha256(),
        }
    )
    raw = json.dumps(value, separators=(",", ":")).encode()
    marker = tmp_path / "runtime-published"
    child = tmp_path / "runtime.py"
    child.write_text(
        "import json,pathlib,sys\n"
        f"raw={raw!r}\n"
        "sys.stdout.buffer.write(raw+b'\\n');sys.stdout.buffer.flush()\n"
        "response=json.loads(sys.stdin.buffer.readline())\n"
        "assert response['settlement']=='fatal'\n"
        "assert response['failure']['code']=='tool_settlement_deadline_exceeded'\n"
        "assert sys.stdin.buffer.readline()==b''\n"
        f"pathlib.Path({str(marker)!r}).write_text('terminal-published')\n",
        encoding="utf-8",
    )

    class BlockingHandler:
        async def execute(self, _request: ToolRequest):
            await asyncio.Event().wait()

        async def cleanup_active(self) -> bool:
            return True

        async def cleanup_active_until(self, _deadline_ns: int) -> bool:
            return True

    with pytest.raises(
        BridgeError,
        match="tool_settlement_deadline_exceeded",
    ):
        asyncio.run(
            run_stdio_bridge(
                [sys.executable, str(child)],
                BlockingHandler(),
                deadline_receipt=receipt,
            )
        )
    assert marker.read_text(encoding="utf-8") == "terminal-published"


def test_live_bridge_sync_encode_postcheck_is_typed_and_cannot_borrow_drain(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now_ns = host_monotonic_ns()
    deadline = RunDeadlineV1.mint(
        source="test_host_phase",
        agent_timeout_ms=95_000,
        now_monotonic_ns=now_ns,
    )
    receipt = RunDeadlineReceiptV1.bind(
        deadline=deadline,
        run_id="run",
        trial_id="trial",
        attempt_id="attempt",
        run_spec_sha256="a" * 64,
    )
    value = _v3_request_value(
        hard_deadline_monotonic_ns=deadline.hard_deadline_monotonic_ns
    )
    value["deadline_receipt_sha256"] = receipt.sha256()
    raw = json.dumps(value, separators=(",", ":")).encode()
    child = tmp_path / "runtime.py"
    child.write_text(
        "import sys\n"
        f"raw={raw!r}\n"
        "sys.stdout.buffer.write(raw+b'\\n');sys.stdout.buffer.flush()\n"
        "assert sys.stdin.buffer.readline()==b''\n",
        encoding="utf-8",
    )
    stages = SettlementStageCutoffsV1.derive(
        actor_done_monotonic_ns=receipt.cutoffs.actor_done_monotonic_ns,
        tool_settled_monotonic_ns=receipt.cutoffs.tool_settled_monotonic_ns,
        process_settlement_reserve_ms=receipt.reserves.process_settlement_ms,
    )
    clock_override: list[int] = []
    real_encode = stdio_bridge_module.encode_tool_response

    def encode_at_cutoff(request, result):
        encoded = real_encode(request, result)
        clock_override.append(stages.encode_monotonic_ns)
        return encoded

    monkeypatch.setattr(stdio_bridge_module, "encode_tool_response", encode_at_cutoff)

    class Handler:
        async def execute(self, _request: ToolRequest):
            return ToolExecution(
                return_code=0,
                timed_out=False,
                stdout=b"done",
                stderr=b"",
                stdout_truncated=False,
                stderr_truncated=False,
                cleanup_attempted=False,
                term_sent=False,
                kill_sent=False,
                cleanup_verified=True,
                census_verified=True,
                survivor_count=0,
            )

        async def cleanup_active(self) -> bool:
            return True

        async def cleanup_active_until(self, _deadline_ns: int) -> bool:
            return True

    with pytest.raises(
        BridgeError,
        match="response_serialization_deadline_exceeded",
    ):
        asyncio.run(
            run_stdio_bridge(
                [sys.executable, str(child)],
                Handler(),
                deadline_receipt=receipt,
                monotonic_ns=lambda: (
                    clock_override[-1] if clock_override else host_monotonic_ns()
                ),
            )
        )


def test_live_bridge_preflight_failure_is_a_typed_fatal_frame(tmp_path) -> None:
    now_ns = host_monotonic_ns()
    deadline = RunDeadlineV1.mint(
        source="test_host_phase",
        agent_timeout_ms=95_000,
        now_monotonic_ns=now_ns,
    )
    receipt = RunDeadlineReceiptV1.bind(
        deadline=deadline,
        run_id="run",
        trial_id="trial",
        attempt_id="attempt",
        run_spec_sha256="a" * 64,
    )
    value = _v3_request_value(
        hard_deadline_monotonic_ns=deadline.hard_deadline_monotonic_ns
    )
    value["deadline_receipt_sha256"] = receipt.sha256()
    raw = json.dumps(value, separators=(",", ":")).encode()
    marker = tmp_path / "typed-fatal"
    child = tmp_path / "runtime.py"
    child.write_text(
        "import json,pathlib,sys\n"
        f"raw={raw!r}\n"
        "sys.stdout.buffer.write(raw+b'\\n');sys.stdout.buffer.flush()\n"
        "response=json.loads(sys.stdin.buffer.readline())\n"
        "assert response['settlement']=='fatal'\n"
        "assert response['failure']['code']=="
        "'response_serialization_size_limit_exceeded'\n"
        f"pathlib.Path({str(marker)!r}).write_text('observed')\n",
        encoding="utf-8",
    )

    class OversizedHandler:
        async def execute(self, _request: ToolRequest):
            return ToolExecution(
                return_code=0,
                timed_out=False,
                stdout=b"x" * (8 * 1024 * 1024),
                stderr=b"",
                stdout_truncated=False,
                stderr_truncated=False,
                cleanup_attempted=False,
                term_sent=False,
                kill_sent=False,
                cleanup_verified=True,
                census_verified=True,
                survivor_count=0,
            )

        async def cleanup_active(self) -> bool:
            return True

        async def cleanup_active_until(self, _deadline_ns: int) -> bool:
            return True

    outcome = asyncio.run(
        run_stdio_bridge(
            [sys.executable, str(child)],
            OversizedHandler(),
            deadline_receipt=receipt,
        )
    )
    assert outcome.request_count == 1
    assert marker.read_text() == "observed"


def test_response_serialization_size_is_preflighted_before_sync_encode() -> None:
    request = _parse(_v3_request_value())
    oversized = ToolExecution(
        return_code=0,
        timed_out=False,
        stdout=b"x" * (8 * 1024 * 1024),
        stderr=b"",
        stdout_truncated=False,
        stderr_truncated=False,
        cleanup_attempted=False,
        term_sent=False,
        kill_sent=False,
        cleanup_verified=True,
        census_verified=True,
        survivor_count=0,
    )
    with pytest.raises(
        BridgeError,
        match="response_serialization_size_limit_exceeded",
    ):
        _preflight_response_serialization(request, oversized)


def test_legal_large_truncated_stdout_encodes_above_request_line_cap() -> None:
    value = _v3_request_value()
    value["stdout_cap_bytes"] = 8 * 1024 * 1024
    value["stderr_cap_bytes"] = 8 * 1024 * 1024
    value["limits"]["process_spool_bytes_per_process"] = 16 * 1024 * 1024
    value["limits"]["process_spool_bytes_per_run"] = 16 * 1024 * 1024
    request = _parse(value)
    raw_stdout = b"x" * 6_500_000
    result = ToolExecution(
        return_code=0,
        timed_out=False,
        stdout=raw_stdout,
        stderr=b"",
        stdout_truncated=True,
        stderr_truncated=False,
        cleanup_attempted=False,
        term_sent=False,
        kill_sent=False,
        cleanup_verified=True,
        census_verified=True,
        survivor_count=0,
    )

    _preflight_response_serialization(request, result)
    encoded = stdio_bridge_module.encode_tool_response(request, result)

    assert len(encoded) > MAX_REQUEST_LINE_BYTES
    assert len(encoded) <= _response_line_limit_bytes(request)
    document = json.loads(encoded)
    assert base64.b64decode(document["result"]["stdout_base64"]) == raw_stdout
    assert document["result"]["stdout_truncated"] is True


@pytest.mark.parametrize("media_enabled", [False, True])
def test_response_line_bound_matches_rust_reader_formula(media_enabled: bool) -> None:
    value = _v3_request_value()
    value["stdout_cap_bytes"] = 8
    value["stderr_cap_bytes"] = 8
    value["limits"]["process_spool_bytes_per_process"] = 15
    value["limits"]["read_file_media_enabled"] = media_enabled
    request = _parse(value)

    def base64_encoded_len(byte_length: int) -> int:
        return ((byte_length + 2) // 3) * 4

    per_stream = (request.process_spool_bytes_per_process + 1) // 2
    assert request.stdout_cap_bytes == per_stream
    assert request.stderr_cap_bytes == per_stream
    expected = base64_encoded_len(per_stream) * 2 + 32 * 1024
    if media_enabled:
        expected += base64_encoded_len(4 * 1024 * 1024)

    assert _response_line_limit_bytes(request) == expected


def test_request_framing_stays_bounded_to_eight_mib() -> None:
    with pytest.raises(BridgeError, match="external_request_framing_invalid"):
        parse_tool_request(
            b"x" * (MAX_REQUEST_LINE_BYTES + 1),
            allow_legacy_v2=False,
        )
