from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib
import importlib.util
import io
import json
import logging
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import time
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from nano_grok_build.adapter.artifactizer import canonical_json, rust_run_spec_sha256
from nano_grok_build.adapter.control_plane import ControlPlane, control_root_for
from nano_grok_build.adapter.deadline import (
    RunDeadlineReceiptV1,
    RunDeadlineV1,
    host_monotonic_ns,
)
from nano_grok_build.adapter.stdio_bridge import (
    BridgeError,
    ProcessDisposition,
    SettlementStageCutoffsV1,
    ToolExecution,
    ToolRequest,
    run_stdio_bridge,
)
from nano_grok_build.adapter.terminal_actor import (
    _REMOTE_ACTOR,
    BackgroundTask,
    RemoteTerminalActor,
)
from nano_grok_build.harbor.git_history_capability import (
    compile_git_history_capability,
)
from nano_grok_build.harbor.provider import HostProviderLaunch, runtime_command

ROOT = Path(__file__).resolve().parents[1]


def _build_nano_cli() -> Path:
    subprocess.run(
        ["cargo", "build", "-q", "-p", "nano-cli"],
        cwd=ROOT,
        check=True,
    )
    binary = ROOT / "target" / "debug" / "nano-cli"
    assert binary.is_file() and os.access(binary, os.X_OK)
    return binary.resolve()


def _contract_set_sha256(directory: Path) -> str:
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
    return hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()


def _write_contract(directory: Path) -> None:
    helper_path = Path(__file__).parent / "harbor" / "run_synthetic.py"
    module_spec = importlib.util.spec_from_file_location(
        "_nano_deadline_live_e2e_contract",
        helper_path,
    )
    assert module_spec is not None and module_spec.loader is not None
    helper = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(helper)
    helper.write_synthetic_contract(directory)

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
    profile["tools"]["background_output_wait_max_ms"] = 600_000
    profile["process"].update(
        {
            "term_grace_ms": 5_000,
            "kill_confirmation_timeout_ms": 5_000,
        }
    )
    profile_path.write_bytes(canonical_json(profile))


def _empty_tar() -> bytes:
    stream = io.BytesIO()
    with tarfile.open(
        fileobj=stream,
        mode="w:",
        format=tarfile.USTAR_FORMAT,
    ):
        pass
    return stream.getvalue()


class _OfflineRemoteEnvironment:
    """Fake only Harbor's remote I/O; all host runtime components remain real."""

    workspace = "/remote/workspace"

    def __init__(self) -> None:
        self._stage_index = 0
        self._leases: dict[str, dict[str, object]] = {}
        self._snapshot_wait_count = 0
        self.invalid_snapshot_wait_at: int | None = None
        self._empty_archive = _empty_tar()
        self.slow_output_started = 0
        self.slow_output_cancelled = 0
        self.upload_count = 0
        self.default_user: str | int | None = None

    @contextmanager
    def with_default_user(self, user: str | int | None):
        previous = self.default_user
        self.default_user = user
        try:
            yield
        finally:
            self.default_user = previous

    @staticmethod
    def _result(
        *,
        return_code: int = 0,
        stdout: str = "",
        stderr: str = "",
    ) -> SimpleNamespace:
        return SimpleNamespace(
            return_code=return_code,
            stdout=stdout,
            stderr=stderr,
        )

    @staticmethod
    def _lease(
        owner_token: str,
        *,
        terminal: bool,
    ) -> dict[str, object]:
        value: dict[str, object] = {
            "version": 1,
            "status": "completed" if terminal else "running",
            "owner_token": owner_token,
            "leader_pid": 101,
            "leader_starttime": 201,
            "pgid": 101,
            "supervisor_pid": 102,
            "supervisor_starttime": 202,
            "supervisor_pgid": 102,
        }
        if terminal:
            value.update(
                {
                    "return_code": 0,
                    "timed_out": False,
                    "term_sent": False,
                    "kill_sent": False,
                    "termination_verified": True,
                    "census_verified": True,
                    "survivor_count": 0,
                }
            )
        return value

    async def exec(self, command: str, *_args, **_kwargs) -> SimpleNamespace:
        if "canonical_default=$(realpath -e" in command:
            encoded = base64.b64encode(self.workspace.encode()).decode()
            scratch = base64.b64encode(b"/tmp").decode()
            return self._result(
                stdout=f"existing_directory\n{encoded}\n{encoded}\n{scratch}\n"
            )
        if "nano-workspace-ready-v1" in command:
            return self._result(stdout="nano-workspace-ready-v1\n")
        if "stage=$(mktemp -d /tmp/nano-workspace-snapshot-v1." in command:
            self._stage_index += 1
            stage = f"/tmp/nano-workspace-snapshot-v1.fixture{self._stage_index:02d}"
            return self._result(stdout=f"{stage}\n")

        arguments = shlex.split(command)
        if "snapshot-start" in arguments:
            action = arguments.index("snapshot-start")
            control_dir = arguments[action + 1]
            owner_token = arguments[action + 6]
            lease = self._lease(owner_token, terminal=False)
            self._leases[control_dir] = lease
            return self._result(stdout=json.dumps(lease) + "\n")
        if "snapshot-release" in arguments:
            return self._result(stdout="released\n")
        if "snapshot-wait" in arguments:
            action = arguments.index("snapshot-wait")
            control_dir = arguments[action + 1]
            owner_token = arguments[action + 2]
            self._snapshot_wait_count += 1
            if self.invalid_snapshot_wait_at == self._snapshot_wait_count:
                return self._result(return_code=92, stdout="invalid wait response\n")
            self._leases.pop(control_dir)
            return self._result(
                stdout=json.dumps(self._lease(owner_token, terminal=True)) + "\n"
            )
        if "snapshot-cancel" in arguments:
            action = arguments.index("snapshot-cancel")
            control_dir = arguments[action + 1]
            owner_token = arguments[action + 2]
            self._leases.pop(control_dir)
            return self._result(
                stdout=json.dumps(self._lease(owner_token, terminal=True)) + "\n"
            )
        if "snapshot-inspect" in arguments:
            raise AssertionError("happy path must not recover a snapshot lease")
        return self._result()

    async def upload_file(
        self,
        source_path: Path | str,
        _target_path: str,
    ) -> None:
        assert Path(source_path).is_file()
        self.upload_count += 1

    async def download_file(
        self,
        source_path: str,
        target_path: Path | str,
    ) -> None:
        target = Path(target_path)
        if source_path.startswith(".nano/tasks/") or "/.nano/tasks/" in source_path:
            self.slow_output_started += 1
            try:
                await asyncio.Event().wait()
            finally:
                self.slow_output_cancelled += 1
            raise AssertionError("slow output fixture unexpectedly returned")
        if source_path.endswith("/inventory.tsv"):
            target.write_bytes(b"")
        elif source_path.endswith("/safe.tar"):
            target.write_bytes(self._empty_archive)
        elif source_path.endswith(("/stdout.bin", "/stderr.bin")):
            target.write_bytes(b"")
        else:
            raise AssertionError(f"unexpected remote download: {source_path}")

    @property
    def owned_census(self) -> int:
        return len(self._leases)


class _RecordingRemoteTerminalActor(RemoteTerminalActor):
    def __init__(
        self,
        environment: object,
        *,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        super().__init__(environment, id_factory=id_factory)
        self.requests: list[ToolRequest] = []
        self.results: list[ToolExecution] = []
        self.errors: list[BaseException] = []

    async def execute(self, request: ToolRequest):
        self.requests.append(request)
        try:
            result = await super().execute(request)
            if isinstance(result, ToolExecution):
                self.results.append(result)
            return result
        except BaseException as error:
            self.errors.append(error)
            raise


class _DockerExecRemote:
    def __init__(self, container_id: str) -> None:
        self.container_id = container_id

    async def exec(
        self,
        command: str,
        cwd: str | None = None,
        timeout_sec: float | None = None,
        user: str | int | None = None,
    ) -> SimpleNamespace:
        argv = ["docker", "exec"]
        if cwd is not None:
            argv.extend(["--workdir", cwd])
        if user is not None:
            argv.extend(["--user", str(user)])
        argv.extend([self.container_id, "/bin/bash", "-c", command])
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        return SimpleNamespace(
            return_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    async def upload_file(self, source_path: Path, target_path: str) -> None:
        subprocess.run(
            ["docker", "cp", str(source_path), f"{self.container_id}:{target_path}"],
            check=True,
            capture_output=True,
            text=True,
        )

    async def download_file(self, source_path: str, target_path: Path) -> None:
        subprocess.run(
            ["docker", "cp", f"{self.container_id}:{source_path}", str(target_path)],
            check=True,
            capture_output=True,
            text=True,
        )


class _FakeContext:
    def __init__(self) -> None:
        self.n_input_tokens = 0
        self.n_cache_tokens = 0
        self.n_output_tokens = 0
        self.metadata: dict[str, object] = {}

    @staticmethod
    def is_empty() -> bool:
        return True


def _install_pinned_harbor(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[type, type]:
    harbor = ModuleType("harbor")
    agents = ModuleType("harbor.agents")
    agents.__path__ = []
    agent_base = ModuleType("harbor.agents.base")
    environments = ModuleType("harbor.environments")
    environments.__path__ = []
    environment_base = ModuleType("harbor.environments.base")
    models = ModuleType("harbor.models")
    models.__path__ = []
    agent_models = ModuleType("harbor.models.agent")
    agent_models.__path__ = []
    context_module = ModuleType("harbor.models.agent.context")
    trial_package = ModuleType("harbor.trial")
    trial_package.__path__ = []
    single_step_module = ModuleType("harbor.trial.single_step")
    trial_module = ModuleType("harbor.trial.trial")
    utils = ModuleType("harbor.utils")
    utils.__path__ = []
    validator_module = ModuleType("harbor.utils.trajectory_validator")

    class FakeBaseAgent:
        def __init__(
            self,
            logs_dir: Path,
            model_name: str | None = None,
            logger: logging.Logger | None = None,
            **_kwargs,
        ) -> None:
            self.logs_dir = Path(logs_dir)
            self.model_name = model_name
            self.logger = logger or logging.getLogger("deadline-live-e2e")
            self.session_id = None
            self.context_id = None

    class FakeTrial:
        async def _run_agent_phase(
            self,
            *,
            target,
            instruction,
            timeout_sec,
            user,
            step_cfg=None,
            resume=False,
        ):
            del step_cfg
            run = self.agent.resume if resume else self.agent.run
            with self.agent_environment.with_default_user(user):
                await asyncio.wait_for(
                    run(
                        instruction=instruction,
                        environment=self.agent_environment,
                        context=target.agent_result,
                    ),
                    timeout=timeout_sec,
                )

    class FakeSingleStepTrial(FakeTrial):
        async def _run_verifier(self) -> None:
            return None

    class TrajectoryValidator:
        def __init__(self) -> None:
            self.errors: list[str] = []

        @staticmethod
        def validate(_trajectory, *, validate_images: bool) -> bool:
            assert validate_images is True
            return True

    agent_base.BaseAgent = FakeBaseAgent
    environment_base.BaseEnvironment = object
    context_module.AgentContext = _FakeContext
    single_step_module.SingleStepTrial = FakeSingleStepTrial
    trial_module.Trial = FakeTrial
    validator_module.TrajectoryValidator = TrajectoryValidator

    modules = {
        "harbor": harbor,
        "harbor.agents": agents,
        "harbor.agents.base": agent_base,
        "harbor.environments": environments,
        "harbor.environments.base": environment_base,
        "harbor.models": models,
        "harbor.models.agent": agent_models,
        "harbor.models.agent.context": context_module,
        "harbor.trial": trial_package,
        "harbor.trial.single_step": single_step_module,
        "harbor.trial.trial": trial_module,
        "harbor.utils": utils,
        "harbor.utils.trajectory_validator": validator_module,
    }
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)

    monkeypatch.delitem(
        sys.modules,
        "nano_grok_build.adapter.harbor",
        raising=False,
    )
    harbor_adapter = importlib.import_module("nano_grok_build.adapter.harbor")
    monkeypatch.setattr(
        "nano_grok_build.adapter.atif.importlib.metadata.version",
        lambda name: "0.20.0" if name == "harbor" else "",
    )
    return FakeSingleStepTrial, harbor_adapter.NanoGrokBuildAgent


def test_pinned_harbor_fake_exposes_exact_verifier_cleanup_seam(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trial_type, _ = _install_pinned_harbor(monkeypatch)
    from nano_grok_build.harbor.compat_v020 import install_harbor_deadline_seam

    install_harbor_deadline_seam()

    from harbor.trial.single_step import SingleStepTrial

    assert SingleStepTrial is trial_type
    assert (
        getattr(
            SingleStepTrial._run_verifier,
            "__nano_verifier_cleanup_seam__",
            None,
        )
        == "nano-background-verifier-cleanup-seam-v1"
    )


def _script(task_id: str, call_id: str) -> dict[str, object]:
    return {
        "schema_version": "scripted-provider-v1",
        "steps": [
            {
                "type": "completed",
                "response": {
                    "response_id": "response-live-e2e-tool",
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
                    "response_id": "response-live-e2e-final",
                    "model": "synthetic-model",
                    "output": [
                        {
                            "type": "assistant_message",
                            "text": "live deadline fixture complete",
                        }
                    ],
                    "usage": None,
                },
            },
        ],
    }


_FOREGROUND_RESIDUAL_SENTINEL = "FG_CHILDREN_KILLED;START_INTENDED_BG;VERIFY_HANDLE"


def _deterministic_uuid7(seed: str) -> str:
    raw = bytearray(hashlib.sha256(seed.encode("utf-8")).digest()[:16])
    raw[:6] = (1_736_942_400_000).to_bytes(6, "big")
    raw[6] = (raw[6] & 0x0F) | 0x70
    raw[8] = (raw[8] & 0x3F) | 0x80
    value = str(uuid.UUID(bytes=bytes(raw)))
    assert uuid.UUID(value).version == 7
    return value


def _foreground_residual_script(task_id: str) -> dict[str, object]:
    def function_step(
        ordinal: int,
        *,
        call_id: str,
        name: str,
        arguments: dict[str, object],
    ) -> dict[str, object]:
        return {
            "type": "completed",
            "response": {
                "response_id": f"response-foreground-residual-{ordinal}",
                "model": "synthetic-model",
                "output": [
                    {
                        "type": "function_call",
                        "call_id": call_id,
                        "name": name,
                        "arguments_json": json.dumps(
                            arguments,
                            separators=(",", ":"),
                        ),
                    }
                ],
                "usage": None,
            },
        }

    return {
        "schema_version": "scripted-provider-v1",
        "steps": [
            function_step(
                1,
                call_id="call-foreground-residual",
                name="run_terminal_command",
                arguments={
                    "command": (
                        "setsid /bin/bash -c "
                        "'trap \"\" TERM; exec sleep 60' "
                        ">/dev/null 2>&1 & printf 'leader-done\\n'"
                    ),
                    "description": "leave one owned foreground residual",
                    "timeout": 5_000,
                    "background": False,
                },
            ),
            function_step(
                2,
                call_id="call-managed-background",
                name="run_terminal_command",
                arguments={
                    "command": (
                        f"printf '%s\\n' {shlex.quote(task_id)} "
                        "> /workspace/managed-handle; exec sleep 60"
                    ),
                    "description": "start the intended managed background process",
                    "timeout": 0,
                    "background": True,
                },
            ),
            function_step(
                3,
                call_id="call-dependent",
                name="run_terminal_command",
                arguments={
                    "command": (
                        'test "$(cat /workspace/managed-handle)" = '
                        f"{shlex.quote(task_id)} && "
                        f"printf 'dependent-ok:%s\\n' {shlex.quote(task_id)}"
                    ),
                    "description": "consume the exact actor-issued background handle",
                    "timeout": 5_000,
                    "background": False,
                },
            ),
            function_step(
                4,
                call_id="call-background-status",
                name="get_terminal_command_output",
                arguments={"task_ids": [task_id], "timeout_ms": 0},
            ),
            {
                "type": "completed",
                "response": {
                    "response_id": "response-foreground-residual-final",
                    "model": "synthetic-model",
                    "output": [
                        {
                            "type": "assistant_message",
                            "text": "foreground residual transition complete",
                        }
                    ],
                    "usage": None,
                },
            },
        ],
    }


def test_real_actor_wait_invalid_v5_receipt_can_reach_eligibility(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, agent_type = _install_pinned_harbor(monkeypatch)
    import nano_grok_build.adapter.harbor as harbor_adapter
    from nano_grok_build.adapter.artifactizer import VerifierTerminalRuntimeV1
    from nano_grok_build.adapter.workspace_snapshot import (
        SnapshotPolicy,
        SnapshotTarget,
        capture_after,
        capture_before,
    )

    logs_dir = tmp_path / "agent"
    logs_dir.mkdir()
    remote = _OfflineRemoteEnvironment()
    remote.invalid_snapshot_wait_at = 2
    actor = RemoteTerminalActor(remote)
    runtime = VerifierTerminalRuntimeV1(
        schema_version="nano-run-record-v3",
        run_id="run-wait-invalid",
        trial_id="trial-wait-invalid",
        attempt_id="attempt-0",
        run_spec_sha256="a" * 64,
        terminal_status="tool_failure",
        terminal_phase="bridge",
        terminal_code="terminal_actor_wait_response_invalid",
        run_record_sha256="b" * 64,
        events_sha256="c" * 64,
    )
    monkeypatch.setattr(
        harbor_adapter,
        "validate_verifier_terminal_runtime",
        lambda **_kwargs: runtime,
    )

    async def scenario():
        await actor.setup()
        target = SnapshotTarget(actor=actor, artifact_dir=logs_dir)
        before = await capture_before(target, SnapshotPolicy())
        hard_ns = actor._monotonic_ns() + 30_000_000_000
        receipt = await capture_after(
            target,
            before,
            hard_deadline_monotonic_ns=hard_ns,
        )
        agent = object.__new__(agent_type)
        agent.logs_dir = logs_dir
        agent._run_spec = {"bound": True}
        agent._actor = actor
        decision = await agent.verifier_opportunity_decision_v1(
            primary_error=RuntimeError("terminalized"),
            result_target=SimpleNamespace(agent_result=object()),
            workspace_receipt=receipt,
            hard_deadline_monotonic_ns=hard_ns,
        )
        return receipt, decision

    receipt, decision = asyncio.run(scenario())
    persisted = json.loads((logs_dir / "workspace-receipt.json").read_bytes())
    assert persisted["schema_version"] == "nano-workspace-receipt-v5"
    assert persisted["status"] == "failed"
    assert persisted["failure"]["subtype"] == "wait_response_invalid"
    assert persisted["failure"]["execution_binding_verified"] is True
    assert receipt.continuable is True
    assert decision.eligible is True
    assert decision.runtime is runtime
    assert actor._active == {}
    assert actor._background == {}
    assert actor._active_snapshots == {}
    assert remote.owned_census == 0


@pytest.mark.parametrize(
    ("receipt_state", "expected_code"),
    [
        ("missing", "deadline_contract_unavailable"),
        ("tampered", "deadline_cutoffs_binding_invalid"),
    ],
)
def test_real_cli_bridge_actor_receipt_negatives_fail_closed_without_orphan(
    tmp_path: Path,
    receipt_state: str,
    expected_code: str,
) -> None:
    binary = _build_nano_cli()
    contract_dir = tmp_path / "contract"
    _write_contract(contract_dir)
    artifact_dir = tmp_path / "runtime"
    artifact_dir.mkdir()
    script_path = tmp_path / "script.json"
    script_path.write_bytes(
        canonical_json(
            {
                "schema_version": "scripted-provider-v1",
                "steps": [
                    {
                        "type": "completed",
                        "response": {
                            "response_id": "receipt-negative-final",
                            "model": "synthetic-model",
                            "output": [
                                {
                                    "type": "assistant_message",
                                    "text": "must not be reached",
                                }
                            ],
                            "usage": None,
                        },
                    }
                ],
            }
        )
    )
    spec = {
        "schema_version": "nano-run-spec-alpha-2",
        "run_id": f"run-receipt-{receipt_state}",
        "trial_id": f"trial-receipt-{receipt_state}",
        "attempt_id": "attempt-0",
        "task": {
            "id": "synthetic-receipt-negative",
            "digest": "e" * 64,
            "instruction": "This provider must not be reached.",
            "git_history_capability": compile_git_history_capability(
                "This provider must not be reached.", "e" * 64
            ),
        },
        "contract": {
            "id": "synthetic-v1",
            "contract_set_sha256": _contract_set_sha256(contract_dir),
            "profile_id": "synthetic-profile-v1",
        },
        "provider": {
            "kind": "scripted",
            "model": "synthetic-model",
            "max_turns": 4,
            "retry_max": 0,
        },
        "workspace_dir": "/workspace",
        "artifact_dir": str(artifact_dir.resolve()),
        "agent_timeout_sec": 120,
    }
    spec_path = tmp_path / "run-spec.json"
    spec_path.write_bytes(canonical_json(spec))
    deadline = RunDeadlineV1.mint(
        source="test_host_phase",
        agent_timeout_ms=120_000,
        now_monotonic_ns=host_monotonic_ns(),
    )
    receipt = RunDeadlineReceiptV1.bind(
        deadline=deadline,
        run_id=spec["run_id"],
        trial_id=spec["trial_id"],
        attempt_id=spec["attempt_id"],
        run_spec_sha256=rust_run_spec_sha256(spec),
    )
    if receipt_state == "tampered":
        value = receipt.as_dict()
        value["cutoffs"]["actor_done_monotonic_ns"] += 1
        (artifact_dir / "deadline.json").write_bytes(canonical_json(value))

    remote = _OfflineRemoteEnvironment()
    actor = _RecordingRemoteTerminalActor(remote)
    command = runtime_command(
        binary_path=binary,
        spec_path=spec_path.resolve(),
        contract_dir=contract_dir.resolve(),
        provider=HostProviderLaunch.scripted(script_path.resolve()),
        deadline_monotonic_ns=deadline.hard_deadline_monotonic_ns,
    )
    with pytest.raises(BridgeError, match="^external_runtime_nonzero$") as raised:
        asyncio.run(
            run_stdio_bridge(
                command,
                actor,
                deadline_receipt=receipt,
            )
        )
    assert raised.value.stderr is not None
    assert expected_code.encode() in raised.value.stderr
    assert actor.requests == []
    assert actor._active == {}
    assert actor._background == {}
    assert actor._active_snapshots == {}
    assert remote.owned_census == 0
    assert not (artifact_dir / "run.json").exists()


def test_harbor_deadline_receipt_crosses_real_adapter_cli_bridge_actor_and_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = _build_nano_cli()
    trial_type, agent_type = _install_pinned_harbor(monkeypatch)
    from nano_grok_build.adapter.harbor import _HarborEnvironmentProxy
    from nano_grok_build.adapter.workspace_snapshot import (
        SnapshotPolicy,
        SnapshotTarget,
        capture_before,
    )
    from nano_grok_build.harbor.compat_v020 import install_harbor_deadline_seam

    install_harbor_deadline_seam()
    contract_dir = tmp_path / "contract"
    _write_contract(contract_dir)
    logs_dir = tmp_path / "agent"
    logs_dir.mkdir()
    script_path = tmp_path / "script.json"
    task_id = "task-live-e2e-001"
    call_id = "call-live-e2e-001"
    script_path.write_bytes(canonical_json(_script(task_id, call_id)))
    run_spec = {
        "schema_version": "nano-run-spec-alpha-2",
        "run_id": "run-live-e2e-001",
        "trial_id": "trial-live-e2e-001",
        "attempt_id": "attempt-0",
        "task": {
            "id": "synthetic-live-e2e",
            "digest": "f" * 64,
            "instruction": "Poll the completed background task and finish.",
            "git_history_capability": compile_git_history_capability(
                "Poll the completed background task and finish.", "f" * 64
            ),
        },
        "contract": {
            "id": "synthetic-v1",
            "contract_set_sha256": _contract_set_sha256(contract_dir),
            "profile_id": "synthetic-profile-v1",
        },
        "provider": {
            "kind": "scripted",
            "model": "synthetic-model",
            "max_turns": 4,
            "retry_max": 0,
        },
        "workspace_dir": "/workspace",
        "artifact_dir": str((control_root_for(logs_dir) / "runtime").resolve()),
        "agent_timeout_sec": 120,
    }
    agent = agent_type(
        logs_dir=logs_dir,
        model_name="synthetic-model",
        binary_path=str(binary),
        contract_dir=str(contract_dir.resolve()),
        provider_launch={
            "kind": "scripted",
            "script_path": str(script_path.resolve()),
        },
        run_spec=run_spec,
        deadline_mode="harbor-root-v1",
    )
    remote = _OfflineRemoteEnvironment()
    actor = _RecordingRemoteTerminalActor(_HarborEnvironmentProxy(remote))
    context = _FakeContext()

    async def scenario() -> None:
        await actor.setup()
        agent._control_plane = ControlPlane.create(
            logs_dir,
            run_spec_sha256=rust_run_spec_sha256(run_spec),
        )
        agent._actor = actor
        agent._before_snapshot = await capture_before(
            SnapshotTarget(
                actor=actor,
                artifact_dir=agent._control_plane.root,
                publication_dir=logs_dir,
            ),
            SnapshotPolicy(),
        )
        actor._background[task_id] = BackgroundTask(
            task_id=task_id,
            request_dir=f"/tmp/{task_id}",
            command="compile",
            logical_cwd="/workspace",
            output_path=f".nano/tasks/{task_id}.log",
            start_wall=time.time() - 1,
            start_monotonic=time.clock_gettime(time.CLOCK_MONOTONIC) - 1,
            runtime_timeout_ms=None,
            spool_cap_bytes=1024,
            term_grace_ms=5_000,
            kill_confirmation_timeout_ms=5_000,
            state="completed",
            exit_code=0,
            end_wall=time.time(),
            end_monotonic=time.clock_gettime(time.CLOCK_MONOTONIC),
            leader_exited=True,
            census_verified=True,
        )
        trial = trial_type()
        trial.agent = agent
        trial.agent_environment = remote
        await trial._run_agent_phase(
            target=SimpleNamespace(agent_result=context),
            instruction=run_spec["task"]["instruction"],
            timeout_sec=run_spec["agent_timeout_sec"],
            user=None,
        )

    try:
        asyncio.run(scenario())
    except BaseException as error:
        raise AssertionError(f"live fixture actor errors: {actor.errors!r}") from error
    agent.populate_context_post_run(context)

    receipt_path = logs_dir / "runtime" / "deadline.json"
    receipt_bytes = receipt_path.read_bytes()
    receipt = RunDeadlineReceiptV1.from_bytes(receipt_bytes)
    receipt_sha256 = hashlib.sha256(receipt_bytes).hexdigest()
    assert receipt_bytes == receipt.to_bytes()
    assert receipt.run_spec_sha256 == rust_run_spec_sha256(run_spec)

    assert len(actor.requests) == 1
    request = actor.requests[0]
    raw_request = json.loads(request.raw_json)
    assert request.hard_deadline_monotonic_ns == (
        receipt.deadline.hard_deadline_monotonic_ns
    )
    for field, value in receipt.cutoffs.as_dict().items():
        assert raw_request[field] == value
    reserve_fields = {
        "cleanup_reserve_ms": receipt.reserves.cleanup_ms,
        "terminalization_reserve_ms": receipt.reserves.terminalization_ms,
        "provider_send_reserve_ms": receipt.reserves.provider_send_ms,
        "process_settlement_reserve_ms": receipt.reserves.process_settlement_ms,
    }
    for field, value in reserve_fields.items():
        assert raw_request[field] == value
    assert request.deadline_receipt_sha256 == receipt_sha256
    assert request.settlement_stages == SettlementStageCutoffsV1.derive(
        actor_done_monotonic_ns=receipt.cutoffs.actor_done_monotonic_ns,
        tool_settled_monotonic_ns=receipt.cutoffs.tool_settled_monotonic_ns,
        process_settlement_reserve_ms=receipt.reserves.process_settlement_ms,
    )

    events = [
        json.loads(line)
        for line in (logs_dir / "runtime" / "events.jsonl").read_text().splitlines()
    ]
    run = json.loads((logs_dir / "runtime" / "run.json").read_bytes())
    marker = json.loads((logs_dir / "agent-run.json").read_bytes())
    assert events[0]["type"] == "run.started"
    assert events[0]["data"]["deadline_receipt_sha256"] == receipt_sha256
    assert run["schema_version"] == "nano-run-record-v3"
    assert run["deadline_receipt_sha256"] == receipt_sha256
    assert run["terminal_status"] == "success"
    assert marker["schema_version"] == "nano-agent-run-v3"
    assert marker["run_record_schema"] == "nano-run-record-v3"
    assert marker["deadline_receipt_sha256"] == receipt_sha256
    assert marker["publication_kind"] == "success_atif"
    assert context.metadata["success_artifact_valid"] is True

    tool_completed = next(
        index for index, event in enumerate(events) if event["type"] == "tool.completed"
    )
    provider_requested = [
        index
        for index, event in enumerate(events)
        if event["type"] == "provider.requested"
    ]
    final = next(
        index
        for index, event in enumerate(events)
        if event["type"] == "assistant.final"
    )
    assert len(provider_requested) == 2
    assert provider_requested[0] < tool_completed < provider_requested[1] < final
    assert "Status: completed" in events[tool_completed]["data"]["output"]
    assert (
        "output unavailable: runtime budget" in events[tool_completed]["data"]["output"]
    )
    assert events[provider_requested[1]]["data"]["function_output_call_ids"] == [
        call_id
    ]
    assert remote.slow_output_started == 1
    assert remote.slow_output_cancelled == 1
    assert remote.owned_census == 0
    assert actor._active == {}
    assert actor._active_snapshots == {}
    assert all(task.state != "running" for task in actor._background.values())
    background = json.loads(
        (logs_dir / "runtime-background-manifest.json").read_bytes()
    )
    assert background["tasks"] == []


@pytest.mark.skipif(
    os.environ.get("NANO_RUN_DOCKER_TESTS") != "1",
    reason="set NANO_RUN_DOCKER_TESTS=1 for the real-Docker regression",
)
def test_foreground_residual_transition_real_e2e(tmp_path: Path) -> None:
    """Exercise the transition through the real CLI, bridge, actor, and Docker."""

    assert shutil.which("docker") is not None, "docker CLI is unavailable"
    assert (
        subprocess.run(["docker", "info"], capture_output=True, check=False).returncode
        == 0
    ), "docker daemon is unavailable"
    image = os.environ.get(
        "NANO_DOCKER_REGRESSION_IMAGE",
        "alexgshaw/fix-git:20260403",
    )
    assert (
        subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            check=False,
        ).returncode
        == 0
    ), f"cached regression image is unavailable: {image}"

    binary = _build_nano_cli()
    contract_dir = tmp_path / "contract"
    _write_contract(contract_dir)
    profile_path = contract_dir / "agent-profile.json"
    profile = json.loads(profile_path.read_bytes())
    profile["context"]["max_provider_turns"] = 8
    profile_path.write_bytes(canonical_json(profile))

    run_id = "run-foreground-residual-real-e2e"
    task_id = _deterministic_uuid7(run_id)
    script_path = tmp_path / "script.json"
    script_path.write_bytes(canonical_json(_foreground_residual_script(task_id)))
    artifact_dir = tmp_path / "runtime"
    artifact_dir.mkdir()
    spec = {
        "schema_version": "nano-run-spec-alpha-2",
        "run_id": run_id,
        "trial_id": "trial-foreground-residual-real-e2e",
        "attempt_id": "attempt-0",
        "task": {
            "id": "synthetic-foreground-residual-real-e2e",
            "digest": "d" * 64,
            "instruction": (
                "Recover from a foreground residual, then start and verify the "
                "intended managed background process."
            ),
            "git_history_capability": compile_git_history_capability(
                "Recover from a foreground residual, then start and verify the "
                "intended managed background process.",
                "d" * 64,
            ),
        },
        "contract": {
            "id": "synthetic-v1",
            "contract_set_sha256": _contract_set_sha256(contract_dir),
            "profile_id": "synthetic-profile-v1",
        },
        "provider": {
            "kind": "scripted",
            "model": "synthetic-model",
            "max_turns": 8,
            "retry_max": 0,
        },
        "workspace_dir": "/workspace",
        "artifact_dir": str(artifact_dir.resolve()),
        "agent_timeout_sec": 120,
    }
    spec_path = tmp_path / "run-spec.json"
    spec_path.write_bytes(canonical_json(spec))
    deadline = RunDeadlineV1.mint(
        source="test_host_phase",
        agent_timeout_ms=120_000,
        now_monotonic_ns=host_monotonic_ns(),
    )
    receipt = RunDeadlineReceiptV1.bind(
        deadline=deadline,
        run_id=spec["run_id"],
        trial_id=spec["trial_id"],
        attempt_id=spec["attempt_id"],
        run_spec_sha256=rust_run_spec_sha256(spec),
    )
    (artifact_dir / "deadline.json").write_bytes(receipt.to_bytes())
    command = runtime_command(
        binary_path=binary,
        spec_path=spec_path.resolve(),
        contract_dir=contract_dir.resolve(),
        provider=HostProviderLaunch.scripted(script_path.resolve()),
        deadline_monotonic_ns=deadline.hard_deadline_monotonic_ns,
    )

    container_id = ""
    actor: _RecordingRemoteTerminalActor | None = None
    task: BackgroundTask | None = None
    process_lease = None
    cleanup_verified = False
    try:
        container_id = subprocess.run(
            ["docker", "run", "--detach", "--rm", image, "sleep", "infinity"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        remote = _DockerExecRemote(container_id)
        actor = _RecordingRemoteTerminalActor(
            remote,
            id_factory=lambda: task_id,
        )
        asyncio.run(actor.setup())
        try:
            outcome = asyncio.run(
                run_stdio_bridge(
                    command,
                    actor,
                    deadline_receipt=receipt,
                )
            )
        except BridgeError as error:
            raise AssertionError(
                f"real E2E runtime stderr={error.stderr!r}; "
                f"actor_errors={actor.errors!r}"
            ) from error
        assert outcome.request_count == 4
        assert actor.errors == []
        assert [request.call_id for request in actor.requests] == [
            "call-foreground-residual",
            "call-managed-background",
            "call-dependent",
            "call-background-status",
        ]
        assert [request.tool_name for request in actor.requests] == [
            "run_terminal_command",
            "run_terminal_command",
            "run_terminal_command",
            "get_terminal_command_output",
        ]
        assert len(actor.results) == 4
        foreground, background, dependent, status = actor.results
        assert foreground.return_code == 0
        assert foreground.timed_out is False
        assert foreground.cleanup_attempted is True
        assert foreground.term_sent or foreground.kill_sent
        assert foreground.cleanup_verified is True
        assert foreground.census_verified is True
        assert foreground.survivor_count == 0
        assert foreground.process_disposition is ProcessDisposition.FOREGROUND_CLEANED
        assert foreground.target_task_id is None

        assert background.process_disposition is ProcessDisposition.BACKGROUND_RETAINED
        assert background.target_task_id == task_id
        assert background.survivor_count > 0
        assert task_id.encode() in background.stdout
        assert dependent.return_code == 0
        assert dependent.process_disposition is ProcessDisposition.FOREGROUND_CLEANED
        assert dependent.term_sent is False
        assert dependent.kill_sent is False
        assert dependent.stdout == f"dependent-ok:{task_id}\n".encode()
        assert status.return_code == 0
        assert task_id.encode() in status.stdout
        assert b"Status: running" in status.stdout

        events = [
            json.loads(line)
            for line in (artifact_dir / "events.jsonl").read_text().splitlines()
        ]
        run = json.loads((artifact_dir / "run.json").read_bytes())
        tool_events = [event for event in events if event["type"] == "tool.completed"]
        provider_events = [
            event for event in events if event["type"] == "provider.requested"
        ]
        assert len(tool_events) == 4
        assert len(provider_events) == 5
        assert [event["data"]["call_id"] for event in tool_events] == [
            "call-foreground-residual",
            "call-managed-background",
            "call-dependent",
            "call-background-status",
        ]
        assert tool_events[0]["data"]["execution_attempted"] is True
        assert tool_events[0]["data"]["outcome"] == "rejected"
        assert tool_events[0]["data"]["output"].startswith(
            _FOREGROUND_RESIDUAL_SENTINEL
        )
        assert task_id in tool_events[1]["data"]["output"]
        assert task_id in tool_events[2]["data"]["output"]
        assert task_id in tool_events[3]["data"]["output"]
        assert provider_events[1]["data"]["function_output_call_ids"] == [
            "call-foreground-residual"
        ]
        assert provider_events[-1]["data"]["function_output_call_ids"] == [
            "call-foreground-residual",
            "call-managed-background",
            "call-dependent",
            "call-background-status",
        ]
        assert run["terminal_status"] == "success"
        assert run["provider_turn_count"] == 5
        assert run["tool_call_count"] == 4
        assert not any(event["type"] == "run.failed" for event in events)

        assert list(actor._background) == [task_id]
        task = actor._background[task_id]
        assert task.task_id == task_id
        assert task.owner_token
        assert task.pgid > 1 and task.leader_starttime > 0
        assert task.monitor_pgid > 1 and task.monitor_starttime > 0
        manifest = asyncio.run(actor.background_manifest())
        assert manifest == [
            {
                "task_id": task_id,
                "pgid": task.pgid,
                "monitor_pgid": task.monitor_pgid,
                "output_path": task.output_path,
                "state": "running",
            }
        ]
        process_lease = actor.seal_process_lease_v1(manifest)
        liveness = asyncio.run(
            actor.observe_process_lease_v1(
                process_lease,
                hard_deadline_monotonic_ns=actor._monotonic_ns() + 10_000_000_000,
            )
        )
        assert liveness == [
            {
                "task_id": task_id,
                "leader_pid": task.pgid,
                "leader_starttime": task.leader_starttime,
                "leader_pgid": task.pgid,
                "monitor_pid": task.monitor_pgid,
                "monitor_starttime": task.monitor_starttime,
                "monitor_pgid": task.monitor_pgid,
                "owner_token_sha256": hashlib.sha256(
                    task.owner_token.encode("ascii")
                ).hexdigest(),
                "process_alive": True,
            }
        ]

        cleanup_verified = asyncio.run(
            actor.close_process_lease_until(
                process_lease,
                actor._monotonic_ns() + 15_000_000_000,
            )
        )
        assert cleanup_verified is True
        assert actor._background == {}
        census = asyncio.run(
            remote.exec(
                " ".join(
                    [
                        "/bin/bash",
                        shlex.quote(_REMOTE_ACTOR),
                        "cleanup-census",
                        shlex.quote(task.request_dir),
                        "background",
                        str(task.pgid),
                        str(task.leader_starttime),
                        str(task.monitor_pgid),
                        str(task.monitor_starttime),
                        task.owner_token,
                    ]
                ),
                timeout_sec=5,
            )
        )
        assert census.return_code == 0
        assert json.loads(census.stdout) == {
            "verified": True,
            "survivor_count": 0,
        }
        dead = asyncio.run(
            remote.exec(
                " ".join(
                    [
                        "for pid in",
                        str(task.pgid),
                        str(task.monitor_pgid) + ";",
                        "do",
                        "if [ -r /proc/$pid/stat ]; then",
                        "state=$(awk '{print $3}' /proc/$pid/stat);",
                        'case "$state" in Z|X) ;; *) exit 1 ;; esac;',
                        "fi;",
                        "done",
                    ]
                ),
                timeout_sec=5,
            )
        )
        assert dead.return_code == 0
    finally:
        if (
            container_id
            and actor is not None
            and task is not None
            and process_lease is not None
            and not cleanup_verified
        ):
            try:
                asyncio.run(
                    actor.close_process_lease_until(
                        process_lease, actor._monotonic_ns() + 15_000_000_000
                    )
                )
            except BaseException:
                pass
        if container_id:
            subprocess.run(
                ["docker", "rm", "--force", container_id],
                capture_output=True,
                check=False,
            )
