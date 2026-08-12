from __future__ import annotations

import asyncio
import json
import sys
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from nano_grok_build.adapter.artifactizer import (
    VerifierOpportunityDecisionV1,
    VerifierTerminalRuntimeV1,
)
from nano_grok_build.adapter.deadline import DeadlineContractError
from nano_grok_build.adapter.stdio_bridge import BridgeError
from nano_grok_build.harbor.compat_v020 import (
    RuntimeInputs,
    bind_run_specs,
    install_resolved_package_task_cache_seam,
)
from nano_grok_build.harbor.trial_lifecycle import VerifierSafetyProof


class FakeTask:
    verifier_mode = "shared"
    steps = None

    def __init__(
        self,
        path,
        *,
        extra_instruction_paths,
        disable_verification=False,
    ):
        self.path = path
        self.extra_instruction_paths = extra_instruction_paths
        self.disable_verification = disable_verification
        self.config = SimpleNamespace(
            agent=SimpleNamespace(timeout_sec=120),
            verifier_mode=self.verifier_mode,
            steps=self.steps,
        )
        self.checksum = "a" * 64
        self.name = "synthetic-task"
        self.instruction = "Use the selected tools."

    @property
    def has_steps(self) -> bool:
        return bool(self.config.steps)


class FakeAgent:
    def model_copy(self, *, update, deep):
        assert deep is True
        return SimpleNamespace(**update)


class FakeEnvironment:
    def __init__(self, default_user=None) -> None:
        self.default_user = default_user

    @contextmanager
    def with_default_user(self, user):
        previous = self.default_user
        self.default_user = user
        try:
            yield
        finally:
            self.default_user = previous


def _safe_proof() -> VerifierSafetyProof:
    return VerifierSafetyProof(
        run_id="run-1",
        trial_id="trial-1",
        attempt_id="attempt-0",
        run_spec_sha256="a" * 64,
        runtime_manifest_sha256="b" * 64,
        git_mode="restored",
        safe=True,
        block_reasons=(),
        manifest_sha256="c" * 64,
    )


def test_v060_safe_ordinary_error_reaches_native_verifier_before_finalization(
    tmp_path: Path,
    monkeypatch,
) -> None:
    trial_type = install_harbor_stubs(monkeypatch)
    job, _ = make_job(tmp_path)
    bind_run_specs(job, make_inputs(tmp_path))
    monkeypatch.setattr(
        "nano_grok_build.harbor.compat_v020.host_monotonic_ns",
        lambda: 10_000_000_000,
    )
    primary = RuntimeError("ordinary-agent-deadline")
    events: list[str] = []

    class Agent:
        SUPPORTS_NANO_RUN_DEADLINE_V1 = True
        SUPPORTS_TRIAL_LIFECYCLE_V1 = True

        async def run_with_deadline(self, **_kwargs):
            events.append("agent")
            raise primary

        async def post_agent_workspace_snapshot_v1(self, **_kwargs):
            events.append("snapshot")
            return object()

        async def complete_runtime_and_prove_safety_v1(self, **kwargs):
            assert kwargs["primary_error"] is primary
            events.append("safety")
            return _safe_proof()

        def verifier_safety_proof_v1(self):
            events.append("proof-read")
            return _safe_proof()

        async def post_verifier_finalize_v1(self, **kwargs):
            assert kwargs["verifier_error"] is None
            assert kwargs["verifier_status"] == "success"
            events.append("finalize")

    trial = trial_type.single_step_type()
    trial.agent = Agent()
    trial.agent_environment = FakeEnvironment(default_user=77)
    trial.task = SimpleNamespace(
        config=SimpleNamespace(agent=SimpleNamespace(user=1002))
    )
    trial.config = SimpleNamespace(verifier=SimpleNamespace(disable=False))
    trial.verifier_calls = 0
    trial.verifier_error = None

    asyncio.run(
        trial._run_agent_phase(
            target=SimpleNamespace(agent_result=object()),
            instruction="work",
            timeout_sec=120,
            user=1002,
        )
    )
    assert trial.recorded_exception is primary
    assert events == ["agent", "snapshot", "safety"]

    asyncio.run(trial._run_verifier())
    assert trial.verifier_calls == 1
    assert events == [
        "agent",
        "snapshot",
        "safety",
        "proof-read",
        "finalize",
    ]


def install_harbor_stubs(monkeypatch) -> type:
    harbor = ModuleType("harbor")
    models = ModuleType("harbor.models")
    task_package = ModuleType("harbor.models.task")
    task_id_module = ModuleType("harbor.models.task.id")
    task_module = ModuleType("harbor.models.task.task")
    verifier_mode_module = ModuleType("harbor.models.task.verifier_mode")
    tasks_package = ModuleType("harbor.tasks")
    task_client_module = ModuleType("harbor.tasks.client")
    trial_package = ModuleType("harbor.trial")
    trial_module = ModuleType("harbor.trial.trial")
    single_step_module = ModuleType("harbor.trial.single_step")

    class FakeTrial:
        @staticmethod
        async def _load_task(config):
            return "network-loader", config

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

        def _record_exception(self, error):
            self.recorded_exception = error

    class FakeSingleStepTrial(FakeTrial):
        async def _run_verifier(self):
            if getattr(self, "verifier_disabled", False):
                return
            verifier_events = getattr(self, "verifier_events", None)
            if isinstance(verifier_events, list):
                verifier_events.append(
                    ("verifier", self.agent_environment.default_user)
                )
            self.verifier_calls += 1
            verifier_error = getattr(self, "verifier_error", None)
            if verifier_error is not None:
                raise verifier_error

    class FakePackageTaskId:
        def __init__(self, *, ref, path) -> None:
            self.ref = ref
            self._path = path

        def get_local_path(self):
            return self._path

    class FakeTaskDownloadResult(SimpleNamespace):
        pass

    FakeTrial.single_step_type = FakeSingleStepTrial
    task_id_module.PackageTaskId = FakePackageTaskId
    task_module.Task = FakeTask
    task_client_module.TaskDownloadResult = FakeTaskDownloadResult
    trial_module.Trial = FakeTrial
    single_step_module.SingleStepTrial = FakeSingleStepTrial
    verifier_mode_module.task_has_any_separate_verifier = (
        lambda config: config.verifier_mode in {"separate", "mixed"}
    )
    verifier_mode_module.task_has_any_shared_verifier = (
        lambda config: config.verifier_mode in {"shared", "mixed"}
    )
    monkeypatch.setitem(sys.modules, "harbor", harbor)
    monkeypatch.setitem(sys.modules, "harbor.models", models)
    monkeypatch.setitem(sys.modules, "harbor.models.task", task_package)
    monkeypatch.setitem(sys.modules, "harbor.models.task.id", task_id_module)
    monkeypatch.setitem(sys.modules, "harbor.models.task.task", task_module)
    monkeypatch.setitem(sys.modules, "harbor.tasks", tasks_package)
    monkeypatch.setitem(sys.modules, "harbor.tasks.client", task_client_module)
    monkeypatch.setitem(sys.modules, "harbor.trial", trial_package)
    monkeypatch.setitem(sys.modules, "harbor.trial.trial", trial_module)
    monkeypatch.setitem(sys.modules, "harbor.trial.single_step", single_step_module)
    monkeypatch.setitem(
        sys.modules,
        "harbor.models.task.verifier_mode",
        verifier_mode_module,
    )
    monkeypatch.setattr(
        "nano_grok_build.harbor.compat_v020.importlib.metadata.version",
        lambda _: "0.20.0",
    )
    FakeTrial.package_task_id_type = FakePackageTaskId
    return FakeTrial


def make_job(tmp_path: Path) -> tuple[SimpleNamespace, SimpleNamespace]:
    trial = SimpleNamespace(
        task=SimpleNamespace(get_local_path=lambda: tmp_path / "task"),
        extra_instruction_paths=[],
        trials_dir=tmp_path / "trials",
        trial_name="trial-1",
        agent=FakeAgent(),
    )
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    return (
        SimpleNamespace(
            is_resuming=False,
            _trial_configs=[trial],
            id="job-1",
            job_dir=job_dir,
        ),
        trial,
    )


def make_inputs(tmp_path: Path) -> RuntimeInputs:
    launch = SimpleNamespace(
        kind=SimpleNamespace(value="scripted"),
        to_config=lambda: {"kind": "scripted"},
    )
    return RuntimeInputs(
        binary_path=tmp_path / "nano-cli",
        contract_dir=tmp_path / "contract",
        provider_launch=launch,
        contract_id="synthetic-v1",
        contract_set_sha256="b" * 64,
        profile_id="synthetic-profile-v1",
        provider_model="synthetic-model",
        max_turns=4,
        active_tools=("write", "run_terminal_command", "read_file"),
        reasoning_effort="high",
    )


def test_bound_run_spec_carries_exact_requested_selector(
    tmp_path: Path,
    monkeypatch,
) -> None:
    install_harbor_stubs(monkeypatch)
    job, trial = make_job(tmp_path)
    inputs = make_inputs(tmp_path)
    specs = bind_run_specs(job, inputs)
    assert specs[0]["active_tools"] == [
        "write",
        "run_terminal_command",
        "read_file",
    ]
    assert trial.agent.kwargs["run_spec"]["active_tools"] == specs[0]["active_tools"]
    assert trial.agent.kwargs["reasoning_effort"] == "high"
    assert "expected_contract_binding" not in trial.agent.kwargs
    envelope = json.loads((Path(job.job_dir) / "nano-dispatch.json").read_text())
    assert (
        envelope["manifest"]["run_specs"][0]["active_tools"] == specs[0]["active_tools"]
    )
    expected_private_runtime = (
        tmp_path / "trials" / "trial-1" / ".nano-control-v2" / "runtime"
    ).resolve()
    assert Path(specs[0]["artifact_dir"]) == expected_private_runtime
    assert (
        Path(trial.agent.kwargs["run_spec"]["artifact_dir"]) == expected_private_runtime
    )
    assert (
        Path(envelope["manifest"]["run_specs"][0]["artifact_dir"])
        == expected_private_runtime
    )
    assert "agent" not in expected_private_runtime.parts[-3:]


def test_resolved_package_task_cache_seam_avoids_trial_registry_lookup(
    tmp_path: Path,
    monkeypatch,
) -> None:
    fake_trial = install_harbor_stubs(monkeypatch)
    digest = "c" * 64
    cached = tmp_path / digest
    cached.mkdir()
    package_id = fake_trial.package_task_id_type(
        ref=f"sha256:{digest}",
        path=cached,
    )
    config = SimpleNamespace(
        task=SimpleNamespace(get_task_id=lambda: package_id),
        extra_instruction_paths=[tmp_path / "extra.md"],
        verifier=SimpleNamespace(disable=True),
    )

    install_resolved_package_task_cache_seam()
    task, result = asyncio.run(fake_trial._load_task(config))

    assert task.path == cached
    assert task.extra_instruction_paths == config.extra_instruction_paths
    assert task.disable_verification is True
    assert result.path == cached
    assert result.cached is True
    assert result.content_hash == digest
    assert result.download_time_sec == 0.0

    fallback_config = SimpleNamespace(
        task=SimpleNamespace(get_task_id=lambda: object()),
    )
    assert asyncio.run(fake_trial._load_task(fallback_config)) == (
        "network-loader",
        fallback_config,
    )


def test_legacy_contract_receipt_fields_remain_in_the_run_spec(
    tmp_path: Path,
    monkeypatch,
) -> None:
    install_harbor_stubs(monkeypatch)
    job, trial = make_job(tmp_path)
    specs = bind_run_specs(job, make_inputs(tmp_path))

    assert specs[0]["contract"] == {
        "id": "synthetic-v1",
        "contract_set_sha256": "b" * 64,
        "profile_id": "synthetic-profile-v1",
    }
    assert "expected_contract_binding" not in specs[0]
    assert "expected_contract_binding" not in trial.agent.kwargs
    envelope = json.loads((Path(job.job_dir) / "nano-dispatch.json").read_text())
    assert "expected_contract_binding" not in envelope["manifest"]


def test_separate_or_mixed_verifier_rejected_before_binding(
    tmp_path: Path,
    monkeypatch,
) -> None:
    install_harbor_stubs(monkeypatch)
    job, trial = make_job(tmp_path)
    original_agent = trial.agent
    for mode in ("separate", "mixed"):
        FakeTask.verifier_mode = mode
        try:
            with pytest.raises(
                RuntimeError,
                match="requires shared verifier mode",
            ):
                bind_run_specs(job, make_inputs(tmp_path))
        finally:
            FakeTask.verifier_mode = "shared"
        assert trial.agent is original_agent
        assert not (Path(job.job_dir) / "nano-dispatch.json").exists()


def test_multi_step_task_rejected_before_binding(
    tmp_path: Path,
    monkeypatch,
) -> None:
    install_harbor_stubs(monkeypatch)
    job, trial = make_job(tmp_path)
    original_agent = trial.agent
    FakeTask.steps = [SimpleNamespace(name="step-1")]
    try:
        with pytest.raises(RuntimeError, match="single-step"):
            bind_run_specs(job, make_inputs(tmp_path))
    finally:
        FakeTask.steps = None
    assert trial.agent is original_agent
    assert not (Path(job.job_dir) / "nano-dispatch.json").exists()


def test_harbor_wait_for_seam_mints_one_root_deadline_at_dispatch(
    tmp_path: Path,
    monkeypatch,
) -> None:
    trial_type = install_harbor_stubs(monkeypatch)
    job, _ = make_job(tmp_path)
    bind_run_specs(job, make_inputs(tmp_path))

    observed = []

    class DeadlineAgent:
        SUPPORTS_NANO_RUN_DEADLINE_V1 = True

        async def run(self, **_kwargs):
            raise AssertionError("live deadline run bypassed the Harbor seam")

        async def resume(self, **_kwargs):
            raise AssertionError("resume is unsupported")

        async def run_with_deadline(self, *, deadline, **_kwargs):
            observed.append(deadline)

        async def post_agent_workspace_snapshot_v1(
            self,
            *,
            hard_deadline_monotonic_ns,
        ):
            assert hard_deadline_monotonic_ns == 160_000_000_000
            return None

    monkeypatch.setattr(
        "nano_grok_build.harbor.compat_v020.host_monotonic_ns",
        lambda: 10_000_000_000,
    )
    trial = trial_type()
    trial.agent = DeadlineAgent()
    trial.agent_environment = FakeEnvironment()
    target = SimpleNamespace(agent_result=object())

    asyncio.run(
        trial._run_agent_phase(
            target=target,
            instruction="do the work",
            timeout_sec=120,
            user=None,
        )
    )

    assert len(observed) == 1
    assert observed[0].as_dict() == {
        "schema_version": "nano-run-deadline-v1",
        "hard_deadline_monotonic_ns": 130_000_000_000,
        "source": "harbor_agent_phase",
        "agent_timeout_ms": 120_000,
    }
    assert "run" not in vars(trial.agent)


def test_verifier_preparation_precedes_harbor_publication_and_repeats_without_io(
    tmp_path: Path,
    monkeypatch,
) -> None:
    trial_type = install_harbor_stubs(monkeypatch)
    job, _ = make_job(tmp_path)
    bind_run_specs(job, make_inputs(tmp_path))
    monkeypatch.setattr(
        "nano_grok_build.harbor.compat_v020.host_monotonic_ns",
        lambda: 10_000_000_000,
    )
    events: list[str] = []

    class Agent:
        SUPPORTS_NANO_RUN_DEADLINE_V1 = True
        SUPPORTS_BACKGROUND_VERIFIER_HANDOFF_V1 = True

        def __init__(self) -> None:
            self.prepared = False
            self.private_control_available = True

        async def run_with_deadline(self, **_kwargs):
            events.append("agent")

        async def post_agent_workspace_snapshot_v1(self, **_kwargs):
            events.append("snapshot")
            return object()

        async def prepare_shared_verifier_v1(self, **_kwargs):
            if not self.prepared:
                assert self.private_control_available is True
                events.append("prepare-and-mint")
                self.prepared = True
            else:
                # Harbor has already published marker-last and destroyed the
                # private control tree. The verifier repeat must be no-I/O.
                assert self.private_control_available is False
                events.append("prepare-idempotent")

        async def post_verifier_cleanup_v1(self, **_kwargs):
            events.append("cleanup")

    trial = trial_type.single_step_type()
    trial.agent = Agent()
    trial.agent_environment = FakeEnvironment(default_user=77)
    trial.task = SimpleNamespace(
        config=SimpleNamespace(
            agent=SimpleNamespace(user=1002),
            verifier=SimpleNamespace(user=1001),
        )
    )
    trial.config = SimpleNamespace(verifier=SimpleNamespace(disable=False))
    trial.verifier_calls = 0
    trial.verifier_error = None

    asyncio.run(
        trial._run_agent_phase(
            target=SimpleNamespace(agent_result=object()),
            instruction="work",
            timeout_sec=120,
            user=1002,
        )
    )
    assert events == ["agent", "snapshot", "prepare-and-mint"]

    # Model Harbor's intervening AgentContext sync: publication is complete and
    # the private control root no longer exists before `_run_verifier` starts.
    trial.agent.private_control_available = False
    asyncio.run(trial._run_verifier())

    assert events == [
        "agent",
        "snapshot",
        "prepare-and-mint",
        "prepare-idempotent",
        "cleanup",
    ]
    assert trial.verifier_calls == 1


def test_prepublication_preparation_failure_prevents_agent_phase_return(
    tmp_path: Path,
    monkeypatch,
) -> None:
    trial_type = install_harbor_stubs(monkeypatch)
    job, _ = make_job(tmp_path)
    bind_run_specs(job, make_inputs(tmp_path))
    monkeypatch.setattr(
        "nano_grok_build.harbor.compat_v020.host_monotonic_ns",
        lambda: 10_000_000_000,
    )
    events: list[str] = []

    class Agent:
        SUPPORTS_NANO_RUN_DEADLINE_V1 = True
        SUPPORTS_BACKGROUND_VERIFIER_HANDOFF_V1 = True

        async def run_with_deadline(self, **_kwargs):
            events.append("agent")

        async def post_agent_workspace_snapshot_v1(self, **_kwargs):
            events.append("snapshot")

        async def prepare_shared_verifier_v1(self, **_kwargs):
            events.append("prepare")
            raise BridgeError("git_history_rehydration_invalid")

    trial = trial_type()
    trial.agent = Agent()
    trial.agent_environment = FakeEnvironment()
    trial.config = SimpleNamespace(verifier=SimpleNamespace(disable=False))

    with pytest.raises(BridgeError, match="^git_history_rehydration_invalid$"):
        asyncio.run(
            trial._run_agent_phase(
                target=SimpleNamespace(agent_result=object()),
                instruction="work",
                timeout_sec=120,
                user=None,
            )
        )
    assert events == ["agent", "snapshot", "prepare"]


def test_disabled_verifier_does_not_mint_rehydration_preparation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    trial_type = install_harbor_stubs(monkeypatch)
    job, _ = make_job(tmp_path)
    bind_run_specs(job, make_inputs(tmp_path))
    monkeypatch.setattr(
        "nano_grok_build.harbor.compat_v020.host_monotonic_ns",
        lambda: 10_000_000_000,
    )
    events: list[str] = []

    class Agent:
        SUPPORTS_NANO_RUN_DEADLINE_V1 = True
        SUPPORTS_BACKGROUND_VERIFIER_HANDOFF_V1 = True

        async def run_with_deadline(self, **_kwargs):
            events.append("agent")

        async def post_agent_workspace_snapshot_v1(self, **_kwargs):
            events.append("snapshot")

        async def prepare_shared_verifier_v1(self, **_kwargs):
            raise AssertionError("disabled verifier must not restore history")

    trial = trial_type()
    trial.agent = Agent()
    trial.agent_environment = FakeEnvironment()
    trial.config = SimpleNamespace(verifier=SimpleNamespace(disable=True))
    asyncio.run(
        trial._run_agent_phase(
            target=SimpleNamespace(agent_result=object()),
            instruction="work",
            timeout_sec=120,
            user=None,
        )
    )
    assert events == ["agent", "snapshot"]


def test_harbor_deadline_seam_is_per_agent_and_restores_after_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    trial_type = install_harbor_stubs(monkeypatch)
    job, _ = make_job(tmp_path)
    bind_run_specs(job, make_inputs(tmp_path))
    clock = iter(
        (
            10_000_000_000,
            20_000_000_000,
            30_000_000_000,
            40_000_000_000,
        )
    )
    monkeypatch.setattr(
        "nano_grok_build.harbor.compat_v020.host_monotonic_ns",
        lambda: next(clock),
    )

    entered = 0
    both_entered = asyncio.Event()
    release = asyncio.Event()
    observed: list[tuple[str, int]] = []

    class DeadlineAgent:
        SUPPORTS_NANO_RUN_DEADLINE_V1 = True

        def __init__(self, name: str, *, fail: bool = False) -> None:
            self.name = name
            self.fail = fail

        async def run(self, **_kwargs):
            raise AssertionError("live deadline run bypassed the Harbor seam")

        async def resume(self, **_kwargs):
            raise AssertionError("resume is unsupported")

        async def run_with_deadline(self, *, deadline, **_kwargs):
            nonlocal entered
            observed.append((self.name, deadline.hard_deadline_monotonic_ns))
            entered += 1
            if entered == 2:
                both_entered.set()
            await release.wait()
            if self.fail:
                raise RuntimeError("synthetic agent failure")

        async def post_agent_workspace_snapshot_v1(
            self,
            *,
            hard_deadline_monotonic_ns,
        ):
            assert hard_deadline_monotonic_ns > 0
            return None

    first = trial_type()
    first.agent = DeadlineAgent("first")
    first.agent_environment = FakeEnvironment()
    second = trial_type()
    second.agent = DeadlineAgent("second", fail=True)
    second.agent_environment = FakeEnvironment()
    target = SimpleNamespace(agent_result=object())

    async def scenario() -> None:
        first_task = asyncio.create_task(
            first._run_agent_phase(
                target=target,
                instruction="first",
                timeout_sec=120,
                user=None,
            )
        )
        second_task = asyncio.create_task(
            second._run_agent_phase(
                target=target,
                instruction="second",
                timeout_sec=120,
                user=None,
            )
        )
        await asyncio.wait_for(both_entered.wait(), timeout=1)
        assert "run" in vars(first.agent)
        assert "run" in vars(second.agent)
        assert vars(first.agent)["run"] is not vars(second.agent)["run"]
        release.set()
        await first_task
        with pytest.raises(RuntimeError, match="synthetic agent failure"):
            await second_task

    asyncio.run(scenario())
    assert observed == [
        ("first", 130_000_000_000),
        ("second", 140_000_000_000),
    ]
    assert "run" not in vars(first.agent)
    assert "run" not in vars(second.agent)


def test_post_agent_hook_exactly_once_and_dual_failure_precedence(
    tmp_path: Path,
    monkeypatch,
) -> None:
    trial_type = install_harbor_stubs(monkeypatch)
    job, _ = make_job(tmp_path)
    bind_run_specs(job, make_inputs(tmp_path))
    monkeypatch.setattr(
        "nano_grok_build.harbor.compat_v020.host_monotonic_ns",
        lambda: 10_000_000_000,
    )
    events: list[str] = []
    primary = RuntimeError("agent-primary")
    hook_fatal = BridgeError("post_agent_workspace_snapshot_security_fatal")

    class DeadlineAgent:
        SUPPORTS_NANO_RUN_DEADLINE_V1 = True

        async def run_with_deadline(self, **_kwargs):
            events.append("agent")
            raise primary

        async def post_agent_workspace_snapshot_v1(
            self,
            *,
            hard_deadline_monotonic_ns,
        ):
            assert hard_deadline_monotonic_ns == 160_000_000_000
            assert "run" not in vars(self)
            events.append("hook")
            raise hook_fatal

    trial = trial_type()
    trial.agent = DeadlineAgent()
    trial.agent_environment = FakeEnvironment()
    target = SimpleNamespace(agent_result=object())

    with pytest.raises(BridgeError) as caught:
        asyncio.run(
            trial._run_agent_phase(
                target=target,
                instruction="work",
                timeout_sec=120,
                user=None,
            )
        )

    assert caught.value is hook_fatal
    assert caught.value.__cause__ is primary
    assert events == ["agent", "hook"]
    assert "run" not in vars(trial.agent)


def test_post_agent_safe_result_preserves_primary_and_missing_hook_is_fatal(
    tmp_path: Path,
    monkeypatch,
) -> None:
    trial_type = install_harbor_stubs(monkeypatch)
    job, _ = make_job(tmp_path)
    bind_run_specs(job, make_inputs(tmp_path))
    monkeypatch.setattr(
        "nano_grok_build.harbor.compat_v020.host_monotonic_ns",
        lambda: 10_000_000_000,
    )
    primary = RuntimeError("agent-primary")

    class SafeAgent:
        SUPPORTS_NANO_RUN_DEADLINE_V1 = True

        def __init__(self) -> None:
            self.hook_calls = 0

        async def run_with_deadline(self, **_kwargs):
            raise primary

        async def post_agent_workspace_snapshot_v1(
            self,
            *,
            hard_deadline_monotonic_ns,
        ):
            assert hard_deadline_monotonic_ns == 160_000_000_000
            assert "run" not in vars(self)
            self.hook_calls += 1

    safe_trial = trial_type()
    safe_trial.agent = SafeAgent()
    safe_trial.agent_environment = FakeEnvironment()
    target = SimpleNamespace(agent_result=object())
    with pytest.raises(RuntimeError) as caught:
        asyncio.run(
            safe_trial._run_agent_phase(
                target=target,
                instruction="work",
                timeout_sec=120,
                user=None,
            )
        )
    assert caught.value is primary
    assert safe_trial.agent.hook_calls == 1

    class DiagnosticFailureAgent:
        SUPPORTS_NANO_RUN_DEADLINE_V1 = True

        def __init__(self) -> None:
            self.run_calls = 0

        async def run_with_deadline(self, **_kwargs):
            self.run_calls += 1

        async def post_agent_workspace_snapshot_v1(
            self,
            *,
            hard_deadline_monotonic_ns,
        ):
            assert hard_deadline_monotonic_ns == 160_000_000_000
            raise BridgeError("post_agent_workspace_snapshot_deadline_exceeded")

    diagnostic_trial = trial_type()
    diagnostic_trial.agent = DiagnosticFailureAgent()
    diagnostic_trial.agent_environment = FakeEnvironment()
    asyncio.run(
        diagnostic_trial._run_agent_phase(
            target=target,
            instruction="work",
            timeout_sec=120,
            user=None,
        )
    )
    assert diagnostic_trial.agent.run_calls == 1

    class MissingHookAgent:
        SUPPORTS_NANO_RUN_DEADLINE_V1 = True

        def __init__(self) -> None:
            self.run_calls = 0

        async def run_with_deadline(self, **_kwargs):
            self.run_calls += 1

    missing_trial = trial_type()
    missing_trial.agent = MissingHookAgent()
    missing_trial.agent_environment = FakeEnvironment()
    with pytest.raises(
        DeadlineContractError,
        match="^post_agent_workspace_hook_unavailable$",
    ):
        asyncio.run(
            missing_trial._run_agent_phase(
                target=target,
                instruction="work",
                timeout_sec=120,
                user=None,
            )
        )
    assert missing_trial.agent.run_calls == 0


def test_eligible_terminal_failure_is_recorded_and_returns_to_harbor(
    tmp_path: Path,
    monkeypatch,
) -> None:
    trial_type = install_harbor_stubs(monkeypatch)
    job, _ = make_job(tmp_path)
    bind_run_specs(job, make_inputs(tmp_path))
    monkeypatch.setattr(
        "nano_grok_build.harbor.compat_v020.host_monotonic_ns",
        lambda: 10_000_000_000,
    )
    primary = RuntimeError("terminalized-agent-failure")
    receipt = object()
    events: list[str] = []
    runtime = VerifierTerminalRuntimeV1(
        schema_version="nano-run-record-v3",
        run_id="run-1",
        trial_id="trial-1",
        attempt_id="attempt-0",
        run_spec_sha256="a" * 64,
        terminal_status="deadline_failure",
        terminal_phase="deadline",
        terminal_code="run_deadline_exceeded",
        run_record_sha256="b" * 64,
        events_sha256="c" * 64,
    )

    class EligibleAgent:
        SUPPORTS_NANO_RUN_DEADLINE_V1 = True
        SUPPORTS_BACKGROUND_VERIFIER_HANDOFF_V1 = True

        async def run_with_deadline(self, **_kwargs):
            events.append("agent")
            raise primary

        async def post_agent_workspace_snapshot_v1(
            self,
            *,
            hard_deadline_monotonic_ns,
        ):
            assert hard_deadline_monotonic_ns == 160_000_000_000
            events.append("snapshot")
            return receipt

        async def verifier_opportunity_decision_v1(self, **kwargs):
            assert kwargs == {
                "primary_error": primary,
                "result_target": target,
                "workspace_receipt": receipt,
                "hard_deadline_monotonic_ns": 160_000_000_000,
            }
            events.append("decision")
            return VerifierOpportunityDecisionV1._grant(
                runtime=runtime,
                workspace_receipt_sha256="d" * 64,
                canonical_workspace="/workspace",
            )

        async def prepare_shared_verifier_v1(self, **_kwargs):
            events.append("prepare")

    trial = trial_type()
    trial.agent = EligibleAgent()
    trial.agent_environment = FakeEnvironment()
    target = SimpleNamespace(agent_result=object())

    asyncio.run(
        trial._run_agent_phase(
            target=target,
            instruction="work",
            timeout_sec=120,
            user=None,
        )
    )

    assert trial.recorded_exception is primary
    assert trial.recorded_exception.__traceback__ is not None
    assert events == ["agent", "snapshot", "decision", "prepare"]


def test_eligible_decision_cannot_be_constructed_without_complete_proof() -> None:
    with pytest.raises(ValueError, match="proof is incomplete"):
        VerifierOpportunityDecisionV1(eligible=True)


def test_base_exception_is_never_absorbed_by_eligible_decision(
    tmp_path: Path,
    monkeypatch,
) -> None:
    trial_type = install_harbor_stubs(monkeypatch)
    job, _ = make_job(tmp_path)
    bind_run_specs(job, make_inputs(tmp_path))
    monkeypatch.setattr(
        "nano_grok_build.harbor.compat_v020.host_monotonic_ns",
        lambda: 10_000_000_000,
    )

    class ControllerAbort(BaseException):
        pass

    primary = ControllerAbort("stop")

    class AbortAgent:
        SUPPORTS_NANO_RUN_DEADLINE_V1 = True

        async def run_with_deadline(self, **_kwargs):
            raise primary

        async def post_agent_workspace_snapshot_v1(self, **_kwargs):
            return object()

        async def verifier_opportunity_decision_v1(self, **_kwargs):
            raise AssertionError("BaseException must not reach eligibility")

    trial = trial_type()
    trial.agent = AbortAgent()
    trial.agent_environment = FakeEnvironment()

    with pytest.raises(ControllerAbort) as caught:
        asyncio.run(
            trial._run_agent_phase(
                target=SimpleNamespace(agent_result=object()),
                instruction="work",
                timeout_sec=120,
                user=None,
            )
        )

    assert caught.value is primary


@pytest.mark.parametrize("post_now_sec", [129, 131])
def test_post_snapshot_gets_fresh_diagnostic_root_after_agent_timeout(
    tmp_path: Path,
    monkeypatch,
    post_now_sec: int,
) -> None:
    trial_type = install_harbor_stubs(monkeypatch)
    job, _ = make_job(tmp_path)
    bind_run_specs(job, make_inputs(tmp_path))
    clock = iter((10_000_000_000, post_now_sec * 1_000_000_000))
    monkeypatch.setattr(
        "nano_grok_build.harbor.compat_v020.host_monotonic_ns",
        lambda: next(clock),
    )
    primary = TimeoutError("agent timed out")

    class DeadlineAgent:
        SUPPORTS_NANO_RUN_DEADLINE_V1 = True

        def __init__(self) -> None:
            self.solve_hard_ns = None
            self.post_hard_ns = None

        async def run_with_deadline(self, *, deadline, **_kwargs):
            self.solve_hard_ns = deadline.hard_deadline_monotonic_ns
            raise primary

        async def post_agent_workspace_snapshot_v1(
            self,
            *,
            hard_deadline_monotonic_ns,
        ):
            assert "run" not in vars(self)
            self.post_hard_ns = hard_deadline_monotonic_ns

    trial = trial_type()
    trial.agent = DeadlineAgent()
    trial.agent_environment = FakeEnvironment()
    target = SimpleNamespace(agent_result=object())

    with pytest.raises(TimeoutError) as caught:
        asyncio.run(
            trial._run_agent_phase(
                target=target,
                instruction="work",
                timeout_sec=120,
                user=None,
            )
        )

    assert caught.value is primary
    assert trial.agent.solve_hard_ns == 130_000_000_000
    assert trial.agent.post_hard_ns == (post_now_sec + 150) * 1_000_000_000


def test_post_snapshot_reenters_same_non_root_default_user(
    tmp_path: Path,
    monkeypatch,
) -> None:
    trial_type = install_harbor_stubs(monkeypatch)
    job, _ = make_job(tmp_path)
    bind_run_specs(job, make_inputs(tmp_path))
    monkeypatch.setattr(
        "nano_grok_build.harbor.compat_v020.host_monotonic_ns",
        lambda: 10_000_000_000,
    )
    observed_users: list[object] = []

    class DeadlineAgent:
        SUPPORTS_NANO_RUN_DEADLINE_V1 = True

        async def run_with_deadline(self, *, environment, **_kwargs):
            observed_users.append(environment.default_user)

        async def post_agent_workspace_snapshot_v1(
            self,
            *,
            hard_deadline_monotonic_ns,
        ):
            assert hard_deadline_monotonic_ns == 160_000_000_000
            observed_users.append(trial.agent_environment.default_user)

    trial = trial_type()
    trial.agent = DeadlineAgent()
    trial.agent_environment = FakeEnvironment(default_user=77)
    target = SimpleNamespace(agent_result=object())
    asyncio.run(
        trial._run_agent_phase(
            target=target,
            instruction="work",
            timeout_sec=120,
            user=1001,
        )
    )

    assert observed_users == [1001, 1001]
    assert trial.agent_environment.default_user == 77


@pytest.mark.parametrize(
    ("label", "verifier_error", "disabled"),
    [
        ("success", None, False),
        ("failure", RuntimeError("verifier failed"), False),
        ("timeout", TimeoutError("verifier timed out"), False),
        ("cancel", asyncio.CancelledError(), False),
        ("disabled", None, True),
    ],
)
def test_verifier_finally_cleanup_runs_once_on_every_exit(
    tmp_path: Path,
    monkeypatch,
    label: str,
    verifier_error: BaseException | None,
    disabled: bool,
) -> None:
    trial_type = install_harbor_stubs(monkeypatch)
    job, _ = make_job(tmp_path)
    bind_run_specs(job, make_inputs(tmp_path))
    monkeypatch.setattr(
        "nano_grok_build.harbor.compat_v020.host_monotonic_ns",
        lambda: 10_000_000_000,
    )
    cleanup_calls: list[int] = []
    cleanup_users: list[object] = []

    class Agent:
        SUPPORTS_BACKGROUND_VERIFIER_HANDOFF_V1 = True

        async def post_verifier_cleanup_v1(
            self,
            *,
            hard_deadline_monotonic_ns,
        ):
            cleanup_calls.append(hard_deadline_monotonic_ns)
            cleanup_users.append(trial.agent_environment.default_user)

    trial = trial_type.single_step_type()
    trial.agent = Agent()
    trial.agent_environment = FakeEnvironment(default_user=77)
    trial.task = SimpleNamespace(
        config=SimpleNamespace(
            agent=SimpleNamespace(user=1002),
            verifier=SimpleNamespace(user=1001),
        )
    )
    trial.verifier_calls = 0
    trial.verifier_error = verifier_error
    trial.verifier_disabled = disabled

    if verifier_error is None:
        asyncio.run(trial._run_verifier())
    else:
        with pytest.raises(type(verifier_error)) as caught:
            asyncio.run(trial._run_verifier())
        assert caught.value is verifier_error, label

    assert trial.verifier_calls == (0 if disabled else 1)
    assert cleanup_calls == [40_000_000_000]
    assert cleanup_users == [1002]
    assert trial.agent_environment.default_user == 77


def test_verifier_preparation_runs_immediately_before_shared_verifier(
    tmp_path: Path,
    monkeypatch,
) -> None:
    trial_type = install_harbor_stubs(monkeypatch)
    job, _ = make_job(tmp_path)
    bind_run_specs(job, make_inputs(tmp_path))
    monkeypatch.setattr(
        "nano_grok_build.harbor.compat_v020.host_monotonic_ns",
        lambda: 10_000_000_000,
    )
    events: list[tuple[str, object]] = []

    class Agent:
        SUPPORTS_BACKGROUND_VERIFIER_HANDOFF_V1 = True

        async def prepare_shared_verifier_v1(
            self,
            *,
            hard_deadline_monotonic_ns,
        ):
            events.append(
                (
                    "prepare",
                    (
                        hard_deadline_monotonic_ns,
                        trial.agent_environment.default_user,
                    ),
                )
            )

        async def post_verifier_cleanup_v1(
            self,
            *,
            hard_deadline_monotonic_ns,
        ):
            events.append(
                (
                    "cleanup",
                    (
                        hard_deadline_monotonic_ns,
                        trial.agent_environment.default_user,
                    ),
                )
            )

    trial = trial_type.single_step_type()
    trial.agent = Agent()
    trial.agent_environment = FakeEnvironment(default_user=77)
    trial.task = SimpleNamespace(
        config=SimpleNamespace(
            agent=SimpleNamespace(user=1002),
            verifier=SimpleNamespace(user=1001),
        )
    )
    trial.config = SimpleNamespace(verifier=SimpleNamespace(disable=False))
    trial.verifier_calls = 0
    trial.verifier_error = None
    trial.verifier_events = events
    asyncio.run(trial._run_verifier())

    assert trial.verifier_calls == 1
    assert events == [
        ("prepare", (160_000_000_000, 1002)),
        ("verifier", 77),
        ("cleanup", (40_000_000_000, 1002)),
    ]
    assert trial.agent_environment.default_user == 77
