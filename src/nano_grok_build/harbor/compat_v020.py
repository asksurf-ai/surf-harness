"""The sole compatibility seam for Harbor v0.20.0 private trial configs."""

from __future__ import annotations

import asyncio
import hashlib
import importlib.metadata
import inspect
import json
import math
import os
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from typing import Any

from nano_grok_build.adapter.artifactizer import VerifierOpportunityDecisionV1
from nano_grok_build.adapter.deadline import (
    DeadlineContractError,
    host_monotonic_ns,
)
from nano_grok_build.harbor.deadline import (
    DEADLINE_MODE_HARBOR_ROOT,
    mint_harbor_agent_phase,
)
from nano_grok_build.harbor.provider import HostProviderLaunch

HARBOR_VERSION = "0.20.0"
_DISPATCH_SCHEMA = "nano-harbor-dispatch-v1"
_DEADLINE_SEAM_VERSION = "nano-harbor-agent-phase-post-snapshot-seam-v4"
_VERIFIER_CLEANUP_SEAM_VERSION = "nano-background-verifier-cleanup-seam-v1"
_RESOLVED_TASK_CACHE_SEAM_VERSION = "nano-resolved-package-task-cache-seam-v1"
_POST_AGENT_DIAGNOSTIC_TIMEOUT_SEC = 150.0
_POST_VERIFIER_CLEANUP_TIMEOUT_SEC = 30.0
_POST_AGENT_FATAL_CODES = frozenset(
    {
        "external_bridge_cleanup_unverified",
        "post_agent_workspace_receipt_binding_invalid",
        "post_agent_workspace_snapshot_security_fatal",
        "post_snapshot_background_liveness_invalid",
        "terminal_actor_snapshot_termination_unverified",
        "workspace_before_snapshot_invalid",
        "workspace_snapshot_remote_cleanup_unverified",
        "workspace_snapshot_remote_termination_unverified",
        "workspace_snapshot_target_mismatch",
    }
)
_AGENT_PHASE_PARAMETERS = (
    "self",
    "target",
    "instruction",
    "timeout_sec",
    "user",
    "step_cfg",
    "resume",
)
_VERIFIER_PARAMETERS = ("self",)
_TASK_LOAD_PARAMETERS = ("config",)


@dataclass(frozen=True)
class RuntimeInputs:
    binary_path: Path
    contract_dir: Path
    provider_launch: HostProviderLaunch
    contract_id: str
    contract_set_sha256: str
    profile_id: str
    provider_model: str
    max_turns: int
    active_tools: tuple[str, ...] | None = None
    reasoning_effort: str | None = None


def _write_new(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _timeout_milliseconds(timeout_sec: object) -> int:
    if (
        isinstance(timeout_sec, bool)
        or not isinstance(timeout_sec, int | float)
        or not math.isfinite(timeout_sec)
        or timeout_sec <= 0
    ):
        raise DeadlineContractError("deadline_timeout_invalid")
    milliseconds = timeout_sec * 1000
    if milliseconds != int(milliseconds) or milliseconds > 2**64 - 1:
        raise DeadlineContractError("deadline_timeout_invalid")
    return int(milliseconds)


def _post_agent_hook_failure_is_fatal(error: BaseException) -> bool:
    code = getattr(error, "code", None)
    stable = code if isinstance(code, str) else str(error)
    return stable in _POST_AGENT_FATAL_CODES


def _install_verifier_cleanup_seam() -> None:
    if importlib.metadata.version("harbor") != HARBOR_VERSION:
        raise RuntimeError("unsupported Harbor version")
    from harbor.trial.single_step import SingleStepTrial

    current = SingleStepTrial._run_verifier  # noqa: SLF001
    if (
        getattr(current, "__nano_verifier_cleanup_seam__", None)
        == _VERIFIER_CLEANUP_SEAM_VERSION
    ):
        return
    if tuple(inspect.signature(current).parameters) != _VERIFIER_PARAMETERS:
        raise RuntimeError("Harbor verifier signature changed")

    @wraps(current)
    async def run_verifier_with_cleanup(self: Any) -> None:
        agent = self.agent
        if not getattr(
            agent,
            "SUPPORTS_BACKGROUND_VERIFIER_HANDOFF_V1",
            False,
        ):
            await current(self)
            return
        cleanup = getattr(agent, "post_verifier_cleanup_v1", None)
        if not callable(cleanup):
            raise DeadlineContractError("background_verifier_cleanup_hook_unavailable")
        primary_error: BaseException | None = None
        primary_traceback: Any = None
        try:
            await current(self)
        except BaseException as error:
            primary_error = error
            primary_traceback = error.__traceback__

        hard_deadline_monotonic_ns = host_monotonic_ns() + int(
            _POST_VERIFIER_CLEANUP_TIMEOUT_SEC * 1_000_000_000
        )
        try:
            user = self.task.config.agent.user
            with self.agent_environment.with_default_user(user):
                await cleanup(
                    hard_deadline_monotonic_ns=hard_deadline_monotonic_ns,
                )
        except BaseException as cleanup_error:
            if primary_error is not None:
                raise cleanup_error from primary_error
            raise
        if primary_error is not None:
            raise primary_error.with_traceback(primary_traceback)

    setattr(
        run_verifier_with_cleanup,
        "__nano_verifier_cleanup_seam__",
        _VERIFIER_CLEANUP_SEAM_VERSION,
    )
    SingleStepTrial._run_verifier = run_verifier_with_cleanup  # noqa: SLF001


def install_harbor_deadline_seam() -> None:
    """Install the pinned, repo-owned root deadline seam once per Harbor class.

    Harbor evaluates ``agent.run(...)`` synchronously while constructing the
    awaitable passed to ``asyncio.wait_for``.  The temporary per-agent wrapper
    therefore mints the root at that exact dispatch expression without editing
    the external checkout or restarting the clock inside the adapter coroutine.
    """

    _install_verifier_cleanup_seam()

    from harbor.trial.trial import Trial

    current = Trial._run_agent_phase  # noqa: SLF001 - pinned compatibility seam
    if getattr(current, "__nano_deadline_seam__", None) == _DEADLINE_SEAM_VERSION:
        return
    if tuple(inspect.signature(current).parameters) != _AGENT_PHASE_PARAMETERS:
        raise RuntimeError("Harbor agent phase signature changed")

    @wraps(current)
    async def run_agent_phase_with_deadline(
        self: Any,
        *,
        target: Any,
        instruction: str,
        timeout_sec: float | None,
        user: str | int | None,
        step_cfg: Any = None,
        resume: bool = False,
    ) -> None:
        agent = self.agent
        if not getattr(agent, "SUPPORTS_NANO_RUN_DEADLINE_V1", False):
            await current(
                self,
                target=target,
                instruction=instruction,
                timeout_sec=timeout_sec,
                user=user,
                step_cfg=step_cfg,
                resume=resume,
            )
            return
        if step_cfg is not None:
            raise DeadlineContractError("deadline_multi_step_unsupported")
        if resume:
            raise DeadlineContractError("deadline_resume_unsupported")
        timeout_ms = _timeout_milliseconds(timeout_sec)
        run_with_deadline = getattr(agent, "run_with_deadline", None)
        if not callable(run_with_deadline):
            raise DeadlineContractError("deadline_contract_unavailable")
        post_agent_hook = getattr(
            agent,
            "post_agent_workspace_snapshot_v1",
            None,
        )
        if not callable(post_agent_hook):
            raise DeadlineContractError("post_agent_workspace_hook_unavailable")

        instance_values = vars(agent)
        had_instance_run = "run" in instance_values
        original_instance_run = instance_values.get("run")
        dispatch_count = 0

        def dispatch_with_root(
            *,
            instruction: str,
            environment: Any,
            context: Any,
        ) -> Any:
            nonlocal dispatch_count
            dispatch_count += 1
            if dispatch_count != 1:
                raise DeadlineContractError("deadline_dispatch_duplicate")
            deadline = mint_harbor_agent_phase(
                agent_timeout_ms=timeout_ms,
                now_monotonic_ns=host_monotonic_ns(),
            )
            return run_with_deadline(
                instruction=instruction,
                environment=environment,
                context=context,
                deadline=deadline,
            )

        agent.run = dispatch_with_root
        primary_error: BaseException | None = None
        primary_traceback: Any = None
        try:
            await current(
                self,
                target=target,
                instruction=instruction,
                timeout_sec=timeout_sec,
                user=user,
                step_cfg=step_cfg,
                resume=False,
            )
        except BaseException as error:
            primary_error = error
            primary_traceback = error.__traceback__
        finally:
            if had_instance_run:
                agent.run = original_instance_run
            else:
                del agent.run

        if dispatch_count != 1:
            if primary_error is not None:
                raise primary_error.with_traceback(primary_traceback)
            raise DeadlineContractError("deadline_contract_unavailable")

        post_hard_deadline_monotonic_ns = host_monotonic_ns() + int(
            _POST_AGENT_DIAGNOSTIC_TIMEOUT_SEC * 1_000_000_000
        )
        post_agent_receipt: object | None = None
        try:
            with self.agent_environment.with_default_user(user):
                post_agent_receipt = await post_agent_hook(
                    hard_deadline_monotonic_ns=post_hard_deadline_monotonic_ns,
                )
        except BaseException as error:
            hook_error: BaseException | None = error
        else:
            hook_error = None

        if hook_error is not None and _post_agent_hook_failure_is_fatal(hook_error):
            if primary_error is not None:
                raise hook_error from primary_error
            raise hook_error
        if hook_error is not None and not isinstance(hook_error, Exception):
            if primary_error is not None:
                raise hook_error from primary_error
            raise hook_error
        if primary_error is not None:
            if isinstance(primary_error, Exception) and hook_error is None:
                decide = getattr(
                    agent,
                    "verifier_opportunity_decision_v1",
                    None,
                )
                if callable(decide):
                    try:
                        with self.agent_environment.with_default_user(user):
                            decision = await decide(
                                primary_error=primary_error,
                                result_target=target,
                                workspace_receipt=post_agent_receipt,
                                hard_deadline_monotonic_ns=(
                                    post_hard_deadline_monotonic_ns
                                ),
                            )
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        decision = None
                    if (
                        type(decision) is VerifierOpportunityDecisionV1
                        and decision.proof_complete is True
                    ):
                        try:
                            raise primary_error.with_traceback(primary_traceback)
                        except Exception as restored:
                            self._record_exception(restored)  # noqa: SLF001
                        return
            raise primary_error.with_traceback(primary_traceback)

    setattr(
        run_agent_phase_with_deadline,
        "__nano_deadline_seam__",
        _DEADLINE_SEAM_VERSION,
    )
    Trial._run_agent_phase = run_agent_phase_with_deadline  # noqa: SLF001


def install_resolved_package_task_cache_seam() -> None:
    """Reuse Harbor's initial immutable package download for every trial.

    ``Job.create`` resolves and caches every package before binding the run.
    Harbor v0.20.0 nevertheless resolves the same package through the remote
    registry again in each ``Trial.create``. A transient registry failure then
    escapes before a trial result exists and cancels the whole ``TaskGroup``.
    Fixed digest refs already name the exact validated cache directory, so the
    repeated network lookup cannot add identity assurance.
    """

    if importlib.metadata.version("harbor") != HARBOR_VERSION:
        raise RuntimeError("unsupported Harbor version")

    from harbor.models.task.id import PackageTaskId
    from harbor.models.task.task import Task
    from harbor.tasks.client import TaskDownloadResult
    from harbor.trial.trial import Trial

    current = Trial._load_task  # noqa: SLF001 - pinned compatibility seam
    if (
        getattr(current, "__nano_resolved_task_cache_seam__", None)
        == _RESOLVED_TASK_CACHE_SEAM_VERSION
    ):
        return
    if tuple(inspect.signature(current).parameters) != _TASK_LOAD_PARAMETERS:
        raise RuntimeError("Harbor task loader signature changed")

    @wraps(current)
    async def load_task_from_resolved_cache(config: Any) -> tuple[Any, Any]:
        task_id = config.task.get_task_id()
        if isinstance(task_id, PackageTaskId) and (
            isinstance(task_id.ref, str) and task_id.ref.startswith("sha256:")
        ):
            content_hash = task_id.ref.removeprefix("sha256:")
            path = task_id.get_local_path()
            if (
                len(content_hash) != 64
                or any(
                    character not in "0123456789abcdef" for character in content_hash
                )
                or path.is_symlink()
                or not path.is_dir()
            ):
                raise RuntimeError("resolved package task cache is invalid")
            return (
                Task(
                    path,
                    extra_instruction_paths=config.extra_instruction_paths,
                    disable_verification=config.verifier.disable,
                ),
                TaskDownloadResult(
                    path=path,
                    download_time_sec=0.0,
                    cached=True,
                    content_hash=content_hash,
                ),
            )
        return await current(config)

    setattr(
        load_task_from_resolved_cache,
        "__nano_resolved_task_cache_seam__",
        _RESOLVED_TASK_CACHE_SEAM_VERSION,
    )
    Trial._load_task = staticmethod(load_task_from_resolved_cache)  # noqa: SLF001


def bind_run_specs(job: Any, inputs: RuntimeInputs) -> list[dict[str, Any]]:
    """Prebind one immutable RunSpec per trial before ``Job.run``.

    Access to ``Job._trial_configs`` is intentionally isolated in this module.
    """

    if importlib.metadata.version("harbor") != HARBOR_VERSION:
        raise RuntimeError("unsupported Harbor version")
    if job.is_resuming:
        raise RuntimeError("nano runs never resume or top up")
    trial_configs = job._trial_configs  # noqa: SLF001 - pinned compatibility seam
    if not isinstance(trial_configs, list) or not trial_configs:
        raise RuntimeError("Harbor trial config shape changed")

    from harbor.models.task.task import Task
    from harbor.models.task.verifier_mode import (
        task_has_any_separate_verifier,
        task_has_any_shared_verifier,
    )

    tasks: list[Any] = []
    for trial_config in trial_configs:
        task = Task(
            trial_config.task.get_local_path(),
            extra_instruction_paths=trial_config.extra_instruction_paths,
        )
        if task_has_any_separate_verifier(
            task.config
        ) or not task_has_any_shared_verifier(task.config):
            raise RuntimeError(
                "nano background lifecycle requires shared verifier mode"
            )
        if task.has_steps:
            raise RuntimeError("nano TB2.1 binding requires a single-step task")
        tasks.append(task)

    install_harbor_deadline_seam()
    specs: list[dict[str, Any]] = []
    for trial_config, task in zip(trial_configs, tasks, strict=True):
        timeout = task.config.agent.timeout_sec
        if (
            timeout is None
            or timeout <= 0
            or not float(timeout).is_integer()
            or timeout > 2**63 - 1
        ):
            raise RuntimeError("task native agent timeout is not a positive integer")
        task_digest = task.checksum
        if len(task_digest) != 64:
            raise RuntimeError("Harbor task digest is invalid")
        artifact_dir = (
            Path(trial_config.trials_dir)
            / trial_config.trial_name
            / ".nano-control-v2"
            / "runtime"
        ).resolve()
        spec = {
            "schema_version": "nano-run-spec-alpha-1",
            "run_id": f"{job.id}:{trial_config.trial_name}",
            "trial_id": trial_config.trial_name,
            "attempt_id": "attempt-0",
            "task": {
                "id": task.name,
                "digest": task_digest,
                "instruction": task.instruction,
            },
            "contract": {
                "id": inputs.contract_id,
                "contract_set_sha256": inputs.contract_set_sha256,
                "profile_id": inputs.profile_id,
            },
            "provider": {
                "kind": inputs.provider_launch.kind.value,
                "model": inputs.provider_model,
                "max_turns": inputs.max_turns,
                "retry_max": 0,
            },
            "workspace_dir": "/workspace",
            "artifact_dir": str(artifact_dir),
            "agent_timeout_sec": int(timeout),
        }
        if inputs.active_tools is not None:
            spec["active_tools"] = list(inputs.active_tools)
        kwargs = {
            "binary_path": str(inputs.binary_path),
            "contract_dir": str(inputs.contract_dir),
            "provider_launch": inputs.provider_launch.to_config(),
            "run_spec": spec,
            "deadline_mode": DEADLINE_MODE_HARBOR_ROOT,
        }
        if inputs.reasoning_effort is not None:
            kwargs["reasoning_effort"] = inputs.reasoning_effort
        trial_config.agent = trial_config.agent.model_copy(
            update={"kwargs": kwargs},
            deep=True,
        )
        specs.append(spec)

    manifest = {
        "schema_version": _DISPATCH_SCHEMA,
        "harbor_version": HARBOR_VERSION,
        "job_id": str(job.id),
        "retry_max": 0,
        "n_attempts": 1,
        "run_specs": specs,
    }
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    envelope = {
        "manifest": manifest,
        "manifest_sha256": digest,
    }
    content = (
        json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    _write_new(Path(job.job_dir) / "nano-dispatch.json", content)
    return specs
