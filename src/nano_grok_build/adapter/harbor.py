"""Pinned Harbor v0.20.0 adapter for the host nano runtime."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

from harbor.agents.base import BaseAgent
from harbor.environments.base import BaseEnvironment
from harbor.models.agent.context import AgentContext

from nano_grok_build import __version__
from nano_grok_build.adapter.artifactizer import (
    BACKGROUND_FAILURE_MANIFEST_SCHEMA,
    BACKGROUND_MANIFEST_SCHEMA,
    ProviderCostProjection,
    VerifierOpportunityDecisionV1,
    canonical_json,
    publish_artifacts,
    rust_run_spec_sha256,
    validate_runtime_artifacts,
    validate_verifier_terminal_runtime,
)
from nano_grok_build.adapter.artifactizer import (
    _read_regular as _read_artifact_regular,
)
from nano_grok_build.adapter.control_plane import ControlPlane, control_root_for
from nano_grok_build.adapter.deadline import (
    DeadlineContractError,
    RunDeadlineReceiptV1,
    RunDeadlineV1,
    host_monotonic_ns,
)
from nano_grok_build.adapter.stdio_bridge import (
    BridgeError,
    BridgeOutcome,
    _complete_shielded,
    run_stdio_bridge,
)
from nano_grok_build.adapter.terminal_actor import (
    ProcessLeaseV1,
    RemoteTerminalActor,
    WorkspaceReadinessV1,
)
from nano_grok_build.adapter.workspace_snapshot import (
    POST_AGENT_SNAPSHOT_CLEANUP_RESERVE_SEC,
    BeforeSnapshot,
    SnapshotPolicy,
    SnapshotReceipt,
    SnapshotTarget,
    capture_after,
    capture_before,
    load_workspace_receipt,
)
from nano_grok_build.harbor.deadline import (
    DEADLINE_MODE_HARBOR_ROOT,
    require_harbor_agent_phase,
)
from nano_grok_build.harbor.git_history_capability import (
    validate_git_history_capability,
)
from nano_grok_build.harbor.git_history_isolation import (
    isolate_preexisting_git_history,
)
from nano_grok_build.harbor.git_history_lifecycle import (
    EXPOSURE_RECEIPT,
    EXPOSURE_SCHEMA,
    LIFECYCLE_POLICY,
    REHYDRATION_RECEIPT,
    REHYDRATION_SCHEMA,
    _background_liveness_counts,
)
from nano_grok_build.harbor.git_history_rehydration import (
    GitHistoryEscrow,
    bind_git_history_escrow_to_isolated_state,
    create_git_history_escrow,
    rehydrate_git_history_for_verifier,
)
from nano_grok_build.harbor.provider import (
    HostProviderKind,
    HostProviderLaunch,
    runtime_command,
)
from nano_grok_build.harbor.runtime_entry import (
    RuntimeEntryError,
    write_not_started,
    write_started,
)
from nano_grok_build.harbor.trial_lifecycle import (
    AdmissionState,
    LifecycleReceiptValidation,
    TrialLifecycleCoordinator,
    TrialPhase,
    VerifierSafetyProof,
    VerifierStatus,
    provider_terminal_ledger,
)

_RUNTIME_BRIDGE_GRACE_SEC = 1.0
_HANDOFF_TIMEOUT_SEC = 150.0
_DEADLINE_MODE_LEGACY = "legacy-adapter-v1"
_BACKGROUND_LIVENESS_SCHEMA = "nano-background-liveness-v1"
_BACKGROUND_LIVENESS_MAX_BYTES = 64 * 1024
_STABLE_FAILURE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_CLEAR_GIT_ENVIRONMENT = (
    "for nano_git_env_name in $(LC_ALL=C env | "
    "sed -n 's/^\\(GIT_[A-Za-z0-9_]*\\)=.*/\\1/p'); do "
    'unset "$nano_git_env_name"; done\n'
)


@dataclass(frozen=True)
class _BackgroundLifecycleState:
    manifest_sha256: str
    liveness_sha256: str | None
    registered_count: int
    live_count: int


class _HarborEnvironmentProxy:
    def __init__(self, environment: BaseEnvironment) -> None:
        self._environment = environment

    async def exec(self, *args: Any, **kwargs: Any) -> Any:
        if args:
            command, *rest = args
            if not isinstance(command, str):
                raise TypeError("Harbor exec command must be text")
            args = (_CLEAR_GIT_ENVIRONMENT + command, *rest)
        else:
            command = kwargs.get("command")
            if not isinstance(command, str):
                raise TypeError("Harbor exec command must be text")
            kwargs["command"] = _CLEAR_GIT_ENVIRONMENT + command
        result = await self._environment.exec(*args, **kwargs)
        result.stdout = "" if result.stdout is None else result.stdout
        result.stderr = "" if result.stderr is None else result.stderr
        return result

    async def upload_file(self, *args: Any, **kwargs: Any) -> None:
        await self._environment.upload_file(*args, **kwargs)

    async def download_file(self, *args: Any, **kwargs: Any) -> None:
        await self._environment.download_file(*args, **kwargs)


class NanoGrokBuildAgent(BaseAgent):
    """Keep the provider/runtime on the host and tools in Harbor's sandbox."""

    SUPPORTS_ATIF = True
    SUPPORTS_RESUME = False
    SUPPORTS_WINDOWS = False
    SUPPORTS_NANO_RUN_DEADLINE_V1 = True
    SUPPORTS_BACKGROUND_VERIFIER_HANDOFF_V1 = True
    SUPPORTS_TRIAL_LIFECYCLE_V1 = True

    def __init__(
        self,
        logs_dir: Path,
        model_name: str | None = None,
        logger: logging.Logger | None = None,
        *,
        binary_path: str,
        contract_dir: str,
        provider_launch: dict[str, Any],
        run_spec: dict[str, Any],
        deadline_mode: str = _DEADLINE_MODE_LEGACY,
        **kwargs: Any,
    ):
        super().__init__(
            logs_dir=logs_dir,
            model_name=model_name,
            logger=logger,
            **kwargs,
        )
        self._binary_path = self._regular_absolute(binary_path, executable=True)
        self._contract_dir = self._directory_absolute(contract_dir)
        self._provider_launch = HostProviderLaunch.from_config(provider_launch)
        if self._provider_launch.kind is HostProviderKind.SCRIPTED:
            assert self._provider_launch.script_path is not None
            script_path = self._regular_absolute(str(self._provider_launch.script_path))
            self._provider_launch = HostProviderLaunch.scripted(script_path.resolve())
        self._run_spec = copy.deepcopy(run_spec)
        task = self._run_spec.get("task")
        if not isinstance(task, dict):
            raise ValueError("run_spec task is invalid")
        try:
            validate_git_history_capability(
                task.get("git_history_capability"),
                task.get("instruction"),
                task.get("digest"),
            )
        except ValueError as error:
            raise ValueError("run_spec git history capability is invalid") from error
        if deadline_mode not in {
            _DEADLINE_MODE_LEGACY,
            DEADLINE_MODE_HARBOR_ROOT,
        }:
            raise ValueError("deadline mode is invalid")
        self._deadline_mode = deadline_mode
        self._instruction: str | None = None
        self._actor: RemoteTerminalActor | None = None
        self._before_snapshot: BeforeSnapshot | None = None
        self._post_agent_snapshot_task: (
            asyncio.Task[tuple[object | None, BaseException | None]] | None
        ) = None
        self._post_agent_snapshot_outcome: (
            tuple[object | None, BaseException | None] | None
        ) = None
        self._post_snapshot_liveness_task: (
            asyncio.Task[tuple[object | None, BaseException | None]] | None
        ) = None
        self._post_snapshot_liveness_outcome: (
            tuple[object | None, BaseException | None] | None
        ) = None
        self._post_snapshot_liveness_aborted = False
        self._post_verifier_cleanup_task: (
            asyncio.Task[tuple[bool, BaseException | None]] | None
        ) = None
        self._post_verifier_cleanup_outcome: (
            tuple[bool, BaseException | None] | None
        ) = None
        self._background_manifest_handoff_v1: (
            tuple[bytes, str, tuple[tuple[object, ...], ...]] | None
        ) = None
        self._process_lease_v1: ProcessLeaseV1 | None = None
        self._git_history_escrow: GitHistoryEscrow | None = None
        self._git_history_escrow_temp: tempfile.TemporaryDirectory[str] | None = None
        self._git_history_baseline_receipt: dict[str, object] | None = None
        self._git_history_rehydration_outcome: (
            tuple[str | None, BaseException | None] | None
        ) = None
        self._git_history_exposure_monotonic_ns: int | None = None
        self._post_agent_closed_monotonic_ns: int | None = None
        self._trial_lifecycle: TrialLifecycleCoordinator | None = None
        self._lifecycle_receipt_validation: LifecycleReceiptValidation | None = None
        self._post_run_context: AgentContext | None = None
        self._bridge_closed = False
        self._child_process_closed = False
        self._runtime_identity_bound = True
        self._post_verifier_publication_error: BaseException | None = None
        self._control_root = control_root_for(self.logs_dir.resolve())
        self._control_plane: ControlPlane | None = None
        expected_artifact_dir = (self._control_root / "runtime").resolve()
        if (
            Path(self._run_spec.get("artifact_dir", "")).resolve()
            != expected_artifact_dir
        ):
            raise ValueError(
                "run_spec artifact_dir is not this trial's runtime directory"
            )
        if self._run_spec.get("workspace_dir") != "/workspace":
            raise ValueError("run_spec workspace_dir must be /workspace")

    @staticmethod
    def _regular_absolute(value: str, *, executable: bool = False) -> Path:
        path = Path(value)
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            raise ValueError("adapter input must be an absolute regular file")
        if executable and not path.stat().st_mode & 0o111:
            raise ValueError("runtime binary is not executable")
        return path

    @staticmethod
    def _directory_absolute(value: str) -> Path:
        path = Path(value)
        if not path.is_absolute() or path.is_symlink() or not path.is_dir():
            raise ValueError("contract directory must be an absolute directory")
        return path

    @staticmethod
    def name() -> str:
        return "nano-grok-build"

    def version(self) -> str:
        return __version__

    @staticmethod
    def _write_immutable(path: Path, content: bytes) -> None:
        temporary = path.with_name(f".{path.name}.tmp")
        linked = False
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary, path)
            linked = True
            temporary.unlink()
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except BaseException:
            temporary.unlink(missing_ok=True)
            if linked:
                path.unlink(missing_ok=True)
            raise

    async def _cleanup_after_handoff_failure(self) -> None:
        assert self._actor is not None
        cleanup_task = asyncio.create_task(self._actor.cleanup_active())
        cancellation: asyncio.CancelledError | None = None
        while not cleanup_task.done():
            try:
                await asyncio.shield(cleanup_task)
            except asyncio.CancelledError as error:
                cancellation = error
        try:
            clean = cleanup_task.result()
        except BaseException as error:
            raise BridgeError("external_bridge_cleanup_unverified") from error
        if not clean:
            raise BridgeError("external_bridge_cleanup_unverified")
        if cancellation is not None:
            raise cancellation

    async def setup(self, environment: BaseEnvironment) -> None:
        if self.session_id is None or self.context_id is None:
            raise RuntimeError("Harbor identity was not assigned before setup")
        self._control_plane = ControlPlane.create(
            self.logs_dir,
            run_spec_sha256=rust_run_spec_sha256(self._run_spec),
        )
        self._actor = RemoteTerminalActor(_HarborEnvironmentProxy(environment))
        await self._actor.setup()
        run_spec_sha256 = rust_run_spec_sha256(self._run_spec)
        self._git_history_escrow_temp = tempfile.TemporaryDirectory(
            prefix="nano-git-history-escrow."
        )
        try:
            self._git_history_escrow = await create_git_history_escrow(
                actor=self._actor,
                local_dir=Path(self._git_history_escrow_temp.name),
                capability=self._run_spec["task"]["git_history_capability"],
                run_spec_sha256=run_spec_sha256,
            )
            self._git_history_baseline_receipt = await isolate_preexisting_git_history(
                actor=self._actor,
                artifact_dir=self._control_plane.root,
                capability=self._run_spec["task"]["git_history_capability"],
                run_spec_sha256=run_spec_sha256,
            )
            self._git_history_escrow = await bind_git_history_escrow_to_isolated_state(
                actor=self._actor,
                escrow=self._git_history_escrow,
                baseline_receipt=self._git_history_baseline_receipt,
            )
            self._write_git_history_exposure_receipt(run_spec_sha256)
            _baseline_raw, baseline_sha256 = self._artifact_sha256(
                self._control_plane.root / "git-history-baseline.json"
            )
            _exposure_raw, exposure_sha256 = self._artifact_sha256(
                self._control_plane.root / EXPOSURE_RECEIPT
            )
            self._trial_lifecycle = TrialLifecycleCoordinator(
                root=self._control_plane.root,
                run_id=str(self._run_spec["run_id"]),
                trial_id=str(self._run_spec["trial_id"]),
                attempt_id=str(self._run_spec["attempt_id"]),
                run_spec_sha256=run_spec_sha256,
            )
            self._trial_lifecycle.bind_setup(
                exposure_receipt_sha256=exposure_sha256,
                baseline_receipt_sha256=baseline_sha256,
                background_registry_sha256=hashlib.sha256(
                    canonical_json(
                        {
                            "schema_version": "nano-background-registry-v1",
                            "tasks": [],
                        }
                    )
                ).hexdigest(),
            )
        except BaseException:
            self._cleanup_git_history_escrow()
            raise
        try:
            self._before_snapshot = await capture_before(
                SnapshotTarget(
                    actor=self._actor,
                    artifact_dir=self._control_plane.root,
                    publication_dir=self.logs_dir,
                ),
                SnapshotPolicy(),
            )
        except BaseException:
            self._cleanup_git_history_escrow()
            raise

    def _cleanup_git_history_escrow(self) -> None:
        temporary = getattr(self, "_git_history_escrow_temp", None)
        self._git_history_escrow = None
        self._git_history_escrow_temp = None
        if temporary is not None:
            temporary.cleanup()

    @staticmethod
    def _artifact_sha256(path: Path, limit: int = 1024 * 1024) -> tuple[bytes, str]:
        raw = _read_artifact_regular(path, limit, "git_history_lifecycle_invalid")
        return raw, hashlib.sha256(raw).hexdigest()

    def _write_git_history_exposure_receipt(self, run_spec_sha256: str) -> None:
        """Persist host-derived proof before Harbor can dispatch the agent."""

        actor = self._actor
        plane = self._control_plane
        baseline = self._git_history_baseline_receipt
        capability = self._run_spec["task"]["git_history_capability"]
        if (
            actor is None
            or not isinstance(plane, ControlPlane)
            or not isinstance(baseline, dict)
            or not isinstance(capability, dict)
        ):
            raise BridgeError("git_history_lifecycle_invalid")
        _baseline_raw, baseline_sha256 = self._artifact_sha256(
            plane.root / "git-history-baseline.json"
        )
        escrow = self._git_history_escrow
        control = plane.root.resolve(strict=True)
        public = plane.public_root.resolve(strict=True)
        if (
            control == public
            or control.is_relative_to(public)
            or public.is_relative_to(control)
            or (baseline.get("status") == "isolated") != (escrow is not None)
        ):
            raise BridgeError("git_history_lifecycle_invalid")
        if escrow is None:
            archive_state = "absent"
            archive_sha256 = None
            archive_size = 0
            source_commit_oid = baseline.get("source_commit_oid")
            source_tree_oid = baseline.get("source_tree_oid")
            guard_sha256 = None
            storage_kind = "none"
            archive_path_sha256 = None
        else:
            archive = escrow.local_archive.resolve(strict=True)
            metadata = archive.lstat()
            if (
                archive.is_symlink()
                or not archive.is_file()
                or stat.S_IMODE(metadata.st_mode) & 0o077
                or archive.is_relative_to(control)
                or archive.is_relative_to(public)
                or escrow.isolated_guard_sha256 is None
            ):
                raise BridgeError("git_history_lifecycle_invalid")
            archive_state = "controller_private"
            archive_sha256 = escrow.archive_sha256
            archive_size = escrow.archive_size
            source_commit_oid = escrow.source_commit_oid
            source_tree_oid = escrow.source_tree_oid
            guard_sha256 = escrow.isolated_guard_sha256
            storage_kind = "private_regular_file"
            archive_path_sha256 = hashlib.sha256(str(archive).encode()).hexdigest()
        minted_ns = host_monotonic_ns()
        payload = canonical_json(
            {
                "schema_version": EXPOSURE_SCHEMA,
                "policy_version": LIFECYCLE_POLICY,
                "run_spec_sha256": run_spec_sha256,
                "capability_instruction_sha256": capability[
                    "canonical_instruction_sha256"
                ],
                "trusted_manifest_sha256": capability["trusted_manifest_sha256"],
                "baseline_receipt_sha256": baseline_sha256,
                "baseline_status": baseline["status"],
                "archive_state": archive_state,
                "archive_sha256": archive_sha256,
                "archive_size": archive_size,
                "source_commit_oid": source_commit_oid,
                "source_tree_oid": source_tree_oid,
                "isolated_guard_sha256": guard_sha256,
                "remote_archive_deleted": True,
                "controller_storage_kind": storage_kind,
                "controller_archive_path_sha256": archive_path_sha256,
                "controller_archive_outside_control_plane": True,
                "controller_archive_outside_workspace": True,
                "agent_remote_archive_absent": True,
                "control_plane_not_agent_mounted": True,
                "pre_agent_monotonic_ns": minted_ns,
                "agent_dispatch_started": False,
            }
        )
        self._write_immutable(plane.root / EXPOSURE_RECEIPT, payload)
        self._git_history_exposure_monotonic_ns = minted_ns

    def _write_git_history_rehydration_receipt(
        self,
        *,
        restore_result: str,
        started_monotonic_ns: int,
        finished_monotonic_ns: int,
        background_state: _BackgroundLifecycleState,
    ) -> None:
        """Persist the closed-agent -> verifier ordering proof."""

        root = self._artifact_source_dir()
        capability = self._run_spec["task"]["git_history_capability"]
        baseline = self._git_history_baseline_receipt
        lease = self._process_lease_v1
        post_agent_ns = self._post_agent_closed_monotonic_ns
        if (
            not isinstance(capability, dict)
            or not isinstance(baseline, dict)
            or type(lease) is not ProcessLeaseV1
            or not isinstance(post_agent_ns, int)
            or not (
                isinstance(self._git_history_exposure_monotonic_ns, int)
                and self._git_history_exposure_monotonic_ns
                < post_agent_ns
                <= started_monotonic_ns
                <= finished_monotonic_ns
            )
        ):
            raise BridgeError("git_history_lifecycle_invalid")
        baseline_raw, baseline_sha = self._artifact_sha256(
            root / "git-history-baseline.json"
        )
        exposure_raw, exposure_sha = self._artifact_sha256(root / EXPOSURE_RECEIPT)
        run_raw, run_sha = self._artifact_sha256(
            root / "runtime" / "run.json", 16 * 1024 * 1024
        )
        events_raw, events_sha = self._artifact_sha256(
            root / "runtime" / "events.jsonl", 64 * 1024 * 1024
        )
        background_raw, background_sha = self._artifact_sha256(
            root / "runtime-background-manifest.json"
        )
        workspace_raw, workspace_sha = self._artifact_sha256(
            root / "workspace-receipt.json"
        )
        try:
            run = json.loads(run_raw)
            background = json.loads(background_raw)
            exposure = json.loads(exposure_raw)
            events = [json.loads(line) for line in events_raw.splitlines()]
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise BridgeError("git_history_lifecycle_invalid") from error
        tasks = background.get("tasks") if isinstance(background, dict) else None
        if (
            run.get("run_spec_sha256") != rust_run_spec_sha256(self._run_spec)
            or run.get("events_sha256") != events_sha
            or not isinstance(tasks, list)
            or len(tasks) != lease.process_count
            or background_sha != background_state.manifest_sha256
            or len(tasks) != background_state.registered_count
            or background_state.live_count > background_state.registered_count
            or not isinstance(exposure, dict)
            or any(not isinstance(event, Mapping) for event in events)
            or hashlib.sha256(baseline_raw).hexdigest() != baseline_sha
            or not workspace_raw
        ):
            raise BridgeError("git_history_lifecycle_invalid")
        provider_ledger_sha = hashlib.sha256(
            canonical_json(self._provider_terminal_ledger(events))
        ).hexdigest()
        lifecycle = self._trial_lifecycle
        if type(lifecycle) is not TrialLifecycleCoordinator:
            raise BridgeError("trial_lifecycle_unavailable")
        expected_bindings = lifecycle.receipt_binding_expectations(
            background_manifest_sha256=background_state.manifest_sha256,
        )
        observed_bindings = {
            "baseline_receipt": baseline_sha,
            "exposure_receipt": exposure_sha,
            "run_record": run_sha,
            "events": events_sha,
            "workspace_receipt": workspace_sha,
            "background_manifest": background_sha,
            "provider_ledger": provider_ledger_sha,
        }
        validation = LifecycleReceiptValidation.compare(
            expected=expected_bindings,
            observed=observed_bindings,
        )
        if not validation.valid:
            raise BridgeError("trial_lifecycle_receipt_identity_mismatch")
        payload = canonical_json(
            {
                "schema_version": REHYDRATION_SCHEMA,
                "policy_version": LIFECYCLE_POLICY,
                "run_spec_sha256": rust_run_spec_sha256(self._run_spec),
                "capability_instruction_sha256": capability[
                    "canonical_instruction_sha256"
                ],
                "trusted_manifest_sha256": capability["trusted_manifest_sha256"],
                "baseline_receipt_sha256": baseline_sha,
                "exposure_receipt_sha256": exposure_sha,
                "run_record_sha256": run_sha,
                "events_sha256": events_sha,
                "terminal_status": run["terminal_status"],
                "agent_closed": True,
                "provider_closed": True,
                "provider_in_flight": (
                    run.get("provider_call_coverage", {}).get("in_flight")
                    if isinstance(run.get("provider_call_coverage"), dict)
                    else None
                ),
                "provider_ledger_sha256": provider_ledger_sha,
                "background_manifest_sha256": background_sha,
                "background_liveness_sha256": background_state.liveness_sha256,
                "background_registered_count": background_state.registered_count,
                "background_count": background_state.live_count,
                "workspace_receipt_sha256": workspace_sha,
                "isolated_guard_sha256": exposure["isolated_guard_sha256"],
                "restore_result": restore_result,
                "verifier_started": False,
                "post_agent_monotonic_ns": post_agent_ns,
                "rehydration_started_monotonic_ns": started_monotonic_ns,
                "rehydration_finished_monotonic_ns": finished_monotonic_ns,
            }
        )
        self._write_immutable(root / REHYDRATION_RECEIPT, payload)

    def _validate_lifecycle_receipt_bindings(
        self,
        *,
        background_manifest_sha256: str | None,
    ) -> LifecycleReceiptValidation:
        lifecycle = self._trial_lifecycle
        if type(lifecycle) is not TrialLifecycleCoordinator:
            raise BridgeError("trial_lifecycle_unavailable")
        expected = lifecycle.receipt_binding_expectations(
            background_manifest_sha256=background_manifest_sha256,
        )
        try:
            raw, _receipt_sha = self._artifact_sha256(
                self._artifact_source_dir() / REHYDRATION_RECEIPT
            )
            receipt = json.loads(raw)
            if (
                not isinstance(receipt, dict)
                or raw != canonical_json(receipt)
                or receipt.get("schema_version") != REHYDRATION_SCHEMA
                or receipt.get("policy_version") != LIFECYCLE_POLICY
                or receipt.get("run_spec_sha256")
                != rust_run_spec_sha256(self._run_spec)
            ):
                raise BridgeError("lifecycle_receipt_unreadable")
            observed = {
                "baseline_receipt": receipt.get("baseline_receipt_sha256"),
                "exposure_receipt": receipt.get("exposure_receipt_sha256"),
                "run_record": receipt.get("run_record_sha256"),
                "events": receipt.get("events_sha256"),
                "workspace_receipt": receipt.get("workspace_receipt_sha256"),
                "background_manifest": receipt.get("background_manifest_sha256"),
                "provider_ledger": receipt.get("provider_ledger_sha256"),
            }
        except Exception:
            validation = LifecycleReceiptValidation.unreadable(
                expected=expected,
                failure_code="lifecycle_receipt_unreadable",
            )
        else:
            validation = LifecycleReceiptValidation.compare(
                expected=expected,
                observed=observed,
            )
        self._lifecycle_receipt_validation = validation
        return validation

    def _git_history_background_lifecycle_state(
        self,
        root: Path,
    ) -> _BackgroundLifecycleState:
        lease = self._process_lease_v1
        binding = self._background_manifest_handoff_v1
        if type(lease) is not ProcessLeaseV1 or binding is None:
            raise BridgeError("git_history_lifecycle_invalid")
        manifest_raw, manifest_sha = self._artifact_sha256(
            root / "runtime-background-manifest.json"
        )
        workspace_raw, workspace_sha = self._artifact_sha256(
            root / "workspace-receipt.json"
        )
        try:
            manifest = json.loads(manifest_raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise BridgeError("git_history_lifecycle_invalid") from error
        persisted_manifest, persisted_sha, persisted_rows = binding
        if (
            manifest_raw != persisted_manifest
            or manifest_sha != persisted_sha
            or not workspace_raw
        ):
            raise BridgeError("git_history_lifecycle_invalid")
        try:
            registered, live, liveness_sha = _background_liveness_counts(
                root,
                background=manifest,
                background_sha256=manifest_sha,
                workspace_sha256=workspace_sha,
                run_spec_sha256=rust_run_spec_sha256(self._run_spec),
            )
        except RuntimeError as error:
            raise BridgeError("git_history_lifecycle_invalid") from error
        if registered != lease.process_count or registered != len(persisted_rows):
            raise BridgeError("git_history_lifecycle_invalid")
        return _BackgroundLifecycleState(
            manifest_sha256=manifest_sha,
            liveness_sha256=liveness_sha,
            registered_count=registered,
            live_count=live,
        )

    async def _rehydrate_git_history_for_verifier(
        self,
        *,
        hard_deadline_monotonic_ns: int,
    ) -> None:
        stored = self._git_history_rehydration_outcome
        if stored is not None:
            _, error = stored
            if error is not None:
                raise error
            return
        escrow = self._git_history_escrow
        lease = self._process_lease_v1
        baseline = self._git_history_baseline_receipt
        if type(lease) is not ProcessLeaseV1 or baseline is None:
            error = BridgeError("git_history_rehydration_invalid")
            self._git_history_rehydration_outcome = (None, error)
            raise error
        remaining_sec = (
            hard_deadline_monotonic_ns - host_monotonic_ns()
        ) / 1_000_000_000
        if remaining_sec <= 0:
            error = BridgeError("git_history_rehydration_invalid")
            self._git_history_rehydration_outcome = (None, error)
            raise error
        started_ns = host_monotonic_ns()
        try:
            root = self._artifact_source_dir()
            background_state = self._git_history_background_lifecycle_state(root)
            if escrow is None:
                status = "not_applicable"
            elif background_state.live_count:
                status = "deferred_background_active"
            else:
                status = await rehydrate_git_history_for_verifier(
                    actor=self._actor,
                    escrow=escrow,
                    baseline_receipt=baseline,
                    background_process_count=background_state.live_count,
                    timeout_sec=remaining_sec,
                )
            finished_ns = host_monotonic_ns()
        except BaseException as cause:
            error = BridgeError("git_history_rehydration_invalid")
            error.__cause__ = cause
            self._git_history_rehydration_outcome = (None, error)
            raise error
        try:
            self._write_git_history_rehydration_receipt(
                restore_result=status,
                started_monotonic_ns=started_ns,
                finished_monotonic_ns=finished_ns,
                background_state=background_state,
            )
        except Exception:
            self.logger.exception("Lifecycle receipt unavailable")
        self._validate_lifecycle_receipt_bindings(
            background_manifest_sha256=background_state.manifest_sha256,
        )
        self._git_history_rehydration_outcome = (status, None)

    def _artifact_source_dir(self) -> Path:
        plane = getattr(self, "_control_plane", None)
        if isinstance(plane, ControlPlane):
            return plane.root
        run_spec = getattr(self, "_run_spec", None)
        if not isinstance(run_spec, dict):
            return self.logs_dir
        artifact_dir = Path(run_spec.get("artifact_dir", ""))
        if artifact_dir.name == "runtime" and artifact_dir.parent.is_absolute():
            return artifact_dir.parent
        return self.logs_dir

    @staticmethod
    def _failure_code(error: BaseException | None) -> str:
        if error is None:
            return "completed"
        if isinstance(error, asyncio.CancelledError):
            return "adapter_cancelled"
        code = getattr(error, "code", None)
        if isinstance(code, str) and _STABLE_FAILURE_CODE.fullmatch(code) is not None:
            return code
        if isinstance(error, BridgeError | DeadlineContractError):
            stable = str(error)
            if _STABLE_FAILURE_CODE.fullmatch(stable) is not None:
                return stable
        if isinstance(error, TimeoutError):
            return "adapter_timed_out"
        return "adapter_runtime_failed"

    def _stderr_receipt(
        self,
        outcome: BridgeOutcome | None,
        error: BaseException | None,
    ) -> bytes:
        stderr = (
            outcome.stderr if outcome is not None else getattr(error, "stderr", None)
        )
        actor_metadata = (
            self._actor.diagnostic_metadata()
            if self._actor is not None and hasattr(self._actor, "diagnostic_metadata")
            else {}
        )
        bridge_receipts = {}
        if isinstance(error, BridgeError):
            if error.failure_receipt is not None:
                bridge_receipts["bridge_failure_receipt"] = error.failure_receipt
            if error.cleanup_receipt is not None:
                bridge_receipts["bridge_cleanup_receipt"] = error.cleanup_receipt
        if isinstance(stderr, bytes):
            return canonical_json(
                {
                    "schema_version": "nano-runtime-stderr-digest-v1",
                    "code": self._failure_code(error),
                    "byte_length": len(stderr),
                    "sha256": hashlib.sha256(stderr).hexdigest(),
                    **bridge_receipts,
                    **actor_metadata,
                }
            )
        return canonical_json(
            {
                "schema_version": "nano-runtime-stderr-receipt-v1",
                "status": "unavailable",
                "code": self._failure_code(error),
                **bridge_receipts,
                **actor_metadata,
            }
        )

    def _emergency_receipt(
        self,
        outcome: BridgeOutcome | None,
        error: BaseException | None,
    ) -> bytes:
        events_path = self._artifact_source_dir() / "runtime" / "events.jsonl"
        events_sha256: str | None = None
        events_byte_length: int | None = None
        try:
            metadata = events_path.lstat()
            if (
                not events_path.is_symlink()
                and events_path.is_file()
                and metadata.st_size <= 64 * 1024 * 1024
            ):
                events = events_path.read_bytes()
                events_sha256 = hashlib.sha256(events).hexdigest()
                events_byte_length = len(events)
        except OSError:
            pass
        return canonical_json(
            {
                "schema_version": "nano-runtime-emergency-v1",
                "run_id": self._run_spec["run_id"],
                "trial_id": self._run_spec["trial_id"],
                "attempt_id": self._run_spec["attempt_id"],
                "run_spec_sha256": rust_run_spec_sha256(self._run_spec),
                "status": "runtime_record_missing",
                "code": (
                    self._failure_code(error)
                    if error is not None
                    else "runtime_record_missing_after_bridge_completion"
                ),
                "bridge_completed": outcome is not None,
                "events_sha256": events_sha256,
                "events_byte_length": events_byte_length,
            }
        )

    async def _finalize_handoff(
        self,
        *,
        outcome: BridgeOutcome | None,
        original_error: BaseException | None,
    ) -> Exception | None:
        """Attempt every handoff receipt; return the first finalization failure."""

        assert self._actor is not None
        errors: list[Exception] = []
        cleanup_attempted = False
        cleanup_verified = False
        manifest_rows: list[dict[str, Any]] | None = None
        manifest_payload: bytes | None = None
        manifest_published = False
        if original_error is not None:
            cleanup_attempted = True
            try:
                if not await self._actor.cleanup_active():
                    errors.append(BridgeError("external_bridge_cleanup_unverified"))
                else:
                    cleanup_verified = True
            except Exception as error:
                errors.append(BridgeError("external_bridge_cleanup_unverified"))
                errors[-1].__cause__ = error

        try:
            self._write_immutable(
                self._artifact_source_dir() / "runtime-stderr.json",
                self._stderr_receipt(outcome, original_error),
            )
        except Exception as error:
            errors.append(error)

        try:
            manifest_rows = await self._actor.background_manifest()
            # Validate and seal the exact owned process set before publishing a
            # normal manifest. An incomplete start acknowledgement (for
            # example a "running" row without process identities) is
            # diagnostic unavailability, never a valid running-task claim.
            self._process_lease_v1 = self._actor.seal_process_lease_v1(manifest_rows)
            manifest_payload = canonical_json(
                {
                    "schema_version": BACKGROUND_MANIFEST_SCHEMA,
                    "run_id": self._run_spec["run_id"],
                    "trial_id": self._run_spec["trial_id"],
                    "attempt_id": self._run_spec["attempt_id"],
                    "run_spec_sha256": rust_run_spec_sha256(self._run_spec),
                    "tasks": manifest_rows,
                }
            )
            self._write_immutable(
                self._artifact_source_dir() / "runtime-background-manifest.json",
                manifest_payload,
            )
            manifest_published = True
            self._background_manifest_handoff_v1 = (
                manifest_payload,
                hashlib.sha256(manifest_payload).hexdigest(),
                tuple(
                    (
                        row["task_id"],
                        row["pgid"],
                        row["monitor_pgid"],
                        row["output_path"],
                        row["state"],
                    )
                    for row in manifest_rows
                ),
            )
        except Exception as error:
            errors.append(error)

        run_record = self._artifact_source_dir() / "runtime" / "run.json"
        run_record_available = run_record.is_file() and not run_record.is_symlink()
        if not run_record_available:
            try:
                self._write_immutable(
                    self._artifact_source_dir() / "runtime-emergency.json",
                    self._emergency_receipt(outcome, original_error),
                )
            except Exception as error:
                errors.append(error)

        if errors and not cleanup_attempted:
            cleanup_attempted = True
            try:
                if not await self._actor.cleanup_active():
                    errors.append(BridgeError("external_bridge_cleanup_unverified"))
                else:
                    cleanup_verified = True
            except Exception as error:
                failure = BridgeError("external_bridge_cleanup_unverified")
                failure.__cause__ = error
                errors.append(failure)
        if not manifest_published:
            failure_source = errors[0] if errors else original_error
            try:
                manifest_payload = canonical_json(
                    {
                        "schema_version": BACKGROUND_FAILURE_MANIFEST_SCHEMA,
                        "run_id": self._run_spec["run_id"],
                        "trial_id": self._run_spec["trial_id"],
                        "attempt_id": self._run_spec["attempt_id"],
                        "run_spec_sha256": rust_run_spec_sha256(self._run_spec),
                        "status": "unavailable",
                        "code": self._failure_code(failure_source),
                        "cleanup_attempted": cleanup_attempted,
                        "cleanup_verified": cleanup_verified,
                    }
                )
                self._write_immutable(
                    self._artifact_source_dir() / "runtime-background-manifest.json",
                    manifest_payload,
                )
                manifest_published = True
            except Exception as error:
                errors.append(error)
        if cleanup_verified and self._process_lease_v1 is None:
            try:
                self._process_lease_v1 = self._actor.seal_process_lease_v1([])
            except Exception as error:
                errors.append(error)
        return errors[0] if errors else None

    async def _post_agent_snapshot_capture(
        self,
        *,
        hard_cutoff_ns: int,
    ) -> tuple[object | None, BaseException | None]:
        try:
            if self._actor is None or self._before_snapshot is None:
                raise BridgeError("post_agent_workspace_snapshot_unavailable")
            receipt = await capture_after(
                SnapshotTarget(
                    actor=self._actor,
                    artifact_dir=self._artifact_source_dir(),
                    publication_dir=self.logs_dir,
                ),
                self._before_snapshot,
                hard_deadline_monotonic_ns=hard_cutoff_ns,
            )
            return receipt, None
        except BaseException as error:
            return None, error

    async def _post_agent_cleanup_until(self, hard_cutoff_ns: int) -> bool:
        assert self._actor is not None
        cleanup_until = getattr(self._actor, "cleanup_active_until", None)
        if callable(cleanup_until):
            return bool(await cleanup_until(hard_cutoff_ns))
        return bool(await self._actor.cleanup_active())

    def _load_bound_workspace_receipt(self, receipt: object) -> SnapshotReceipt:
        if type(receipt) is not SnapshotReceipt:
            raise BridgeError("post_agent_workspace_receipt_binding_invalid")
        try:
            persisted = load_workspace_receipt(
                self._artifact_source_dir() / "workspace-receipt.json"
            )
        except BaseException as error:
            raise BridgeError("post_agent_workspace_receipt_binding_invalid") from error
        if persisted != receipt:
            raise BridgeError("post_agent_workspace_receipt_binding_invalid")
        return persisted

    def _write_background_liveness_receipt(
        self,
        *,
        workspace_receipt: SnapshotReceipt,
        rows: list[dict[str, object]],
    ) -> None:
        binding = getattr(self, "_background_manifest_handoff_v1", None)
        if binding is None:
            raise BridgeError("post_snapshot_background_liveness_invalid")
        manifest_payload, manifest_sha256, manifest_rows = binding
        manifest_path = self._artifact_source_dir() / "runtime-background-manifest.json"
        try:
            persisted_manifest = _read_artifact_regular(
                manifest_path,
                _BACKGROUND_LIVENESS_MAX_BYTES,
                "post_snapshot_background_liveness_invalid",
            )
        except Exception as error:
            raise BridgeError("post_snapshot_background_liveness_invalid") from error
        if persisted_manifest != manifest_payload or len(rows) != len(manifest_rows):
            raise BridgeError("post_snapshot_background_liveness_invalid")
        expected_keys = {
            "task_id",
            "leader_pid",
            "leader_starttime",
            "leader_pgid",
            "monitor_pid",
            "monitor_starttime",
            "monitor_pgid",
            "owner_token_sha256",
            "process_alive",
        }
        task_ids: list[str] = []
        for row, manifest_row in zip(rows, manifest_rows, strict=True):
            if (
                type(row) is not dict
                or set(row) != expected_keys
                or type(row["task_id"]) is not str
                or not row["task_id"]
                or any(
                    type(row[key]) is not int or row[key] <= 0
                    for key in (
                        "leader_pid",
                        "leader_starttime",
                        "leader_pgid",
                        "monitor_pid",
                        "monitor_starttime",
                        "monitor_pgid",
                    )
                )
                or row["leader_pid"] != row["leader_pgid"]
                or row["monitor_pid"] != row["monitor_pgid"]
                or row["task_id"] != manifest_row[0]
                or row["leader_pid"] != manifest_row[1]
                or row["monitor_pid"] != manifest_row[2]
                or type(row["owner_token_sha256"]) is not str
                or len(row["owner_token_sha256"]) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in row["owner_token_sha256"]
                )
                or type(row["process_alive"]) is not bool
            ):
                raise BridgeError("post_snapshot_background_liveness_invalid")
            task_ids.append(row["task_id"])
        if task_ids != sorted(task_ids) or len(task_ids) != len(set(task_ids)):
            raise BridgeError("post_snapshot_background_liveness_invalid")
        receipt = canonical_json(
            {
                "schema_version": _BACKGROUND_LIVENESS_SCHEMA,
                "run_id": self._run_spec["run_id"],
                "trial_id": self._run_spec["trial_id"],
                "attempt_id": self._run_spec["attempt_id"],
                "run_spec_sha256": rust_run_spec_sha256(self._run_spec),
                "background_manifest_sha256": manifest_sha256,
                "workspace_receipt_sha256": workspace_receipt.canonical_sha256,
                "tasks": rows,
            }
        )
        if len(receipt) > _BACKGROUND_LIVENESS_MAX_BYTES:
            raise BridgeError("post_snapshot_background_liveness_invalid")
        try:
            self._write_immutable(
                self._artifact_source_dir() / "runtime-background-liveness-v1.json",
                receipt,
            )
        except Exception as error:
            raise BridgeError("post_snapshot_background_liveness_invalid") from error

    async def _post_snapshot_liveness_capture(
        self,
        *,
        workspace_receipt: SnapshotReceipt,
        hard_cutoff_ns: int,
    ) -> tuple[object | None, BaseException | None]:
        try:
            if self._actor is None:
                raise BridgeError("post_snapshot_background_liveness_invalid")
            lease = getattr(self, "_process_lease_v1", None)
            if type(lease) is not ProcessLeaseV1:
                raise BridgeError("post_snapshot_background_liveness_invalid")
            rows = await self._actor.observe_process_lease_v1(
                lease,
                hard_deadline_monotonic_ns=hard_cutoff_ns,
            )
            if getattr(self, "_post_snapshot_liveness_aborted", False):
                raise BridgeError("post_snapshot_background_liveness_invalid")
            if type(rows) is not list:
                raise BridgeError("post_snapshot_background_liveness_invalid")
            if not rows:
                return None, None
            self._write_background_liveness_receipt(
                workspace_receipt=workspace_receipt,
                rows=rows,
            )
            return rows, None
        except BaseException as error:
            return None, error

    async def _ensure_post_snapshot_background_liveness(
        self,
        *,
        workspace_receipt: SnapshotReceipt,
        hard_deadline_monotonic_ns: int,
    ) -> None:
        # A failure manifest intentionally carries no live-process handoff.
        # Cleanup evidence, not a fabricated empty/partial liveness receipt,
        # is authoritative for that path.
        if getattr(self, "_background_manifest_handoff_v1", None) is None:
            self._post_snapshot_liveness_outcome = (None, None)
            return
        stored = getattr(self, "_post_snapshot_liveness_outcome", None)
        if stored is not None:
            _, error = stored
            if error is not None:
                raise error
            return
        remaining_sec = max(
            0.0,
            (hard_deadline_monotonic_ns - host_monotonic_ns()) / 1_000_000_000,
        )
        if remaining_sec <= 0:
            raise BridgeError("post_snapshot_background_liveness_invalid")
        task = getattr(self, "_post_snapshot_liveness_task", None)
        if task is None:
            task = asyncio.create_task(
                self._post_snapshot_liveness_capture(
                    workspace_receipt=workspace_receipt,
                    hard_cutoff_ns=hard_deadline_monotonic_ns,
                )
            )
            self._post_snapshot_liveness_task = task
        completed, value, cancellation = await _complete_shielded(
            task,
            timeout_sec=remaining_sec,
        )
        if completed:
            evidence, error = value
        else:
            self._post_snapshot_liveness_aborted = True
            evidence = None
            error = BridgeError("post_snapshot_background_liveness_invalid")
        if error is not None:
            try:
                clean = await self._post_agent_cleanup_until(hard_deadline_monotonic_ns)
            except BaseException as cleanup_error:
                fatal = BridgeError("external_bridge_cleanup_unverified")
                fatal.__cause__ = cleanup_error
                error = fatal
            else:
                if not clean:
                    error = BridgeError("external_bridge_cleanup_unverified")
            self._post_snapshot_liveness_outcome = (evidence, error)
            raise error
        self._post_snapshot_liveness_outcome = (evidence, None)
        if cancellation is not None:
            raise cancellation

    async def post_agent_workspace_snapshot_v1(
        self,
        *,
        hard_deadline_monotonic_ns: int,
    ) -> object:
        """Idempotently capture after state outside Harbor's agent deadline."""

        stored = getattr(self, "_post_agent_snapshot_outcome", None)
        if stored is not None:
            receipt, error = stored
            if error is not None:
                raise error
            assert receipt is not None
            return self._load_bound_workspace_receipt(receipt)

        now_ns = host_monotonic_ns()
        if (
            isinstance(hard_deadline_monotonic_ns, bool)
            or not isinstance(hard_deadline_monotonic_ns, int)
            or hard_deadline_monotonic_ns <= now_ns
        ):
            raise BridgeError("post_agent_workspace_budget_unavailable")
        remaining_sec = (hard_deadline_monotonic_ns - now_ns) / 1_000_000_000
        capture_budget_sec = remaining_sec - POST_AGENT_SNAPSHOT_CLEANUP_RESERVE_SEC
        if capture_budget_sec <= 0:
            raise BridgeError("post_agent_workspace_budget_unavailable")

        task = getattr(self, "_post_agent_snapshot_task", None)
        if task is None:
            task = asyncio.create_task(
                self._post_agent_snapshot_capture(
                    hard_cutoff_ns=hard_deadline_monotonic_ns,
                )
            )
            self._post_agent_snapshot_task = task
        completed, value, cancellation = await _complete_shielded(
            task,
            timeout_sec=remaining_sec,
        )
        if completed:
            receipt, error = value
        else:
            receipt = None
            error = BridgeError("post_agent_workspace_snapshot_deadline_exceeded")
        persisted_receipt: SnapshotReceipt | None = None
        if error is None and receipt is not None:
            try:
                persisted_receipt = self._load_bound_workspace_receipt(receipt)
            except BridgeError:
                error = BridgeError("post_agent_workspace_receipt_binding_invalid")
            else:
                if (
                    persisted_receipt.status != "complete"
                    and persisted_receipt.continuable is not True
                ):
                    error = BridgeError("post_agent_workspace_snapshot_security_fatal")

        if error is not None:
            try:
                clean = await self._post_agent_cleanup_until(hard_deadline_monotonic_ns)
            except BaseException as cleanup_error:
                fatal = BridgeError("external_bridge_cleanup_unverified")
                fatal.__cause__ = cleanup_error
                error = fatal
            else:
                if not clean:
                    error = BridgeError("external_bridge_cleanup_unverified")
            self._post_agent_snapshot_outcome = (receipt, error)
            self._cleanup_git_history_escrow()
            if cancellation is not None:
                error.add_note("post-agent hook observed caller cancellation")
            raise error

        assert receipt is not None
        assert persisted_receipt is not None
        liveness_cancellation: asyncio.CancelledError | None = None
        try:
            await self._ensure_post_snapshot_background_liveness(
                workspace_receipt=persisted_receipt,
                hard_deadline_monotonic_ns=hard_deadline_monotonic_ns,
            )
        except asyncio.CancelledError as error:
            liveness_cancellation = error
        except BaseException as liveness_error:
            self._post_agent_snapshot_outcome = (receipt, liveness_error)
            self._cleanup_git_history_escrow()
            raise
        cancellation = liveness_cancellation or cancellation
        if cancellation is not None:
            try:
                await self.post_verifier_cleanup_v1(
                    hard_deadline_monotonic_ns=hard_deadline_monotonic_ns,
                )
            except BaseException as cleanup_error:
                self._post_agent_snapshot_outcome = (receipt, cleanup_error)
                raise cleanup_error from cancellation
            self._post_agent_snapshot_outcome = (receipt, cancellation)
            raise cancellation
        self._post_agent_closed_monotonic_ns = host_monotonic_ns()
        self._post_agent_snapshot_outcome = (receipt, None)
        return persisted_receipt

    async def prepare_shared_verifier_v1(
        self,
        *,
        hard_deadline_monotonic_ns: int,
    ) -> None:
        """Compatibility alias for verifier safety preparation without publication."""

        await self._rehydrate_git_history_for_verifier(
            hard_deadline_monotonic_ns=hard_deadline_monotonic_ns,
        )

    @staticmethod
    def _provider_terminal_ledger(
        events: list[Mapping[str, Any]],
    ) -> dict[str, int]:
        return provider_terminal_ledger(events)

    def _runtime_terminal_manifest(self) -> None:
        lifecycle = self._trial_lifecycle
        if type(lifecycle) is not TrialLifecycleCoordinator:
            raise BridgeError("trial_lifecycle_unavailable")
        source = self._artifact_source_dir()
        run_path = source / "runtime" / "run.json"
        events_path = source / "runtime" / "events.jsonl"
        events: list[Mapping[str, Any]] = []
        if run_path.exists() and not run_path.is_symlink():
            try:
                validated = validate_runtime_artifacts(
                    runtime_dir=run_path.parent,
                    run_spec=self._run_spec,
                )
            except Exception:
                run_raw, run_sha256 = self._artifact_sha256(run_path, 16 * 1024 * 1024)
                try:
                    record = json.loads(run_raw)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    record = {}
                terminal_status = str(record.get("terminal_status", "runtime_failure"))
                terminal_code = str(
                    record.get("terminal_code", "runtime_artifact_invalid")
                )
                self._runtime_identity_bound = bool(
                    isinstance(record, Mapping)
                    and record.get("run_id") == self._run_spec["run_id"]
                    and record.get("trial_id") == self._run_spec["trial_id"]
                    and record.get("attempt_id") == self._run_spec["attempt_id"]
                    and record.get("run_spec_sha256")
                    == rust_run_spec_sha256(self._run_spec)
                )
                if events_path.exists() and not events_path.is_symlink():
                    events_raw = _read_artifact_regular(
                        events_path,
                        64 * 1024 * 1024,
                        "trial_lifecycle_runtime_invalid",
                    )
                    events_sha256 = hashlib.sha256(events_raw).hexdigest()
                    for line in events_raw.splitlines():
                        try:
                            event = json.loads(line)
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            break
                        if isinstance(event, Mapping):
                            events.append(event)
                else:
                    events_sha256 = hashlib.sha256(b"").hexdigest()
            else:
                record = validated.record
                run_sha256 = hashlib.sha256(validated.record_bytes).hexdigest()
                events_sha256 = hashlib.sha256(validated.event_bytes).hexdigest()
                events = list(validated.events)
                terminal_status = str(record["terminal_status"])
                terminal_code = str(record["terminal_code"])
                self._runtime_identity_bound = True
        else:
            emergency_path = source / "runtime-emergency.json"
            emergency_raw, run_sha256 = self._artifact_sha256(emergency_path)
            try:
                emergency = json.loads(emergency_raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise BridgeError("trial_lifecycle_runtime_invalid") from error
            terminal_status = "runtime_failure"
            terminal_code = str(emergency.get("code", "runtime_record_missing"))
            self._runtime_identity_bound = bool(
                emergency.get("run_id") == self._run_spec["run_id"]
                and emergency.get("trial_id") == self._run_spec["trial_id"]
                and emergency.get("attempt_id") == self._run_spec["attempt_id"]
                and emergency.get("run_spec_sha256")
                == rust_run_spec_sha256(self._run_spec)
            )
            if events_path.exists() and not events_path.is_symlink():
                events_raw = _read_artifact_regular(
                    events_path,
                    64 * 1024 * 1024,
                    "trial_lifecycle_runtime_invalid",
                )
                events_sha256 = hashlib.sha256(events_raw).hexdigest()
                for line in events_raw.splitlines():
                    try:
                        event = json.loads(line)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        break
                    if isinstance(event, Mapping):
                        events.append(event)
            else:
                events_sha256 = hashlib.sha256(b"").hexdigest()
        workspace_path = source / "workspace-receipt.json"
        workspace_sha256 = (
            self._artifact_sha256(workspace_path)[1]
            if workspace_path.exists() and not workspace_path.is_symlink()
            else None
        )
        lifecycle.runtime_terminal(
            terminal_status=terminal_status,
            terminal_code=terminal_code,
            run_record_sha256=run_sha256,
            events_sha256=events_sha256,
            workspace_receipt_sha256=workspace_sha256,
            provider_ledger=self._provider_terminal_ledger(events),
            bridge_closed=self._bridge_closed,
            child_process_closed=self._child_process_closed,
        )

    async def complete_runtime_and_prove_safety_v1(
        self,
        *,
        primary_error: BaseException | None,
        snapshot_error: BaseException | None,
        result_target: object,
        workspace_receipt: object,
        hard_deadline_monotonic_ns: int,
    ) -> VerifierSafetyProof:
        """Terminalize runtime and mint the sole verifier-safety decision."""

        del primary_error, result_target
        lifecycle = self._trial_lifecycle
        if type(lifecycle) is not TrialLifecycleCoordinator:
            raise BridgeError("trial_lifecycle_unavailable")
        self._runtime_terminal_manifest()
        workspace_complete = False
        if snapshot_error is None:
            try:
                persisted = self._load_bound_workspace_receipt(workspace_receipt)
            except Exception:
                persisted = None
            workspace_complete = persisted is not None and (
                persisted.status == "complete" or persisted.continuable is True
            )

        restore_valid = False
        background_liveness_known = False
        background_identity_bound = False
        background_manifest_sha256: str | None = None
        git_mode = "not_applicable"
        if workspace_complete and self._bridge_closed and self._child_process_closed:
            try:
                await self._rehydrate_git_history_for_verifier(
                    hard_deadline_monotonic_ns=hard_deadline_monotonic_ns,
                )
                outcome = self._git_history_rehydration_outcome
                root = self._artifact_source_dir()
                background = self._git_history_background_lifecycle_state(root)
                background_manifest_sha256 = background.manifest_sha256
                if not (
                    type(outcome) is tuple
                    and len(outcome) == 2
                    and isinstance(outcome[0], str)
                    and outcome[1] is None
                ):
                    raise BridgeError("git_history_rehydration_invalid")
                status = outcome[0]
                baseline = self._git_history_baseline_receipt or {}
                if status == "restored":
                    git_mode = "restored"
                elif status == "deferred_background_active":
                    git_mode = "synthetic_preserved"
                elif baseline.get("status") == "preserved":
                    git_mode = "preserved_authorized"
                else:
                    git_mode = "not_applicable"
                restore_valid = True
                background_liveness_known = True
                background_identity_bound = background.registered_count == getattr(
                    self._process_lease_v1, "process_count", -1
                )
            except Exception:
                restore_valid = False
        receipt_validation = getattr(self, "_lifecycle_receipt_validation", None)
        if type(receipt_validation) is not LifecycleReceiptValidation:
            expected = lifecycle.receipt_binding_expectations(
                background_manifest_sha256=background_manifest_sha256,
            )
            receipt_validation = LifecycleReceiptValidation.unreadable(
                expected=expected,
                failure_code="lifecycle_receipt_unreadable",
            )
            self._lifecycle_receipt_validation = receipt_validation
        baseline = self._git_history_baseline_receipt or {}
        escrow_isolated = baseline.get("status") != "isolated" or (
            self._git_history_escrow is not None
        )
        return lifecycle.prove_safety(
            identity_bound=self._runtime_identity_bound,
            receipt_validation=receipt_validation,
            bridge_closed=self._bridge_closed,
            child_process_closed=self._child_process_closed,
            workspace_capture_complete=workspace_complete,
            restore_valid=restore_valid,
            escrow_isolated=escrow_isolated,
            background_liveness_known=background_liveness_known,
            background_identity_bound=background_identity_bound,
            verifier_not_started=True,
            git_mode=git_mode,
        )

    def verifier_safety_proof_v1(self) -> VerifierSafetyProof:
        lifecycle = self._trial_lifecycle
        if type(lifecycle) is not TrialLifecycleCoordinator:
            raise BridgeError("trial_lifecycle_unavailable")
        proof = lifecycle.safety_proof
        if type(proof) is not VerifierSafetyProof:
            raise BridgeError("verifier_safety_proof_invalid")
        return proof

    def _publish_after_verifier(self) -> None:
        context = self._post_run_context
        if context is None or self._instruction is None:
            raise BridgeError("post_verifier_publication_context_unavailable")
        source_dir = self._artifact_source_dir()
        validated_runtime = None
        run_record_path = source_dir / "runtime" / "run.json"
        if run_record_path.exists() or run_record_path.is_symlink():
            validated_runtime = validate_runtime_artifacts(
                runtime_dir=run_record_path.parent,
                run_spec=self._run_spec,
            )
        publication = publish_artifacts(
            logs_dir=source_dir,
            publication_dir=(self.logs_dir if source_dir != self.logs_dir else None),
            run_spec=self._run_spec,
            instruction=self._instruction,
            agent_name=self.name(),
            agent_version=self.version(),
            model_name=self._run_spec["provider"]["model"],
            require_harbor_validator=True,
            require_background_manifest=True,
            require_git_history_lifecycle=False,
            validated_runtime=validated_runtime,
        )
        background = publication.background_manifest
        if background is None:
            raise BridgeError("background_manifest_receipt_missing")
        context.n_input_tokens = publication.context["n_input_tokens"]
        context.n_cache_tokens = publication.context["n_cache_tokens"]
        context.n_output_tokens = publication.context["n_output_tokens"]
        metadata = dict(context.metadata) if isinstance(context.metadata, dict) else {}
        metadata.update(
            {
                "nano_run_id": self._run_spec["run_id"],
                "nano_trial_id": self._run_spec["trial_id"],
                "nano_attempt_id": self._run_spec["attempt_id"],
                "publication_kind": publication.publication_kind,
                "success_artifact_valid": publication.success_artifact_valid,
                "diagnostic_package_valid": publication.diagnostic_package_valid,
                "trajectory_path": publication.trajectory_path.name,
                "publication_marker": publication.marker_path.name,
                "background_manifest_sha256": background.sha256,
                "background_task_count": background.task_count,
                "background_manifest_status": background.status,
            }
        )
        if background.failure_code is not None:
            metadata["background_manifest_failure_code"] = background.failure_code
        context.metadata = metadata
        self._project_provider_cost_context(
            context,
            publication.provider_cost,
            publication.usage_coverage,
        )

    async def post_verifier_finalize_v1(
        self,
        *,
        verifier_status: str,
        verifier_error: BaseException | None,
        hard_deadline_monotonic_ns: int,
    ) -> None:
        """Record verifier truth, publish after it, then run one-shot cleanup."""

        lifecycle = self._trial_lifecycle
        if type(lifecycle) is not TrialLifecycleCoordinator:
            raise BridgeError("trial_lifecycle_unavailable")
        if lifecycle.verifier_permitted:
            status = {
                "success": VerifierStatus.SUCCESS,
                "timeout": VerifierStatus.TIMEOUT,
                "error": VerifierStatus.ERROR,
            }.get(verifier_status)
            if status is None:
                raise BridgeError("trial_lifecycle_verifier_invalid")
            if lifecycle.phase is TrialPhase.SAFETY_READY:
                lifecycle.verifier_terminal(
                    status=status,
                    detail=(
                        "native_verifier_terminal"
                        if verifier_error is None
                        else self._failure_code(verifier_error)
                    ),
                )

        async def cleanup_owner() -> None:
            cleanup_error: BaseException | None = None
            try:
                await self._post_verifier_cleanup_impl(
                    hard_deadline_monotonic_ns=hard_deadline_monotonic_ns,
                )
            except BaseException as error:
                cleanup_error = error
            finally:
                self._cleanup_git_history_escrow()
            if lifecycle.verifier_permitted:
                try:
                    self._publish_after_verifier()
                except BaseException as error:
                    self._post_verifier_publication_error = error
                if (
                    cleanup_error is None
                    and self._post_verifier_publication_error is None
                ):
                    lifecycle.submission_terminal(
                        state=AdmissionState.SUBMISSION_READY,
                        reason="marker_last_admission_passed",
                    )
                else:
                    lifecycle.submission_terminal(
                        state=AdmissionState.COMPLETE_NOT_SUBMITTABLE,
                        reason=(
                            "cleanup_failed"
                            if cleanup_error is not None
                            else "post_verifier_publication_failed"
                        ),
                    )
            plane = getattr(self, "_control_plane", None)
            if (
                isinstance(plane, ControlPlane)
                and cleanup_error is None
                and self._post_verifier_publication_error is None
            ):
                plane.cleanup()
            if cleanup_error is not None:
                raise cleanup_error

        cleanup = await lifecycle.finalize_once(cleanup_owner)
        if (
            lifecycle.verifier_permitted
            and lifecycle.phase is TrialPhase.VERIFIER_TERMINAL
        ):
            lifecycle.submission_terminal(
                state=AdmissionState.COMPLETE_NOT_SUBMITTABLE,
                reason=(
                    "cleanup_failed"
                    if not cleanup.succeeded
                    else "post_verifier_publication_failed"
                ),
            )

    async def _post_verifier_cleanup_capture(
        self,
        *,
        hard_cutoff_ns: int,
    ) -> tuple[bool, BaseException | None]:
        try:
            if self._actor is None:
                raise BridgeError("background_verifier_cleanup_unverified")
            lease = getattr(self, "_process_lease_v1", None)
            if type(lease) is not ProcessLeaseV1:
                raise BridgeError("background_verifier_cleanup_unverified")
            clean = await self._actor.close_process_lease_until(
                lease,
                hard_cutoff_ns,
            )
            if clean is not True:
                raise BridgeError("background_verifier_cleanup_unverified")
            return True, None
        except BaseException as error:
            return False, error

    async def _post_verifier_cleanup_impl(
        self,
        *,
        hard_deadline_monotonic_ns: int,
    ) -> None:
        """Idempotently terminate the sealed background set after verifier."""

        stored = getattr(self, "_post_verifier_cleanup_outcome", None)
        if stored is not None:
            _, error = stored
            if error is not None:
                raise error
            return
        now_ns = host_monotonic_ns()
        if (
            isinstance(hard_deadline_monotonic_ns, bool)
            or not isinstance(hard_deadline_monotonic_ns, int)
            or hard_deadline_monotonic_ns <= now_ns
        ):
            raise BridgeError("background_verifier_cleanup_unverified")
        task = getattr(self, "_post_verifier_cleanup_task", None)
        if task is None:
            task = asyncio.create_task(
                self._post_verifier_cleanup_capture(
                    hard_cutoff_ns=hard_deadline_monotonic_ns,
                )
            )
            self._post_verifier_cleanup_task = task
        completed, value, cancellation = await _complete_shielded(
            task,
            timeout_sec=(hard_deadline_monotonic_ns - host_monotonic_ns())
            / 1_000_000_000,
        )
        if completed:
            clean, error = value
        else:
            clean = False
            error = BridgeError("background_verifier_cleanup_unverified")
        if error is not None or clean is not True:
            failure = (
                error
                if error is not None
                else BridgeError("background_verifier_cleanup_unverified")
            )
            self._post_verifier_cleanup_outcome = (False, failure)
            raise failure
        self._post_verifier_cleanup_outcome = (True, None)
        if cancellation is not None:
            raise cancellation

    async def post_verifier_cleanup_v1(
        self,
        *,
        hard_deadline_monotonic_ns: int,
    ) -> None:
        """Terminate the sealed background set and destroy verifier-only escrow."""

        try:
            await self._post_verifier_cleanup_impl(
                hard_deadline_monotonic_ns=hard_deadline_monotonic_ns,
            )
        finally:
            self._cleanup_git_history_escrow()

    async def verifier_opportunity_decision_v1(
        self,
        *,
        primary_error: BaseException,
        result_target: object,
        workspace_receipt: object,
        hard_deadline_monotonic_ns: int,
    ) -> VerifierOpportunityDecisionV1:
        """Fail closed unless a terminal failure left a safe shared verifier."""

        denied = VerifierOpportunityDecisionV1(eligible=False)
        if (
            not isinstance(primary_error, Exception)
            or result_target is None
            or getattr(result_target, "agent_result", None) is None
            or self._actor is None
        ):
            return denied
        try:
            runtime = validate_verifier_terminal_runtime(
                runtime_dir=self._artifact_source_dir() / "runtime",
                run_spec=self._run_spec,
            )
            receipt = self._load_bound_workspace_receipt(workspace_receipt)
            if receipt.status != "complete" and receipt.continuable is not True:
                return denied
            if not await self._post_agent_cleanup_until(hard_deadline_monotonic_ns):
                return denied
            readiness = await self._actor.workspace_readiness_v1(
                hard_deadline_monotonic_ns=hard_deadline_monotonic_ns,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            return denied
        if (
            type(readiness) is not WorkspaceReadinessV1
            or readiness.mapping_verified is not True
            or readiness.environment_reachable is not True
            or readiness.zero_owned_processes_verified is not True
            or readiness.logical_workspace != "/workspace"
        ):
            return denied
        return VerifierOpportunityDecisionV1._grant(
            runtime=runtime,
            workspace_receipt_sha256=receipt.canonical_sha256,
            canonical_workspace=readiness.canonical_workspace,
        )

    async def run(
        self,
        instruction: str,
        environment: BaseEnvironment,
        context: AgentContext,
    ) -> None:
        """Retain an explicitly typed legacy path for non-live old callers."""

        if (
            getattr(self, "_deadline_mode", _DEADLINE_MODE_LEGACY)
            == DEADLINE_MODE_HARBOR_ROOT
        ):
            raise BridgeError("deadline_contract_unavailable")
        await self._run_bound(
            instruction=instruction,
            environment=environment,
            context=context,
            deadline_receipt=None,
        )

    async def run_with_deadline(
        self,
        *,
        instruction: str,
        environment: BaseEnvironment,
        context: AgentContext,
        deadline: RunDeadlineV1,
    ) -> None:
        """Run only with the immutable root minted by the Harbor phase seam."""

        if (
            getattr(self, "_deadline_mode", _DEADLINE_MODE_LEGACY)
            != DEADLINE_MODE_HARBOR_ROOT
        ):
            raise BridgeError("deadline_mode_mismatch")
        if not isinstance(deadline, RunDeadlineV1):
            raise BridgeError("deadline_contract_unavailable")
        try:
            require_harbor_agent_phase(deadline)
        except DeadlineContractError as error:
            raise BridgeError(error.args[0]) from error
        timeout_sec = self._run_spec.get("agent_timeout_sec")
        if (
            isinstance(timeout_sec, bool)
            or not isinstance(timeout_sec, int)
            or timeout_sec <= 0
            or deadline.agent_timeout_ms != timeout_sec * 1000
        ):
            raise BridgeError("deadline_timeout_binding_invalid")
        try:
            receipt = RunDeadlineReceiptV1.bind(
                deadline=deadline,
                run_id=self._run_spec["run_id"],
                trial_id=self._run_spec["trial_id"],
                attempt_id=self._run_spec["attempt_id"],
                run_spec_sha256=rust_run_spec_sha256(self._run_spec),
            )
        except (KeyError, DeadlineContractError) as error:
            raise BridgeError("deadline_contract_invalid") from error
        await self._run_bound(
            instruction=instruction,
            environment=environment,
            context=context,
            deadline_receipt=receipt,
        )

    async def _run_bound(
        self,
        *,
        instruction: str,
        environment: BaseEnvironment,
        context: AgentContext,
        deadline_receipt: RunDeadlineReceiptV1 | None,
    ) -> None:
        if not context.is_empty():
            raise RuntimeError("AgentContext must remain empty during run")
        if self._actor is None:
            raise RuntimeError("terminal actor was not set up")
        if instruction != self._run_spec["task"]["instruction"]:
            raise RuntimeError("Harbor instruction does not match pre-bound RunSpec")
        plane = getattr(self, "_control_plane", None)
        if isinstance(plane, ControlPlane):
            plane.verify_pre_dispatch()
        self._instruction = instruction
        loop = asyncio.get_running_loop()
        if deadline_receipt is None:
            origin = loop.time()
            runtime_deadline = (
                origin
                + float(self._run_spec["agent_timeout_sec"])
                + _RUNTIME_BRIDGE_GRACE_SEC
            )
            handoff_deadline = runtime_deadline + _HANDOFF_TIMEOUT_SEC
        else:
            runtime_deadline = None
            handoff_deadline = None
        outcome: BridgeOutcome | None = None
        original_error: BaseException | None = None
        runtime_launch_committed = False
        bridge_dispatch_started = False
        before_snapshot = getattr(self, "_before_snapshot", None)
        try:
            if before_snapshot is None:
                if deadline_receipt is not None:
                    raise BridgeError("workspace_before_snapshot_unavailable")
                before_snapshot = await capture_before(
                    SnapshotTarget(
                        actor=self._actor,
                        artifact_dir=self._artifact_source_dir(),
                        publication_dir=self.logs_dir,
                    ),
                    SnapshotPolicy(),
                )
                self._before_snapshot = before_snapshot
            input_dir = self._artifact_source_dir() / "input"
            input_dir.mkdir(parents=True, exist_ok=False)
            spec_path = input_dir / "run-spec.json"
            spec_path.write_bytes(canonical_json(self._run_spec))
            deadline_monotonic_ns: int | None = None
            if deadline_receipt is not None:
                runtime_dir = self._artifact_source_dir() / "runtime"
                runtime_dir.mkdir(parents=True, exist_ok=True)
                self._write_immutable(
                    runtime_dir / "deadline.json",
                    deadline_receipt.to_bytes(),
                )
                deadline_monotonic_ns = (
                    deadline_receipt.deadline.hard_deadline_monotonic_ns
                )
            command = runtime_command(
                binary_path=self._binary_path,
                spec_path=spec_path.resolve(),
                contract_dir=self._contract_dir.resolve(),
                provider=self._provider_launch,
                deadline_monotonic_ns=deadline_monotonic_ns,
            )
            if deadline_receipt is None:
                assert runtime_deadline is not None
                remaining = runtime_deadline - loop.time()
                if remaining <= 0:
                    raise BridgeError("external_bridge_deadline_exceeded")
            else:
                now_ns = host_monotonic_ns()
                if now_ns >= deadline_receipt.cutoffs.actor_done_monotonic_ns:
                    raise BridgeError("deadline_before_dispatch")
            if self._run_spec.get("schema_version") == "nano-run-spec-alpha-2":
                write_started(self._artifact_source_dir(), self._run_spec)
                runtime_launch_committed = True
            task_image = self._run_spec["task"]["id"]
            trial_id = self._run_spec["trial_id"]
            trial_family = (
                trial_id.split("__", 1)[0]
                if "__" in trial_id
                else task_image.rsplit("/", 1)[-1]
            )
            if deadline_receipt is None:
                bridge_dispatch_started = True
                outcome = await run_stdio_bridge(
                    command,
                    self._actor,
                    task_image=task_image,
                    trial_family=trial_family,
                    deadline_sec=remaining,
                )
            else:
                bridge_dispatch_started = True
                outcome = await run_stdio_bridge(
                    command,
                    self._actor,
                    task_image=task_image,
                    trial_family=trial_family,
                    deadline_receipt=deadline_receipt,
                )
            self._bridge_closed = True
            self._child_process_closed = True
        except BaseException as error:
            original_error = error
            closure_unverified = isinstance(error, BridgeError) and str(error) in {
                "cleanup_deadline_exceeded",
                "external_bridge_cleanup_unverified",
            }
            self._bridge_closed = not bridge_dispatch_started or not closure_unverified
            self._child_process_closed = (
                not bridge_dispatch_started or not closure_unverified
            )

        if deadline_receipt is None:
            assert handoff_deadline is not None
            handoff_budget = max(0.0, handoff_deadline - loop.time())
        else:
            handoff_budget = min(
                _HANDOFF_TIMEOUT_SEC,
                max(
                    0.0,
                    (
                        deadline_receipt.deadline.hard_deadline_monotonic_ns
                        - host_monotonic_ns()
                    )
                    / 1_000_000_000,
                ),
            )
        completed, finalization_error, handoff_cancellation = await _complete_shielded(
            self._finalize_handoff(
                outcome=outcome,
                original_error=original_error,
            ),
            timeout_sec=handoff_budget,
        )
        if not completed:
            finalization_error = BridgeError("adapter_handoff_deadline_exceeded")
        if (
            self._run_spec.get("schema_version") == "nano-run-spec-alpha-2"
            and not runtime_launch_committed
            and original_error is not None
        ):
            try:
                write_not_started(
                    self._artifact_source_dir(),
                    self._run_spec,
                    terminalization_path=(
                        self._artifact_source_dir() / "runtime-emergency.json"
                    ),
                    terminal_code=self._failure_code(original_error),
                )
            except RuntimeEntryError as error:
                if finalization_error is None:
                    finalization_error = BridgeError(str(error))
        if original_error is not None:
            if isinstance(finalization_error, BridgeError) and str(
                finalization_error
            ) in {
                "external_bridge_cleanup_unverified",
                "adapter_handoff_deadline_exceeded",
            }:
                raise finalization_error from original_error
            if isinstance(finalization_error, BaseException):
                original_error.add_note(
                    f"adapter handoff failure: {type(finalization_error).__name__}: "
                    f"{finalization_error}"
                )
            raise original_error.with_traceback(original_error.__traceback__)
        if isinstance(finalization_error, BaseException):
            raise finalization_error
        if handoff_cancellation is not None:
            raise handoff_cancellation

    def populate_context_post_run(self, context: AgentContext) -> None:
        """Best-effort runtime/cost sync; never publish, admit, or clean up."""

        self._post_run_context = context
        try:
            if self._instruction is None:
                self.logger.error(
                    "Nano runtime projection skipped: instruction unavailable"
                )
                return
            source_dir = self._artifact_source_dir()
            run_record_path = source_dir / "runtime" / "run.json"
            if run_record_path.exists() or run_record_path.is_symlink():
                validated_runtime = validate_runtime_artifacts(
                    runtime_dir=run_record_path.parent,
                    run_spec=self._run_spec,
                )
                self._project_provider_cost_context(
                    context,
                    validated_runtime.provider_cost,
                    validated_runtime.usage_coverage,
                )
        except Exception:
            self.logger.exception(
                "Nano runtime/cost projection failed; verifier authority is unchanged"
            )

    @staticmethod
    def _project_provider_cost_context(
        context: AgentContext,
        provider_cost: ProviderCostProjection,
        usage_coverage: Mapping[str, Any] | None,
    ) -> None:
        """Persist one validated cost projection independently of ATIF success."""

        context.cost_usd = (
            None
            if provider_cost.exact_ticks is None
            else float(
                Decimal(provider_cost.exact_ticks)
                / Decimal(provider_cost.ticks_per_usd)
            )
        )
        metadata = dict(context.metadata) if isinstance(context.metadata, dict) else {}
        metadata["provider_cost"] = {
            "source": provider_cost.source,
            "ticks_per_usd": provider_cost.ticks_per_usd,
            "observed_ticks": provider_cost.observed_ticks,
            "requested_calls": provider_cost.requested_calls,
            "covered_calls": provider_cost.covered_calls,
            "coverage": provider_cost.coverage,
            "is_complete": provider_cost.is_complete,
            "is_lower_bound": provider_cost.is_lower_bound,
        }
        if usage_coverage is not None:
            metadata["provider_call_coverage"] = dict(usage_coverage)
        context.metadata = metadata
