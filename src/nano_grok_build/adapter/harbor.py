"""Pinned Harbor v0.20.0 adapter for the host nano runtime."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import logging
import os
import re
from pathlib import Path
from typing import Any

from harbor.agents.base import BaseAgent
from harbor.environments.base import BaseEnvironment
from harbor.models.agent.context import AgentContext

from nano_grok_build import __version__
from nano_grok_build.adapter.artifactizer import (
    BACKGROUND_FAILURE_MANIFEST_SCHEMA,
    BACKGROUND_MANIFEST_SCHEMA,
    VerifierOpportunityDecisionV1,
    canonical_json,
    publish_artifacts,
    rust_run_spec_sha256,
    validate_verifier_terminal_runtime,
)
from nano_grok_build.adapter.artifactizer import (
    _read_regular as _read_artifact_regular,
)
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
from nano_grok_build.harbor.provider import (
    HostProviderKind,
    HostProviderLaunch,
    runtime_command,
)

_RUNTIME_BRIDGE_GRACE_SEC = 1.0
_HANDOFF_TIMEOUT_SEC = 150.0
_DEADLINE_MODE_LEGACY = "legacy-adapter-v1"
_BACKGROUND_LIVENESS_SCHEMA = "nano-background-liveness-v1"
_BACKGROUND_LIVENESS_MAX_BYTES = 64 * 1024
_STABLE_FAILURE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")


class _HarborEnvironmentProxy:
    def __init__(self, environment: BaseEnvironment) -> None:
        self._environment = environment

    async def exec(self, *args: Any, **kwargs: Any) -> Any:
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
        expected_artifact_dir = (self.logs_dir / "runtime").resolve()
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
        self._actor = RemoteTerminalActor(_HarborEnvironmentProxy(environment))
        await self._actor.setup()
        self._before_snapshot = await capture_before(
            SnapshotTarget(actor=self._actor, artifact_dir=self.logs_dir),
            SnapshotPolicy(),
        )

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
        if isinstance(stderr, bytes):
            return canonical_json(
                {
                    "schema_version": "nano-runtime-stderr-digest-v1",
                    "code": self._failure_code(error),
                    "byte_length": len(stderr),
                    "sha256": hashlib.sha256(stderr).hexdigest(),
                    **actor_metadata,
                }
            )
        return canonical_json(
            {
                "schema_version": "nano-runtime-stderr-receipt-v1",
                "status": "unavailable",
                "code": self._failure_code(error),
                **actor_metadata,
            }
        )

    def _emergency_receipt(
        self,
        outcome: BridgeOutcome | None,
        error: BaseException | None,
    ) -> bytes:
        events_path = self.logs_dir / "runtime" / "events.jsonl"
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
                self.logs_dir / "runtime-stderr.json",
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
                self.logs_dir / "runtime-background-manifest.json",
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

        run_record = self.logs_dir / "runtime" / "run.json"
        run_record_available = run_record.is_file() and not run_record.is_symlink()
        if not run_record_available:
            try:
                self._write_immutable(
                    self.logs_dir / "runtime-emergency.json",
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
                    self.logs_dir / "runtime-background-manifest.json",
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
                SnapshotTarget(actor=self._actor, artifact_dir=self.logs_dir),
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
            persisted = load_workspace_receipt(self.logs_dir / "workspace-receipt.json")
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
        manifest_path = self.logs_dir / "runtime-background-manifest.json"
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
                self.logs_dir / "runtime-background-liveness-v1.json",
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
        self._post_agent_snapshot_outcome = (receipt, None)
        return persisted_receipt

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

    async def post_verifier_cleanup_v1(
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
                runtime_dir=self.logs_dir / "runtime",
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
        before_snapshot = getattr(self, "_before_snapshot", None)
        try:
            if before_snapshot is None:
                if deadline_receipt is not None:
                    raise BridgeError("workspace_before_snapshot_unavailable")
                before_snapshot = await capture_before(
                    SnapshotTarget(actor=self._actor, artifact_dir=self.logs_dir),
                    SnapshotPolicy(),
                )
                self._before_snapshot = before_snapshot
            input_dir = self.logs_dir / "input"
            input_dir.mkdir(parents=True, exist_ok=False)
            spec_path = input_dir / "run-spec.json"
            spec_path.write_bytes(canonical_json(self._run_spec))
            deadline_monotonic_ns: int | None = None
            if deadline_receipt is not None:
                runtime_dir = self.logs_dir / "runtime"
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
                outcome = await run_stdio_bridge(
                    command,
                    self._actor,
                    deadline_sec=remaining,
                )
            else:
                now_ns = host_monotonic_ns()
                if now_ns >= deadline_receipt.cutoffs.actor_done_monotonic_ns:
                    raise BridgeError("deadline_before_dispatch")
                outcome = await run_stdio_bridge(
                    command,
                    self._actor,
                    deadline_receipt=deadline_receipt,
                )
        except BaseException as error:
            original_error = error

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
        """Idempotent, marker-last projection. This hook must never throw."""

        try:
            if self._instruction is None:
                self.logger.error(
                    "Nano artifactization skipped: instruction unavailable"
                )
                return
            publication = publish_artifacts(
                logs_dir=self.logs_dir,
                run_spec=self._run_spec,
                instruction=self._instruction,
                agent_name=self.name(),
                agent_version=self.version(),
                model_name=self._run_spec["provider"]["model"],
                require_harbor_validator=True,
                require_background_manifest=True,
            )
            background = publication.background_manifest
            if background is None:
                raise RuntimeError("background manifest receipt missing")
            context.n_input_tokens = publication.context["n_input_tokens"]
            context.n_cache_tokens = publication.context["n_cache_tokens"]
            context.n_output_tokens = publication.context["n_output_tokens"]
            context.metadata = {
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
            if background.failure_code is not None:
                context.metadata["background_manifest_failure_code"] = (
                    background.failure_code
                )
            if publication.usage_coverage is not None:
                context.metadata["provider_call_coverage"] = dict(
                    publication.usage_coverage
                )
        except Exception:
            self.logger.exception(
                "Nano artifactization failed; marker remains authoritative"
            )
