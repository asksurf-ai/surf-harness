"""Private, hash-chained trial lifecycle and verifier-safety authority.

This module deliberately has no artifact, ATIF, cost, reward, or submission
policy dependencies.  A verifier decision is derived only from identity,
workspace, Git, bridge/child, background, and ordering safety facts.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class TrialPhase(str, Enum):
    SETUP_BOUND = "SETUP_BOUND"
    RUNTIME_TERMINAL = "RUNTIME_TERMINAL"
    SAFETY_READY = "SAFETY_READY"
    SAFETY_BLOCKED = "SAFETY_BLOCKED"
    VERIFIER_SKIPPED_UNSAFE = "VERIFIER_SKIPPED_UNSAFE"
    VERIFIER_TERMINAL = "VERIFIER_TERMINAL"
    SUBMISSION_READY = "SUBMISSION_READY"
    COMPLETE_NOT_SUBMITTABLE = "COMPLETE_NOT_SUBMITTABLE"
    EXECUTION_FAILED_UNSAFE = "EXECUTION_FAILED_UNSAFE"
    CANCELLED_TERMINAL = "CANCELLED_TERMINAL"


class VerifierStatus(str, Enum):
    SUCCESS = "success"
    ZERO_REWARD = "zero_reward"
    ERROR = "error"
    TIMEOUT = "timeout"
    SKIPPED_UNSAFE = "skipped_unsafe"


class AdmissionState(str, Enum):
    SUBMISSION_READY = "SUBMISSION_READY"
    COMPLETE_NOT_SUBMITTABLE = "COMPLETE_NOT_SUBMITTABLE"


class SafetyBlockReason(str, Enum):
    IDENTITY_MISMATCH = "identity_mismatch"
    PROVIDER_BRIDGE_UNCLOSED = "provider_bridge_unclosed"
    CHILD_PROCESS_UNCLOSED = "child_process_unclosed"
    WORKSPACE_CAPTURE_UNPROVEN = "workspace_capture_unproven"
    GIT_EXPOSURE_UNSAFE = "git_exposure_unsafe"
    GIT_RESTORE_INVALID = "git_restore_invalid"
    ESCROW_ISOLATION_INVALID = "escrow_isolation_invalid"
    BACKGROUND_LIVENESS_UNKNOWN = "background_liveness_unknown"
    BACKGROUND_IDENTITY_MISMATCH = "background_identity_mismatch"
    ORDER_CONTRADICTION = "order_contradiction"


_HEX = frozenset("0123456789abcdef")
_GIT_MODES = frozenset(
    {
        "not_applicable",
        "restored",
        "synthetic_preserved",
        "preserved_authorized",
    }
)
_RECEIPT_BINDING_NAMES = (
    "baseline_receipt",
    "exposure_receipt",
    "run_record",
    "events",
    "workspace_receipt",
    "background_manifest",
    "provider_ledger",
)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def provider_terminal_ledger(
    events: Iterable[Mapping[str, object]],
) -> dict[str, int]:
    """Derive terminal provider accounting after bridge/process closure."""

    requests: dict[int, str] = {}
    for event in events:
        event_type = event.get("type")
        data = event.get("data")
        if not isinstance(data, Mapping):
            continue
        turn_index = data.get("turn_index")
        if type(turn_index) is not int or turn_index < 0:
            continue
        if event_type == "provider.requested":
            requests.setdefault(turn_index, "requested")
        elif event_type == "provider.completed" and turn_index in requests:
            requests[turn_index] = "completed"
        elif event_type == "provider.failed" and turn_index in requests:
            code = data.get("code")
            if code == "provider_request_cancelled":
                requests[turn_index] = "cancelled"
            elif code == "provider_response_unobserved":
                requests[turn_index] = "response_unobserved"
            else:
                requests[turn_index] = "failed"
    for turn_index, state in tuple(requests.items()):
        if state == "requested":
            requests[turn_index] = "response_unobserved"
    return {
        "requested": len(requests),
        "completed": sum(state == "completed" for state in requests.values()),
        "failed": sum(state == "failed" for state in requests.values()),
        "cancelled": sum(state == "cancelled" for state in requests.values()),
        "response_unobserved": sum(
            state == "response_unobserved" for state in requests.values()
        ),
        "outstanding": 0,
    }


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _digest(value: object) -> str:
    return _sha256(_canonical(value))


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX


def _bounded_text(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and "\x00" not in value
        and len(value.encode("utf-8")) <= 1024
    )


@dataclass(frozen=True)
class VerifierSafetyProof:
    run_id: str
    trial_id: str
    attempt_id: str
    run_spec_sha256: str
    runtime_manifest_sha256: str
    git_mode: str
    safe: bool
    block_reasons: tuple[SafetyBlockReason, ...]
    manifest_sha256: str

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "nano-verifier-safety-v1",
            "run_id": self.run_id,
            "trial_id": self.trial_id,
            "attempt_id": self.attempt_id,
            "run_spec_sha256": self.run_spec_sha256,
            "runtime_manifest_sha256": self.runtime_manifest_sha256,
            "git_mode": self.git_mode,
            "safe": self.safe,
            "block_reasons": [reason.value for reason in self.block_reasons],
            "manifest_sha256": self.manifest_sha256,
        }


@dataclass(frozen=True)
class CleanupResult:
    attempted: bool
    succeeded: bool
    failure: str | None


@dataclass(frozen=True)
class ReceiptHashBinding:
    name: str
    expected_sha256: str | None
    observed_sha256: str | None

    @property
    def valid(self) -> bool:
        return (
            self.name in _RECEIPT_BINDING_NAMES
            and _is_sha256(self.expected_sha256)
            and self.observed_sha256 == self.expected_sha256
        )


@dataclass(frozen=True)
class LifecycleReceiptValidation:
    """Mechanically compare persisted lifecycle identities to phase authority."""

    bindings: tuple[ReceiptHashBinding, ...]
    receipt_readable: bool
    failure_code: str | None

    @classmethod
    def compare(
        cls,
        *,
        expected: Mapping[str, object],
        observed: Mapping[str, object],
    ) -> LifecycleReceiptValidation:
        exact_names = set(expected) == set(_RECEIPT_BINDING_NAMES) and set(
            observed
        ) == set(_RECEIPT_BINDING_NAMES)
        bindings = tuple(
            ReceiptHashBinding(
                name=name,
                expected_sha256=(
                    expected.get(name) if isinstance(expected.get(name), str) else None
                ),
                observed_sha256=(
                    observed.get(name) if isinstance(observed.get(name), str) else None
                ),
            )
            for name in _RECEIPT_BINDING_NAMES
        )
        valid = exact_names and all(binding.valid for binding in bindings)
        return cls(
            bindings=bindings,
            receipt_readable=True,
            failure_code=None if valid else "lifecycle_receipt_identity_mismatch",
        )

    @classmethod
    def unreadable(
        cls,
        *,
        expected: Mapping[str, object],
        failure_code: str,
    ) -> LifecycleReceiptValidation:
        return cls(
            bindings=tuple(
                ReceiptHashBinding(
                    name=name,
                    expected_sha256=(
                        expected.get(name)
                        if isinstance(expected.get(name), str)
                        else None
                    ),
                    observed_sha256=None,
                )
                for name in _RECEIPT_BINDING_NAMES
            ),
            receipt_readable=False,
            failure_code=(
                failure_code
                if _bounded_text(failure_code)
                else "lifecycle_receipt_unreadable"
            ),
        )

    @property
    def valid(self) -> bool:
        return (
            self.receipt_readable
            and self.failure_code is None
            and tuple(binding.name for binding in self.bindings)
            == _RECEIPT_BINDING_NAMES
            and all(binding.valid for binding in self.bindings)
        )

    def binding_valid(self, name: str) -> bool:
        return any(binding.name == name and binding.valid for binding in self.bindings)


class TrialLifecycleCoordinator:
    """The sole monotonic transition and cleanup owner for one trial."""

    def __init__(
        self,
        *,
        root: Path,
        run_id: str,
        trial_id: str,
        attempt_id: str,
        run_spec_sha256: str,
    ) -> None:
        if (
            not root.is_absolute()
            or root.is_symlink()
            or not root.is_dir()
            or not all(_bounded_text(item) for item in (run_id, trial_id, attempt_id))
            or not _is_sha256(run_spec_sha256)
        ):
            raise RuntimeError("trial_lifecycle_identity_invalid")
        self.root = root.resolve()
        self.run_id = run_id
        self.trial_id = trial_id
        self.attempt_id = attempt_id
        self.run_spec_sha256 = run_spec_sha256
        self._phase: TrialPhase | None = None
        self._last_manifest_sha256: str | None = None
        self._manifests: dict[TrialPhase, tuple[str, bytes]] = {}
        self._safety_proof: VerifierSafetyProof | None = None
        self._finalize_started = False
        self._finalize_result: CleanupResult | None = None

    @property
    def phase(self) -> TrialPhase | None:
        return self._phase

    @property
    def verifier_permitted(self) -> bool:
        return self._safety_proof is not None and self._safety_proof.safe is True

    @property
    def safety_proof(self) -> VerifierSafetyProof | None:
        return self._safety_proof

    def _identity(self) -> dict[str, str]:
        return {
            "run_id": self.run_id,
            "trial_id": self.trial_id,
            "attempt_id": self.attempt_id,
            "run_spec_sha256": self.run_spec_sha256,
        }

    @staticmethod
    def _filename(phase: TrialPhase) -> str:
        return f"phase-{phase.value.lower().replace('_', '-')}.json"

    def _write_phase(
        self,
        phase: TrialPhase,
        body: Mapping[str, object],
        *,
        predecessor_sha256: str | None = None,
    ) -> str:
        existing = self._manifests.get(phase)
        if existing is not None:
            persisted = json.loads(existing[1])
            if (
                persisted.get("body") != dict(body)
                or predecessor_sha256 is not None
                and persisted.get("predecessor_sha256") != predecessor_sha256
            ):
                raise RuntimeError("trial_lifecycle_conflict")
            return existing[0]
        predecessor = (
            self._last_manifest_sha256
            if predecessor_sha256 is None
            else predecessor_sha256
        )
        unsigned = {
            "schema_version": "nano-trial-phase-manifest-v1",
            "phase": phase.value,
            **self._identity(),
            "predecessor_sha256": predecessor,
            "body": dict(body),
        }
        manifest_sha256 = _digest(unsigned)
        payload = _canonical({**unsigned, "manifest_sha256": manifest_sha256})
        path = self.root / self._filename(phase)
        descriptor: int | None = None
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = None
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError as error:
            raise RuntimeError("trial_lifecycle_manifest_exists") from error
        except OSError as error:
            raise RuntimeError("trial_lifecycle_manifest_write_failed") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
        self._manifests[phase] = (manifest_sha256, payload)
        self._last_manifest_sha256 = manifest_sha256
        self._phase = phase
        return manifest_sha256

    def bind_setup(
        self,
        *,
        exposure_receipt_sha256: str,
        baseline_receipt_sha256: str,
        background_registry_sha256: str,
    ) -> str:
        values = (
            exposure_receipt_sha256,
            baseline_receipt_sha256,
            background_registry_sha256,
        )
        if not all(_is_sha256(value) for value in values):
            raise RuntimeError("trial_lifecycle_setup_invalid")
        return self._write_phase(
            TrialPhase.SETUP_BOUND,
            {
                "exposure_receipt_sha256": exposure_receipt_sha256,
                "baseline_receipt_sha256": baseline_receipt_sha256,
                "background_registry_sha256": background_registry_sha256,
                "verifier_not_started": True,
            },
            predecessor_sha256=None,
        )

    def runtime_terminal(
        self,
        *,
        terminal_status: str,
        terminal_code: str,
        run_record_sha256: str,
        events_sha256: str,
        workspace_receipt_sha256: str | None,
        provider_ledger: Mapping[str, object],
        bridge_closed: bool,
        child_process_closed: bool,
    ) -> str:
        expected = {
            "requested",
            "completed",
            "failed",
            "cancelled",
            "response_unobserved",
            "outstanding",
        }
        if (
            TrialPhase.SETUP_BOUND not in self._manifests
            or not _bounded_text(terminal_status)
            or not _bounded_text(terminal_code)
            or not _is_sha256(run_record_sha256)
            or not _is_sha256(events_sha256)
            or workspace_receipt_sha256 is not None
            and not _is_sha256(workspace_receipt_sha256)
            or set(provider_ledger) != expected
            or any(
                type(provider_ledger[key]) is not int or provider_ledger[key] < 0
                for key in expected
            )
            or provider_ledger["outstanding"] != 0
            or provider_ledger["requested"]
            != provider_ledger["completed"]
            + provider_ledger["failed"]
            + provider_ledger["cancelled"]
            + provider_ledger["response_unobserved"]
            or type(bridge_closed) is not bool
            or type(child_process_closed) is not bool
        ):
            raise RuntimeError("trial_lifecycle_runtime_invalid")
        setup_sha = self._manifests[TrialPhase.SETUP_BOUND][0]
        return self._write_phase(
            TrialPhase.RUNTIME_TERMINAL,
            {
                "terminal_status": terminal_status,
                "terminal_code": terminal_code,
                "run_record_sha256": run_record_sha256,
                "events_sha256": events_sha256,
                "workspace_receipt_sha256": workspace_receipt_sha256,
                "provider_ledger": dict(provider_ledger),
                "bridge_closed": bridge_closed,
                "child_process_closed": child_process_closed,
            },
            predecessor_sha256=setup_sha,
        )

    def receipt_binding_expectations(
        self,
        *,
        background_manifest_sha256: str | None,
    ) -> dict[str, str | None]:
        """Return immutable setup/runtime identities used by receipt validation."""

        setup_entry = self._manifests.get(TrialPhase.SETUP_BOUND)
        runtime_entry = self._manifests.get(TrialPhase.RUNTIME_TERMINAL)
        if setup_entry is None or runtime_entry is None:
            raise RuntimeError("trial_lifecycle_receipt_binding_invalid")
        try:
            setup = json.loads(setup_entry[1])["body"]
            runtime = json.loads(runtime_entry[1])["body"]
        except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("trial_lifecycle_receipt_binding_invalid") from error
        ledger = runtime.get("provider_ledger") if isinstance(runtime, dict) else None
        return {
            "baseline_receipt": setup.get("baseline_receipt_sha256"),
            "exposure_receipt": setup.get("exposure_receipt_sha256"),
            "run_record": runtime.get("run_record_sha256"),
            "events": runtime.get("events_sha256"),
            "workspace_receipt": runtime.get("workspace_receipt_sha256"),
            "background_manifest": background_manifest_sha256,
            "provider_ledger": _digest(ledger) if isinstance(ledger, dict) else None,
        }

    def prove_safety(
        self,
        *,
        identity_bound: bool,
        receipt_validation: LifecycleReceiptValidation,
        bridge_closed: bool,
        child_process_closed: bool,
        workspace_capture_complete: bool,
        restore_valid: bool,
        escrow_isolated: bool,
        background_liveness_known: bool,
        background_identity_bound: bool,
        verifier_not_started: bool,
        git_mode: str,
    ) -> VerifierSafetyProof:
        if (
            TrialPhase.RUNTIME_TERMINAL not in self._manifests
            or git_mode not in _GIT_MODES
            or not isinstance(receipt_validation, LifecycleReceiptValidation)
        ):
            raise RuntimeError("trial_lifecycle_safety_invalid")
        predecessor_hashes_bound = receipt_validation.valid
        git_exposure_safe = receipt_validation.binding_valid(
            "baseline_receipt"
        ) and receipt_validation.binding_valid("exposure_receipt")
        facts = {
            "identity_bound": identity_bound,
            "predecessor_hashes_bound": predecessor_hashes_bound,
            "bridge_closed": bridge_closed,
            "child_process_closed": child_process_closed,
            "workspace_capture_complete": workspace_capture_complete,
            "git_exposure_safe": git_exposure_safe,
            "restore_valid": restore_valid,
            "escrow_isolated": escrow_isolated,
            "background_liveness_known": background_liveness_known,
            "background_identity_bound": background_identity_bound,
            "verifier_not_started": verifier_not_started,
        }
        if any(type(value) is not bool for value in facts.values()):
            raise RuntimeError("trial_lifecycle_safety_invalid")
        reasons: list[SafetyBlockReason] = []
        if not identity_bound or not predecessor_hashes_bound:
            reasons.append(SafetyBlockReason.IDENTITY_MISMATCH)
        mapping = (
            (bridge_closed, SafetyBlockReason.PROVIDER_BRIDGE_UNCLOSED),
            (child_process_closed, SafetyBlockReason.CHILD_PROCESS_UNCLOSED),
            (workspace_capture_complete, SafetyBlockReason.WORKSPACE_CAPTURE_UNPROVEN),
            (git_exposure_safe, SafetyBlockReason.GIT_EXPOSURE_UNSAFE),
            (restore_valid, SafetyBlockReason.GIT_RESTORE_INVALID),
            (escrow_isolated, SafetyBlockReason.ESCROW_ISOLATION_INVALID),
            (background_liveness_known, SafetyBlockReason.BACKGROUND_LIVENESS_UNKNOWN),
            (background_identity_bound, SafetyBlockReason.BACKGROUND_IDENTITY_MISMATCH),
            (verifier_not_started, SafetyBlockReason.ORDER_CONTRADICTION),
        )
        reasons.extend(reason for valid, reason in mapping if not valid)
        reasons = list(dict.fromkeys(reasons))
        runtime_sha = self._manifests[TrialPhase.RUNTIME_TERMINAL][0]
        proof_body = {
            "schema_version": "nano-verifier-safety-v1",
            "runtime_manifest_sha256": runtime_sha,
            "git_mode": git_mode,
            **facts,
            "safe": not reasons,
            "block_reasons": [reason.value for reason in reasons],
        }
        phase = TrialPhase.SAFETY_READY if not reasons else TrialPhase.SAFETY_BLOCKED
        manifest_sha = self._write_phase(
            phase,
            proof_body,
            predecessor_sha256=runtime_sha,
        )
        proof = VerifierSafetyProof(
            **self._identity(),
            runtime_manifest_sha256=runtime_sha,
            git_mode=git_mode,
            safe=not reasons,
            block_reasons=tuple(reasons),
            manifest_sha256=manifest_sha,
        )
        if self._safety_proof is not None and self._safety_proof != proof:
            raise RuntimeError("trial_lifecycle_conflict")
        self._safety_proof = proof
        if reasons:
            self._write_phase(
                TrialPhase.VERIFIER_SKIPPED_UNSAFE,
                {
                    "verifier_status": VerifierStatus.SKIPPED_UNSAFE.value,
                    "block_reasons": [reason.value for reason in reasons],
                    "safety_manifest_sha256": manifest_sha,
                },
                predecessor_sha256=manifest_sha,
            )
        return proof

    def verifier_terminal(self, *, status: VerifierStatus, detail: str) -> str:
        if not self.verifier_permitted or not isinstance(status, VerifierStatus):
            raise RuntimeError("trial_lifecycle_verifier_invalid")
        if status is VerifierStatus.SKIPPED_UNSAFE or not _bounded_text(detail):
            raise RuntimeError("trial_lifecycle_verifier_invalid")
        assert self._safety_proof is not None
        return self._write_phase(
            TrialPhase.VERIFIER_TERMINAL,
            {
                "verifier_status": status.value,
                "detail": detail,
                "safety_manifest_sha256": self._safety_proof.manifest_sha256,
            },
            predecessor_sha256=self._safety_proof.manifest_sha256,
        )

    def submission_terminal(self, *, state: AdmissionState, reason: str) -> str:
        if not isinstance(state, AdmissionState) or not _bounded_text(reason):
            raise RuntimeError("trial_lifecycle_submission_invalid")
        if self._phase is TrialPhase.VERIFIER_TERMINAL:
            predecessor = self._manifests[TrialPhase.VERIFIER_TERMINAL][0]
        elif (
            self._phase is TrialPhase.SUBMISSION_READY
            and state is AdmissionState.COMPLETE_NOT_SUBMITTABLE
        ):
            predecessor = self._manifests[TrialPhase.SUBMISSION_READY][0]
        else:
            raise RuntimeError("trial_lifecycle_submission_invalid")
        phase = TrialPhase(state.value)
        return self._write_phase(
            phase,
            {"submission_status": state.value, "reason": reason},
            predecessor_sha256=predecessor,
        )

    async def finalize_once(
        self,
        cleanup: Callable[[], Awaitable[None]],
    ) -> CleanupResult:
        if self._finalize_result is not None:
            return self._finalize_result
        if self._finalize_started:
            raise RuntimeError("trial_lifecycle_finalize_in_progress")
        self._finalize_started = True
        try:
            await cleanup()
        except BaseException as error:
            result = CleanupResult(
                attempted=True,
                succeeded=False,
                failure=type(error).__name__,
            )
        else:
            result = CleanupResult(attempted=True, succeeded=True, failure=None)
        self._finalize_result = result
        if self._phase is TrialPhase.VERIFIER_SKIPPED_UNSAFE:
            self._write_phase(
                TrialPhase.EXECUTION_FAILED_UNSAFE,
                {
                    "cleanup_succeeded": result.succeeded,
                    "cleanup_failure": result.failure,
                },
            )
        elif (
            self._phase
            in {
                TrialPhase.VERIFIER_TERMINAL,
                TrialPhase.SUBMISSION_READY,
            }
            and result.succeeded is False
        ):
            self.submission_terminal(
                state=AdmissionState.COMPLETE_NOT_SUBMITTABLE,
                reason="cleanup_failed",
            )
        return result
