"""Bounded, deterministic, secret-aware workspace snapshot support."""

from __future__ import annotations

import asyncio
import base64
import difflib
import errno as errno_module
import hashlib
import inspect
import io
import json
import os
import re
import shlex
import stat
import subprocess
import tarfile
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any

from nano_grok_build.adapter.artifact_limits import (
    WORKSPACE_CHANGED_TAR_MAX_BYTES,
)
from nano_grok_build.adapter.deadline import host_monotonic_ns
from nano_grok_build.adapter.terminal_actor import (
    SNAPSHOT_OUTPUT_CAP_BYTES,
    SnapshotFailureEvidenceV1,
    SnapshotFailureReasonV1,
    SnapshotFailureSubtypeV1,
    SnapshotOperationCancelled,
    SnapshotTimeoutOriginV1,
)

SNAPSHOT_POLICY_VERSION = "nano-workspace-snapshot-policy-v1"
MANIFEST_SCHEMA = "nano-workspace-manifest-v1"
DELTA_SCHEMA = "nano-workspace-delta-v1"
RECEIPT_SCHEMA = "nano-workspace-receipt-v1"
LEGACY_FAILURE_RECEIPT_SCHEMA = "nano-workspace-receipt-v2"
FAILURE_RECEIPT_SCHEMA = "nano-workspace-receipt-v3"
FAILURE_RECEIPT_SCHEMA_V4 = "nano-workspace-receipt-v4"
FAILURE_RECEIPT_SCHEMA_V5 = "nano-workspace-receipt-v5"
SENSITIVE_RULES_VERSION = "nano-workspace-sensitive-rules-v1"
_EXCLUDED_NAMES = frozenset(
    {
        ".cache",
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".terminals",
        "__pycache__",
        "cache",
        "caches",
        "dataset",
        "datasets",
        "node_modules",
    }
)
_SENSITIVE_NAMES = frozenset(
    {
        ".env",
        ".netrc",
        "credentials",
        "credentials.json",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
    }
)
_SENSITIVE_PATH = re.compile(
    r"(?:^|[._-])(secret|secrets|credential|credentials|password|passwd|token)"
    r"(?:$|[._-])",
    re.IGNORECASE,
)
_SENSITIVE_CONTENT = re.compile(
    rb"(?:"
    rb"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"
    rb"|(?:api[_-]?key|secret|password|passwd|token|credential)"
    rb"\s*[\"']?\s*[:=]\s*[\"']?\s*[^\s\"']{4,}"
    rb"|(?:sk|xai)-[A-Za-z0-9_-]{8,}"
    rb")",
    re.IGNORECASE,
)
_SENSITIVE_SAMPLE_BYTES = 1024 * 1024
_REMOTE_SENSITIVE_ERE = (
    "BEGIN ([A-Z ]+ )?PRIVATE KEY|"
    "(api[_-]?key|secret|password|passwd|token|credential)"
    "[[:space:]]*[\"']?[[:space:]]*[:=][[:space:]]*[\"']?"
    "[[:space:]]*[^[:space:]\"']{4,}|"
    "(sk|xai)-[A-Za-z0-9_-]{8,}"
)
_REMOTE_STAGE_PREFIX = "/tmp/nano-workspace-snapshot-v1."
_REMOTE_STAGE_TIMEOUT_SEC = 5.0
_REMOTE_TIMEOUT_SEC = 120.0
_REMOTE_GIT_COMMAND_TIMEOUT_SEC = 5
_REMOTE_SCAN_PHASE_TIMEOUT_SEC = 15
_REMOTE_CONTENT_PHASE_TIMEOUT_SEC = 45
_REMOTE_FILE_OPERATION_TIMEOUT_SEC = 3
_REMOTE_ARCHIVE_PHASE_TIMEOUT_SEC = 15
_REMOTE_SYNC_PHASE_TIMEOUT_SEC = 2
POST_AGENT_SNAPSHOT_MAX_SEC = 150.0
SNAPSHOT_CANCEL_TERMINAL_RESERVE_SEC = 13.0
SNAPSHOT_REAP_RESERVE_SEC = 2.0
SNAPSHOT_STAGE_CLEANUP_RESERVE_SEC = 5.0
SNAPSHOT_RECEIPT_SCHEDULE_RESERVE_SEC = 2.0
POST_AGENT_SNAPSHOT_CLEANUP_RESERVE_SEC = (
    SNAPSHOT_CANCEL_TERMINAL_RESERVE_SEC
    + SNAPSHOT_REAP_RESERVE_SEC
    + SNAPSHOT_STAGE_CLEANUP_RESERVE_SEC
    + SNAPSHOT_RECEIPT_SCHEDULE_RESERVE_SEC
)
FAILURE_STAGES = frozenset(
    "target remote-exec remote-command stage-parse inventory-download "
    "archive-download inventory-parse archive-parse cleanup publish "
    "host-evidence".split()
)
FAILURE_CATEGORIES = frozenset(
    "cancelled timeout connection os_error transport command parse policy "
    "publish evidence internal".split()
)
_TRANSIENT_ERRNOS = (
    errno_module.EAGAIN,
    errno_module.ECONNABORTED,
    errno_module.ECONNREFUSED,
    errno_module.ECONNRESET,
    errno_module.EINTR,
    errno_module.EPIPE,
    errno_module.ETIMEDOUT,
)
_CAPTURE_FAILURE_CODES = {
    "workspace_before_capture_failed",
    "workspace_after_capture_failed",
}
_REMOTE_PARTIAL_REASONS = frozenset(
    {
        "archive_unavailable",
        "archive_wall_budget",
        "content_scan_wall_budget",
        "git_metadata_unavailable",
        "inventory_scan_unavailable",
        "inventory_scan_wall_budget",
    }
)
_REMOTE_ARCHIVE_OMISSION_REASONS = frozenset(
    {"archive_unavailable", "archive_wall_budget"}
)


@dataclass(frozen=True)
class _SnapshotCaptureDeadlineV1:
    hard_monotonic_ns: int

    def __post_init__(self) -> None:
        if type(self.hard_monotonic_ns) is not int or self.hard_monotonic_ns <= 0:
            raise WorkspaceSnapshotError("workspace_snapshot_deadline_invalid")

    @property
    def capture_monotonic_ns(self) -> int:
        return self.hard_monotonic_ns - int(
            POST_AGENT_SNAPSHOT_CLEANUP_RESERVE_SEC * 1_000_000_000
        )

    @property
    def recovery_monotonic_ns(self) -> int:
        return self.hard_monotonic_ns - int(
            (SNAPSHOT_STAGE_CLEANUP_RESERVE_SEC + SNAPSHOT_RECEIPT_SCHEDULE_RESERVE_SEC)
            * 1_000_000_000
        )

    @property
    def cleanup_monotonic_ns(self) -> int:
        return self.hard_monotonic_ns - int(
            SNAPSHOT_RECEIPT_SCHEDULE_RESERVE_SEC * 1_000_000_000
        )

    def timeout(
        self,
        requested_sec: float,
        *,
        cleanup: bool = False,
    ) -> float:
        cutoff_ns = self.cleanup_monotonic_ns if cleanup else self.capture_monotonic_ns
        remaining_sec = (cutoff_ns - host_monotonic_ns()) / 1_000_000_000
        if remaining_sec <= 0:
            raise TimeoutError("workspace_snapshot_absolute_deadline_exceeded")
        return min(requested_sec, remaining_sec)

    def remaining(self, *, cleanup: bool = False) -> float:
        cutoff_ns = self.cleanup_monotonic_ns if cleanup else self.capture_monotonic_ns
        return max(0.0, (cutoff_ns - host_monotonic_ns()) / 1_000_000_000)


def _capture_checkpoint(deadline: _SnapshotCaptureDeadlineV1 | None) -> None:
    if deadline is not None:
        deadline.timeout(POST_AGENT_SNAPSHOT_MAX_SEC)


_OWNED_TIMEOUT_ORIGINS_V1 = frozenset(
    {
        SnapshotTimeoutOriginV1.SEMANTIC_EXECUTION_TIMED_OUT,
        SnapshotTimeoutOriginV1.WAIT_TRANSPORT_TIMED_OUT_RECOVERED,
    }
)
_BEFORE_CONTINUABLE_SUBTYPES_V1 = frozenset(
    {
        SnapshotFailureSubtypeV1.WAIT_TRANSPORT_FAILED,
        SnapshotFailureSubtypeV1.WAIT_RESPONSE_INVALID,
    }
)
_AFTER_CONTINUABLE_SUBTYPES_V1 = frozenset(
    {
        SnapshotFailureSubtypeV1.HOST_EVIDENCE_PARSE_FAILED,
        SnapshotFailureSubtypeV1.WAIT_TRANSPORT_FAILED,
        SnapshotFailureSubtypeV1.WAIT_RESPONSE_INVALID,
        SnapshotFailureSubtypeV1.HOST_EVIDENCE_MATERIALIZATION_FAILED,
    }
)
_OUTER_RESPONSE_FAILURE_REASONS_V1 = frozenset(
    {
        SnapshotFailureReasonV1.OUTER_RETURN_CODE_TYPE_INVALID,
        SnapshotFailureReasonV1.OUTER_RETURN_CODE_NONZERO,
        SnapshotFailureReasonV1.OUTER_STDOUT_TYPE_INVALID,
        SnapshotFailureReasonV1.OUTER_STDERR_TYPE_INVALID,
        SnapshotFailureReasonV1.OUTER_STDERR_NONEMPTY,
    }
)


def workspace_failure_disposition(
    code: object,
    stage: object,
    category: object,
    *,
    subtype: object = None,
    timeout_origin: object = None,
    reason: object = None,
    stage_validated: bool = False,
    termination_verified: bool = False,
    cleanup_verified: bool = False,
    zero_census_verified: bool = False,
    execution_binding_verified: bool = False,
) -> str:
    """Classify one persisted capture failure using a closed security allowlist."""

    if code not in _CAPTURE_FAILURE_CODES:
        return "trial_fatal"
    try:
        selected_subtype = (
            subtype
            if isinstance(subtype, SnapshotFailureSubtypeV1)
            else SnapshotFailureSubtypeV1(subtype)
        )
        selected_timeout_origin = (
            timeout_origin
            if isinstance(timeout_origin, SnapshotTimeoutOriginV1)
            else SnapshotTimeoutOriginV1(timeout_origin)
        )
        selected_reason = (
            SnapshotFailureReasonV1.NOT_APPLICABLE
            if reason is None
            else (
                reason
                if isinstance(reason, SnapshotFailureReasonV1)
                else SnapshotFailureReasonV1(reason)
            )
        )
    except (TypeError, ValueError):
        return "trial_fatal"
    if not (
        stage_validated is True
        and termination_verified is True
        and cleanup_verified is True
        and zero_census_verified is True
    ):
        return "trial_fatal"
    phase_allowlist = (
        _BEFORE_CONTINUABLE_SUBTYPES_V1
        if code == "workspace_before_capture_failed"
        else _AFTER_CONTINUABLE_SUBTYPES_V1
    )
    if selected_subtype not in phase_allowlist:
        return "trial_fatal"
    if selected_subtype is SnapshotFailureSubtypeV1.WAIT_TRANSPORT_FAILED:
        if (
            stage == "remote-exec"
            and category == "timeout"
            and selected_timeout_origin in _OWNED_TIMEOUT_ORIGINS_V1
        ):
            return "diagnostic_failed_continue"
        return "trial_fatal"
    if selected_subtype is SnapshotFailureSubtypeV1.WAIT_RESPONSE_INVALID:
        if (
            stage == "remote-exec"
            and category == "internal"
            and selected_timeout_origin is SnapshotTimeoutOriginV1.NOT_A_TIMEOUT
            and selected_reason in _OUTER_RESPONSE_FAILURE_REASONS_V1
            and execution_binding_verified is True
        ):
            return "diagnostic_failed_continue"
        return "trial_fatal"
    if selected_subtype is SnapshotFailureSubtypeV1.HOST_EVIDENCE_PARSE_FAILED:
        if (
            stage in {"inventory-parse", "archive-parse"}
            and category == "parse"
            and selected_timeout_origin is SnapshotTimeoutOriginV1.NOT_A_TIMEOUT
        ):
            return "diagnostic_failed_continue"
        return "trial_fatal"
    if (
        selected_subtype
        is SnapshotFailureSubtypeV1.HOST_EVIDENCE_MATERIALIZATION_FAILED
    ):
        if (
            code == "workspace_after_capture_failed"
            and stage == "host-evidence"
            and category == "evidence"
            and selected_timeout_origin is SnapshotTimeoutOriginV1.NOT_A_TIMEOUT
        ):
            return "diagnostic_failed_continue"
    return "trial_fatal"


@dataclass(frozen=True)
class WorkspaceFailureV3:
    stage: str | None = None
    category: str | None = None
    errno: int | None = None
    return_code: int | None = None
    attempt: int = 1
    transient: bool = False
    subtype: SnapshotFailureSubtypeV1 = SnapshotFailureSubtypeV1.UNKNOWN_INTERNAL
    timeout_origin: SnapshotTimeoutOriginV1 = SnapshotTimeoutOriginV1.NOT_A_TIMEOUT
    stage_validated: bool = False
    termination_verified: bool = False
    cleanup_verified: bool = False
    zero_census_verified: bool = False

    def continuable(self, code: str) -> bool:
        return (
            workspace_failure_disposition(
                code,
                self.stage,
                self.category,
                subtype=self.subtype,
                timeout_origin=self.timeout_origin,
                stage_validated=self.stage_validated,
                termination_verified=self.termination_verified,
                cleanup_verified=self.cleanup_verified,
                zero_census_verified=self.zero_census_verified,
            )
            == "diagnostic_failed_continue"
        )


@dataclass(frozen=True)
class WorkspaceFailureV4(WorkspaceFailureV3):
    reason: SnapshotFailureReasonV1 = SnapshotFailureReasonV1.NOT_APPLICABLE
    observed_byte_length: int | None = None
    observed_sha256: str | None = None
    execution_binding_verified: bool = False

    def continuable(self, code: str) -> bool:
        return (
            self.reason is not SnapshotFailureReasonV1.UNKNOWN
            and workspace_failure_disposition(
                code,
                self.stage,
                self.category,
                subtype=self.subtype,
                timeout_origin=self.timeout_origin,
                reason=self.reason,
                stage_validated=self.stage_validated,
                termination_verified=self.termination_verified,
                cleanup_verified=self.cleanup_verified,
                zero_census_verified=self.zero_census_verified,
                execution_binding_verified=self.execution_binding_verified,
            )
            == "diagnostic_failed_continue"
        )


class WorkspaceSnapshotError(RuntimeError):
    """A stable, non-secret snapshot failure."""

    def __init__(
        self,
        code: str,
        *,
        stage: str | None = None,
        category: str | None = None,
        errno: int | None = None,
        return_code: int | None = None,
        attempt: int = 1,
        transient: bool = False,
        subtype: SnapshotFailureSubtypeV1 = SnapshotFailureSubtypeV1.UNKNOWN_INTERNAL,
        timeout_origin: SnapshotTimeoutOriginV1 = SnapshotTimeoutOriginV1.NOT_A_TIMEOUT,
        stage_validated: bool = False,
        termination_verified: bool = False,
        cleanup_verified: bool = False,
        zero_census_verified: bool = False,
        execution_binding_verified: bool = False,
        reason: SnapshotFailureReasonV1 = SnapshotFailureReasonV1.NOT_APPLICABLE,
        observed_byte_length: int | None = None,
        observed_sha256: str | None = None,
        failure: WorkspaceFailureV4 | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        try:
            selected_subtype = SnapshotFailureSubtypeV1(subtype)
            selected_timeout_origin = SnapshotTimeoutOriginV1(timeout_origin)
        except (TypeError, ValueError):
            selected_subtype = SnapshotFailureSubtypeV1.UNKNOWN_INTERNAL
            selected_timeout_origin = SnapshotTimeoutOriginV1.NOT_A_TIMEOUT
        try:
            selected_reason = SnapshotFailureReasonV1(reason)
        except (TypeError, ValueError):
            selected_reason = SnapshotFailureReasonV1.UNKNOWN
        valid_observation = bool(
            type(observed_byte_length) is int
            and observed_byte_length >= 0
            and observed_byte_length <= SNAPSHOT_OUTPUT_CAP_BYTES
            and isinstance(observed_sha256, str)
            and len(observed_sha256) == 64
            and all(character in "0123456789abcdef" for character in observed_sha256)
        )
        self.failure = failure or WorkspaceFailureV4(
            stage=stage,
            category=category,
            errno=errno if type(errno) is int else None,
            return_code=return_code if type(return_code) is int else None,
            attempt=attempt if attempt in {1, 2} else 1,
            transient=transient is True,
            subtype=selected_subtype,
            timeout_origin=selected_timeout_origin,
            stage_validated=stage_validated is True,
            termination_verified=termination_verified is True,
            cleanup_verified=cleanup_verified is True,
            zero_census_verified=zero_census_verified is True,
            execution_binding_verified=execution_binding_verified is True,
            reason=selected_reason,
            observed_byte_length=(observed_byte_length if valid_observation else None),
            observed_sha256=observed_sha256 if valid_observation else None,
        )


def _typed_failure(
    error: BaseException,
    *,
    code: str,
    stage: str,
    attempt: int,
) -> WorkspaceSnapshotError:
    if stage not in FAILURE_STAGES:
        stage = "target"
    existing = error if isinstance(error, WorkspaceSnapshotError) else None
    actor_evidence = getattr(error, "evidence", error)
    classification_error = error
    cause = error.__cause__
    if existing is None and isinstance(
        cause,
        TimeoutError | ConnectionError | OSError,
    ):
        classification_error = cause
    transient = False
    selected_stage = stage
    if existing is not None and existing.failure.stage in FAILURE_STAGES:
        selected_stage = str(existing.failure.stage)
    if existing is not None and existing.failure.category in FAILURE_CATEGORIES:
        category = str(existing.failure.category)
        transient = existing.failure.transient
    elif isinstance(classification_error, TimeoutError):
        category = "timeout"
        transient = True
    elif isinstance(classification_error, ConnectionError):
        category = "connection"
        transient = True
    elif isinstance(classification_error, OSError):
        category = "os_error"
        transient = classification_error.errno in _TRANSIENT_ERRNOS
    elif "archive" in getattr(existing, "code", "") or "inventory" in getattr(
        existing, "code", ""
    ):
        category = "parse"
    elif "publish" in getattr(existing, "code", "") or "existing_mismatch" in getattr(
        existing, "code", ""
    ):
        category = "publish"
    elif selected_stage in {"stage-parse", "inventory-parse", "archive-parse"}:
        category = "parse"
    else:
        category = "internal"
    selected_errno = getattr(classification_error, "errno", None)
    if existing is not None and existing.failure.errno is not None:
        selected_errno = existing.failure.errno
    try:
        subtype = SnapshotFailureSubtypeV1(getattr(actor_evidence, "subtype"))
    except (AttributeError, TypeError, ValueError):
        subtype = (
            existing.failure.subtype
            if existing is not None
            else SnapshotFailureSubtypeV1.UNKNOWN_INTERNAL
        )
    if subtype is SnapshotFailureSubtypeV1.UNKNOWN_INTERNAL:
        if selected_stage in {"inventory-download", "archive-download"}:
            subtype = SnapshotFailureSubtypeV1.OUTPUT_DOWNLOAD_FAILED
        elif selected_stage in {"inventory-parse", "archive-parse"}:
            subtype = SnapshotFailureSubtypeV1.HOST_EVIDENCE_PARSE_FAILED
        elif selected_stage == "cleanup":
            subtype = SnapshotFailureSubtypeV1.STAGE_CLEANUP_FAILED
    if (
        subtype is not SnapshotFailureSubtypeV1.WAIT_TRANSPORT_FAILED
        and classification_error is not error
        and isinstance(classification_error, TimeoutError)
        and getattr(actor_evidence, "timeout_origin", None)
        is SnapshotTimeoutOriginV1.NOT_A_TIMEOUT
    ):
        category = "transport"
    if (
        selected_stage == "remote-exec"
        and code == "workspace_snapshot_remote_exec_failed"
        and getattr(actor_evidence, "stage_validated", False) is not True
    ):
        subtype = SnapshotFailureSubtypeV1.OWNED_STAGE_SETUP_FAILED
    try:
        timeout_origin = SnapshotTimeoutOriginV1(
            getattr(actor_evidence, "timeout_origin")
        )
    except (AttributeError, TypeError, ValueError):
        timeout_origin = (
            existing.failure.timeout_origin
            if existing is not None
            else (
                SnapshotTimeoutOriginV1.WAIT_TRANSPORT_TIMED_OUT_UNRECOVERED
                if isinstance(error, TimeoutError)
                else SnapshotTimeoutOriginV1.NOT_A_TIMEOUT
            )
        )
    if (
        category == "timeout"
        and timeout_origin is SnapshotTimeoutOriginV1.NOT_A_TIMEOUT
    ):
        timeout_origin = SnapshotTimeoutOriginV1.WAIT_TRANSPORT_TIMED_OUT_UNRECOVERED
    try:
        reason = SnapshotFailureReasonV1(getattr(actor_evidence, "reason"))
    except (AttributeError, TypeError, ValueError):
        reason = (
            existing.failure.reason
            if existing is not None
            else SnapshotFailureReasonV1.NOT_APPLICABLE
        )
    observed_byte_length = getattr(actor_evidence, "observed_byte_length", None)
    observed_sha256 = getattr(actor_evidence, "observed_sha256", None)
    return WorkspaceSnapshotError(
        code,
        stage=selected_stage,
        category=category,
        errno=selected_errno,
        return_code=(
            existing.failure.return_code
            if existing is not None
            else getattr(error, "return_code", None)
        ),
        attempt=(
            existing.failure.attempt
            if existing is not None and existing.failure.stage in FAILURE_STAGES
            else attempt
        ),
        transient=transient,
        subtype=subtype,
        timeout_origin=timeout_origin,
        stage_validated=(
            existing.failure.stage_validated
            if existing is not None
            else getattr(actor_evidence, "stage_validated", False) is True
        ),
        termination_verified=(
            existing.failure.termination_verified
            if existing is not None
            else getattr(actor_evidence, "termination_verified", False) is True
        ),
        cleanup_verified=(
            existing.failure.cleanup_verified
            if existing is not None
            else getattr(actor_evidence, "cleanup_verified", False) is True
        ),
        zero_census_verified=(
            existing.failure.zero_census_verified
            if existing is not None
            else getattr(actor_evidence, "zero_census_verified", False) is True
        ),
        execution_binding_verified=(
            existing.failure.execution_binding_verified
            if existing is not None
            else (
                getattr(
                    actor_evidence,
                    "execution_binding_verified",
                    False,
                )
                is True
            )
        ),
        reason=reason,
        observed_byte_length=(
            existing.failure.observed_byte_length
            if existing is not None
            else observed_byte_length
        ),
        observed_sha256=(
            existing.failure.observed_sha256
            if existing is not None
            else observed_sha256
        ),
    )


def _with_failure_evidence(
    error: WorkspaceSnapshotError,
    *,
    stage_validated: bool | None = None,
    termination_verified: bool | None = None,
    cleanup_verified: bool | None = None,
    zero_census_verified: bool | None = None,
    subtype: SnapshotFailureSubtypeV1 | None = None,
    stage: str | None = None,
    category: str | None = None,
) -> WorkspaceSnapshotError:
    """Return a new error; proof-bearing failures are never mutated in place."""

    failure = error.failure
    return WorkspaceSnapshotError(
        error.code,
        failure=replace(
            failure,
            stage=stage if stage is not None else failure.stage,
            category=category if category is not None else failure.category,
            subtype=subtype if subtype is not None else failure.subtype,
            stage_validated=(
                failure.stage_validated
                if stage_validated is None
                else stage_validated is True
            ),
            termination_verified=(
                failure.termination_verified
                if termination_verified is None
                else termination_verified is True
            ),
            cleanup_verified=(
                failure.cleanup_verified
                if cleanup_verified is None
                else cleanup_verified is True
            ),
            zero_census_verified=(
                failure.zero_census_verified
                if zero_census_verified is None
                else zero_census_verified is True
            ),
        ),
    )


def _cancelled_failure(
    error: asyncio.CancelledError,
    *,
    code: str,
    fallback_stage: str,
) -> WorkspaceSnapshotError:
    actor_evidence = getattr(error, "evidence", error)
    try:
        subtype = SnapshotFailureSubtypeV1(getattr(actor_evidence, "subtype"))
    except (AttributeError, TypeError, ValueError):
        subtype = SnapshotFailureSubtypeV1.UNKNOWN_INTERNAL
    try:
        timeout_origin = SnapshotTimeoutOriginV1(
            getattr(actor_evidence, "timeout_origin")
        )
    except (AttributeError, TypeError, ValueError):
        timeout_origin = SnapshotTimeoutOriginV1.NOT_A_TIMEOUT
        subtype = SnapshotFailureSubtypeV1.UNKNOWN_INTERNAL
    try:
        reason = SnapshotFailureReasonV1(getattr(actor_evidence, "reason"))
    except (AttributeError, TypeError, ValueError):
        reason = SnapshotFailureReasonV1.NOT_APPLICABLE
    return WorkspaceSnapshotError(
        code,
        stage=(
            "remote-exec"
            if subtype is not SnapshotFailureSubtypeV1.UNKNOWN_INTERNAL
            else fallback_stage
        ),
        category="cancelled",
        subtype=subtype,
        timeout_origin=timeout_origin,
        stage_validated=getattr(actor_evidence, "stage_validated", False) is True,
        termination_verified=(
            getattr(actor_evidence, "termination_verified", False) is True
        ),
        cleanup_verified=getattr(actor_evidence, "cleanup_verified", False) is True,
        zero_census_verified=(
            getattr(actor_evidence, "zero_census_verified", False) is True
        ),
        execution_binding_verified=(
            getattr(
                actor_evidence,
                "execution_binding_verified",
                False,
            )
            is True
        ),
        reason=reason,
        observed_byte_length=getattr(actor_evidence, "observed_byte_length", None),
        observed_sha256=getattr(actor_evidence, "observed_sha256", None),
    )


@dataclass(frozen=True)
class SnapshotPolicy:
    """Versioned resource and disclosure limits for one workspace capture."""

    max_files: int = 10_000
    max_total_bytes: int = 64 * 1024 * 1024
    max_file_bytes: int = 8 * 1024 * 1024
    max_patch_bytes: int = 8 * 1024 * 1024
    version: str = SNAPSHOT_POLICY_VERSION

    def __post_init__(self) -> None:
        values = (
            self.max_files,
            self.max_total_bytes,
            self.max_file_bytes,
            self.max_patch_bytes,
        )
        if (
            self.version != SNAPSHOT_POLICY_VERSION
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value <= 0
                for value in values
            )
            or self.max_file_bytes > self.max_total_bytes
        ):
            raise ValueError("workspace_snapshot_policy_invalid")

    def as_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "max_files": self.max_files,
            "max_total_bytes": self.max_total_bytes,
            "max_file_bytes": self.max_file_bytes,
            "max_patch_bytes": self.max_patch_bytes,
            "excluded_names": sorted(_EXCLUDED_NAMES),
            "sensitive_rules_version": SENSITIVE_RULES_VERSION,
        }


@dataclass(frozen=True)
class SnapshotTarget:
    """Bind an actor transport to the host-side artifact directory."""

    actor: object
    artifact_dir: Path
    publication_dir: Path | None = None


class WorkspaceBaselineStateV1(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class BeforeSnapshot:
    """Private pre-agent state used to compute the post-agent delta."""

    target: SnapshotTarget
    policy: SnapshotPolicy
    manifest: Mapping[str, Any] | None
    safe_contents: Mapping[str, bytes]
    content_omissions: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    baseline_state: WorkspaceBaselineStateV1 = WorkspaceBaselineStateV1.AVAILABLE
    status: str = "complete"
    code: str = "completed"
    failure: WorkspaceFailureV4 | None = None
    receipt_sha256: str = ""

    @property
    def continuable(self) -> bool:
        return self.failure is not None and self.failure.continuable(self.code)


@dataclass(frozen=True)
class SnapshotReceipt:
    """Canonical receipt returned to Harbor for marker binding."""

    status: str
    code: str
    truncated: bool
    omitted_count: int
    schema_version: str = RECEIPT_SCHEMA
    baseline_state: WorkspaceBaselineStateV1 = WorkspaceBaselineStateV1.AVAILABLE
    artifact_hashes: Mapping[str, str] = field(default_factory=dict)
    artifact_byte_lengths: Mapping[str, int] = field(default_factory=dict)
    canonical_sha256: str = ""
    failure: WorkspaceFailureV4 | None = None

    @property
    def continuable(self) -> bool:
        return self.failure is not None and self.failure.continuable(self.code)


@dataclass(frozen=True)
class _Inventory:
    manifest: Mapping[str, Any]
    entries: Mapping[str, Mapping[str, Any]]
    safe_contents: Mapping[str, bytes]
    content_omissions: Mapping[str, Mapping[str, Any]]
    stage_validated: bool = False
    termination_verified: bool = False
    cleanup_verified: bool = False
    zero_census_verified: bool = False


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


_WORKSPACE_RECEIPT_MAX_BYTES = 1024 * 1024
_WORKSPACE_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "code",
        "policy",
        "truncated",
        "omitted_count",
        "artifacts",
    }
)
_WORKSPACE_ARTIFACT_NAMES = frozenset(
    {
        "workspace-before.json",
        "workspace-after.json",
        "workspace-delta.json",
        "workspace-diff.patch",
        "workspace-changed.tar",
    }
)
_WORKSPACE_POLICY_KEYS = frozenset(
    {
        "version",
        "max_files",
        "max_total_bytes",
        "max_file_bytes",
        "max_patch_bytes",
        "excluded_names",
        "sensitive_rules_version",
    }
)
_WORKSPACE_FAILURE_V2_KEYS = frozenset(
    {"stage", "category", "errno", "return_code", "attempt"}
)
_WORKSPACE_FAILURE_V3_KEYS = frozenset(
    {
        *_WORKSPACE_FAILURE_V2_KEYS,
        "subtype",
        "timeout_origin",
        "stage_validated",
        "termination_verified",
        "cleanup_verified",
        "zero_census_verified",
    }
)
_WORKSPACE_FAILURE_V5_KEYS = frozenset(
    {
        *_WORKSPACE_FAILURE_V3_KEYS,
        "reason",
        "execution_binding_verified",
    }
)


class _DuplicateWorkspaceReceiptKey(ValueError):
    pass


def _workspace_receipt_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateWorkspaceReceiptKey
        value[key] = item
    return value


def _workspace_receipt_invalid_constant(_: str) -> object:
    raise ValueError


def _workspace_policy_valid(value: object, *, complete: bool) -> bool:
    if type(value) is not dict or value.get("version") != SNAPSHOT_POLICY_VERSION:
        return False
    if not complete and set(value) == {"version"}:
        return True
    if set(value) != _WORKSPACE_POLICY_KEYS:
        return False
    limits = tuple(
        value.get(field)
        for field in (
            "max_files",
            "max_total_bytes",
            "max_file_bytes",
            "max_patch_bytes",
        )
    )
    excluded = value.get("excluded_names")
    return bool(
        all(type(limit) is int and limit > 0 for limit in limits)
        and limits[2] <= limits[1]
        and type(excluded) is list
        and all(type(name) is str and name for name in excluded)
        and excluded == sorted(set(excluded))
        and type(value.get("sensitive_rules_version")) is str
        and value["sensitive_rules_version"]
    )


def _workspace_failure_common_valid(value: object) -> bool:
    if type(value) is not dict:
        return False
    return bool(
        value.get("stage") in FAILURE_STAGES
        and value.get("category") in FAILURE_CATEGORIES
        and type(value.get("attempt")) is int
        and value["attempt"] in {1, 2}
        and all(
            item is None or type(item) is int
            for item in (value.get("errno"), value.get("return_code"))
        )
        and not (
            value.get("errno") is not None and value.get("return_code") is not None
        )
    )


def _workspace_failure_proofs_valid(
    value: Mapping[str, object],
    subtype: SnapshotFailureSubtypeV1,
    timeout_origin: SnapshotTimeoutOriginV1,
) -> bool:
    proofs = tuple(
        value.get(field)
        for field in (
            "stage_validated",
            "termination_verified",
            "cleanup_verified",
            "zero_census_verified",
        )
    )
    execution_binding_verified = value.get(
        "execution_binding_verified",
        False,
    )
    return bool(
        all(type(proof) is bool for proof in proofs)
        and type(execution_binding_verified) is bool
        and not (any(proofs[1:]) and proofs[0] is not True)
        and not ((proofs[2] or proofs[3]) and proofs[1] is not True)
        and not (
            execution_binding_verified and not (proofs[0] and proofs[1] and proofs[3])
        )
        and not (
            timeout_origin is SnapshotTimeoutOriginV1.NOT_A_TIMEOUT
            and value.get("category") == "timeout"
        )
        and not (
            timeout_origin is not SnapshotTimeoutOriginV1.NOT_A_TIMEOUT
            and value.get("category") != "timeout"
        )
        and not (
            timeout_origin
            in {
                SnapshotTimeoutOriginV1.SEMANTIC_EXECUTION_TIMED_OUT,
                SnapshotTimeoutOriginV1.WAIT_TRANSPORT_TIMED_OUT_RECOVERED,
            }
            and subtype is not SnapshotFailureSubtypeV1.WAIT_TRANSPORT_FAILED
        )
        and not (
            subtype is SnapshotFailureSubtypeV1.HOST_EVIDENCE_MATERIALIZATION_FAILED
            and (
                value.get("stage") != "host-evidence"
                or value.get("category") != "evidence"
                or timeout_origin is not SnapshotTimeoutOriginV1.NOT_A_TIMEOUT
                or proofs != (True, True, True, True)
            )
        )
    )


def _parsed_workspace_failure(
    value: object,
    *,
    schema_version: str,
) -> WorkspaceFailureV4:
    if not _workspace_failure_common_valid(value):
        raise WorkspaceSnapshotError("workspace_receipt_invalid")
    assert isinstance(value, dict)
    if schema_version == LEGACY_FAILURE_RECEIPT_SCHEMA:
        if set(value) != _WORKSPACE_FAILURE_V2_KEYS:
            raise WorkspaceSnapshotError("workspace_receipt_invalid")
        return WorkspaceFailureV4(
            stage=str(value["stage"]),
            category=str(value["category"]),
            errno=value["errno"] if type(value["errno"]) is int else None,
            return_code=(
                value["return_code"] if type(value["return_code"]) is int else None
            ),
            attempt=int(value["attempt"]),
            reason=SnapshotFailureReasonV1.NOT_APPLICABLE,
        )

    observed_keys = {"observed_byte_length", "observed_sha256"}
    expected_keys = set(_WORKSPACE_FAILURE_V3_KEYS)
    if schema_version in {
        FAILURE_RECEIPT_SCHEMA_V4,
        FAILURE_RECEIPT_SCHEMA_V5,
    }:
        expected_keys.add("reason")
        if observed_keys <= set(value):
            expected_keys |= observed_keys
    if schema_version == FAILURE_RECEIPT_SCHEMA_V5:
        expected_keys = set(_WORKSPACE_FAILURE_V5_KEYS)
        if observed_keys <= set(value):
            expected_keys |= observed_keys
    if set(value) != expected_keys:
        raise WorkspaceSnapshotError("workspace_receipt_invalid")
    try:
        subtype = SnapshotFailureSubtypeV1(value["subtype"])
        timeout_origin = SnapshotTimeoutOriginV1(value["timeout_origin"])
        reason = (
            SnapshotFailureReasonV1(value["reason"])
            if schema_version
            in {
                FAILURE_RECEIPT_SCHEMA_V4,
                FAILURE_RECEIPT_SCHEMA_V5,
            }
            else SnapshotFailureReasonV1.NOT_APPLICABLE
        )
    except (TypeError, ValueError):
        raise WorkspaceSnapshotError("workspace_receipt_invalid") from None
    if not _workspace_failure_proofs_valid(value, subtype, timeout_origin):
        raise WorkspaceSnapshotError("workspace_receipt_invalid")

    observed_byte_length = value.get("observed_byte_length")
    observed_sha256 = value.get("observed_sha256")
    no_observation = observed_byte_length is None and observed_sha256 is None
    valid_observation = bool(
        type(observed_byte_length) is int
        and observed_byte_length >= 0
        and observed_byte_length <= SNAPSHOT_OUTPUT_CAP_BYTES
        and type(observed_sha256) is str
        and len(observed_sha256) == 64
        and all(character in "0123456789abcdef" for character in observed_sha256)
    )
    wrong_type_reasons = {
        SnapshotFailureReasonV1.OUTER_RETURN_CODE_TYPE_INVALID,
        SnapshotFailureReasonV1.OUTER_STDOUT_TYPE_INVALID,
        SnapshotFailureReasonV1.OUTER_STDERR_TYPE_INVALID,
        SnapshotFailureReasonV1.NOT_APPLICABLE,
        SnapshotFailureReasonV1.UNKNOWN,
    }
    if (
        schema_version
        in {
            FAILURE_RECEIPT_SCHEMA_V4,
            FAILURE_RECEIPT_SCHEMA_V5,
        }
        and not (no_observation or valid_observation)
    ) or (reason in wrong_type_reasons and not no_observation):
        raise WorkspaceSnapshotError("workspace_receipt_invalid")
    proofs = {
        field: bool(value[field])
        for field in (
            "stage_validated",
            "termination_verified",
            "cleanup_verified",
            "zero_census_verified",
        )
    }
    proofs["execution_binding_verified"] = (
        value["execution_binding_verified"]
        if schema_version == FAILURE_RECEIPT_SCHEMA_V5
        else False
    )
    return WorkspaceFailureV4(
        stage=str(value["stage"]),
        category=str(value["category"]),
        errno=value["errno"] if type(value["errno"]) is int else None,
        return_code=(
            value["return_code"] if type(value["return_code"]) is int else None
        ),
        attempt=int(value["attempt"]),
        subtype=subtype,
        timeout_origin=timeout_origin,
        reason=reason,
        observed_byte_length=observed_byte_length if valid_observation else None,
        observed_sha256=observed_sha256 if valid_observation else None,
        **proofs,
    )


def parse_workspace_receipt_bytes(payload: bytes) -> SnapshotReceipt:
    """Parse canonical workspace receipt bytes without reading any other state."""

    if type(payload) is not bytes or len(payload) > _WORKSPACE_RECEIPT_MAX_BYTES:
        raise WorkspaceSnapshotError("workspace_receipt_invalid")
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_workspace_receipt_object,
            parse_constant=_workspace_receipt_invalid_constant,
        )
    except (
        TypeError,
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateWorkspaceReceiptKey,
        RecursionError,
    ):
        raise WorkspaceSnapshotError("workspace_receipt_invalid") from None
    try:
        canonical_payload = canonical_json(value)
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        raise WorkspaceSnapshotError("workspace_receipt_invalid") from None
    if type(value) is not dict or payload != canonical_payload:
        raise WorkspaceSnapshotError("workspace_receipt_invalid")
    schema_version = value.get("schema_version")
    if schema_version not in {
        RECEIPT_SCHEMA,
        LEGACY_FAILURE_RECEIPT_SCHEMA,
        FAILURE_RECEIPT_SCHEMA,
        FAILURE_RECEIPT_SCHEMA_V4,
        FAILURE_RECEIPT_SCHEMA_V5,
    }:
        raise WorkspaceSnapshotError("workspace_receipt_invalid")
    expected_top_keys = set(_WORKSPACE_RECEIPT_KEYS)
    if schema_version != RECEIPT_SCHEMA:
        expected_top_keys.add("failure")
    if schema_version in {
        FAILURE_RECEIPT_SCHEMA_V4,
        FAILURE_RECEIPT_SCHEMA_V5,
    }:
        expected_top_keys.add("baseline_state")
    if (
        set(value) != expected_top_keys
        or type(value.get("status")) is not str
        or type(value.get("code")) is not str
        or not value["code"]
        or type(value.get("truncated")) is not bool
        or type(value.get("omitted_count")) is not int
        or value["omitted_count"] < 0
        or type(value.get("artifacts")) is not dict
    ):
        raise WorkspaceSnapshotError("workspace_receipt_invalid")
    complete = schema_version == RECEIPT_SCHEMA
    if not _workspace_policy_valid(value.get("policy"), complete=complete):
        raise WorkspaceSnapshotError("workspace_receipt_invalid")
    artifacts = value["artifacts"]
    artifact_hashes: dict[str, str] = {}
    artifact_byte_lengths: dict[str, int] = {}
    if complete:
        if (
            value["status"] != "complete"
            or value["code"] != "completed"
            or set(artifacts) != _WORKSPACE_ARTIFACT_NAMES
        ):
            raise WorkspaceSnapshotError("workspace_receipt_invalid")
        for name in sorted(_WORKSPACE_ARTIFACT_NAMES):
            row = artifacts.get(name)
            if (
                type(row) is not dict
                or set(row) != {"byte_length", "sha256"}
                or type(row.get("byte_length")) is not int
                or row["byte_length"] < 0
                or type(row.get("sha256")) is not str
                or len(row["sha256"]) != 64
                or any(
                    character not in "0123456789abcdef" for character in row["sha256"]
                )
            ):
                raise WorkspaceSnapshotError("workspace_receipt_invalid")
            artifact_hashes[name] = row["sha256"]
            artifact_byte_lengths[name] = row["byte_length"]
        baseline_state = WorkspaceBaselineStateV1.AVAILABLE
        failure = None
    else:
        if (
            value["status"] != "failed"
            or value["code"] == "completed"
            or value["truncated"] is not False
            or value["omitted_count"] != 0
            or artifacts
        ):
            raise WorkspaceSnapshotError("workspace_receipt_invalid")
        failure = _parsed_workspace_failure(
            value["failure"],
            schema_version=str(schema_version),
        )
        inferred_baseline = (
            WorkspaceBaselineStateV1.UNAVAILABLE
            if value["code"].startswith("workspace_before_")
            else WorkspaceBaselineStateV1.AVAILABLE
        )
        if schema_version in {
            FAILURE_RECEIPT_SCHEMA_V4,
            FAILURE_RECEIPT_SCHEMA_V5,
        }:
            try:
                baseline_state = WorkspaceBaselineStateV1(value["baseline_state"])
            except (TypeError, ValueError):
                raise WorkspaceSnapshotError("workspace_receipt_invalid") from None
            if baseline_state is not inferred_baseline:
                raise WorkspaceSnapshotError("workspace_receipt_invalid")
        else:
            baseline_state = inferred_baseline
    return SnapshotReceipt(
        status=str(value["status"]),
        code=str(value["code"]),
        truncated=bool(value["truncated"]),
        omitted_count=int(value["omitted_count"]),
        schema_version=str(schema_version),
        baseline_state=baseline_state,
        artifact_hashes=artifact_hashes,
        artifact_byte_lengths=artifact_byte_lengths,
        canonical_sha256=_sha256(payload),
        failure=failure,
    )


def load_workspace_receipt(path: Path) -> SnapshotReceipt:
    """Read one bounded regular receipt through a single no-follow descriptor."""

    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 0
            or before.st_size > _WORKSPACE_RECEIPT_MAX_BYTES
        ):
            raise WorkspaceSnapshotError("workspace_receipt_invalid")
        payload = bytearray()
        while True:
            remaining = _WORKSPACE_RECEIPT_MAX_BYTES + 1 - len(payload)
            if remaining <= 0:
                raise WorkspaceSnapshotError("workspace_receipt_invalid")
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > _WORKSPACE_RECEIPT_MAX_BYTES:
                raise WorkspaceSnapshotError("workspace_receipt_invalid")
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity or after.st_size != len(payload):
            raise WorkspaceSnapshotError("workspace_receipt_invalid")
    except OSError:
        raise WorkspaceSnapshotError("workspace_receipt_invalid") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return parse_workspace_receipt_bytes(bytes(payload))


def _target(value: object) -> SnapshotTarget:
    if isinstance(value, SnapshotTarget):
        target = value
    else:
        artifacts = getattr(value, "artifacts", None)
        if not isinstance(artifacts, Path):
            raise WorkspaceSnapshotError("workspace_snapshot_target_invalid")
        target = SnapshotTarget(actor=value, artifact_dir=artifacts)
    artifact_dir = target.artifact_dir.resolve()
    if (
        target.artifact_dir.is_symlink()
        or not artifact_dir.is_absolute()
        or not artifact_dir.is_dir()
    ):
        raise WorkspaceSnapshotError("workspace_snapshot_artifact_dir_invalid")
    publication_dir: Path | None = None
    if target.publication_dir is not None:
        publication_dir = target.publication_dir.resolve()
        if (
            target.publication_dir.is_symlink()
            or not publication_dir.is_absolute()
            or not publication_dir.is_dir()
            or publication_dir == artifact_dir
        ):
            raise WorkspaceSnapshotError("workspace_snapshot_publication_dir_invalid")
    return SnapshotTarget(
        actor=target.actor,
        artifact_dir=artifact_dir,
        publication_dir=publication_dir,
    )


def _local_workspace(actor: object) -> Path:
    workspace = getattr(actor, "workspace", None)
    if not isinstance(workspace, Path):
        raise WorkspaceSnapshotError("workspace_snapshot_transport_unavailable")
    resolved = workspace.resolve()
    if workspace.is_symlink() or not resolved.is_absolute() or not resolved.is_dir():
        raise WorkspaceSnapshotError("workspace_snapshot_root_invalid")
    return resolved


def _mode(metadata: os.stat_result) -> str:
    return f"{stat.S_IMODE(metadata.st_mode):04o}"


def _sort_key(path: str) -> bytes:
    return path.encode("utf-8", "surrogateescape")


def _safe_relative(path: Path, root: Path) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise WorkspaceSnapshotError("workspace_snapshot_path_escape") from error
    value = relative.as_posix()
    parsed = PurePosixPath(value)
    if (
        not value
        or value.startswith("/")
        or "\x00" in value
        or any(part in {"", ".", ".."} for part in parsed.parts)
    ):
        raise WorkspaceSnapshotError("workspace_snapshot_path_invalid")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise WorkspaceSnapshotError(
            "workspace_snapshot_path_encoding_invalid"
        ) from error
    return value


def _read_exact_regular(path: Path, metadata: os.stat_result) -> bytes:
    """Read one planned regular file without following a replacement link."""

    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_dev != metadata.st_dev
            or observed.st_ino != metadata.st_ino
            or observed.st_size != metadata.st_size
            or stat.S_IMODE(observed.st_mode) != stat.S_IMODE(metadata.st_mode)
        ):
            raise WorkspaceSnapshotError("workspace_snapshot_file_identity_changed")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            payload = handle.read(metadata.st_size + 1)
            after = os.fstat(handle.fileno())
        if len(payload) != metadata.st_size:
            raise WorkspaceSnapshotError("workspace_snapshot_file_size_changed")
        if (
            after.st_dev != metadata.st_dev
            or after.st_ino != metadata.st_ino
            or after.st_size != metadata.st_size
            or stat.S_IMODE(after.st_mode) != stat.S_IMODE(metadata.st_mode)
            or after.st_mtime_ns != metadata.st_mtime_ns
            or after.st_ctime_ns != metadata.st_ctime_ns
        ):
            raise WorkspaceSnapshotError("workspace_snapshot_file_identity_changed")
        return payload
    except OSError as error:
        raise WorkspaceSnapshotError(
            "workspace_snapshot_content_unavailable"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_regular_prefix(
    path: Path,
    metadata: os.stat_result,
    *,
    max_bytes: int = _SENSITIVE_SAMPLE_BYTES,
) -> bytes:
    """Read a bounded prefix without following a replacement link.

    Capped files are intentionally partial evidence. Reading their complete
    contents merely to retain a digest defeats the capture policy and can make
    snapshot time unbounded. The prefix is used only for the secret scan; the
    omission remains explicit and does not claim a whole-file hash.
    """

    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_dev != metadata.st_dev
            or observed.st_ino != metadata.st_ino
            or observed.st_size != metadata.st_size
            or stat.S_IMODE(observed.st_mode) != stat.S_IMODE(metadata.st_mode)
        ):
            raise WorkspaceSnapshotError("workspace_snapshot_file_identity_changed")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            prefix = handle.read(min(metadata.st_size, max_bytes) + 1)
            after = os.fstat(handle.fileno())
        if len(prefix) > min(metadata.st_size, max_bytes):
            raise WorkspaceSnapshotError("workspace_snapshot_file_size_changed")
        if (
            after.st_dev != metadata.st_dev
            or after.st_ino != metadata.st_ino
            or after.st_size != metadata.st_size
            or stat.S_IMODE(after.st_mode) != stat.S_IMODE(metadata.st_mode)
            or after.st_mtime_ns != metadata.st_mtime_ns
            or after.st_ctime_ns != metadata.st_ctime_ns
        ):
            raise WorkspaceSnapshotError("workspace_snapshot_file_identity_changed")
        return prefix
    except OSError as error:
        raise WorkspaceSnapshotError(
            "workspace_snapshot_content_unavailable"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _sensitive_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return any(
        part.casefold() in _SENSITIVE_NAMES
        or part.casefold().startswith(".env.")
        or _SENSITIVE_PATH.search(part) is not None
        for part in parts
    )


def _sensitive_content(payload: bytes) -> bool:
    return _SENSITIVE_CONTENT.search(payload[: 1024 * 1024]) is not None


def _binary(payload: bytes) -> bool:
    sample = payload[:8192]
    if b"\x00" in sample:
        return True
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def _excluded(path: str) -> bool:
    return any(part.casefold() in _EXCLUDED_NAMES for part in PurePosixPath(path).parts)


def _walk(
    root: Path,
    *,
    max_entries: int,
) -> tuple[list[tuple[Path, str]], bool, bool]:
    """Walk at most ``max_entries`` non-excluded entries.

    A globally sorted filesystem walk must consume the complete tree before it
    can emit its first row. That makes the nominal file cap ineffective. This
    walk sorts each bounded directory batch and records an explicit lower-bound
    omission when it cuts off; complete scans retain the prior deterministic
    ordering.
    """

    rows: list[tuple[Path, str]] = []
    scan_failed = False
    scan_truncated = False

    def visit(directory: Path) -> None:
        nonlocal scan_failed, scan_truncated
        if scan_truncated:
            return
        children: list[tuple[os.DirEntry[str], Path, str]] = []
        try:
            with os.scandir(directory) as iterator:
                for child in iterator:
                    path = Path(child.path)
                    try:
                        relative = _safe_relative(path, root)
                    except WorkspaceSnapshotError:
                        scan_failed = True
                        continue
                    if _excluded(relative):
                        continue
                    children.append((child, path, relative))
                    if len(rows) + len(children) >= max_entries:
                        scan_truncated = True
                        break
        except OSError:
            scan_failed = True
            return
        children.sort(key=lambda row: _sort_key(row[2]))
        batch_truncated = scan_truncated
        for child, path, relative in children:
            rows.append((path, relative))
            if _sensitive_path(relative):
                continue
            try:
                if not batch_truncated and child.is_dir(follow_symlinks=False):
                    visit(path)
            except OSError:
                scan_failed = True
            if not batch_truncated and scan_truncated:
                break

    visit(root)
    rows.sort(key=lambda row: _sort_key(row[1]))
    return rows, scan_failed, scan_truncated


def _git_metadata(root: Path) -> Mapping[str, object] | None:
    def run(arguments: list[str]) -> bytes | None:
        try:
            completed = subprocess.run(
                ["git", "-C", str(root), *arguments],
                check=False,
                capture_output=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return completed.stdout if completed.returncode == 0 else None

    inside = run(["rev-parse", "--is-inside-work-tree"])
    if inside is None or inside.strip() != b"true":
        return None
    head_raw = run(["rev-parse", "--verify", "HEAD"])
    index_raw = run(["ls-files", "-s", "-z"])
    status_raw = run(["status", "--porcelain=v2", "-z", "--untracked-files=all"])
    if index_raw is None or status_raw is None:
        raise WorkspaceSnapshotError("workspace_snapshot_git_metadata_failed")
    head = head_raw.strip().decode("ascii") if head_raw is not None else None
    return {
        "head": head,
        "index_tree": _sha256(index_raw),
        "status_porcelain_v2_z_sha256": _sha256(status_raw),
    }


def _inventory(root: Path, policy: SnapshotPolicy) -> _Inventory:
    rows, scan_failed, scan_truncated = _walk(
        root,
        max_entries=policy.max_files + 1,
    )
    entries: dict[str, Mapping[str, Any]] = {}
    safe_contents: dict[str, bytes] = {}
    omissions: dict[str, Mapping[str, Any]] = {}
    captured_bytes = 0
    selected_rows = rows[: policy.max_files]
    capped_omitted = len(rows) - len(selected_rows)
    if capped_omitted:
        omissions[""] = {
            "path": "",
            "reason": "file_count_cap",
            "count": capped_omitted,
            **({"count_is_lower_bound": True} if scan_truncated else {}),
        }

    for path, relative in selected_rows:
        try:
            metadata = path.lstat()
        except OSError:
            omissions[relative] = {
                "path": relative,
                "reason": "metadata_unavailable",
            }
            continue
        common: dict[str, object] = {
            "path": relative,
            "mode": _mode(metadata),
        }
        if _sensitive_path(relative):
            omissions[relative] = {
                "path": relative,
                "reason": "sensitive_path",
            }
            continue
        if stat.S_ISDIR(metadata.st_mode):
            entry = {**common, "kind": "directory", "size": 0}
        elif stat.S_ISLNK(metadata.st_mode):
            try:
                target = os.readlink(path)
            except OSError:
                omissions[relative] = {
                    "path": relative,
                    "reason": "symlink_unavailable",
                }
                continue
            entry = {
                **common,
                "kind": "symlink",
                "size": len(os.fsencode(target)),
                "target": target,
            }
            if not _safe_symlink(relative, target):
                omissions[relative] = {
                    "path": relative,
                    "reason": "symlink_escape",
                }
        elif stat.S_ISREG(metadata.st_mode):
            entry = {
                **common,
                "kind": "file",
                "size": metadata.st_size,
            }
        else:
            entry = {
                **common,
                "kind": "special",
                "size": metadata.st_size,
            }
            omissions[relative] = {
                "path": relative,
                "reason": "special_file",
            }
        if entry["kind"] == "file":
            size = int(entry["size"])
            cap_reason = None
            if size > policy.max_file_bytes:
                cap_reason = "per_file_byte_cap"
            elif captured_bytes + size > policy.max_total_bytes:
                cap_reason = "total_byte_cap"
            try:
                if cap_reason is None:
                    payload = _read_exact_regular(path, metadata)
                    digest = _sha256(payload)
                    sample = payload
                else:
                    sample = _read_regular_prefix(path, metadata)
                    payload = None
            except WorkspaceSnapshotError:
                omissions[relative] = {
                    "path": relative,
                    "reason": "content_unavailable",
                }
                entries[relative] = entry
                continue
            if cap_reason is None:
                entry["sha256"] = digest
            if _sensitive_content(sample):
                omission = {
                    "path": relative,
                    "reason": "sensitive_content",
                }
                if "sha256" in entry:
                    omission["sha256"] = entry["sha256"]
                omissions[relative] = omission
            elif cap_reason is not None:
                omissions[relative] = {
                    "path": relative,
                    "reason": cap_reason,
                }
            else:
                assert payload is not None
                safe_contents[relative] = payload
                captured_bytes += len(payload)
        entries[relative] = entry

    ordered_entries = [entries[path] for path in sorted(entries, key=_sort_key)]
    git = _git_metadata(root)
    manifest: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA,
        "policy_version": policy.version,
        "entries": ordered_entries,
        "entry_count": len(ordered_entries),
        "scan_complete": not scan_failed and not scan_truncated and not capped_omitted,
    }
    if git is not None:
        manifest["git"] = git
    return _Inventory(
        manifest=manifest,
        entries=entries,
        safe_contents=safe_contents,
        content_omissions=omissions,
    )


def _remote_stage_script() -> str:
    return f"""set -u
umask 077
stage=$(mktemp -d {_REMOTE_STAGE_PREFIX}XXXXXXXX) || exit 71
printf '%s\\n' "$stage"
"""


def _remote_script(root: str, policy: SnapshotPolicy, stage: str) -> str:
    excluded = " -o ".join(
        f"-iname {shlex.quote(name)}" for name in sorted(_EXCLUDED_NAMES)
    )
    return f"""set -u
umask 077
root={shlex.quote(root)}
stage={shlex.quote(stage)}
test -d "$root" || exit 70
test -d "$stage" || exit 71
command -v timeout >/dev/null 2>&1 || exit 76
root=$(realpath -m -- "$root") || exit 70
inventory="$stage/inventory.tsv"
selected="$stage/selected.bin"
paths="$stage/paths.bin"
: > "$inventory"
: > "$selected"
if timeout -k 1s {_REMOTE_GIT_COMMAND_TIMEOUT_SEC}s \
  git -C "$root" rev-parse --is-inside-work-tree \
  > "$stage/git-inside.txt" 2>/dev/null &&
  grep -qx true "$stage/git-inside.txt"; then
  git_complete=1
  head=$(timeout -k 1s {_REMOTE_GIT_COMMAND_TIMEOUT_SEC}s \
    git -C "$root" rev-parse --verify HEAD 2>/dev/null || true)
  timeout -k 1s {_REMOTE_GIT_COMMAND_TIMEOUT_SEC}s \
    git -C "$root" ls-files -s -z > "$stage/index.bin" 2>/dev/null ||
    git_complete=0
  timeout -k 1s {_REMOTE_GIT_COMMAND_TIMEOUT_SEC}s \
    git -C "$root" status --porcelain=v2 -z --untracked-files=all \
    > "$stage/status.bin" 2>/dev/null || git_complete=0
  if [ "$git_complete" -eq 1 ]; then
    index_hash=$(timeout -k 1s {_REMOTE_GIT_COMMAND_TIMEOUT_SEC}s \
      sha256sum "$stage/index.bin" 2>/dev/null | awk '{{print $1}}')
    status_hash=$(timeout -k 1s {_REMOTE_GIT_COMMAND_TIMEOUT_SEC}s \
      sha256sum "$stage/status.bin" 2>/dev/null | awk '{{print $1}}')
    if [ -n "$index_hash" ] && [ -n "$status_hash" ]; then
      printf 'G\\thead\\t%s\\n' "$head" >> "$inventory"
      printf 'G\\tindex_tree\\t%s\\n' "$index_hash" >> "$inventory"
      printf 'G\\tstatus_porcelain_v2_z_sha256\\t%s\\n' \
        "$status_hash" >> "$inventory"
    else
      printf 'C\\tgit_metadata_unavailable\\n' >> "$inventory"
    fi
  else
    printf 'C\\tgit_metadata_unavailable\\n' >> "$inventory"
  fi
fi

timeout -k 1s {_REMOTE_SCAN_PHASE_TIMEOUT_SEC}s \
  find "$root" \
    \\( \\( {excluded} \\) -prune \\) -o \
    -mindepth 1 -print0 |
  head -z -n {policy.max_files + 1} > "$paths"
scan_status=${{PIPESTATUS[0]}}
if [ "$scan_status" -eq 124 ] || [ "$scan_status" -eq 137 ]; then
  printf 'C\\tinventory_scan_wall_budget\\n' >> "$inventory"
elif [ "$scan_status" -ne 0 ] && [ "$scan_status" -ne 141 ]; then
  printf 'C\\tinventory_scan_unavailable\\n' >> "$inventory"
fi

count=0
included_bytes=0
count_omitted=0
content_cutoff=$(( $(date +%s) + {_REMOTE_CONTENT_PHASE_TIMEOUT_SEC} ))
while IFS= read -r -d '' path; do
  if [ "$(date +%s)" -ge "$content_cutoff" ]; then
    printf 'C\\tcontent_scan_wall_budget\\n' >> "$inventory"
    break
  fi
  rel=${{path#"$root"/}}
  count=$((count + 1))
  if [ "$count" -gt {policy.max_files} ]; then
    count_omitted=1
    break
  fi
  lower=$(printf '%s' "$rel" | tr '[:upper:]' '[:lower:]')
  case "/$lower/" in
    */.env/*|*/.env.*/*|*/.netrc/*|*/id_rsa/*|*/id_dsa/*|*/id_ecdsa/*|\
*/id_ed25519/*|*secret*|*credential*|*password*|*passwd*|*token*)
      path64=$(printf '%s' "$rel" | base64 | tr -d '\\n')
      printf 'S\\t%s\\n' "$path64" >> "$inventory"
      continue
      ;;
  esac
  path64=$(printf '%s' "$rel" | base64 | tr -d '\\n')
  metadata=$(timeout -k 1s {_REMOTE_FILE_OPERATION_TIMEOUT_SEC}s \
    stat -c '%a %s' -- "$path" 2>/dev/null) || {{
    printf 'E\\t%s\\tunknown\\t0000\\t0\\t\\tmetadata_unavailable\\n' \
      "$path64" >> "$inventory"
    continue
  }}
  mode=${{metadata%% *}}
  size=${{metadata#* }}
  kind=special
  detail=
  reason=
  if [ -L "$path" ]; then
    kind=symlink
    target=$(timeout -k 1s {_REMOTE_FILE_OPERATION_TIMEOUT_SEC}s \
      readlink -- "$path" 2>/dev/null) || {{
      reason=symlink_unavailable
      target=
    }}
    detail=$(printf '%s' "$target" | base64 | tr -d '\\n')
    if [ -z "$reason" ]; then
      case "$target" in
        /*) reason=symlink_escape ;;
        *)
          resolved=$(timeout -k 1s {_REMOTE_FILE_OPERATION_TIMEOUT_SEC}s \
            realpath -m -- "$(dirname -- "$path")/$target" 2>/dev/null) ||
            reason=symlink_unavailable
          if [ -z "$reason" ]; then
            case "$resolved" in
              "$root"|"$root"/*) ;;
              *) reason=symlink_escape ;;
            esac
          fi
          ;;
      esac
    fi
  elif [ -d "$path" ]; then
    kind=directory
  elif [ -f "$path" ]; then
    kind=file
  else
    reason=special_file
  fi
  if [ "$kind" = file ] && [ -z "$reason" ]; then
    if [ "$size" -gt {policy.max_file_bytes} ]; then
      reason=per_file_byte_cap
    elif [ $((included_bytes + size)) -gt {policy.max_total_bytes} ]; then
      reason=total_byte_cap
    fi
    if ! timeout -k 1s {_REMOTE_FILE_OPERATION_TIMEOUT_SEC}s \
      head -c {_SENSITIVE_SAMPLE_BYTES} -- "$path" \
      > "$stage/sample.bin" 2>/dev/null; then
      reason=content_unavailable
    elif tr '\\n' ' ' < "$stage/sample.bin" | LC_ALL=C grep -aEiq -- \
        {shlex.quote(_REMOTE_SENSITIVE_ERE)}; then
      reason=sensitive_content
    elif [ -z "$reason" ]; then
      detail=$(timeout -k 1s {_REMOTE_FILE_OPERATION_TIMEOUT_SEC}s \
        sha256sum "$path" 2>/dev/null | awk '{{print $1}}')
      if [ -z "$detail" ]; then
        reason=content_unavailable
      else
        printf '%s\\0' "$rel" >> "$selected"
        included_bytes=$((included_bytes + size))
      fi
    fi
  elif [ "$kind" = symlink ] && [ -z "$reason" ]; then
    printf '%s\\0' "$rel" >> "$selected"
  fi
  printf 'E\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \
    "$path64" "$kind" "$mode" "$size" "$detail" "$reason" >> "$inventory"
done < "$paths"
if [ "$count_omitted" -gt 0 ]; then
  printf 'C\\tfile_count_cap\\t%s\\tlower_bound\\n' \
    "$count_omitted" >> "$inventory"
fi
if [ -s "$selected" ]; then
  timeout -k 1s {_REMOTE_ARCHIVE_PHASE_TIMEOUT_SEC}s \
    tar -C "$root" --null --no-recursion -T "$selected" \
    -cf "$stage/safe.partial.tar" >/dev/null 2>&1
  archive_status=$?
  if [ "$archive_status" -eq 0 ]; then
    mv "$stage/safe.partial.tar" "$stage/safe.tar"
  else
    rm -f "$stage/safe.partial.tar"
    if [ "$archive_status" -eq 124 ] || [ "$archive_status" -eq 137 ]; then
      printf 'C\\tarchive_wall_budget\\n' >> "$inventory"
    else
      printf 'C\\tarchive_unavailable\\n' >> "$inventory"
    fi
    timeout -k 1s {_REMOTE_FILE_OPERATION_TIMEOUT_SEC}s \
      tar -C "$root" -T /dev/null -cf "$stage/safe.tar" \
      >/dev/null 2>&1 || exit 74
  fi
else
  timeout -k 1s {_REMOTE_FILE_OPERATION_TIMEOUT_SEC}s \
    tar -C "$root" -T /dev/null -cf "$stage/safe.tar" \
    >/dev/null 2>&1 || exit 75
fi
timeout -k 1s {_REMOTE_SYNC_PHASE_TIMEOUT_SEC}s \
  sync "$inventory" "$stage/safe.tar" 2>/dev/null || true
"""


def _decode_remote_path(encoded: str) -> str:
    try:
        raw = base64.b64decode(encoded, validate=True)
        value = raw.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as error:
        raise WorkspaceSnapshotError(
            "workspace_snapshot_remote_inventory_invalid"
        ) from error
    parsed = PurePosixPath(value)
    if (
        not value
        or value.startswith("/")
        or "\x00" in value
        or any(part in {"", ".", ".."} for part in parsed.parts)
        or _excluded(value)
    ):
        raise WorkspaceSnapshotError("workspace_snapshot_remote_inventory_invalid")
    return value


def _parse_remote_archive(
    path: Path,
    *,
    entries: Mapping[str, Mapping[str, Any]],
    omissions: Mapping[str, Mapping[str, Any]],
    policy: SnapshotPolicy,
) -> Mapping[str, bytes]:
    contents: dict[str, bytes] = {}
    seen: set[str] = set()
    total = 0
    archive_omitted = any(
        row.get("reason") in _REMOTE_ARCHIVE_OMISSION_REASONS
        for row in omissions.values()
    )
    expected = (
        set()
        if archive_omitted
        else {
            relative
            for relative, entry in entries.items()
            if entry["kind"] in {"file", "symlink"} and relative not in omissions
        }
    )
    try:
        with tarfile.open(path, mode="r:") as archive:
            members = archive.getmembers()
            if len(members) > policy.max_files:
                raise WorkspaceSnapshotError(
                    "workspace_snapshot_remote_archive_invalid"
                )
            for member in members:
                relative = _decode_remote_path(
                    base64.b64encode(member.name.encode()).decode()
                )
                entry = entries.get(relative)
                if entry is None or member.name != relative or relative in seen:
                    raise WorkspaceSnapshotError(
                        "workspace_snapshot_remote_archive_invalid"
                    )
                seen.add(relative)
                if member.issym():
                    if (
                        entry["kind"] != "symlink"
                        or member.linkname != entry["target"]
                        or not _safe_symlink(relative, member.linkname)
                    ):
                        raise WorkspaceSnapshotError(
                            "workspace_snapshot_remote_archive_invalid"
                        )
                    continue
                if not member.isfile() or entry["kind"] != "file":
                    raise WorkspaceSnapshotError(
                        "workspace_snapshot_remote_archive_invalid"
                    )
                if (
                    member.size != entry["size"]
                    or member.size > policy.max_file_bytes
                    or total + member.size > policy.max_total_bytes
                ):
                    raise WorkspaceSnapshotError(
                        "workspace_snapshot_remote_archive_limit_exceeded"
                    )
                handle = archive.extractfile(member)
                if handle is None:
                    raise WorkspaceSnapshotError(
                        "workspace_snapshot_remote_archive_invalid"
                    )
                payload = handle.read(policy.max_file_bytes + 1)
                if (
                    len(payload) != member.size
                    or _sha256(payload) != entry["sha256"]
                    or _sensitive_path(relative)
                    or _sensitive_content(payload)
                ):
                    raise WorkspaceSnapshotError(
                        "workspace_snapshot_remote_archive_invalid"
                    )
                contents[relative] = payload
                total += len(payload)
            if seen != expected:
                raise WorkspaceSnapshotError(
                    "workspace_snapshot_remote_archive_invalid"
                )
    except (OSError, tarfile.TarError) as error:
        raise WorkspaceSnapshotError(
            "workspace_snapshot_remote_archive_invalid"
        ) from error
    return contents


def _parse_remote_inventory(
    inventory_path: Path,
    archive_path: Path,
    policy: SnapshotPolicy,
) -> _Inventory:
    try:
        raw = inventory_path.read_bytes()
    except OSError as error:
        raise WorkspaceSnapshotError(
            "workspace_snapshot_remote_inventory_invalid"
        ) from error
    inventory_limit = min(policy.max_files * 8192 + 4096, 64 * 1024 * 1024)
    if len(raw) > inventory_limit:
        raise WorkspaceSnapshotError("workspace_snapshot_remote_inventory_invalid")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise WorkspaceSnapshotError(
            "workspace_snapshot_remote_inventory_invalid"
        ) from error
    entries: dict[str, Mapping[str, Any]] = {}
    omissions: dict[str, Mapping[str, Any]] = {}
    git: dict[str, object] = {}
    scan_complete = True
    for line in lines:
        fields = line.split("\t")
        if len(fields) == 3 and fields[0] == "G":
            key, value = fields[1:]
            if (
                key
                not in {
                    "head",
                    "index_tree",
                    "status_porcelain_v2_z_sha256",
                }
                or key in git
                or (
                    key != "head"
                    and (
                        len(value) != 64
                        or any(
                            character not in "0123456789abcdef" for character in value
                        )
                    )
                )
            ):
                raise WorkspaceSnapshotError(
                    "workspace_snapshot_remote_inventory_invalid"
                )
            git[key] = value or None
            continue
        if len(fields) == 2 and fields[0] == "S":
            relative = _decode_remote_path(fields[1])
            if relative in entries or relative in omissions:
                raise WorkspaceSnapshotError(
                    "workspace_snapshot_remote_inventory_invalid"
                )
            omissions[relative] = {
                "path": relative,
                "reason": "sensitive_path",
            }
            continue
        if (
            len(fields) in {3, 4}
            and fields[:2] == ["C", "file_count_cap"]
            and fields[2].isdigit()
            and int(fields[2]) > 0
            and (len(fields) == 3 or fields[3] == "lower_bound")
        ):
            scan_complete = False
            _add_global_omission(
                omissions,
                reason="file_count_cap",
                count=int(fields[2]),
                count_is_lower_bound=len(fields) == 4,
            )
            continue
        if (
            len(fields) == 2
            and fields[0] == "C"
            and fields[1] in _REMOTE_PARTIAL_REASONS
        ):
            scan_complete = False
            _add_global_omission(omissions, reason=fields[1])
            continue
        if len(fields) != 7 or fields[0] != "E":
            raise WorkspaceSnapshotError("workspace_snapshot_remote_inventory_invalid")
        _, encoded, kind, raw_mode, raw_size, detail, reason = fields
        relative = _decode_remote_path(encoded)
        if relative in entries or kind not in {
            "directory",
            "file",
            "special",
            "symlink",
            "unknown",
        }:
            raise WorkspaceSnapshotError("workspace_snapshot_remote_inventory_invalid")
        try:
            size = int(raw_size)
            mode_value = int(raw_mode, 8)
        except ValueError as error:
            raise WorkspaceSnapshotError(
                "workspace_snapshot_remote_inventory_invalid"
            ) from error
        if size < 0 or mode_value < 0 or mode_value > 0o7777:
            raise WorkspaceSnapshotError("workspace_snapshot_remote_inventory_invalid")
        entry: dict[str, object] = {
            "path": relative,
            "kind": kind,
            "mode": f"{mode_value:04o}",
            "size": size,
        }
        allowed_reasons = {
            "",
            "content_unavailable",
            "metadata_unavailable",
            "per_file_byte_cap",
            "sensitive_content",
            "sensitive_path",
            "special_file",
            "symlink_escape",
            "symlink_unavailable",
            "total_byte_cap",
        }
        if reason not in allowed_reasons:
            raise WorkspaceSnapshotError("workspace_snapshot_remote_inventory_invalid")
        if kind == "file":
            if detail and (
                len(detail) != 64
                or any(character not in "0123456789abcdef" for character in detail)
            ):
                raise WorkspaceSnapshotError(
                    "workspace_snapshot_remote_inventory_invalid"
                )
            if detail:
                entry["sha256"] = detail
            elif reason not in {
                "content_unavailable",
                "per_file_byte_cap",
                "sensitive_content",
                "total_byte_cap",
            }:
                raise WorkspaceSnapshotError(
                    "workspace_snapshot_remote_inventory_invalid"
                )
        elif kind == "symlink":
            try:
                target = base64.b64decode(detail, validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError) as error:
                raise WorkspaceSnapshotError(
                    "workspace_snapshot_remote_inventory_invalid"
                ) from error
            entry["target"] = target
            if (reason == "" and not _safe_symlink(relative, target)) or (
                reason == "symlink_escape" and _safe_symlink(relative, target)
            ):
                raise WorkspaceSnapshotError(
                    "workspace_snapshot_remote_inventory_invalid"
                )
        if (
            (kind == "directory" and reason)
            or (kind == "special" and reason != "special_file")
            or (kind == "unknown" and reason != "metadata_unavailable")
            or (
                kind == "symlink"
                and reason not in {"", "symlink_escape", "symlink_unavailable"}
            )
            or (
                kind == "file"
                and reason
                not in {
                    "",
                    "content_unavailable",
                    "per_file_byte_cap",
                    "sensitive_content",
                    "sensitive_path",
                    "total_byte_cap",
                }
            )
        ):
            raise WorkspaceSnapshotError("workspace_snapshot_remote_inventory_invalid")
        entries[relative] = entry
        if reason:
            omission: dict[str, object] = {
                "path": relative,
                "reason": reason,
            }
            if kind == "file" and "sha256" in entry:
                omission["sha256"] = entry["sha256"]
            omissions[relative] = omission
    ordered_entries = [entries[path] for path in sorted(entries, key=_sort_key)]
    manifest: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA,
        "policy_version": policy.version,
        "entries": ordered_entries,
        "entry_count": len(ordered_entries),
        "scan_complete": scan_complete,
    }
    if git:
        if set(git) != {
            "head",
            "index_tree",
            "status_porcelain_v2_z_sha256",
        }:
            raise WorkspaceSnapshotError("workspace_snapshot_remote_inventory_invalid")
        manifest["git"] = git
    contents = _parse_remote_archive(
        archive_path,
        entries=entries,
        omissions=omissions,
        policy=policy,
    )
    return _Inventory(
        manifest=manifest,
        entries=entries,
        safe_contents=contents,
        content_omissions=omissions,
    )


def _remote_stage(value: str) -> str:
    lines = value.splitlines()
    if (
        not lines
        or not lines[0].startswith(_REMOTE_STAGE_PREFIX)
        or PurePosixPath(lines[0]).parent != PurePosixPath("/tmp")
        or "\x00" in lines[0]
    ):
        raise WorkspaceSnapshotError("workspace_snapshot_remote_stage_invalid")
    return lines[0]


async def _remote_call(
    awaitable: Any,
    *,
    code: str,
    stage: str,
    attempt: int,
    deadline: _SnapshotCaptureDeadlineV1 | None = None,
    cleanup: bool = False,
) -> Any:
    try:
        if deadline is None:
            return await awaitable
        try:
            timeout_sec = deadline.timeout(
                POST_AGENT_SNAPSHOT_MAX_SEC,
                cleanup=cleanup,
            )
        except BaseException:
            if inspect.iscoroutine(awaitable):
                awaitable.close()
            raise
        return await asyncio.wait_for(
            awaitable,
            timeout=timeout_sec,
        )
    except asyncio.CancelledError:
        raise
    except Exception as error:
        raise _typed_failure(
            error,
            code=code,
            stage=stage,
            attempt=attempt,
        ) from error


def _execution_termination_verified(value: object) -> bool:
    """Accept only an explicit, internally consistent zero-census proof."""

    evidence = getattr(value, "evidence", value)
    return (
        getattr(evidence, "termination_verified", False) is True
        and getattr(evidence, "zero_census_verified", False) is True
        and (
            evidence is not value
            or (
                getattr(value, "census_verified", False) is True
                and type(getattr(value, "survivor_count", None)) is int
                and value.survivor_count == 0
            )
        )
    )


async def _remote_inventory_attempt(
    actor: object,
    policy: SnapshotPolicy,
    *,
    root: str,
    execute: Any,
    execute_owned: Any,
    download: Any,
    attempt: int,
    deadline: _SnapshotCaptureDeadlineV1 | None,
) -> _Inventory:
    stage: str | None = None
    termination_verified = False
    zero_census_verified = False
    primary: BaseException | None = None

    async def capture() -> _Inventory:
        nonlocal stage, termination_verified, zero_census_verified
        stage_result = await _remote_call(
            execute(
                _remote_stage_script(),
                timeout_sec=(
                    _REMOTE_STAGE_TIMEOUT_SEC
                    if deadline is None
                    else deadline.timeout(_REMOTE_STAGE_TIMEOUT_SEC)
                ),
            ),
            code="workspace_snapshot_remote_exec_failed",
            stage="remote-exec",
            attempt=attempt,
            deadline=deadline,
        )
        stage_return_code = getattr(stage_result, "return_code", None)
        if (
            isinstance(stage_return_code, bool)
            or not isinstance(stage_return_code, int)
            or stage_return_code != 0
        ):
            raise WorkspaceSnapshotError(
                "workspace_snapshot_remote_exec_failed",
                stage="remote-exec",
                category="command",
                return_code=stage_return_code,
                attempt=attempt,
            )
        try:
            stage = _remote_stage(stage_result.stdout)
        except Exception as error:
            raise _typed_failure(
                error,
                code="workspace_snapshot_remote_stage_invalid",
                stage="stage-parse",
                attempt=attempt,
            ) from error
        try:
            if callable(execute_owned):
                owned_kwargs: dict[str, object] = {
                    "stage": stage,
                    "timeout_sec": (
                        _REMOTE_TIMEOUT_SEC
                        if deadline is None
                        else deadline.timeout(_REMOTE_TIMEOUT_SEC)
                    ),
                }
                if (
                    deadline is not None
                    and "hard_deadline_monotonic_ns"
                    in inspect.signature(execute_owned).parameters
                ):
                    owned_kwargs["hard_deadline_monotonic_ns"] = (
                        deadline.recovery_monotonic_ns
                    )
                if (
                    deadline is not None
                    and "capture_deadline_monotonic_ns"
                    in inspect.signature(execute_owned).parameters
                ):
                    owned_kwargs["capture_deadline_monotonic_ns"] = (
                        deadline.capture_monotonic_ns
                    )
                result = await execute_owned(
                    _remote_script(root, policy, stage),
                    **owned_kwargs,
                )
            else:
                result = await execute(
                    _remote_script(root, policy, stage),
                    timeout_sec=(
                        _REMOTE_TIMEOUT_SEC
                        if deadline is None
                        else deadline.timeout(_REMOTE_TIMEOUT_SEC)
                    ),
                )
        except BaseException as error:
            if not _execution_termination_verified(error):
                typed = _typed_failure(
                    error,
                    code="workspace_snapshot_remote_termination_unverified",
                    stage="remote-exec",
                    attempt=attempt,
                )
                raise WorkspaceSnapshotError(
                    "workspace_snapshot_remote_termination_unverified",
                    stage="remote-exec",
                    category="internal",
                    errno=typed.failure.errno,
                    return_code=typed.failure.return_code,
                    attempt=attempt,
                    subtype=typed.failure.subtype,
                    timeout_origin=SnapshotTimeoutOriginV1.NOT_A_TIMEOUT,
                    stage_validated=True,
                    termination_verified=typed.failure.termination_verified,
                    zero_census_verified=typed.failure.zero_census_verified,
                    reason=typed.failure.reason,
                    observed_byte_length=typed.failure.observed_byte_length,
                    observed_sha256=typed.failure.observed_sha256,
                ) from error
            termination_verified = True
            zero_census_verified = True
            if isinstance(error, asyncio.CancelledError):
                raise
            raise _typed_failure(
                error,
                code="workspace_snapshot_remote_exec_failed",
                stage="remote-exec",
                attempt=attempt,
            ) from error
        if not _execution_termination_verified(result):
            raise WorkspaceSnapshotError(
                "workspace_snapshot_remote_termination_unverified",
                stage="remote-exec",
                category="internal",
                attempt=attempt,
                stage_validated=True,
            )
        termination_verified = True
        zero_census_verified = True
        return_code = getattr(result, "return_code", None)
        if isinstance(return_code, bool) or not isinstance(return_code, int):
            raise WorkspaceSnapshotError(
                "workspace_snapshot_remote_exec_invalid",
                stage="remote-exec",
                category="internal",
                attempt=attempt,
            )
        if return_code != 0:
            raise WorkspaceSnapshotError(
                "workspace_snapshot_remote_command_failed",
                stage="remote-command",
                category="command",
                return_code=return_code,
                attempt=attempt,
            )
        with tempfile.TemporaryDirectory(
            prefix="nano-workspace-snapshot."
        ) as temporary:
            inventory_path = Path(temporary) / "inventory.tsv"
            archive_path = Path(temporary) / "safe.tar"
            await _remote_call(
                download(f"{stage}/inventory.tsv", inventory_path),
                code="workspace_snapshot_inventory_download_failed",
                stage="inventory-download",
                attempt=attempt,
                deadline=deadline,
            )
            await _remote_call(
                download(f"{stage}/safe.tar", archive_path),
                code="workspace_snapshot_archive_download_failed",
                stage="archive-download",
                attempt=attempt,
                deadline=deadline,
            )
            try:
                return _parse_remote_inventory(inventory_path, archive_path, policy)
            except Exception as error:
                parse_stage = (
                    "archive-parse"
                    if "remote_archive" in getattr(error, "code", "")
                    else "inventory-parse"
                )
                raise _typed_failure(
                    error,
                    code=(
                        error.code
                        if isinstance(error, WorkspaceSnapshotError)
                        else "workspace_snapshot_remote_inventory_invalid"
                    ),
                    stage=parse_stage,
                    attempt=attempt,
                ) from error

    try:
        inventory = await capture()
    except (WorkspaceSnapshotError, asyncio.CancelledError) as error:
        primary = error
    except Exception as error:
        primary = _typed_failure(
            error,
            code="workspace_snapshot_remote_inventory_invalid",
            stage="inventory-parse",
            attempt=attempt,
        )
    cleanup_failure: WorkspaceSnapshotError | None = None
    cleanup_verified = False
    if stage is not None and termination_verified:
        try:
            cleanup = await _remote_call(
                execute(
                    f"rm -rf -- {shlex.quote(stage)} && "
                    f"test ! -e {shlex.quote(stage)} && "
                    f"test ! -L {shlex.quote(stage)}",
                    timeout_sec=(
                        5.0 if deadline is None else deadline.timeout(5.0, cleanup=True)
                    ),
                ),
                code="workspace_snapshot_remote_cleanup_failed",
                stage="cleanup",
                attempt=attempt,
                deadline=deadline,
                cleanup=True,
            )
            cleanup_return_code = getattr(cleanup, "return_code", None)
            if (
                isinstance(cleanup_return_code, bool)
                or not isinstance(cleanup_return_code, int)
                or cleanup_return_code != 0
            ):
                cleanup_failure = WorkspaceSnapshotError(
                    "workspace_snapshot_remote_cleanup_failed",
                    stage="cleanup",
                    category="command",
                    return_code=(
                        cleanup_return_code
                        if isinstance(cleanup_return_code, int)
                        and not isinstance(cleanup_return_code, bool)
                        else None
                    ),
                    attempt=attempt,
                    subtype=SnapshotFailureSubtypeV1.STAGE_CLEANUP_FAILED,
                    stage_validated=True,
                    termination_verified=True,
                    zero_census_verified=zero_census_verified,
                )
            else:
                cleanup_verified = True
        except WorkspaceSnapshotError as error:
            cleanup_failure = _with_failure_evidence(
                error,
                subtype=SnapshotFailureSubtypeV1.STAGE_CLEANUP_FAILED,
                stage_validated=True,
                termination_verified=True,
                zero_census_verified=zero_census_verified,
            )
    if primary is not None:
        if cleanup_failure is not None:
            cleanup_unverified = WorkspaceSnapshotError(
                "workspace_snapshot_remote_cleanup_unverified",
                stage="cleanup",
                category="internal",
                attempt=attempt,
                subtype=SnapshotFailureSubtypeV1.STAGE_CLEANUP_FAILED,
                stage_validated=True,
                termination_verified=True,
                zero_census_verified=zero_census_verified,
            )
            if isinstance(primary, asyncio.CancelledError):
                raise cleanup_unverified from primary
            raise cleanup_unverified from primary
        if isinstance(primary, asyncio.CancelledError):
            actor_evidence = getattr(primary, "evidence", primary)
            try:
                subtype = SnapshotFailureSubtypeV1(getattr(actor_evidence, "subtype"))
            except (AttributeError, TypeError, ValueError):
                subtype = SnapshotFailureSubtypeV1.UNKNOWN_INTERNAL
            try:
                timeout_origin = SnapshotTimeoutOriginV1(
                    getattr(actor_evidence, "timeout_origin")
                )
            except (AttributeError, TypeError, ValueError):
                timeout_origin = SnapshotTimeoutOriginV1.NOT_A_TIMEOUT
                subtype = SnapshotFailureSubtypeV1.UNKNOWN_INTERNAL
            try:
                reason = SnapshotFailureReasonV1(getattr(actor_evidence, "reason"))
            except (AttributeError, TypeError, ValueError):
                reason = SnapshotFailureReasonV1.NOT_APPLICABLE
            raise SnapshotOperationCancelled(
                SnapshotFailureEvidenceV1(
                    subtype=subtype,
                    timeout_origin=timeout_origin,
                    stage_validated=stage is not None,
                    termination_verified=termination_verified,
                    cleanup_verified=cleanup_verified,
                    zero_census_verified=zero_census_verified,
                    execution_binding_verified=(
                        getattr(
                            actor_evidence,
                            "execution_binding_verified",
                            False,
                        )
                        is True
                    ),
                    reason=reason,
                    observed_byte_length=getattr(
                        actor_evidence,
                        "observed_byte_length",
                        None,
                    ),
                    observed_sha256=getattr(
                        actor_evidence,
                        "observed_sha256",
                        None,
                    ),
                )
            ) from primary
        if isinstance(primary, WorkspaceSnapshotError):
            primary = _with_failure_evidence(
                primary,
                stage_validated=stage is not None,
                termination_verified=termination_verified,
                cleanup_verified=cleanup_verified,
                zero_census_verified=zero_census_verified,
            )
        raise primary
    assert inventory is not None
    if cleanup_failure is not None:
        partial_omissions = dict(inventory.content_omissions)
        _add_global_omission(
            partial_omissions,
            reason="stage_cleanup_unverified",
        )
        inventory = replace(
            inventory,
            content_omissions=partial_omissions,
        )
    return replace(
        inventory,
        stage_validated=stage is not None,
        termination_verified=termination_verified,
        cleanup_verified=cleanup_verified,
        zero_census_verified=zero_census_verified,
    )


def _snapshot_failure_retryable(error: WorkspaceSnapshotError) -> bool:
    """Match only exact transient boundary tuples; cross-products stay fatal."""

    failure = error.failure
    if failure.subtype is SnapshotFailureSubtypeV1.WAIT_TRANSPORT_FAILED:
        return bool(
            failure.stage == "remote-exec"
            and failure.category in {"connection", "os_error", "transport"}
            and failure.timeout_origin is SnapshotTimeoutOriginV1.NOT_A_TIMEOUT
        )
    if failure.subtype is SnapshotFailureSubtypeV1.OUTPUT_DOWNLOAD_FAILED:
        return bool(
            failure.stage in {"inventory-download", "archive-download"}
            and failure.category in {"connection", "os_error", "transport"}
            and failure.timeout_origin is SnapshotTimeoutOriginV1.NOT_A_TIMEOUT
        )
    return False


async def _remote_inventory(
    actor: object,
    policy: SnapshotPolicy,
    *,
    deadline: _SnapshotCaptureDeadlineV1 | None = None,
) -> _Inventory:
    root_method = getattr(actor, "snapshot_workspace_root", None)
    execute = getattr(actor, "exec_snapshot", None)
    execute_owned = getattr(actor, "exec_snapshot_owned", None)
    download = getattr(actor, "download_snapshot", None)
    if not callable(root_method) or not callable(execute) or not callable(download):
        raise WorkspaceSnapshotError(
            "workspace_snapshot_transport_unavailable",
            stage="target",
            category="transport",
        )
    root = root_method()
    if (
        not isinstance(root, str)
        or not root.startswith("/")
        or PurePosixPath(root).as_posix() != root
        or "\x00" in root
    ):
        raise WorkspaceSnapshotError(
            "workspace_snapshot_root_invalid",
            stage="target",
            category="policy",
        )
    for attempt in (1, 2):
        try:
            return await _remote_inventory_attempt(
                actor,
                policy,
                root=root,
                execute=execute,
                execute_owned=execute_owned,
                download=download,
                attempt=attempt,
                deadline=deadline,
            )
        except WorkspaceSnapshotError as error:
            if (
                attempt == 1
                and error.failure.transient
                and _snapshot_failure_retryable(error)
                and error.failure.stage_validated
                and error.failure.termination_verified
                and error.failure.cleanup_verified
                and error.failure.zero_census_verified
                and (
                    deadline is None or deadline.remaining() > _REMOTE_STAGE_TIMEOUT_SEC
                )
            ):
                continue
            raise
    raise AssertionError("workspace snapshot retry loop exhausted")


async def _capture_inventory(
    target: SnapshotTarget,
    policy: SnapshotPolicy,
    *,
    deadline: _SnapshotCaptureDeadlineV1 | None = None,
) -> _Inventory:
    if isinstance(getattr(target.actor, "workspace", None), Path):
        workspace = _local_workspace(target.actor)
        return await asyncio.to_thread(_inventory, workspace, policy)
    return await _remote_inventory(target.actor, policy, deadline=deadline)


def _changed(
    before: Mapping[str, Mapping[str, Any]],
    after: Mapping[str, Mapping[str, Any]],
) -> tuple[list[str], list[str], list[str]]:
    before_paths = set(before)
    after_paths = set(after)
    created = sorted(after_paths - before_paths, key=_sort_key)
    deleted = sorted(before_paths - after_paths, key=_sort_key)
    modified = sorted(
        (path for path in before_paths & after_paths if before[path] != after[path]),
        key=_sort_key,
    )
    return created, deleted, modified


def _add_global_omission(
    omissions: dict[str, Mapping[str, Any]],
    *,
    reason: str,
    count: int | None = None,
    count_is_lower_bound: bool = False,
) -> None:
    row: dict[str, Any] = {"path": "", "reason": reason}
    if count is not None:
        row["count"] = count
        if count_is_lower_bound:
            row["count_is_lower_bound"] = True
    if row in omissions.values():
        return
    key = "" if "" not in omissions else f"\x00{reason}"
    suffix = 2
    while key in omissions and omissions[key] != row:
        key = f"\x00{reason}:{suffix}"
        suffix += 1
    omissions[key] = row


def _safe_symlink(path: str, target: str) -> bool:
    parsed = PurePosixPath(target)
    if parsed.is_absolute():
        return False
    combined = PurePosixPath(path).parent / parsed
    depth = 0
    for part in combined.parts:
        if part == "..":
            depth -= 1
        elif part not in {"", "."}:
            depth += 1
        if depth < 0:
            return False
    return True


def _patch(
    *,
    paths: list[str],
    before_contents: Mapping[str, bytes],
    after_contents: Mapping[str, bytes],
    max_bytes: int,
) -> tuple[bytes, bool]:
    output = bytearray()
    truncated = False
    for path in paths:
        old = before_contents.get(path, b"")
        new = after_contents.get(path, b"")
        if _binary(old) or _binary(new):
            continue
        try:
            old.decode("utf-8")
            new.decode("utf-8")
        except UnicodeDecodeError:
            continue
        rows = difflib.diff_bytes(
            difflib.unified_diff,
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=f"a/{path}".encode(),
            tofile=f"b/{path}".encode(),
        )
        chunk = b"".join(rows)
        if len(output) + len(chunk) > max_bytes:
            remaining = max_bytes - len(output)
            output.extend(chunk[:remaining])
            truncated = True
            break
        output.extend(chunk)
    return bytes(output), truncated


def _tar(
    *,
    paths: list[str],
    entries: Mapping[str, Mapping[str, Any]],
    contents: Mapping[str, bytes],
    omissions: dict[str, Mapping[str, Any]],
) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(
        fileobj=stream, mode="w:", format=tarfile.USTAR_FORMAT
    ) as archive:
        for path in paths:
            entry = entries[path]
            kind = entry["kind"]
            if kind == "directory":
                continue
            information = tarfile.TarInfo(path)
            information.uid = 0
            information.gid = 0
            information.uname = ""
            information.gname = ""
            information.mtime = 0
            information.mode = int(str(entry["mode"]), 8)
            if kind == "symlink":
                target = str(entry["target"])
                if not _safe_symlink(path, target):
                    omissions[path] = {
                        "path": path,
                        "reason": "symlink_escape",
                    }
                    continue
                information.type = tarfile.SYMTYPE
                information.linkname = target
                information.size = 0
                archive.addfile(information)
                continue
            payload = contents.get(path)
            if kind != "file" or payload is None:
                continue
            information.type = tarfile.REGTYPE
            information.size = len(payload)
            archive.addfile(information, io.BytesIO(payload))
    return stream.getvalue()


def _artifact_row(payload: bytes) -> dict[str, object]:
    return {"byte_length": len(payload), "sha256": _sha256(payload)}


def _write(path: Path, payload: bytes) -> None:
    if path.exists():
        try:
            existing = path.read_bytes()
        except OSError as error:
            raise WorkspaceSnapshotError(
                "workspace_snapshot_publish_failed",
                stage="publish",
                category="publish",
                errno=error.errno,
            ) from None
        if existing != payload:
            raise WorkspaceSnapshotError(
                "workspace_snapshot_existing_mismatch",
                stage="publish",
                category="publish",
            )
        return
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as error:
        temporary.unlink(missing_ok=True)
        raise WorkspaceSnapshotError(
            "workspace_snapshot_publish_failed",
            stage="publish",
            category="os_error",
            errno=error.errno,
        ) from None


def _write_workspace_receipt(path: Path, payload: bytes) -> SnapshotReceipt:
    intended = parse_workspace_receipt_bytes(payload)
    _write(path, payload)
    persisted = load_workspace_receipt(path)
    if persisted != intended:
        raise WorkspaceSnapshotError(
            "workspace_receipt_persisted_mismatch",
            stage="publish",
            category="publish",
        )
    return persisted


def _failure_receipt_value(
    policy: SnapshotPolicy,
    code: str,
    failure: WorkspaceFailureV4,
) -> dict[str, object]:
    baseline_state = (
        WorkspaceBaselineStateV1.UNAVAILABLE
        if code.startswith("workspace_before_")
        else WorkspaceBaselineStateV1.AVAILABLE
    )
    return {
        "schema_version": FAILURE_RECEIPT_SCHEMA_V5,
        "status": "failed",
        "code": code,
        "baseline_state": baseline_state.value,
        "policy": policy.as_dict(),
        "truncated": False,
        "omitted_count": 0,
        "artifacts": {},
        "failure": {
            "stage": failure.stage,
            "category": failure.category,
            "subtype": failure.subtype.value,
            "timeout_origin": failure.timeout_origin.value,
            "errno": failure.errno if failure.return_code is None else None,
            "return_code": failure.return_code,
            "attempt": failure.attempt,
            "stage_validated": failure.stage_validated,
            "termination_verified": failure.termination_verified,
            "cleanup_verified": failure.cleanup_verified,
            "zero_census_verified": failure.zero_census_verified,
            "execution_binding_verified": failure.execution_binding_verified,
            "reason": failure.reason.value,
            "observed_byte_length": failure.observed_byte_length,
            "observed_sha256": failure.observed_sha256,
        },
    }


def _failure_receipt(
    target: SnapshotTarget,
    policy: SnapshotPolicy,
    code: str,
    error: WorkspaceSnapshotError,
) -> SnapshotReceipt:
    failure = replace(
        error.failure,
        stage=error.failure.stage
        if error.failure.stage in FAILURE_STAGES
        else "target",
        category=(
            error.failure.category
            if error.failure.category in FAILURE_CATEGORIES
            else "internal"
        ),
    )
    payload = canonical_json(_failure_receipt_value(policy, code, failure))
    path = target.artifact_dir / "workspace-receipt.json"
    return _write_workspace_receipt(path, payload)


def _failed_before_receipt(
    target: SnapshotTarget,
    before: BeforeSnapshot,
) -> SnapshotReceipt:
    failure = before.failure
    if (
        before.status != "failed"
        or before.baseline_state is not WorkspaceBaselineStateV1.UNAVAILABLE
        or before.manifest is not None
        or before.safe_contents
        or before.content_omissions
        or failure is None
        or failure.stage not in FAILURE_STAGES
        or failure.category not in FAILURE_CATEGORIES
        or not before.receipt_sha256
    ):
        raise WorkspaceSnapshotError("workspace_before_snapshot_invalid")
    try:
        receipt = load_workspace_receipt(target.artifact_dir / "workspace-receipt.json")
    except WorkspaceSnapshotError:
        raise WorkspaceSnapshotError("workspace_before_snapshot_invalid") from None
    if (
        receipt.status != "failed"
        or receipt.code != before.code
        or receipt.baseline_state is not WorkspaceBaselineStateV1.UNAVAILABLE
        or receipt.failure != failure
        or not receipt.continuable
        or receipt.canonical_sha256 != before.receipt_sha256
    ):
        raise WorkspaceSnapshotError("workspace_before_snapshot_invalid")
    return receipt


async def capture_before(actor: object, policy: SnapshotPolicy) -> BeforeSnapshot:
    """Capture the pre-agent inventory outside the workspace."""

    target = _target(actor)
    failure_to_raise: WorkspaceSnapshotError | None = None
    phases = getattr(target.actor, "capture_phases", None)
    if isinstance(phases, list):
        phases.append("before")
    if getattr(target.actor, "fail_phase", None) == "before":
        failure = WorkspaceSnapshotError(
            "workspace_before_capture_failed",
            stage="target",
            category="internal",
        )
        _failure_receipt(target, policy, failure.code, failure)
        raise failure
    try:
        await asyncio.sleep(0)
        inventory = await _capture_inventory(target, policy)
        payload = canonical_json(inventory.manifest)
        _write(target.artifact_dir / "workspace-before.json", payload)
        return BeforeSnapshot(
            target=target,
            policy=policy,
            manifest=inventory.manifest,
            safe_contents=inventory.safe_contents,
            content_omissions=inventory.content_omissions,
            baseline_state=WorkspaceBaselineStateV1.AVAILABLE,
        )
    except asyncio.CancelledError as error:
        failure = _cancelled_failure(
            error,
            code="workspace_before_capture_cancelled",
            fallback_stage="target",
        )
        _failure_receipt(target, policy, failure.code, failure)
        raise
    except Exception as error:
        failure_to_raise = _typed_failure(
            error,
            code="workspace_before_capture_failed",
            stage="target",
            attempt=1,
        )
        receipt = _failure_receipt(
            target,
            policy,
            failure_to_raise.code,
            failure_to_raise,
        )
        if receipt.continuable:
            return BeforeSnapshot(
                target=target,
                policy=policy,
                manifest=None,
                safe_contents={},
                baseline_state=WorkspaceBaselineStateV1.UNAVAILABLE,
                status="failed",
                code=receipt.code,
                failure=receipt.failure,
                receipt_sha256=receipt.canonical_sha256,
            )
        if isinstance(error.__cause__, asyncio.CancelledError):
            raise failure_to_raise from error.__cause__
    assert failure_to_raise is not None
    raise failure_to_raise from None


async def capture_after(
    actor: object,
    before: object,
    *,
    hard_deadline_monotonic_ns: int | None = None,
) -> SnapshotReceipt:
    """Capture the post-agent state and publish its bounded deterministic delta."""

    if not isinstance(before, BeforeSnapshot):
        raise WorkspaceSnapshotError("workspace_before_snapshot_invalid")
    deadline = (
        None
        if hard_deadline_monotonic_ns is None
        else _SnapshotCaptureDeadlineV1(hard_deadline_monotonic_ns)
    )
    target = _target(actor)
    if target != before.target:
        raise WorkspaceSnapshotError("workspace_snapshot_target_mismatch")
    policy = before.policy
    if before.baseline_state is WorkspaceBaselineStateV1.UNAVAILABLE:
        return _failed_before_receipt(target, before)
    if (
        before.baseline_state is not WorkspaceBaselineStateV1.AVAILABLE
        or before.status != "complete"
        or before.manifest is None
    ):
        raise WorkspaceSnapshotError("workspace_before_snapshot_invalid")
    phases = getattr(target.actor, "capture_phases", None)
    if isinstance(phases, list):
        phases.append("after")
    if getattr(target.actor, "fail_phase", None) == "after":
        failure = WorkspaceSnapshotError(
            "workspace_after_capture_failed",
            stage="publish",
            category="internal",
        )
        return _failure_receipt(target, policy, failure.code, failure)
    after: _Inventory | None = None
    try:
        await asyncio.sleep(0)
        after = await _capture_inventory(target, policy, deadline=deadline)
        _capture_checkpoint(deadline)
        before_entries = {str(row["path"]): row for row in before.manifest["entries"]}
        created, deleted, modified = _changed(before_entries, after.entries)
        changed_paths = sorted(created + modified, key=_sort_key)
        after_omissions = {
            key: row
            for key, row in after.content_omissions.items()
            if not row["path"]
            or row["path"] in changed_paths
            or row["path"] not in before_entries
        }
        before_omissions = {
            key: row
            for key, row in before.content_omissions.items()
            if not row["path"] or row["path"] in modified or row["path"] in deleted
        }
        omissions: dict[str, Mapping[str, Any]] = {}
        for source in (before_omissions, after_omissions):
            for row in source.values():
                if row["path"]:
                    omissions[str(row["path"])] = row
                else:
                    _add_global_omission(
                        omissions,
                        reason=str(row["reason"]),
                        count=(
                            int(row["count"]) if type(row.get("count")) is int else None
                        ),
                        count_is_lower_bound=(row.get("count_is_lower_bound") is True),
                    )
        after_omitted_paths = {
            str(row["path"]) for row in after.content_omissions.values() if row["path"]
        }
        archive_paths = [
            path
            for path in changed_paths
            if path not in after_omitted_paths
            and after.entries[path]["kind"] in {"file", "symlink"}
        ]
        archive = _tar(
            paths=archive_paths,
            entries=after.entries,
            contents=after.safe_contents,
            omissions=omissions,
        )
        if len(archive) > WORKSPACE_CHANGED_TAR_MAX_BYTES:
            raise WorkspaceSnapshotError("workspace_snapshot_archive_limit_exceeded")
        _capture_checkpoint(deadline)
        patch_paths = sorted(
            [
                *(path for path in created if path in after.safe_contents),
                *(path for path in deleted if path in before.safe_contents),
                *(
                    path
                    for path in modified
                    if path in before.safe_contents and path in after.safe_contents
                ),
            ],
            key=_sort_key,
        )
        patch, patch_truncated = _patch(
            paths=patch_paths,
            before_contents=before.safe_contents,
            after_contents=after.safe_contents,
            max_bytes=policy.max_patch_bytes,
        )
        _capture_checkpoint(deadline)
        if patch_truncated:
            _add_global_omission(
                omissions,
                reason="patch_byte_cap",
            )
        git_before = before.manifest.get("git")
        git_after = after.manifest.get("git")
        delta: dict[str, Any] = {
            "schema_version": DELTA_SCHEMA,
            "policy_version": policy.version,
            "created": [{"path": path} for path in created],
            "deleted": [{"path": path} for path in deleted],
            "modified": [{"path": path} for path in modified],
            "omitted": sorted(
                omissions.values(),
                key=lambda row: (
                    _sort_key(str(row["path"])),
                    _sort_key(str(row["reason"])),
                ),
            ),
        }
        if git_before is not None or git_after is not None:
            delta["git"] = {
                "head": (
                    git_after.get("head") if isinstance(git_after, Mapping) else None
                ),
                "head_before": (
                    git_before.get("head") if isinstance(git_before, Mapping) else None
                ),
                "head_after": (
                    git_after.get("head") if isinstance(git_after, Mapping) else None
                ),
                "index_tree_before": (
                    git_before.get("index_tree")
                    if isinstance(git_before, Mapping)
                    else None
                ),
                "index_tree_after": (
                    git_after.get("index_tree")
                    if isinstance(git_after, Mapping)
                    else None
                ),
                "status_porcelain_v2_z_sha256": (
                    git_after.get("status_porcelain_v2_z_sha256")
                    if isinstance(git_after, Mapping)
                    else None
                ),
            }
        before_payload = canonical_json(before.manifest)
        after_payload = canonical_json(after.manifest)
        delta_payload = canonical_json(delta)
        _capture_checkpoint(deadline)
        artifacts = {
            "workspace-before.json": before_payload,
            "workspace-after.json": after_payload,
            "workspace-delta.json": delta_payload,
            "workspace-diff.patch": patch,
            "workspace-changed.tar": archive,
        }
        for name, payload in artifacts.items():
            _capture_checkpoint(deadline)
            _write(target.artifact_dir / name, payload)
            _capture_checkpoint(deadline)
        artifact_rows = {
            name: _artifact_row(payload) for name, payload in sorted(artifacts.items())
        }
        partial_reasons = {
            *_REMOTE_PARTIAL_REASONS,
            "file_count_cap",
            "per_file_byte_cap",
            "patch_byte_cap",
            "stage_cleanup_unverified",
            "total_byte_cap",
        }
        truncated = (
            not bool(before.manifest.get("scan_complete"))
            or not bool(after.manifest.get("scan_complete"))
            or any(
                row.get("reason") in partial_reasons
                for source in (
                    before.content_omissions,
                    after.content_omissions,
                    omissions,
                )
                for row in source.values()
            )
        )
        omitted_count = sum(
            (
                int(row.get("count", 1))
                if type(row.get("count", 1)) is int and int(row.get("count", 1)) > 0
                else 1
            )
            for row in omissions.values()
        )
        receipt_value = {
            "schema_version": RECEIPT_SCHEMA,
            "status": "complete",
            "code": "completed",
            "policy": policy.as_dict(),
            "truncated": truncated,
            "omitted_count": omitted_count,
            "artifacts": artifact_rows,
        }
        receipt_payload = canonical_json(receipt_value)
        _capture_checkpoint(deadline)
        receipt = _write_workspace_receipt(
            target.artifact_dir / "workspace-receipt.json",
            receipt_payload,
        )
        _capture_checkpoint(deadline)
        return receipt
    except asyncio.CancelledError as error:
        failure = _cancelled_failure(
            error,
            code="workspace_after_capture_cancelled",
            fallback_stage="publish",
        )
        _failure_receipt(target, policy, failure.code, failure)
        raise
    except Exception as error:
        integrity_failure = isinstance(error, WorkspaceSnapshotError) and (
            error.code == "workspace_snapshot_existing_mismatch"
            or error.failure.category in {"policy", "publish"}
        )
        if (
            after is not None
            and after.stage_validated
            and after.termination_verified
            and after.cleanup_verified
            and after.zero_census_verified
            and not integrity_failure
        ):
            failure = WorkspaceSnapshotError(
                "workspace_after_capture_failed",
                stage="host-evidence",
                category="evidence",
                errno=getattr(error, "errno", None),
                attempt=1,
                subtype=(SnapshotFailureSubtypeV1.HOST_EVIDENCE_MATERIALIZATION_FAILED),
                timeout_origin=SnapshotTimeoutOriginV1.NOT_A_TIMEOUT,
                stage_validated=after.stage_validated,
                termination_verified=after.termination_verified,
                cleanup_verified=after.cleanup_verified,
                zero_census_verified=after.zero_census_verified,
            )
        else:
            failure = _typed_failure(
                error,
                code="workspace_after_capture_failed",
                stage="publish",
                attempt=1,
            )
        receipt = _failure_receipt(target, policy, failure.code, failure)
        if isinstance(error.__cause__, asyncio.CancelledError):
            raise failure from error.__cause__
        return receipt
