"""Sandbox-resident foreground terminal actor with process-group cleanup."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json
import os
import posixpath
import secrets
import shlex
import subprocess
import tempfile
import time
import uuid
from collections import Counter
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol

from nano_grok_build.adapter.deadline import host_monotonic
from nano_grok_build.adapter.stdio_bridge import (
    BACKGROUND_START_PROOF_VERSION,
    BackgroundStartKind,
    BackgroundStartObservation,
    BridgeError,
    EffectObservationStatusV1,
    EffectObservationV1,
    MediaPayload,
    ProcessDisposition,
    TerminalActorOriginV1,
    TerminalActorPhaseV1,
    TerminalActorReceiptV1,
    TerminalActorSubtypeV1,
    ToolExecution,
    ToolFailure,
    ToolFatalError,
    ToolRequest,
    _complete_shielded,
    _strict_remaining_sec,
)

_REMOTE_ROOT = "/tmp/nano-grok-build-terminal-v1"
_REMOTE_ACTOR = f"{_REMOTE_ROOT}/actor.sh"
_BACKGROUND_ROOT = f"{_REMOTE_ROOT}/background"
_LOGICAL_WORKSPACE = "/workspace"
_WORKSPACE_MAPPING_MODES = {
    "created_symlink",
    "existing_directory",
    "existing_symlink",
}
_FORBIDDEN_WORKSPACE_PARTS = {
    ".terminals",
    "artifact",
    "artifacts",
    "log",
    "logs",
}
_MAX_BACKGROUND_TOMBSTONES = 100
_FOREGROUND_DRAIN_TIMEOUT_MS = 1_000
_BACKGROUND_START_SETUP_TIMEOUT_SEC = 10.0
_BACKGROUND_START_DISPATCH_TIMEOUT_SEC = 10.0
_BACKGROUND_START_ACTION_RESERVE_MS = int(
    (_BACKGROUND_START_SETUP_TIMEOUT_SEC + _BACKGROUND_START_DISPATCH_TIMEOUT_SEC)
    * 1000
)
_WORKSPACE_MAPPING_CHECK_TIMEOUT_SEC = 5.0
_WORKSPACE_MAPPING_CHECK_MAX_ATTEMPTS = 2
_SNAPSHOT_TERM_GRACE_MS = 1_000
_SNAPSHOT_CONFIRMATION_MS = 3_000
_SNAPSHOT_LAUNCH_TIMEOUT_SEC = 10.0
_SNAPSHOT_CONTROL_GUARD_SEC = 5.0
_SNAPSHOT_REAP_TIMEOUT_SEC = 2.0
SNAPSHOT_OUTPUT_CAP_BYTES = 1024 * 1024
_SNAPSHOT_OUTPUT_CAP_BYTES = SNAPSHOT_OUTPUT_CAP_BYTES
_META_KEYS = {
    "return_code",
    "timed_out",
    "stdout_truncated",
    "stderr_truncated",
    "cleanup_attempted",
    "term_sent",
    "kill_sent",
    "cleanup_verified",
    "census_verified",
    "survivor_count",
}
_SNAPSHOT_LEASE_KEYS = {
    "version",
    "status",
    "owner_token",
    "leader_pid",
    "leader_starttime",
    "pgid",
    "supervisor_pid",
    "supervisor_starttime",
    "supervisor_pgid",
}
_SNAPSHOT_TERMINAL_KEYS = _SNAPSHOT_LEASE_KEYS | {
    "return_code",
    "timed_out",
    "term_sent",
    "kill_sent",
    "termination_verified",
    "census_verified",
    "survivor_count",
}
_MEDIA_SUFFIXES = {
    ".bmp",
    ".gif",
    ".jpeg",
    ".jpg",
    ".pdf",
    ".png",
    ".ppt",
    ".pptx",
    ".tif",
    ".tiff",
    ".webp",
}
_RASTER_SUFFIXES = {".jpeg", ".jpg", ".png", ".webp"}
_READ_FILE_MEDIA_MAX_BYTES = 4 * 1024 * 1024
_READ_FILE_MEDIA_MAX_DIMENSION = 8192
_READ_FILE_MEDIA_MAX_PIXELS = 25_000_000
_SENSITIVE_MEDIA_PARTS = {
    ".aws",
    ".git",
    ".ssh",
    ".terminals",
    "artifact",
    "artifacts",
    "log",
    "logs",
}
_SENSITIVE_MEDIA_BASENAMES = {
    ".netrc",
    "authorized_keys",
    "credentials",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "known_hosts",
    "secrets",
    "secrets.json",
}
_SENSITIVE_MEDIA_EXTENSIONS = {
    ".jks",
    ".key",
    ".keystore",
    ".p12",
    ".pem",
    ".pfx",
}
_GREP_TYPE_GLOBS = {
    "c": "*.[ch]",
    "cpp": "*.[ch]pp",
    "go": "*.go",
    "java": "*.java",
    "js": "*.js",
    "json": "*.json",
    "md": "*.md",
    "py": "*.py",
    "rust": "*.rs",
    "sh": "*.sh",
    "ts": "*.ts",
}

_BACKGROUND_STATES = {"running", "completed", "failed", "cancelled"}
_BACKGROUND_STATUS_KEYS = {
    "state",
    "exit_code",
    "timed_out",
    "total_bytes",
    "truncated",
    "leader_exited",
    "started_epoch",
    "ended_epoch",
}


def _uuid7() -> str:
    timestamp_ms = int(time.time() * 1000) & ((1 << 48) - 1)
    value = (
        (timestamp_ms << 80)
        | (0x7 << 76)
        | (secrets.randbits(12) << 64)
        | (0b10 << 62)
        | secrets.randbits(62)
    )
    return str(uuid.UUID(int=value))


def _workspace_root_is_safe(value: str) -> bool:
    if (
        not value.startswith("/")
        or posixpath.normpath(value) != value
        or value == "/"
        or "\x00" in value
        or len(value.encode("utf-8")) > 4096
    ):
        return False
    if value == _REMOTE_ROOT or value.startswith(f"{_REMOTE_ROOT}/"):
        return False
    return not any(part in _FORBIDDEN_WORKSPACE_PARTS for part in value.split("/"))


def _workspace_mapping_check_timed_out(
    error: BaseException,
    *,
    timeout_sec: float,
) -> bool:
    if timeout_sec != _WORKSPACE_MAPPING_CHECK_TIMEOUT_SEC:
        return False
    if type(error) is TimeoutError:
        return True
    if type(error) is subprocess.TimeoutExpired:
        observed_timeout = error.timeout
        return (
            type(observed_timeout) in {int, float}
            and observed_timeout == _WORKSPACE_MAPPING_CHECK_TIMEOUT_SEC
        )
    return type(error) is RuntimeError and error.args == (
        f"Command timed out after {_WORKSPACE_MAPPING_CHECK_TIMEOUT_SEC} seconds",
    )


def _owner_token_is_valid(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


@dataclass
class BackgroundTask:
    task_id: str
    request_dir: str
    command: str
    logical_cwd: str
    output_path: str
    start_wall: float
    start_monotonic: float
    runtime_timeout_ms: int | None
    spool_cap_bytes: int
    term_grace_ms: int
    kill_confirmation_timeout_ms: int
    owner_token: str = field(default_factory=lambda: secrets.token_hex(32))
    pgid: int | None = None
    leader_starttime: int | None = None
    monitor_pgid: int | None = None
    monitor_starttime: int | None = None
    state: str = "running"
    exit_code: int | None = None
    timed_out: bool = False
    leader_exited: bool = False
    end_wall: float | None = None
    end_monotonic: float | None = None
    explicitly_killed: bool = False
    total_bytes: int = 0
    truncated: bool = False
    spool_finalized: bool = False
    census_verified: bool = False
    status_fresh: bool = True
    status_reason: str | None = None
    output_reason: str | None = None


@dataclass(frozen=True)
class _CleanupParticipant:
    term_grace_ms: int
    term: Callable[[int], Awaitable[bool]]
    kill: Callable[[int], Awaitable[bool]]
    census: Callable[[int], Awaitable[bool]]
    finalize: Callable[[], None]


@dataclass(frozen=True)
class _ProcessLeaseIdentityV1:
    task_id: str
    request_dir: str
    output_path: str
    leader_pid: int
    leader_starttime: int
    leader_pgid: int
    monitor_pid: int
    monitor_starttime: int
    monitor_pgid: int
    owner_token: str
    term_grace_ms: int
    kill_confirmation_timeout_ms: int


@dataclass(frozen=True)
class ProcessLeaseV1:
    """Opaque exact set of managed processes retained across host phases."""

    _identities: tuple[_ProcessLeaseIdentityV1, ...]

    @property
    def process_count(self) -> int:
        return len(self._identities)


@dataclass(frozen=True)
class SnapshotCommandResult:
    return_code: int
    stdout: str
    stderr: str
    termination_verified: bool = False
    census_verified: bool = False
    survivor_count: int | None = None

    @property
    def zero_census_verified(self) -> bool:
        return self.census_verified is True and self.survivor_count == 0


@dataclass(frozen=True)
class WorkspaceReadinessV1:
    """Typed proof that a workspace is reachable with zero owned processes."""

    canonical_workspace: str
    logical_workspace: str
    mapping_verified: bool
    environment_reachable: bool
    zero_owned_processes_verified: bool


class SnapshotFailureSubtypeV1(str, Enum):
    """Closed, secret-free failure boundary for owned workspace capture."""

    OWNED_STAGE_SETUP_FAILED = "owned_stage_setup_failed"
    COMMAND_UPLOAD_FAILED = "command_upload_failed"
    LAUNCH_FAILED = "launch_failed"
    LEASE_PARSE_FAILED = "lease_parse_failed"
    LEASE_RELEASE_FAILED = "lease_release_failed"
    WAIT_TRANSPORT_FAILED = "wait_transport_failed"
    WAIT_RESPONSE_INVALID = "wait_response_invalid"
    TERMINAL_RECORD_INVALID = "terminal_record_invalid"
    OUTPUT_DOWNLOAD_FAILED = "output_download_failed"
    HOST_EVIDENCE_PARSE_FAILED = "host_evidence_parse_failed"
    HOST_EVIDENCE_MATERIALIZATION_FAILED = "host_evidence_materialization_failed"
    RECOVERY_UNVERIFIED = "recovery_unverified"
    STAGE_CLEANUP_FAILED = "stage_cleanup_failed"
    UNKNOWN_INTERNAL = "unknown_internal"


class SnapshotTimeoutOriginV1(str, Enum):
    """Closed timeout provenance; never inferred from persisted legacy text."""

    NOT_A_TIMEOUT = "not_a_timeout"
    SEMANTIC_EXECUTION_TIMED_OUT = "semantic_execution_timed_out"
    WAIT_TRANSPORT_TIMED_OUT_RECOVERED = "wait_transport_timed_out_recovered"
    WAIT_TRANSPORT_TIMED_OUT_UNRECOVERED = "wait_transport_timed_out_unrecovered"


class SnapshotFailureReasonV1(str, Enum):
    """Closed mechanical discriminants within a snapshot failure boundary."""

    OUTER_RETURN_CODE_TYPE_INVALID = "outer_return_code_type_invalid"
    OUTER_RETURN_CODE_NONZERO = "outer_return_code_nonzero"
    OUTER_STDOUT_TYPE_INVALID = "outer_stdout_type_invalid"
    OUTER_STDERR_TYPE_INVALID = "outer_stderr_type_invalid"
    OUTER_STDERR_NONEMPTY = "outer_stderr_nonempty"
    TERMINAL_JSON_INVALID = "terminal_json_invalid"
    TERMINAL_KEYSET_INVALID = "terminal_keyset_invalid"
    TERMINAL_FIELD_TYPE_INVALID = "terminal_field_type_invalid"
    TERMINAL_STATUS_INVALID = "terminal_status_invalid"
    TERMINAL_IDENTITY_MISMATCH = "terminal_identity_mismatch"
    TERMINATION_PROOF_INVALID = "termination_proof_invalid"
    TERMINAL_CANCELLED = "terminal_cancelled"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SnapshotFailureEvidenceV1:
    """Immutable ownership evidence carried between actor and receipt writer."""

    subtype: SnapshotFailureSubtypeV1
    timeout_origin: SnapshotTimeoutOriginV1 = SnapshotTimeoutOriginV1.NOT_A_TIMEOUT
    stage_validated: bool = False
    termination_verified: bool = False
    cleanup_verified: bool = False
    zero_census_verified: bool = False
    execution_binding_verified: bool = False
    reason: SnapshotFailureReasonV1 = SnapshotFailureReasonV1.NOT_APPLICABLE
    observed_byte_length: int | None = None
    observed_sha256: str | None = None


class SnapshotOperationFailure(RuntimeError):
    """Stable exact operational failure; the original exception stays a cause."""

    code = "terminal_actor_snapshot_operation_failed"

    def __init__(
        self,
        evidence: SnapshotFailureEvidenceV1 | SnapshotFailureSubtypeV1,
        *,
        timeout_origin: SnapshotTimeoutOriginV1 = SnapshotTimeoutOriginV1.NOT_A_TIMEOUT,
        stage_validated: bool = False,
        termination_verified: bool = False,
        cleanup_verified: bool = False,
        zero_census_verified: bool = False,
        execution_binding_verified: bool = False,
        reason: SnapshotFailureReasonV1 = SnapshotFailureReasonV1.NOT_APPLICABLE,
        observed_byte_length: int | None = None,
        observed_sha256: str | None = None,
        return_code: int | None = None,
    ) -> None:
        RuntimeError.__init__(self, self.code)
        self.return_code = return_code if type(return_code) is int else None
        self.evidence = (
            evidence
            if isinstance(evidence, SnapshotFailureEvidenceV1)
            else SnapshotFailureEvidenceV1(
                evidence,
                timeout_origin=timeout_origin,
                stage_validated=stage_validated,
                termination_verified=termination_verified,
                cleanup_verified=cleanup_verified,
                zero_census_verified=zero_census_verified,
                execution_binding_verified=(execution_binding_verified is True),
                reason=reason,
                observed_byte_length=observed_byte_length,
                observed_sha256=observed_sha256,
            )
        )


class SnapshotTransportTimeout(TimeoutError):
    """Stable snapshot-only timeout raised by the remote environment wrapper."""

    code = "terminal_actor_snapshot_transport_timeout"

    def __init__(
        self,
        *,
        termination_verified: bool = False,
        census_verified: bool = False,
        survivor_count: int | None = None,
        subtype: SnapshotFailureSubtypeV1 = (
            SnapshotFailureSubtypeV1.WAIT_TRANSPORT_FAILED
        ),
        timeout_origin: SnapshotTimeoutOriginV1 = (
            SnapshotTimeoutOriginV1.WAIT_TRANSPORT_TIMED_OUT_UNRECOVERED
        ),
        stage_validated: bool = False,
        cleanup_verified: bool = False,
        zero_census_verified: bool | None = None,
        execution_binding_verified: bool = False,
    ) -> None:
        super().__init__(self.code)
        zero_verified = (
            census_verified is True and survivor_count == 0
            if zero_census_verified is None
            else zero_census_verified is True
        )
        self.evidence = SnapshotFailureEvidenceV1(
            subtype,
            timeout_origin=timeout_origin,
            stage_validated=stage_validated,
            termination_verified=termination_verified,
            cleanup_verified=cleanup_verified,
            zero_census_verified=zero_verified,
            execution_binding_verified=(execution_binding_verified is True),
        )


class SnapshotTerminationUnverified(RuntimeError):
    """Stable fatal error when exact snapshot execution cleanup is unknown."""

    code = "terminal_actor_snapshot_termination_unverified"

    def __init__(
        self,
        evidence: SnapshotFailureEvidenceV1 | SnapshotFailureSubtypeV1 | None = None,
        *,
        stage_validated: bool = False,
    ) -> None:
        RuntimeError.__init__(self, self.code)
        self.evidence = (
            evidence
            if isinstance(evidence, SnapshotFailureEvidenceV1)
            else SnapshotFailureEvidenceV1(
                evidence or SnapshotFailureSubtypeV1.RECOVERY_UNVERIFIED,
                stage_validated=stage_validated,
            )
        )


class SnapshotOperationCancelled(asyncio.CancelledError):
    code = "terminal_actor_snapshot_operation_cancelled"

    def __init__(self, evidence: SnapshotFailureEvidenceV1) -> None:
        asyncio.CancelledError.__init__(self, self.code)
        self.evidence = evidence


def _bounded_snapshot_observation(value: object) -> tuple[int | None, str | None]:
    if type(value) is not str:
        return None, None
    try:
        payload = value.encode("utf-8")
    except UnicodeEncodeError:
        return None, None
    if len(payload) > _SNAPSHOT_OUTPUT_CAP_BYTES:
        return None, None
    return len(payload), hashlib.sha256(payload).hexdigest()


def _validate_snapshot_outer_result(
    result: object,
    *,
    boundary_subtype: SnapshotFailureSubtypeV1,
) -> SnapshotCommandResult:
    """Validate one provider result in the fixed outer-discriminant order."""

    try:
        selected_subtype = SnapshotFailureSubtypeV1(boundary_subtype)
    except (TypeError, ValueError):
        selected_subtype = SnapshotFailureSubtypeV1.UNKNOWN_INTERNAL
    return_code = getattr(result, "return_code", None)
    stdout = getattr(result, "stdout", None)
    stderr = getattr(result, "stderr", None)

    reason: SnapshotFailureReasonV1 | None = None
    observed: object = None
    if type(return_code) is not int:
        reason = SnapshotFailureReasonV1.OUTER_RETURN_CODE_TYPE_INVALID
    elif return_code != 0:
        reason = SnapshotFailureReasonV1.OUTER_RETURN_CODE_NONZERO
        observed = stderr if type(stderr) is str and stderr else stdout
    elif type(stdout) is not str:
        reason = SnapshotFailureReasonV1.OUTER_STDOUT_TYPE_INVALID
    elif type(stderr) is not str:
        reason = SnapshotFailureReasonV1.OUTER_STDERR_TYPE_INVALID
    elif stderr:
        reason = SnapshotFailureReasonV1.OUTER_STDERR_NONEMPTY
        observed = stderr

    if reason is not None:
        observed_byte_length, observed_sha256 = _bounded_snapshot_observation(observed)
        raise SnapshotOperationFailure(
            SnapshotFailureEvidenceV1(
                subtype=selected_subtype,
                reason=reason,
                observed_byte_length=observed_byte_length,
                observed_sha256=observed_sha256,
            ),
            return_code=return_code,
        )
    return SnapshotCommandResult(
        return_code=return_code,
        stdout=stdout,
        stderr=stderr,
        termination_verified=(getattr(result, "termination_verified", False) is True),
        census_verified=getattr(result, "census_verified", False) is True,
        survivor_count=(
            getattr(result, "survivor_count", None)
            if type(getattr(result, "survivor_count", None)) is int
            else None
        ),
    )


class _SnapshotDeadlineExceeded(TimeoutError):
    """An actor-enforced absolute snapshot phase cutoff."""


class _ActorDoneDeadlineExceeded(TimeoutError):
    """The one signed foreground actor cutoff has no remaining time."""


@dataclass(frozen=True)
class _SnapshotLease:
    control_dir: str
    owner_token: str
    leader_pid: int
    leader_starttime: int
    pgid: int
    supervisor_pid: int
    supervisor_starttime: int
    supervisor_pgid: int


_SNAPSHOT_EXECUTION_BINDING_TOKEN = object()


class _BoundSnapshotTerminalV1(Mapping[str, Any]):
    """Immutable terminal record minted only after lease-bound proof validation."""

    __slots__ = ("_record", "_token")

    def __init__(
        self,
        record: Mapping[str, Any],
        *,
        token: object,
    ) -> None:
        if token is not _SNAPSHOT_EXECUTION_BINDING_TOKEN:
            raise TypeError("terminal_actor_snapshot_binding_invalid")
        self._record = MappingProxyType(dict(record))
        self._token = token

    def __getitem__(self, key: str) -> Any:
        return self._record[key]

    def __iter__(self):
        return iter(self._record)

    def __len__(self) -> int:
        return len(self._record)

    @property
    def execution_binding_verified(self) -> bool:
        return self._token is _SNAPSHOT_EXECUTION_BINDING_TOKEN


def _snapshot_execution_binding_verified(terminal: object) -> bool:
    return (
        type(terminal) is _BoundSnapshotTerminalV1
        and terminal.execution_binding_verified is True
    )


@dataclass(frozen=True)
class _MediaSourceSnapshot:
    logical_path: str
    byte_length: int
    sha256: str
    device: int
    inode: int
    has_symlink: bool


_ACTOR = r"""#!/bin/bash
set -u

mode=$1
request_dir=$2

seconds_from_ms() {
  printf '%d.%03d' "$(($1 / 1000))" "$(($1 % 1000))"
}

group_alive() {
  local target_pgid=$1
  if [ -d /proc/1 ]; then
    local stat raw fields state process_group
    for stat in /proc/[0-9]*/stat; do
      test -r "$stat" || continue
      IFS= read -r raw < "$stat" || continue
      fields=${raw##*) }
      set -- $fields
      state=${1-}
      process_group=${3-}
      if [ "$process_group" = "$target_pgid" ] &&
        [ "$state" != "Z" ] && [ "$state" != "X" ]; then
        return 0
      fi
    done
    return 1
  fi
  kill -0 -- "-$1" 2>/dev/null
}

wait_for_group_exit() {
  local pgid=$1
  local timeout_ms=$2
  local loops=$(((timeout_ms + 49) / 50))
  local index=0
  while group_alive "$pgid" && [ "$index" -lt "$loops" ]; do
    sleep 0.05
    index=$((index + 1))
  done
  ! group_alive "$pgid"
}

positive_process_group() {
  local value=$1
  case "$value" in (''|*[!0-9]*) return 1;; esac
  [ "$value" -gt 1 ] 2>/dev/null
}

positive_process_identity() {
  local value=$1
  case "$value" in (''|*[!0-9]*) return 1;; esac
  [ "$value" -gt 0 ] 2>/dev/null
}

background_groups_alive() {
  local pgid=$1
  local monitor_pgid=$2
  if group_alive "$pgid"; then
    return 0
  fi
  if [ "$monitor_pgid" != "$pgid" ] && group_alive "$monitor_pgid"; then
    return 0
  fi
  return 1
}

wait_for_background_groups_exit() {
  local pgid=$1
  local monitor_pgid=$2
  local timeout_ms=$3
  local loops=$(((timeout_ms + 49) / 50))
  local index=0
  while background_groups_alive "$pgid" "$monitor_pgid" &&
    [ "$index" -lt "$loops" ]; do
    sleep 0.05
    index=$((index + 1))
  done
  ! background_groups_alive "$pgid" "$monitor_pgid"
}

read_expected_background_identity() {
  local path=$1
  local expected=$2
  local value
  test -f "$path" || return 1
  test ! -L "$path" || return 1
  IFS= read -r value < "$path" || return 1
  positive_process_group "$value" || return 1
  test "$value" = "$expected" || return 1
  printf '%s\n' "$value"
}

read_expected_background_starttime() {
  local path=$1
  local expected=$2
  local value
  test -f "$path" || return 1
  test ! -L "$path" || return 1
  IFS= read -r value < "$path" || return 1
  positive_process_identity "$value" || return 1
  test "$value" = "$expected" || return 1
  printf '%s\n' "$value"
}

valid_owner_token() {
  local value=$1
  case "$value" in (''|*[!0-9a-f]*) return 1;; esac
  test "${#value}" -eq 64
}

read_expected_background_owner() {
  local path=$1
  local expected=$2
  local value
  test -f "$path" || return 1
  test ! -L "$path" || return 1
  IFS= read -r value < "$path" || return 1
  valid_owner_token "$value" || return 1
  test "$value" = "$expected" || return 1
  printf '%s\n' "$value"
}

owner_scan_available() {
  test -d /proc/1 &&
    test -r /proc/self/stat &&
    test -r /proc/self/environ
}

owned_pids() {
  local owner_token=$1
  local scan_pid=${BASHPID:-$$}
  local environ pid raw fields state
  for environ in /proc/[0-9]*/environ; do
    test -r "$environ" || continue
    if tr '\0' '\n' < "$environ" 2>/dev/null |
      grep -Fqx -- "NANO_NGB_OWNER=$owner_token"; then
      pid=${environ#/proc/}
      pid=${pid%/environ}
      test "$pid" != "$$" || continue
      test "$pid" != "$scan_pid" || continue
      if test -r "/proc/$pid/stat"; then
        IFS= read -r raw < "/proc/$pid/stat" || continue
        fields=${raw##*) }
        set -- $fields
        state=${1-}
        test "$state" != "Z" && test "$state" != "X" || continue
      fi
      printf '%s\n' "$pid"
    fi
  done
}

owner_alive() {
  owner_scan_available || return 2
  test -n "$(owned_pids "$1")"
}

signal_owned() {
  local signal=$1
  local owner_token=$2
  local pid
  owner_scan_available || return 1
  while IFS= read -r pid; do
    test -n "$pid" || continue
    kill "-$signal" "$pid" 2>/dev/null || true
  done < <(owned_pids "$owner_token")
}

wait_for_owner_exit() {
  local owner_token=$1
  local timeout_ms=$2
  local loops=$(((timeout_ms + 49) / 50))
  local index=0
  local alive_status
  owner_scan_available || return 1
  while :; do
    owner_alive "$owner_token"
    alive_status=$?
    if [ "$alive_status" -eq 1 ]; then
      return 0
    fi
    if [ "$alive_status" -ne 0 ] || [ "$index" -ge "$loops" ]; then
      return 1
    fi
    sleep 0.05
    index=$((index + 1))
  done
}

background_identity_alive() {
  local pgid=$1
  local leader_starttime=$2
  local monitor_pgid=$3
  local monitor_starttime=$4
  local owner_token=$5
  local leader_status monitor_status owner_status
  owner_scan_available || return 2
  background_pid_identity_state \
    "$pgid" "$leader_starttime" "$pgid" "$owner_token" true
  leader_status=$?
  background_pid_identity_state \
    "$monitor_pgid" "$monitor_starttime" "$monitor_pgid" \
    "$owner_token" true
  monitor_status=$?
  if [ "$leader_status" -eq 2 ] || [ "$monitor_status" -eq 2 ]; then
    return 2
  fi
  if [ "$leader_status" -eq 0 ] || [ "$monitor_status" -eq 0 ]; then
    return 0
  fi
  owner_alive "$owner_token"
  owner_status=$?
  if [ "$owner_status" -eq 0 ]; then
    return 0
  fi
  if [ "$owner_status" -eq 1 ]; then
    return 1
  fi
  return 2
}

wait_for_background_identity_exit() {
  local pgid=$1
  local leader_starttime=$2
  local monitor_pgid=$3
  local monitor_starttime=$4
  local owner_token=$5
  local timeout_ms=$6
  local loops=$(((timeout_ms + 49) / 50))
  local index=0
  local stable_absent=0
  local alive_status
  owner_scan_available || return 1
  while :; do
    background_identity_alive \
      "$pgid" "$leader_starttime" "$monitor_pgid" "$monitor_starttime" \
      "$owner_token"
    alive_status=$?
    if [ "$alive_status" -eq 1 ]; then
      stable_absent=$((stable_absent + 1))
      if [ "$stable_absent" -ge 3 ]; then
        return 0
      fi
    elif [ "$alive_status" -eq 0 ]; then
      stable_absent=0
    else
      return 1
    fi
    if [ "$index" -ge "$loops" ]; then
      return 1
    fi
    sleep 0.05
    index=$((index + 1))
  done
}

pid_alive() {
  local pid=$1
  local raw fields state
  test -r "/proc/$pid/stat" || return 1
  IFS= read -r raw < "/proc/$pid/stat" || return 1
  fields=${raw##*) }
  set -- $fields
  state=${1-}
  test "$state" != "Z" && test "$state" != "X"
}

wait_for_pid_exit() {
  local pid=$1
  local timeout_ms=$2
  local loops=$(((timeout_ms + 49) / 50))
  local index=0
  while pid_alive "$pid" && [ "$index" -lt "$loops" ]; do
    sleep 0.05
    index=$((index + 1))
  done
  ! pid_alive "$pid"
}

snapshot_proc_identity() {
  local pid=$1
  local raw fields state process_group starttime
  test -r "/proc/$pid/stat" || return 1
  IFS= read -r raw < "/proc/$pid/stat" || return 1
  fields=${raw##*) }
  set -- $fields
  state=${1-}
  process_group=${3-}
  starttime=${20-}
  case "$process_group:$starttime" in (*[!0-9:]*|:|*:0|0:*) return 1;; esac
  test "$state" != "Z" && test "$state" != "X" || return 1
  printf '%s %s\n' "$starttime" "$process_group"
}

snapshot_pid_identity_matches() {
  local pid=$1
  local expected_starttime=$2
  local expected_pgid=$3
  local current current_starttime current_pgid
  current=$(snapshot_proc_identity "$pid") || return 1
  read -r current_starttime current_pgid <<< "$current"
  test "$current_starttime" = "$expected_starttime" &&
    test "$current_pgid" = "$expected_pgid"
}

snapshot_pid_identity_state() {
  local pid=$1
  local expected_starttime=$2
  local expected_pgid=$3
  local current current_starttime current_pgid
  current=$(snapshot_proc_identity "$pid") || return 1
  read -r current_starttime current_pgid <<< "$current"
  if test "$current_starttime" != "$expected_starttime" ||
    test "$current_pgid" != "$expected_pgid"; then
    return 2
  fi
  return 0
}

snapshot_pid_has_owner() {
  local pid=$1
  local owner_token=$2
  test -r "/proc/$pid/environ" || return 1
  tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null |
    grep -Fqx -- "NANO_NGB_OWNER=$owner_token"
}

background_pid_identity_state() {
  local pid=$1
  local expected_starttime=$2
  local expected_pgid=$3
  local owner_token=$4
  local require_owner=$5
  if ! pid_alive "$pid"; then
    return 1
  fi
  snapshot_pid_identity_matches \
    "$pid" "$expected_starttime" "$expected_pgid" || return 2
  if [ "$require_owner" = "true" ]; then
    snapshot_pid_has_owner "$pid" "$owner_token" || return 2
  fi
  return 0
}

background_signal_identity() {
  local signal_name=$1
  local pgid=$2
  local leader_starttime=$3
  local monitor_pgid=$4
  local monitor_starttime=$5
  local owner_token=$6
  local leader_status monitor_status mismatch=false
  background_pid_identity_state \
    "$pgid" "$leader_starttime" "$pgid" "$owner_token" true
  leader_status=$?
  background_pid_identity_state \
    "$monitor_pgid" "$monitor_starttime" "$monitor_pgid" \
    "$owner_token" true
  monitor_status=$?
  if [ "$leader_status" -eq 0 ]; then
    kill "-$signal_name" -- "-$pgid" 2>/dev/null || true
  elif [ "$leader_status" -eq 2 ]; then
    mismatch=true
  fi
  if [ "$monitor_status" -eq 0 ] && [ "$monitor_pgid" != "$pgid" ]; then
    kill "-$signal_name" -- "-$monitor_pgid" 2>/dev/null || true
  elif [ "$monitor_status" -eq 2 ]; then
    mismatch=true
  fi
  signal_owned "$signal_name" "$owner_token" || return 3
  test "$mismatch" = "false"
}

snapshot_group_has_owner() {
  local pgid=$1
  local owner_token=$2
  local pid raw fields process_group
  while IFS= read -r pid; do
    test -n "$pid" || continue
    test -r "/proc/$pid/stat" || continue
    IFS= read -r raw < "/proc/$pid/stat" || continue
    fields=${raw##*) }
    set -- $fields
    process_group=${3-}
    if [ "$process_group" = "$pgid" ]; then
      return 0
    fi
  done < <(owned_pids "$owner_token")
  return 1
}

snapshot_survivor_count() {
  local pgid=$1
  local owner_token=$2
  local stat pid raw fields state process_group
  {
    for stat in /proc/[0-9]*/stat; do
      test -r "$stat" || continue
      IFS= read -r raw < "$stat" || continue
      fields=${raw##*) }
      set -- $fields
      state=${1-}
      process_group=${3-}
      if [ "$process_group" = "$pgid" ] &&
        [ "$state" != "Z" ] && [ "$state" != "X" ]; then
        pid=${stat#/proc/}
        printf '%s\n' "${pid%/stat}"
      fi
    done
    owned_pids "$owner_token"
  } | sort -un | awk 'NF { count += 1 } END { print count + 0 }'
}

snapshot_identity_files_match() {
  local expected_token=$1
  local expected_pid=$2
  local expected_starttime=$3
  local expected_pgid=$4
  local expected_supervisor_pid=$5
  local expected_supervisor_starttime=$6
  local expected_supervisor_pgid=$7
  local value
  for name in owner_token leader_pid leader_starttime pgid \
    supervisor_pid supervisor_starttime supervisor_pgid; do
    test -f "$request_dir/$name" || return 1
  done
  IFS= read -r value < "$request_dir/owner_token"
  test "$value" = "$expected_token" || return 1
  IFS= read -r value < "$request_dir/leader_pid"
  test "$value" = "$expected_pid" || return 1
  IFS= read -r value < "$request_dir/leader_starttime"
  test "$value" = "$expected_starttime" || return 1
  IFS= read -r value < "$request_dir/pgid"
  test "$value" = "$expected_pgid" || return 1
  IFS= read -r value < "$request_dir/supervisor_pid"
  test "$value" = "$expected_supervisor_pid" || return 1
  IFS= read -r value < "$request_dir/supervisor_starttime"
  test "$value" = "$expected_supervisor_starttime" || return 1
  IFS= read -r value < "$request_dir/supervisor_pgid"
  test "$value" = "$expected_supervisor_pgid"
}

if [ "$mode" = "cleanup-signal" ]; then
  process_kind=$3
  signal_name=$4
  case "$signal_name" in (TERM|KILL) ;; (*) exit 72;; esac
  if [ "$process_kind" = "foreground" ]; then
    test -f "$request_dir/pgid" || exit 71
    test -f "$request_dir/owner_token" || exit 71
    IFS= read -r pgid < "$request_dir/pgid"
    IFS= read -r owner_token < "$request_dir/owner_token"
    case "$pgid" in (*[!0-9]*|'') exit 72;; esac
    case "$owner_token" in (*[!0-9a-f]*|'') exit 72;; esac
    kill "-$signal_name" -- "-$pgid" 2>/dev/null || true
    signal_owned "$signal_name" "$owner_token"
  elif [ "$process_kind" = "background" ]; then
    expected_pgid=$5
    expected_leader_starttime=$6
    expected_monitor_pgid=$7
    expected_monitor_starttime=$8
    expected_owner_token=$9
    positive_process_group "$expected_pgid" || exit 72
    positive_process_identity "$expected_leader_starttime" || exit 72
    positive_process_group "$expected_monitor_pgid" || exit 72
    positive_process_identity "$expected_monitor_starttime" || exit 72
    valid_owner_token "$expected_owner_token" || exit 72
    pgid=$(read_expected_background_identity \
      "$request_dir/pgid" "$expected_pgid") || exit 71
    leader_starttime=$(read_expected_background_starttime \
      "$request_dir/leader_starttime" "$expected_leader_starttime") || exit 71
    monitor_pgid=$(read_expected_background_identity \
      "$request_dir/monitor_pgid" "$expected_monitor_pgid") || exit 71
    monitor_starttime=$(read_expected_background_starttime \
      "$request_dir/monitor_starttime" "$expected_monitor_starttime") || exit 71
    owner_token=$(read_expected_background_owner \
      "$request_dir/owner_token" "$expected_owner_token") || exit 71
    owner_scan_available || exit 74
    : > "$request_dir/.explicit_kill.tmp"
    mv -f -- "$request_dir/.explicit_kill.tmp" "$request_dir/explicit_kill"
    background_signal_identity \
      "$signal_name" "$pgid" "$leader_starttime" "$monitor_pgid" \
      "$monitor_starttime" "$owner_token" || exit 74
  else
    exit 72
  fi
  printf 'signal-ok\n'
  exit 0
fi

if [ "$mode" = "cleanup-census" ]; then
  process_kind=$3
  survivor_count=0
  if [ "$process_kind" = "foreground" ]; then
    test -f "$request_dir/pgid" || exit 71
    test -f "$request_dir/owner_token" || exit 71
    IFS= read -r pgid < "$request_dir/pgid"
    IFS= read -r owner_token < "$request_dir/owner_token"
    case "$pgid" in (*[!0-9]*|'') exit 72;; esac
    case "$owner_token" in (*[!0-9a-f]*|'') exit 72;; esac
    if group_alive "$pgid" || owner_alive "$owner_token"; then
      survivor_count=1
    fi
  elif [ "$process_kind" = "background" ]; then
    expected_pgid=$4
    expected_leader_starttime=$5
    expected_monitor_pgid=$6
    expected_monitor_starttime=$7
    expected_owner_token=$8
    positive_process_group "$expected_pgid" || exit 72
    positive_process_identity "$expected_leader_starttime" || exit 72
    positive_process_group "$expected_monitor_pgid" || exit 72
    positive_process_identity "$expected_monitor_starttime" || exit 72
    valid_owner_token "$expected_owner_token" || exit 72
    pgid=$(read_expected_background_identity \
      "$request_dir/pgid" "$expected_pgid") || exit 71
    leader_starttime=$(read_expected_background_starttime \
      "$request_dir/leader_starttime" "$expected_leader_starttime") || exit 71
    monitor_pgid=$(read_expected_background_identity \
      "$request_dir/monitor_pgid" "$expected_monitor_pgid") || exit 71
    monitor_starttime=$(read_expected_background_starttime \
      "$request_dir/monitor_starttime" "$expected_monitor_starttime") || exit 71
    owner_token=$(read_expected_background_owner \
      "$request_dir/owner_token" "$expected_owner_token") || exit 71
    background_identity_alive \
      "$pgid" "$leader_starttime" "$monitor_pgid" "$monitor_starttime" \
      "$owner_token"
    alive_status=$?
    if [ "$alive_status" -eq 0 ]; then
      survivor_count=1
    elif [ "$alive_status" -ne 1 ]; then
      exit 74
    fi
  else
    exit 72
  fi
  if [ "$survivor_count" -eq 0 ]; then
    printf '{"verified":true,"survivor_count":0}\n'
    exit 0
  fi
  printf '{"verified":true,"survivor_count":1}\n'
  exit 73
fi

if [ "$mode" = "cleanup" ]; then
  grace_ms=$3
  confirmation_ms=$4
  test -f "$request_dir/pgid" || exit 71
  IFS= read -r pgid < "$request_dir/pgid"
  test -f "$request_dir/owner_token" || exit 71
  IFS= read -r owner_token < "$request_dir/owner_token"
  case "$pgid" in (*[!0-9]*|'') exit 72;; esac
  case "$owner_token" in (*[!0-9a-f]*|'') exit 72;; esac
  if group_alive "$pgid" || owner_alive "$owner_token"; then
    kill -TERM -- "-$pgid" 2>/dev/null || true
    signal_owned TERM "$owner_token"
    sleep "$(seconds_from_ms "$grace_ms")"
  fi
  if group_alive "$pgid" || owner_alive "$owner_token"; then
    kill -KILL -- "-$pgid" 2>/dev/null || true
    signal_owned KILL "$owner_token"
  fi
  if wait_for_group_exit "$pgid" "$confirmation_ms" &&
    wait_for_owner_exit "$owner_token" "$confirmation_ms"; then
    printf 'cleanup-ok\n'
    exit 0
  fi
  exit 73
fi

if [ "$mode" = "snapshot-supervise" ]; then
  logical_cwd=$3
  timeout_ms=$4
  grace_ms=$5
  confirmation_ms=$6
  owner_token=$7
  output_cap=$8
  case "$timeout_ms:$grace_ms:$confirmation_ms:$output_cap" in
    (*[!0-9:]*|:*|*::*) exit 82;;
  esac
  case "$owner_token" in (*[!0-9a-f]*|'') exit 82;; esac
  test "${#owner_token}" -eq 64 || exit 82
  cd "$logical_cwd" || exit 83

  supervisor_pid=$$
  supervisor_identity=$(snapshot_proc_identity "$supervisor_pid") || exit 84
  read -r supervisor_starttime supervisor_pgid <<< "$supervisor_identity"
  test "$supervisor_pid" = "$supervisor_pgid" || exit 84

  mkfifo "$request_dir/stdout.fifo" "$request_dir/stderr.fifo"
  tee -p \
    >(head -c "$output_cap" > "$request_dir/stdout.bin") \
    >(wc -c > "$request_dir/stdout.size") \
    >/dev/null < "$request_dir/stdout.fifo" 2>/dev/null &
  stdout_drain=$!
  tee -p \
    >(head -c "$output_cap" > "$request_dir/stderr.bin") \
    >(wc -c > "$request_dir/stderr.size") \
    >/dev/null < "$request_dir/stderr.fifo" 2>/dev/null &
  stderr_drain=$!

  setsid env -i \
    HOME="${HOME-}" \
    LANG="${LANG-}" \
    LC_ALL="${LC_ALL-}" \
    PATH="${PATH-}" \
    TERM="${TERM-}" \
    TMPDIR="${TMPDIR-}" \
    USER="${USER-}" \
    NANO_NGB_OWNER="$owner_token" \
    /bin/bash -c '
      request_dir=$1
      while ! test -f "$request_dir/release"; do
        if test -f "$request_dir/cancel_intent"; then
          exit 125
        fi
        sleep 0.02
      done
      exec /bin/bash "$request_dir/command.sh"
    ' snapshot-gate "$request_dir" \
    >"$request_dir/stdout.fifo" 2>"$request_dir/stderr.fifo" < /dev/null &
  leader_pid=$!
  leader_ready=false
  for _ in $(seq 1 250); do
    if leader_identity=$(snapshot_proc_identity "$leader_pid"); then
      read -r leader_starttime pgid <<< "$leader_identity"
      if [ "$leader_pid" = "$pgid" ] &&
        snapshot_pid_has_owner "$leader_pid" "$owner_token"; then
        leader_ready=true
        break
      fi
    fi
    pid_alive "$leader_pid" || exit 84
    sleep 0.02
  done
  test "$leader_ready" = "true" || exit 84

  for pair in \
    "owner_token:$owner_token" \
    "leader_pid:$leader_pid" \
    "leader_starttime:$leader_starttime" \
    "pgid:$pgid" \
    "supervisor_pid:$supervisor_pid" \
    "supervisor_starttime:$supervisor_starttime" \
    "supervisor_pgid:$supervisor_pgid"; do
    name=${pair%%:*}
    value=${pair#*:}
    printf '%s\n' "$value" > "$request_dir/.${name}.tmp"
    sync "$request_dir/.${name}.tmp" 2>/dev/null || true
    mv -f -- "$request_dir/.${name}.tmp" "$request_dir/$name"
  done
  lease_format='{"version":1,"status":"running","owner_token":"%s"'
  lease_format="${lease_format}"',"leader_pid":%s,"leader_starttime":%s,"pgid":%s'
  lease_format="${lease_format}"',"supervisor_pid":%s'
  lease_format="${lease_format}"',"supervisor_starttime":%s'
  lease_format="${lease_format}"',"supervisor_pgid":%s}'
  printf "${lease_format}\n" \
    "$owner_token" "$leader_pid" "$leader_starttime" "$pgid" \
    "$supervisor_pid" "$supervisor_starttime" "$supervisor_pgid" \
    > "$request_dir/.lease.json.tmp"
  sync "$request_dir/.lease.json.tmp" 2>/dev/null || true
  mv -f -- "$request_dir/.lease.json.tmp" "$request_dir/lease.json"

  timed_out=false
  cancelled=false
  term_sent=false
  kill_sent=false
  remaining_ms=$timeout_ms
  while group_alive "$pgid" || owner_alive "$owner_token"; do
    if test -f "$request_dir/cancel_requested" || {
      test -f "$request_dir/cancel_intent" &&
        ! test -f "$request_dir/release"
    }; then
      cancelled=true
      break
    fi
    if ! test -f "$request_dir/release"; then
      sleep 0.02
      continue
    fi
    if [ "$remaining_ms" -le 0 ]; then
      timed_out=true
      break
    fi
    step_ms=50
    if [ "$remaining_ms" -lt "$step_ms" ]; then
      step_ms=$remaining_ms
    fi
    sleep "$(seconds_from_ms "$step_ms")"
    remaining_ms=$((remaining_ms - step_ms))
  done

  identity_valid=true
  if pid_alive "$leader_pid"; then
    if ! snapshot_pid_identity_matches \
      "$leader_pid" "$leader_starttime" "$pgid" ||
      ! snapshot_pid_has_owner "$leader_pid" "$owner_token"; then
      identity_valid=false
    fi
  elif (group_alive "$pgid" || owner_alive "$owner_token") &&
    ! snapshot_group_has_owner "$pgid" "$owner_token"; then
    identity_valid=false
  fi

  if [ "$identity_valid" = "true" ] &&
    (group_alive "$pgid" || owner_alive "$owner_token"); then
    term_sent=true
    kill -TERM -- "-$pgid" 2>/dev/null || true
    signal_owned TERM "$owner_token"
    wait_for_group_exit "$pgid" "$grace_ms" || true
    wait_for_owner_exit "$owner_token" "$grace_ms" || true
  fi
  if [ "$identity_valid" = "true" ] &&
    (group_alive "$pgid" || owner_alive "$owner_token"); then
    kill_sent=true
    kill -KILL -- "-$pgid" 2>/dev/null || true
    signal_owned KILL "$owner_token"
  fi

  survivor_count=$(snapshot_survivor_count "$pgid" "$owner_token")
  termination_verified=false
  census_verified=false
  if [ "$identity_valid" = "true" ] &&
    wait_for_group_exit "$pgid" "$confirmation_ms" &&
    wait_for_owner_exit "$owner_token" "$confirmation_ms"; then
    survivor_count=$(snapshot_survivor_count "$pgid" "$owner_token")
    if [ "$survivor_count" -eq 0 ]; then
      termination_verified=true
      census_verified=true
    fi
  fi

  if [ "$termination_verified" != "true" ]; then
    terminal_format='{"version":1,"status":"termination_unverified"'
    terminal_format="${terminal_format}"',"owner_token":"%s","leader_pid":%s'
    terminal_format="${terminal_format}"',"leader_starttime":%s,"pgid":%s'
    terminal_format="${terminal_format}"',"supervisor_pid":%s'
    terminal_format="${terminal_format}"',"supervisor_starttime":%s'
    terminal_format="${terminal_format}"',"supervisor_pgid":%s'
    terminal_format="${terminal_format}"',"return_code":70,"timed_out":%s'
    terminal_format="${terminal_format}"',"term_sent":%s,"kill_sent":%s'
    terminal_format="${terminal_format}"',"termination_verified":false'
    terminal_format="${terminal_format}"',"census_verified":false'
    terminal_format="${terminal_format}"',"survivor_count":%s}'
    printf "${terminal_format}\n" \
      "$owner_token" "$leader_pid" "$leader_starttime" "$pgid" \
      "$supervisor_pid" "$supervisor_starttime" "$supervisor_pgid" \
      "$timed_out" "$term_sent" "$kill_sent" "$survivor_count" \
      > "$request_dir/.terminal.json.tmp"
    mv -f -- "$request_dir/.terminal.json.tmp" "$request_dir/terminal.json"
    exit 90
  fi

  wait "$leader_pid" 2>/dev/null
  return_code=$?
  wait "$stdout_drain" 2>/dev/null || true
  wait "$stderr_drain" 2>/dev/null || true
  status=failed
  if [ "$cancelled" = "true" ]; then
    status=cancelled
    return_code=125
  elif [ "$timed_out" = "true" ]; then
    status=timed_out
    return_code=124
  elif [ "$return_code" -eq 0 ]; then
    status=completed
  fi
  terminal_format='{"version":1,"status":"%s","owner_token":"%s"'
  terminal_format="${terminal_format}"',"leader_pid":%s,"leader_starttime":%s'
  terminal_format="${terminal_format}"',"pgid":%s,"supervisor_pid":%s'
  terminal_format="${terminal_format}"',"supervisor_starttime":%s'
  terminal_format="${terminal_format}"',"supervisor_pgid":%s'
  terminal_format="${terminal_format}"',"return_code":%s,"timed_out":%s'
  terminal_format="${terminal_format}"',"term_sent":%s,"kill_sent":%s'
  terminal_format="${terminal_format}"',"termination_verified":true'
  terminal_format="${terminal_format}"',"census_verified":true'
  terminal_format="${terminal_format}"',"survivor_count":0}'
  printf "${terminal_format}\n" \
    "$status" "$owner_token" "$leader_pid" "$leader_starttime" "$pgid" \
    "$supervisor_pid" "$supervisor_starttime" "$supervisor_pgid" \
    "$return_code" "$timed_out" "$term_sent" "$kill_sent" \
    > "$request_dir/.terminal.json.tmp"
  sync "$request_dir/.terminal.json.tmp" 2>/dev/null || true
  mv -f -- "$request_dir/.terminal.json.tmp" "$request_dir/terminal.json"
  exit 0
fi

if [ "$mode" = "snapshot-start" ]; then
  logical_cwd=$3
  timeout_ms=$4
  grace_ms=$5
  confirmation_ms=$6
  owner_token=$7
  output_cap=$8
  case "$timeout_ms:$grace_ms:$confirmation_ms:$output_cap" in
    (*[!0-9:]*|:*|*::*) exit 82;;
  esac
  case "$owner_token" in (*[!0-9a-f]*|'') exit 82;; esac
  test "${#owner_token}" -eq 64 || exit 82
  test -f "$request_dir/command.sh" || exit 82
  setsid /bin/bash "$0" snapshot-supervise "$request_dir" \
    "$logical_cwd" "$timeout_ms" "$grace_ms" "$confirmation_ms" \
    "$owner_token" "$output_cap" </dev/null >/dev/null 2>&1 &
  supervisor_pid=$!
  for _ in $(seq 1 250); do
    if test -f "$request_dir/lease.json"; then
      cat "$request_dir/lease.json"
      exit 0
    fi
    if ! pid_alive "$supervisor_pid"; then
      exit 85
    fi
    sleep 0.02
  done
  : > "$request_dir/.cancel_intent.tmp"
  mv -f -- "$request_dir/.cancel_intent.tmp" "$request_dir/cancel_intent"
  exit 86
fi

if [ "$mode" = "snapshot-inspect" ]; then
  expected_token=$3
  case "$request_dir" in
    (*"/.nano-snapshot-execution-$expected_token") ;;
    (*) exit 88;;
  esac
  : > "$request_dir/.cancel_intent.tmp"
  sync "$request_dir/.cancel_intent.tmp" 2>/dev/null || true
  mv -f -- "$request_dir/.cancel_intent.tmp" "$request_dir/cancel_intent"
  for _ in $(seq 1 250); do
    if test -f "$request_dir/owner_token" &&
      test -f "$request_dir/lease.json"; then
      IFS= read -r actual_token < "$request_dir/owner_token"
      test "$actual_token" = "$expected_token" || exit 88
      cat "$request_dir/lease.json"
      exit 0
    fi
    sleep 0.02
  done
  exit 87
fi

if [ "$mode" = "snapshot-release" ]; then
  expected_token=$3
  expected_pid=$4
  expected_starttime=$5
  expected_pgid=$6
  expected_supervisor_pid=$7
  expected_supervisor_starttime=$8
  expected_supervisor_pgid=$9
  snapshot_identity_files_match \
    "$expected_token" "$expected_pid" "$expected_starttime" "$expected_pgid" \
    "$expected_supervisor_pid" "$expected_supervisor_starttime" \
    "$expected_supervisor_pgid" || exit 92
  snapshot_pid_identity_matches \
    "$expected_pid" "$expected_starttime" "$expected_pgid" || exit 92
  snapshot_pid_has_owner "$expected_pid" "$expected_token" || exit 92
  snapshot_pid_identity_matches \
    "$expected_supervisor_pid" "$expected_supervisor_starttime" \
    "$expected_supervisor_pgid" || exit 92
  if test -f "$request_dir/cancel_intent" ||
    test -f "$request_dir/cancel_requested" ||
    test -f "$request_dir/terminal.json" ||
    test -f "$request_dir/release"; then
    exit 96
  fi
  : > "$request_dir/.release.tmp"
  sync "$request_dir/.release.tmp" 2>/dev/null || true
  mv -f -- "$request_dir/.release.tmp" "$request_dir/release"
  printf 'released\n'
  exit 0
fi

if [ "$mode" = "snapshot-wait" ]; then
  expected_token=$3
  expected_pid=$4
  expected_starttime=$5
  expected_pgid=$6
  expected_supervisor_pid=$7
  expected_supervisor_starttime=$8
  expected_supervisor_pgid=$9
  wait_ms=${10}
  case "$expected_pid:$expected_starttime:$expected_pgid:"\
"$expected_supervisor_pid:$expected_supervisor_starttime:"\
"$expected_supervisor_pgid:$wait_ms" in
    (*[!0-9:]*|:*|*::*) exit 89;;
  esac
  snapshot_identity_files_match \
    "$expected_token" "$expected_pid" "$expected_starttime" "$expected_pgid" \
    "$expected_supervisor_pid" "$expected_supervisor_starttime" \
    "$expected_supervisor_pgid" || exit 92
  loops=$(((wait_ms + 49) / 50))
  index=0
  identity_state=0
  while ! test -f "$request_dir/terminal.json" &&
    [ "$index" -lt "$loops" ]; do
    snapshot_pid_identity_state \
      "$expected_supervisor_pid" "$expected_supervisor_starttime" \
      "$expected_supervisor_pgid"
    identity_state=$?
    if [ "$identity_state" -eq 2 ]; then
      exit 92
    elif [ "$identity_state" -eq 1 ]; then
      for _ in $(seq 1 20); do
        test -f "$request_dir/terminal.json" && break
        sleep 0.01
      done
      test -f "$request_dir/terminal.json" || exit 93
      break
    fi
    sleep 0.05
    index=$((index + 1))
  done
  test -f "$request_dir/terminal.json" || exit 94
  index=0
  while [ "$index" -lt 100 ]; do
    snapshot_pid_identity_state \
      "$expected_supervisor_pid" "$expected_supervisor_starttime" \
      "$expected_supervisor_pgid"
    identity_state=$?
    [ "$identity_state" -eq 2 ] && exit 92
    [ "$identity_state" -eq 1 ] && break
    sleep 0.02
    index=$((index + 1))
  done
  snapshot_pid_identity_state \
    "$expected_supervisor_pid" "$expected_supervisor_starttime" \
    "$expected_supervisor_pgid"
  identity_state=$?
  [ "$identity_state" -eq 2 ] && exit 92
  [ "$identity_state" -eq 0 ] && exit 95
  cat "$request_dir/terminal.json"
  exit 0
fi

if [ "$mode" = "snapshot-cleanup-signal" ]; then
  expected_token=$3
  expected_pid=$4
  expected_starttime=$5
  expected_pgid=$6
  expected_supervisor_pid=$7
  expected_supervisor_starttime=$8
  expected_supervisor_pgid=$9
  signal_name=${10}
  case "$signal_name" in (TERM|KILL) ;; (*) exit 92;; esac
  snapshot_identity_files_match \
    "$expected_token" "$expected_pid" "$expected_starttime" "$expected_pgid" \
    "$expected_supervisor_pid" "$expected_supervisor_starttime" \
    "$expected_supervisor_pgid" || exit 92
  if pid_alive "$expected_pid"; then
    snapshot_pid_identity_matches \
      "$expected_pid" "$expected_starttime" "$expected_pgid" || exit 92
    snapshot_pid_has_owner "$expected_pid" "$expected_token" || exit 92
  elif (group_alive "$expected_pgid" || owner_alive "$expected_token") &&
    ! snapshot_group_has_owner "$expected_pgid" "$expected_token"; then
    exit 92
  fi
  if pid_alive "$expected_supervisor_pid"; then
    snapshot_pid_identity_matches \
      "$expected_supervisor_pid" "$expected_supervisor_starttime" \
      "$expected_supervisor_pgid" || exit 92
  elif ! test -f "$request_dir/terminal.json" &&
    (group_alive "$expected_pgid" || owner_alive "$expected_token"); then
    exit 93
  fi
  if [ "$signal_name" = "TERM" ]; then
    : > "$request_dir/.cancel_requested.tmp"
    sync "$request_dir/.cancel_requested.tmp" 2>/dev/null || true
    mv -f -- "$request_dir/.cancel_requested.tmp" \
      "$request_dir/cancel_requested"
  fi
  kill "-$signal_name" -- "-$expected_pgid" 2>/dev/null || true
  signal_owned "$signal_name" "$expected_token"
  kill "-$signal_name" -- "-$expected_supervisor_pgid" 2>/dev/null || true
  printf 'signal-ok\n'
  exit 0
fi

if [ "$mode" = "snapshot-cleanup-census" ]; then
  expected_token=$3
  expected_pid=$4
  expected_starttime=$5
  expected_pgid=$6
  expected_supervisor_pid=$7
  expected_supervisor_starttime=$8
  expected_supervisor_pgid=$9
  snapshot_identity_files_match \
    "$expected_token" "$expected_pid" "$expected_starttime" "$expected_pgid" \
    "$expected_supervisor_pid" "$expected_supervisor_starttime" \
    "$expected_supervisor_pgid" || exit 92
  if pid_alive "$expected_pid"; then
    snapshot_pid_identity_matches \
      "$expected_pid" "$expected_starttime" "$expected_pgid" || exit 92
    snapshot_pid_has_owner "$expected_pid" "$expected_token" || exit 92
  elif (group_alive "$expected_pgid" || owner_alive "$expected_token") &&
    ! snapshot_group_has_owner "$expected_pgid" "$expected_token"; then
    exit 92
  fi
  if pid_alive "$expected_supervisor_pid"; then
    snapshot_pid_identity_matches \
      "$expected_supervisor_pid" "$expected_supervisor_starttime" \
      "$expected_supervisor_pgid" || exit 92
  fi
  if group_alive "$expected_pgid" || owner_alive "$expected_token" ||
    group_alive "$expected_supervisor_pgid"; then
    printf '{"verified":true,"survivor_count":1}\n'
    exit 93
  fi
  printf '{"verified":true,"survivor_count":0}\n'
  exit 0
fi

if [ "$mode" = "snapshot-cancel" ]; then
  expected_token=$3
  expected_pid=$4
  expected_starttime=$5
  expected_pgid=$6
  expected_supervisor_pid=$7
  expected_supervisor_starttime=$8
  expected_supervisor_pgid=$9
  wait_ms=${10}
  snapshot_identity_files_match \
    "$expected_token" "$expected_pid" "$expected_starttime" "$expected_pgid" \
    "$expected_supervisor_pid" "$expected_supervisor_starttime" \
    "$expected_supervisor_pgid" || exit 92
  if pid_alive "$expected_pid"; then
    snapshot_pid_identity_matches \
      "$expected_pid" "$expected_starttime" "$expected_pgid" || exit 92
    snapshot_pid_has_owner "$expected_pid" "$expected_token" || exit 92
  elif (group_alive "$expected_pgid" || owner_alive "$expected_token") &&
    ! snapshot_group_has_owner "$expected_pgid" "$expected_token"; then
    exit 92
  fi
  if pid_alive "$expected_supervisor_pid"; then
    snapshot_pid_identity_matches \
      "$expected_supervisor_pid" "$expected_supervisor_starttime" \
      "$expected_supervisor_pgid" || exit 92
  elif ! test -f "$request_dir/terminal.json"; then
    exit 93
  fi
  : > "$request_dir/.cancel_requested.tmp"
  sync "$request_dir/.cancel_requested.tmp" 2>/dev/null || true
  mv -f -- "$request_dir/.cancel_requested.tmp" \
    "$request_dir/cancel_requested"
  loops=$(((wait_ms + 49) / 50))
  index=0
  while ! test -f "$request_dir/terminal.json" &&
    [ "$index" -lt "$loops" ]; do
    sleep 0.05
    index=$((index + 1))
  done
  test -f "$request_dir/terminal.json" || exit 94
  index=0
  identity_state=0
  while [ "$index" -lt 100 ]; do
    snapshot_pid_identity_state \
      "$expected_supervisor_pid" "$expected_supervisor_starttime" \
      "$expected_supervisor_pgid"
    identity_state=$?
    [ "$identity_state" -eq 2 ] && exit 92
    [ "$identity_state" -eq 1 ] && break
    sleep 0.02
    index=$((index + 1))
  done
  snapshot_pid_identity_state \
    "$expected_supervisor_pid" "$expected_supervisor_starttime" \
    "$expected_supervisor_pgid"
  identity_state=$?
  [ "$identity_state" -eq 2 ] && exit 92
  [ "$identity_state" -eq 0 ] && exit 95
  cat "$request_dir/terminal.json"
  exit 0
fi

write_background_status() {
  local destination=$1
  local state=$2
  local exit_code=$3
  local timed_out=$4
  local total_bytes=$5
  local truncated=$6
  local started_epoch=$7
  local ended_epoch=$8
  local leader_exited=$9
  local temporary="${destination}.tmp.$$"
  printf '{"state":"%s","exit_code":%s,"timed_out":%s,' \
    "$state" "$exit_code" "$timed_out" > "$temporary"
  printf '"total_bytes":%s,"truncated":%s,"leader_exited":%s,' \
    "$total_bytes" "$truncated" "$leader_exited" >> "$temporary"
  printf '"started_epoch":%s,"ended_epoch":%s}\n' \
    "$started_epoch" "$ended_epoch" >> "$temporary"
  sync "$temporary" 2>/dev/null || true
  mv -f -- "$temporary" "$destination"
}

if [ "$mode" = "background-monitor" ]; then
  logical_cwd=$3
  runtime_timeout_ms=$4
  grace_ms=$5
  spool_cap=$6
  output_path=$7
  owner_token=$8
  valid_owner_token "$owner_token" || exit 66
  owner_scan_available || exit 66
  mkdir -p -- "$request_dir" "$(dirname -- "$output_path")"
  chmod 700 "$request_dir"
  cd "$logical_cwd" || exit 65
  if test -f "$request_dir/owner_token"; then
    read_expected_background_owner \
      "$request_dir/owner_token" "$owner_token" >/dev/null || exit 66
  else
    printf '%s\n' "$owner_token" > "$request_dir/.owner_token.tmp"
    sync "$request_dir/.owner_token.tmp" 2>/dev/null || true
    mv -f -- "$request_dir/.owner_token.tmp" "$request_dir/owner_token"
  fi
  monitor_pid=$$
  monitor_identity=$(snapshot_proc_identity "$monitor_pid") || exit 66
  read -r monitor_starttime monitor_pgid <<< "$monitor_identity"
  test "$monitor_pid" = "$monitor_pgid" || exit 66
  printf '%s\n' "$monitor_pgid" > "$request_dir/.monitor_pgid.tmp"
  sync "$request_dir/.monitor_pgid.tmp" 2>/dev/null || true
  mv -f -- "$request_dir/.monitor_pgid.tmp" "$request_dir/monitor_pgid"
  printf '%s\n' "$monitor_starttime" \
    > "$request_dir/.monitor_starttime.tmp"
  sync "$request_dir/.monitor_starttime.tmp" 2>/dev/null || true
  mv -f -- "$request_dir/.monitor_starttime.tmp" \
    "$request_dir/monitor_starttime"
  : > "$output_path"
  chmod 600 "$output_path"
  fifo="$request_dir/output.fifo"
  rm -f -- "$fifo"
  mkfifo "$fifo"
  tee -p \
    >(head -c "$spool_cap" > "$output_path") \
    >(wc -c > "$request_dir/output.size") \
    >/dev/null < "$fifo" 2>/dev/null &
  output_drain=$!
  launch_gate="$request_dir/launch.gate"
  rm -f -- "$launch_gate"
  setsid env -i \
    HOME="${HOME-}" \
    LANG="${LANG-}" \
    LC_ALL="${LC_ALL-}" \
    PATH="${PATH-}" \
    TERM="${TERM-}" \
    TMPDIR="${TMPDIR-}" \
    USER="${USER-}" \
    NANO_NGB_OWNER="$owner_token" \
    /bin/bash -c '
      launch_gate=$1
      command_path=$2
      while [ ! -f "$launch_gate" ]; do sleep 0.01; done
      exec /bin/bash "$command_path"
    ' nano-background-launch "$launch_gate" "$request_dir/command.sh" \
    >"$fifo" 2>&1 < /dev/null &
  pgid=$!
  leader_ready=false
  for _ in $(seq 1 100); do
    if leader_identity=$(snapshot_proc_identity "$pgid"); then
      read -r leader_starttime leader_pgid <<< "$leader_identity"
      if [ "$pgid" = "$leader_pgid" ] &&
        snapshot_pid_has_owner "$pgid" "$owner_token"; then
        leader_ready=true
        break
      fi
    fi
    pid_alive "$pgid" || exit 67
    sleep 0.01
  done
  test "$leader_ready" = "true" || exit 67
  printf '%s\n' "$pgid" > "$request_dir/.pgid.tmp"
  mv -f -- "$request_dir/.pgid.tmp" "$request_dir/pgid"
  printf '%s\n' "$leader_starttime" \
    > "$request_dir/.leader_starttime.tmp"
  mv -f -- "$request_dir/.leader_starttime.tmp" \
    "$request_dir/leader_starttime"
  started_epoch=$(date +%s.%N)
  write_background_status \
    "$request_dir/status.json" running null false 0 false \
    "$started_epoch" null false
  : > "$launch_gate"
  : > "$request_dir/ready"

  if [ "$runtime_timeout_ms" != "none" ]; then
    remaining_ms=$runtime_timeout_ms
    while (group_alive "$pgid" || owner_alive "$owner_token") &&
      [ "$remaining_ms" -gt 0 ]; do
      step_ms=50
      if [ "$remaining_ms" -lt "$step_ms" ]; then
        step_ms=$remaining_ms
      fi
      sleep "$(seconds_from_ms "$step_ms")"
      remaining_ms=$((remaining_ms - step_ms))
    done
    if group_alive "$pgid" || owner_alive "$owner_token"; then
      : > "$request_dir/timed_out"
      kill -TERM -- "-$pgid" 2>/dev/null || true
      signal_owned TERM "$owner_token" || true
      sleep "$(seconds_from_ms "$grace_ms")"
      if group_alive "$pgid" || owner_alive "$owner_token"; then
        kill -KILL -- "-$pgid" 2>/dev/null || true
        signal_owned KILL "$owner_token" || true
      fi
    fi
  fi

  wait "$pgid"
  return_code=$?
  : > "$request_dir/leader_exited"
  wait "$output_drain" 2>/dev/null || true
  total_bytes=0
  if [ -f "$request_dir/output.size" ]; then
    IFS= read -r total_bytes < "$request_dir/output.size"
  fi
  case "$total_bytes" in (*[!0-9]*|'') total_bytes=0;; esac
  truncated=false
  if [ "$total_bytes" -gt "$spool_cap" ]; then
    truncated=true
  fi
  timed_out=false
  state=failed
  exit_code=$return_code
  if [ -f "$request_dir/explicit_kill" ]; then
    state=cancelled
  elif [ -f "$request_dir/timed_out" ]; then
    timed_out=true
    exit_code=124
  elif [ "$return_code" -eq 0 ]; then
    state=completed
  fi
  leader_exit_published=false
  while ! wait_for_background_identity_exit \
    "$pgid" "$leader_starttime" "$pgid" "$leader_starttime" \
    "$owner_token" 100; do
    background_identity_alive \
      "$pgid" "$leader_starttime" "$pgid" "$leader_starttime" "$owner_token"
    alive_status=$?
    test "$alive_status" -ne 2 || exit 75
    if [ "$alive_status" -eq 0 ] &&
      [ "$leader_exit_published" = "false" ]; then
      write_background_status \
        "$request_dir/status.json" running null false \
        "$total_bytes" "$truncated" "$started_epoch" null true
      leader_exit_published=true
    fi
  done
  ended_epoch=$(date +%s.%N)
  write_background_status \
    "$request_dir/status.json" "$state" "$exit_code" "$timed_out" \
    "$total_bytes" "$truncated" "$started_epoch" "$ended_epoch" true
  : > "$request_dir/done"
  exit 0
fi

if [ "$mode" = "start" ]; then
  logical_cwd=$3
  runtime_timeout_ms=$4
  grace_ms=$5
  spool_cap=$6
  output_path=$7
  owner_token=$8
  valid_owner_token "$owner_token" || exit 72
  mkdir -p -- "$request_dir"
  chmod 700 "$request_dir"
  setsid env NANO_NGB_OWNER="$owner_token" /bin/bash "$0" \
    background-monitor "$request_dir" \
    "$logical_cwd" "$runtime_timeout_ms" "$grace_ms" "$spool_cap" \
    "$output_path" "$owner_token" </dev/null >/dev/null 2>&1 &
  monitor_pgid=$!
  monitor_ready=false
  for _ in $(seq 1 100); do
    if monitor_identity=$(snapshot_proc_identity "$monitor_pgid"); then
      read -r monitor_starttime actual_monitor_pgid <<< "$monitor_identity"
      if [ "$monitor_pgid" = "$actual_monitor_pgid" ]; then
        monitor_ready=true
        break
      fi
    fi
    pid_alive "$monitor_pgid" || exit 79
    sleep 0.01
  done
  test "$monitor_ready" = "true" || exit 79
  monitor_record_ready=false
  for _ in $(seq 1 100); do
    if read_expected_background_identity \
      "$request_dir/monitor_pgid" "$monitor_pgid" >/dev/null &&
      read_expected_background_starttime \
        "$request_dir/monitor_starttime" "$monitor_starttime" >/dev/null; then
      monitor_record_ready=true
      break
    fi
    pid_alive "$monitor_pgid" || exit 79
    sleep 0.01
  done
  test "$monitor_record_ready" = "true" || exit 79
  launch_ready=false
  for _ in $(seq 1 100); do
    if [ -f "$request_dir/ready" ] && [ -f "$request_dir/pgid" ] &&
      [ -f "$request_dir/leader_starttime" ] &&
      [ -f "$request_dir/monitor_starttime" ] &&
      [ -f "$request_dir/owner_token" ]; then
      IFS= read -r pgid < "$request_dir/pgid"
      IFS= read -r leader_starttime < "$request_dir/leader_starttime"
      actual_owner_token=$(read_expected_background_owner \
        "$request_dir/owner_token" "$owner_token") || exit 79
      launch_ready=true
      break
    fi
    if ! group_alive "$monitor_pgid"; then
      exit 79
    fi
    sleep 0.05
  done
  if [ "$launch_ready" = "true" ]; then
    for _ in $(seq 1 10); do
      if test -f "$request_dir/done" ||
        test -f "$request_dir/leader_exited"; then
        break
      fi
      sleep 0.01
    done
    printf '{"pgid":%s,"leader_starttime":%s,' \
      "$pgid" "$leader_starttime"
    printf '"monitor_pgid":%s,"monitor_starttime":%s,' \
      "$monitor_pgid" "$monitor_starttime"
    printf '"owner_token":"%s"}\n' "$actual_owner_token"
    exit 0
  fi
  if [ -f "$request_dir/pgid" ]; then
    IFS= read -r pgid < "$request_dir/pgid"
    case "$pgid" in (*[!0-9]*|'') pgid=;; esac
    if [ -n "$pgid" ]; then
      kill -KILL -- "-$pgid" 2>/dev/null || true
      wait_for_group_exit "$pgid" 1000 || true
    fi
  fi
  signal_owned KILL "$owner_token" 2>/dev/null || true
  kill -KILL -- "-$monitor_pgid" 2>/dev/null || true
  exit 80
fi

if [ "$mode" = "status" ]; then
  test -f "$request_dir/status.json" || exit 81
  if grep -q '"state":"running"' "$request_dir/status.json" &&
    ! grep -q '"leader_exited":true' "$request_dir/status.json" &&
    test -f "$request_dir/pgid"; then
    IFS= read -r pgid < "$request_dir/pgid"
    if ! group_alive "$pgid"; then
      for _ in $(seq 1 100); do
        grep -q '"state":"running"' "$request_dir/status.json" || break
        sleep 0.01
      done
    fi
  fi
  cat "$request_dir/status.json"
  exit 0
fi

if [ "$mode" = "background-inspect" ]; then
  expected_owner_token=$3
  valid_owner_token "$expected_owner_token" || exit 72
  for _ in $(seq 1 100); do
    if test -f "$request_dir/pgid" &&
      test -f "$request_dir/leader_starttime" &&
      test -f "$request_dir/monitor_pgid" &&
      test -f "$request_dir/monitor_starttime" &&
      test -f "$request_dir/owner_token"; then
      test ! -L "$request_dir/pgid" || exit 71
      test ! -L "$request_dir/leader_starttime" || exit 71
      test ! -L "$request_dir/monitor_pgid" || exit 71
      test ! -L "$request_dir/monitor_starttime" || exit 71
      IFS= read -r pgid < "$request_dir/pgid" || exit 71
      IFS= read -r leader_starttime \
        < "$request_dir/leader_starttime" || exit 71
      IFS= read -r monitor_pgid \
        < "$request_dir/monitor_pgid" || exit 71
      IFS= read -r monitor_starttime \
        < "$request_dir/monitor_starttime" || exit 71
      positive_process_group "$pgid" || exit 71
      positive_process_identity "$leader_starttime" || exit 71
      positive_process_group "$monitor_pgid" || exit 71
      positive_process_identity "$monitor_starttime" || exit 71
      owner_token=$(read_expected_background_owner \
        "$request_dir/owner_token" "$expected_owner_token") || exit 71
      printf '{"pgid":%s,"leader_starttime":%s,' \
        "$pgid" "$leader_starttime"
      printf '"monitor_pgid":%s,"monitor_starttime":%s,' \
        "$monitor_pgid" "$monitor_starttime"
      printf '"owner_token":"%s"}\n' "$owner_token"
      exit 0
    fi
    sleep 0.05
  done
  exit 81
fi

if [ "$mode" = "background-liveness" ]; then
  expected_pgid=$3
  expected_leader_starttime=$4
  expected_monitor_pgid=$5
  expected_monitor_starttime=$6
  expected_owner_token=$7
  positive_process_group "$expected_pgid" || exit 72
  positive_process_identity "$expected_leader_starttime" || exit 72
  positive_process_group "$expected_monitor_pgid" || exit 72
  positive_process_identity "$expected_monitor_starttime" || exit 72
  valid_owner_token "$expected_owner_token" || exit 72
  pgid=$(read_expected_background_identity \
    "$request_dir/pgid" "$expected_pgid") || exit 71
  leader_starttime=$(read_expected_background_starttime \
    "$request_dir/leader_starttime" "$expected_leader_starttime") || exit 71
  monitor_pgid=$(read_expected_background_identity \
    "$request_dir/monitor_pgid" "$expected_monitor_pgid") || exit 71
  monitor_starttime=$(read_expected_background_starttime \
    "$request_dir/monitor_starttime" "$expected_monitor_starttime") || exit 71
  owner_token=$(read_expected_background_owner \
    "$request_dir/owner_token" "$expected_owner_token") || exit 71
  owner_scan_available || exit 74
  background_identity_alive \
    "$pgid" "$leader_starttime" "$monitor_pgid" "$monitor_starttime" \
    "$owner_token"
  alive_status=$?
  if [ "$alive_status" -eq 2 ]; then
    exit 74
  fi
  process_alive=false
  if [ "$alive_status" -eq 0 ]; then
    process_alive=true
  fi
  printf '{"process_alive":%s}\n' "$process_alive"
  exit 0
fi

if [ "$mode" = "kill-background" ]; then
  grace_ms=$3
  confirmation_ms=$4
  expected_pgid=$5
  expected_leader_starttime=$6
  expected_monitor_pgid=$7
  expected_monitor_starttime=$8
  expected_owner_token=$9
  positive_process_group "$expected_pgid" || exit 72
  positive_process_identity "$expected_leader_starttime" || exit 72
  positive_process_group "$expected_monitor_pgid" || exit 72
  positive_process_identity "$expected_monitor_starttime" || exit 72
  valid_owner_token "$expected_owner_token" || exit 72
  pgid=$(read_expected_background_identity \
    "$request_dir/pgid" "$expected_pgid") || exit 71
  leader_starttime=$(read_expected_background_starttime \
    "$request_dir/leader_starttime" "$expected_leader_starttime") || exit 71
  monitor_pgid=$(read_expected_background_identity \
    "$request_dir/monitor_pgid" "$expected_monitor_pgid") || exit 71
  monitor_starttime=$(read_expected_background_starttime \
    "$request_dir/monitor_starttime" "$expected_monitor_starttime") || exit 71
  owner_token=$(read_expected_background_owner \
    "$request_dir/owner_token" "$expected_owner_token") || exit 71
  owner_scan_available || exit 74
  : > "$request_dir/.explicit_kill.tmp"
  mv -f -- "$request_dir/.explicit_kill.tmp" "$request_dir/explicit_kill"
  term_sent=false
  kill_sent=false
  background_identity_alive \
    "$pgid" "$leader_starttime" "$monitor_pgid" "$monitor_starttime" \
    "$owner_token"
  alive_status=$?
  if [ "$alive_status" -eq 0 ]; then
    term_sent=true
    background_signal_identity \
      TERM "$pgid" "$leader_starttime" "$monitor_pgid" \
      "$monitor_starttime" "$owner_token" || true
    wait_for_background_identity_exit \
      "$pgid" "$leader_starttime" "$monitor_pgid" "$monitor_starttime" \
      "$owner_token" "$grace_ms" || true
  elif [ "$alive_status" -ne 1 ]; then
    exit 74
  fi
  background_identity_alive \
    "$pgid" "$leader_starttime" "$monitor_pgid" "$monitor_starttime" \
    "$owner_token"
  alive_status=$?
  if [ "$alive_status" -eq 0 ]; then
    kill_sent=true
    background_signal_identity \
      KILL "$pgid" "$leader_starttime" "$monitor_pgid" \
      "$monitor_starttime" "$owner_token" || true
  elif [ "$alive_status" -ne 1 ]; then
    exit 74
  fi
  verified=false
  if wait_for_background_identity_exit \
    "$pgid" "$leader_starttime" "$monitor_pgid" "$monitor_starttime" \
    "$owner_token" "$confirmation_ms"; then
    verified=true
  fi
  printf '{"term_sent":%s,"kill_sent":%s,"verified":%s}\n' \
    "$term_sent" "$kill_sent" "$verified"
  test "$verified" = "true"
  exit
fi

if [ "$mode" = "confirm-background" ]; then
  confirmation_ms=$3
  expected_pgid=$4
  expected_leader_starttime=$5
  expected_monitor_pgid=$6
  expected_monitor_starttime=$7
  expected_owner_token=$8
  positive_process_group "$expected_pgid" || exit 72
  positive_process_identity "$expected_leader_starttime" || exit 72
  positive_process_group "$expected_monitor_pgid" || exit 72
  positive_process_identity "$expected_monitor_starttime" || exit 72
  valid_owner_token "$expected_owner_token" || exit 72
  pgid=$(read_expected_background_identity \
    "$request_dir/pgid" "$expected_pgid") || exit 71
  leader_starttime=$(read_expected_background_starttime \
    "$request_dir/leader_starttime" "$expected_leader_starttime") || exit 71
  monitor_pgid=$(read_expected_background_identity \
    "$request_dir/monitor_pgid" "$expected_monitor_pgid") || exit 71
  monitor_starttime=$(read_expected_background_starttime \
    "$request_dir/monitor_starttime" "$expected_monitor_starttime") || exit 71
  owner_token=$(read_expected_background_owner \
    "$request_dir/owner_token" "$expected_owner_token") || exit 71
  verified=false
  if wait_for_background_identity_exit \
    "$pgid" "$leader_starttime" "$monitor_pgid" "$monitor_starttime" \
    "$owner_token" "$confirmation_ms"; then
    verified=true
  fi
  printf '{"verified":%s}\n' "$verified"
  test "$verified" = "true"
  exit
fi

test "$mode" = "run" || exit 64
logical_cwd=$3
timeout_ms=$4
grace_ms=$5
confirmation_ms=$6
stdout_cap=$7
stderr_cap=$8
owner_token=$9
drain_timeout_ms=${10}

mkdir -p "$request_dir"
chmod 700 "$request_dir"
cd "$logical_cwd" || exit 65
case "$owner_token" in (*[!0-9a-f]*|'') exit 66;; esac
printf '%s\n' "$owner_token" > "$request_dir/.owner_token.tmp"
mv "$request_dir/.owner_token.tmp" "$request_dir/owner_token"

printf 'false\n' > "$request_dir/timed_out"
printf 'false\n' > "$request_dir/term_sent"
printf 'false\n' > "$request_dir/kill_sent"
mkfifo "$request_dir/stdout.fifo" "$request_dir/stderr.fifo"
tee -p \
  >(head -c "$stdout_cap" > "$request_dir/stdout.bin") \
  >(wc -c > "$request_dir/stdout.size") \
  >/dev/null < "$request_dir/stdout.fifo" 2>/dev/null &
stdout_drain=$!
tee -p \
  >(head -c "$stderr_cap" > "$request_dir/stderr.bin") \
  >(wc -c > "$request_dir/stderr.size") \
  >/dev/null < "$request_dir/stderr.fifo" 2>/dev/null &
stderr_drain=$!
set -m
(
  exec env -i \
    HOME="${HOME-}" \
    LANG="${LANG-}" \
    LC_ALL="${LC_ALL-}" \
    PATH="${PATH-}" \
    TERM="${TERM-}" \
    TMPDIR="${TMPDIR-}" \
    USER="${USER-}" \
    NANO_NGB_OWNER="$owner_token" \
    /bin/bash "$request_dir/command.sh"
) >"$request_dir/stdout.fifo" 2>"$request_dir/stderr.fifo" < /dev/null &
pgid=$!
printf '%s\n' "$pgid" > "$request_dir/.pgid.tmp"
sync "$request_dir/.pgid.tmp" 2>/dev/null || true
mv "$request_dir/.pgid.tmp" "$request_dir/pgid"

(
  sleep "$(seconds_from_ms "$timeout_ms")"
  if group_alive "$pgid"; then
    printf 'true\n' > "$request_dir/timed_out"
    printf 'true\n' > "$request_dir/term_sent"
    kill -TERM -- "-$pgid" 2>/dev/null || true
    sleep "$(seconds_from_ms "$grace_ms")"
    if group_alive "$pgid"; then
      printf 'true\n' > "$request_dir/kill_sent"
      kill -KILL -- "-$pgid" 2>/dev/null || true
    fi
  fi
) &
watcher=$!

wait "$pgid"
return_code=$?
kill -- "-$watcher" 2>/dev/null || kill "$watcher" 2>/dev/null || true
wait "$watcher" 2>/dev/null || true

IFS= read -r timed_out < "$request_dir/timed_out"
IFS= read -r term_sent < "$request_dir/term_sent"
IFS= read -r kill_sent < "$request_dir/kill_sent"
if [ "$timed_out" = "true" ]; then
  return_code=124
fi

if group_alive "$pgid" || owner_alive "$owner_token"; then
  printf 'true\n' > "$request_dir/term_sent"
  term_sent=true
  kill -TERM -- "-$pgid" 2>/dev/null || true
  signal_owned TERM "$owner_token"
  sleep "$(seconds_from_ms "$grace_ms")"
fi
if group_alive "$pgid" || owner_alive "$owner_token"; then
  printf 'true\n' > "$request_dir/kill_sent"
  kill_sent=true
  kill -KILL -- "-$pgid" 2>/dev/null || true
  signal_owned KILL "$owner_token"
fi

cleanup_verified=false
census_verified=false
survivor_count=1
if wait_for_group_exit "$pgid" "$confirmation_ms" &&
  wait_for_owner_exit "$owner_token" "$confirmation_ms"; then
  cleanup_verified=true
  census_verified=true
  survivor_count=0
fi

if [ "$cleanup_verified" != "true" ]; then
  kill "$stdout_drain" "$stderr_drain" 2>/dev/null || true
  exit 76
fi
drain_forced=false
if ! wait_for_pid_exit "$stdout_drain" "$drain_timeout_ms"; then
  drain_forced=true
  kill -KILL "$stdout_drain" 2>/dev/null || true
fi
if ! wait_for_pid_exit "$stderr_drain" "$drain_timeout_ms"; then
  drain_forced=true
  kill -KILL "$stderr_drain" 2>/dev/null || true
fi
wait "$stdout_drain" 2>/dev/null || true
wait "$stderr_drain" 2>/dev/null || true
for _ in $(seq 1 100); do
  if [ -f "$request_dir/stdout.size" ] &&
    [ -f "$request_dir/stderr.size" ]; then
    break
  fi
  sleep 0.01
done
if ! test -f "$request_dir/stdout.size"; then
  wc -c < "$request_dir/stdout.bin" > "$request_dir/stdout.size"
  drain_forced=true
fi
if ! test -f "$request_dir/stderr.size"; then
  wc -c < "$request_dir/stderr.bin" > "$request_dir/stderr.size"
  drain_forced=true
fi
stdout_size=$(cat "$request_dir/stdout.size")
stderr_size=$(cat "$request_dir/stderr.size")
stdout_truncated=false
stderr_truncated=false
if [ "$drain_forced" = "true" ]; then
  stdout_truncated=true
  stderr_truncated=true
fi
if [ "$stdout_size" -gt "$stdout_cap" ]; then
  stdout_truncated=true
fi
if [ "$stderr_size" -gt "$stderr_cap" ]; then
  stderr_truncated=true
fi

meta_format='{"return_code":%s,"timed_out":%s'
meta_format="${meta_format}"',"stdout_truncated":%s,"stderr_truncated":%s'
meta_format="${meta_format}"',"cleanup_attempted":true,"term_sent":%s'
meta_format="${meta_format}"',"kill_sent":%s,"cleanup_verified":%s'
meta_format="${meta_format}"',"census_verified":%s,"survivor_count":%s}'
printf "${meta_format}\n" \
  "$return_code" "$timed_out" "$stdout_truncated" "$stderr_truncated" \
  "$term_sent" "$kill_sent" "$cleanup_verified" "$census_verified" \
  "$survivor_count" > "$request_dir/.meta.json.tmp"
sync "$request_dir/.meta.json.tmp" 2>/dev/null || true
mv "$request_dir/.meta.json.tmp" "$request_dir/meta.json"
test "$cleanup_verified" = "true" && test "$census_verified" = "true"
"""


class RemoteEnvironment(Protocol):
    async def exec(
        self,
        command: str,
        cwd: str | None = None,
        timeout_sec: float | None = None,
        user: str | int | None = None,
    ) -> Any: ...

    async def upload_file(self, source_path: Path | str, target_path: str) -> None: ...

    async def download_file(
        self, source_path: str, target_path: Path | str
    ) -> None: ...


class _ToolRejected(RuntimeError):
    pass


class _BackgroundStartFailure(BridgeError):
    """A start failure with an exact local dispatch boundary."""

    def __init__(
        self,
        code: str,
        *,
        start_dispatched: bool,
        not_started_verified: bool = False,
    ) -> None:
        if start_dispatched and not_started_verified:
            raise ValueError("dispatched start cannot be a verified non-start")
        super().__init__(code)
        self.start_dispatched = start_dispatched
        self.not_started_verified = not_started_verified


def _png_dimensions(payload: bytes) -> tuple[int, int]:
    if not payload.startswith(b"\x89PNG\r\n\x1a\n"):
        raise _ToolRejected("read_file_media_invalid")
    offset = 8
    width = 0
    height = 0
    saw_ihdr = False
    saw_idat = False
    idat_finished = False
    while offset < len(payload):
        if len(payload) - offset < 12:
            raise _ToolRejected("read_file_media_invalid")
        chunk_length = int.from_bytes(payload[offset : offset + 4], "big")
        chunk_type = payload[offset + 4 : offset + 8]
        chunk_end = offset + 12 + chunk_length
        if (
            chunk_end > len(payload)
            or not all(
                byte in range(ord("A"), ord("Z") + 1)
                or byte in range(ord("a"), ord("z") + 1)
                for byte in chunk_type
            )
            or chunk_type[2] in range(ord("a"), ord("z") + 1)
        ):
            raise _ToolRejected("read_file_media_invalid")
        chunk_data = payload[offset + 8 : offset + 8 + chunk_length]
        expected_crc = int.from_bytes(payload[chunk_end - 4 : chunk_end], "big")
        actual_crc = binascii.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            raise _ToolRejected("read_file_media_invalid")
        if not saw_ihdr:
            if chunk_type != b"IHDR" or chunk_length != 13:
                raise _ToolRejected("read_file_media_invalid")
            width = int.from_bytes(chunk_data[:4], "big")
            height = int.from_bytes(chunk_data[4:8], "big")
            bit_depth, color_type, compression, filter_method, interlace = chunk_data[
                8:
            ]
            valid_depths = {
                0: {1, 2, 4, 8, 16},
                2: {8, 16},
                3: {1, 2, 4, 8},
                4: {8, 16},
                6: {8, 16},
            }
            if (
                bit_depth not in valid_depths.get(color_type, set())
                or compression != 0
                or filter_method != 0
                or interlace not in {0, 1}
            ):
                raise _ToolRejected("read_file_media_invalid")
            saw_ihdr = True
        elif chunk_type == b"IHDR":
            raise _ToolRejected("read_file_media_invalid")
        if chunk_type in {b"acTL", b"fcTL", b"fdAT"}:
            raise _ToolRejected("read_file_media_animation_unsupported")
        if chunk_type == b"IDAT":
            if idat_finished:
                raise _ToolRejected("read_file_media_invalid")
            saw_idat = True
        elif saw_idat and chunk_type != b"IEND":
            idat_finished = True
        if chunk_type == b"IEND":
            if chunk_length != 0 or not saw_idat or chunk_end != len(payload):
                raise _ToolRejected("read_file_media_invalid")
            return width, height
        if chunk_type[0] in range(ord("A"), ord("Z") + 1) and chunk_type not in {
            b"IHDR",
            b"PLTE",
            b"IDAT",
            b"IEND",
        }:
            raise _ToolRejected("read_file_media_invalid")
        offset = chunk_end
    raise _ToolRejected("read_file_media_invalid")


def _jpeg_dimensions(payload: bytes) -> tuple[int, int]:
    if not payload.startswith(b"\xff\xd8\xff"):
        raise _ToolRejected("read_file_media_invalid")
    sof_markers = {
        0xC0,
        0xC1,
        0xC2,
        0xC3,
        0xC5,
        0xC6,
        0xC7,
        0xC9,
        0xCA,
        0xCB,
        0xCD,
        0xCE,
        0xCF,
    }
    offset = 2
    while offset < len(payload):
        if payload[offset] != 0xFF:
            raise _ToolRejected("read_file_media_invalid")
        while offset < len(payload) and payload[offset] == 0xFF:
            offset += 1
        if offset >= len(payload):
            raise _ToolRejected("read_file_media_invalid")
        marker = payload[offset]
        offset += 1
        if marker in {0x00, 0x01, 0xD8, 0xD9, 0xDA} or 0xD0 <= marker <= 0xD7:
            raise _ToolRejected("read_file_media_invalid")
        if len(payload) - offset < 2:
            raise _ToolRejected("read_file_media_invalid")
        segment_length = int.from_bytes(payload[offset : offset + 2], "big")
        segment_end = offset + segment_length
        if segment_length < 2 or segment_end > len(payload):
            raise _ToolRejected("read_file_media_invalid")
        if marker in sof_markers:
            if segment_length < 11:
                raise _ToolRejected("read_file_media_invalid")
            component_count = payload[offset + 7]
            if (
                component_count == 0
                or segment_length != 8 + (3 * component_count)
                or payload[offset + 2] == 0
            ):
                raise _ToolRejected("read_file_media_invalid")
            height = int.from_bytes(payload[offset + 3 : offset + 5], "big")
            width = int.from_bytes(payload[offset + 5 : offset + 7], "big")
            return width, height
        offset = segment_end
    raise _ToolRejected("read_file_media_invalid")


def _cleanup_unknown_failure(
    *,
    execution_may_have_started: bool,
) -> ToolFatalError:
    return ToolFatalError(
        ToolFailure(
            code="terminal_actor_cleanup_unverified",
            execution_may_have_started=execution_may_have_started,
            cleanup_verified=False,
            census_verified=False,
        )
    )


def _background_transport_unknown_failure() -> ToolFatalError:
    return ToolFatalError(
        ToolFailure(
            code="terminal_actor_transport_unknown",
            execution_may_have_started=True,
            cleanup_verified=True,
            census_verified=True,
        )
    )


def _background_pre_start_transport_failure(code: str) -> ToolFatalError:
    return ToolFatalError(
        ToolFailure(
            code=code,
            execution_may_have_started=False,
            cleanup_verified=None,
            census_verified=None,
        )
    )


def _background_status_invalid_failure() -> ToolFatalError:
    return ToolFatalError(
        ToolFailure(
            code="terminal_actor_background_status_invalid",
            execution_may_have_started=True,
            cleanup_verified=True,
            census_verified=True,
        )
    )


def _truncate_utf8_bytes(payload: bytes, max_bytes: int) -> bytes:
    if len(payload) <= max_bytes:
        return payload
    marker = b"\n... output truncated ...\n"
    if max_bytes <= len(marker):
        return marker[:max_bytes]
    text = payload.decode("utf-8")
    remaining = max_bytes - len(marker)
    head_budget = remaining // 2
    tail_budget = remaining - head_budget
    head = text.encode("utf-8")[:head_budget]
    while head and (head[-1] & 0xC0) == 0x80:
        head = head[:-1]
    while True:
        try:
            head.decode("utf-8")
            break
        except UnicodeDecodeError:
            head = head[:-1]
    tail = text.encode("utf-8")[-tail_budget:]
    while tail and (tail[0] & 0xC0) == 0x80:
        tail = tail[1:]
    while True:
        try:
            tail.decode("utf-8")
            break
        except UnicodeDecodeError:
            tail = tail[1:]
    return head + marker + tail


def _render_directory_entries(
    root: str,
    entries: list[tuple[str, bool]],
    *,
    max_bytes: int,
    inventory_cutoff: bool,
) -> str:
    ordered = sorted(
        entries,
        key=lambda item: (item[0].casefold(), item[0].encode("utf-8")),
    )
    lines = [f"- {root.rstrip('/')}/\n"]
    used = len(lines[0].encode("utf-8"))
    rendered_count = 0
    reserve = 256
    for relative, is_directory in ordered:
        depth = relative.count("/")
        name = relative.rsplit("/", 1)[-1] + ("/" if is_directory else "")
        line = f"{'  ' * (depth + 1)}- {name}\n"
        if used + len(line.encode("utf-8")) + reserve > max_bytes:
            break
        lines.append(line)
        used += len(line.encode("utf-8"))
        rendered_count += 1
    if rendered_count < len(ordered):
        remaining = ordered[rendered_count:]
        files = [path for path, is_directory in remaining if not is_directory]
        extensions = Counter(
            Path(path).suffix.lower() or "[no extension]" for path in files
        )
        summary = ", ".join(
            f"{count} *{extension}"
            if extension != "[no extension]"
            else f"{count} files without extension"
            for extension, count in sorted(
                extensions.items(),
                key=lambda item: (-item[1], item[0]),
            )[:3]
        )
        lines.append(f"  [{len(files)} files in subtree: {summary or 'none'}]\n")
        inventory_cutoff = True
    if inventory_cutoff:
        lines.append("\n... output truncated ...\n")
    return "".join(lines)


def _strict_meta(raw: bytes) -> Mapping[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BridgeError("terminal_actor_meta_invalid") from error
    if not isinstance(value, dict) or set(value) != _META_KEYS:
        raise BridgeError("terminal_actor_meta_invalid")
    integer_fields = {"return_code", "survivor_count"}
    boolean_fields = _META_KEYS - integer_fields
    if any(
        isinstance(value[field], bool) or not isinstance(value[field], int)
        for field in integer_fields
    ):
        raise BridgeError("terminal_actor_meta_invalid")
    if any(not isinstance(value[field], bool) for field in boolean_fields):
        raise BridgeError("terminal_actor_meta_invalid")
    return value


def _snapshot_record_failure(
    reason: SnapshotFailureReasonV1,
    raw: object,
    *,
    terminal: bool,
) -> SnapshotTerminationUnverified:
    observed_byte_length, observed_sha256 = _bounded_snapshot_observation(raw)
    return SnapshotTerminationUnverified(
        SnapshotFailureEvidenceV1(
            subtype=(
                SnapshotFailureSubtypeV1.TERMINAL_RECORD_INVALID
                if terminal
                else SnapshotFailureSubtypeV1.LEASE_PARSE_FAILED
            ),
            reason=reason,
            observed_byte_length=observed_byte_length,
            observed_sha256=observed_sha256,
        )
    )


def _strict_snapshot_json(raw: str, *, terminal: bool) -> Mapping[str, Any]:
    try:
        value = json.loads(raw)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _snapshot_record_failure(
            SnapshotFailureReasonV1.TERMINAL_JSON_INVALID,
            raw,
            terminal=terminal,
        ) from error
    expected_keys = _SNAPSHOT_TERMINAL_KEYS if terminal else _SNAPSHOT_LEASE_KEYS
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise _snapshot_record_failure(
            SnapshotFailureReasonV1.TERMINAL_KEYSET_INVALID,
            raw,
            terminal=terminal,
        )
    integer_fields = {
        "version",
        "leader_pid",
        "leader_starttime",
        "pgid",
        "supervisor_pid",
        "supervisor_starttime",
        "supervisor_pgid",
    }
    if terminal:
        integer_fields |= {"return_code", "survivor_count"}
    boolean_fields = (
        {
            "timed_out",
            "term_sent",
            "kill_sent",
            "termination_verified",
            "census_verified",
        }
        if terminal
        else set()
    )
    if (
        any(type(value[field]) is not int for field in integer_fields)
        or any(type(value[field]) is not bool for field in boolean_fields)
        or type(value["status"]) is not str
        or type(value["owner_token"]) is not str
    ):
        raise _snapshot_record_failure(
            SnapshotFailureReasonV1.TERMINAL_FIELD_TYPE_INVALID,
            raw,
            terminal=terminal,
        )
    if (
        value["version"] != 1
        or any(
            value[field] <= 1
            for field in {
                "leader_pid",
                "leader_starttime",
                "pgid",
                "supervisor_pid",
                "supervisor_starttime",
                "supervisor_pgid",
            }
        )
        or value["leader_pid"] != value["pgid"]
        or value["supervisor_pid"] != value["supervisor_pgid"]
        or len(value["owner_token"]) != 64
        or any(
            character not in "0123456789abcdef" for character in value["owner_token"]
        )
    ):
        raise _snapshot_record_failure(
            SnapshotFailureReasonV1.TERMINAL_STATUS_INVALID,
            raw,
            terminal=terminal,
        )
    if terminal:
        if (
            value["status"]
            not in {
                "completed",
                "failed",
                "timed_out",
                "cancelled",
                "termination_unverified",
            }
            or value["return_code"] < 0
            or value["survivor_count"] < 0
            or value["kill_sent"] is True
            and value["term_sent"] is not True
            or value["status"] == "timed_out"
            and (
                value["timed_out"] is not True
                or value["return_code"] != 124
                or value["term_sent"] is not True
            )
            or value["status"] != "timed_out"
            and value["timed_out"] is True
            or value["status"] == "cancelled"
            and value["return_code"] != 125
            or value["status"] == "completed"
            and value["return_code"] != 0
        ):
            raise _snapshot_record_failure(
                SnapshotFailureReasonV1.TERMINAL_STATUS_INVALID,
                raw,
                terminal=terminal,
            )
    elif value["status"] != "running":
        raise _snapshot_record_failure(
            SnapshotFailureReasonV1.TERMINAL_STATUS_INVALID,
            raw,
            terminal=terminal,
        )
    return value


def _snapshot_lease(
    raw: str,
    *,
    control_dir: str,
    owner_token: str,
) -> _SnapshotLease:
    value = _strict_snapshot_json(raw, terminal=False)
    if value["owner_token"] != owner_token:
        raise _snapshot_record_failure(
            SnapshotFailureReasonV1.TERMINAL_IDENTITY_MISMATCH,
            raw,
            terminal=False,
        )
    return _SnapshotLease(
        control_dir=control_dir,
        owner_token=owner_token,
        leader_pid=value["leader_pid"],
        leader_starttime=value["leader_starttime"],
        pgid=value["pgid"],
        supervisor_pid=value["supervisor_pid"],
        supervisor_starttime=value["supervisor_starttime"],
        supervisor_pgid=value["supervisor_pgid"],
    )


def _snapshot_terminal(
    raw: str,
    lease: _SnapshotLease,
) -> _BoundSnapshotTerminalV1:
    value = _strict_snapshot_json(raw, terminal=True)
    identity = {
        "owner_token": lease.owner_token,
        "leader_pid": lease.leader_pid,
        "leader_starttime": lease.leader_starttime,
        "pgid": lease.pgid,
        "supervisor_pid": lease.supervisor_pid,
        "supervisor_starttime": lease.supervisor_starttime,
        "supervisor_pgid": lease.supervisor_pgid,
    }
    if any(value[field] != expected for field, expected in identity.items()):
        raise _snapshot_record_failure(
            SnapshotFailureReasonV1.TERMINAL_IDENTITY_MISMATCH,
            raw,
            terminal=True,
        )
    if not (
        value["termination_verified"] is True
        and value["census_verified"] is True
        and value["survivor_count"] == 0
        and value["status"] != "termination_unverified"
    ):
        raise _snapshot_record_failure(
            SnapshotFailureReasonV1.TERMINATION_PROOF_INVALID,
            raw,
            terminal=True,
        )
    return _BoundSnapshotTerminalV1(
        value,
        token=_SNAPSHOT_EXECUTION_BINDING_TOKEN,
    )


class RemoteTerminalActor:
    """Execute one request at a time in a remote environment."""

    def __init__(
        self,
        environment: RemoteEnvironment,
        *,
        id_factory: Callable[[], str] | None = None,
        snapshot_token_factory: Callable[[], str] | None = None,
        monotonic: Callable[[], float] | None = None,
        wall_clock: Callable[[], float] | None = None,
    ):
        self._environment = environment
        self._active: dict[str, ToolRequest] = {}
        self._background: dict[str, BackgroundTask] = {}
        self._process_lease_v1: ProcessLeaseV1 | None = None
        self._process_lease_observation_v1: tuple[dict[str, object], ...] | None = None
        self._process_lease_close_outcome_v1: bool | None = None
        self._background_spool_reserved = 0
        self._id_factory = id_factory or _uuid7
        self._snapshot_token_factory = snapshot_token_factory or (
            lambda: secrets.token_hex(32)
        )
        self._active_snapshots: dict[str, _SnapshotLease | None] = {}
        self._monotonic = monotonic or host_monotonic
        self._wall_clock = wall_clock or time.time
        self._ready = False
        self._workspace_mapping: dict[str, str] | None = None
        self._deadline_request: ToolRequest | None = None

    def _monotonic_ns(self) -> int:
        return int(self._monotonic() * 1_000_000_000)

    def _actor_phase_budget(
        self,
        request: ToolRequest,
        *,
        phase_cap_sec: float | None = None,
    ) -> tuple[int, float]:
        """Clamp one foreground RPC to the signed actor_done root."""

        now_ns = self._monotonic_ns()
        actor_done_ns = request.actor_done_monotonic_ns
        if actor_done_ns is None:
            if phase_cap_sec is None:
                raise BridgeError("terminal_actor_deadline_unavailable")
            cutoff_ns = now_ns + max(1, int(phase_cap_sec * 1_000_000_000))
        else:
            cutoff_ns = actor_done_ns
            if phase_cap_sec is not None:
                cutoff_ns = min(
                    cutoff_ns,
                    now_ns + max(1, int(phase_cap_sec * 1_000_000_000)),
                )
        if cutoff_ns <= now_ns:
            raise _ActorDoneDeadlineExceeded("terminal_actor_deadline_exceeded")
        return cutoff_ns, (cutoff_ns - now_ns) / 1_000_000_000

    def _foreground_receipt(
        self,
        request: ToolRequest,
        *,
        phase: TerminalActorPhaseV1,
        origin: TerminalActorOriginV1,
        primary_subtype: TerminalActorSubtypeV1,
        recovery_subtype: TerminalActorSubtypeV1 | None,
        execution_may_have_started: bool,
        cleanup_verified: bool | None,
        census_verified: bool | None,
        effective_cutoff_monotonic_ns: int | None = None,
    ) -> TerminalActorReceiptV1 | None:
        actor_done_ns = request.actor_done_monotonic_ns
        if actor_done_ns is None:
            return None
        cutoff_ns = (
            actor_done_ns
            if effective_cutoff_monotonic_ns is None
            else min(actor_done_ns, effective_cutoff_monotonic_ns)
        )
        return TerminalActorReceiptV1.create(
            phase=phase,
            origin=origin,
            primary_subtype=primary_subtype,
            recovery_subtype=recovery_subtype,
            execution_may_have_started=execution_may_have_started,
            effective_cutoff_monotonic_ns=max(1, cutoff_ns),
            cleanup_verified=cleanup_verified,
            census_verified=census_verified,
        )

    def _foreground_failure(
        self,
        request: ToolRequest,
        *,
        code: str,
        phase: TerminalActorPhaseV1,
        origin: TerminalActorOriginV1,
        primary_subtype: TerminalActorSubtypeV1,
        recovery_subtype: TerminalActorSubtypeV1 | None = None,
        execution_may_have_started: bool,
        cleanup_verified: bool | None,
        census_verified: bool | None,
        effective_cutoff_monotonic_ns: int | None = None,
    ) -> ToolFatalError:
        return ToolFatalError(
            ToolFailure(
                code=code,
                execution_may_have_started=execution_may_have_started,
                cleanup_verified=cleanup_verified,
                census_verified=census_verified,
                actor_receipt=self._foreground_receipt(
                    request,
                    phase=phase,
                    origin=origin,
                    primary_subtype=primary_subtype,
                    recovery_subtype=recovery_subtype,
                    execution_may_have_started=execution_may_have_started,
                    cleanup_verified=cleanup_verified,
                    census_verified=census_verified,
                    effective_cutoff_monotonic_ns=effective_cutoff_monotonic_ns,
                ),
            )
        )

    def _request_remaining_sec(
        self,
        request: ToolRequest,
        *,
        settlement: bool,
        settlement_stage: str | None = None,
    ) -> float | None:
        if settlement and settlement_stage is not None:
            stages = request.settlement_stages
            if stages is None:
                cutoff = None
            else:
                cutoff = {
                    "probe": stages.probe_monotonic_ns,
                    "output": stages.output_monotonic_ns,
                }[settlement_stage]
        else:
            cutoff = (
                request.tool_settled_monotonic_ns
                if settlement
                else request.actor_done_monotonic_ns
            )
        if cutoff is None:
            return None
        return _strict_remaining_sec(cutoff, self._monotonic_ns())

    async def _foreground_run_dispatch_rpc(
        self,
        request: ToolRequest,
        command_factory: Callable[[int], str],
        *,
        cwd: str,
    ) -> tuple[Any, int]:
        """Start the remote run and its host timer from one signed boundary."""

        actor_done_ns = request.actor_done_monotonic_ns
        if actor_done_ns is None:
            raise BridgeError("terminal_actor_deadline_unavailable")
        now_ns = self._monotonic_ns()
        remaining_ns = actor_done_ns - now_ns
        remaining_ms = remaining_ns // 1_000_000
        if remaining_ms <= 0:
            raise self._foreground_action_admission_failure(
                request,
                phase=TerminalActorPhaseV1.REMOTE_EXEC,
            )
        action_timeout_ms = min(request.timeout_ms, remaining_ms)
        timeout_sec = remaining_ns / 1_000_000_000

        async def dispatch() -> Any:
            command = command_factory(action_timeout_ms)
            return await self._environment.exec(
                command,
                cwd=cwd,
                timeout_sec=timeout_sec,
            )

        try:
            result = await asyncio.wait_for(dispatch(), timeout=timeout_sec)
        except TimeoutError as error:
            if self._monotonic_ns() >= actor_done_ns:
                raise _ActorDoneDeadlineExceeded(
                    "terminal_actor_deadline_exceeded"
                ) from error
            raise
        return result, actor_done_ns

    def _foreground_action_admission_failure(
        self,
        request: ToolRequest,
        *,
        phase: TerminalActorPhaseV1 = TerminalActorPhaseV1.REMOTE_SETUP,
    ) -> ToolFatalError:
        return self._foreground_failure(
            request,
            code="terminal_actor_action_admission_rejected",
            phase=phase,
            origin=TerminalActorOriginV1.ACTOR,
            primary_subtype=TerminalActorSubtypeV1.ACTOR_DEADLINE_EXCEEDED,
            execution_may_have_started=False,
            cleanup_verified=None,
            census_verified=None,
        )

    def _background_start_action_admitted(self, request: ToolRequest) -> bool:
        """Reserve both bounded setup and dispatch RPCs before a new start."""

        actor_done_ns = request.actor_done_monotonic_ns
        return actor_done_ns is None or (
            actor_done_ns - self._monotonic_ns()
            >= _BACKGROUND_START_ACTION_RESERVE_MS * 1_000_000
        )

    def _background_dispatch_admitted(self, request: ToolRequest) -> bool:
        actor_done_ns = request.actor_done_monotonic_ns
        required_ns = int(
            min(
                _BACKGROUND_START_DISPATCH_TIMEOUT_SEC,
                request.timeout_ms / 1000,
            )
            * 1_000_000_000
        )
        return actor_done_ns is None or (
            actor_done_ns - self._monotonic_ns() >= required_ns
        )

    @staticmethod
    def _background_start_not_started_result(
        request: ToolRequest,
        *,
        diagnostic: str,
        next_step: str,
    ) -> ToolExecution:
        return RemoteTerminalActor._direct_result(
            (
                "<observation>background_start_not_running</observation>\n"
                "<status>not_started</status>\n"
                "<exit-code>unavailable</exit-code>\n"
                f"<diagnostic>{diagnostic}</diagnostic>\n"
                f"<next-step>{next_step}</next-step>"
            ),
            request=request,
            succeeded=False,
            disposition=ProcessDisposition.NO_PROCESS,
            background_start_observation=BackgroundStartObservation(
                proof_version=BACKGROUND_START_PROOF_VERSION,
                kind=BackgroundStartKind.NOT_STARTED,
                task_id_published=False,
                child_exit_code=None,
            ),
        )

    async def setup(self) -> None:
        if self._ready:
            return
        await self._setup_workspace()
        result = await self._environment.exec(
            f"mkdir -p {shlex.quote(_REMOTE_ROOT)} && chmod 700 "
            f"{shlex.quote(_REMOTE_ROOT)}",
            timeout_sec=10,
        )
        if result.return_code != 0:
            raise BridgeError("terminal_actor_setup_failed")
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                prefix="nano-terminal-actor.",
                suffix=".sh",
                delete=False,
            ) as handle:
                handle.write(_ACTOR.encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
                temporary_path = Path(handle.name)
            await self._environment.upload_file(temporary_path, _REMOTE_ACTOR)
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
        result = await self._environment.exec(
            f"chmod 700 {shlex.quote(_REMOTE_ACTOR)}",
            timeout_sec=10,
        )
        if result.return_code != 0:
            raise BridgeError("terminal_actor_setup_failed")
        self._ready = True

    async def _setup_workspace(self) -> None:
        script = "\n".join(
            [
                "set -eu",
                "is_forbidden_workspace() {",
                '  case "$1" in',
                "    ''|/|"
                f"{_REMOTE_ROOT}|{_REMOTE_ROOT}/*|"
                "/artifact|/artifact/*|/artifacts|/artifacts/*|"
                "/log|/log/*|/logs|/logs/*|"
                "*/artifact|*/artifact/*|*/artifacts|*/artifacts/*|"
                "*/log|*/log/*|*/logs|*/logs/*|"
                "*/.terminals|*/.terminals/*) return 0;;",
                "    *) return 1;;",
                "  esac",
                "}",
                "default_cwd=$(/bin/pwd -P)",
                'test -n "$default_cwd"',
                'canonical_default=$(realpath -e -- "$default_cwd")',
                'test -d "$canonical_default"',
                'test "$default_cwd" = "$canonical_default"',
                'if is_forbidden_workspace "$canonical_default"; then exit 91; fi',
                f"logical={shlex.quote(_LOGICAL_WORKSPACE)}",
                'if test -L "$logical"; then',
                '  canonical=$(realpath -e -- "$logical")',
                '  test -d "$canonical"',
                '  test "$canonical" = "$canonical_default" || exit 92',
                "  mode=existing_symlink",
                'elif test -e "$logical"; then',
                '  test -d "$logical"',
                '  canonical=$(realpath -e -- "$logical")',
                "  mode=existing_directory",
                "else",
                '  ln -s -- "$canonical_default" "$logical"',
                '  canonical=$(realpath -e -- "$logical")',
                '  test "$canonical" = "$canonical_default" || exit 93',
                "  mode=created_symlink",
                "fi",
                'if is_forbidden_workspace "$canonical"; then exit 94; fi',
                'scratch=$(realpath -e -- "${TMPDIR:-/tmp}")',
                'test -d "$scratch"',
                'test "$scratch" != "/"',
                'printf "%s\\n" "$mode"',
                'printf %s "$canonical_default" | base64 | tr -d "\\n"',
                "printf '\\n'",
                'printf %s "$canonical" | base64 | tr -d "\\n"',
                "printf '\\n'",
                'printf %s "$scratch" | base64 | tr -d "\\n"',
                "printf '\\n'",
            ]
        )
        try:
            result = await self._environment.exec(
                f"/bin/bash -c {shlex.quote(script)}",
                timeout_sec=10,
            )
        except BaseException as error:
            raise BridgeError("terminal_actor_workspace_setup_failed") from error
        if result.return_code != 0:
            raise BridgeError("terminal_actor_workspace_setup_failed")
        lines = result.stdout.splitlines()
        if len(lines) != 4 or lines[0] not in _WORKSPACE_MAPPING_MODES:
            raise BridgeError("terminal_actor_workspace_setup_invalid")
        try:
            default_cwd, canonical_cwd, scratch_root = (
                base64.b64decode(value, validate=True).decode("utf-8")
                for value in lines[1:]
            )
        except (ValueError, UnicodeDecodeError) as error:
            raise BridgeError("terminal_actor_workspace_setup_invalid") from error
        for value in (default_cwd, canonical_cwd, scratch_root):
            if not _workspace_root_is_safe(value):
                raise BridgeError("terminal_actor_workspace_setup_invalid")
        if scratch_root == canonical_cwd or scratch_root.startswith(
            f"{canonical_cwd.rstrip('/')}/"
        ):
            scratch_root = canonical_cwd
        if lines[0] != "existing_directory" and canonical_cwd != default_cwd:
            raise BridgeError("terminal_actor_workspace_setup_invalid")
        self._workspace_mapping = {
            "canonical_cwd": canonical_cwd,
            "default_cwd": default_cwd,
            "logical_cwd": _LOGICAL_WORKSPACE,
            "mode": lines[0],
            "scratch_root": scratch_root,
        }

    def diagnostic_metadata(self) -> dict[str, object]:
        if self._workspace_mapping is None:
            raise BridgeError("terminal_actor_workspace_not_mapped")
        return {
            "workspace_mapping": dict(self._workspace_mapping),
            "allowed_roots": list(self._allowed_roots()),
        }

    def snapshot_workspace_root(self) -> str:
        """Return the canonical remote workspace bound during actor setup."""

        return self._canonical_workspace()

    async def exec_snapshot(
        self,
        command: str,
        *,
        timeout_sec: float,
    ) -> SnapshotCommandResult:
        """Run one bounded, trusted snapshot command in the bound workspace."""

        if (
            not isinstance(command, str)
            or not command
            or "\x00" in command
            or len(command.encode("utf-8")) > 1024 * 1024
            or isinstance(timeout_sec, bool)
            or not isinstance(timeout_sec, int | float)
            or timeout_sec <= 0
            or timeout_sec == float("inf")
            or timeout_sec != timeout_sec
        ):
            raise BridgeError("terminal_actor_snapshot_request_invalid")
        validated_timeout_sec = float(timeout_sec)
        try:
            result = await self._environment.exec(
                command,
                cwd=self._canonical_workspace(),
                timeout_sec=validated_timeout_sec,
            )
        except RuntimeError as error:
            expected = f"Command timed out after {validated_timeout_sec} seconds"
            if type(error) is RuntimeError and error.args == (expected,):
                raise SnapshotTransportTimeout() from error
            raise
        if (
            type(result.return_code) is not int
            or type(result.stdout) is not str
            or type(result.stderr) is not str
        ):
            raise BridgeError("terminal_actor_snapshot_response_invalid")
        return SnapshotCommandResult(
            return_code=result.return_code,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    @staticmethod
    def _snapshot_identity_arguments(lease: _SnapshotLease) -> list[str]:
        return [
            lease.owner_token,
            str(lease.leader_pid),
            str(lease.leader_starttime),
            str(lease.pgid),
            str(lease.supervisor_pid),
            str(lease.supervisor_starttime),
            str(lease.supervisor_pgid),
        ]

    def _snapshot_bounded_timeout(
        self,
        requested_sec: float,
        hard_deadline_monotonic_ns: int | None,
    ) -> float:
        if hard_deadline_monotonic_ns is None:
            return requested_sec
        remaining_sec = (
            hard_deadline_monotonic_ns - self._monotonic_ns()
        ) / 1_000_000_000
        if remaining_sec <= 0:
            raise SnapshotTransportTimeout(
                subtype=SnapshotFailureSubtypeV1.WAIT_TRANSPORT_FAILED,
                timeout_origin=(
                    SnapshotTimeoutOriginV1.WAIT_TRANSPORT_TIMED_OUT_UNRECOVERED
                ),
                stage_validated=True,
            )
        return min(requested_sec, remaining_sec)

    async def _snapshot_deadline_await(
        self,
        awaitable: Awaitable[Any],
        hard_deadline_monotonic_ns: int | None,
    ) -> Any:
        if hard_deadline_monotonic_ns is None:
            return await awaitable
        try:
            timeout_sec = self._snapshot_bounded_timeout(
                float(2**31),
                hard_deadline_monotonic_ns,
            )
        except BaseException:
            if asyncio.iscoroutine(awaitable):
                awaitable.close()
            raise
        timeout = asyncio.timeout(timeout_sec)
        try:
            async with timeout:
                return await awaitable
        except TimeoutError as error:
            if timeout.expired():
                raise _SnapshotDeadlineExceeded from error
            raise

    async def _snapshot_exec(
        self,
        command: str,
        *,
        requested_timeout_sec: float,
        deadline_monotonic_ns: int | None,
    ) -> Any:
        timeout_sec = self._snapshot_bounded_timeout(
            requested_timeout_sec,
            deadline_monotonic_ns,
        )
        try:
            return await self._snapshot_deadline_await(
                self._environment.exec(
                    command,
                    cwd=self._canonical_workspace(),
                    timeout_sec=timeout_sec,
                ),
                deadline_monotonic_ns,
            )
        except RuntimeError as error:
            if error.args == (f"Command timed out after {timeout_sec} seconds",):
                raise _SnapshotDeadlineExceeded from error
            raise

    async def _inspect_snapshot_lease(
        self,
        control_dir: str,
        owner_token: str,
        *,
        hard_deadline_monotonic_ns: int | None = None,
    ) -> _SnapshotLease:
        command = " ".join(
            [
                "/bin/bash",
                shlex.quote(_REMOTE_ACTOR),
                "snapshot-inspect",
                shlex.quote(control_dir),
                owner_token,
            ]
        )
        try:
            result = await self._snapshot_exec(
                command,
                requested_timeout_sec=_SNAPSHOT_LAUNCH_TIMEOUT_SEC,
                deadline_monotonic_ns=hard_deadline_monotonic_ns,
            )
        except BaseException as error:
            raise SnapshotTerminationUnverified() from error
        try:
            result = _validate_snapshot_outer_result(
                result,
                boundary_subtype=SnapshotFailureSubtypeV1.RECOVERY_UNVERIFIED,
            )
        except SnapshotOperationFailure as error:
            raise SnapshotTerminationUnverified(error.evidence) from error
        return _snapshot_lease(
            result.stdout,
            control_dir=control_dir,
            owner_token=owner_token,
        )

    async def _cancel_snapshot_lease(
        self,
        lease: _SnapshotLease,
        *,
        hard_deadline_monotonic_ns: int | None = None,
    ) -> _BoundSnapshotTerminalV1:
        wait_ms = (
            _SNAPSHOT_TERM_GRACE_MS * 2
            + _SNAPSHOT_CONFIRMATION_MS * 2
            + int(_SNAPSHOT_CONTROL_GUARD_SEC * 1000)
        )
        command = " ".join(
            [
                "/bin/bash",
                shlex.quote(_REMOTE_ACTOR),
                "snapshot-cancel",
                shlex.quote(lease.control_dir),
                *self._snapshot_identity_arguments(lease),
                str(wait_ms),
            ]
        )
        try:
            result = await self._snapshot_exec(
                command,
                requested_timeout_sec=(wait_ms / 1000 + _SNAPSHOT_REAP_TIMEOUT_SEC),
                deadline_monotonic_ns=hard_deadline_monotonic_ns,
            )
        except BaseException as error:
            raise SnapshotTerminationUnverified() from error
        try:
            result = _validate_snapshot_outer_result(
                result,
                boundary_subtype=SnapshotFailureSubtypeV1.RECOVERY_UNVERIFIED,
            )
        except SnapshotOperationFailure as error:
            raise SnapshotTerminationUnverified(error.evidence) from error
        terminal = _snapshot_terminal(result.stdout, lease)
        self._active_snapshots.pop(lease.control_dir, None)
        return terminal

    async def _release_snapshot_lease(
        self,
        lease: _SnapshotLease,
        *,
        hard_deadline_monotonic_ns: int | None = None,
    ) -> None:
        command = " ".join(
            [
                "/bin/bash",
                shlex.quote(_REMOTE_ACTOR),
                "snapshot-release",
                shlex.quote(lease.control_dir),
                *self._snapshot_identity_arguments(lease),
            ]
        )
        result = await self._snapshot_exec(
            command,
            requested_timeout_sec=_SNAPSHOT_LAUNCH_TIMEOUT_SEC,
            deadline_monotonic_ns=hard_deadline_monotonic_ns,
        )
        try:
            result = _validate_snapshot_outer_result(
                result,
                boundary_subtype=SnapshotFailureSubtypeV1.LEASE_RELEASE_FAILED,
            )
        except SnapshotOperationFailure as error:
            raise SnapshotTerminationUnverified(error.evidence) from error
        if result.stdout != "released\n":
            raise SnapshotTerminationUnverified(
                SnapshotFailureEvidenceV1(
                    SnapshotFailureSubtypeV1.LEASE_RELEASE_FAILED,
                    reason=SnapshotFailureReasonV1.NOT_APPLICABLE,
                )
            )

    async def _recover_snapshot_execution(
        self,
        control_dir: str,
        owner_token: str,
        lease: _SnapshotLease | None,
        *,
        hard_deadline_monotonic_ns: int | None = None,
    ) -> _BoundSnapshotTerminalV1:
        if lease is None:
            lease = await self._inspect_snapshot_lease(
                control_dir,
                owner_token,
                hard_deadline_monotonic_ns=hard_deadline_monotonic_ns,
            )
            self._active_snapshots[control_dir] = lease
        return await self._cancel_snapshot_lease(
            lease,
            hard_deadline_monotonic_ns=hard_deadline_monotonic_ns,
        )

    async def _settle_snapshot_recovery(
        self,
        control_dir: str,
        owner_token: str,
        lease: _SnapshotLease | None,
        *,
        hard_deadline_monotonic_ns: int | None = None,
    ) -> tuple[_BoundSnapshotTerminalV1, asyncio.CancelledError | None]:
        """Settle one recovery task despite repeated caller cancellation."""

        task = asyncio.create_task(
            self._recover_snapshot_execution(
                control_dir,
                owner_token,
                lease,
                hard_deadline_monotonic_ns=hard_deadline_monotonic_ns,
            )
        )
        cancellation: asyncio.CancelledError | None = None
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError as error:
                cancellation = error
            except BaseException:
                break
        return task.result(), cancellation

    async def _raise_after_snapshot_recovery(
        self,
        primary: BaseException,
        terminal: Mapping[str, Any],
        *,
        transport_timeout_sec: float | None = None,
    ) -> None:
        execution_binding_verified = _snapshot_execution_binding_verified(terminal)
        if isinstance(primary, asyncio.CancelledError):
            raise SnapshotOperationCancelled(
                SnapshotFailureEvidenceV1(
                    SnapshotFailureSubtypeV1.WAIT_TRANSPORT_FAILED,
                    stage_validated=True,
                    termination_verified=True,
                    zero_census_verified=True,
                    execution_binding_verified=execution_binding_verified,
                    reason=SnapshotFailureReasonV1.TERMINAL_CANCELLED,
                )
            ) from primary
        exact_transport_timeout = (
            primary.__cause__
            if isinstance(primary, SnapshotOperationFailure)
            else primary
        )
        if isinstance(exact_transport_timeout, _SnapshotDeadlineExceeded) or (
            type(exact_transport_timeout) is RuntimeError
            and transport_timeout_sec is not None
            and exact_transport_timeout.args
            == (f"Command timed out after {transport_timeout_sec} seconds",)
        ):
            raise SnapshotTransportTimeout(
                termination_verified=True,
                census_verified=True,
                survivor_count=0,
                stage_validated=True,
                timeout_origin=(
                    SnapshotTimeoutOriginV1.WAIT_TRANSPORT_TIMED_OUT_RECOVERED
                ),
                execution_binding_verified=execution_binding_verified,
            ) from primary
        if terminal["status"] == "timed_out":
            raise SnapshotTransportTimeout(
                termination_verified=True,
                census_verified=True,
                survivor_count=0,
                stage_validated=True,
                timeout_origin=SnapshotTimeoutOriginV1.SEMANTIC_EXECUTION_TIMED_OUT,
                execution_binding_verified=execution_binding_verified,
            ) from primary
        if isinstance(primary, SnapshotOperationFailure):
            raise SnapshotOperationFailure(
                replace(
                    primary.evidence,
                    stage_validated=True,
                    termination_verified=True,
                    zero_census_verified=True,
                    execution_binding_verified=execution_binding_verified,
                ),
                return_code=primary.return_code,
            ) from primary
        if isinstance(primary, SnapshotTerminationUnverified):
            raise SnapshotOperationFailure(
                replace(
                    primary.evidence,
                    stage_validated=True,
                    termination_verified=True,
                    zero_census_verified=True,
                    execution_binding_verified=execution_binding_verified,
                ),
            ) from primary
        raise SnapshotOperationFailure(
            SnapshotFailureSubtypeV1.UNKNOWN_INTERNAL,
            stage_validated=True,
            termination_verified=True,
            zero_census_verified=True,
            execution_binding_verified=execution_binding_verified,
            reason=SnapshotFailureReasonV1.UNKNOWN,
        ) from primary

    async def exec_snapshot_owned(
        self,
        command: str,
        *,
        stage: str,
        timeout_sec: float,
        capture_deadline_monotonic_ns: int | None = None,
        hard_deadline_monotonic_ns: int | None = None,
    ) -> SnapshotCommandResult:
        """Run a long snapshot capture under an exact in-container lease."""

        operation_start_monotonic_ns = self._monotonic_ns()
        if (
            not isinstance(command, str)
            or not command
            or "\x00" in command
            or len(command.encode("utf-8")) > 1024 * 1024
            or not isinstance(stage, str)
            or not stage.startswith("/tmp/nano-workspace-snapshot-v1.")
            or posixpath.dirname(stage) != "/tmp"
            or posixpath.normpath(stage) != stage
            or "\x00" in stage
            or isinstance(timeout_sec, bool)
            or not isinstance(timeout_sec, int | float)
            or timeout_sec <= 0
            or timeout_sec == float("inf")
            or timeout_sec != timeout_sec
            or capture_deadline_monotonic_ns is not None
            and (
                isinstance(capture_deadline_monotonic_ns, bool)
                or not isinstance(capture_deadline_monotonic_ns, int)
            )
            or hard_deadline_monotonic_ns is not None
            and (
                isinstance(hard_deadline_monotonic_ns, bool)
                or not isinstance(hard_deadline_monotonic_ns, int)
                or hard_deadline_monotonic_ns <= operation_start_monotonic_ns
            )
            or capture_deadline_monotonic_ns is not None
            and hard_deadline_monotonic_ns is not None
            and capture_deadline_monotonic_ns > hard_deadline_monotonic_ns
        ):
            raise BridgeError("terminal_actor_snapshot_request_invalid")
        if (
            capture_deadline_monotonic_ns is not None
            and capture_deadline_monotonic_ns <= operation_start_monotonic_ns
        ):
            raise SnapshotTransportTimeout(
                termination_verified=True,
                census_verified=True,
                survivor_count=0,
                stage_validated=True,
                timeout_origin=(
                    SnapshotTimeoutOriginV1.WAIT_TRANSPORT_TIMED_OUT_UNRECOVERED
                ),
            )
        operation_deadline_monotonic_ns = capture_deadline_monotonic_ns
        if hard_deadline_monotonic_ns is not None:
            operation_deadline_monotonic_ns = (
                hard_deadline_monotonic_ns
                if operation_deadline_monotonic_ns is None
                else min(
                    operation_deadline_monotonic_ns,
                    hard_deadline_monotonic_ns,
                )
            )
        owner_token = self._snapshot_token_factory()
        if (
            not isinstance(owner_token, str)
            or len(owner_token) != 64
            or any(character not in "0123456789abcdef" for character in owner_token)
        ):
            raise BridgeError("terminal_actor_snapshot_token_invalid")
        control_dir = f"{stage}/.nano-snapshot-execution-{owner_token}"
        if control_dir in self._active_snapshots:
            raise BridgeError("terminal_actor_snapshot_duplicate_lease")
        try:
            self._snapshot_bounded_timeout(
                float(timeout_sec),
                operation_deadline_monotonic_ns,
            )
        except SnapshotTransportTimeout as error:
            raise SnapshotTransportTimeout(
                termination_verified=True,
                census_verified=True,
                survivor_count=0,
                stage_validated=True,
                timeout_origin=(
                    SnapshotTimeoutOriginV1.WAIT_TRANSPORT_TIMED_OUT_UNRECOVERED
                ),
            ) from error
        self._active_snapshots[control_dir] = None
        lease: _SnapshotLease | None = None
        temporary_path: Path | None = None
        try:
            try:
                setup = await self._snapshot_exec(
                    f"test -d {shlex.quote(stage)} && "
                    f"test ! -e {shlex.quote(control_dir)} && "
                    f"mkdir -- {shlex.quote(control_dir)} && "
                    f"chmod 700 {shlex.quote(control_dir)}",
                    requested_timeout_sec=_SNAPSHOT_LAUNCH_TIMEOUT_SEC,
                    deadline_monotonic_ns=operation_deadline_monotonic_ns,
                )
            except BaseException as error:
                self._active_snapshots.pop(control_dir, None)
                raise SnapshotOperationFailure(
                    SnapshotFailureSubtypeV1.OWNED_STAGE_SETUP_FAILED,
                    stage_validated=True,
                    termination_verified=True,
                    zero_census_verified=True,
                ) from error
            try:
                _validate_snapshot_outer_result(
                    setup,
                    boundary_subtype=(
                        SnapshotFailureSubtypeV1.OWNED_STAGE_SETUP_FAILED
                    ),
                )
            except SnapshotOperationFailure as error:
                self._active_snapshots.pop(control_dir, None)
                raise SnapshotOperationFailure(
                    replace(
                        error.evidence,
                        stage_validated=True,
                        termination_verified=True,
                        zero_census_verified=True,
                    ),
                    return_code=error.return_code,
                ) from error
            with tempfile.NamedTemporaryFile(
                prefix="nano-snapshot-command.",
                suffix=".sh",
                delete=False,
            ) as handle:
                handle.write(b"#!/bin/bash\n")
                handle.write(command.encode("utf-8"))
                handle.write(b"\n")
                handle.flush()
                os.fsync(handle.fileno())
                temporary_path = Path(handle.name)
            try:
                await self._snapshot_deadline_await(
                    self._environment.upload_file(
                        temporary_path,
                        f"{control_dir}/command.sh",
                    ),
                    operation_deadline_monotonic_ns,
                )
            except BaseException as error:
                self._active_snapshots.pop(control_dir, None)
                raise SnapshotOperationFailure(
                    SnapshotFailureSubtypeV1.COMMAND_UPLOAD_FAILED,
                    stage_validated=True,
                    termination_verified=True,
                    zero_census_verified=True,
                ) from error
            semantic_timeout_ms = max(
                1,
                int(
                    self._snapshot_bounded_timeout(
                        float(timeout_sec),
                        operation_deadline_monotonic_ns,
                    )
                    * 1000
                ),
            )
            launch_command = " ".join(
                [
                    "/bin/bash",
                    shlex.quote(_REMOTE_ACTOR),
                    "snapshot-start",
                    shlex.quote(control_dir),
                    shlex.quote(self._canonical_workspace()),
                    str(semantic_timeout_ms),
                    str(_SNAPSHOT_TERM_GRACE_MS),
                    str(_SNAPSHOT_CONFIRMATION_MS),
                    owner_token,
                    str(_SNAPSHOT_OUTPUT_CAP_BYTES),
                ]
            )
            try:
                launch = await self._snapshot_exec(
                    launch_command,
                    requested_timeout_sec=_SNAPSHOT_LAUNCH_TIMEOUT_SEC,
                    deadline_monotonic_ns=operation_deadline_monotonic_ns,
                )
            except BaseException as error:
                raise SnapshotOperationFailure(
                    SnapshotFailureSubtypeV1.LAUNCH_FAILED,
                    stage_validated=True,
                ) from error
            try:
                launch = _validate_snapshot_outer_result(
                    launch,
                    boundary_subtype=SnapshotFailureSubtypeV1.LAUNCH_FAILED,
                )
            except SnapshotOperationFailure as error:
                raise SnapshotOperationFailure(
                    replace(error.evidence, stage_validated=True),
                    return_code=error.return_code,
                ) from error
            try:
                lease = _snapshot_lease(
                    launch.stdout,
                    control_dir=control_dir,
                    owner_token=owner_token,
                )
            except BaseException as error:
                evidence = getattr(error, "evidence", None)
                raise SnapshotOperationFailure(
                    (
                        replace(
                            evidence,
                            subtype=SnapshotFailureSubtypeV1.LEASE_PARSE_FAILED,
                            stage_validated=True,
                        )
                        if isinstance(evidence, SnapshotFailureEvidenceV1)
                        else SnapshotFailureSubtypeV1.LEASE_PARSE_FAILED
                    ),
                    stage_validated=True,
                ) from error
            self._active_snapshots[control_dir] = lease
            try:
                await self._release_snapshot_lease(
                    lease,
                    hard_deadline_monotonic_ns=operation_deadline_monotonic_ns,
                )
            except BaseException as error:
                evidence = getattr(error, "evidence", None)
                raise SnapshotOperationFailure(
                    (
                        replace(
                            evidence,
                            subtype=SnapshotFailureSubtypeV1.LEASE_RELEASE_FAILED,
                            stage_validated=True,
                        )
                        if isinstance(evidence, SnapshotFailureEvidenceV1)
                        else SnapshotFailureSubtypeV1.LEASE_RELEASE_FAILED
                    ),
                    stage_validated=True,
                ) from error

            wait_ms = (
                semantic_timeout_ms
                + _SNAPSHOT_TERM_GRACE_MS * 2
                + _SNAPSHOT_CONFIRMATION_MS * 2
                + int(_SNAPSHOT_CONTROL_GUARD_SEC * 1000)
            )
            wait_command = " ".join(
                [
                    "/bin/bash",
                    shlex.quote(_REMOTE_ACTOR),
                    "snapshot-wait",
                    shlex.quote(control_dir),
                    *self._snapshot_identity_arguments(lease),
                    str(wait_ms),
                ]
            )
            transport_timeout_sec = self._snapshot_bounded_timeout(
                wait_ms / 1000 + _SNAPSHOT_REAP_TIMEOUT_SEC,
                operation_deadline_monotonic_ns,
            )
            try:
                settled = await self._snapshot_exec(
                    wait_command,
                    requested_timeout_sec=transport_timeout_sec,
                    deadline_monotonic_ns=operation_deadline_monotonic_ns,
                )
            except BaseException as error:
                if isinstance(error, asyncio.CancelledError):
                    primary = error
                else:
                    primary = SnapshotOperationFailure(
                        SnapshotFailureSubtypeV1.WAIT_TRANSPORT_FAILED,
                        timeout_origin=(
                            SnapshotTimeoutOriginV1.WAIT_TRANSPORT_TIMED_OUT_UNRECOVERED
                            if isinstance(error, _SnapshotDeadlineExceeded)
                            or (
                                type(error) is RuntimeError
                                and error.args
                                == (
                                    "Command timed out after "
                                    f"{transport_timeout_sec} seconds",
                                )
                            )
                            else SnapshotTimeoutOriginV1.NOT_A_TIMEOUT
                        ),
                        stage_validated=True,
                    )
                    primary.__cause__ = error
                try:
                    (
                        terminal,
                        recovery_cancellation,
                    ) = await self._settle_snapshot_recovery(
                        control_dir,
                        owner_token,
                        lease,
                        hard_deadline_monotonic_ns=(hard_deadline_monotonic_ns),
                    )
                except BaseException as recovery_error:
                    evidence = getattr(recovery_error, "evidence", None)
                    raise SnapshotTerminationUnverified(
                        (
                            replace(
                                evidence,
                                subtype=SnapshotFailureSubtypeV1.RECOVERY_UNVERIFIED,
                                stage_validated=True,
                            )
                            if isinstance(evidence, SnapshotFailureEvidenceV1)
                            else SnapshotFailureSubtypeV1.RECOVERY_UNVERIFIED
                        ),
                        stage_validated=True,
                    ) from primary
                if recovery_cancellation is not None:
                    primary = recovery_cancellation
                await self._raise_after_snapshot_recovery(
                    primary,
                    terminal,
                    transport_timeout_sec=transport_timeout_sec,
                )
                raise AssertionError("snapshot recovery unexpectedly returned")
            try:
                settled = _validate_snapshot_outer_result(
                    settled,
                    boundary_subtype=SnapshotFailureSubtypeV1.WAIT_RESPONSE_INVALID,
                )
            except SnapshotOperationFailure as error:
                raise SnapshotOperationFailure(
                    replace(error.evidence, stage_validated=True),
                    return_code=error.return_code,
                ) from error
            try:
                terminal = _snapshot_terminal(settled.stdout, lease)
            except BaseException as error:
                evidence = getattr(error, "evidence", None)
                primary = SnapshotOperationFailure(
                    (
                        replace(
                            evidence,
                            subtype=SnapshotFailureSubtypeV1.TERMINAL_RECORD_INVALID,
                            stage_validated=True,
                        )
                        if isinstance(evidence, SnapshotFailureEvidenceV1)
                        else SnapshotFailureSubtypeV1.TERMINAL_RECORD_INVALID
                    ),
                    stage_validated=True,
                )
                primary.__cause__ = error
                if (
                    not isinstance(evidence, SnapshotFailureEvidenceV1)
                    or evidence.reason
                    is not SnapshotFailureReasonV1.TERMINAL_JSON_INVALID
                ):
                    raise primary from error
                try:
                    (
                        terminal,
                        recovery_cancellation,
                    ) = await self._settle_snapshot_recovery(
                        control_dir,
                        owner_token,
                        lease,
                        hard_deadline_monotonic_ns=hard_deadline_monotonic_ns,
                    )
                except BaseException as recovery_error:
                    recovery_evidence = getattr(recovery_error, "evidence", None)
                    raise SnapshotTerminationUnverified(
                        (
                            replace(
                                recovery_evidence,
                                subtype=SnapshotFailureSubtypeV1.RECOVERY_UNVERIFIED,
                                stage_validated=True,
                            )
                            if isinstance(recovery_evidence, SnapshotFailureEvidenceV1)
                            else SnapshotFailureSubtypeV1.RECOVERY_UNVERIFIED
                        ),
                        stage_validated=True,
                    ) from primary
                if recovery_cancellation is not None or terminal["status"] not in {
                    "completed",
                    "failed",
                }:
                    await self._raise_after_snapshot_recovery(
                        recovery_cancellation or primary,
                        terminal,
                    )
                    raise AssertionError("snapshot recovery unexpectedly returned")
            self._active_snapshots.pop(control_dir, None)
            execution_binding_verified = _snapshot_execution_binding_verified(terminal)
            if terminal["status"] == "timed_out":
                raise SnapshotTransportTimeout(
                    termination_verified=True,
                    census_verified=True,
                    survivor_count=0,
                    stage_validated=True,
                    timeout_origin=(
                        SnapshotTimeoutOriginV1.SEMANTIC_EXECUTION_TIMED_OUT
                    ),
                    execution_binding_verified=execution_binding_verified,
                )
            if terminal["status"] == "cancelled":
                observed_byte_length, observed_sha256 = _bounded_snapshot_observation(
                    settled.stdout
                )
                raise SnapshotOperationFailure(
                    SnapshotFailureEvidenceV1(
                        SnapshotFailureSubtypeV1.TERMINAL_RECORD_INVALID,
                        stage_validated=True,
                        termination_verified=True,
                        zero_census_verified=True,
                        execution_binding_verified=execution_binding_verified,
                        reason=SnapshotFailureReasonV1.TERMINAL_CANCELLED,
                        observed_byte_length=observed_byte_length,
                        observed_sha256=observed_sha256,
                    )
                )
            try:
                with tempfile.TemporaryDirectory(
                    prefix="nano-snapshot-output."
                ) as temporary:
                    stdout_path = Path(temporary) / "stdout.bin"
                    stderr_path = Path(temporary) / "stderr.bin"
                    await self._snapshot_deadline_await(
                        self._environment.download_file(
                            f"{control_dir}/stdout.bin",
                            stdout_path,
                        ),
                        operation_deadline_monotonic_ns,
                    )
                    await self._snapshot_deadline_await(
                        self._environment.download_file(
                            f"{control_dir}/stderr.bin",
                            stderr_path,
                        ),
                        operation_deadline_monotonic_ns,
                    )
                    stdout = stdout_path.read_text(
                        encoding="utf-8",
                        errors="replace",
                    )
                    stderr = stderr_path.read_text(
                        encoding="utf-8",
                        errors="replace",
                    )
            except BaseException as error:
                raise SnapshotOperationFailure(
                    SnapshotFailureSubtypeV1.OUTPUT_DOWNLOAD_FAILED,
                    stage_validated=True,
                    termination_verified=True,
                    zero_census_verified=True,
                    execution_binding_verified=execution_binding_verified,
                ) from error
            return SnapshotCommandResult(
                return_code=terminal["return_code"],
                stdout=stdout,
                stderr=stderr,
                termination_verified=True,
                census_verified=True,
                survivor_count=0,
            )
        except BaseException as primary:
            proof = getattr(primary, "evidence", None)
            if (
                isinstance(proof, SnapshotFailureEvidenceV1)
                and proof.termination_verified
                and proof.zero_census_verified
            ):
                raise
            try:
                terminal, recovery_cancellation = await self._settle_snapshot_recovery(
                    control_dir,
                    owner_token,
                    lease,
                    hard_deadline_monotonic_ns=hard_deadline_monotonic_ns,
                )
            except BaseException as recovery_error:
                evidence = getattr(recovery_error, "evidence", None)
                raise SnapshotTerminationUnverified(
                    (
                        replace(
                            evidence,
                            subtype=SnapshotFailureSubtypeV1.RECOVERY_UNVERIFIED,
                            stage_validated=True,
                        )
                        if isinstance(evidence, SnapshotFailureEvidenceV1)
                        else SnapshotFailureSubtypeV1.RECOVERY_UNVERIFIED
                    ),
                    stage_validated=True,
                ) from primary
            if recovery_cancellation is not None:
                primary = recovery_cancellation
            await self._raise_after_snapshot_recovery(primary, terminal)
            raise AssertionError("snapshot recovery unexpectedly returned")
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    async def download_snapshot(
        self,
        source_path: str,
        target_path: Path | str,
    ) -> None:
        """Download one snapshot payload through the remote environment."""

        if (
            not isinstance(source_path, str)
            or not source_path.startswith("/")
            or posixpath.normpath(source_path) != source_path
            or "\x00" in source_path
            or len(source_path.encode("utf-8")) > 4096
        ):
            raise BridgeError("terminal_actor_snapshot_path_invalid")
        await self._environment.download_file(source_path, target_path)

    async def upload_snapshot(
        self,
        source_path: Path | str,
        target_path: str,
    ) -> None:
        """Upload one host-held snapshot payload through the remote environment."""

        source = Path(source_path)
        if (
            not source.is_absolute()
            or source.is_symlink()
            or not source.is_file()
            or not isinstance(target_path, str)
            or not target_path.startswith("/")
            or posixpath.normpath(target_path) != target_path
            or "\x00" in target_path
            or len(target_path.encode("utf-8")) > 4096
        ):
            raise BridgeError("terminal_actor_snapshot_path_invalid")
        await self._environment.upload_file(source, target_path)

    def _canonical_workspace(self) -> str:
        if self._workspace_mapping is None:
            raise BridgeError("terminal_actor_workspace_not_mapped")
        return self._workspace_mapping["canonical_cwd"]

    def _translate_logical_path(self, value: str) -> str:
        canonical = self._canonical_workspace()
        if value == _LOGICAL_WORKSPACE:
            return canonical
        prefix = f"{_LOGICAL_WORKSPACE}/"
        if value.startswith(prefix):
            return f"{canonical.rstrip('/')}/{value.removeprefix(prefix)}"
        return value

    def _allowed_roots(self) -> tuple[str, ...]:
        canonical = self._canonical_workspace()
        scratch = (
            self._workspace_mapping.get("scratch_root")
            if self._workspace_mapping is not None
            else None
        )
        roots = {
            root
            for root in (canonical, scratch)
            if isinstance(root, str) and _workspace_root_is_safe(root)
        }
        return tuple(sorted(roots, key=lambda root: (-len(root), root)))

    def _allowed_root_for(self, path: str) -> str | None:
        normalized = posixpath.normpath(path)
        if (
            normalized == _REMOTE_ROOT
            or normalized.startswith(f"{_REMOTE_ROOT}/")
            or any(part == ".terminals" for part in normalized.split("/"))
        ):
            return None
        return next(
            (
                root
                for root in self._allowed_roots()
                if normalized == root or normalized.startswith(f"{root.rstrip('/')}/")
            ),
            None,
        )

    async def _prepare_request(self, request: ToolRequest) -> str:
        if request.logical_cwd != _LOGICAL_WORKSPACE:
            raise BridgeError("terminal_actor_logical_cwd_invalid")
        canonical = self._canonical_workspace()
        legacy_timeout_sec = min(
            _WORKSPACE_MAPPING_CHECK_TIMEOUT_SEC,
            request.timeout_ms / 1000,
        )
        script = "\n".join(
            [
                "set -eu",
                f"actual=$(realpath -e -- {shlex.quote(_LOGICAL_WORKSPACE)})",
                f'test "$actual" = {shlex.quote(canonical)}',
                'test -d "$actual"',
            ]
        )
        for attempt in range(_WORKSPACE_MAPPING_CHECK_MAX_ATTEMPTS):
            try:
                if request.actor_done_monotonic_ns is None:
                    cutoff_ns = None
                    timeout_sec = legacy_timeout_sec
                else:
                    cutoff_ns, timeout_sec = self._actor_phase_budget(
                        request,
                        phase_cap_sec=_WORKSPACE_MAPPING_CHECK_TIMEOUT_SEC,
                    )
            except _ActorDoneDeadlineExceeded as error:
                if (
                    request.tool_name == "run_terminal_command"
                    and not request.arguments.get("background", False)
                ):
                    raise self._foreground_failure(
                        request,
                        code="terminal_actor_deadline_exceeded",
                        phase=TerminalActorPhaseV1.MAPPING_PREFLIGHT,
                        origin=TerminalActorOriginV1.ACTOR,
                        primary_subtype=(
                            TerminalActorSubtypeV1.ACTOR_DEADLINE_EXCEEDED
                        ),
                        execution_may_have_started=False,
                        cleanup_verified=None,
                        census_verified=None,
                    ) from error
                raise BridgeError("terminal_actor_deadline_exceeded") from error
            try:
                result = await asyncio.wait_for(
                    self._environment.exec(
                        f"/bin/bash -c {shlex.quote(script)}",
                        cwd=canonical,
                        timeout_sec=timeout_sec,
                    ),
                    timeout=timeout_sec,
                )
            except asyncio.CancelledError:
                raise
            except BaseException as error:
                root_expired = (
                    request.actor_done_monotonic_ns is not None
                    and self._monotonic_ns() >= request.actor_done_monotonic_ns
                )
                if root_expired and isinstance(error, TimeoutError):
                    if (
                        request.tool_name == "run_terminal_command"
                        and not request.arguments.get("background", False)
                    ):
                        raise self._foreground_failure(
                            request,
                            code="terminal_actor_deadline_exceeded",
                            phase=TerminalActorPhaseV1.MAPPING_PREFLIGHT,
                            origin=TerminalActorOriginV1.ACTOR,
                            primary_subtype=(
                                TerminalActorSubtypeV1.ACTOR_DEADLINE_EXCEEDED
                            ),
                            execution_may_have_started=False,
                            cleanup_verified=None,
                            census_verified=None,
                            effective_cutoff_monotonic_ns=cutoff_ns,
                        ) from error
                    raise BridgeError("terminal_actor_deadline_exceeded") from error
                if not _workspace_mapping_check_timed_out(
                    error,
                    timeout_sec=timeout_sec,
                ):
                    raise BridgeError(
                        "terminal_actor_workspace_mapping_changed"
                    ) from error
                retry_open = attempt + 1 < _WORKSPACE_MAPPING_CHECK_MAX_ATTEMPTS
                if retry_open and request.actor_done_monotonic_ns is not None:
                    retry_remaining = self._request_remaining_sec(
                        request,
                        settlement=False,
                    )
                    retry_open = (
                        retry_remaining is not None
                        and retry_remaining >= _WORKSPACE_MAPPING_CHECK_TIMEOUT_SEC
                    )
                if retry_open:
                    continue
                if (
                    request.actor_done_monotonic_ns is not None
                    and request.tool_name == "run_terminal_command"
                    and not request.arguments.get("background", False)
                ):
                    raise self._foreground_failure(
                        request,
                        code="terminal_actor_workspace_mapping_check_timeout",
                        phase=TerminalActorPhaseV1.MAPPING_PREFLIGHT,
                        origin=TerminalActorOriginV1.TRANSPORT,
                        primary_subtype=(
                            TerminalActorSubtypeV1.WORKSPACE_MAPPING_CHECK_TIMEOUT
                        ),
                        execution_may_have_started=False,
                        cleanup_verified=None,
                        census_verified=None,
                        effective_cutoff_monotonic_ns=cutoff_ns,
                    )
                raise ToolFatalError(
                    ToolFailure(
                        code="terminal_actor_workspace_mapping_check_timeout",
                        execution_may_have_started=False,
                        cleanup_verified=None,
                        census_verified=None,
                    )
                ) from error
            if result.return_code != 0:
                if (
                    request.actor_done_monotonic_ns is not None
                    and request.tool_name == "run_terminal_command"
                    and not request.arguments.get("background", False)
                ):
                    raise self._foreground_failure(
                        request,
                        code="terminal_actor_workspace_mapping_changed",
                        phase=TerminalActorPhaseV1.MAPPING_PREFLIGHT,
                        origin=TerminalActorOriginV1.PROTOCOL,
                        primary_subtype=(
                            TerminalActorSubtypeV1.WORKSPACE_MAPPING_CHANGED
                        ),
                        execution_may_have_started=False,
                        cleanup_verified=None,
                        census_verified=None,
                        effective_cutoff_monotonic_ns=cutoff_ns,
                    )
                raise BridgeError("terminal_actor_workspace_mapping_changed")
            return canonical
        raise AssertionError("workspace mapping check retry loop exhausted")

    @staticmethod
    def _request_dir(request: ToolRequest) -> str:
        digest = request.request_sha256[:32]
        return f"{_REMOTE_ROOT}/requests/{digest}"

    async def _cleanup_dir_evidence(
        self,
        request_dir: str,
        request: ToolRequest,
    ) -> tuple[bool | None, bool | None]:
        command = " ".join(
            [
                "/bin/bash",
                shlex.quote(_REMOTE_ACTOR),
                "cleanup",
                shlex.quote(request_dir),
                str(request.term_grace_ms),
                str(request.kill_confirmation_timeout_ms),
            ]
        )
        phase_cap_sec = (
            request.term_grace_ms + request.kill_confirmation_timeout_ms
        ) / 1000 + 5
        try:
            timeout_sec = phase_cap_sec
            if request.actor_done_monotonic_ns is not None:
                _, timeout_sec = self._actor_phase_budget(
                    request,
                    phase_cap_sec=phase_cap_sec,
                )
            result = await asyncio.wait_for(
                self._environment.exec(command, timeout_sec=timeout_sec),
                timeout=timeout_sec,
            )
        except BaseException:
            return None, None
        if result.return_code == 0 and result.stdout == "cleanup-ok\n":
            return True, True
        return False, None

    async def _cleanup_dir(self, request_dir: str, request: ToolRequest) -> bool:
        return await self._cleanup_dir_evidence(request_dir, request) == (
            True,
            True,
        )

    async def _cleanup_failed_foreground_launch_evidence(
        self,
        request_dir: str,
        request: ToolRequest,
    ) -> tuple[bool | None, bool | None]:
        pgid_path = f"{request_dir}/pgid"
        meta_path = f"{request_dir}/meta.json"
        evidence_command = (
            f"if test -f {shlex.quote(pgid_path)}; then exit 0; "
            f"elif test -f {shlex.quote(meta_path)}; then exit 2; "
            "else exit 1; fi"
        )
        try:
            timeout_sec = 5.0
            if request.actor_done_monotonic_ns is not None:
                _, timeout_sec = self._actor_phase_budget(
                    request,
                    phase_cap_sec=5.0,
                )
            evidence = await asyncio.wait_for(
                self._environment.exec(
                    evidence_command,
                    timeout_sec=timeout_sec,
                ),
                timeout=timeout_sec,
            )
        except BaseException:
            return None, None
        if evidence.return_code == 1:
            return True, True
        if evidence.return_code != 0:
            return None, None
        return await self._cleanup_dir_evidence(request_dir, request)

    async def _cleanup_undispatched_foreground_residue(
        self,
        request_dir: str,
        request: ToolRequest,
    ) -> bool:
        """Remove only pre-run files, inside the signed settlement probe stage."""

        stages = request.settlement_stages
        if stages is None:
            return False
        timeout_sec = _strict_remaining_sec(
            stages.probe_monotonic_ns,
            self._monotonic_ns(),
        )
        if timeout_sec <= 0:
            return False
        command_path = f"{request_dir}/command.sh"
        script = "\n".join(
            [
                "set -eu",
                f"request_dir={shlex.quote(request_dir)}",
                f"command_path={shlex.quote(command_path)}",
                'test -d "$request_dir"',
                'test ! -L "$request_dir"',
                f"test ! -e {shlex.quote(f'{request_dir}/pgid')}",
                f"test ! -e {shlex.quote(f'{request_dir}/owner_token')}",
                f"test ! -e {shlex.quote(f'{request_dir}/meta.json')}",
                'if test -e "$command_path"; then',
                '  test -f "$command_path"',
                '  test ! -L "$command_path"',
                '  rm -- "$command_path"',
                "fi",
                'rmdir -- "$request_dir"',
            ]
        )
        try:
            result = await asyncio.wait_for(
                self._environment.exec(
                    f"/bin/bash -lc {shlex.quote(script)}",
                    timeout_sec=timeout_sec,
                ),
                timeout=timeout_sec,
            )
        except BaseException:
            return False
        return_code = getattr(result, "return_code", None)
        return type(return_code) is int and return_code == 0

    async def _settle_dispatched_foreground(
        self,
        request_dir: str,
        request: ToolRequest,
    ) -> tuple[bool, bool]:
        """Contain one dispatched foreground owner inside signed settlement stages."""

        stages = request.settlement_stages
        if stages is None:
            cleanup, census = await self._cleanup_dir_evidence(request_dir, request)
            return cleanup is True, census is True
        term_ok = await self._signal_cleanup_process(
            "foreground",
            request_dir,
            "TERM",
            stages.probe_monotonic_ns,
        )
        grace_remaining = _strict_remaining_sec(
            stages.output_monotonic_ns,
            self._monotonic_ns(),
        )
        if grace_remaining > 0:
            await asyncio.sleep(min(request.term_grace_ms / 1000, grace_remaining))
        kill_ok = await self._signal_cleanup_process(
            "foreground",
            request_dir,
            "KILL",
            stages.encode_monotonic_ns,
        )
        census_ok = await self._census_cleanup_process(
            "foreground",
            request_dir,
            stages.history_commit_monotonic_ns,
        )
        return term_ok and kill_ok and census_ok, census_ok

    async def _cleanup_failed_foreground_launch(
        self,
        request_dir: str,
        request: ToolRequest,
    ) -> bool:
        return await self._cleanup_failed_foreground_launch_evidence(
            request_dir,
            request,
        ) == (True, True)

    async def _signal_cleanup_process(
        self,
        process_kind: str,
        request_dir: str,
        signal_name: str,
        cutoff_monotonic_ns: int,
        *,
        background_task: BackgroundTask | None = None,
    ) -> bool:
        remaining = max(
            0.0,
            (cutoff_monotonic_ns - self._monotonic_ns()) / 1_000_000_000,
        )
        if remaining <= 0:
            return False
        command_parts = [
            "/bin/bash",
            shlex.quote(_REMOTE_ACTOR),
            "cleanup-signal",
            shlex.quote(request_dir),
            process_kind,
            signal_name,
        ]
        if process_kind == "background":
            if (
                background_task is None
                or background_task.request_dir != request_dir
                or (identity := self._background_identity_arguments(background_task))
                is None
            ):
                return False
            command_parts.extend(identity)
        command = " ".join(command_parts)
        try:
            result = await asyncio.wait_for(
                self._environment.exec(
                    command,
                    timeout_sec=remaining,
                ),
                timeout=remaining,
            )
        except Exception:
            return False
        return result.return_code == 0 and result.stdout == "signal-ok\n"

    async def _census_cleanup_process(
        self,
        process_kind: str,
        request_dir: str,
        cutoff_monotonic_ns: int,
        *,
        background_task: BackgroundTask | None = None,
    ) -> bool:
        remaining = max(
            0.0,
            (cutoff_monotonic_ns - self._monotonic_ns()) / 1_000_000_000,
        )
        if remaining <= 0:
            return False
        command_parts = [
            "/bin/bash",
            shlex.quote(_REMOTE_ACTOR),
            "cleanup-census",
            shlex.quote(request_dir),
            process_kind,
        ]
        if process_kind == "background":
            if (
                background_task is None
                or background_task.request_dir != request_dir
                or (identity := self._background_identity_arguments(background_task))
                is None
            ):
                return False
            command_parts.extend(identity)
        command = " ".join(command_parts)
        try:
            result = await asyncio.wait_for(
                self._environment.exec(
                    command,
                    timeout_sec=remaining,
                ),
                timeout=remaining,
            )
            value = json.loads(result.stdout)
        except (Exception, TypeError, json.JSONDecodeError):
            return False
        return (
            result.return_code == 0
            and isinstance(value, dict)
            and set(value) == {"verified", "survivor_count"}
            and value["verified"] is True
            and value["survivor_count"] == 0
        )

    async def _census_snapshot_cleanup(
        self,
        lease: _SnapshotLease,
        cutoff_monotonic_ns: int,
    ) -> bool:
        remaining = max(
            0.0,
            (cutoff_monotonic_ns - self._monotonic_ns()) / 1_000_000_000,
        )
        if remaining <= 0:
            return False
        command = " ".join(
            [
                "/bin/bash",
                shlex.quote(_REMOTE_ACTOR),
                "snapshot-cleanup-census",
                shlex.quote(lease.control_dir),
                *self._snapshot_identity_arguments(lease),
            ]
        )
        try:
            result = await self._environment.exec(
                command,
                cwd=self._canonical_workspace(),
                timeout_sec=remaining,
            )
            value = json.loads(result.stdout)
        except (Exception, TypeError, json.JSONDecodeError):
            return False
        return (
            result.return_code == 0
            and isinstance(value, dict)
            and set(value) == {"verified", "survivor_count"}
            and value["verified"] is True
            and value["survivor_count"] == 0
        )

    async def _signal_snapshot_cleanup(
        self,
        lease: _SnapshotLease,
        signal_name: str,
        cutoff_monotonic_ns: int,
    ) -> bool:
        remaining = max(
            0.0,
            (cutoff_monotonic_ns - self._monotonic_ns()) / 1_000_000_000,
        )
        if remaining <= 0:
            return False
        command = " ".join(
            [
                "/bin/bash",
                shlex.quote(_REMOTE_ACTOR),
                "snapshot-cleanup-signal",
                shlex.quote(lease.control_dir),
                *self._snapshot_identity_arguments(lease),
                signal_name,
            ]
        )
        try:
            result = await self._environment.exec(
                command,
                cwd=self._canonical_workspace(),
                timeout_sec=remaining,
            )
        except Exception:
            return False
        return result.return_code == 0 and result.stdout == "signal-ok\n"

    def _cleanup_participants(self) -> list[_CleanupParticipant]:
        participants: list[_CleanupParticipant] = []
        for control_dir, initial_lease in list(self._active_snapshots.items()):
            owner_token = control_dir.rsplit(
                "/.nano-snapshot-execution-",
                1,
            )[-1]
            lease_holder = [initial_lease]

            async def signal_snapshot(
                cutoff_ns: int,
                *,
                signal_name: str,
                control_dir: str = control_dir,
                owner_token: str = owner_token,
                lease_holder: list[_SnapshotLease | None] = lease_holder,
            ) -> bool:
                try:
                    if lease_holder[0] is None:
                        lease_holder[0] = await self._inspect_snapshot_lease(
                            control_dir,
                            owner_token,
                        )
                except Exception:
                    return False
                return await self._signal_snapshot_cleanup(
                    lease_holder[0],
                    signal_name,
                    cutoff_ns,
                )

            async def census_snapshot(
                cutoff_ns: int,
                *,
                lease_holder: list[_SnapshotLease | None] = lease_holder,
            ) -> bool:
                lease = lease_holder[0]
                return (
                    False
                    if lease is None
                    else await self._census_snapshot_cleanup(lease, cutoff_ns)
                )

            participants.append(
                _CleanupParticipant(
                    term_grace_ms=_SNAPSHOT_TERM_GRACE_MS,
                    term=lambda cutoff_ns,
                    signal_snapshot=signal_snapshot: signal_snapshot(
                        cutoff_ns,
                        signal_name="TERM",
                    ),
                    kill=lambda cutoff_ns,
                    signal_snapshot=signal_snapshot: signal_snapshot(
                        cutoff_ns,
                        signal_name="KILL",
                    ),
                    census=census_snapshot,
                    finalize=lambda control_dir=control_dir: self._active_snapshots.pop(
                        control_dir,
                        None,
                    ),
                )
            )
        for request_dir, request in list(self._active.items()):
            participants.append(
                _CleanupParticipant(
                    term_grace_ms=request.term_grace_ms,
                    term=lambda cutoff_ns, request_dir=request_dir: (
                        self._signal_cleanup_process(
                            "foreground",
                            request_dir,
                            "TERM",
                            cutoff_ns,
                        )
                    ),
                    kill=lambda cutoff_ns, request_dir=request_dir: (
                        self._signal_cleanup_process(
                            "foreground",
                            request_dir,
                            "KILL",
                            cutoff_ns,
                        )
                    ),
                    census=lambda cutoff_ns, request_dir=request_dir: (
                        self._census_cleanup_process(
                            "foreground",
                            request_dir,
                            cutoff_ns,
                        )
                    ),
                    finalize=lambda request_dir=request_dir: self._active.pop(
                        request_dir,
                        None,
                    ),
                )
            )
        for task_id, task in list(self._background.items()):
            if task.state != "running" and task.census_verified:
                self._finalize_background_spool(task)
                self._background.pop(task_id, None)
                continue
            participants.append(
                _CleanupParticipant(
                    term_grace_ms=task.term_grace_ms,
                    term=lambda cutoff_ns, task=task: self._signal_cleanup_process(
                        "background",
                        task.request_dir,
                        "TERM",
                        cutoff_ns,
                        background_task=task,
                    ),
                    kill=lambda cutoff_ns, task=task: self._signal_cleanup_process(
                        "background",
                        task.request_dir,
                        "KILL",
                        cutoff_ns,
                        background_task=task,
                    ),
                    census=lambda cutoff_ns, task=task: self._census_cleanup_process(
                        "background",
                        task.request_dir,
                        cutoff_ns,
                        background_task=task,
                    ),
                    finalize=lambda task_id=task_id, task=task: (
                        self._finalize_background_spool(task),
                        self._background.pop(task_id, None),
                    ),
                )
            )
        return participants

    async def cleanup_active(self) -> bool:
        participants = self._cleanup_participants()
        max_grace_ms = max(
            (participant.term_grace_ms for participant in participants),
            default=0,
        )
        cleanup_budget_ms = max(20_000, max_grace_ms * 2 + 10_000)
        return await self.cleanup_active_until(
            self._monotonic_ns() + cleanup_budget_ms * 1_000_000
        )

    async def cleanup_active_until(
        self,
        hard_deadline_monotonic_ns: int,
    ) -> bool:
        """TERM, grace, KILL, then census every owned set under one root."""

        if (
            isinstance(hard_deadline_monotonic_ns, bool)
            or not isinstance(hard_deadline_monotonic_ns, int)
            or hard_deadline_monotonic_ns <= self._monotonic_ns()
        ):
            return False
        participants = self._cleanup_participants()
        if not participants:
            return True
        started_ns = self._monotonic_ns()
        duration_ns = hard_deadline_monotonic_ns - started_ns
        term_cutoff_ns = started_ns + duration_ns // 4
        grace_cutoff_ns = started_ns + duration_ns // 2
        kill_cutoff_ns = started_ns + duration_ns * 3 // 4
        pending_cancellation: asyncio.CancelledError | None = None

        async def run_phase(
            actions: list[Callable[[int], Awaitable[bool]]],
            cutoff_ns: int,
        ) -> tuple[bool, list[bool]]:
            nonlocal pending_cancellation
            remaining = max(
                0.0,
                (cutoff_ns - self._monotonic_ns()) / 1_000_000_000,
            )
            if remaining <= 0:
                return False, []
            completed, values, cancellation = await _complete_shielded(
                asyncio.gather(*(action(cutoff_ns) for action in actions)),
                timeout_sec=remaining,
            )
            if pending_cancellation is None and cancellation is not None:
                pending_cancellation = cancellation
            if not completed:
                return False, []
            return True, list(values)

        await run_phase(
            [participant.term for participant in participants],
            term_cutoff_ns,
        )
        grace_remaining = max(
            0.0,
            (grace_cutoff_ns - self._monotonic_ns()) / 1_000_000_000,
        )
        shared_grace = min(
            grace_remaining,
            max(participant.term_grace_ms for participant in participants) / 1000,
        )
        if shared_grace > 0:
            _, _, cancellation = await _complete_shielded(
                asyncio.sleep(shared_grace),
                timeout_sec=grace_remaining,
            )
            if pending_cancellation is None and cancellation is not None:
                pending_cancellation = cancellation
        await run_phase(
            [participant.kill for participant in participants],
            kill_cutoff_ns,
        )
        census_completed, census = await run_phase(
            [participant.census for participant in participants],
            hard_deadline_monotonic_ns,
        )
        if census_completed:
            for participant, zero_proven in zip(
                participants,
                census,
                strict=True,
            ):
                if zero_proven:
                    participant.finalize()
        if pending_cancellation is not None:
            raise pending_cancellation
        return census_completed and len(census) == len(participants) and all(census)

    async def workspace_readiness_v1(
        self,
        *,
        hard_deadline_monotonic_ns: int,
    ) -> WorkspaceReadinessV1:
        """Run one fixed read-only mapping/reachability probe after zero census."""

        now_ns = self._monotonic_ns()
        if (
            not self._ready
            or isinstance(hard_deadline_monotonic_ns, bool)
            or not isinstance(hard_deadline_monotonic_ns, int)
            or hard_deadline_monotonic_ns <= now_ns
            or self._cleanup_participants()
        ):
            raise BridgeError("terminal_actor_workspace_readiness_unverified")
        canonical = self._canonical_workspace()
        timeout_sec = min(
            _WORKSPACE_MAPPING_CHECK_TIMEOUT_SEC,
            (hard_deadline_monotonic_ns - now_ns) / 1_000_000_000,
        )
        script = "\n".join(
            [
                "set -eu",
                f"actual=$(realpath -e -- {shlex.quote(_LOGICAL_WORKSPACE)})",
                f'test "$actual" = {shlex.quote(canonical)}',
                f"test -d {shlex.quote(_LOGICAL_WORKSPACE)}",
                f"test -d {shlex.quote(canonical)}",
                "printf 'nano-workspace-ready-v1\\n'",
            ]
        )
        try:
            result = await asyncio.wait_for(
                self._environment.exec(
                    f"/bin/bash -c {shlex.quote(script)}",
                    cwd=canonical,
                    timeout_sec=timeout_sec,
                ),
                timeout=timeout_sec,
            )
        except asyncio.CancelledError:
            raise
        except Exception as error:
            raise BridgeError(
                "terminal_actor_workspace_readiness_unverified"
            ) from error
        if (
            result.return_code != 0
            or result.stdout != "nano-workspace-ready-v1\n"
            or result.stderr != ""
            or self._cleanup_participants()
        ):
            raise BridgeError("terminal_actor_workspace_readiness_unverified")
        return WorkspaceReadinessV1(
            canonical_workspace=canonical,
            logical_workspace=_LOGICAL_WORKSPACE,
            mapping_verified=True,
            environment_reachable=True,
            zero_owned_processes_verified=True,
        )

    async def execute(self, request: ToolRequest) -> ToolExecution:
        if not self._ready:
            raise BridgeError("terminal_actor_not_ready")
        previous_request = self._deadline_request
        self._deadline_request = request
        try:
            await self._prepare_request(request)
            if request.tool_name == "run_terminal_command":
                return await self._execute_terminal(request)
            if request.tool_name == "get_terminal_command_output":
                return await self._get_terminal_output(request)
            if request.tool_name == "kill_terminal_command":
                return await self._kill_terminal_command(request)
            try:
                if request.tool_name == "read_file":
                    return await self._read_file(request)
                if request.tool_name == "write":
                    return await self._write_file(request)
                if request.tool_name == "search_replace":
                    return await self._search_replace(request)
                if request.tool_name == "list_dir":
                    return await self._list_dir(request)
                if request.tool_name == "grep":
                    return await self._grep(request)
            except _ToolRejected as error:
                return self._settled(str(error), succeeded=False, request=request)
            raise BridgeError("terminal_actor_tool_unsupported")
        finally:
            self._deadline_request = previous_request

    async def _execute_terminal(self, request: ToolRequest) -> ToolExecution:
        if not self._ready:
            raise BridgeError("terminal_actor_not_ready")
        command_text = request.arguments.get("command")
        if not isinstance(command_text, str):
            raise BridgeError("terminal_actor_arguments_invalid")
        background = request.arguments.get("background", False)
        if not isinstance(background, bool):
            raise BridgeError("terminal_actor_arguments_invalid")
        if background:
            return await self._start_background(request, command_text)
        if request.actor_done_monotonic_ns is None:
            return await self._execute_foreground_legacy(request, command_text)
        return await self._execute_foreground_v3(request, command_text)

    async def _foreground_exec_rpc(
        self,
        request: ToolRequest,
        command: str,
        *,
        cwd: str | None = None,
        phase_cap_sec: float | None = None,
        admission_phase: TerminalActorPhaseV1 | None = None,
    ) -> tuple[Any, int]:
        try:
            cutoff_ns, timeout_sec = self._actor_phase_budget(
                request,
                phase_cap_sec=phase_cap_sec,
            )
        except _ActorDoneDeadlineExceeded:
            if admission_phase is not None:
                raise self._foreground_action_admission_failure(
                    request,
                    phase=admission_phase,
                ) from None
            raise
        try:
            result = await asyncio.wait_for(
                self._environment.exec(
                    command,
                    cwd=cwd,
                    timeout_sec=timeout_sec,
                ),
                timeout=timeout_sec,
            )
        except TimeoutError as error:
            if (
                cutoff_ns == request.actor_done_monotonic_ns
                and self._monotonic_ns() >= cutoff_ns
            ):
                raise _ActorDoneDeadlineExceeded(
                    "terminal_actor_deadline_exceeded"
                ) from error
            raise
        return result, cutoff_ns

    async def _foreground_upload_rpc(
        self,
        request: ToolRequest,
        source_path: Path,
        target_path: str,
        *,
        admission_phase: TerminalActorPhaseV1 | None = None,
    ) -> int:
        try:
            cutoff_ns, timeout_sec = self._actor_phase_budget(request)
        except _ActorDoneDeadlineExceeded:
            if admission_phase is not None:
                raise self._foreground_action_admission_failure(
                    request,
                    phase=admission_phase,
                ) from None
            raise
        try:
            await asyncio.wait_for(
                self._environment.upload_file(source_path, target_path),
                timeout=timeout_sec,
            )
        except TimeoutError as error:
            if (
                cutoff_ns == request.actor_done_monotonic_ns
                and self._monotonic_ns() >= cutoff_ns
            ):
                raise _ActorDoneDeadlineExceeded(
                    "terminal_actor_deadline_exceeded"
                ) from error
            raise
        return cutoff_ns

    @staticmethod
    def _foreground_recovery_subtype(
        error: BaseException,
    ) -> TerminalActorSubtypeV1:
        code = str(error)
        if isinstance(error, _ActorDoneDeadlineExceeded):
            return TerminalActorSubtypeV1.ACTOR_DEADLINE_EXCEEDED
        if code == "terminal_actor_meta_invalid":
            return TerminalActorSubtypeV1.META_INVALID
        if code == "terminal_actor_output_limit_exceeded":
            return TerminalActorSubtypeV1.OUTPUT_LIMIT_EXCEEDED
        if code == "terminal_actor_cleanup_unverified":
            return TerminalActorSubtypeV1.CLEANUP_UNVERIFIED
        if isinstance(error, TimeoutError):
            return TerminalActorSubtypeV1.RECOVERY_DOWNLOAD_FAILED
        return TerminalActorSubtypeV1.OUTPUT_DOWNLOAD_FAILED

    async def _execute_foreground_v3(
        self,
        request: ToolRequest,
        command_text: str,
    ) -> ToolExecution:
        request_dir = self._request_dir(request)
        if request_dir in self._active:
            raise BridgeError("terminal_actor_duplicate_request")
        self._active[request_dir] = request
        temporary_path: Path | None = None
        owner_token = secrets.token_hex(32)
        request_dir_created = False
        phase = TerminalActorPhaseV1.REMOTE_SETUP
        phase_cutoff_ns = request.actor_done_monotonic_ns
        try:
            result, phase_cutoff_ns = await self._foreground_exec_rpc(
                request,
                f"mkdir -p {shlex.quote(request_dir)} && "
                f"chmod 700 {shlex.quote(request_dir)}",
                phase_cap_sec=10.0,
                admission_phase=TerminalActorPhaseV1.REMOTE_SETUP,
            )
            if result.return_code != 0:
                raise self._foreground_failure(
                    request,
                    code="terminal_actor_request_setup_failed",
                    phase=phase,
                    origin=TerminalActorOriginV1.PROTOCOL,
                    primary_subtype=TerminalActorSubtypeV1.REQUEST_SETUP_FAILED,
                    execution_may_have_started=False,
                    cleanup_verified=None,
                    census_verified=None,
                    effective_cutoff_monotonic_ns=phase_cutoff_ns,
                )
            request_dir_created = True
            phase = TerminalActorPhaseV1.COMMAND_UPLOAD
            with tempfile.NamedTemporaryFile(
                prefix="nano-terminal-command.",
                suffix=".sh",
                delete=False,
            ) as handle:
                handle.write(b"#!/bin/bash\n")
                handle.write(command_text.encode("utf-8"))
                handle.write(b"\n")
                handle.flush()
                os.fsync(handle.fileno())
                temporary_path = Path(handle.name)
            phase_cutoff_ns = await self._foreground_upload_rpc(
                request,
                temporary_path,
                f"{request_dir}/command.sh",
                admission_phase=TerminalActorPhaseV1.COMMAND_UPLOAD,
            )
            phase = TerminalActorPhaseV1.REMOTE_EXEC

            def command_factory(action_timeout_ms: int) -> str:
                return " ".join(
                    [
                        "/bin/bash",
                        shlex.quote(_REMOTE_ACTOR),
                        "run",
                        shlex.quote(request_dir),
                        shlex.quote(self._canonical_workspace()),
                        str(action_timeout_ms),
                        str(request.term_grace_ms),
                        str(request.kill_confirmation_timeout_ms),
                        str(request.stdout_cap_bytes),
                        str(request.stderr_cap_bytes),
                        owner_token,
                        str(_FOREGROUND_DRAIN_TIMEOUT_MS),
                    ]
                )

            try:
                result, phase_cutoff_ns = await self._foreground_run_dispatch_rpc(
                    request,
                    command_factory,
                    cwd=self._canonical_workspace(),
                )
            except asyncio.CancelledError:
                raise
            except ToolFatalError:
                raise
            except _ActorDoneDeadlineExceeded:
                raise
            except BaseException as transport_error:
                primary_subtype = (
                    TerminalActorSubtypeV1.RUN_TRANSPORT_TIMEOUT
                    if isinstance(transport_error, TimeoutError)
                    else TerminalActorSubtypeV1.RUN_TRANSPORT_FAILED
                )
                recovered, recovery_subtype = await self._recover_settled_foreground(
                    request_dir,
                    request,
                )
                if recovered is not None:
                    self._active.pop(request_dir, None)
                    return replace(
                        recovered,
                        actor_receipt=self._foreground_receipt(
                            request,
                            phase=TerminalActorPhaseV1.META_VALIDATE,
                            origin=TerminalActorOriginV1.TRANSPORT,
                            primary_subtype=primary_subtype,
                            recovery_subtype=recovery_subtype,
                            execution_may_have_started=True,
                            cleanup_verified=recovered.cleanup_verified,
                            census_verified=recovered.census_verified,
                            effective_cutoff_monotonic_ns=phase_cutoff_ns,
                        ),
                    )
                raise self._foreground_failure(
                    request,
                    code="terminal_actor_transport_unknown",
                    phase=TerminalActorPhaseV1.RECOVERY_DOWNLOAD,
                    origin=TerminalActorOriginV1.TRANSPORT,
                    primary_subtype=primary_subtype,
                    recovery_subtype=recovery_subtype,
                    execution_may_have_started=True,
                    cleanup_verified=None,
                    census_verified=None,
                    effective_cutoff_monotonic_ns=phase_cutoff_ns,
                ) from transport_error
            if result.return_code != 0:
                recovered, recovery_subtype = await self._recover_settled_foreground(
                    request_dir,
                    request,
                )
                if recovered is not None:
                    self._active.pop(request_dir, None)
                    return replace(
                        recovered,
                        actor_receipt=self._foreground_receipt(
                            request,
                            phase=TerminalActorPhaseV1.META_VALIDATE,
                            origin=TerminalActorOriginV1.PROTOCOL,
                            primary_subtype=(
                                TerminalActorSubtypeV1.RUN_RESPONSE_NONZERO
                            ),
                            recovery_subtype=recovery_subtype,
                            execution_may_have_started=True,
                            cleanup_verified=recovered.cleanup_verified,
                            census_verified=recovered.census_verified,
                            effective_cutoff_monotonic_ns=phase_cutoff_ns,
                        ),
                    )
                raise self._foreground_failure(
                    request,
                    code="terminal_actor_run_failed",
                    phase=TerminalActorPhaseV1.RECOVERY_DOWNLOAD,
                    origin=TerminalActorOriginV1.PROTOCOL,
                    primary_subtype=TerminalActorSubtypeV1.RUN_RESPONSE_NONZERO,
                    recovery_subtype=recovery_subtype,
                    execution_may_have_started=True,
                    cleanup_verified=None,
                    census_verified=None,
                    effective_cutoff_monotonic_ns=phase_cutoff_ns,
                )
            phase = TerminalActorPhaseV1.RESULT_DOWNLOAD
            execution = await self._download_verified_foreground(
                request_dir,
                request,
            )
            self._active.pop(request_dir, None)
            return replace(
                execution,
                actor_receipt=self._foreground_receipt(
                    request,
                    phase=TerminalActorPhaseV1.META_VALIDATE,
                    origin=(
                        TerminalActorOriginV1.SEMANTIC
                        if execution.timed_out
                        else TerminalActorOriginV1.ACTOR
                    ),
                    primary_subtype=(
                        TerminalActorSubtypeV1.SEMANTIC_EXECUTION_TIMED_OUT
                        if execution.timed_out
                        else TerminalActorSubtypeV1.COMPLETED
                    ),
                    recovery_subtype=None,
                    execution_may_have_started=True,
                    cleanup_verified=execution.cleanup_verified,
                    census_verified=execution.census_verified,
                    effective_cutoff_monotonic_ns=phase_cutoff_ns,
                ),
            )
        except asyncio.CancelledError:
            dispatched = phase not in {
                TerminalActorPhaseV1.REMOTE_SETUP,
                TerminalActorPhaseV1.COMMAND_UPLOAD,
            }
            if dispatched and request.settlement_stages is not None:
                cleanup_verified, census_verified = await asyncio.shield(
                    self._settle_dispatched_foreground(request_dir, request)
                )
                clean = cleanup_verified and census_verified
            else:
                clean = await asyncio.shield(
                    self._cleanup_failed_foreground_launch(request_dir, request)
                )
            if clean:
                self._active.pop(request_dir, None)
            elif dispatched:
                raise _cleanup_unknown_failure(execution_may_have_started=True)
            raise
        except BaseException as primary_error:
            if isinstance(primary_error, ToolFatalError):
                failure = primary_error.failure
                if (
                    failure.actor_receipt is None
                    and failure.code == "terminal_actor_cleanup_unverified"
                ):
                    phase = (
                        TerminalActorPhaseV1.CLEANUP
                        if failure.cleanup_verified is not True
                        else TerminalActorPhaseV1.CENSUS
                    )
                    failure = replace(
                        failure,
                        actor_receipt=self._foreground_receipt(
                            request,
                            phase=phase,
                            origin=TerminalActorOriginV1.ACTOR,
                            primary_subtype=(TerminalActorSubtypeV1.CLEANUP_UNVERIFIED),
                            recovery_subtype=None,
                            execution_may_have_started=True,
                            cleanup_verified=failure.cleanup_verified,
                            census_verified=failure.census_verified,
                            effective_cutoff_monotonic_ns=phase_cutoff_ns,
                        ),
                    )
            else:
                code = str(primary_error)
                if isinstance(primary_error, _ActorDoneDeadlineExceeded):
                    subtype = TerminalActorSubtypeV1.ACTOR_DEADLINE_EXCEEDED
                    origin = TerminalActorOriginV1.ACTOR
                elif phase is TerminalActorPhaseV1.COMMAND_UPLOAD:
                    subtype = TerminalActorSubtypeV1.COMMAND_UPLOAD_FAILED
                    origin = TerminalActorOriginV1.TRANSPORT
                elif phase is TerminalActorPhaseV1.REMOTE_SETUP:
                    subtype = TerminalActorSubtypeV1.REQUEST_SETUP_FAILED
                    origin = TerminalActorOriginV1.TRANSPORT
                elif code == "terminal_actor_meta_invalid":
                    phase = TerminalActorPhaseV1.META_VALIDATE
                    subtype = TerminalActorSubtypeV1.META_INVALID
                    origin = TerminalActorOriginV1.PROTOCOL
                elif code == "terminal_actor_output_limit_exceeded":
                    phase = TerminalActorPhaseV1.META_VALIDATE
                    subtype = TerminalActorSubtypeV1.OUTPUT_LIMIT_EXCEEDED
                    origin = TerminalActorOriginV1.PROTOCOL
                else:
                    subtype = TerminalActorSubtypeV1.OUTPUT_DOWNLOAD_FAILED
                    origin = TerminalActorOriginV1.TRANSPORT
                failure = self._foreground_failure(
                    request,
                    code=(
                        "terminal_actor_deadline_exceeded"
                        if subtype is TerminalActorSubtypeV1.ACTOR_DEADLINE_EXCEEDED
                        else "terminal_actor_transport_unknown"
                    ),
                    phase=phase,
                    origin=origin,
                    primary_subtype=subtype,
                    execution_may_have_started=(
                        phase
                        not in {
                            TerminalActorPhaseV1.REMOTE_SETUP,
                            TerminalActorPhaseV1.COMMAND_UPLOAD,
                        }
                    ),
                    cleanup_verified=None,
                    census_verified=None,
                    effective_cutoff_monotonic_ns=phase_cutoff_ns,
                ).failure
            started = failure.execution_may_have_started
            if (
                not started
                and failure.code == "terminal_actor_action_admission_rejected"
            ):
                if request_dir_created:
                    await asyncio.shield(
                        self._cleanup_undispatched_foreground_residue(
                            request_dir,
                            request,
                        )
                    )
                self._active.pop(request_dir, None)
                raise primary_error
            if (
                started
                and isinstance(primary_error, _ActorDoneDeadlineExceeded)
                and request.settlement_stages is not None
            ):
                later_cleanup, later_census = await asyncio.shield(
                    self._settle_dispatched_foreground(request_dir, request)
                )
            else:
                later_cleanup, later_census = await asyncio.shield(
                    self._cleanup_failed_foreground_launch_evidence(
                        request_dir,
                        request,
                    )
                )
            clean = later_cleanup is True and later_census is True
            if clean:
                self._active.pop(request_dir, None)

            def merge_containment(
                prior: bool | None,
                later: bool | None,
            ) -> bool | None:
                if not started:
                    return None
                if later is True:
                    return True
                if prior is not None:
                    return prior
                return later

            cleanup_verified = merge_containment(
                failure.cleanup_verified,
                later_cleanup,
            )
            census_verified = merge_containment(
                failure.census_verified,
                later_census,
            )
            receipt = failure.actor_receipt or self._foreground_receipt(
                request,
                phase=phase,
                origin=TerminalActorOriginV1.ACTOR,
                primary_subtype=TerminalActorSubtypeV1.UNEXPECTED_FAILURE,
                recovery_subtype=None,
                execution_may_have_started=started,
                cleanup_verified=cleanup_verified,
                census_verified=census_verified,
                effective_cutoff_monotonic_ns=phase_cutoff_ns,
            )
            if receipt is not None:
                containment_phase = None
                if started:
                    if cleanup_verified is not True:
                        containment_phase = TerminalActorPhaseV1.CLEANUP
                    elif census_verified is not True:
                        containment_phase = TerminalActorPhaseV1.CENSUS
                    elif (
                        receipt.primary_subtype
                        is TerminalActorSubtypeV1.CLEANUP_UNVERIFIED
                        and receipt.phase is TerminalActorPhaseV1.CLEANUP
                    ):
                        containment_phase = TerminalActorPhaseV1.CENSUS
                receipt = receipt.with_containment(
                    phase=containment_phase,
                    cleanup_verified=cleanup_verified,
                    census_verified=census_verified,
                )
            raise ToolFatalError(
                ToolFailure(
                    code=(
                        failure.code if clean else "terminal_actor_cleanup_unverified"
                    ),
                    execution_may_have_started=started,
                    cleanup_verified=cleanup_verified,
                    census_verified=census_verified,
                    actor_receipt=receipt,
                )
            ) from primary_error
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    async def _execute_foreground_legacy(
        self,
        request: ToolRequest,
        command_text: str,
    ) -> ToolExecution:
        request_dir = self._request_dir(request)
        if request_dir in self._active:
            raise BridgeError("terminal_actor_duplicate_request")
        self._active[request_dir] = request
        temporary_path: Path | None = None
        owner_token = secrets.token_hex(32)
        try:
            result = await self._environment.exec(
                f"mkdir -p {shlex.quote(request_dir)} && "
                f"chmod 700 {shlex.quote(request_dir)}",
                timeout_sec=10,
            )
            if result.return_code != 0:
                raise BridgeError("terminal_actor_request_setup_failed")
            with tempfile.NamedTemporaryFile(
                prefix="nano-terminal-command.",
                suffix=".sh",
                delete=False,
            ) as handle:
                handle.write(b"#!/bin/bash\n")
                handle.write(command_text.encode("utf-8"))
                handle.write(b"\n")
                handle.flush()
                os.fsync(handle.fileno())
                temporary_path = Path(handle.name)
            await self._environment.upload_file(
                temporary_path, f"{request_dir}/command.sh"
            )
            command = " ".join(
                [
                    "/bin/bash",
                    shlex.quote(_REMOTE_ACTOR),
                    "run",
                    shlex.quote(request_dir),
                    shlex.quote(self._canonical_workspace()),
                    str(request.timeout_ms),
                    str(request.term_grace_ms),
                    str(request.kill_confirmation_timeout_ms),
                    str(request.stdout_cap_bytes),
                    str(request.stderr_cap_bytes),
                    owner_token,
                    str(_FOREGROUND_DRAIN_TIMEOUT_MS),
                ]
            )
            transport_timeout = (
                request.timeout_ms
                + request.term_grace_ms * 2
                + request.kill_confirmation_timeout_ms * 2
                + _FOREGROUND_DRAIN_TIMEOUT_MS * 2
            ) / 1000 + 5.0
            try:
                result = await self._environment.exec(
                    command,
                    cwd=self._canonical_workspace(),
                    timeout_sec=transport_timeout,
                )
            except asyncio.CancelledError:
                raise
            except BaseException as transport_error:
                recovered, _ = await self._recover_settled_foreground(
                    request_dir,
                    request,
                )
                if recovered is None:
                    raise transport_error
                self._active.pop(request_dir, None)
                return recovered
            if result.return_code != 0:
                recovered, _ = await self._recover_settled_foreground(
                    request_dir,
                    request,
                )
                if recovered is None:
                    raise BridgeError("terminal_actor_run_failed")
                self._active.pop(request_dir, None)
                return recovered
            execution = await self._download_verified_foreground(
                request_dir,
                request,
            )
            self._active.pop(request_dir, None)
            return execution
        except BaseException:
            clean = await asyncio.shield(
                self._cleanup_failed_foreground_launch(request_dir, request)
            )
            if clean:
                self._active.pop(request_dir, None)
            else:
                raise _cleanup_unknown_failure(execution_may_have_started=True)
            raise
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    async def _recover_settled_foreground(
        self,
        request_dir: str,
        request: ToolRequest,
    ) -> tuple[ToolExecution | None, TerminalActorSubtypeV1]:
        try:
            return (
                await self._download_verified_foreground(request_dir, request),
                TerminalActorSubtypeV1.RECOVERED_SETTLED,
            )
        except asyncio.CancelledError:
            raise
        except ToolFatalError as error:
            return None, self._foreground_recovery_subtype(error)
        except Exception as error:
            return None, self._foreground_recovery_subtype(error)

    async def _download_verified_foreground(
        self,
        request_dir: str,
        request: ToolRequest,
    ) -> ToolExecution:
        execution = await self._download_result(request_dir, request)
        if not (
            execution.cleanup_attempted
            and execution.cleanup_verified
            and execution.census_verified
            and execution.survivor_count == 0
        ):
            raise ToolFatalError(
                ToolFailure(
                    code="terminal_actor_cleanup_unverified",
                    execution_may_have_started=True,
                    cleanup_verified=execution.cleanup_verified,
                    census_verified=execution.census_verified,
                )
            )
        return execution

    @staticmethod
    def _background_dir(task_id: str) -> str:
        return f"{_BACKGROUND_ROOT}/{task_id}"

    def _background_identity_arguments(
        self,
        task: BackgroundTask,
    ) -> list[str] | None:
        if (
            type(task.pgid) is not int
            or task.pgid <= 1
            or type(task.leader_starttime) is not int
            or task.leader_starttime <= 0
            or type(task.monitor_pgid) is not int
            or task.monitor_pgid <= 1
            or type(task.monitor_starttime) is not int
            or task.monitor_starttime <= 0
            or not _owner_token_is_valid(task.owner_token)
            or task.request_dir != self._background_dir(task.task_id)
        ):
            return None
        return [
            str(task.pgid),
            str(task.leader_starttime),
            str(task.monitor_pgid),
            str(task.monitor_starttime),
            task.owner_token,
        ]

    @staticmethod
    def _bind_background_identity(task: BackgroundTask, raw: str) -> None:
        try:
            value = json.loads(raw)
        except (TypeError, json.JSONDecodeError) as error:
            raise BridgeError("terminal_actor_background_start_invalid") from error
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "pgid",
                "leader_starttime",
                "monitor_pgid",
                "monitor_starttime",
                "owner_token",
            }
            or any(
                isinstance(value[key], bool)
                or not isinstance(value[key], int)
                or value[key] <= (1 if key.endswith("pgid") else 0)
                for key in (
                    "pgid",
                    "leader_starttime",
                    "monitor_pgid",
                    "monitor_starttime",
                )
            )
            or value["owner_token"] != task.owner_token
        ):
            raise BridgeError("terminal_actor_background_start_invalid")
        task.pgid = value["pgid"]
        task.leader_starttime = value["leader_starttime"]
        task.monitor_pgid = value["monitor_pgid"]
        task.monitor_starttime = value["monitor_starttime"]

    async def _inspect_background_identity_remote(
        self,
        task: BackgroundTask,
        request: ToolRequest,
    ) -> bool:
        command = " ".join(
            [
                "/bin/bash",
                shlex.quote(_REMOTE_ACTOR),
                "background-inspect",
                shlex.quote(task.request_dir),
                task.owner_token,
            ]
        )
        timeout_sec = 5.0
        if request.settlement_stages is not None:
            timeout_sec = _strict_remaining_sec(
                request.settlement_stages.probe_monotonic_ns,
                self._monotonic_ns(),
            )
            if timeout_sec <= 0:
                return False
        try:
            result = await asyncio.wait_for(
                self._environment.exec(command, timeout_sec=timeout_sec),
                timeout=timeout_sec,
            )
            if result.return_code != 0:
                return False
            self._bind_background_identity(task, result.stdout)
        except BaseException:
            return False
        return self._background_identity_arguments(task) is not None

    async def _verify_background_terminal_census(
        self,
        task: BackgroundTask,
        term_grace_ms: int,
        confirmation_ms: int,
    ) -> tuple[bool, bool]:
        if task.state == "running" and not task.leader_exited:
            return False, False
        if task.state == "running":
            process_alive = await self._background_process_alive_remote(task)
            if process_alive is True:
                # A shell leader is only one member of the owned lifecycle.
                # Exact owner-bound descendants keep the managed task live.
                task.census_verified = False
                return False, False
            if process_alive is None:
                task.status_fresh = False
                task.status_reason = "status_unavailable"
                return False, False
        if not task.census_verified:
            task.census_verified = await self._confirm_background_stopped_remote(
                task,
                confirmation_ms,
            )
        if task.census_verified:
            if task.state == "running":
                task.state = "failed"
                task.status_fresh = False
                task.status_reason = "group_exited_status_unavailable"
                task.end_wall = task.end_wall or self._wall_clock()
                task.end_monotonic = task.end_monotonic or self._monotonic()
                self._finalize_background_spool(task)
            return False, False
        term_sent = False
        kill_sent = False
        if not task.census_verified:
            term_sent, kill_sent, task.census_verified = await asyncio.shield(
                self._terminate_background_remote(
                    task,
                    term_grace_ms,
                    confirmation_ms,
                )
            )
        if not task.census_verified:
            raise _cleanup_unknown_failure(execution_may_have_started=True)
        if task.state == "running" or term_sent or kill_sent:
            task.state = "cancelled"
            task.explicitly_killed = True
            task.exit_code = -15
            task.end_wall = task.end_wall or self._wall_clock()
            task.end_monotonic = task.end_monotonic or self._monotonic()
            self._finalize_background_spool(task)
        return term_sent, kill_sent

    async def _start_background(
        self,
        request: ToolRequest,
        command_text: str,
    ) -> ToolExecution:
        description = request.arguments.get("description")
        raw_timeout = request.arguments.get("timeout")
        if (
            not command_text
            or "\x00" in command_text
            or not isinstance(description, str)
            or not description
            or isinstance(raw_timeout, bool)
            or raw_timeout is not None
            and not isinstance(raw_timeout, int)
            or isinstance(raw_timeout, int)
            and (raw_timeout < 0 or raw_timeout > 300_000)
        ):
            raise BridgeError("terminal_actor_arguments_invalid")
        # Pinned Grok runtime semantics: background omitted/None and explicit
        # zero are both model-owned/unbounded. Positive values are backstops.
        runtime_timeout_ms = (
            raw_timeout if isinstance(raw_timeout, int) and raw_timeout > 0 else None
        )
        if not self._background_start_action_admitted(request):
            return self._background_start_not_started_result(
                request,
                diagnostic=(
                    "Background start was rejected before dispatch because the "
                    "signed action window cannot preserve the minimum containment "
                    "window; no task ID was published and no process was started."
                ),
                next_step=(
                    "Finish with the strongest durable result instead of starting "
                    "new background work near actor_done."
                ),
            )
        await self._refresh_all_background()
        self._prune_background()
        live_count = sum(task.state == "running" for task in self._background.values())
        if live_count >= request.max_background_processes:
            return self._direct_result(
                (
                    "<observation>background_start_not_running</observation>\n"
                    "<status>not_started</status>\n"
                    "<exit-code>unavailable</exit-code>\n"
                    "<diagnostic>Background start was rejected because the managed "
                    "process limit is already reached; no task ID was published and "
                    "no process was started.</diagnostic>\n"
                    "<next-step>Inspect or stop an existing managed background task, "
                    "then submit the command again.</next-step>"
                ),
                request=request,
                succeeded=False,
                disposition=ProcessDisposition.NO_PROCESS,
                background_start_observation=BackgroundStartObservation(
                    proof_version=BACKGROUND_START_PROOF_VERSION,
                    kind=BackgroundStartKind.NOT_STARTED,
                    task_id_published=False,
                    child_exit_code=None,
                ),
            )
        next_reserved = (
            self._background_spool_reserved + request.process_spool_bytes_per_process
        )
        if next_reserved > request.process_spool_bytes_per_run:
            return self._direct_result(
                (
                    "<observation>background_start_not_running</observation>\n"
                    "<status>not_started</status>\n"
                    "<exit-code>unavailable</exit-code>\n"
                    "<diagnostic>Background start was rejected because the managed "
                    "output-spool limit is exhausted; no task ID was published and "
                    "no process was started.</diagnostic>\n"
                    "<next-step>Reduce background output or finish existing managed "
                    "tasks before submitting another command.</next-step>"
                ),
                request=request,
                succeeded=False,
                disposition=ProcessDisposition.NO_PROCESS,
                background_start_observation=BackgroundStartObservation(
                    proof_version=BACKGROUND_START_PROOF_VERSION,
                    kind=BackgroundStartKind.NOT_STARTED,
                    task_id_published=False,
                    child_exit_code=None,
                ),
            )
        task_id = self._id_factory()
        try:
            parsed_id = uuid.UUID(task_id)
        except (ValueError, AttributeError) as error:
            raise BridgeError("terminal_actor_task_id_invalid") from error
        if (
            parsed_id.version != 7
            or task_id != str(parsed_id)
            or task_id in self._background
        ):
            raise BridgeError("terminal_actor_task_id_invalid")
        start_wall = self._wall_clock()
        start_monotonic = self._monotonic()
        owner_token = secrets.token_hex(32)
        task = BackgroundTask(
            task_id=task_id,
            request_dir=self._background_dir(task_id),
            command=command_text,
            logical_cwd=request.logical_cwd,
            output_path=(f"{request.logical_cwd.rstrip('/')}/.terminals/{task_id}.log"),
            start_wall=start_wall,
            start_monotonic=start_monotonic,
            runtime_timeout_ms=runtime_timeout_ms,
            spool_cap_bytes=request.process_spool_bytes_per_process,
            term_grace_ms=request.term_grace_ms,
            kill_confirmation_timeout_ms=request.kill_confirmation_timeout_ms,
            owner_token=owner_token,
        )
        self._background[task_id] = task
        try:
            await self._launch_background_remote(
                task,
                request,
                runtime_timeout_ms,
            )
            if (
                task.pgid is None
                or task.leader_starttime is None
                or task.monitor_pgid is None
                or task.monitor_starttime is None
            ):
                raise BridgeError("terminal_actor_background_registration_failed")
            # Account for the reservation before the first status probe: a fast
            # child may terminalize and finalize its spool during that probe.
            self._background_spool_reserved = next_reserved
            fresh = await self._refresh_background_remote(task)
            if not fresh:
                # The start RPC returns only after the remote monitor has
                # published the exact leader/monitor identities, owner token,
                # and initial running status. A later status probe is useful
                # for detecting a quick exit, but transient loss of that probe
                # cannot invalidate the authoritative launch acknowledgement.
                # Retain the managed handle so a later status call or terminal
                # cleanup can settle the exact owned process group.
                task.status_fresh = False
                task.status_reason = task.status_reason or "status_unavailable"
            if task.state != "running" or task.leader_exited:
                await self._verify_background_terminal_census(
                    task,
                    request.term_grace_ms,
                    request.kill_confirmation_timeout_ms,
                )
            if task.state != "running":
                self._finalize_background_spool(task)
                return await self._settled_background_start(task, request)
        except ToolFatalError:
            # Fatal settlements below are already based on bounded cleanup and
            # census evidence. Re-running the generic launch recovery can turn
            # a cleaned transport loss into a forged quick-exit observation.
            raise
        except BaseException as original_error:
            try:
                if (
                    isinstance(original_error, _BackgroundStartFailure)
                    and not original_error.start_dispatched
                ):
                    if original_error.not_started_verified:
                        settlement = "not_started"
                    else:
                        settlement = "pre_start_transport"
                elif (
                    task.pgid is None
                    or task.leader_starttime is None
                    or task.monitor_pgid is None
                    or task.monitor_starttime is None
                ):
                    settlement = await asyncio.shield(
                        self._cleanup_failed_background_launch(task, request)
                    )
                elif task.state == "running":
                    _, _, clean = await asyncio.shield(
                        self._terminate_background_remote(
                            task,
                            request.term_grace_ms,
                            request.kill_confirmation_timeout_ms,
                        )
                    )
                    settlement = (
                        "transport_unknown_cleaned" if clean else "cleanup_unknown"
                    )
                else:
                    clean = await asyncio.shield(
                        self._confirm_background_stopped_remote(
                            task,
                            request.kill_confirmation_timeout_ms,
                        )
                    )
                    if not clean:
                        _, _, clean = await asyncio.shield(
                            self._terminate_background_remote(
                                task,
                                request.term_grace_ms,
                                request.kill_confirmation_timeout_ms,
                            )
                        )
                    settlement = (
                        "completed_before_handoff" if clean else "cleanup_unknown"
                    )
            except BaseException:
                settlement = "cleanup_unknown"
            if settlement != "cleanup_unknown":
                self._background.pop(task_id, None)
            if isinstance(original_error, asyncio.CancelledError):
                if settlement == "cleanup_unknown":
                    raise _cleanup_unknown_failure(execution_may_have_started=True)
                raise
            if settlement == "pre_start_transport":
                raise _background_pre_start_transport_failure(
                    str(original_error)
                ) from original_error
            if settlement == "cleanup_unknown":
                raise _cleanup_unknown_failure(execution_may_have_started=True)
            if settlement != "not_started":
                # Once any dispatched/error path is entered, later status or
                # cleanup evidence can prove zero survivors but cannot prove
                # the mutation's response semantics. Keep fatal provenance;
                # only the straight launch-ack/fresh-status path may certify a
                # quick exit.
                raise _background_transport_unknown_failure()
            return self._direct_result(
                (
                    "<observation>background_start_not_running</observation>\n"
                    "<status>not_started</status>\n"
                    "<exit-code>unavailable</exit-code>\n"
                    "<diagnostic>The background command was rejected before start; "
                    "no task ID was published and no owned process "
                    "exists.</diagnostic>\n"
                    "<next-step>Inspect the command and working directory, then "
                    "submit a corrected background command.</next-step>"
                ),
                request=request,
                succeeded=False,
                disposition=ProcessDisposition.NO_PROCESS,
                background_start_observation=BackgroundStartObservation(
                    proof_version=BACKGROUND_START_PROOF_VERSION,
                    kind=BackgroundStartKind.NOT_STARTED,
                    task_id_published=False,
                    child_exit_code=None,
                ),
            )
        status_evidence = (
            ""
            if task.status_fresh
            else (
                "\n<status-fresh>false</status-fresh>\n"
                "<diagnostic>The launch acknowledgement registered an exact "
                "managed process identity, but the immediate status refresh "
                "was unavailable. Treat running as the last known status and "
                "poll this task ID for a fresh observation.</diagnostic>"
            )
        )
        output = (
            f"<task-id>{task_id}</task-id>\n"
            "<task-type>bash</task-type>\n"
            f"<output-file>{task.output_path}</output-file>\n"
            "<status>running</status>\n"
            f"<summary>Background task {task_id} started</summary>"
            f"{status_evidence}\n"
            "No unsolicited completion message is injected. Use "
            "get_terminal_command_output with "
            f'task_ids=["{task_id}"], timeout_ms=30000, wait_for="any" '
            "as the authoritative status and output channel. While it reports "
            "running, keep waiting through that managed handle instead of "
            "issuing separate shell or process progress probes. Use "
            f'kill_terminal_command with task_id="{task_id}" '
            "to cancel it through the managed owner."
        )
        return self._direct_result(
            output,
            request=request,
            succeeded=True,
            disposition=ProcessDisposition.BACKGROUND_RETAINED,
            target_task_id=task_id,
            survivor_count=1,
        )

    async def _settled_background_start(
        self,
        task: BackgroundTask,
        request: ToolRequest,
    ) -> ToolExecution:
        exit_code = task.exit_code
        quick_exit_valid = (
            task.census_verified
            and not task.timed_out
            and not task.explicitly_killed
            and (
                task.state == "completed"
                and exit_code == 0
                or task.state == "failed"
                and type(exit_code) is int
                and exit_code != 0
            )
            and type(exit_code) is int
            and -(2**31) <= exit_code <= 2**31 - 1
        )
        if not quick_exit_valid:
            self._background.pop(task.task_id, None)
            raise _background_status_invalid_failure()
        payload = await self._read_background_output(
            task,
            task.spool_cap_bytes,
        )
        output, hint = self._background_output_preview(task, payload)
        if hint:
            hint = (
                "\nOutput truncated; no retained background handle is available "
                "for further reads."
            )
        rendered = (
            "<observation>background_start_quick_exit</observation>\n"
            f"<status>{task.state}</status>\n"
            f"<exit-code>{exit_code}</exit-code>\n"
            "<diagnostic>The command exited before background handoff; no task ID "
            "was published and no owned process remains.</diagnostic>\n"
            "<next-step>Inspect the exit code and bounded output, correct the "
            "command if a persistent service was intended, then start it again."
            "</next-step>\n"
            f"{output}"
            f"{hint}"
        )
        result = self._direct_result(
            rendered,
            request=request,
            succeeded=task.state == "completed" and exit_code == 0,
            disposition=ProcessDisposition.NO_PROCESS,
            cleanup_attempted=True,
            background_start_observation=BackgroundStartObservation(
                proof_version=BACKGROUND_START_PROOF_VERSION,
                kind=BackgroundStartKind.QUICK_EXIT,
                task_id_published=False,
                child_exit_code=exit_code,
            ),
        )
        self._background.pop(task.task_id, None)
        return result

    async def _cleanup_failed_background_launch(
        self,
        task: BackgroundTask,
        request: ToolRequest,
    ) -> str:
        if await self._inspect_background_identity_remote(task, request):
            if request.settlement_stages is not None:
                stages = request.settlement_stages
                assert stages is not None
                term_ok = await self._signal_cleanup_process(
                    "background",
                    task.request_dir,
                    "TERM",
                    stages.probe_monotonic_ns,
                    background_task=task,
                )
                grace_remaining = _strict_remaining_sec(
                    stages.output_monotonic_ns,
                    self._monotonic_ns(),
                )
                if grace_remaining > 0:
                    await asyncio.sleep(
                        min(request.term_grace_ms / 1000, grace_remaining)
                    )
                kill_ok = await self._signal_cleanup_process(
                    "background",
                    task.request_dir,
                    "KILL",
                    stages.encode_monotonic_ns,
                    background_task=task,
                )
                census_ok = await self._census_cleanup_process(
                    "background",
                    task.request_dir,
                    stages.history_commit_monotonic_ns,
                    background_task=task,
                )
                if term_ok and kill_ok and census_ok:
                    task.census_verified = True
                    return "transport_unknown_cleaned"
                return "cleanup_unknown"
            fresh = await self._refresh_background_remote(task)
            if fresh and task.state != "running":
                clean = await self._confirm_background_stopped_remote(
                    task,
                    request.kill_confirmation_timeout_ms,
                )
                if clean:
                    return "completed_before_handoff"
            _, _, clean = await self._terminate_background_remote(
                task,
                request.term_grace_ms,
                request.kill_confirmation_timeout_ms,
            )
            return "transport_unknown_cleaned" if clean else "cleanup_unknown"
        pgid = f"{task.request_dir}/pgid"
        leader_starttime = f"{task.request_dir}/leader_starttime"
        monitor_pgid = f"{task.request_dir}/monitor_pgid"
        monitor_starttime = f"{task.request_dir}/monitor_starttime"
        status = f"{task.request_dir}/status.json"
        command = (
            f"if test -f {shlex.quote(pgid)} && "
            f"test -f {shlex.quote(leader_starttime)} && "
            f"test -f {shlex.quote(monitor_pgid)} && "
            f"test -f {shlex.quote(monitor_starttime)}; then exit 0; "
            f"elif test -f {shlex.quote(pgid)} || "
            f"test -f {shlex.quote(leader_starttime)} || "
            f"test -f {shlex.quote(monitor_pgid)} || "
            f"test -f {shlex.quote(monitor_starttime)} || "
            f"test -f {shlex.quote(status)}; then exit 2; "
            "else exit 1; fi"
        )
        try:
            evidence = await self._environment.exec(command, timeout_sec=5)
        except BaseException:
            return "cleanup_unknown"
        if evidence.return_code == 1:
            # Once the start RPC was dispatched, missing control files do not
            # prove non-execution; publication may have raced the observation.
            return "cleanup_unknown"
        if evidence.return_code != 0:
            return "cleanup_unknown"
        fresh = await self._refresh_background_remote(task)
        if fresh and task.state != "running":
            clean = await self._confirm_background_stopped_remote(
                task,
                request.kill_confirmation_timeout_ms,
            )
            if not clean:
                _, _, clean = await self._terminate_background_remote(
                    task,
                    request.term_grace_ms,
                    request.kill_confirmation_timeout_ms,
                )
                return "transport_unknown_cleaned" if clean else "cleanup_unknown"
            return (
                "completed_before_handoff"
                if task.state == "completed"
                else "failed_before_handoff"
            )
        _, _, clean = await self._terminate_background_remote(
            task,
            request.term_grace_ms,
            request.kill_confirmation_timeout_ms,
        )
        return "transport_unknown_cleaned" if clean else "cleanup_unknown"

    async def _launch_background_remote(
        self,
        task: BackgroundTask,
        request: ToolRequest,
        runtime_timeout_ms: int | None,
    ) -> None:
        setup_timeout_sec = min(
            _BACKGROUND_START_SETUP_TIMEOUT_SEC,
            request.timeout_ms / 1000,
        )
        if request.actor_done_monotonic_ns is not None:
            _, setup_timeout_sec = self._actor_phase_budget(
                request,
                phase_cap_sec=setup_timeout_sec,
            )
        owner_setup = "\n".join(
            [
                "set -eu",
                f"request_dir={shlex.quote(task.request_dir)}",
                f"owner_token={task.owner_token}",
                'mkdir -p -- "$request_dir"',
                'chmod 700 "$request_dir"',
                'if test -f "$request_dir/owner_token"; then',
                '  test ! -L "$request_dir/owner_token"',
                '  IFS= read -r actual < "$request_dir/owner_token"',
                '  test "$actual" = "$owner_token"',
                "else",
                '  printf "%s\\n" "$owner_token" > "$request_dir/.owner_token.tmp"',
                '  sync "$request_dir/.owner_token.tmp" 2>/dev/null || true',
                '  mv -f -- "$request_dir/.owner_token.tmp" "$request_dir/owner_token"',
                "fi",
            ]
        )
        try:
            result = await asyncio.wait_for(
                self._environment.exec(
                    f"/bin/bash -c {shlex.quote(owner_setup)}",
                    timeout_sec=setup_timeout_sec,
                ),
                timeout=setup_timeout_sec,
            )
        except asyncio.CancelledError:
            raise
        except BaseException as error:
            raise _BackgroundStartFailure(
                "terminal_actor_background_setup_failed",
                start_dispatched=False,
            ) from error
        if type(result.return_code) is not int:
            raise _BackgroundStartFailure(
                "terminal_actor_background_setup_failed",
                start_dispatched=False,
            )
        if result.return_code != 0:
            raise _BackgroundStartFailure(
                "terminal_actor_background_setup_failed",
                start_dispatched=False,
                not_started_verified=True,
            )
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                prefix="nano-background-command.",
                suffix=".sh",
                delete=False,
            ) as handle:
                handle.write(b"#!/bin/bash\n")
                handle.write(task.command.encode("utf-8"))
                handle.write(b"\n")
                handle.flush()
                os.fsync(handle.fileno())
                temporary_path = Path(handle.name)
            try:
                upload = self._environment.upload_file(
                    temporary_path,
                    f"{task.request_dir}/command.sh",
                )
                if request.actor_done_monotonic_ns is None:
                    await upload
                else:
                    _, upload_timeout_sec = self._actor_phase_budget(request)
                    await asyncio.wait_for(upload, timeout=upload_timeout_sec)
            except asyncio.CancelledError:
                raise
            except BaseException as error:
                raise _BackgroundStartFailure(
                    "terminal_actor_background_start_failed",
                    start_dispatched=False,
                ) from error
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
        if not self._background_dispatch_admitted(request):
            raise _BackgroundStartFailure(
                "terminal_actor_background_action_admission_rejected",
                start_dispatched=False,
                not_started_verified=True,
            )
        command = " ".join(
            [
                "/bin/bash",
                shlex.quote(_REMOTE_ACTOR),
                "start",
                shlex.quote(task.request_dir),
                shlex.quote(self._canonical_workspace()),
                ("none" if runtime_timeout_ms is None else str(runtime_timeout_ms)),
                str(request.term_grace_ms),
                str(task.spool_cap_bytes),
                shlex.quote(self._translate_logical_path(task.output_path)),
                task.owner_token,
            ]
        )
        try:
            dispatch_timeout_sec = min(
                _BACKGROUND_START_DISPATCH_TIMEOUT_SEC,
                request.timeout_ms / 1000,
            )
            if request.actor_done_monotonic_ns is not None:
                _, dispatch_timeout_sec = self._actor_phase_budget(
                    request,
                    phase_cap_sec=dispatch_timeout_sec,
                )
            result = await asyncio.wait_for(
                self._environment.exec(
                    command,
                    cwd=self._canonical_workspace(),
                    timeout_sec=dispatch_timeout_sec,
                ),
                timeout=dispatch_timeout_sec,
            )
        except BaseException as error:
            raise _BackgroundStartFailure(
                "terminal_actor_background_start_failed",
                start_dispatched=True,
            ) from error
        if result.return_code != 0:
            raise _BackgroundStartFailure(
                "terminal_actor_background_start_failed",
                start_dispatched=True,
            )
        try:
            self._bind_background_identity(task, result.stdout)
        except BridgeError as error:
            raise _BackgroundStartFailure(
                "terminal_actor_background_start_invalid",
                start_dispatched=True,
            ) from error

    async def _refresh_all_background(self) -> None:
        for task in list(self._background.values()):
            if task.state == "running" and not task.leader_exited:
                await self._refresh_background_remote(task)
            if (
                task.state != "running" or task.leader_exited
            ) and not task.census_verified:
                await self._verify_background_terminal_census(
                    task,
                    task.term_grace_ms,
                    task.kill_confirmation_timeout_ms,
                )

    async def _refresh_background_remote(
        self,
        task: BackgroundTask,
        request: ToolRequest | None = None,
    ) -> bool:
        request = request or self._deadline_request
        if task.state != "running":
            task.status_fresh = True
            task.status_reason = None
            return True
        command = " ".join(
            [
                "/bin/bash",
                shlex.quote(_REMOTE_ACTOR),
                "status",
                shlex.quote(task.request_dir),
            ]
        )
        result = None
        for _ in range(2):
            timeout_sec = 5.0
            if request is not None:
                remaining = self._request_remaining_sec(
                    request,
                    settlement=True,
                    settlement_stage="probe",
                )
                if remaining is not None:
                    if remaining <= 0:
                        task.status_fresh = False
                        task.status_reason = "runtime_budget"
                        return False
                    timeout_sec = min(timeout_sec, remaining)
            try:
                result = await asyncio.wait_for(
                    self._environment.exec(command, timeout_sec=timeout_sec),
                    timeout=timeout_sec,
                )
            except asyncio.CancelledError:
                raise
            except (Exception, TimeoutError):
                result = None
            if result is not None and result.return_code == 0:
                break
        if result is None or result.return_code != 0:
            task.status_fresh = False
            task.status_reason = "status_unavailable"
            return False
        # A syntactically successful response with invalid identity/state is
        # protocol evidence, not a transient transport failure.
        status = self._parse_background_status(result.stdout)
        task.status_fresh = True
        task.status_reason = None
        task.state = status["state"]
        task.exit_code = status["exit_code"]
        task.timed_out = status["timed_out"]
        task.leader_exited = status["leader_exited"]
        task.census_verified = False
        task.total_bytes = status["total_bytes"]
        task.truncated = status["truncated"]
        if status["state"] != "running":
            task.end_wall = float(status["ended_epoch"])
            task.end_monotonic = task.start_monotonic + max(
                0.0,
                task.end_wall - task.start_wall,
            )
            task.explicitly_killed = status["state"] == "cancelled"
            self._finalize_background_spool(task)
        return True

    async def _background_process_alive_remote(
        self,
        task: BackgroundTask,
        request: ToolRequest | None = None,
    ) -> bool | None:
        identity = self._background_identity_arguments(task)
        if identity is None:
            return None
        request = request or self._deadline_request
        timeout_sec = 5.0
        if request is not None:
            remaining = self._request_remaining_sec(
                request,
                settlement=True,
                settlement_stage="probe",
            )
            if remaining is not None:
                if remaining <= 0:
                    return None
                timeout_sec = min(timeout_sec, remaining)
        command = " ".join(
            [
                "/bin/bash",
                shlex.quote(_REMOTE_ACTOR),
                "background-liveness",
                shlex.quote(task.request_dir),
                *identity,
            ]
        )
        try:
            result = await asyncio.wait_for(
                self._environment.exec(command, timeout_sec=timeout_sec),
                timeout=timeout_sec,
            )
            value = json.loads(result.stdout)
        except asyncio.CancelledError:
            raise
        except (Exception, TypeError, json.JSONDecodeError):
            return None
        if (
            result.return_code != 0
            or type(value) is not dict
            or set(value) != {"process_alive"}
            or type(value["process_alive"]) is not bool
        ):
            return None
        return value["process_alive"]

    @staticmethod
    def _parse_background_status(raw: str) -> Mapping[str, Any]:
        try:
            value = json.loads(raw)
        except (TypeError, json.JSONDecodeError) as error:
            raise BridgeError("terminal_actor_background_status_invalid") from error
        if not isinstance(value, dict) or set(value) != _BACKGROUND_STATUS_KEYS:
            raise BridgeError("terminal_actor_background_status_invalid")
        if (
            value["state"] not in _BACKGROUND_STATES
            or not isinstance(value["timed_out"], bool)
            or not isinstance(value["truncated"], bool)
            or not isinstance(value["leader_exited"], bool)
            or isinstance(value["total_bytes"], bool)
            or not isinstance(value["total_bytes"], int)
            or value["total_bytes"] < 0
            or isinstance(value["started_epoch"], bool)
            or not isinstance(value["started_epoch"], int | float)
            or (
                value["exit_code"] is not None
                and (
                    isinstance(value["exit_code"], bool)
                    or not isinstance(value["exit_code"], int)
                )
            )
            or (
                value["ended_epoch"] is not None
                and (
                    isinstance(value["ended_epoch"], bool)
                    or not isinstance(value["ended_epoch"], int | float)
                )
            )
            or (value["state"] == "running") != (value["ended_epoch"] is None)
            or value["state"] != "running"
            and value["leader_exited"] is not True
        ):
            raise BridgeError("terminal_actor_background_status_invalid")
        return value

    async def _read_background_output(
        self,
        task: BackgroundTask,
        max_bytes: int,
        request: ToolRequest | None = None,
    ) -> bytes:
        request = request or self._deadline_request
        with tempfile.TemporaryDirectory(prefix="nano-background-output.") as raw:
            local_path = Path(raw) / "output"
            try:
                remaining = (
                    None
                    if request is None
                    else self._request_remaining_sec(
                        request,
                        settlement=True,
                        settlement_stage="output",
                    )
                )
                if remaining is not None and remaining <= 0:
                    raise BridgeError(
                        "terminal_actor_background_output_deadline_exceeded"
                    )
                download = self._environment.download_file(
                    self._translate_logical_path(task.output_path), local_path
                )
                if remaining is None:
                    await download
                else:
                    await asyncio.wait_for(download, timeout=remaining)
                payload = local_path.read_bytes()
            except TimeoutError as error:
                raise BridgeError(
                    "terminal_actor_background_output_deadline_exceeded"
                ) from error
            except OSError as error:
                raise BridgeError("terminal_actor_background_output_failed") from error
        if len(payload) > max_bytes:
            raise BridgeError("terminal_actor_background_output_limit_exceeded")
        task.total_bytes = max(task.total_bytes, len(payload))
        if task.state == "running" and len(payload) >= task.spool_cap_bytes:
            task.truncated = True
        return payload

    async def _get_terminal_output(self, request: ToolRequest) -> ToolExecution:
        raw_ids = request.arguments.get("task_ids", [])
        raw_timeout = request.arguments.get("timeout_ms")
        raw_wait_for = request.arguments.get("wait_for", "all")
        if (
            not isinstance(raw_ids, list)
            or isinstance(raw_timeout, bool)
            or raw_timeout is not None
            and not isinstance(raw_timeout, int)
            or isinstance(raw_timeout, int)
            and raw_timeout < 0
            or raw_wait_for not in {"any", "all"}
        ):
            raise BridgeError("terminal_actor_arguments_invalid")
        task_ids: list[str] = []
        seen: set[str] = set()
        for raw_id in raw_ids:
            if not isinstance(raw_id, str):
                raise BridgeError("terminal_actor_arguments_invalid")
            task_id = raw_id.strip()
            if not task_id:
                continue
            if len(task_id.encode("utf-8")) > 256 or any(
                ord(char) < 32 for char in task_id
            ):
                raise BridgeError("terminal_actor_arguments_invalid")
            if task_id not in seen:
                seen.add(task_id)
                task_ids.append(task_id)
        if not task_ids or len(task_ids) > 20:
            raise BridgeError("terminal_actor_arguments_invalid")
        timeout_ms = min(
            raw_timeout or 0,
            request.background_output_wait_max_ms,
        )
        semantic_deadline = self._monotonic() + timeout_ms / 1000
        actor_remaining = self._request_remaining_sec(
            request,
            settlement=False,
        )
        wait_clamped = (
            timeout_ms > 0
            and actor_remaining is not None
            and actor_remaining < timeout_ms / 1000
        )
        deadline = (
            semantic_deadline
            if actor_remaining is None
            else min(
                semantic_deadline,
                self._monotonic() + actor_remaining,
            )
        )
        while True:
            found_count = 0
            pending_count = 0
            terminal_count = 0
            for task_id in task_ids:
                task = self._background.get(task_id)
                if task is not None:
                    found_count += 1
                    fresh = True
                    if task.state == "running" and not task.leader_exited:
                        fresh = await self._refresh_background_remote(task)
                    if (
                        fresh
                        and (task.state != "running" or task.leader_exited)
                        and not task.census_verified
                    ):
                        await self._verify_background_terminal_census(
                            task,
                            task.term_grace_ms,
                            task.kill_confirmation_timeout_ms,
                        )
                    if fresh and task.state == "running":
                        pending_count += 1
                    elif fresh:
                        terminal_count += 1
            wait_condition_met = (
                terminal_count > 0
                if raw_wait_for == "any"
                else found_count > 0 and pending_count == 0
            )
            if (
                wait_condition_met
                or pending_count == 0
                or timeout_ms == 0
                or self._monotonic() >= deadline
            ):
                break
            sleep_for = min(0.1, max(0.0, deadline - self._monotonic()))
            if sleep_for <= 0:
                break
            await asyncio.sleep(sleep_for)
        self._prune_background()
        if len(task_ids) == 1:
            task = self._background.get(task_ids[0])
            output = (
                f"Task {task_ids[0]} not found."
                if task is None
                else await self._render_single_background(task, request)
            )
        else:
            mode = f"wait_{raw_wait_for}" if timeout_ms > 0 else "poll"
            terminal_ids: list[str] = []
            running_ids: list[str] = []
            not_found_ids: list[str] = []
            for task_id in task_ids:
                task = self._background.get(task_id)
                if task is None:
                    not_found_ids.append(task_id)
                elif task.state == "running":
                    running_ids.append(task_id)
                else:
                    terminal_ids.append(task_id)
            wait_condition_met = (
                bool(terminal_ids)
                if raw_wait_for == "any"
                else bool(terminal_ids) and not running_ids and not not_found_ids
            )
            rendered = [
                "<background-completion-facts>\n",
                f"<wait-mode>{mode}</wait-mode>\n",
                f"<wait-condition-met>{str(wait_condition_met).lower()}</wait-condition-met>\n",
                f"<terminal-task-ids>{','.join(terminal_ids)}</terminal-task-ids>\n",
                f"<running-task-ids>{','.join(running_ids)}</running-task-ids>\n",
                f"<not-found-task-ids>{','.join(not_found_ids)}</not-found-task-ids>\n",
                "</background-completion-facts>\n",
                f"=== Multi-wait ({mode}) ===\n",
            ]
            terminal_count = 0
            for task_id in task_ids:
                task = self._background.get(task_id)
                if task is None:
                    rendered.append(
                        f"--- Task {task_id} [not_found] ---\n"
                        f"Task {task_id} not found.\n\n"
                    )
                    continue
                if task.state != "running":
                    terminal_count += 1
                rendered.append(await self._render_multi_background(task, request))
                rendered.append("\n\n")
            rendered.append(
                f"\n{terminal_count}/{len(task_ids)} tasks completed ({mode})"
            )
            if running_ids:
                rendered.append(
                    "\nThe managed status and output above are authoritative. "
                    "Continue waiting for the running task IDs with "
                    "get_terminal_command_output rather than spending turns on "
                    "separate shell or process progress probes."
                )
            output = "".join(rendered)
        wait_clamped = wait_clamped or any(
            task is not None
            and (
                task.status_reason == "runtime_budget"
                or task.output_reason == "runtime_budget"
            )
            for task_id in task_ids
            if (task := self._background.get(task_id)) is not None
        )
        return self._direct_result(
            output,
            request=request,
            succeeded=True,
            disposition=ProcessDisposition.NO_PROCESS,
            wait_clamped=wait_clamped,
            wait_reason="runtime_budget" if wait_clamped else None,
        )

    async def _render_single_background(
        self,
        task: BackgroundTask,
        request: ToolRequest,
    ) -> str:
        try:
            payload = await self._read_background_output(
                task,
                task.spool_cap_bytes,
            )
            task.output_reason = None
            output, hint = self._background_output_preview(task, payload)
        except BridgeError as error:
            if str(error) != "terminal_actor_background_output_deadline_exceeded":
                raise
            task.output_reason = "runtime_budget"
            output = "(output unavailable: runtime budget)"
            hint = ""
        ended = (
            ""
            if task.end_wall is None
            else f"Ended: {self._format_epoch(task.end_wall)}\n"
        )
        exit_code = "" if task.exit_code is None else f"Exit Code: {task.exit_code}\n"
        status = task.state if task.status_fresh else "status_unavailable"
        last_known = "" if task.status_fresh else f"Last Known Status: {task.state}\n"
        continuation = (
            "\n\nThe managed status and output above are authoritative. Continue "
            "waiting with get_terminal_command_output rather than spending turns "
            "on separate shell or process progress probes."
            if task.state == "running"
            else ""
        )
        return (
            f"=== Task {task.task_id} ===\n"
            f"Command: {task.command}\n"
            f"Status: {status}\n"
            f"{last_known}"
            f"Started: {self._format_epoch(task.start_wall)}\n"
            f"{ended}"
            f"Duration: {self._duration(task):.2f}s\n"
            f"{exit_code}"
            f"Output File: {task.output_path}\n\n"
            "=== Output ===\n"
            f"{output or '(no output yet)'}"
            f"{hint}"
            f"{continuation}"
        )

    async def _render_multi_background(
        self,
        task: BackgroundTask,
        request: ToolRequest,
    ) -> str:
        try:
            payload = await self._read_background_output(
                task,
                task.spool_cap_bytes,
            )
            task.output_reason = None
            output, hint = self._background_output_preview(task, payload)
        except BridgeError as error:
            if str(error) != "terminal_actor_background_output_deadline_exceeded":
                raise
            task.output_reason = "runtime_budget"
            output = "(output unavailable: runtime budget)"
            hint = ""
        exit_code = "" if task.exit_code is None else f"\nExit Code: {task.exit_code}"
        status = task.state if task.status_fresh else "status_unavailable"
        last_known = "" if task.status_fresh else f"\nLast Known Status: {task.state}"
        rendered_output = f"\n{output}{hint}" if output or hint else ""
        return (
            f"--- Task {task.task_id} [{status}] ---\n"
            f"Command: {task.command}\n"
            f"Duration: {self._duration(task):.2f}s"
            f"{exit_code}"
            f"{last_known}"
            f"{rendered_output}"
        )

    @staticmethod
    def _format_epoch(value: float) -> str:
        return datetime.fromtimestamp(value, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _duration(self, task: BackgroundTask) -> float:
        end = (
            task.end_monotonic if task.end_monotonic is not None else self._monotonic()
        )
        return max(0.0, end - task.start_monotonic)

    @staticmethod
    def _background_output_preview(
        task: BackgroundTask,
        payload: bytes,
    ) -> tuple[str, str]:
        text = payload.decode("utf-8", errors="replace")
        encoded = text.encode("utf-8")
        preview_cap = 40_000
        truncated = task.truncated or len(encoded) > preview_cap
        if len(encoded) > preview_cap:
            encoded = _truncate_utf8_bytes(encoded, preview_cap)
            text = encoded.decode("utf-8")
        hint = (
            f"\nOutput truncated. Full output: {task.output_path}" if truncated else ""
        )
        return text, hint

    async def _kill_terminal_command(
        self,
        request: ToolRequest,
    ) -> ToolExecution:
        raw_task_id = request.arguments.get("task_id")
        if not isinstance(raw_task_id, str) or not raw_task_id.strip():
            raise BridgeError("terminal_actor_arguments_invalid")
        task_id = raw_task_id.strip()
        task = self._background.get(task_id)
        if task is None:
            return self._direct_result(
                f"Task or subagent {task_id} not found",
                request=request,
                succeeded=True,
                disposition=ProcessDisposition.NO_PROCESS,
            )
        await self._refresh_background_remote(task)
        term_sent = False
        kill_sent = False
        if task.state != "running" or task.leader_exited:
            term_sent, kill_sent = await self._verify_background_terminal_census(
                task,
                request.term_grace_ms,
                request.kill_confirmation_timeout_ms,
            )
        if task.state != "running":
            if term_sent or kill_sent:
                return self._direct_result(
                    "killed: Task was terminated successfully",
                    request=request,
                    succeeded=True,
                    disposition=ProcessDisposition.BACKGROUND_TERMINATED,
                    target_task_id=task_id,
                    cleanup_attempted=True,
                    term_sent=term_sent,
                    kill_sent=kill_sent,
                )
            return self._direct_result(
                "already_exited: Task had already completed",
                request=request,
                succeeded=True,
                disposition=ProcessDisposition.BACKGROUND_TERMINATED,
                target_task_id=task_id,
                cleanup_attempted=True,
            )
        term_sent, kill_sent, verified = await self._terminate_background_remote(
            task,
            request.term_grace_ms,
            request.kill_confirmation_timeout_ms,
        )
        if not verified:
            raise _cleanup_unknown_failure(execution_may_have_started=True)
        task.census_verified = True
        task.state = "cancelled"
        task.explicitly_killed = True
        task.exit_code = task.exit_code if task.exit_code is not None else -15
        task.end_wall = task.end_wall or self._wall_clock()
        task.end_monotonic = task.end_monotonic or self._monotonic()
        self._finalize_background_spool(task)
        return self._direct_result(
            "killed: Task was terminated successfully",
            request=request,
            succeeded=True,
            disposition=ProcessDisposition.BACKGROUND_TERMINATED,
            target_task_id=task_id,
            cleanup_attempted=True,
            term_sent=term_sent,
            kill_sent=kill_sent,
        )

    async def _terminate_background_remote(
        self,
        task: BackgroundTask,
        term_grace_ms: int,
        confirmation_ms: int,
    ) -> tuple[bool, bool, bool]:
        identity = self._background_identity_arguments(task)
        if identity is None:
            return False, False, False
        command = " ".join(
            [
                "/bin/bash",
                shlex.quote(_REMOTE_ACTOR),
                "kill-background",
                shlex.quote(task.request_dir),
                str(term_grace_ms),
                str(confirmation_ms),
                *identity,
            ]
        )
        try:
            result = await self._environment.exec(
                command,
                timeout_sec=(term_grace_ms + confirmation_ms * 3) / 1000 + 5,
            )
        except BaseException:
            return False, False, False
        try:
            value = json.loads(result.stdout)
        except (TypeError, json.JSONDecodeError):
            return False, False, False
        if (
            not isinstance(value, dict)
            or set(value) != {"term_sent", "kill_sent", "verified"}
            or any(not isinstance(value[key], bool) for key in value)
        ):
            return False, False, False
        verified = result.return_code == 0 and value["verified"]
        if verified:
            task.census_verified = True
            try:
                fresh = await self._refresh_background_remote(task)
                if not fresh:
                    task.state = "cancelled"
                    task.status_fresh = True
                    task.status_reason = None
            except BridgeError:
                task.state = "cancelled"
        return value["term_sent"], value["kill_sent"], verified

    async def _confirm_background_stopped_remote(
        self,
        task: BackgroundTask,
        confirmation_ms: int,
    ) -> bool:
        identity = self._background_identity_arguments(task)
        if identity is None:
            return False
        command = " ".join(
            [
                "/bin/bash",
                shlex.quote(_REMOTE_ACTOR),
                "confirm-background",
                shlex.quote(task.request_dir),
                str(confirmation_ms),
                *identity,
            ]
        )
        try:
            result = await self._environment.exec(
                command,
                timeout_sec=confirmation_ms / 1000 + 5,
            )
            value = json.loads(result.stdout)
        except (BaseException, TypeError, json.JSONDecodeError):
            return False
        verified = (
            result.return_code == 0
            and isinstance(value, dict)
            and set(value) == {"verified"}
            and value["verified"] is True
        )
        if verified:
            task.census_verified = True
        return verified

    def _prune_background(self) -> None:
        terminal = sorted(
            (
                task
                for task in self._background.values()
                if task.state != "running" and task.census_verified
            ),
            key=lambda task: (
                task.end_monotonic or task.start_monotonic,
                task.task_id,
            ),
        )
        for task in terminal[:-_MAX_BACKGROUND_TOMBSTONES]:
            self._background.pop(task.task_id, None)

    def _finalize_background_spool(self, task: BackgroundTask) -> None:
        if task.spool_finalized:
            return
        self._background_spool_reserved = max(
            0,
            self._background_spool_reserved - task.spool_cap_bytes,
        ) + min(task.total_bytes, task.spool_cap_bytes)
        task.spool_finalized = True

    async def background_manifest(self) -> list[dict[str, Any]]:
        await self._refresh_all_background()
        running = [
            task for task in self._background.values() if task.state == "running"
        ]
        if any(
            not task.status_fresh or self._process_lease_identity(task) is None
            for task in running
        ):
            raise BridgeError("terminal_actor_background_status_unavailable")
        self._prune_background()
        return [
            {
                "task_id": task.task_id,
                "pgid": task.pgid,
                "monitor_pgid": task.monitor_pgid,
                "output_path": task.output_path,
                "state": task.state,
            }
            for task in sorted(
                running,
                key=lambda task: task.task_id,
            )
        ]

    @staticmethod
    def _process_lease_identity(
        task: BackgroundTask,
    ) -> _ProcessLeaseIdentityV1 | None:
        if (
            task.state != "running"
            or type(task.pgid) is not int
            or task.pgid <= 1
            or type(task.leader_starttime) is not int
            or task.leader_starttime <= 0
            or type(task.monitor_pgid) is not int
            or task.monitor_pgid <= 1
            or type(task.monitor_starttime) is not int
            or task.monitor_starttime <= 0
            or not _owner_token_is_valid(task.owner_token)
            or task.request_dir != RemoteTerminalActor._background_dir(task.task_id)
        ):
            return None
        return _ProcessLeaseIdentityV1(
            task_id=task.task_id,
            request_dir=task.request_dir,
            output_path=task.output_path,
            leader_pid=task.pgid,
            leader_starttime=task.leader_starttime,
            leader_pgid=task.pgid,
            monitor_pid=task.monitor_pgid,
            monitor_starttime=task.monitor_starttime,
            monitor_pgid=task.monitor_pgid,
            owner_token=task.owner_token,
            term_grace_ms=task.term_grace_ms,
            kill_confirmation_timeout_ms=task.kill_confirmation_timeout_ms,
        )

    @staticmethod
    def _process_lease_manifest_row(
        identity: _ProcessLeaseIdentityV1,
    ) -> dict[str, object]:
        return {
            "task_id": identity.task_id,
            "pgid": identity.leader_pgid,
            "monitor_pgid": identity.monitor_pgid,
            "output_path": identity.output_path,
            "state": "running",
        }

    def seal_process_lease_v1(
        self,
        manifest_rows: list[dict[str, Any]],
    ) -> ProcessLeaseV1:
        """Freeze and return the exact live managed-process set."""

        if type(manifest_rows) is not list:
            raise BridgeError("terminal_actor_process_lease_invalid")
        identities: list[_ProcessLeaseIdentityV1] = []
        for task in sorted(
            (task for task in self._background.values() if task.state == "running"),
            key=lambda task: task.task_id,
        ):
            identity = self._process_lease_identity(task)
            if identity is None:
                raise BridgeError("terminal_actor_process_lease_invalid")
            identities.append(identity)
        expected_rows = [
            self._process_lease_manifest_row(identity) for identity in identities
        ]
        if manifest_rows != expected_rows or self._active or self._active_snapshots:
            raise BridgeError("terminal_actor_process_lease_invalid")
        lease = ProcessLeaseV1(tuple(identities))
        if self._process_lease_v1 is not None:
            if self._process_lease_v1 != lease:
                raise BridgeError("terminal_actor_process_lease_invalid")
            return self._process_lease_v1
        self._process_lease_v1 = lease
        return lease

    def _process_lease_still_exact(self, lease: ProcessLeaseV1) -> bool:
        if type(lease) is not ProcessLeaseV1 or self._process_lease_v1 != lease:
            return False
        live: list[_ProcessLeaseIdentityV1] = []
        for task in sorted(
            (task for task in self._background.values() if task.state == "running"),
            key=lambda task: task.task_id,
        ):
            identity = self._process_lease_identity(task)
            if identity is None:
                return False
            live.append(identity)
        return tuple(live) == lease._identities

    @staticmethod
    def _process_lease_arguments(
        identity: _ProcessLeaseIdentityV1,
    ) -> list[str]:
        return [
            str(identity.leader_pgid),
            str(identity.leader_starttime),
            str(identity.monitor_pgid),
            str(identity.monitor_starttime),
            identity.owner_token,
        ]

    async def observe_process_lease_v1(
        self,
        lease: ProcessLeaseV1,
        *,
        hard_deadline_monotonic_ns: int,
    ) -> list[dict[str, object]]:
        """Observe, but never gate on, an exact managed-process lease."""

        if self._process_lease_observation_v1 is not None:
            if self._process_lease_v1 != lease:
                raise BridgeError("terminal_actor_process_lease_observation_invalid")
            return [dict(row) for row in self._process_lease_observation_v1]
        if (
            isinstance(hard_deadline_monotonic_ns, bool)
            or not isinstance(hard_deadline_monotonic_ns, int)
            or hard_deadline_monotonic_ns <= self._monotonic_ns()
            or not self._process_lease_still_exact(lease)
        ):
            raise BridgeError("terminal_actor_process_lease_observation_invalid")
        rows: list[dict[str, object]] = []
        for identity in lease._identities:
            remaining = (
                hard_deadline_monotonic_ns - self._monotonic_ns()
            ) / 1_000_000_000
            if remaining <= 0:
                raise BridgeError("terminal_actor_process_lease_observation_invalid")
            command = " ".join(
                [
                    "/bin/bash",
                    shlex.quote(_REMOTE_ACTOR),
                    "background-liveness",
                    shlex.quote(identity.request_dir),
                    *self._process_lease_arguments(identity),
                ]
            )
            try:
                result = await self._environment.exec(
                    command,
                    timeout_sec=remaining,
                )
                value = json.loads(result.stdout)
            except (BaseException, TypeError, json.JSONDecodeError) as error:
                raise BridgeError(
                    "terminal_actor_process_lease_observation_invalid"
                ) from error
            if (
                result.return_code != 0
                or type(value) is not dict
                or set(value) != {"process_alive"}
                or type(value["process_alive"]) is not bool
            ):
                raise BridgeError("terminal_actor_process_lease_observation_invalid")
            rows.append(
                {
                    "task_id": identity.task_id,
                    "leader_pid": identity.leader_pid,
                    "leader_starttime": identity.leader_starttime,
                    "leader_pgid": identity.leader_pgid,
                    "monitor_pid": identity.monitor_pid,
                    "monitor_starttime": identity.monitor_starttime,
                    "monitor_pgid": identity.monitor_pgid,
                    "owner_token_sha256": hashlib.sha256(
                        identity.owner_token.encode("ascii")
                    ).hexdigest(),
                    "process_alive": value["process_alive"],
                }
            )
        self._process_lease_observation_v1 = tuple(dict(row) for row in rows)
        return rows

    async def close_process_lease_until(
        self,
        lease: ProcessLeaseV1,
        hard_deadline_monotonic_ns: int,
    ) -> bool:
        """Bounded TERM/KILL/census closure for an exact process lease."""

        if self._process_lease_close_outcome_v1 is not None:
            return (
                self._process_lease_v1 == lease and self._process_lease_close_outcome_v1
            )
        if not self._process_lease_still_exact(lease):
            return False
        closed = await self.cleanup_active_until(hard_deadline_monotonic_ns)
        self._process_lease_close_outcome_v1 = closed
        return closed

    @staticmethod
    def _direct_result(
        output: str,
        *,
        request: ToolRequest,
        succeeded: bool,
        disposition: ProcessDisposition,
        target_task_id: str | None = None,
        survivor_count: int = 0,
        cleanup_attempted: bool = False,
        term_sent: bool = False,
        kill_sent: bool = False,
        wait_clamped: bool = False,
        wait_reason: str | None = None,
        background_start_observation: BackgroundStartObservation | None = None,
    ) -> ToolExecution:
        raw = output.encode("utf-8")
        truncated = False
        if len(raw) > request.stdout_cap_bytes:
            raw = _truncate_utf8_bytes(raw, request.stdout_cap_bytes)
            truncated = True
        return ToolExecution(
            return_code=0 if succeeded else 2,
            timed_out=False,
            stdout=raw,
            stderr=b"",
            stdout_truncated=truncated,
            stderr_truncated=False,
            cleanup_attempted=cleanup_attempted,
            term_sent=term_sent,
            kill_sent=kill_sent,
            cleanup_verified=True,
            census_verified=True,
            survivor_count=survivor_count,
            process_disposition=disposition,
            target_task_id=target_task_id,
            wait_clamped=wait_clamped,
            wait_reason=wait_reason,
            background_start_observation=background_start_observation,
        )

    async def _resolve_workspace_path(
        self,
        request: ToolRequest,
        raw_path: object,
        *,
        expected: str,
        allow_create: bool = False,
    ) -> str:
        if (
            not isinstance(raw_path, str)
            or not raw_path
            or "\x00" in raw_path
            or len(raw_path.encode("utf-8")) > request.max_path_bytes
        ):
            raise _ToolRejected("invalid_path")
        candidate = (
            self._translate_logical_path(raw_path)
            if raw_path.startswith("/")
            else f"{self._canonical_workspace().rstrip('/')}/{raw_path}"
        )
        expected_check = {
            "file": 'test -f "$resolved"',
            "directory": 'test -d "$resolved"',
            "any": 'test -f "$resolved" || test -d "$resolved"',
            "create": (
                'if test -e "$resolved" || test -L "$resolved"; then '
                'test -f "$resolved"; else '
                'ancestor=$(dirname -- "$resolved"); '
                'while ! test -e "$ancestor" && ! test -L "$ancestor"; do '
                'next=$(dirname -- "$ancestor"); '
                'test "$next" != "$ancestor" || exit 78; ancestor=$next; done; '
                'test -d "$(realpath -e -- "$ancestor")"; fi'
            ),
        }[expected]
        script = "\n".join(
            [
                "set -eu",
                *(
                    f"root_{index}={shlex.quote(root)}"
                    for index, root in enumerate(self._allowed_roots())
                ),
                f"resolved=$(realpath -m -- {shlex.quote(candidate)})",
                "allowed=false",
                *(
                    f'case "$resolved" in "$root_{index}"|"$root_{index}"/*) '
                    "allowed=true;; esac"
                    for index, _ in enumerate(self._allowed_roots())
                ),
                f'case "$resolved" in {shlex.quote(_REMOTE_ROOT)}|'
                f"{shlex.quote(_REMOTE_ROOT)}/*|*/.terminals|*/.terminals/*) "
                "allowed=false;; esac",
                'test "$allowed" = true || exit 77',
                expected_check,
                'printf %s "$resolved" | base64 | tr -d "\\n"',
                "printf '\\n'",
            ]
        )
        try:
            result = await self._environment.exec(
                f"/bin/bash -lc {shlex.quote(script)}",
                cwd=self._canonical_workspace(),
                timeout_sec=min(10.0, request.timeout_ms / 1000),
            )
        except BaseException as error:
            raise _ToolRejected("path_resolution_failed") from error
        if result.return_code != 0:
            if result.return_code == 77:
                raise _ToolRejected("path_outside_workspace")
            if allow_create and expected == "create":
                raise _ToolRejected("write_target_invalid")
            raise _ToolRejected(f"{request.tool_name}_target_invalid")
        encoded = result.stdout.strip()
        try:
            resolved = base64.b64decode(encoded, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as error:
            raise BridgeError("terminal_actor_path_response_invalid") from error
        if not resolved.startswith("/"):
            raise BridgeError("terminal_actor_path_response_invalid")
        if self._allowed_root_for(resolved) is None:
            raise BridgeError("terminal_actor_path_response_invalid")
        return resolved

    async def _read_file(self, request: ToolRequest) -> ToolExecution:
        arguments = request.arguments
        raw_target = arguments.get("target_file")
        offset = arguments.get("offset", 1)
        limit = arguments.get("limit", 1000)
        if isinstance(offset, bool) or not isinstance(offset, int):
            raise _ToolRejected("read_file_arguments_invalid")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            raise _ToolRejected("read_file_arguments_invalid")
        target = await self._resolve_workspace_path(
            request,
            raw_target,
            expected="file",
        )
        source_before = await self._media_source_snapshot(
            request,
            raw_target,
            target,
        )
        if source_before.byte_length > request.max_read_or_write_bytes:
            raise _ToolRejected("read_file_too_large")
        with tempfile.TemporaryDirectory(prefix="nano-read-file.") as raw:
            local_path = Path(raw) / "content"
            descriptor = os.open(
                local_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            os.close(descriptor)
            try:
                await self._environment.download_file(target, local_path)
                local_path.chmod(0o600)
                payload = local_path.read_bytes()
            except OSError as error:
                raise _ToolRejected("read_file_failed") from error
        source_after = await self._media_source_snapshot(
            request,
            raw_target,
            target,
        )
        source_digest = hashlib.sha256(payload).hexdigest()
        if (
            source_before != source_after
            or len(payload) != source_before.byte_length
            or source_digest != source_before.sha256
            or len(payload) > request.max_read_or_write_bytes
        ):
            if self._is_media_candidate(raw_target, payload):
                raise _ToolRejected("read_file_media_source_changed")
            raise BridgeError("terminal_actor_read_size_changed")
        if self._is_media_candidate(raw_target, payload):
            return self._read_media(
                request,
                source_before,
                payload,
            )
        text = self._read_text(payload)
        effective_limit = min(limit, 1000)
        normalized = text.replace("\r\n", "\n")
        lines = normalized.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        if offset == 0:
            offset = 1
        start = max(0, len(lines) + offset) if offset < 0 else offset - 1
        selected = lines[start : start + effective_limit] if start >= 0 else []
        output = "".join(
            f"{index}\u2192{line}\n"
            for index, line in enumerate(selected, start=start + 1)
        )
        return self._settled(output, succeeded=True, request=request)

    async def _media_source_snapshot(
        self,
        request: ToolRequest,
        raw_path: object,
        target: str,
    ) -> _MediaSourceSnapshot:
        if not isinstance(raw_path, str):
            raise _ToolRejected("invalid_path")
        candidate = (
            self._translate_logical_path(raw_path)
            if raw_path.startswith("/")
            else f"{self._canonical_workspace().rstrip('/')}/{raw_path}"
        )
        root = self._allowed_root_for(target)
        if root is None:
            raise _ToolRejected("path_outside_workspace")
        script = "\n".join(
            [
                "set -eu",
                f"workspace={shlex.quote(root)}",
                f"candidate={shlex.quote(candidate)}",
                f"target={shlex.quote(target)}",
                'lexical=$(realpath -sm -- "$candidate")',
                'case "$lexical" in "$workspace"/*) ;; *) exit 77;; esac',
                'resolved=$(realpath -e -- "$lexical")',
                'test "$resolved" = "$target"',
                'test -f "$target" && test ! -L "$target"',
                'relative=${lexical#"$workspace"/}',
                "has_symlink=false",
                'current="$workspace"',
                "old_ifs=$IFS",
                "IFS=/",
                "set -- $relative",
                "IFS=$old_ifs",
                'for component in "$@"; do',
                '  current="$current/$component"',
                '  if test -L "$current"; then has_symlink=true; fi',
                "done",
                'stat -c "%s" -- "$target"',
                'stat -c "%d" -- "$target"',
                'stat -c "%i" -- "$target"',
                'sha256sum -- "$target" | cut -d " " -f 1',
                'printf "%s\\n" "$has_symlink"',
            ]
        )
        try:
            result = await self._environment.exec(
                f"/bin/bash -lc {shlex.quote(script)}",
                cwd=self._canonical_workspace(),
                timeout_sec=min(10.0, request.timeout_ms / 1000),
            )
        except BaseException as error:
            raise _ToolRejected("read_file_metadata_failed") from error
        lines = result.stdout.splitlines()
        try:
            byte_length, device, inode = (int(value) for value in lines[:3])
            digest = lines[3]
            has_symlink = {"true": True, "false": False}[lines[4]]
        except (ValueError, IndexError, KeyError) as error:
            raise _ToolRejected("read_file_metadata_failed") from error
        if (
            result.return_code != 0
            or len(lines) != 5
            or byte_length < 0
            or device < 0
            or inode <= 0
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            raise _ToolRejected("read_file_metadata_failed")
        lexical = posixpath.normpath(candidate)
        logical_path = posixpath.relpath(lexical, root)
        if (
            logical_path in {"", "."}
            or logical_path.startswith("../")
            or logical_path == ".."
            or logical_path.startswith("/")
        ):
            raise _ToolRejected("path_outside_workspace")
        if root != self._canonical_workspace():
            logical_path = f"scratch/{logical_path}"
        return _MediaSourceSnapshot(
            logical_path=logical_path,
            byte_length=byte_length,
            sha256=digest,
            device=device,
            inode=inode,
            has_symlink=has_symlink,
        )

    @staticmethod
    def _is_media_candidate(raw_path: object, payload: bytes) -> bool:
        suffix = Path(raw_path).suffix.lower() if isinstance(raw_path, str) else ""
        return (
            suffix in _MEDIA_SUFFIXES
            or payload.startswith(b"\x89PNG\r\n\x1a\n")
            or payload.startswith(b"\xff\xd8\xff")
            or (
                len(payload) >= 12
                and payload.startswith(b"RIFF")
                and payload[8:12] == b"WEBP"
            )
            or payload.startswith(b"%PDF-")
        )

    def _read_media(
        self,
        request: ToolRequest,
        source: _MediaSourceSnapshot,
        payload: bytes,
    ) -> ToolExecution:
        suffix = Path(source.logical_path).suffix.lower()
        if not request.read_file_media_enabled:
            raise _ToolRejected("read_file_media_not_enabled")
        if suffix in _MEDIA_SUFFIXES - _RASTER_SUFFIXES or payload.startswith(b"%PDF-"):
            raise _ToolRejected("unsupported_media_in_foreground_six")
        if suffix == ".webp" or (
            len(payload) >= 12
            and payload.startswith(b"RIFF")
            and payload[8:12] == b"WEBP"
        ):
            raise _ToolRejected("read_file_media_unsupported")
        if source.has_symlink:
            raise _ToolRejected("read_file_media_symlink_rejected")
        if self._sensitive_media_path(source.logical_path):
            raise _ToolRejected("read_file_sensitive_path")
        if source.byte_length > _READ_FILE_MEDIA_MAX_BYTES:
            raise _ToolRejected("read_file_media_source_too_large")
        if payload.startswith(b"\x89PNG\r\n\x1a\n"):
            mime_type = "image/png"
            width, height = _png_dimensions(payload)
        elif payload.startswith(b"\xff\xd8\xff"):
            mime_type = "image/jpeg"
            width, height = _jpeg_dimensions(payload)
        elif suffix in {".jpeg", ".jpg", ".png"}:
            raise _ToolRejected("read_file_media_invalid")
        else:
            raise _ToolRejected("read_file_media_unsupported")
        if (
            width <= 0
            or height <= 0
            or width > _READ_FILE_MEDIA_MAX_DIMENSION
            or height > _READ_FILE_MEDIA_MAX_DIMENSION
        ):
            raise _ToolRejected("read_file_media_dimension_limit_exceeded")
        if width * height > _READ_FILE_MEDIA_MAX_PIXELS:
            raise _ToolRejected("read_file_media_pixel_limit_exceeded")
        canonical = payload
        if not canonical or len(canonical) > _READ_FILE_MEDIA_MAX_BYTES:
            raise _ToolRejected("read_file_media_canonical_too_large")
        canonical_sha256 = source.sha256
        media = MediaPayload(
            logical_path=source.logical_path,
            mime_type=mime_type,
            width=width,
            height=height,
            source_byte_length=source.byte_length,
            source_sha256=source.sha256,
            canonical_byte_length=len(canonical),
            canonical_sha256=canonical_sha256,
            content=canonical,
        )
        output = (
            f"read_file returned an attached image: {mime_type}, "
            f"{width}x{height}, sha256={canonical_sha256}"
        )
        return self._settled(
            output,
            succeeded=True,
            request=request,
            media=media,
        )

    @staticmethod
    def _sensitive_media_path(logical_path: str) -> bool:
        parts = tuple(part.casefold() for part in Path(logical_path).parts)
        basename = parts[-1] if parts else ""
        return (
            any(part in _SENSITIVE_MEDIA_PARTS for part in parts)
            or basename.startswith(".env")
            or basename in _SENSITIVE_MEDIA_BASENAMES
            or Path(basename).stem.casefold() in _SENSITIVE_MEDIA_BASENAMES
            or Path(basename).suffix.casefold() in _SENSITIVE_MEDIA_EXTENSIONS
        )

    @staticmethod
    def _read_text(payload: bytes) -> str:
        if b"\x00" in payload:
            raise _ToolRejected("binary_file_unsupported")
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise _ToolRejected("binary_file_unsupported") from error

    async def _write_file(self, request: ToolRequest) -> ToolExecution:
        arguments = request.arguments
        content = arguments.get("content")
        if not isinstance(content, str):
            raise _ToolRejected("write_arguments_invalid")
        payload = content.encode("utf-8")
        if len(payload) > request.max_read_or_write_bytes:
            raise _ToolRejected("write_content_too_large")
        target = await self._resolve_workspace_path(
            request,
            arguments.get("file_path"),
            expected="create",
            allow_create=True,
        )
        existed = await self._remote_regular_file_exists(request, target)
        effect_observation = await self._atomic_upload(request, target, payload)
        message = (
            f"Wrote file successfully to {target}."
            if existed
            else f"The file {target} has been " + "created."
        )
        return self._settled(
            message,
            succeeded=True,
            request=request,
            effect_observation_v1=effect_observation,
        )

    async def _remote_regular_file_exists(
        self, request: ToolRequest, target: str
    ) -> bool:
        result = await self._environment.exec(
            f"test -f {shlex.quote(target)}",
            cwd=self._canonical_workspace(),
            timeout_sec=min(10.0, request.timeout_ms / 1000),
        )
        if result.return_code not in {0, 1}:
            raise _ToolRejected("write_target_invalid")
        return result.return_code == 0

    async def _atomic_upload(
        self, request: ToolRequest, target: str, payload: bytes
    ) -> EffectObservationV1:
        root = self._allowed_root_for(target)
        if root is None:
            raise _ToolRejected("path_outside_workspace")
        request_dir = self._request_dir(request)
        result = await self._environment.exec(
            f"mkdir -p {shlex.quote(request_dir)} && "
            f"chmod 700 {shlex.quote(request_dir)}",
            timeout_sec=min(10.0, request.timeout_ms / 1000),
        )
        if result.return_code != 0:
            raise _ToolRejected("write_staging_failed")
        with tempfile.NamedTemporaryFile(
            prefix="nano-write.",
            delete=False,
        ) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            local_path = Path(handle.name)
        incoming = f"{request_dir}/incoming"
        try:
            await self._environment.upload_file(local_path, incoming)
        finally:
            local_path.unlink(missing_ok=True)
        script = "\n".join(
            [
                "set -eu",
                f"workspace={shlex.quote(root)}",
                f"destination={shlex.quote(target)}",
                'parent=$(dirname -- "$destination")',
                'mkdir -p -- "$parent"',
                'resolved=$(realpath -m -- "$destination")',
                'test "$resolved" = "$destination"',
                'case "$resolved" in "$workspace"|"$workspace"/*) ;; *) exit 77;; esac',
                'temporary=$(mktemp -- "$parent/.nano-write.XXXXXX")',
                "trap 'rm -f -- \"$temporary\"' EXIT",
                f'cp -- {shlex.quote(incoming)} "$temporary"',
                (
                    'if test -f "$destination"; then '
                    'chmod --reference="$destination" "$temporary"; fi'
                ),
                "effect=changed",
                (
                    'if test -f "$destination" && '
                    'cmp -s -- "$temporary" "$destination"; then '
                    "effect=unchanged; fi"
                ),
                'mv -f -- "$temporary" "$destination"',
                "trap - EXIT",
                'printf "%s\\n" "$effect"',
            ]
        )
        result = await self._environment.exec(
            f"/bin/bash -lc {shlex.quote(script)}",
            cwd=self._canonical_workspace(),
            timeout_sec=request.timeout_ms / 1000,
        )
        if (
            result.return_code != 0
            or result.stderr != ""
            or result.stdout not in {"changed\n", "unchanged\n"}
        ):
            raise _ToolRejected("write_failed")
        return EffectObservationV1(
            status=(
                EffectObservationStatusV1.CHANGED
                if result.stdout == "changed\n"
                else EffectObservationStatusV1.UNCHANGED
            )
        )

    @staticmethod
    def _settled(
        output: str,
        *,
        succeeded: bool,
        request: ToolRequest,
        media: MediaPayload | None = None,
        effect_observation_v1: EffectObservationV1 | None = None,
    ) -> ToolExecution:
        raw = output.encode("utf-8")
        truncated = False
        if len(raw) > request.stdout_cap_bytes:
            raw = _truncate_utf8_bytes(raw, request.stdout_cap_bytes)
            truncated = True
        observed_effect = effect_observation_v1
        if observed_effect is None and request.tool_name in {
            "read_file",
            "list_dir",
            "grep",
        }:
            observed_effect = EffectObservationV1(
                status=EffectObservationStatusV1.NOT_APPLICABLE
            )
        return ToolExecution(
            return_code=0 if succeeded else 2,
            timed_out=False,
            stdout=raw,
            stderr=b"",
            stdout_truncated=truncated,
            stderr_truncated=False,
            cleanup_attempted=True,
            term_sent=False,
            kill_sent=False,
            cleanup_verified=True,
            census_verified=True,
            survivor_count=0,
            effect_observation_v1=observed_effect,
            media=media,
        )

    async def _search_replace(self, request: ToolRequest) -> ToolExecution:
        arguments = request.arguments
        file_path = arguments.get("file_path")
        old_string = arguments.get("old_string")
        new_string = arguments.get("new_string")
        replace_all = arguments.get("replace_all", False)
        if (
            not isinstance(old_string, str)
            or not isinstance(new_string, str)
            or not isinstance(replace_all, bool)
            or old_string == new_string
        ):
            raise _ToolRejected("search_replace_arguments_invalid")
        if (
            len(old_string.encode("utf-8")) > request.max_read_or_write_bytes
            or len(new_string.encode("utf-8")) > request.max_read_or_write_bytes
        ):
            raise _ToolRejected("search_replace_content_too_large")
        if old_string == "":
            target = await self._resolve_workspace_path(
                request,
                file_path,
                expected="create",
                allow_create=True,
            )
            payload = new_string.encode("utf-8")
            if len(payload) > request.max_read_or_write_bytes:
                raise _ToolRejected("search_replace_content_too_large")
            effect_observation = await self._atomic_upload(request, target, payload)
            return self._settled(
                f"The file {file_path} has been " + "created.",
                succeeded=True,
                request=request,
                effect_observation_v1=effect_observation,
            )

        target = await self._resolve_workspace_path(
            request,
            file_path,
            expected="file",
        )
        payload = await self._download_bounded(request, target)
        text = self._read_text(payload)
        had_crlf = "\r\n" in text
        match_text = text.replace("\r\n", "\n") if had_crlf else text
        matches = match_text.count(old_string)
        if matches == 0:
            return self._settled(
                (
                    "The string to replace was not found in the file, use the "
                    "read_file tool to see the correct string."
                ),
                succeeded=False,
                request=request,
            )
        if matches > request.max_replacements:
            raise _ToolRejected("search_replace_replacement_limit_exceeded")
        if matches > 1 and not replace_all:
            return self._settled(
                (
                    "The string to replace was found multiple times in the file. "
                    "Use replace_all to replace all occurrences, or include more "
                    "context to only edit one occurrence."
                ),
                succeeded=False,
                request=request,
            )
        updated = match_text.replace(
            old_string,
            new_string,
            -1 if replace_all else 1,
        )
        if had_crlf:
            updated = updated.replace("\r\n", "\n").replace("\n", "\r\n")
        updated_bytes = updated.encode("utf-8")
        if len(updated_bytes) > request.max_read_or_write_bytes:
            raise _ToolRejected("search_replace_result_too_large")
        effect_observation = await self._atomic_upload(
            request,
            target,
            updated_bytes,
        )
        message = (
            f"The file {file_path} has been updated. "
            "All occurrences were successfully replaced."
            if replace_all and matches > 1
            else f"The file {file_path} has been updated " + "successfully."
        )
        return self._settled(
            message,
            succeeded=True,
            request=request,
            effect_observation_v1=effect_observation,
        )

    async def _download_bounded(self, request: ToolRequest, target: str) -> bytes:
        try:
            result = await self._environment.exec(
                f"stat -c %s -- {shlex.quote(target)}",
                cwd=self._canonical_workspace(),
                timeout_sec=min(10.0, request.timeout_ms / 1000),
            )
            size = int(result.stdout.strip()) if result.return_code == 0 else -1
        except (OSError, ValueError) as error:
            raise _ToolRejected("file_metadata_failed") from error
        if size < 0:
            raise _ToolRejected("file_metadata_failed")
        if size > request.max_read_or_write_bytes:
            raise _ToolRejected("file_too_large")
        with tempfile.TemporaryDirectory(prefix="nano-file-download.") as raw:
            local_path = Path(raw) / "content"
            try:
                await self._environment.download_file(target, local_path)
                payload = local_path.read_bytes()
            except OSError as error:
                raise _ToolRejected("file_download_failed") from error
        if len(payload) != size or len(payload) > request.max_read_or_write_bytes:
            raise BridgeError("terminal_actor_file_size_changed")
        return payload

    async def _list_dir(self, request: ToolRequest) -> ToolExecution:
        target = await self._resolve_workspace_path(
            request,
            request.arguments.get("target_directory"),
            expected="directory",
        )
        entries, cutoff = await self._remote_directory_inventory(
            request,
            target,
        )
        output = _render_directory_entries(
            target,
            entries,
            max_bytes=request.stdout_cap_bytes,
            inventory_cutoff=cutoff,
        )
        return self._settled(output, succeeded=True, request=request)

    async def _grep(self, request: ToolRequest) -> ToolExecution:
        arguments = request.arguments
        pattern = arguments.get("pattern")
        if not isinstance(pattern, str):
            raise _ToolRejected("grep_arguments_invalid")
        raw_path = arguments.get("path")
        if raw_path is not None and not isinstance(raw_path, str):
            raise _ToolRejected("grep_arguments_invalid")
        target = await self._resolve_workspace_path(
            request,
            raw_path or self._canonical_workspace(),
            expected="any",
        )
        glob = arguments.get("glob")
        file_type = arguments.get("type")
        multiline = arguments.get("multiline", False)
        insensitive = arguments.get("-i", False)
        if (
            glob is not None
            and not isinstance(glob, str)
            or file_type is not None
            and not isinstance(file_type, str)
            or not isinstance(multiline, bool)
            or not isinstance(insensitive, bool)
        ):
            raise _ToolRejected("grep_arguments_invalid")
        contexts = {}
        for key in ("-A", "-B", "-C"):
            value = arguments.get(key)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 0
            ):
                raise _ToolRejected("grep_arguments_invalid")
            contexts[key] = value
        head_limit = arguments.get("head_limit", 200)
        if (
            isinstance(head_limit, bool)
            or not isinstance(head_limit, int)
            or head_limit <= 0
        ):
            raise _ToolRejected("grep_arguments_invalid")
        line_limit = min(head_limit, 2000, request.max_grep_matches)
        backend = await self._grep_backend(request)
        root = self._allowed_root_for(target)
        if root is None:
            raise _ToolRejected("path_outside_workspace")
        relative_target = (
            posixpath.relpath(target, root)
            if root == self._canonical_workspace()
            else target
        )
        if backend == "rg":
            argv = [
                "rg",
                "--no-heading",
                "--color",
                "never",
                "--line-number",
                "--with-filename",
            ]
            if insensitive:
                argv.append("-i")
            for key in ("-A", "-B", "-C"):
                if contexts[key] is not None:
                    argv.extend([key, str(contexts[key])])
            if glob is not None:
                argv.extend(["--glob", glob])
            if file_type is not None:
                argv.extend(["--type", file_type])
            if multiline:
                argv.extend(["-U", "--multiline-dotall"])
            argv.extend(["--regexp", pattern, "--", relative_target])
        else:
            if multiline:
                raise _ToolRejected("grep_multiline_unsupported_without_rg")
            if glob is not None and any(char in glob for char in "{},"):
                raise _ToolRejected("grep_glob_unsupported_without_rg")
            if file_type is not None:
                mapped_glob = _GREP_TYPE_GLOBS.get(file_type)
                if mapped_glob is None:
                    raise _ToolRejected("grep_type_unsupported_without_rg")
                if glob is not None:
                    raise _ToolRejected("grep_glob_and_type_unsupported_without_rg")
                glob = mapped_glob
            argv = ["grep", "-E", "-nH", "-R"]
            if insensitive:
                argv.append("-i")
            for key in ("-A", "-B", "-C"):
                if contexts[key] is not None:
                    argv.extend([key, str(contexts[key])])
            if glob is not None:
                argv.append(f"--include={glob}")
            argv.extend(["--", pattern, relative_target])
        code, lines, overflow = await self._run_bounded_search(
            request,
            argv,
            line_limit,
        )
        if code == 1:
            return self._settled("", succeeded=True, request=request)
        output = "".join(f"{line}\n" for line in lines)
        if overflow:
            output += "\n... output truncated ...\n"
        if code != 0:
            return self._settled(
                output or f"{backend}_search_failed",
                succeeded=False,
                request=request,
            )
        return self._settled(output, succeeded=True, request=request)

    async def _remote_directory_inventory(
        self,
        request: ToolRequest,
        target: str,
    ) -> tuple[list[tuple[str, bool]], bool]:
        script = "\n".join(
            [
                "set -u",
                f"root={shlex.quote(target)}",
                f"workspace={shlex.quote(self._canonical_workspace())}",
                "count=0",
                "cutoff=false",
                "while IFS= read -r -d '' entry; do",
                '  relative=${entry#"$root"/}',
                '  case "$relative" in .*|*/.*) continue;; esac',
                '  if git -C "$workspace" check-ignore -q -- "$entry" '
                "2>/dev/null; then continue; fi",
                '  if test -L "$entry"; then continue; '
                'elif test -d "$entry"; then kind=D; '
                'elif test -f "$entry"; then kind=F; else continue; fi',
                (
                    f'  if test "$count" -ge {request.max_directory_entries}; '
                    "then cutoff=true; break; fi"
                ),
                '  printf "%s\\t" "$kind"',
                '  printf %s "$relative" | base64 | tr -d "\\n"',
                "  printf '\\n'",
                "  count=$((count + 1))",
                'done < <(find "$root" -mindepth 1 -print0)',
                'printf "X\\t%s\\n" "$cutoff"',
            ]
        )
        result = await self._environment.exec(
            f"/bin/bash -lc {shlex.quote(script)}",
            cwd=self._canonical_workspace(),
            timeout_sec=request.timeout_ms / 1000,
        )
        if result.return_code != 0:
            raise _ToolRejected("list_dir_failed")
        rows = result.stdout.splitlines()
        if not rows or not rows[-1].startswith("X\t"):
            raise BridgeError("terminal_actor_list_inventory_invalid")
        cutoff = rows.pop() == "X\ttrue"
        entries: list[tuple[str, bool]] = []
        for row in rows:
            try:
                kind, encoded = row.split("\t", 1)
                relative = base64.b64decode(encoded, validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError) as error:
                raise BridgeError("terminal_actor_list_inventory_invalid") from error
            if kind not in {"D", "F"} or not relative or relative.startswith("/"):
                raise BridgeError("terminal_actor_list_inventory_invalid")
            entries.append((relative, kind == "D"))
        if len(entries) > request.max_directory_entries:
            raise BridgeError("terminal_actor_list_inventory_invalid")
        return entries, cutoff

    async def _grep_backend(self, request: ToolRequest) -> str:
        for backend in ("rg", "grep"):
            result = await self._environment.exec(
                f"command -v {backend} >/dev/null 2>&1",
                cwd=self._canonical_workspace(),
                timeout_sec=min(5.0, request.timeout_ms / 1000),
            )
            if result.return_code == 0:
                return backend
        raise _ToolRejected("grep_backend_unavailable")

    async def _run_bounded_search(
        self,
        request: ToolRequest,
        argv: list[str],
        line_limit: int,
    ) -> tuple[int, list[str], bool]:
        marker = f"__NANO_SEARCH_{request.request_sha256[:16]}__"
        command = shlex.join(argv)
        script = "\n".join(
            [
                "set +e",
                (
                    f"{command} 2>&1 | "
                    f"awk 'NR<={line_limit} "
                    "{ if (length($0)>1000) print substr($0,1,1000); "
                    "else print; next } { exit 42 }'"
                ),
                'codes=("${PIPESTATUS[@]}")',
                f"printf '%s=%s,%s\\n' {shlex.quote(marker)} "
                '"${codes[0]}" "${codes[1]}"',
            ]
        )
        result = await self._environment.exec(
            f"/bin/bash -lc {shlex.quote(script)}",
            cwd=self._canonical_workspace(),
            timeout_sec=request.timeout_ms / 1000,
        )
        if result.return_code != 0:
            raise _ToolRejected("grep_transport_failed")
        lines = result.stdout.splitlines()
        if not lines or not lines[-1].startswith(f"{marker}="):
            raise BridgeError("terminal_actor_grep_response_invalid")
        try:
            raw_codes = lines.pop().split("=", 1)[1]
            command_code, limiter_code = (
                int(value) for value in raw_codes.split(",", 1)
            )
        except (ValueError, IndexError) as error:
            raise BridgeError("terminal_actor_grep_response_invalid") from error
        overflow = limiter_code == 42
        if limiter_code not in {0, 42}:
            raise BridgeError("terminal_actor_grep_response_invalid")
        if overflow and command_code in {0, 141}:
            command_code = 0
        return command_code, lines[:line_limit], overflow

    async def _download_result(
        self, request_dir: str, request: ToolRequest
    ) -> ToolExecution:
        with tempfile.TemporaryDirectory(prefix="nano-terminal-result.") as raw:
            root = Path(raw)
            for name in ("meta.json", "stdout.bin", "stderr.bin"):
                if request.actor_done_monotonic_ns is None:
                    await self._environment.download_file(
                        f"{request_dir}/{name}",
                        root / name,
                    )
                else:
                    cutoff_ns, timeout_sec = self._actor_phase_budget(request)
                    try:
                        await asyncio.wait_for(
                            self._environment.download_file(
                                f"{request_dir}/{name}",
                                root / name,
                            ),
                            timeout=timeout_sec,
                        )
                    except TimeoutError as error:
                        if self._monotonic_ns() >= cutoff_ns:
                            raise _ActorDoneDeadlineExceeded(
                                "terminal_actor_deadline_exceeded"
                            ) from error
                        raise
            meta = _strict_meta((root / "meta.json").read_bytes())
            stdout = (root / "stdout.bin").read_bytes()
            stderr = (root / "stderr.bin").read_bytes()
        if (
            len(stdout) > request.stdout_cap_bytes
            or len(stderr) > request.stderr_cap_bytes
        ):
            raise BridgeError("terminal_actor_output_limit_exceeded")
        return ToolExecution(
            return_code=meta["return_code"],
            timed_out=meta["timed_out"],
            stdout=stdout,
            stderr=stderr,
            stdout_truncated=meta["stdout_truncated"],
            stderr_truncated=meta["stderr_truncated"],
            cleanup_attempted=meta["cleanup_attempted"],
            term_sent=meta["term_sent"],
            kill_sent=meta["kill_sent"],
            cleanup_verified=meta["cleanup_verified"],
            census_verified=meta["census_verified"],
            survivor_count=meta["survivor_count"],
            process_disposition=ProcessDisposition.FOREGROUND_CLEANED,
            target_task_id=None,
        )
