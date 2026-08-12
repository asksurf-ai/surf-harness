"""Strict JSONL bridge between the host runtime and a sandbox tool actor."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePosixPath
from typing import Any, Protocol

from nano_grok_build.adapter.cleanup_closure import (
    ActorDispatchStateV1,
    HandlerCompletionStateV1,
)
from nano_grok_build.adapter.deadline import RunDeadlineReceiptV1, host_monotonic_ns

LEGACY_SCHEMA_VERSION = "external-tool-stdio-v2"
LIVE_SCHEMA_VERSION = "external-tool-stdio-v3"
# Kept as the historical-reader alias for callers that inspect archived v2
# fixtures.  The live bridge selects LIVE_SCHEMA_VERSION explicitly.
SCHEMA_VERSION = LEGACY_SCHEMA_VERSION
TOOL_NAMES = (
    "run_terminal_command",
    "read_file",
    "search_replace",
    "write",
    "list_dir",
    "grep",
    "kill_terminal_command",
    "get_terminal_command_output",
)
MAX_REQUEST_LINE_BYTES = 8 * 1024 * 1024
MAX_STDERR_BYTES = 1024 * 1024
RESPONSE_PROTOCOL_OVERHEAD_BYTES = 32 * 1024
SETTLEMENT_STAGE_COUNT = 6
MIN_SETTLEMENT_STAGE_MS = 1
U64_MAX = 2**64 - 1
READ_FILE_MEDIA_MAX_BYTES = 4 * 1024 * 1024
READ_FILE_MEDIA_MAX_DIMENSION = 8192
READ_FILE_MEDIA_MAX_PIXELS = 25_000_000
REMOTE_ENVIRONMENT_ALLOWLIST = (
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "TERM",
    "TMPDIR",
    "USER",
)
_REQUEST_KEYS = {
    "schema_version",
    "message_type",
    "seq",
    "run_id",
    "trial_id",
    "attempt_id",
    "call_id",
    "tool_name",
    "arguments_json",
    "logical_cwd",
    "timeout_ms",
    "term_grace_ms",
    "kill_confirmation_timeout_ms",
    "stdout_cap_bytes",
    "stderr_cap_bytes",
    "environment",
    "limits",
}
_LIVE_DEADLINE_KEYS = {
    "actor_done_monotonic_ns",
    "tool_settled_monotonic_ns",
    "last_send_monotonic_ns",
    "runtime_final_monotonic_ns",
    "cleanup_start_monotonic_ns",
    "hard_deadline_monotonic_ns",
    "cleanup_reserve_ms",
    "terminalization_reserve_ms",
    "provider_send_reserve_ms",
    "process_settlement_reserve_ms",
    "deadline_receipt_sha256",
}
_LIVE_REQUEST_KEYS = (
    (_REQUEST_KEYS - {"timeout_ms"}) | {"operation_timeout_ms"} | _LIVE_DEADLINE_KEYS
)
_LIMIT_KEYS = {
    "arguments_cap_bytes",
    "max_path_bytes",
    "max_read_or_write_bytes",
    "max_directory_entries",
    "max_grep_matches",
    "max_replacements",
    "max_background_processes",
    "process_spool_bytes_per_process",
    "process_spool_bytes_per_run",
    "background_output_wait_max_ms",
}
_OPTIONAL_LIMIT_KEYS = {"read_file_media_enabled"}


class BridgeError(RuntimeError):
    """The runtime/tool exchange cannot be safely settled."""

    def __init__(
        self,
        code: str,
        *,
        stderr: bytes | None = None,
        failure_receipt: Mapping[str, Any] | None = None,
        cleanup_receipt: Mapping[str, Any] | None = None,
    ):
        super().__init__(code)
        self.stderr = stderr
        self.failure_receipt = (
            dict(failure_receipt) if failure_receipt is not None else None
        )
        self.cleanup_receipt = (
            dict(cleanup_receipt) if cleanup_receipt is not None else None
        )


def _bridge_handler_identity(
    handler: ToolHandler,
    *,
    task_image: str | None,
    trial_family: str | None,
) -> tuple[str, str]:
    """Return bounded non-secret workload identity for diagnostic receipts."""

    if task_image is None:
        task_image = getattr(handler, "task_image", "unknown")
    if trial_family is None:
        trial_family = getattr(handler, "trial_family", "unknown")
    return (
        task_image if isinstance(task_image, str) else "unknown",
        trial_family if isinstance(trial_family, str) else "unknown",
    )


def _runtime_exit_failure_receipt(
    handler: ToolHandler,
    *,
    task_image: str | None,
    trial_family: str | None,
    return_code: int,
    stderr: bytes,
) -> dict[str, Any]:
    task_image, trial_family = _bridge_handler_identity(
        handler,
        task_image=task_image,
        trial_family=trial_family,
    )
    return {
        "schema_version": "external-bridge-failure-v1",
        "code": "external_runtime_nonzero",
        "phase": "runtime_exit",
        "task_image": task_image,
        "trial_family": trial_family,
        "return_code": return_code,
        "stderr_byte_length": len(stderr),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
    }


@dataclass(frozen=True)
class SettlementStageCutoffsV1:
    """Deterministic, non-borrowable subdivisions of the one settlement reserve."""

    probe_monotonic_ns: int
    output_monotonic_ns: int
    encode_monotonic_ns: int
    drain_monotonic_ns: int
    parse_monotonic_ns: int
    history_commit_monotonic_ns: int

    @classmethod
    def derive(
        cls,
        *,
        actor_done_monotonic_ns: int,
        tool_settled_monotonic_ns: int,
        process_settlement_reserve_ms: int,
    ) -> SettlementStageCutoffsV1:
        if (
            isinstance(actor_done_monotonic_ns, bool)
            or not isinstance(actor_done_monotonic_ns, int)
            or not 0 < actor_done_monotonic_ns <= U64_MAX
            or isinstance(tool_settled_monotonic_ns, bool)
            or not isinstance(tool_settled_monotonic_ns, int)
            or not 0 < tool_settled_monotonic_ns <= U64_MAX
            or isinstance(process_settlement_reserve_ms, bool)
            or not isinstance(process_settlement_reserve_ms, int)
            or not 0 < process_settlement_reserve_ms <= U64_MAX // 1_000_000
        ):
            raise BridgeError("external_request_settlement_budget_invalid")
        span_ns = tool_settled_monotonic_ns - actor_done_monotonic_ns
        if (
            process_settlement_reserve_ms
            < SETTLEMENT_STAGE_COUNT * MIN_SETTLEMENT_STAGE_MS
            or span_ns != process_settlement_reserve_ms * 1_000_000
        ):
            raise BridgeError("external_request_settlement_budget_invalid")
        cutoffs = tuple(
            actor_done_monotonic_ns + span_ns * index // SETTLEMENT_STAGE_COUNT
            for index in range(1, SETTLEMENT_STAGE_COUNT + 1)
        )
        if (
            any(earlier >= later for earlier, later in zip(cutoffs, cutoffs[1:]))
            or cutoffs[-1] != tool_settled_monotonic_ns
        ):
            raise BridgeError("external_request_settlement_budget_invalid")
        return cls(*cutoffs)


def _strict_remaining_sec(cutoff_monotonic_ns: int, now_monotonic_ns: int) -> float:
    """Return zero at or after a cutoff; equality never borrows the next stage."""

    if now_monotonic_ns >= cutoff_monotonic_ns:
        return 0.0
    return (cutoff_monotonic_ns - now_monotonic_ns) / 1_000_000_000


def _write_response_before_drain_cutoff(
    stdin: Any,
    response: bytes,
    *,
    drain_cutoff_monotonic_ns: int,
    monotonic_ns: Callable[[], int],
) -> None:
    """Synchronously buffer a response only inside the strict drain stage."""

    if monotonic_ns() >= drain_cutoff_monotonic_ns:
        raise BridgeError("response_serialization_deadline_exceeded")
    stdin.write(response + b"\n")
    if monotonic_ns() >= drain_cutoff_monotonic_ns:
        raise BridgeError("response_serialization_deadline_exceeded")


class ToolHandler(Protocol):
    async def execute(self, request: ToolRequest) -> ToolExecution | ToolFailure: ...

    async def cleanup_active(self) -> bool: ...


class ProcessDisposition(str, Enum):
    NO_PROCESS = "no_process"
    FOREGROUND_CLEANED = "foreground_cleaned"
    BACKGROUND_RETAINED = "background_retained"
    BACKGROUND_TERMINATED = "background_terminated"


class EffectObservationStatusV1(str, Enum):
    """Closed direct-effect states safe to cross the v3 bridge."""

    CHANGED = "changed"
    UNCHANGED = "unchanged"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class EffectObservationV1:
    """One bounded observation; absent means unobserved, never unchanged."""

    status: EffectObservationStatusV1


BACKGROUND_START_PROOF_VERSION = "background-start-no-id-proof-v1"
TERMINAL_ACTOR_RECEIPT_SCHEMA_VERSION = "terminal-actor-receipt-v1"


class BackgroundStartKind(str, Enum):
    """Closed observations that prove a background request published no handle."""

    NOT_STARTED = "not_started"
    QUICK_EXIT = "quick_exit"


@dataclass(frozen=True)
class BackgroundStartObservation:
    """Versioned, request-bound proof facts for a no-ID background start."""

    proof_version: str
    kind: BackgroundStartKind
    task_id_published: bool
    child_exit_code: int | None


class TerminalActorPhaseV1(str, Enum):
    """Closed actor phase at which the terminal outcome became authoritative."""

    MAPPING_PREFLIGHT = "mapping_preflight"
    REMOTE_SETUP = "remote_setup"
    COMMAND_UPLOAD = "command_upload"
    REMOTE_EXEC = "remote_exec"
    RECOVERY_DOWNLOAD = "recovery_download"
    RESULT_DOWNLOAD = "result_download"
    META_VALIDATE = "meta_validate"
    CLEANUP = "cleanup"
    CENSUS = "census"
    ACTOR_DONE = "actor_done"


class TerminalActorOriginV1(str, Enum):
    """Closed provenance for one terminal actor primary outcome."""

    SEMANTIC = "semantic"
    TRANSPORT = "transport"
    PROTOCOL = "protocol"
    ACTOR = "actor"


class TerminalActorSubtypeV1(str, Enum):
    """Closed, secret-free terminal actor outcome discriminants."""

    COMPLETED = "completed"
    SEMANTIC_EXECUTION_TIMED_OUT = "semantic_execution_timed_out"
    ACTOR_DEADLINE_EXCEEDED = "actor_deadline_exceeded"
    WORKSPACE_MAPPING_CHECK_TIMEOUT = "workspace_mapping_check_timeout"
    WORKSPACE_MAPPING_CHANGED = "workspace_mapping_changed"
    REQUEST_SETUP_FAILED = "request_setup_failed"
    COMMAND_UPLOAD_FAILED = "command_upload_failed"
    RUN_TRANSPORT_TIMEOUT = "run_transport_timeout"
    RUN_TRANSPORT_FAILED = "run_transport_failed"
    RUN_RESPONSE_NONZERO = "run_response_nonzero"
    RECOVERED_SETTLED = "recovered_settled"
    RECOVERY_DOWNLOAD_FAILED = "recovery_download_failed"
    META_INVALID = "meta_invalid"
    OUTPUT_DOWNLOAD_FAILED = "output_download_failed"
    OUTPUT_LIMIT_EXCEEDED = "output_limit_exceeded"
    CLEANUP_UNVERIFIED = "cleanup_unverified"
    CANCELLED = "cancelled"
    UNEXPECTED_FAILURE = "unexpected_failure"


@dataclass(frozen=True)
class TerminalActorReceiptV1:
    """Immutable typed terminal evidence safe to cross the stdio boundary."""

    schema_version: str
    phase: TerminalActorPhaseV1
    origin: TerminalActorOriginV1
    primary_subtype: TerminalActorSubtypeV1
    recovery_subtype: TerminalActorSubtypeV1 | None
    execution_may_have_started: bool
    effective_cutoff_monotonic_ns: int
    cleanup_verified: bool | None
    census_verified: bool | None
    diagnostic_digest_sha256: str

    @staticmethod
    def _diagnostic_value(
        *,
        schema_version: str,
        phase: TerminalActorPhaseV1,
        origin: TerminalActorOriginV1,
        primary_subtype: TerminalActorSubtypeV1,
        recovery_subtype: TerminalActorSubtypeV1 | None,
        execution_may_have_started: bool,
        effective_cutoff_monotonic_ns: int,
        cleanup_verified: bool | None,
        census_verified: bool | None,
    ) -> dict[str, object]:
        return {
            "schema_version": schema_version,
            "phase": phase.value,
            "origin": origin.value,
            "primary_subtype": primary_subtype.value,
            "recovery_subtype": (
                None if recovery_subtype is None else recovery_subtype.value
            ),
            "execution_may_have_started": execution_may_have_started,
            "effective_cutoff_monotonic_ns": effective_cutoff_monotonic_ns,
            "cleanup_verified": cleanup_verified,
            "census_verified": census_verified,
        }

    @classmethod
    def create(
        cls,
        *,
        phase: TerminalActorPhaseV1,
        origin: TerminalActorOriginV1,
        primary_subtype: TerminalActorSubtypeV1,
        recovery_subtype: TerminalActorSubtypeV1 | None,
        execution_may_have_started: bool,
        effective_cutoff_monotonic_ns: int,
        cleanup_verified: bool | None,
        census_verified: bool | None,
    ) -> TerminalActorReceiptV1:
        value = cls._diagnostic_value(
            schema_version=TERMINAL_ACTOR_RECEIPT_SCHEMA_VERSION,
            phase=phase,
            origin=origin,
            primary_subtype=primary_subtype,
            recovery_subtype=recovery_subtype,
            execution_may_have_started=execution_may_have_started,
            effective_cutoff_monotonic_ns=effective_cutoff_monotonic_ns,
            cleanup_verified=cleanup_verified,
            census_verified=census_verified,
        )
        digest = hashlib.sha256(
            json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        return cls(
            schema_version=TERMINAL_ACTOR_RECEIPT_SCHEMA_VERSION,
            phase=phase,
            origin=origin,
            primary_subtype=primary_subtype,
            recovery_subtype=recovery_subtype,
            execution_may_have_started=execution_may_have_started,
            effective_cutoff_monotonic_ns=effective_cutoff_monotonic_ns,
            cleanup_verified=cleanup_verified,
            census_verified=census_verified,
            diagnostic_digest_sha256=digest,
        )

    def diagnostic_value(self) -> dict[str, object]:
        return self._diagnostic_value(
            schema_version=self.schema_version,
            phase=self.phase,
            origin=self.origin,
            primary_subtype=self.primary_subtype,
            recovery_subtype=self.recovery_subtype,
            execution_may_have_started=self.execution_may_have_started,
            effective_cutoff_monotonic_ns=self.effective_cutoff_monotonic_ns,
            cleanup_verified=self.cleanup_verified,
            census_verified=self.census_verified,
        )

    def as_dict(self) -> dict[str, object]:
        return {
            **self.diagnostic_value(),
            "diagnostic_digest_sha256": self.diagnostic_digest_sha256,
        }

    def with_containment(
        self,
        *,
        phase: TerminalActorPhaseV1 | None = None,
        cleanup_verified: bool | None,
        census_verified: bool | None,
    ) -> TerminalActorReceiptV1:
        return self.create(
            phase=self.phase if phase is None else phase,
            origin=self.origin,
            primary_subtype=self.primary_subtype,
            recovery_subtype=self.recovery_subtype,
            execution_may_have_started=self.execution_may_have_started,
            effective_cutoff_monotonic_ns=self.effective_cutoff_monotonic_ns,
            cleanup_verified=cleanup_verified,
            census_verified=census_verified,
        )


@dataclass(frozen=True)
class ToolRequest:
    raw_json: bytes
    seq: int
    run_id: str
    trial_id: str
    attempt_id: str
    call_id: str
    tool_name: str
    arguments_json: str
    arguments: Mapping[str, Any]
    logical_cwd: str
    timeout_ms: int
    term_grace_ms: int
    kill_confirmation_timeout_ms: int
    stdout_cap_bytes: int
    stderr_cap_bytes: int
    arguments_cap_bytes: int
    max_path_bytes: int
    max_read_or_write_bytes: int
    max_directory_entries: int
    max_grep_matches: int
    max_replacements: int
    max_background_processes: int
    process_spool_bytes_per_process: int
    process_spool_bytes_per_run: int
    background_output_wait_max_ms: int
    read_file_media_enabled: bool
    schema_version: str = LEGACY_SCHEMA_VERSION
    actor_done_monotonic_ns: int | None = None
    tool_settled_monotonic_ns: int | None = None
    last_send_monotonic_ns: int | None = None
    runtime_final_monotonic_ns: int | None = None
    cleanup_start_monotonic_ns: int | None = None
    hard_deadline_monotonic_ns: int | None = None
    cleanup_reserve_ms: int | None = None
    terminalization_reserve_ms: int | None = None
    provider_send_reserve_ms: int | None = None
    process_settlement_reserve_ms: int | None = None
    deadline_receipt_sha256: str | None = None

    @property
    def request_sha256(self) -> str:
        return hashlib.sha256(self.raw_json).hexdigest()

    @property
    def has_absolute_deadline(self) -> bool:
        return self.schema_version == LIVE_SCHEMA_VERSION

    @property
    def settlement_stages(self) -> SettlementStageCutoffsV1 | None:
        if not self.has_absolute_deadline:
            return None
        if (
            self.actor_done_monotonic_ns is None
            or self.tool_settled_monotonic_ns is None
            or self.process_settlement_reserve_ms is None
        ):
            raise BridgeError("external_request_settlement_budget_invalid")
        return SettlementStageCutoffsV1.derive(
            actor_done_monotonic_ns=self.actor_done_monotonic_ns,
            tool_settled_monotonic_ns=self.tool_settled_monotonic_ns,
            process_settlement_reserve_ms=self.process_settlement_reserve_ms,
        )


@dataclass(frozen=True)
class MediaPayload:
    logical_path: str
    mime_type: str
    width: int
    height: int
    source_byte_length: int
    source_sha256: str
    canonical_byte_length: int
    canonical_sha256: str
    content: bytes = field(repr=False)


@dataclass(frozen=True)
class ToolExecution:
    return_code: int
    timed_out: bool
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    cleanup_attempted: bool
    term_sent: bool
    kill_sent: bool
    cleanup_verified: bool
    census_verified: bool
    survivor_count: int
    process_disposition: ProcessDisposition = ProcessDisposition.NO_PROCESS
    target_task_id: str | None = None
    effect_observation_v1: EffectObservationV1 | None = None
    media: MediaPayload | None = None
    wait_clamped: bool = False
    wait_reason: str | None = None
    background_start_observation: BackgroundStartObservation | None = None
    actor_receipt: TerminalActorReceiptV1 | None = None


@dataclass(frozen=True)
class ToolFailure:
    code: str
    execution_may_have_started: bool
    cleanup_verified: bool | None
    census_verified: bool | None
    actor_receipt: TerminalActorReceiptV1 | None = None


class ToolFatalError(BridgeError):
    """A request-bound tool failure that can be truthfully settled as fatal."""

    def __init__(self, failure: ToolFailure):
        super().__init__(failure.code)
        self.failure = failure


@dataclass(frozen=True)
class BridgeOutcome:
    request_count: int
    stderr: bytes
    closure_receipt: BridgeClosureReceiptV1 | None = None


@dataclass(frozen=True)
class BridgeClosureReceiptV1:
    """Independent local/remote closure axes emitted by the bridge owner."""

    handler_completion: HandlerCompletionStateV1
    actor_dispatch: ActorDispatchStateV1
    actor_quiescent: bool
    remote_census_verified: bool
    remote_survivor_count: int | None
    stdio_bridge_closed: bool
    runtime_child_closed: bool

    @property
    def process_safe(self) -> bool:
        return (
            self.actor_dispatch is ActorDispatchStateV1.REVOKED
            and self.actor_quiescent
            and self.remote_census_verified
            and self.remote_survivor_count == 0
            and self.stdio_bridge_closed
            and self.runtime_child_closed
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "external-bridge-closure-v2",
            "handler_completion": self.handler_completion.value,
            "actor_dispatch": self.actor_dispatch.value,
            "actor_quiescent": self.actor_quiescent,
            "remote_census_verified": self.remote_census_verified,
            "remote_survivor_count": self.remote_survivor_count,
            "stdio_bridge_closed": self.stdio_bridge_closed,
            "runtime_child_closed": self.runtime_child_closed,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> BridgeClosureReceiptV1:
        expected = {
            "schema_version",
            "handler_completion",
            "actor_dispatch",
            "actor_quiescent",
            "remote_census_verified",
            "remote_survivor_count",
            "stdio_bridge_closed",
            "runtime_child_closed",
        }
        try:
            if type(value) is not dict or set(value) != expected:
                raise ValueError
            if value["schema_version"] != "external-bridge-closure-v2":
                raise ValueError
            handler_completion = HandlerCompletionStateV1(value["handler_completion"])
            actor_dispatch = ActorDispatchStateV1(value["actor_dispatch"])
            booleans = (
                value["actor_quiescent"],
                value["remote_census_verified"],
                value["stdio_bridge_closed"],
                value["runtime_child_closed"],
            )
            if any(type(item) is not bool for item in booleans):
                raise ValueError
            survivor_count = value["remote_survivor_count"]
            if survivor_count is not None and (
                type(survivor_count) is not int or survivor_count < 0
            ):
                raise ValueError
        except (KeyError, TypeError, ValueError) as error:
            raise BridgeError("external_bridge_closure_receipt_invalid") from error
        return cls(
            handler_completion=handler_completion,
            actor_dispatch=actor_dispatch,
            actor_quiescent=value["actor_quiescent"],
            remote_census_verified=value["remote_census_verified"],
            remote_survivor_count=survivor_count,
            stdio_bridge_closed=value["stdio_bridge_closed"],
            runtime_child_closed=value["runtime_child_closed"],
        )


def _validate_live_request_binding(
    request: ToolRequest,
    receipt: RunDeadlineReceiptV1,
) -> None:
    cutoffs = receipt.cutoffs
    reserves = receipt.reserves
    expected = {
        "run_id": receipt.run_id,
        "trial_id": receipt.trial_id,
        "attempt_id": receipt.attempt_id,
        "actor_done_monotonic_ns": cutoffs.actor_done_monotonic_ns,
        "tool_settled_monotonic_ns": cutoffs.tool_settled_monotonic_ns,
        "last_send_monotonic_ns": cutoffs.last_send_monotonic_ns,
        "runtime_final_monotonic_ns": cutoffs.runtime_final_monotonic_ns,
        "cleanup_start_monotonic_ns": cutoffs.cleanup_start_monotonic_ns,
        "hard_deadline_monotonic_ns": cutoffs.hard_deadline_monotonic_ns,
        "cleanup_reserve_ms": reserves.cleanup_ms,
        "terminalization_reserve_ms": reserves.terminalization_ms,
        "provider_send_reserve_ms": reserves.provider_send_ms,
        "process_settlement_reserve_ms": reserves.process_settlement_ms,
        "deadline_receipt_sha256": receipt.sha256(),
    }
    if request.schema_version != LIVE_SCHEMA_VERSION or any(
        getattr(request, field) != value for field, value in expected.items()
    ):
        raise BridgeError("external_request_deadline_binding_invalid")


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise BridgeError("external_request_duplicate_field")
        value[key] = item
    return value


def _strict_json_object(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_no_duplicate_object,
            parse_constant=lambda _: (_ for _ in ()).throw(
                BridgeError("external_request_nonfinite_number")
            ),
        )
    except BridgeError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BridgeError("external_request_invalid_json") from error
    if not isinstance(value, dict):
        raise BridgeError("external_request_not_object")
    return value


def _require_exact_keys(
    value: Mapping[str, Any], expected: set[str], code: str
) -> None:
    if set(value) != expected:
        raise BridgeError(code)


def _require_text(value: object, code: str, *, max_bytes: int = 256) -> str:
    if not isinstance(value, str):
        raise BridgeError(code)
    encoded = value.encode("utf-8")
    if not encoded or len(encoded) > max_bytes or any(ord(char) < 32 for char in value):
        raise BridgeError(code)
    return value


def _require_positive_int(value: object, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise BridgeError(code)
    if value > 2**63 - 1:
        raise BridgeError(code)
    return value


def _require_positive_u64(value: object, code: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 < value <= U64_MAX
    ):
        raise BridgeError(code)
    return value


def parse_tool_request(
    raw: bytes,
    *,
    allow_legacy_v2: bool = True,
) -> ToolRequest:
    """Parse one LF-free request and reject every protocol ambiguity."""

    if not raw or len(raw) > MAX_REQUEST_LINE_BYTES or b"\n" in raw or b"\r" in raw:
        raise BridgeError("external_request_framing_invalid")
    value = _strict_json_object(raw)
    schema_version = value.get("schema_version")
    if schema_version == LIVE_SCHEMA_VERSION:
        _require_exact_keys(
            value,
            _LIVE_REQUEST_KEYS,
            "external_request_fields_invalid",
        )
    elif schema_version == LEGACY_SCHEMA_VERSION and allow_legacy_v2:
        _require_exact_keys(value, _REQUEST_KEYS, "external_request_fields_invalid")
    else:
        raise BridgeError("external_request_schema_mismatch")
    if value["message_type"] != "tool.request":
        raise BridgeError("external_request_type_mismatch")
    tool_name = value["tool_name"]
    if not isinstance(tool_name, str) or tool_name not in TOOL_NAMES:
        raise BridgeError("external_request_tool_mismatch")
    seq = value["seq"]
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise BridgeError("external_request_sequence_invalid")
    environment = value["environment"]
    if not isinstance(environment, dict):
        raise BridgeError("external_request_environment_invalid")
    _require_exact_keys(
        environment,
        {"clear", "inherit_remote"},
        "external_request_environment_invalid",
    )
    if environment["clear"] is not True or environment["inherit_remote"] != list(
        REMOTE_ENVIRONMENT_ALLOWLIST
    ):
        raise BridgeError("external_request_environment_invalid")
    limits = value["limits"]
    if not isinstance(limits, dict):
        raise BridgeError("external_request_limits_invalid")
    if set(limits) not in {
        frozenset(_LIMIT_KEYS),
        frozenset(_LIMIT_KEYS | _OPTIONAL_LIMIT_KEYS),
    }:
        raise BridgeError("external_request_limits_invalid")
    parsed_limits = {
        key: _require_positive_int(
            limits[key],
            "external_request_limits_invalid",
        )
        for key in _LIMIT_KEYS
    }
    read_file_media_enabled = limits.get("read_file_media_enabled", False)
    if not isinstance(read_file_media_enabled, bool):
        raise BridgeError("external_request_limits_invalid")
    arguments_json = value["arguments_json"]
    if not isinstance(arguments_json, str) or not arguments_json:
        raise BridgeError("external_request_arguments_invalid")
    if len(arguments_json.encode("utf-8")) > parsed_limits["arguments_cap_bytes"]:
        raise BridgeError("external_request_arguments_invalid")
    arguments = _strict_json_object(arguments_json.encode("utf-8"))
    logical_cwd = value["logical_cwd"]
    if not isinstance(logical_cwd, str) or not logical_cwd.startswith("/"):
        raise BridgeError("external_request_cwd_invalid")
    path = PurePosixPath(logical_cwd)
    if str(path) != logical_cwd or any(part in {".", ".."} for part in path.parts):
        raise BridgeError("external_request_cwd_invalid")
    deadline_values: dict[str, int | str | None] = {
        key: None for key in _LIVE_DEADLINE_KEYS
    }
    if schema_version == LIVE_SCHEMA_VERSION:
        for key in _LIVE_DEADLINE_KEYS - {"deadline_receipt_sha256"}:
            deadline_values[key] = _require_positive_u64(
                value[key],
                "external_request_deadline_invalid",
            )
        receipt_sha256 = value["deadline_receipt_sha256"]
        if not _valid_sha256(receipt_sha256):
            raise BridgeError("external_request_deadline_invalid")
        deadline_values["deadline_receipt_sha256"] = receipt_sha256
        actor_done = deadline_values["actor_done_monotonic_ns"]
        tool_settled = deadline_values["tool_settled_monotonic_ns"]
        last_send = deadline_values["last_send_monotonic_ns"]
        runtime_final = deadline_values["runtime_final_monotonic_ns"]
        cleanup_start = deadline_values["cleanup_start_monotonic_ns"]
        hard = deadline_values["hard_deadline_monotonic_ns"]
        cleanup_ms = deadline_values["cleanup_reserve_ms"]
        terminalization_ms = deadline_values["terminalization_reserve_ms"]
        provider_send_ms = deadline_values["provider_send_reserve_ms"]
        settlement_ms = deadline_values["process_settlement_reserve_ms"]
        if (
            cleanup_ms != 20_000
            or terminalization_ms != 15_000
            or provider_send_ms != 30_000
            or settlement_ms != 10_000
            or not all(
                isinstance(item, int)
                for item in (
                    actor_done,
                    tool_settled,
                    last_send,
                    runtime_final,
                    cleanup_start,
                    hard,
                )
            )
            or last_send != runtime_final
            or hard - cleanup_start != cleanup_ms * 1_000_000
            or cleanup_start - runtime_final != terminalization_ms * 1_000_000
            or last_send - tool_settled != provider_send_ms * 1_000_000
            or tool_settled - actor_done != settlement_ms * 1_000_000
        ):
            raise BridgeError("external_request_deadline_invalid")
        SettlementStageCutoffsV1.derive(
            actor_done_monotonic_ns=actor_done,
            tool_settled_monotonic_ns=tool_settled,
            process_settlement_reserve_ms=settlement_ms,
        )
    timeout_key = (
        "operation_timeout_ms"
        if schema_version == LIVE_SCHEMA_VERSION
        else "timeout_ms"
    )
    return ToolRequest(
        raw_json=raw,
        seq=seq,
        run_id=_require_text(value["run_id"], "external_request_identity_invalid"),
        trial_id=_require_text(value["trial_id"], "external_request_identity_invalid"),
        attempt_id=_require_text(
            value["attempt_id"], "external_request_identity_invalid"
        ),
        call_id=_require_text(value["call_id"], "external_request_identity_invalid"),
        tool_name=tool_name,
        arguments_json=arguments_json,
        arguments=arguments,
        logical_cwd=logical_cwd,
        timeout_ms=_require_positive_int(
            value[timeout_key], "external_request_timeout_invalid"
        ),
        term_grace_ms=_require_positive_int(
            value["term_grace_ms"], "external_request_timeout_invalid"
        ),
        kill_confirmation_timeout_ms=_require_positive_int(
            value["kill_confirmation_timeout_ms"],
            "external_request_timeout_invalid",
        ),
        stdout_cap_bytes=_require_positive_int(
            value["stdout_cap_bytes"], "external_request_cap_invalid"
        ),
        stderr_cap_bytes=_require_positive_int(
            value["stderr_cap_bytes"], "external_request_cap_invalid"
        ),
        arguments_cap_bytes=parsed_limits["arguments_cap_bytes"],
        max_path_bytes=parsed_limits["max_path_bytes"],
        max_read_or_write_bytes=parsed_limits["max_read_or_write_bytes"],
        max_directory_entries=parsed_limits["max_directory_entries"],
        max_grep_matches=parsed_limits["max_grep_matches"],
        max_replacements=parsed_limits["max_replacements"],
        max_background_processes=parsed_limits["max_background_processes"],
        process_spool_bytes_per_process=parsed_limits[
            "process_spool_bytes_per_process"
        ],
        process_spool_bytes_per_run=parsed_limits["process_spool_bytes_per_run"],
        background_output_wait_max_ms=parsed_limits["background_output_wait_max_ms"],
        read_file_media_enabled=read_file_media_enabled,
        schema_version=schema_version,
        actor_done_monotonic_ns=deadline_values["actor_done_monotonic_ns"],
        tool_settled_monotonic_ns=deadline_values["tool_settled_monotonic_ns"],
        last_send_monotonic_ns=deadline_values["last_send_monotonic_ns"],
        runtime_final_monotonic_ns=deadline_values["runtime_final_monotonic_ns"],
        cleanup_start_monotonic_ns=deadline_values["cleanup_start_monotonic_ns"],
        hard_deadline_monotonic_ns=deadline_values["hard_deadline_monotonic_ns"],
        cleanup_reserve_ms=deadline_values["cleanup_reserve_ms"],
        terminalization_reserve_ms=deadline_values["terminalization_reserve_ms"],
        provider_send_reserve_ms=deadline_values["provider_send_reserve_ms"],
        process_settlement_reserve_ms=deadline_values["process_settlement_reserve_ms"],
        deadline_receipt_sha256=deadline_values["deadline_receipt_sha256"],
    )


def _is_background_start_request(request: ToolRequest) -> bool:
    return (
        request.tool_name == "run_terminal_command"
        and request.arguments.get("background", False) is True
    )


def _is_foreground_terminal_request(request: ToolRequest) -> bool:
    return (
        request.tool_name == "run_terminal_command"
        and request.arguments.get("background", False) is False
    )


_RECOVERY_RECEIPT_SUBTYPES = {
    TerminalActorSubtypeV1.RECOVERED_SETTLED,
    TerminalActorSubtypeV1.RECOVERY_DOWNLOAD_FAILED,
    TerminalActorSubtypeV1.META_INVALID,
    TerminalActorSubtypeV1.OUTPUT_DOWNLOAD_FAILED,
    TerminalActorSubtypeV1.OUTPUT_LIMIT_EXCEEDED,
    TerminalActorSubtypeV1.CLEANUP_UNVERIFIED,
    TerminalActorSubtypeV1.ACTOR_DEADLINE_EXCEEDED,
}

_RECOVERY_PRIMARY_SUBTYPES = {
    TerminalActorSubtypeV1.RUN_TRANSPORT_TIMEOUT,
    TerminalActorSubtypeV1.RUN_TRANSPORT_FAILED,
    TerminalActorSubtypeV1.RUN_RESPONSE_NONZERO,
}

_PRIMARY_RECEIPT_RULES = {
    TerminalActorSubtypeV1.COMPLETED: (
        {TerminalActorPhaseV1.META_VALIDATE},
        {TerminalActorOriginV1.ACTOR},
    ),
    TerminalActorSubtypeV1.SEMANTIC_EXECUTION_TIMED_OUT: (
        {TerminalActorPhaseV1.META_VALIDATE},
        {TerminalActorOriginV1.SEMANTIC},
    ),
    TerminalActorSubtypeV1.ACTOR_DEADLINE_EXCEEDED: (
        set(TerminalActorPhaseV1),
        {TerminalActorOriginV1.ACTOR},
    ),
    TerminalActorSubtypeV1.WORKSPACE_MAPPING_CHECK_TIMEOUT: (
        {TerminalActorPhaseV1.MAPPING_PREFLIGHT},
        {TerminalActorOriginV1.TRANSPORT},
    ),
    TerminalActorSubtypeV1.WORKSPACE_MAPPING_CHANGED: (
        {TerminalActorPhaseV1.MAPPING_PREFLIGHT},
        {TerminalActorOriginV1.PROTOCOL},
    ),
    TerminalActorSubtypeV1.REQUEST_SETUP_FAILED: (
        {TerminalActorPhaseV1.REMOTE_SETUP, TerminalActorPhaseV1.CLEANUP},
        {TerminalActorOriginV1.PROTOCOL, TerminalActorOriginV1.TRANSPORT},
    ),
    TerminalActorSubtypeV1.COMMAND_UPLOAD_FAILED: (
        {TerminalActorPhaseV1.COMMAND_UPLOAD, TerminalActorPhaseV1.CLEANUP},
        {TerminalActorOriginV1.TRANSPORT},
    ),
    TerminalActorSubtypeV1.RUN_TRANSPORT_TIMEOUT: (
        {
            TerminalActorPhaseV1.RECOVERY_DOWNLOAD,
            TerminalActorPhaseV1.META_VALIDATE,
            TerminalActorPhaseV1.CLEANUP,
            TerminalActorPhaseV1.CENSUS,
        },
        {TerminalActorOriginV1.TRANSPORT},
    ),
    TerminalActorSubtypeV1.RUN_TRANSPORT_FAILED: (
        {
            TerminalActorPhaseV1.RECOVERY_DOWNLOAD,
            TerminalActorPhaseV1.META_VALIDATE,
            TerminalActorPhaseV1.CLEANUP,
            TerminalActorPhaseV1.CENSUS,
        },
        {TerminalActorOriginV1.TRANSPORT},
    ),
    TerminalActorSubtypeV1.RUN_RESPONSE_NONZERO: (
        {
            TerminalActorPhaseV1.RECOVERY_DOWNLOAD,
            TerminalActorPhaseV1.META_VALIDATE,
            TerminalActorPhaseV1.CLEANUP,
            TerminalActorPhaseV1.CENSUS,
        },
        {TerminalActorOriginV1.PROTOCOL},
    ),
    TerminalActorSubtypeV1.META_INVALID: (
        {TerminalActorPhaseV1.META_VALIDATE, TerminalActorPhaseV1.CLEANUP},
        {TerminalActorOriginV1.PROTOCOL},
    ),
    TerminalActorSubtypeV1.OUTPUT_DOWNLOAD_FAILED: (
        {TerminalActorPhaseV1.RESULT_DOWNLOAD, TerminalActorPhaseV1.CLEANUP},
        {TerminalActorOriginV1.TRANSPORT},
    ),
    TerminalActorSubtypeV1.OUTPUT_LIMIT_EXCEEDED: (
        {TerminalActorPhaseV1.META_VALIDATE, TerminalActorPhaseV1.CLEANUP},
        {TerminalActorOriginV1.PROTOCOL},
    ),
    TerminalActorSubtypeV1.CLEANUP_UNVERIFIED: (
        {TerminalActorPhaseV1.CLEANUP, TerminalActorPhaseV1.CENSUS},
        {TerminalActorOriginV1.ACTOR},
    ),
    TerminalActorSubtypeV1.CANCELLED: (
        {TerminalActorPhaseV1.CLEANUP, TerminalActorPhaseV1.ACTOR_DONE},
        {TerminalActorOriginV1.ACTOR},
    ),
    TerminalActorSubtypeV1.UNEXPECTED_FAILURE: (
        set(TerminalActorPhaseV1),
        {TerminalActorOriginV1.ACTOR},
    ),
}

_FATAL_RECOVERY_SUBTYPES = _RECOVERY_RECEIPT_SUBTYPES - {
    TerminalActorSubtypeV1.RECOVERED_SETTLED
}


def _validate_actor_receipt(
    request: ToolRequest,
    result: ToolExecution | ToolFailure,
) -> None:
    receipt = result.actor_receipt
    required = (
        request.schema_version == LIVE_SCHEMA_VERSION
        and _is_foreground_terminal_request(request)
    )
    if not required:
        if receipt is not None:
            raise BridgeError("external_response_actor_receipt_invalid")
        return
    if type(receipt) is not TerminalActorReceiptV1:
        raise BridgeError("external_response_actor_receipt_invalid")
    assert receipt is not None
    actor_done = request.actor_done_monotonic_ns
    if (
        receipt.schema_version != TERMINAL_ACTOR_RECEIPT_SCHEMA_VERSION
        or type(receipt.phase) is not TerminalActorPhaseV1
        or type(receipt.origin) is not TerminalActorOriginV1
        or type(receipt.primary_subtype) is not TerminalActorSubtypeV1
        or receipt.recovery_subtype is not None
        and type(receipt.recovery_subtype) is not TerminalActorSubtypeV1
        or not isinstance(receipt.execution_may_have_started, bool)
        or isinstance(receipt.effective_cutoff_monotonic_ns, bool)
        or not isinstance(receipt.effective_cutoff_monotonic_ns, int)
        or actor_done is None
        or not 0 < receipt.effective_cutoff_monotonic_ns <= actor_done
        or receipt.cleanup_verified is not None
        and not isinstance(receipt.cleanup_verified, bool)
        or receipt.census_verified is not None
        and not isinstance(receipt.census_verified, bool)
        or not _valid_sha256(receipt.diagnostic_digest_sha256)
    ):
        raise BridgeError("external_response_actor_receipt_invalid")
    expected = TerminalActorReceiptV1.create(
        phase=receipt.phase,
        origin=receipt.origin,
        primary_subtype=receipt.primary_subtype,
        recovery_subtype=receipt.recovery_subtype,
        execution_may_have_started=receipt.execution_may_have_started,
        effective_cutoff_monotonic_ns=receipt.effective_cutoff_monotonic_ns,
        cleanup_verified=receipt.cleanup_verified,
        census_verified=receipt.census_verified,
    )
    if expected.diagnostic_digest_sha256 != receipt.diagnostic_digest_sha256:
        raise BridgeError("external_response_actor_receipt_invalid")
    rule = _PRIMARY_RECEIPT_RULES.get(receipt.primary_subtype)
    if (
        rule is None
        or receipt.phase not in rule[0]
        or receipt.origin not in rule[1]
        or (receipt.primary_subtype in _RECOVERY_PRIMARY_SUBTYPES)
        != (receipt.recovery_subtype is not None)
        or not receipt.execution_may_have_started
        and (
            receipt.cleanup_verified is not None or receipt.census_verified is not None
        )
        or receipt.recovery_subtype is not None
        and receipt.recovery_subtype not in _RECOVERY_RECEIPT_SUBTYPES
        or receipt.phase is TerminalActorPhaseV1.RECOVERY_DOWNLOAD
        and receipt.recovery_subtype is None
        or receipt.phase is TerminalActorPhaseV1.CLEANUP
        and receipt.cleanup_verified is True
        or receipt.phase is TerminalActorPhaseV1.ACTOR_DONE
        and (
            receipt.primary_subtype
            not in {
                TerminalActorSubtypeV1.ACTOR_DEADLINE_EXCEEDED,
                TerminalActorSubtypeV1.CANCELLED,
                TerminalActorSubtypeV1.UNEXPECTED_FAILURE,
            }
            or receipt.recovery_subtype is not None
        )
    ):
        raise BridgeError("external_response_actor_receipt_invalid")
    if isinstance(result, ToolExecution):
        if (
            receipt.execution_may_have_started is not True
            or receipt.cleanup_verified is not result.cleanup_verified
            or receipt.census_verified is not result.census_verified
            or result.timed_out
            and receipt.recovery_subtype is None
            and (
                receipt.origin is not TerminalActorOriginV1.SEMANTIC
                or receipt.primary_subtype
                is not TerminalActorSubtypeV1.SEMANTIC_EXECUTION_TIMED_OUT
            )
            or not result.timed_out
            and receipt.recovery_subtype is None
            and (
                receipt.origin is not TerminalActorOriginV1.ACTOR
                or receipt.primary_subtype is not TerminalActorSubtypeV1.COMPLETED
            )
            or receipt.recovery_subtype is TerminalActorSubtypeV1.RECOVERED_SETTLED
            and (
                receipt.primary_subtype not in _RECOVERY_PRIMARY_SUBTYPES
                or receipt.phase is not TerminalActorPhaseV1.META_VALIDATE
                or receipt.execution_may_have_started is not True
                or receipt.cleanup_verified is not True
                or receipt.census_verified is not True
            )
            or receipt.recovery_subtype is not None
            and receipt.recovery_subtype is not TerminalActorSubtypeV1.RECOVERED_SETTLED
        ):
            raise BridgeError("external_response_actor_receipt_invalid")
    else:
        if (
            receipt.execution_may_have_started is not result.execution_may_have_started
            or receipt.cleanup_verified is not result.cleanup_verified
            or receipt.census_verified is not result.census_verified
            or receipt.recovery_subtype is TerminalActorSubtypeV1.RECOVERED_SETTLED
            or receipt.recovery_subtype is not None
            and receipt.recovery_subtype not in _FATAL_RECOVERY_SUBTYPES
            or receipt.primary_subtype
            in {
                TerminalActorSubtypeV1.COMPLETED,
                TerminalActorSubtypeV1.SEMANTIC_EXECUTION_TIMED_OUT,
            }
        ):
            raise BridgeError("external_response_actor_receipt_invalid")


def _encoded_actor_receipt(
    receipt: TerminalActorReceiptV1 | None,
) -> dict[str, object] | None:
    return None if receipt is None else receipt.as_dict()


def _fallback_actor_receipt(
    request: ToolRequest,
    *,
    execution_may_have_started: bool = True,
    effective_cutoff_monotonic_ns: int | None = None,
    cleanup_verified: bool | None,
    census_verified: bool | None,
    existing: TerminalActorReceiptV1 | None = None,
) -> TerminalActorReceiptV1 | None:
    if (
        request.schema_version != LIVE_SCHEMA_VERSION
        or not _is_foreground_terminal_request(request)
    ):
        return None
    if type(existing) is TerminalActorReceiptV1:
        return existing.with_containment(
            cleanup_verified=cleanup_verified,
            census_verified=census_verified,
        )
    actor_done = request.actor_done_monotonic_ns
    if actor_done is None:
        return None
    cutoff_ns = (
        effective_cutoff_monotonic_ns
        if (
            not isinstance(effective_cutoff_monotonic_ns, bool)
            and isinstance(effective_cutoff_monotonic_ns, int)
            and 0 < effective_cutoff_monotonic_ns <= actor_done
        )
        else actor_done
    )
    return TerminalActorReceiptV1.create(
        phase=TerminalActorPhaseV1.ACTOR_DONE,
        origin=TerminalActorOriginV1.ACTOR,
        primary_subtype=TerminalActorSubtypeV1.UNEXPECTED_FAILURE,
        recovery_subtype=None,
        execution_may_have_started=execution_may_have_started,
        effective_cutoff_monotonic_ns=cutoff_ns,
        cleanup_verified=cleanup_verified,
        census_verified=census_verified,
    )


def _tool_settlement_deadline_failure(request: ToolRequest) -> ToolFailure:
    """Encode the root-owned deadline before EOF becomes observable."""

    receipt = None
    if (
        request.schema_version == LIVE_SCHEMA_VERSION
        and _is_foreground_terminal_request(request)
    ):
        actor_done = request.actor_done_monotonic_ns
        assert actor_done is not None
        receipt = TerminalActorReceiptV1.create(
            phase=TerminalActorPhaseV1.ACTOR_DONE,
            origin=TerminalActorOriginV1.ACTOR,
            primary_subtype=TerminalActorSubtypeV1.ACTOR_DEADLINE_EXCEEDED,
            recovery_subtype=None,
            execution_may_have_started=True,
            effective_cutoff_monotonic_ns=actor_done,
            cleanup_verified=None,
            census_verified=None,
        )
    return ToolFailure(
        code="tool_settlement_deadline_exceeded",
        execution_may_have_started=True,
        cleanup_verified=None,
        census_verified=None,
        actor_receipt=receipt,
    )


def _fallback_serialization_failure(
    request: ToolRequest,
    result: ToolExecution | ToolFailure,
    *,
    code: str,
) -> ToolFailure:
    """Convert a local response-encoding failure into one valid fatal frame."""

    was_failure = isinstance(result, ToolFailure)
    execution_may_have_started = (
        result.execution_may_have_started if was_failure else True
    )
    existing = (
        result.actor_receipt
        if was_failure and code != "external_response_actor_receipt_invalid"
        else None
    )
    receipt = result.actor_receipt
    return ToolFailure(
        code=code if _valid_failure_code(code) else "response_serialization_failure",
        execution_may_have_started=execution_may_have_started,
        cleanup_verified=result.cleanup_verified,
        census_verified=result.census_verified,
        actor_receipt=_fallback_actor_receipt(
            request,
            execution_may_have_started=execution_may_have_started,
            effective_cutoff_monotonic_ns=(
                receipt.effective_cutoff_monotonic_ns
                if type(receipt) is TerminalActorReceiptV1
                else None
            ),
            cleanup_verified=result.cleanup_verified,
            census_verified=result.census_verified,
            existing=existing,
        ),
    )


def _valid_background_start_observation(
    request: ToolRequest,
    result: ToolExecution,
) -> bool:
    observation = result.background_start_observation
    if (
        type(observation) is not BackgroundStartObservation
        or observation.proof_version != BACKGROUND_START_PROOF_VERSION
        or type(observation.kind) is not BackgroundStartKind
        or observation.task_id_published is not False
        or not _is_background_start_request(request)
        or result.process_disposition is not ProcessDisposition.NO_PROCESS
        or result.target_task_id is not None
        or result.timed_out
        or not result.cleanup_verified
        or not result.census_verified
        or result.survivor_count != 0
        or result.term_sent
        or result.kill_sent
    ):
        return False
    child_exit_code = observation.child_exit_code
    if observation.kind is BackgroundStartKind.NOT_STARTED:
        return (
            child_exit_code is None
            and result.return_code == 2
            and not result.cleanup_attempted
        )
    if observation.kind is BackgroundStartKind.QUICK_EXIT:
        return (
            type(child_exit_code) is int
            and -(2**31) <= child_exit_code <= 2**31 - 1
            and result.return_code == (0 if child_exit_code == 0 else 2)
            and result.cleanup_attempted
        )
    return False


def _validate_process_result(request: ToolRequest, result: ToolExecution) -> None:
    target_ok = (
        isinstance(result.target_task_id, str)
        and 0 < len(result.target_task_id.encode("utf-8")) <= 256
        and all(ord(char) >= 32 for char in result.target_task_id)
    )
    common_verified = result.cleanup_verified and result.census_verified
    live_background_no_process = (
        request.schema_version == LIVE_SCHEMA_VERSION
        and _is_background_start_request(request)
        and result.process_disposition is ProcessDisposition.NO_PROCESS
    )
    observation_valid = _valid_background_start_observation(request, result)
    if result.process_disposition is ProcessDisposition.NO_PROCESS:
        if live_background_no_process:
            mode_valid = observation_valid
        elif _is_background_start_request(request):
            mode_valid = (
                request.schema_version == LEGACY_SCHEMA_VERSION
                and result.background_start_observation is None
                and result.return_code == 2
            )
        else:
            mode_valid = (
                not _is_foreground_terminal_request(request)
                and result.background_start_observation is None
            )
        valid = (
            result.target_task_id is None
            and common_verified
            and result.survivor_count == 0
            and mode_valid
        )
    elif result.process_disposition is ProcessDisposition.FOREGROUND_CLEANED:
        valid = (
            _is_foreground_terminal_request(request)
            and result.target_task_id is None
            and result.cleanup_attempted
            and common_verified
            and result.survivor_count == 0
        )
    elif result.process_disposition is ProcessDisposition.BACKGROUND_RETAINED:
        valid = (
            _is_background_start_request(request)
            and target_ok
            and not result.cleanup_attempted
            and common_verified
            and result.survivor_count > 0
        )
    elif result.process_disposition is ProcessDisposition.BACKGROUND_TERMINATED:
        valid = (
            request.tool_name == "kill_terminal_command"
            and target_ok
            and result.cleanup_attempted
            and common_verified
            and result.survivor_count == 0
        )
    else:  # pragma: no cover - frozen enum, defensive against untyped callers
        valid = False
    if (
        result.background_start_observation is not None
        and not live_background_no_process
    ):
        valid = False
    if not valid:
        raise BridgeError("external_response_process_invalid")


def _valid_failure_code(value: str) -> bool:
    return 0 < len(value.encode("utf-8")) <= 128 and all(
        char.isascii() and (char.islower() or char.isdigit() or char in "_.-")
        for char in value
    )


def _valid_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))


def _validate_media(request: ToolRequest, result: ToolExecution) -> None:
    media = result.media
    if media is None:
        return
    path = PurePosixPath(media.logical_path)
    mime_magic = {
        "image/png": b"\x89PNG\r\n\x1a\n",
        "image/jpeg": b"\xff\xd8\xff",
    }
    valid = (
        request.read_file_media_enabled
        and request.tool_name == "read_file"
        and result.return_code == 0
        and not result.timed_out
        and not result.stderr
        and not result.stdout_truncated
        and not result.stderr_truncated
        and result.process_disposition is ProcessDisposition.NO_PROCESS
        and isinstance(media.logical_path, str)
        and bool(media.logical_path)
        and not media.logical_path.startswith("/")
        and str(path) == media.logical_path
        and all(part not in {"", ".", ".."} for part in path.parts)
        and len(media.logical_path.encode("utf-8")) <= 4096
        and all(ord(char) >= 32 for char in media.logical_path)
        and media.mime_type in mime_magic
        and isinstance(media.width, int)
        and not isinstance(media.width, bool)
        and 0 < media.width <= READ_FILE_MEDIA_MAX_DIMENSION
        and isinstance(media.height, int)
        and not isinstance(media.height, bool)
        and 0 < media.height <= READ_FILE_MEDIA_MAX_DIMENSION
        and media.width * media.height <= READ_FILE_MEDIA_MAX_PIXELS
        and isinstance(media.source_byte_length, int)
        and not isinstance(media.source_byte_length, bool)
        and 0 < media.source_byte_length <= READ_FILE_MEDIA_MAX_BYTES
        and isinstance(media.canonical_byte_length, int)
        and not isinstance(media.canonical_byte_length, bool)
        and media.canonical_byte_length == len(media.content)
        and media.canonical_byte_length <= READ_FILE_MEDIA_MAX_BYTES
        and _valid_sha256(media.source_sha256)
        and _valid_sha256(media.canonical_sha256)
        and hashlib.sha256(media.content).hexdigest() == media.canonical_sha256
        and media.content.startswith(mime_magic.get(media.mime_type, b"\x00"))
    )
    if not valid:
        raise BridgeError("external_response_media_invalid")


def encode_tool_response(
    request: ToolRequest,
    result: ToolExecution | ToolFailure,
) -> bytes:
    """Encode a response whose identity and request bytes are fully bound."""

    response = {
        "schema_version": request.schema_version,
        "message_type": "tool.response",
        "seq": request.seq,
        "run_id": request.run_id,
        "trial_id": request.trial_id,
        "attempt_id": request.attempt_id,
        "call_id": request.call_id,
        "tool_name": request.tool_name,
        "request_sha256": request.request_sha256,
    }
    if isinstance(result, ToolFailure):
        if (
            not _valid_failure_code(result.code)
            or not isinstance(result.execution_may_have_started, bool)
            or result.cleanup_verified is not None
            and not isinstance(result.cleanup_verified, bool)
            or result.census_verified is not None
            and not isinstance(result.census_verified, bool)
        ):
            raise BridgeError("external_response_failure_invalid")
        _validate_actor_receipt(request, result)
        failure_value: dict[str, object] = {
            "code": result.code,
            "execution_may_have_started": result.execution_may_have_started,
            "cleanup_verified": result.cleanup_verified,
            "census_verified": result.census_verified,
            "recoverability": "fatal",
        }
        if request.schema_version == LIVE_SCHEMA_VERSION:
            failure_value["actor_receipt"] = _encoded_actor_receipt(
                result.actor_receipt
            )
        response.update(
            {
                "settlement": "fatal",
                "failure": failure_value,
            }
        )
        return json.dumps(
            response,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

    if not -(2**31) <= result.return_code <= 2**31 - 1:
        raise BridgeError("external_response_return_code_invalid")
    if (
        not isinstance(result.wait_clamped, bool)
        or result.wait_reason not in {None, "runtime_budget"}
        or (result.wait_reason is None) != (not result.wait_clamped)
    ):
        raise BridgeError("external_response_wait_invalid")
    if (
        len(result.stdout) > request.stdout_cap_bytes
        or len(result.stderr) > request.stderr_cap_bytes
        or result.survivor_count < 0
    ):
        raise BridgeError("external_response_bounds_invalid")
    _validate_process_result(request, result)
    _validate_actor_receipt(request, result)
    _validate_media(request, result)
    if result.effect_observation_v1 is not None and not (
        isinstance(result.effect_observation_v1, EffectObservationV1)
        and isinstance(
            result.effect_observation_v1.status,
            EffectObservationStatusV1,
        )
    ):
        raise BridgeError("external_response_effect_observation_invalid")
    media = None
    if result.media is not None:
        media = {
            "logical_path": result.media.logical_path,
            "mime_type": result.media.mime_type,
            "width": result.media.width,
            "height": result.media.height,
            "source_byte_length": result.media.source_byte_length,
            "source_sha256": result.media.source_sha256,
            "canonical_byte_length": result.media.canonical_byte_length,
            "canonical_sha256": result.media.canonical_sha256,
            "content_base64": base64.b64encode(result.media.content).decode("ascii"),
        }
    result_value = {
        "return_code": result.return_code,
        "timed_out": result.timed_out,
        "stdout_base64": base64.b64encode(result.stdout).decode("ascii"),
        "stderr_base64": base64.b64encode(result.stderr).decode("ascii"),
        "stdout_truncated": result.stdout_truncated,
        "stderr_truncated": result.stderr_truncated,
        "process_disposition": result.process_disposition.value,
        "target_task_id": result.target_task_id,
        "cleanup": {
            "attempted": result.cleanup_attempted,
            "term_sent": result.term_sent,
            "kill_sent": result.kill_sent,
            "verified": result.cleanup_verified,
        },
        "census": {
            "verified": result.census_verified,
            "owned_processes_alive": result.survivor_count,
        },
        "media": media,
    }
    if request.schema_version == LIVE_SCHEMA_VERSION:
        background_start_observation = result.background_start_observation
        result_value.update(
            {
                "wait_clamped": result.wait_clamped,
                "wait_reason": result.wait_reason,
                "effect_observation_v1": (
                    None
                    if result.effect_observation_v1 is None
                    else {"status": result.effect_observation_v1.status.value}
                ),
                "background_start_observation": (
                    None
                    if background_start_observation is None
                    else {
                        "proof_version": background_start_observation.proof_version,
                        "kind": background_start_observation.kind.value,
                        "task_id_published": (
                            background_start_observation.task_id_published
                        ),
                        "child_exit_code": (
                            background_start_observation.child_exit_code
                        ),
                    }
                ),
                "actor_receipt": _encoded_actor_receipt(result.actor_receipt),
            }
        )
    response.update({"settlement": "completed", "result": result_value})
    return json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )


def _preflight_response_serialization(
    request: ToolRequest,
    result: ToolExecution | ToolFailure,
) -> None:
    """Reject an oversized synchronous encode before allocating its base64 payload."""

    _validate_actor_receipt(request, result)
    if isinstance(result, ToolFailure):
        encoded_upper_bound = RESPONSE_PROTOCOL_OVERHEAD_BYTES
    else:
        encoded_upper_bound = (
            _base64_encoded_len(len(result.stdout))
            + _base64_encoded_len(len(result.stderr))
            + RESPONSE_PROTOCOL_OVERHEAD_BYTES
        )
        if result.media is not None:
            encoded_upper_bound += _base64_encoded_len(len(result.media.content))
    if encoded_upper_bound > _response_line_limit_bytes(request):
        raise BridgeError("response_serialization_size_limit_exceeded")


def _base64_encoded_len(byte_length: int) -> int:
    return ((byte_length + 2) // 3) * 4


def _response_line_limit_bytes(request: ToolRequest) -> int:
    """Mirror the Rust reader's signed, per-request response-line envelope."""

    encoded_media = (
        _base64_encoded_len(READ_FILE_MEDIA_MAX_BYTES)
        if request.read_file_media_enabled
        else 0
    )
    return (
        _base64_encoded_len(request.stdout_cap_bytes)
        + _base64_encoded_len(request.stderr_cap_bytes)
        + encoded_media
        + RESPONSE_PROTOCOL_OVERHEAD_BYTES
    )


async def _bounded_stderr(reader: asyncio.StreamReader) -> bytes:
    captured = bytearray()
    while chunk := await reader.read(8192):
        remaining = MAX_STDERR_BYTES - len(captured)
        if remaining > 0:
            captured.extend(chunk[:remaining])
    return bytes(captured)


async def _stop_child(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    try:
        process.terminate()
    except ProcessLookupError:
        await process.wait()
        return
    try:
        await asyncio.wait_for(process.wait(), timeout=2)
    except TimeoutError:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.wait()


async def _allow_publication_then_stop_child(
    process: asyncio.subprocess.Process,
    *,
    publication_timeout_sec: float,
) -> None:
    """Give the runtime its terminal-publication window before termination."""

    if process.returncode is not None:
        return
    if publication_timeout_sec > 0:
        try:
            await asyncio.wait_for(
                process.wait(),
                timeout=publication_timeout_sec,
            )
            return
        except TimeoutError:
            pass
    await _stop_child(process)


async def _cancel_execution(task: asyncio.Task[Any]) -> bool:
    # Actor-done already issued the revocation cancel.  Re-cancelling while the
    # trusted handler is performing its signed containment tail interrupts that
    # very proof and recreates the cleanup race this join is meant to close.
    if task.cancelling() == 0:
        task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    return task.done()


async def _complete_shielded(
    awaitable: Awaitable[Any],
    *,
    timeout_sec: float = 5.0,
    reserve_cancellation: bool = True,
) -> tuple[bool, Any, asyncio.CancelledError | None]:
    """Finish owned cleanup within a hard bound, preserving caller cancellation."""

    task = asyncio.ensure_future(awaitable)
    cancellation: asyncio.CancelledError | None = None
    loop = asyncio.get_running_loop()
    total_timeout_sec = max(0.0, timeout_sec)
    deadline = loop.time() + total_timeout_sec
    cancellation_reserve_sec = (
        min(0.05, total_timeout_sec * 0.25) if reserve_cancellation else 0.0
    )
    action_deadline = deadline - cancellation_reserve_sec

    def consume_completion(completed: asyncio.Future[Any]) -> None:
        try:
            completed.exception()
        except asyncio.CancelledError:
            pass

    async def cancel_with_hard_bound() -> None:
        # asyncio.wait_for waits for cancellation settlement and therefore is
        # not itself a hard bound when a coroutine swallows CancelledError. The
        # cancellation slice is reserved inside the caller's total deadline.
        # At the deadline only issue a final cancel and detach; never await
        # beyond the root.
        try:
            while not task.done():
                task.cancel()
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                await asyncio.wait(
                    {task},
                    timeout=min(0.001, remaining),
                )
        finally:
            if not task.done():
                task.cancel()
            if task.done():
                consume_completion(task)
            else:
                task.add_done_callback(consume_completion)

    while not task.done():
        remaining = action_deadline - loop.time()
        if remaining <= 0:
            await cancel_with_hard_bound()
            return False, None, cancellation
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=remaining)
        except TimeoutError:
            await cancel_with_hard_bound()
            return False, None, cancellation
        except asyncio.CancelledError as error:
            cancellation = error
        except BaseException:
            break
    if not task.done():
        return False, None, cancellation
    try:
        return True, task.result(), cancellation
    except BaseException:
        return False, None, cancellation


async def run_stdio_bridge(
    command: Sequence[str],
    handler: ToolHandler,
    *,
    task_image: str | None = None,
    trial_family: str | None = None,
    deadline_sec: float | None = None,
    deadline_receipt: RunDeadlineReceiptV1 | None = None,
    monotonic_ns: Callable[[], int] = host_monotonic_ns,
    spawn: Callable[..., Awaitable[asyncio.subprocess.Process]] | None = None,
) -> BridgeOutcome:
    """Run one host child, forwarding only typed tool requests to ``handler``."""

    legacy = deadline_receipt is None
    if (
        not command
        or legacy
        and (
            isinstance(deadline_sec, bool)
            or not isinstance(deadline_sec, int | float)
            or deadline_sec <= 0
        )
        or not legacy
        and deadline_sec is not None
    ):
        raise BridgeError("external_bridge_configuration_invalid")
    if deadline_receipt is not None:
        now_ns = monotonic_ns()
        if (
            isinstance(now_ns, bool)
            or not isinstance(now_ns, int)
            or now_ns >= deadline_receipt.cutoffs.actor_done_monotonic_ns
        ):
            raise BridgeError("deadline_before_dispatch")
    create = spawn or asyncio.create_subprocess_exec
    process = await create(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        limit=MAX_REQUEST_LINE_BYTES + 1,
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        await _stop_child(process)
        raise BridgeError("external_bridge_pipe_missing")
    stderr_task = asyncio.create_task(_bounded_stderr(process.stderr))
    loop = asyncio.get_running_loop()
    if legacy:
        assert deadline_sec is not None
        deadline = loop.time() + deadline_sec
        settlement_reserve = min(1.0, max(0.05, deadline_sec * 0.01))
        operation_deadline = deadline - settlement_reserve
    else:
        assert deadline_receipt is not None
        deadline = None
        operation_deadline = None

    def remaining_to(cutoff_ns: int, *, floor: float = 0.0) -> float:
        return max(floor, _strict_remaining_sec(cutoff_ns, monotonic_ns()))

    def read_remaining() -> float:
        if legacy:
            assert operation_deadline is not None
            return operation_deadline - loop.time()
        assert deadline_receipt is not None
        return remaining_to(deadline_receipt.cutoffs.cleanup_start_monotonic_ns)

    def hard_remaining() -> float:
        if legacy:
            assert deadline is not None
            return max(0.0, deadline - loop.time())
        assert deadline_receipt is not None
        return remaining_to(deadline_receipt.cutoffs.hard_deadline_monotonic_ns)

    expected_seq = 0
    fatal_sent = False
    execution_task: asyncio.Task[ToolExecution | ToolFailure] | None = None
    active_request: ToolRequest | None = None
    terminal_control_error: BridgeError | None = None
    try:
        while True:
            remaining = read_remaining()
            if remaining <= 0:
                raise BridgeError(
                    "runtime_publication_deadline_exceeded"
                    if not legacy
                    else "external_bridge_deadline_exceeded"
                )
            try:
                line = await asyncio.wait_for(process.stdout.readline(), remaining)
            except (TimeoutError, ValueError) as error:
                raise BridgeError(
                    "runtime_publication_deadline_exceeded"
                    if not legacy
                    else "external_bridge_read_failed"
                ) from error
            if not line:
                break
            if fatal_sent:
                raise BridgeError("external_request_after_fatal")
            if len(line) > MAX_REQUEST_LINE_BYTES or not line.endswith(b"\n"):
                raise BridgeError("external_request_framing_invalid")
            request = parse_tool_request(
                line[:-1],
                allow_legacy_v2=legacy,
            )
            if deadline_receipt is not None:
                _validate_live_request_binding(request, deadline_receipt)
            if request.seq != expected_seq:
                raise BridgeError("external_request_sequence_mismatch")
            if request.has_absolute_deadline:
                stages = request.settlement_stages
                assert stages is not None
                request_cutoff_ns = (
                    stages.output_monotonic_ns
                    if request.tool_name == "get_terminal_command_output"
                    else request.actor_done_monotonic_ns
                )
                assert request_cutoff_ns is not None
                remaining = remaining_to(request_cutoff_ns)
            else:
                assert operation_deadline is not None
                remaining = operation_deadline - loop.time()
            if remaining <= 0:
                raise BridgeError(
                    "deadline_before_dispatch"
                    if request.has_absolute_deadline
                    else "external_bridge_handler_deadline_exceeded"
                )
            active_request = request
            execution_task = asyncio.create_task(handler.execute(request))
            done, _ = await asyncio.wait(
                {execution_task},
                timeout=remaining,
            )
            if not done:
                execution_task.cancel()
                if not request.has_absolute_deadline:
                    await asyncio.gather(execution_task, return_exceptions=True)
                    raise BridgeError("external_bridge_handler_deadline_exceeded")
                result = _tool_settlement_deadline_failure(request)
                terminal_control_error = BridgeError(
                    "tool_settlement_deadline_exceeded"
                )
            else:
                try:
                    result = execution_task.result()
                except asyncio.CancelledError:
                    raise
                except ToolFatalError as error:
                    result = error.failure
                except BridgeError as error:
                    code = str(error)
                    result = ToolFailure(
                        code=(
                            code
                            if _valid_failure_code(code)
                            else "terminal_actor_failure"
                        ),
                        execution_may_have_started=True,
                        cleanup_verified=None,
                        census_verified=None,
                        actor_receipt=_fallback_actor_receipt(
                            request,
                            cleanup_verified=None,
                            census_verified=None,
                        ),
                    )
                except Exception:
                    result = ToolFailure(
                        code="terminal_actor_unexpected_failure",
                        execution_may_have_started=True,
                        cleanup_verified=None,
                        census_verified=None,
                        actor_receipt=_fallback_actor_receipt(
                            request,
                            cleanup_verified=None,
                            census_verified=None,
                        ),
                    )
                execution_task = None
                active_request = None
            try:
                if request.has_absolute_deadline:
                    stages = request.settlement_stages
                    assert stages is not None
                    if remaining_to(stages.encode_monotonic_ns) <= 0:
                        raise BridgeError("response_serialization_deadline_exceeded")
                    _preflight_response_serialization(request, result)
                response = encode_tool_response(request, result)
            except BridgeError as error:
                code = str(error)
                if (
                    not request.has_absolute_deadline
                    or code == "response_serialization_deadline_exceeded"
                ):
                    raise
                # A pre-encode bridge failure still has encode/drain budget.
                # Settle it as a small typed fatal frame so Rust can classify
                # the terminal cause instead of inferring it from EOF.
                result = _fallback_serialization_failure(
                    request,
                    result,
                    code=code,
                )
                _preflight_response_serialization(request, result)
                response = encode_tool_response(request, result)
            if request.has_absolute_deadline:
                stages = request.settlement_stages
                assert stages is not None
                if remaining_to(stages.encode_monotonic_ns) <= 0:
                    raise BridgeError("response_serialization_deadline_exceeded")
            if request.has_absolute_deadline:
                stages = request.settlement_stages
                assert stages is not None
                _write_response_before_drain_cutoff(
                    process.stdin,
                    response,
                    drain_cutoff_monotonic_ns=stages.drain_monotonic_ns,
                    monotonic_ns=monotonic_ns,
                )
                remaining = remaining_to(stages.drain_monotonic_ns)
            else:
                assert operation_deadline is not None
                process.stdin.write(response + b"\n")
                remaining = operation_deadline - loop.time()
            if remaining <= 0:
                raise BridgeError(
                    "response_serialization_deadline_exceeded"
                    if request.has_absolute_deadline
                    else "external_bridge_write_deadline_exceeded"
                )
            try:
                await asyncio.wait_for(process.stdin.drain(), timeout=remaining)
            except TimeoutError as error:
                raise BridgeError(
                    "response_serialization_deadline_exceeded"
                    if request.has_absolute_deadline
                    else "external_bridge_write_deadline_exceeded"
                ) from error
            expected_seq += 1
            fatal_sent = isinstance(result, ToolFailure)
            if terminal_control_error is not None:
                raise terminal_control_error
        process.stdin.close()
        remaining = max(0.001, read_remaining())
        return_code = await asyncio.wait_for(process.wait(), remaining)
        stderr = await stderr_task
        if return_code != 0:
            raise BridgeError(
                "external_runtime_nonzero",
                failure_receipt=_runtime_exit_failure_receipt(
                    handler,
                    task_image=task_image,
                    trial_family=trial_family,
                    return_code=return_code,
                    stderr=stderr,
                ),
            )
        return BridgeOutcome(
            request_count=expected_seq,
            stderr=stderr,
            closure_receipt=BridgeClosureReceiptV1(
                handler_completion=HandlerCompletionStateV1.COMPLETED,
                actor_dispatch=ActorDispatchStateV1.REVOKED,
                actor_quiescent=True,
                remote_census_verified=True,
                remote_survivor_count=0,
                stdio_bridge_closed=True,
                runtime_child_closed=True,
            ),
        )
    except BaseException as original_error:
        if not legacy and not process.stdin.is_closing():
            # EOF is the typed signal that lets Rust publish its terminal
            # prefix; terminating the child here would recreate the missing
            # run.json/usage failure this deadline contract exists to prevent.
            process.stdin.close()
        captured_stderr: bytes | None = None
        stderr_cancel: asyncio.CancelledError | None = None
        execution_completed = True
        execution_value: Any = True
        execution_cancel: asyncio.CancelledError | None = None
        cleanup_completed = False
        cleanup_value: Any = False
        cleanup_cancel: asyncio.CancelledError | None = None
        stop_completed = False
        stop_cancel: asyncio.CancelledError | None = None
        try:
            if execution_task is not None and not execution_task.done():
                if (
                    not legacy
                    and active_request is not None
                    and active_request.settlement_stages is not None
                ):
                    execution_budget = remaining_to(
                        active_request.settlement_stages.history_commit_monotonic_ns
                    )
                else:
                    execution_budget = hard_remaining() / 4
                (
                    execution_completed,
                    execution_value,
                    execution_cancel,
                ) = await _complete_shielded(
                    _cancel_execution(execution_task),
                    timeout_sec=execution_budget,
                    reserve_cancellation=False,
                )
            elif execution_task is not None:
                execution_completed = True
                execution_value = True

            # The handler owns its foreground lease until it has completely
            # unwound.  Global actor cleanup is therefore strictly sequential,
            # never raced with the cancellation handler.
            if execution_completed and execution_value is True:
                cleanup_awaitable = (
                    handler.cleanup_active_until(
                        deadline_receipt.cutoffs.hard_deadline_monotonic_ns
                    )
                    if deadline_receipt is not None
                    and hasattr(handler, "cleanup_active_until")
                    else handler.cleanup_active()
                )
                (
                    cleanup_completed,
                    cleanup_value,
                    cleanup_cancel,
                ) = await _complete_shielded(
                    cleanup_awaitable,
                    timeout_sec=hard_remaining() / 2 if legacy else hard_remaining(),
                )
            if legacy:
                stop_awaitable = _stop_child(process)
            else:
                stop_awaitable = _allow_publication_then_stop_child(
                    process,
                    publication_timeout_sec=remaining_to(
                        deadline_receipt.cutoffs.cleanup_start_monotonic_ns
                    ),
                )
            stop_completed, _, stop_cancel = await _complete_shielded(
                stop_awaitable,
                timeout_sec=hard_remaining(),
            )
        finally:
            if not stderr_task.done():
                stderr_budget = hard_remaining()
                if stderr_budget > 0:
                    try:
                        await asyncio.wait_for(
                            asyncio.shield(stderr_task),
                            timeout=stderr_budget,
                        )
                    except TimeoutError:
                        pass
                    except asyncio.CancelledError as error:
                        stderr_cancel = error
            if not stderr_task.done():
                stderr_task.cancel()
            await asyncio.gather(stderr_task, return_exceptions=True)
            if (
                stderr_task.done()
                and not stderr_task.cancelled()
                and stderr_task.exception() is None
            ):
                captured_stderr = stderr_task.result()
        structural_state: Mapping[str, object] | None = None
        state_reader = getattr(handler, "settlement_state_v1", None)
        if callable(state_reader):
            try:
                candidate = state_reader()
            except Exception:
                candidate = None
            if (
                type(candidate) is dict
                and set(candidate)
                == {
                    "schema_version",
                    "actor_dispatch",
                    "actor_quiescent",
                    "remote_census_verified",
                    "remote_survivor_count",
                }
                and candidate.get("schema_version")
                == "terminal-actor-settlement-state-v1"
            ):
                structural_state = candidate
        structurally_quiescent = bool(
            structural_state is not None
            and structural_state.get("actor_dispatch") == "revoked"
            and structural_state.get("actor_quiescent") is True
            and structural_state.get("remote_census_verified") is True
            and structural_state.get("remote_survivor_count") == 0
        )
        actor_safe = (
            cleanup_completed and cleanup_value is True
        ) or structurally_quiescent
        handler_completion = (
            HandlerCompletionStateV1.SETTLEMENT_DEADLINE
            if terminal_control_error is not None
            or not (execution_completed and execution_value is True)
            else HandlerCompletionStateV1.COMPLETED
        )
        child_closed = stop_completed and process.returncode is not None
        bridge_closed = (
            process.stdin.is_closing() and child_closed and stderr_task.done()
        )
        closure_receipt = BridgeClosureReceiptV1(
            handler_completion=handler_completion,
            actor_dispatch=(
                ActorDispatchStateV1.REVOKED
                if actor_safe
                else ActorDispatchStateV1.UNVERIFIED
            ),
            actor_quiescent=actor_safe,
            remote_census_verified=actor_safe,
            remote_survivor_count=0 if actor_safe else None,
            stdio_bridge_closed=bridge_closed,
            runtime_child_closed=child_closed,
        )
        cleanup_ok = closure_receipt.process_safe
        if not cleanup_ok:
            raise BridgeError(
                "cleanup_deadline_exceeded"
                if not legacy and hard_remaining() <= 0
                else "external_bridge_cleanup_unverified",
                stderr=captured_stderr,
                failure_receipt=getattr(original_error, "failure_receipt", None),
                cleanup_receipt=closure_receipt.to_dict(),
            ) from original_error
        try:
            setattr(original_error, "cleanup_receipt", closure_receipt.to_dict())
        except Exception:
            pass
        if stop_cancel is not None:
            raise stop_cancel
        if cleanup_cancel is not None:
            raise cleanup_cancel
        if execution_cancel is not None:
            raise execution_cancel
        if stderr_cancel is not None:
            raise stderr_cancel
        if isinstance(original_error, BridgeError):
            original_error.stderr = captured_stderr
        raise original_error
