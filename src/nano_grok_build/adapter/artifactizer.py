"""Validate runtime truth and atomically publish ATIF plus marker-last metadata."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import stat
import unicodedata
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nano_grok_build.adapter.artifact_limits import WORKSPACE_CHANGED_TAR_MAX_BYTES
from nano_grok_build.adapter.atif import (
    project_emergency_prefix,
    project_emergency_trajectory,
    project_failure_trajectory,
    project_partial_trajectory,
    project_trajectory,
    usage_context,
    validate_with_pinned_harbor,
)
from nano_grok_build.adapter.control_plane import ControlPlane, ControlPlaneError
from nano_grok_build.adapter.deadline import (
    DeadlineContractError,
    RunDeadlineReceiptV1,
)

EVENT_SCHEMA = "event-v3"
PREVIOUS_EVENT_SCHEMA = "event-v2"
LEGACY_EVENT_SCHEMA = "event-v1"
RUN_SCHEMA = "nano-run-record-v2"
RUN_V3_SCHEMA = "nano-run-record-v3"
LEGACY_RUN_SCHEMA = "nano-run-record-alpha-1"
MARKER_SCHEMA = "nano-agent-run-v2"
MARKER_V3_SCHEMA = "nano-agent-run-v3"
TERMINAL_ATIF_MARKER_SCHEMA = "nano-agent-run-v4"
LEGACY_MARKER_SCHEMA = "nano-agent-run-v1"
USAGE_RECEIPT_SCHEMA = "nano-usage-receipt-v1"
BACKGROUND_MANIFEST_SCHEMA = "nano-background-manifest-v1"
BACKGROUND_FAILURE_MANIFEST_SCHEMA = "nano-background-manifest-failure-v1"
TOOL_RECEIPT_TELEMETRY_SCHEMA = "nano-tool-receipt-telemetry-v1"
TOOL_RECEIPT_SCHEMA = "nano-tool-receipt-v1"
_MAX_EVENTS_BYTES = 64 * 1024 * 1024
_MAX_RECORD_BYTES = 16 * 1024 * 1024
_MAX_RECEIPT_BYTES = 1024 * 1024
_MAX_IDENTITY_BYTES = 256
_MAX_TOOL_RECEIPT_SAMPLES = 256
_MAX_U64 = (1 << 64) - 1
_EVENT_KEYS = {
    "schema_version",
    "run_id",
    "trial_id",
    "attempt_id",
    "seq",
    "elapsed_ms",
    "type",
    "data",
}
_LEGACY_RUN_KEYS = {
    "schema_version",
    "run_id",
    "trial_id",
    "attempt_id",
    "run_spec_sha256",
    "contract_id",
    "contract_set_sha256",
    "profile_id",
    "terminal_status",
    "terminal_code",
    "final_event_seq",
    "provider_turn_count",
    "tool_call_count",
    "raw_usage",
    "start_elapsed_ms",
    "end_elapsed_ms",
    "events_sha256",
}
_RUN_KEYS = {
    "schema_version",
    "run_id",
    "trial_id",
    "attempt_id",
    "run_spec_sha256",
    "contract_id",
    "contract_set_sha256",
    "profile_id",
    "terminal_status",
    "terminal_phase",
    "terminal_code",
    "final_event_seq",
    "provider_turn_count",
    "tool_call_count",
    "provider_call_coverage",
    "usage_totals",
    "start_elapsed_ms",
    "end_elapsed_ms",
    "events_sha256",
}
_DEADLINE_RECEIPT_FIELD = "deadline_receipt_sha256"
_MEDIA_HISTORY_POLICY_VERSION = "rolling-media-history-latest-suffix-v1"
_MEDIA_HISTORY_POLICY_SHA256 = (
    "b34dc9dd4f9d37c53e98fbf2fd3a3d816ba3e1071dd3e981161f23d16ffb6cd6"
)
_MEDIA_HISTORY_POLICY_VERSION_FIELD = "media_history_policy_version"
_MEDIA_HISTORY_POLICY_SHA256_FIELD = "media_history_policy_sha256"
_MEDIA_HISTORY_POLICY_FIELDS = {
    _MEDIA_HISTORY_POLICY_VERSION_FIELD,
    _MEDIA_HISTORY_POLICY_SHA256_FIELD,
}
_MEDIA_HISTORY_REQUEST_RECEIPT_FIELD = "media_history_receipt"
_MEDIA_HISTORY_REQUEST_RECEIPT_KEYS = {
    "history_sha256",
    "retained_count",
    "retained_bytes",
    "evicted_total",
}
_BUDGET_OBSERVATION_FIELD = "budget_observation"
_PROVIDER_BUDGET_OBSERVATION_KEYS = {
    "phase",
    "budget_notice_visible",
    "action_remaining_ms",
    "settlement_remaining_ms",
    "last_send_remaining_ms",
}
_TOOL_BUDGET_OBSERVATION_KEYS = {
    "dispatch_open_at_registration",
    "action_remaining_ms",
    "settlement_remaining_ms",
    "last_send_remaining_ms",
}
_TOOL_RECEIPT_OMITTED_FIELD = "tool_receipt_omitted_count"
_PREVIOUS_TOOL_RECEIPT_OMITTED_FIELD = "tool_receipt_telemetry_omitted_samples"
_TOOL_RECEIPT_OMITTED_FIELDS = {
    _TOOL_RECEIPT_OMITTED_FIELD,
    _PREVIOUS_TOOL_RECEIPT_OMITTED_FIELD,
}
_TOOL_RECEIPT_KEYS = {
    "schema_version",
    "phase",
    "origin",
    "primary_subtype",
    "recovery_subtype",
    "receipt_digest_sha256",
    "tool_identity_sha256",
    "tool_call_ordinal",
}
_PREVIOUS_TOOL_RECEIPT_KEYS = _TOOL_RECEIPT_KEYS | {
    "coverage",
    "owner",
    "source",
    "relation",
}
_TOOL_RECEIPT_COVERAGE = {
    "complete",
    "partial",
    "unavailable",
    "invalid",
}
_TOOL_RECEIPT_PHASES = {
    "mapping_preflight",
    "remote_setup",
    "command_upload",
    "remote_exec",
    "recovery_download",
    "result_download",
    "meta_validate",
    "cleanup",
    "census",
    "actor_done",
}
_TOOL_RECEIPT_ORIGINS = {"semantic", "transport", "protocol", "actor"}
_TOOL_RECEIPT_PRIMARY_SUBTYPES = {
    "completed",
    "semantic_execution_timed_out",
    "actor_deadline_exceeded",
    "workspace_mapping_check_timeout",
    "workspace_mapping_changed",
    "request_setup_failed",
    "command_upload_failed",
    "run_transport_timeout",
    "run_transport_failed",
    "run_response_nonzero",
    "meta_invalid",
    "output_download_failed",
    "output_limit_exceeded",
    "cleanup_unverified",
    "cancelled",
    "unexpected_failure",
}
_TOOL_RECEIPT_RECOVERY_PRIMARY_SUBTYPES = {
    "run_transport_timeout",
    "run_transport_failed",
    "run_response_nonzero",
}
_TOOL_RECEIPT_RECOVERY_SUBTYPES = {
    "recovered_settled",
    "recovery_download_failed",
    "meta_invalid",
    "output_download_failed",
    "output_limit_exceeded",
    "cleanup_unverified",
    "actor_deadline_exceeded",
}
_OPTIONAL_RUN_FIELD_SETS = {
    frozenset(),
    frozenset({_DEADLINE_RECEIPT_FIELD}),
}
_COVERAGE_KEYS = {
    "requested",
    "completed",
    "failed",
    "in_flight",
    "usage_present",
    "usage_absent",
    "usage_covered",
    "cost_present",
    "cost_absent",
    "state",
}
_USAGE_TOTAL_KEYS = {
    "input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "provider_cost_ticks",
}
_EVENT_TYPES = {
    "run.started",
    "provider.requested",
    "provider.completed",
    "provider.failed",
    "tool.registered",
    "tool.dispatched",
    "tool.completed",
    "tool.failed",
    "tool.receipt",
    "assistant.final",
    "run.completed",
    "run.failed",
}


class ArtifactError(RuntimeError):
    """Artifacts are incomplete, inconsistent, or cannot be safely published."""


@dataclass(frozen=True)
class ToolReceiptTelemetrySample:
    schema_version: str
    coverage: str
    owner: str
    source: str
    phase: str
    origin: str
    primary_subtype: str
    recovery_subtype: str | None
    receipt_digest_sha256: str
    relation: str
    tool_identity_sha256: str
    tool_call_ordinal: int

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "coverage": self.coverage,
            "owner": self.owner,
            "source": self.source,
            "phase": self.phase,
            "origin": self.origin,
            "primary_subtype": self.primary_subtype,
            "recovery_subtype": self.recovery_subtype,
            "receipt_digest_sha256": self.receipt_digest_sha256,
            "relation": self.relation,
            "tool_identity_sha256": self.tool_identity_sha256,
            "tool_call_ordinal": self.tool_call_ordinal,
        }


@dataclass(frozen=True)
class AtifEligibility:
    """Fail-closed leaderboard eligibility for one published trajectory.

    Diagnostic paths deliberately remain absent here. Consumers must use the
    publication's diagnostic ``trajectory_path`` explicitly and cannot mistake
    it for a judgeable ATIF path.
    """

    leaderboard_eligible: bool
    conformance: str
    trajectory_path: str | None
    trajectory_sha256: str | None
    ineligibility_reason: str | None


@dataclass(frozen=True)
class ArtifactPublication:
    trajectory_path: Path
    marker_path: Path
    trajectory: Mapping[str, Any]
    context: Mapping[str, int]
    marker_bytes: bytes
    background_manifest: BackgroundManifestReceipt | None
    publication_kind: str
    success_artifact_valid: bool
    diagnostic_package_valid: bool
    atif_eligibility: AtifEligibility
    usage_receipt_path: Path | None
    usage_coverage: Mapping[str, Any] | None
    tool_receipt_telemetry: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class BackgroundManifestReceipt:
    sha256: str
    task_count: int
    status: str
    failure_code: str | None


@dataclass(frozen=True)
class VerifierTerminalRuntimeV1:
    """Read-only projection authorizing consideration of a failed runtime."""

    schema_version: str
    run_id: str
    trial_id: str
    attempt_id: str
    run_spec_sha256: str
    terminal_status: str
    terminal_phase: str
    terminal_code: str
    run_record_sha256: str
    events_sha256: str

    def __post_init__(self) -> None:
        phase_by_status = {
            "provider_failure": {"provider"},
            "tool_failure": {"tool", "bridge"},
            "deadline_failure": {"deadline"},
        }
        if (
            self.schema_version not in {RUN_SCHEMA, RUN_V3_SCHEMA}
            or any(
                not isinstance(value, str) or not value
                for value in (
                    self.run_id,
                    self.trial_id,
                    self.attempt_id,
                    self.terminal_code,
                )
            )
            or not _is_sha256(self.run_spec_sha256)
            or not _is_sha256(self.run_record_sha256)
            or not _is_sha256(self.events_sha256)
            or self.terminal_status not in phase_by_status
            or self.terminal_phase not in phase_by_status[self.terminal_status]
        ):
            raise ValueError("verifier terminal runtime proof is invalid")


_VERIFIER_DECISION_TOKEN = object()


@dataclass(frozen=True)
class VerifierOpportunityDecisionV1:
    """Closed decision consumed only by the pinned Harbor scheduling seam."""

    eligible: bool
    runtime: VerifierTerminalRuntimeV1 | None = None
    workspace_receipt_sha256: str | None = None
    canonical_workspace: str | None = None
    _token: object | None = dataclasses.field(
        default=None,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        complete = (
            type(self.runtime) is VerifierTerminalRuntimeV1
            and _is_sha256(self.workspace_receipt_sha256)
            and isinstance(self.canonical_workspace, str)
            and self.canonical_workspace.startswith("/")
            and "\x00" not in self.canonical_workspace
        )
        if self.eligible:
            if self._token is not _VERIFIER_DECISION_TOKEN or not complete:
                raise ValueError("eligible verifier decision proof is incomplete")
        elif (
            self.runtime is not None
            or self.workspace_receipt_sha256 is not None
            or self.canonical_workspace is not None
            or self._token is not None
        ):
            raise ValueError("ineligible verifier decision carries proof")

    @classmethod
    def _grant(
        cls,
        *,
        runtime: VerifierTerminalRuntimeV1,
        workspace_receipt_sha256: str,
        canonical_workspace: str,
    ) -> VerifierOpportunityDecisionV1:
        return cls(
            eligible=True,
            runtime=runtime,
            workspace_receipt_sha256=workspace_receipt_sha256,
            canonical_workspace=canonical_workspace,
            _token=_VERIFIER_DECISION_TOKEN,
        )

    @property
    def proof_complete(self) -> bool:
        return (
            self.eligible is True
            and self._token is _VERIFIER_DECISION_TOKEN
            and type(self.runtime) is VerifierTerminalRuntimeV1
            and _is_sha256(self.workspace_receipt_sha256)
            and isinstance(self.canonical_workspace, str)
            and self.canonical_workspace.startswith("/")
            and "\x00" not in self.canonical_workspace
        )


def canonical_json(value: object) -> bytes:
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


def rust_run_spec_sha256(spec: Mapping[str, Any]) -> str:
    """Match ``serde_json::to_vec(RunSpec)`` field order exactly."""

    task = spec["task"]
    contract = spec["contract"]
    provider = spec["provider"]
    ordered = {
        "schema_version": spec["schema_version"],
        "run_id": spec["run_id"],
        "trial_id": spec["trial_id"],
        "attempt_id": spec["attempt_id"],
        "task": {
            "id": task["id"],
            "digest": task["digest"],
            "instruction": task["instruction"],
        },
        "contract": {
            "id": contract["id"],
            "contract_set_sha256": contract["contract_set_sha256"],
            "profile_id": contract["profile_id"],
        },
        "provider": {
            "kind": provider["kind"],
            "model": provider["model"],
            "max_turns": provider["max_turns"],
            "retry_max": provider["retry_max"],
        },
        "workspace_dir": spec["workspace_dir"],
        "artifact_dir": spec["artifact_dir"],
        "agent_timeout_sec": spec["agent_timeout_sec"],
    }
    if spec.get("active_tools") is not None:
        ordered["active_tools"] = spec["active_tools"]
    raw = json.dumps(ordered, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactError("artifact_duplicate_json_field")
        result[key] = value
    return result


def _load_json(raw: bytes, code: str) -> Any:
    try:
        return json.loads(
            raw,
            object_pairs_hook=_no_duplicates,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except ArtifactError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ArtifactError(code) from error


class _TrackedJsonObject(dict[str, Any]):
    def __init__(self, pairs: list[tuple[str, Any]]) -> None:
        super().__init__()
        duplicates: set[str] = set()
        for key, value in pairs:
            if key in self:
                duplicates.add(key)
            self[key] = value
        self.duplicate_keys = frozenset(duplicates)


@dataclass(frozen=True)
class _InvalidJsonConstant:
    value: str


def _json_issues(value: object) -> tuple[bool, bool]:
    if isinstance(value, _InvalidJsonConstant):
        return False, True
    if isinstance(value, _TrackedJsonObject):
        duplicate = bool(value.duplicate_keys)
        invalid_constant = False
        for item in value.values():
            item_duplicate, item_constant = _json_issues(item)
            duplicate = duplicate or item_duplicate
            invalid_constant = invalid_constant or item_constant
        return duplicate, invalid_constant
    if isinstance(value, list):
        duplicate = False
        invalid_constant = False
        for item in value:
            item_duplicate, item_constant = _json_issues(item)
            duplicate = duplicate or item_duplicate
            invalid_constant = invalid_constant or item_constant
        return duplicate, invalid_constant
    return False, False


def _plain_json(value: Any) -> Any:
    if isinstance(value, _TrackedJsonObject):
        return {key: _plain_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_plain_json(item) for item in value]
    return value


def _load_event_json(raw: bytes, code: str) -> tuple[Any, bool]:
    """Decode one event while isolating issues inside known advisory fields."""

    try:
        value = json.loads(
            raw,
            object_pairs_hook=_TrackedJsonObject,
            parse_constant=_InvalidJsonConstant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ArtifactError(code) from error
    if not isinstance(value, _TrackedJsonObject):
        return _plain_json(value), False
    if value.duplicate_keys:
        raise ArtifactError("artifact_duplicate_json_field")

    for key, item in value.items():
        if key == "data":
            continue
        duplicate, invalid_constant = _json_issues(item)
        if duplicate:
            raise ArtifactError("artifact_duplicate_json_field")
        if invalid_constant:
            raise ArtifactError(code)

    data = value.get("data")
    event_type = value.get("type")
    if event_type == "tool.receipt":
        duplicate, invalid_constant = _json_issues(data)
        return _plain_json(value), duplicate or invalid_constant

    advisory_issue = False
    if isinstance(data, _TrackedJsonObject):
        fatal_duplicate_keys = data.duplicate_keys - _TOOL_RECEIPT_OMITTED_FIELDS
        if fatal_duplicate_keys:
            raise ArtifactError("artifact_duplicate_json_field")
        advisory_issue = bool(_TOOL_RECEIPT_OMITTED_FIELDS & data.duplicate_keys)
        for key, item in data.items():
            duplicate, invalid_constant = _json_issues(item)
            if key in _TOOL_RECEIPT_OMITTED_FIELDS:
                advisory_issue = advisory_issue or duplicate or invalid_constant
            else:
                if duplicate:
                    raise ArtifactError("artifact_duplicate_json_field")
                if invalid_constant:
                    raise ArtifactError(code)
    else:
        duplicate, invalid_constant = _json_issues(data)
        if duplicate:
            raise ArtifactError("artifact_duplicate_json_field")
        if invalid_constant:
            raise ArtifactError(code)
    return _plain_json(value), advisory_issue


def _read_regular(path: Path, limit: int, code: str) -> bytes:
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
            or before.st_size > limit
        ):
            raise ArtifactError(code)
        payload = bytearray()
        while True:
            remaining = limit + 1 - len(payload)
            if remaining <= 0:
                raise ArtifactError(code)
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > limit:
                raise ArtifactError(code)
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
        named = path.lstat()
        named_identity = (
            named.st_dev,
            named.st_ino,
            named.st_mode,
            named.st_size,
            named.st_mtime_ns,
            named.st_ctime_ns,
        )
        if (
            before_identity != after_identity
            or after_identity != named_identity
            or after.st_size != len(payload)
        ):
            raise ArtifactError(code)
    except OSError as error:
        raise ArtifactError(code) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return bytes(payload)


def validate_background_manifest(
    *,
    logs_dir: Path,
    run_spec: Mapping[str, Any],
) -> BackgroundManifestReceipt:
    raw = _read_regular(
        logs_dir / "runtime-background-manifest.json",
        256 * 1024,
        "background_manifest_missing_or_invalid",
    )
    value = _load_json(raw, "background_manifest_json_invalid")
    identity_keys = {
        "schema_version",
        "run_id",
        "trial_id",
        "attempt_id",
        "run_spec_sha256",
    }
    if (
        not isinstance(value, dict)
        or value.get("run_id") != run_spec["run_id"]
        or value.get("trial_id") != run_spec["trial_id"]
        or value.get("attempt_id") != run_spec["attempt_id"]
        or value.get("run_spec_sha256") != rust_run_spec_sha256(run_spec)
        or raw != canonical_json(value)
    ):
        raise ArtifactError("background_manifest_invalid")
    if value.get("schema_version") == BACKGROUND_FAILURE_MANIFEST_SCHEMA:
        if (
            set(value)
            != identity_keys
            | {
                "status",
                "code",
                "cleanup_attempted",
                "cleanup_verified",
            }
            or value["status"] != "unavailable"
            or not isinstance(value["code"], str)
            or not value["code"]
            or len(value["code"].encode("utf-8")) > 128
            or not isinstance(value["cleanup_attempted"], bool)
            or not isinstance(value["cleanup_verified"], bool)
            or value["cleanup_verified"]
            and not value["cleanup_attempted"]
        ):
            raise ArtifactError("background_manifest_invalid")
        return BackgroundManifestReceipt(
            sha256=hashlib.sha256(raw).hexdigest(),
            task_count=0,
            status="unavailable",
            failure_code=value["code"],
        )
    if (
        set(value)
        != {
            "schema_version",
            "run_id",
            "trial_id",
            "attempt_id",
            "run_spec_sha256",
            "tasks",
        }
        or value["schema_version"] != BACKGROUND_MANIFEST_SCHEMA
        or not isinstance(value["tasks"], list)
        or len(value["tasks"]) > 8
    ):
        raise ArtifactError("background_manifest_invalid")
    workspace = str(run_spec["workspace_dir"]).rstrip("/")
    seen: set[str] = set()
    for row in value["tasks"]:
        if not isinstance(row, dict) or set(row) != {
            "task_id",
            "pgid",
            "monitor_pgid",
            "output_path",
            "state",
        }:
            raise ArtifactError("background_manifest_invalid")
        try:
            parsed_id = uuid.UUID(row["task_id"])
        except (ValueError, AttributeError, TypeError) as error:
            raise ArtifactError("background_manifest_invalid") from error
        if (
            parsed_id.version != 7
            or str(parsed_id) != row["task_id"]
            or row["task_id"] in seen
            or row["state"] != "running"
            or isinstance(row["pgid"], bool)
            or not isinstance(row["pgid"], int)
            or row["pgid"] <= 1
            or isinstance(row["monitor_pgid"], bool)
            or not isinstance(row["monitor_pgid"], int)
            or row["monitor_pgid"] <= 1
            or not isinstance(row["output_path"], str)
            or row["output_path"] != f"{workspace}/.terminals/{row['task_id']}.log"
        ):
            raise ArtifactError("background_manifest_invalid")
        seen.add(row["task_id"])
    return BackgroundManifestReceipt(
        sha256=hashlib.sha256(raw).hexdigest(),
        task_count=len(value["tasks"]),
        status="complete",
        failure_code=None,
    )


def _is_uint(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def run_event_elapsed_bounds_valid(
    *,
    start_elapsed_ms: object,
    end_elapsed_ms: object,
    first_event_elapsed_ms: object,
    terminal_event_elapsed_ms: object,
) -> bool:
    """Return whether a run record consistently bounds its event timeline."""
    values = (
        start_elapsed_ms,
        end_elapsed_ms,
        first_event_elapsed_ms,
        terminal_event_elapsed_ms,
    )
    return (
        all(_is_uint(value) for value in values)
        and start_elapsed_ms <= first_event_elapsed_ms
        and end_elapsed_ms == terminal_event_elapsed_ms
    )


def _is_string(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _positive_u64(value: object) -> int | None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value <= 0
        or value > _MAX_U64
    ):
        return None
    return value


def _bounded_identity(value: object) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or any(unicodedata.category(character) == "Cc" for character in value)
    ):
        return False
    try:
        return len(value.encode("utf-8")) <= _MAX_IDENTITY_BYTES
    except UnicodeEncodeError:
        return False


def _tool_identity_sha256(call_id: str, provider_name: str) -> str:
    encoded = json.dumps(
        {"call_id": call_id, "provider_name": provider_name},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _tool_receipt_primary_binding_valid(
    phase: str,
    origin: str,
    primary_subtype: str,
    recovery_subtype: str | None,
) -> bool:
    if (
        primary_subtype not in _TOOL_RECEIPT_PRIMARY_SUBTYPES
        or (recovery_subtype is not None)
        != (primary_subtype in _TOOL_RECEIPT_RECOVERY_PRIMARY_SUBTYPES)
        or (
            recovery_subtype is not None
            and recovery_subtype not in _TOOL_RECEIPT_RECOVERY_SUBTYPES
        )
        or (phase == "recovery_download" and recovery_subtype is None)
        or (
            phase == "actor_done"
            and (
                primary_subtype
                not in {
                    "actor_deadline_exceeded",
                    "cancelled",
                    "unexpected_failure",
                }
                or recovery_subtype is not None
            )
        )
    ):
        return False
    if primary_subtype == "completed":
        return phase == "meta_validate" and origin == "actor"
    if primary_subtype == "semantic_execution_timed_out":
        return phase == "meta_validate" and origin == "semantic"
    if primary_subtype in {"actor_deadline_exceeded", "unexpected_failure"}:
        return origin == "actor"
    if primary_subtype == "workspace_mapping_check_timeout":
        return phase == "mapping_preflight" and origin == "transport"
    if primary_subtype == "workspace_mapping_changed":
        return phase == "mapping_preflight" and origin == "protocol"
    if primary_subtype == "request_setup_failed":
        return phase in {"remote_setup", "cleanup"} and origin in {
            "protocol",
            "transport",
        }
    if primary_subtype == "command_upload_failed":
        return phase in {"command_upload", "cleanup"} and origin == "transport"
    if primary_subtype in {"run_transport_timeout", "run_transport_failed"}:
        return (
            phase in {"recovery_download", "meta_validate", "cleanup"}
            and origin == "transport"
        )
    if primary_subtype == "run_response_nonzero":
        return (
            phase in {"recovery_download", "meta_validate", "cleanup"}
            and origin == "protocol"
        )
    if primary_subtype == "output_download_failed":
        return phase in {"result_download", "cleanup"} and origin == "transport"
    if primary_subtype in {"meta_invalid", "output_limit_exceeded"}:
        return phase in {"meta_validate", "cleanup"} and origin == "protocol"
    if primary_subtype == "cleanup_unverified":
        return phase in {"cleanup", "census"} and origin == "actor"
    if primary_subtype == "cancelled":
        return phase in {"cleanup", "actor_done"} and origin == "actor"
    return False


def _parse_tool_receipt_sample(
    data: Mapping[str, Any],
    *,
    event_schema: str | None = None,
) -> ToolReceiptTelemetrySample | None:
    fields = set(data)
    if fields == _TOOL_RECEIPT_KEYS:
        if (
            data.get("schema_version") != TOOL_RECEIPT_SCHEMA
            or event_schema is not None
            and event_schema != EVENT_SCHEMA
        ):
            return None
    elif fields == _PREVIOUS_TOOL_RECEIPT_KEYS:
        if (
            data.get("schema_version") != TOOL_RECEIPT_TELEMETRY_SCHEMA
            or event_schema is not None
            and event_schema != PREVIOUS_EVENT_SCHEMA
            or data.get("coverage") != "complete"
            or data.get("owner") != "tool"
            or data.get("source") != "actor_receipt"
            or data.get("relation") != "settles"
        ):
            return None
    else:
        return None
    phase = data.get("phase")
    origin = data.get("origin")
    primary_subtype = data.get("primary_subtype")
    recovery_subtype = data.get("recovery_subtype")
    ordinal = _positive_u64(data.get("tool_call_ordinal"))
    if (
        not isinstance(phase, str)
        or phase not in _TOOL_RECEIPT_PHASES
        or not isinstance(origin, str)
        or origin not in _TOOL_RECEIPT_ORIGINS
        or not isinstance(primary_subtype, str)
        or (recovery_subtype is not None and not isinstance(recovery_subtype, str))
        or not _tool_receipt_primary_binding_valid(
            phase,
            origin,
            primary_subtype,
            recovery_subtype,
        )
        or not _is_sha256(data.get("receipt_digest_sha256"))
        or not _is_sha256(data.get("tool_identity_sha256"))
        or ordinal is None
    ):
        return None
    return ToolReceiptTelemetrySample(
        schema_version=TOOL_RECEIPT_TELEMETRY_SCHEMA,
        coverage="complete",
        owner="tool",
        source="actor_receipt",
        phase=phase,
        origin=origin,
        primary_subtype=primary_subtype,
        recovery_subtype=recovery_subtype,
        receipt_digest_sha256=str(data["receipt_digest_sha256"]),
        relation="settles",
        tool_identity_sha256=str(data["tool_identity_sha256"]),
        tool_call_ordinal=ordinal,
    )


def _receipt_omitted_field(event_schema: str) -> str | None:
    if event_schema == EVENT_SCHEMA:
        return _TOOL_RECEIPT_OMITTED_FIELD
    if event_schema == PREVIOUS_EVENT_SCHEMA:
        return _PREVIOUS_TOOL_RECEIPT_OMITTED_FIELD
    return None


def _tool_receipt_projection(
    *,
    signal: bool,
    invalid: bool,
    omitted_samples: int,
    samples: tuple[ToolReceiptTelemetrySample, ...],
) -> Mapping[str, Any] | None:
    if not signal:
        return None
    if invalid:
        coverage = "invalid"
    elif samples and omitted_samples == 0:
        coverage = "complete"
    elif samples or omitted_samples:
        coverage = "partial"
    else:
        coverage = "unavailable"
    if coverage not in _TOOL_RECEIPT_COVERAGE:
        raise AssertionError("unreachable tool receipt coverage")
    return {
        "coverage": coverage,
        "sample_count": len(samples),
        "omitted_samples": omitted_samples,
        "samples": [sample.as_dict() for sample in samples],
    }


def _validate_modern_record(record: Mapping[str, Any]) -> None:
    fields = set(record)
    schema = record.get("schema_version")
    if schema == RUN_SCHEMA:
        optional_fields = frozenset(fields - _RUN_KEYS)
        fields_valid = (
            optional_fields in _OPTIONAL_RUN_FIELD_SETS and _RUN_KEYS <= fields
        )
    elif schema == RUN_V3_SCHEMA:
        fields_valid = fields == _RUN_KEYS | {_DEADLINE_RECEIPT_FIELD}
    else:
        raise ArtifactError("run_marker_schema_invalid")
    if not fields_valid:
        raise ArtifactError("run_marker_fields_invalid")
    if not all(
        _is_string(record[field])
        for field in (
            "run_id",
            "trial_id",
            "attempt_id",
            "contract_id",
            "profile_id",
            "terminal_code",
        )
    ) or not all(
        _is_sha256(record[field])
        for field in ("run_spec_sha256", "contract_set_sha256", "events_sha256")
    ):
        raise ArtifactError("run_marker_value_invalid")
    if _DEADLINE_RECEIPT_FIELD in record and not _is_sha256(
        record[_DEADLINE_RECEIPT_FIELD]
    ):
        raise ArtifactError("run_marker_value_invalid")
    for field in (
        "final_event_seq",
        "provider_turn_count",
        "tool_call_count",
        "start_elapsed_ms",
        "end_elapsed_ms",
    ):
        if not _is_uint(record[field]):
            raise ArtifactError("run_marker_value_invalid")
    if record["end_elapsed_ms"] < record["start_elapsed_ms"]:
        raise ArtifactError("run_marker_elapsed_invalid")

    status = record["terminal_status"]
    phase = record["terminal_phase"]
    valid_terminal = {
        "success": {None},
        "provider_failure": {"provider"},
        "tool_failure": {"tool", "bridge"},
        "deadline_failure": {"deadline"},
        "cancelled": {"cancellation"},
        "runtime_failure": {"artifact", "runtime"},
    }
    if status not in valid_terminal or phase not in valid_terminal[status]:
        raise ArtifactError("run_marker_terminal_invalid")

    coverage = record["provider_call_coverage"]
    if not isinstance(coverage, dict) or set(coverage) != _COVERAGE_KEYS:
        raise ArtifactError("provider_coverage_invalid")
    for field in _COVERAGE_KEYS - {"state"}:
        if not _is_uint(coverage[field]):
            raise ArtifactError("provider_coverage_invalid")
    if coverage["state"] not in {"complete", "partial", "unavailable", "invalid"}:
        raise ArtifactError("provider_coverage_invalid")
    settled = coverage["completed"] + coverage["failed"]
    usage_observed = coverage["usage_present"] + coverage["usage_absent"]
    cost_observed = coverage["cost_present"] + coverage["cost_absent"]
    legacy_shape = (
        usage_observed == coverage["completed"]
        and cost_observed == coverage["completed"]
    )
    settled_shape = usage_observed == settled and cost_observed == settled
    if (
        settled + coverage["in_flight"] != coverage["requested"]
        or not (legacy_shape or settled_shape)
        or coverage["usage_covered"] > coverage["requested"]
        or record["provider_turn_count"] != coverage["requested"]
    ):
        raise ArtifactError("provider_coverage_arithmetic_invalid")
    if coverage["state"] == "complete" and (
        coverage["in_flight"] != 0 or coverage["usage_covered"] != coverage["requested"]
    ):
        raise ArtifactError("provider_coverage_complete_invalid")

    totals = record["usage_totals"]
    if not isinstance(totals, dict) or set(totals) != _USAGE_TOTAL_KEYS:
        raise ArtifactError("usage_totals_invalid")
    if any(value is not None and not _is_uint(value) for value in totals.values()):
        raise ArtifactError("usage_totals_invalid")
    token_fields = ("input_tokens", "cached_input_tokens", "output_tokens")
    if coverage["usage_present"] == 0:
        if any(totals[field] is not None for field in token_fields):
            raise ArtifactError("usage_totals_coverage_mismatch")
    elif any(totals[field] is None for field in token_fields):
        raise ArtifactError("usage_totals_coverage_mismatch")
    if (coverage["cost_present"] == 0) != (totals["provider_cost_ticks"] is None):
        raise ArtifactError("usage_totals_coverage_mismatch")


def _v2_data_keys(event_type: str) -> set[str]:
    return {
        "run.started": {
            "task_id",
            "contract_id",
            "profile_id",
            "contract_set_sha256",
            "model",
            "run_spec_sha256",
        },
        "provider.requested": {
            "turn_index",
            "history_item_count",
            "tool_count",
            "function_output_call_ids",
        },
        "provider.completed": {
            "turn_index",
            "response_id",
            "model",
            "call_ids",
            "has_final_text",
            "usage",
        },
        "provider.failed": {"turn_index", "code"},
        "tool.registered": {
            "call_id",
            "provider_name",
            "known",
            "arguments_json",
        },
        "tool.dispatched": {"call_id", "provider_name"},
        "tool.completed": {
            "call_id",
            "provider_name",
            "execution_attempted",
            "outcome",
            "output",
        },
        "tool.failed": {
            "call_id",
            "provider_name",
            "code",
            "execution_may_have_started",
            "cleanup_verified",
            "census_verified",
            "recoverability",
        },
        "tool.receipt": _TOOL_RECEIPT_KEYS,
        "assistant.final": {"text"},
        "run.completed": {"code"},
        "run.failed": {"code"},
    }[event_type]


def _string_list(value: object) -> bool:
    return isinstance(value, list) and all(_is_string(item) for item in value)


def _validate_provider_attempt_data(data: Mapping[str, Any]) -> None:
    attempt_count = data.get("attempt_count")
    if attempt_count is None:
        return
    if not _is_uint(attempt_count) or attempt_count == 0:
        raise ArtifactError("event_data_invalid")
    retry_code = data.get("retry_code")
    retry_stage = data.get("retry_stage")
    if retry_code is None and retry_stage is None:
        return
    if (
        attempt_count < 2
        or not _is_string(retry_code)
        or retry_stage not in {"request", "response_stream"}
    ):
        raise ArtifactError("event_data_invalid")


def _validate_v2_event_data(event_type: str, data: Mapping[str, Any]) -> None:
    expected_keys = _v2_data_keys(event_type)
    if event_type == "run.started" and _DEADLINE_RECEIPT_FIELD in data:
        expected_keys = expected_keys | {_DEADLINE_RECEIPT_FIELD}
    if event_type == "run.started" and _MEDIA_HISTORY_POLICY_FIELDS <= set(data):
        expected_keys = expected_keys | _MEDIA_HISTORY_POLICY_FIELDS
    if (
        event_type == "provider.requested"
        and _MEDIA_HISTORY_REQUEST_RECEIPT_FIELD in data
    ):
        expected_keys = expected_keys | {_MEDIA_HISTORY_REQUEST_RECEIPT_FIELD}
    if (
        event_type in {"provider.requested", "tool.registered"}
        and _BUDGET_OBSERVATION_FIELD in data
    ):
        expected_keys = expected_keys | {_BUDGET_OBSERVATION_FIELD}
    provider_attempt_fields = {"attempt_count", "retry_code", "retry_stage"}
    if event_type in {"provider.completed", "provider.failed"}:
        present_attempt_fields = provider_attempt_fields & set(data)
        if present_attempt_fields not in (
            set(),
            {"attempt_count"},
            provider_attempt_fields,
        ):
            raise ArtifactError("event_data_fields_invalid")
        expected_keys = expected_keys | present_attempt_fields
    if event_type == "provider.failed":
        rejected_fields = {"rejected_call_count", "response_usage"} & set(data)
        expected_keys = expected_keys | rejected_fields
    if set(data) != expected_keys:
        raise ArtifactError("event_data_fields_invalid")
    if event_type == "run.started":
        if not all(
            _is_string(data[field])
            for field in ("task_id", "contract_id", "profile_id", "model")
        ) or not all(
            _is_sha256(data[field])
            for field in ("contract_set_sha256", "run_spec_sha256")
        ):
            raise ArtifactError("event_data_invalid")
        if _DEADLINE_RECEIPT_FIELD in data and not _is_sha256(
            data[_DEADLINE_RECEIPT_FIELD]
        ):
            raise ArtifactError("event_data_invalid")
        if _MEDIA_HISTORY_POLICY_FIELDS <= set(data) and (
            data[_MEDIA_HISTORY_POLICY_VERSION_FIELD] != _MEDIA_HISTORY_POLICY_VERSION
            or data[_MEDIA_HISTORY_POLICY_SHA256_FIELD] != _MEDIA_HISTORY_POLICY_SHA256
        ):
            raise ArtifactError("event_data_invalid")
    elif event_type == "provider.requested":
        if not all(
            _is_uint(data[field])
            for field in ("turn_index", "history_item_count", "tool_count")
        ) or not _string_list(data["function_output_call_ids"]):
            raise ArtifactError("event_data_invalid")
        receipt = data.get(_MEDIA_HISTORY_REQUEST_RECEIPT_FIELD)
        if receipt is not None and (
            not isinstance(receipt, dict)
            or set(receipt) != _MEDIA_HISTORY_REQUEST_RECEIPT_KEYS
            or not _is_sha256(receipt["history_sha256"])
            or not all(
                _is_uint(receipt[field])
                for field in ("retained_count", "retained_bytes", "evicted_total")
            )
        ):
            raise ArtifactError("event_data_invalid")
        observation = data.get(_BUDGET_OBSERVATION_FIELD)
        if observation is not None and (
            not isinstance(observation, dict)
            or set(observation) != _PROVIDER_BUDGET_OBSERVATION_KEYS
            or observation["phase"]
            not in {"action_open", "final_only", "completion_critic"}
            or not isinstance(observation["budget_notice_visible"], bool)
            or not all(
                _is_uint(observation[field])
                for field in (
                    "action_remaining_ms",
                    "settlement_remaining_ms",
                    "last_send_remaining_ms",
                )
            )
        ):
            raise ArtifactError("event_data_invalid")
    elif event_type == "provider.completed":
        if (
            not _is_uint(data["turn_index"])
            or not _is_string(data["response_id"])
            or not _is_string(data["model"])
            or not _string_list(data["call_ids"])
            or not isinstance(data["has_final_text"], bool)
        ):
            raise ArtifactError("event_data_invalid")
        usage = data["usage"]
        if (
            isinstance(usage, dict)
            and {"cost_in_usd_ticks", "provider_cost_ticks"} <= set(usage)
            and (
                not _is_uint(usage["cost_in_usd_ticks"])
                or not _is_uint(usage["provider_cost_ticks"])
                or usage["cost_in_usd_ticks"] != usage["provider_cost_ticks"]
            )
        ):
            raise ArtifactError("event_data_invalid")
        _validate_provider_attempt_data(data)
    elif event_type == "provider.failed":
        if not _is_uint(data["turn_index"]) or not _is_string(data["code"]):
            raise ArtifactError("event_data_invalid")
        rejected_count = data.get("rejected_call_count")
        if rejected_count is not None and (
            not _is_uint(rejected_count)
            or rejected_count == 0
            or data["code"]
            not in {
                "provider_call_limit_exceeded",
                "provider_run_call_limit_exceeded",
            }
        ):
            raise ArtifactError("event_data_invalid")
        response_usage = data.get("response_usage")
        if response_usage is not None:
            if not isinstance(response_usage, dict):
                raise ArtifactError("event_data_invalid")
            if {"cost_in_usd_ticks", "provider_cost_ticks"} <= set(response_usage) and (
                not _is_uint(response_usage["cost_in_usd_ticks"])
                or not _is_uint(response_usage["provider_cost_ticks"])
                or response_usage["cost_in_usd_ticks"]
                != response_usage["provider_cost_ticks"]
            ):
                raise ArtifactError("event_data_invalid")
        _validate_provider_attempt_data(data)
    elif event_type == "tool.registered":
        if (
            not _is_string(data["call_id"])
            or not _is_string(data["provider_name"])
            or not isinstance(data["known"], bool)
            or not isinstance(data["arguments_json"], str)
        ):
            raise ArtifactError("event_data_invalid")
        observation = data.get(_BUDGET_OBSERVATION_FIELD)
        if observation is not None and (
            not isinstance(observation, dict)
            or set(observation) != _TOOL_BUDGET_OBSERVATION_KEYS
            or not isinstance(observation["dispatch_open_at_registration"], bool)
            or not all(
                _is_uint(observation[field])
                for field in (
                    "action_remaining_ms",
                    "settlement_remaining_ms",
                    "last_send_remaining_ms",
                )
            )
        ):
            raise ArtifactError("event_data_invalid")
    elif event_type == "tool.dispatched":
        if not _is_string(data["call_id"]) or not _is_string(data["provider_name"]):
            raise ArtifactError("event_data_invalid")
    elif event_type == "tool.completed":
        if (
            not _is_string(data["call_id"])
            or not _is_string(data["provider_name"])
            or not isinstance(data["execution_attempted"], bool)
            or data["outcome"] not in {"succeeded", "timed_out", "rejected"}
            or not isinstance(data["output"], str)
        ):
            raise ArtifactError("event_data_invalid")
    elif event_type == "tool.failed":
        if (
            not _is_string(data["call_id"])
            or not _is_string(data["provider_name"])
            or not _is_string(data["code"])
            or not isinstance(data["execution_may_have_started"], bool)
            or (
                data["cleanup_verified"] is not None
                and not isinstance(data["cleanup_verified"], bool)
            )
            or (
                data["census_verified"] is not None
                and not isinstance(data["census_verified"], bool)
            )
            or data["recoverability"] not in {"recoverable", "fatal"}
        ):
            raise ArtifactError("event_data_invalid")
    elif event_type == "tool.receipt":
        if _parse_tool_receipt_sample(data) is None:
            raise ArtifactError("event_data_invalid")
    elif event_type == "assistant.final":
        if not isinstance(data["text"], str):
            raise ArtifactError("event_data_invalid")
    elif not _is_string(data["code"]):
        raise ArtifactError("event_data_invalid")


def _validate_v2_event_relations(
    events: list[dict[str, Any]],
    record: Mapping[str, Any],
    expected_spec: Mapping[str, Any],
    receipt_samples: Mapping[int, ToolReceiptTelemetrySample],
) -> tuple[tuple[ToolReceiptTelemetrySample, ...], bool]:
    started = events[0]["data"]
    contract = expected_spec["contract"]
    if (
        events[0]["type"] != "run.started"
        or started["task_id"] != expected_spec["task"]["id"]
        or started["contract_id"] != contract["id"]
        or started["profile_id"] != contract["profile_id"]
        or started["contract_set_sha256"] != contract["contract_set_sha256"]
        or started["model"] != expected_spec["provider"]["model"]
        or started["run_spec_sha256"] != record["run_spec_sha256"]
        or started.get(_DEADLINE_RECEIPT_FIELD) != record.get(_DEADLINE_RECEIPT_FIELD)
    ):
        raise ArtifactError("run_started_binding_invalid")
    if any(event["type"] == "run.started" for event in events[1:]):
        raise ArtifactError("duplicate_run_started")

    provider_states: dict[int, str] = {}
    tool_states: dict[str, tuple[str, str, bool]] = {}
    registered_tools: list[str] = []
    valid_receipt_samples: list[ToolReceiptTelemetrySample] = []
    previous_receipt_ordinal = 0
    receipt_suffix_started = False
    receipt_invalid = False
    assistant_final_count = 0
    observed_completed = 0
    observed_failed = 0
    policy_version = started.get(_MEDIA_HISTORY_POLICY_VERSION_FIELD)
    for event in events:
        event_type = event["type"]
        data = event["data"]
        if receipt_suffix_started and event_type not in {
            "tool.receipt",
            "run.completed",
            "run.failed",
        }:
            receipt_invalid = True
        if event_type == "provider.requested":
            media_receipt = data.get(_MEDIA_HISTORY_REQUEST_RECEIPT_FIELD)
            if (policy_version is None) != (media_receipt is None):
                raise ArtifactError("media_history_request_binding_invalid")
            turn_index = data["turn_index"]
            if turn_index in provider_states:
                raise ArtifactError("duplicate_provider_request")
            provider_states[turn_index] = "in_flight"
        elif event_type in {"provider.completed", "provider.failed"}:
            turn_index = data["turn_index"]
            if provider_states.get(turn_index) != "in_flight":
                raise ArtifactError("orphan_provider_settlement")
            provider_states[turn_index] = event_type.removeprefix("provider.")
            observed_completed += event_type == "provider.completed"
            observed_failed += event_type == "provider.failed"
        elif event_type == "tool.registered":
            call_id = data["call_id"]
            if call_id in tool_states:
                raise ArtifactError("duplicate_tool_registration")
            tool_states[call_id] = (data["provider_name"], "in_flight", False)
            registered_tools.append(call_id)
        elif event_type == "tool.dispatched":
            call_id = data["call_id"]
            state = tool_states.get(call_id)
            if (
                state is None
                or state[0] != data["provider_name"]
                or state[1] != "in_flight"
                or state[2]
            ):
                raise ArtifactError("orphan_tool_dispatch")
            tool_states[call_id] = (state[0], state[1], True)
        elif event_type in {"tool.completed", "tool.failed"}:
            call_id = data["call_id"]
            state = tool_states.get(call_id)
            if (
                state is None
                or state[0] != data["provider_name"]
                or state[1] != "in_flight"
            ):
                raise ArtifactError("orphan_tool_settlement")
            tool_states[call_id] = (
                state[0],
                event_type.removeprefix("tool."),
                state[2],
            )
        elif event_type == "tool.receipt":
            receipt_suffix_started = True
            sample = receipt_samples.get(event["seq"])
            relation_valid = sample is not None
            if relation_valid and sample is not None:
                ordinal = sample.tool_call_ordinal
                call_id = (
                    registered_tools[ordinal - 1]
                    if ordinal <= len(registered_tools)
                    else None
                )
                state = tool_states.get(call_id) if call_id is not None else None
                relation_valid = bool(
                    ordinal > previous_receipt_ordinal
                    and call_id is not None
                    and state is not None
                    and state[1] in {"completed", "failed"}
                    and _bounded_identity(call_id)
                    and _bounded_identity(state[0])
                    and sample.tool_identity_sha256
                    == _tool_identity_sha256(call_id, state[0])
                    and len(valid_receipt_samples) < _MAX_TOOL_RECEIPT_SAMPLES
                )
                if relation_valid:
                    previous_receipt_ordinal = ordinal
                    valid_receipt_samples.append(sample)
            if not relation_valid:
                receipt_invalid = True
        elif event_type == "assistant.final":
            assistant_final_count += 1
            if assistant_final_count > 1:
                raise ArtifactError("duplicate_assistant_final")

    coverage = record["provider_call_coverage"]
    if (
        len(provider_states) != record["provider_turn_count"]
        or observed_completed > coverage["completed"]
        or observed_failed > coverage["failed"]
        or len(tool_states) > record["tool_call_count"]
    ):
        raise ArtifactError("event_record_count_mismatch")
    missing_provider_settlements = (
        coverage["completed"]
        - observed_completed
        + coverage["failed"]
        - observed_failed
    )
    missing_tool_registrations = record["tool_call_count"] - len(tool_states)
    artifact_prefix_gap_allowed = (
        record["terminal_status"] == "runtime_failure"
        and record["terminal_phase"] == "artifact"
    )
    if (
        missing_provider_settlements or missing_tool_registrations
    ) and not artifact_prefix_gap_allowed:
        raise ArtifactError("event_record_count_mismatch")
    if record["terminal_status"] == "success":
        if assistant_final_count != 1 or any(
            state != "completed" for _, state, _ in tool_states.values()
        ):
            raise ArtifactError("successful_event_prefix_incomplete")
    return tuple(valid_receipt_samples), receipt_invalid


def _validate_deadline_receipt_binding(
    runtime_dir: Path,
    record: Mapping[str, Any],
    started: Mapping[str, Any],
    expected_spec: Mapping[str, Any],
) -> None:
    bound_sha256 = record.get(_DEADLINE_RECEIPT_FIELD)
    receipt_path = runtime_dir / "deadline.json"
    if bound_sha256 is None:
        if receipt_path.exists():
            raise ArtifactError("deadline_receipt_unbound")
        return
    if started.get(_DEADLINE_RECEIPT_FIELD) != bound_sha256:
        raise ArtifactError("deadline_receipt_event_binding_mismatch")

    raw = _read_regular(
        receipt_path,
        _MAX_RECEIPT_BYTES,
        "deadline_receipt_missing_or_invalid",
    )
    try:
        receipt = RunDeadlineReceiptV1.from_bytes(raw)
    except DeadlineContractError as error:
        raise ArtifactError("deadline_receipt_invalid") from error
    if raw != receipt.to_bytes():
        raise ArtifactError("deadline_receipt_canonical_invalid")
    if hashlib.sha256(raw).hexdigest() != bound_sha256:
        raise ArtifactError("deadline_receipt_hash_mismatch")
    if (
        receipt.run_id != expected_spec["run_id"]
        or receipt.trial_id != expected_spec["trial_id"]
        or receipt.attempt_id != expected_spec["attempt_id"]
        or receipt.run_spec_sha256 != rust_run_spec_sha256(expected_spec)
    ):
        raise ArtifactError("deadline_receipt_identity_mismatch")


def _validate_run_and_events(
    runtime_dir: Path, expected_spec: Mapping[str, Any]
) -> tuple[
    dict[str, Any],
    list[dict[str, Any]],
    bytes,
    bytes,
    Mapping[str, Any] | None,
]:
    record_bytes = _read_regular(
        runtime_dir / "run.json", _MAX_RECORD_BYTES, "run_marker_missing_or_invalid"
    )
    if not record_bytes.endswith(b"\n") or record_bytes[:-1].endswith(b"\n"):
        raise ArtifactError("run_marker_framing_invalid")
    record = _load_json(record_bytes, "run_marker_json_invalid")
    if not isinstance(record, dict):
        raise ArtifactError("run_marker_fields_invalid")
    legacy = record.get("schema_version") == LEGACY_RUN_SCHEMA
    if legacy:
        if set(record) != _LEGACY_RUN_KEYS:
            raise ArtifactError("run_marker_fields_invalid")
        if (
            record["terminal_status"] != "success"
            or record["terminal_code"] != "completed"
        ):
            raise ArtifactError("run_not_successful")
    else:
        _validate_modern_record(record)

    spec_sha256 = rust_run_spec_sha256(expected_spec)
    if record["run_spec_sha256"] != spec_sha256:
        raise ArtifactError("run_spec_hash_mismatch")
    for field in ("run_id", "trial_id", "attempt_id"):
        if record[field] != expected_spec[field]:
            raise ArtifactError("run_identity_mismatch")
    contract = expected_spec["contract"]
    if (
        record["contract_id"] != contract["id"]
        or record["contract_set_sha256"] != contract["contract_set_sha256"]
        or record["profile_id"] != contract["profile_id"]
    ):
        raise ArtifactError("run_contract_mismatch")

    event_bytes = _read_regular(
        runtime_dir / "events.jsonl",
        _MAX_EVENTS_BYTES,
        "event_log_missing_or_invalid",
    )
    if not event_bytes.endswith(b"\n"):
        raise ArtifactError("event_log_framing_invalid")
    if hashlib.sha256(event_bytes).hexdigest() != record["events_sha256"]:
        raise ArtifactError("event_log_hash_mismatch")
    lines = event_bytes.splitlines()
    events: list[dict[str, Any]] = []
    previous_elapsed = -1
    terminal_count = 0
    receipt_samples: dict[int, ToolReceiptTelemetrySample] = {}
    receipt_signal = False
    receipt_invalid = False
    receipt_omitted_samples = 0
    observed_event_schema: str | None = None
    for seq, line in enumerate(lines):
        event, advisory_issue = _load_event_json(line, "event_json_invalid")
        if not isinstance(event, dict) or set(event) != _EVENT_KEYS:
            raise ArtifactError("event_fields_invalid")
        event_type = event["type"]
        data = event["data"]
        event_schema = event["schema_version"]
        if (
            (
                event_schema != LEGACY_EVENT_SCHEMA
                if legacy
                else event_schema not in {PREVIOUS_EVENT_SCHEMA, EVENT_SCHEMA}
            )
            or observed_event_schema is not None
            and event_schema != observed_event_schema
            or not _is_uint(event["seq"])
            or event["seq"] != seq
            or not isinstance(event_type, str)
            or event_type not in _EVENT_TYPES
            or (legacy and event_type in {"tool.failed", "tool.receipt"})
            or (
                not isinstance(data, dict)
                and not (not legacy and event_type == "tool.receipt")
            )
        ):
            raise ArtifactError("event_grammar_invalid")
        observed_event_schema = event_schema
        if not legacy:
            if event_type == "tool.receipt":
                receipt_signal = True
                sample = (
                    _parse_tool_receipt_sample(
                        data,
                        event_schema=event_schema,
                    )
                    if isinstance(data, dict) and not advisory_issue
                    else None
                )
                if sample is None:
                    receipt_invalid = True
                    event["data"] = {}
                else:
                    receipt_samples[seq] = sample
                    event["data"] = sample.as_dict()
            else:
                omitted_field = _receipt_omitted_field(event_schema)
                present_omitted_fields = (
                    _TOOL_RECEIPT_OMITTED_FIELDS & set(data)
                    if isinstance(data, dict)
                    else set()
                )
                if present_omitted_fields:
                    receipt_signal = True
                    omitted_samples = _positive_u64(
                        data.get(omitted_field) if omitted_field is not None else None
                    )
                    if (
                        present_omitted_fields != {omitted_field}
                        or event_type not in {"run.completed", "run.failed"}
                        or omitted_samples is None
                        or advisory_issue
                    ):
                        receipt_invalid = True
                    else:
                        receipt_omitted_samples = omitted_samples
                    data = dict(data)
                    for field in _TOOL_RECEIPT_OMITTED_FIELDS:
                        data.pop(field, None)
                    event["data"] = data
                elif advisory_issue:
                    receipt_signal = True
                    receipt_invalid = True
                _validate_v2_event_data(event_type, event["data"])
        if any(
            event[field] != record[field]
            for field in ("run_id", "trial_id", "attempt_id")
        ):
            raise ArtifactError("event_identity_mismatch")
        elapsed = event["elapsed_ms"]
        if not _is_uint(elapsed) or elapsed < previous_elapsed:
            raise ArtifactError("event_elapsed_invalid")
        previous_elapsed = elapsed
        if event["type"] in {"run.completed", "run.failed"}:
            terminal_count += 1
            if seq != len(lines) - 1:
                raise ArtifactError("event_after_terminal")
        events.append(event)
    expected_terminal = (
        "run.completed" if record["terminal_status"] == "success" else "run.failed"
    )
    if (
        not events
        or terminal_count != 1
        or events[-1]["type"] != expected_terminal
        or record["final_event_seq"] != len(events) - 1
        or events[-1]["data"].get("code") != record["terminal_code"]
        or not run_event_elapsed_bounds_valid(
            start_elapsed_ms=record["start_elapsed_ms"],
            end_elapsed_ms=record["end_elapsed_ms"],
            first_event_elapsed_ms=events[0]["elapsed_ms"],
            terminal_event_elapsed_ms=events[-1]["elapsed_ms"],
        )
    ):
        raise ArtifactError("event_terminal_invalid")
    tool_receipt_telemetry: Mapping[str, Any] | None = None
    if not legacy:
        valid_receipt_samples, relation_invalid = _validate_v2_event_relations(
            events,
            record,
            expected_spec,
            receipt_samples,
        )
        receipt_invalid = receipt_invalid or relation_invalid
        tool_receipt_telemetry = _tool_receipt_projection(
            signal=receipt_signal,
            invalid=receipt_invalid,
            omitted_samples=receipt_omitted_samples,
            samples=valid_receipt_samples,
        )
        _validate_deadline_receipt_binding(
            runtime_dir,
            record,
            events[0]["data"],
            expected_spec,
        )
    return record, events, record_bytes, event_bytes, tool_receipt_telemetry


def validate_verifier_terminal_runtime(
    *,
    runtime_dir: Path,
    run_spec: Mapping[str, Any],
) -> VerifierTerminalRuntimeV1:
    """Validate a bound modern terminal failure without publishing artifacts."""

    record, _, record_bytes, _, _ = _validate_run_and_events(
        runtime_dir,
        run_spec,
    )
    if record["schema_version"] == LEGACY_RUN_SCHEMA or record[
        "terminal_status"
    ] not in {"provider_failure", "tool_failure", "deadline_failure"}:
        raise ArtifactError("verifier_terminal_runtime_ineligible")
    terminal_phase = record["terminal_phase"]
    if not isinstance(terminal_phase, str):
        raise ArtifactError("verifier_terminal_runtime_ineligible")
    return VerifierTerminalRuntimeV1(
        schema_version=str(record["schema_version"]),
        run_id=str(record["run_id"]),
        trial_id=str(record["trial_id"]),
        attempt_id=str(record["attempt_id"]),
        run_spec_sha256=str(record["run_spec_sha256"]),
        terminal_status=str(record["terminal_status"]),
        terminal_phase=terminal_phase,
        terminal_code=str(record["terminal_code"]),
        run_record_sha256=hashlib.sha256(record_bytes).hexdigest(),
        events_sha256=str(record["events_sha256"]),
    )


def _atomic_publish(path: Path, content: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    if temporary.exists():
        raise ArtifactError("artifact_temp_exists")
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
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as error:
        temporary.unlink(missing_ok=True)
        raise ArtifactError("artifact_publish_failed") from error


_PRIVATE_EVIDENCE_LIMITS = {
    "runtime/run.json": _MAX_RECORD_BYTES,
    "runtime/events.jsonl": _MAX_EVENTS_BYTES,
    "runtime/deadline.json": _MAX_RECEIPT_BYTES,
    "runtime-stderr.json": _MAX_RECEIPT_BYTES,
    "runtime-emergency.json": _MAX_RECEIPT_BYTES,
    "runtime-background-manifest.json": _MAX_RECEIPT_BYTES,
    "runtime-background-liveness-v1.json": _MAX_RECEIPT_BYTES,
    "workspace-before.json": _MAX_EVENTS_BYTES,
    "workspace-after.json": _MAX_EVENTS_BYTES,
    "workspace-delta.json": _MAX_EVENTS_BYTES,
    "workspace-diff.patch": _MAX_EVENTS_BYTES,
    "workspace-changed.tar": WORKSPACE_CHANGED_TAR_MAX_BYTES,
    "workspace-receipt.json": _MAX_RECEIPT_BYTES,
}


def _publish_from_private_control(
    *,
    source_dir: Path,
    publication_dir: Path,
    run_spec_sha256: str,
    generated: Mapping[str, bytes],
) -> Mapping[str, Path]:
    files: dict[str, bytes] = {}
    for name, limit in _PRIVATE_EVIDENCE_LIMITS.items():
        path = source_dir / name
        if path.exists() or path.is_symlink():
            files[name] = _read_regular(
                path,
                limit,
                "private_evidence_invalid",
            )
    files.update(generated)
    try:
        plane = ControlPlane.open(
            source_dir,
            publication_dir,
            run_spec_sha256=run_spec_sha256,
        )
        return plane.publish(files)
    except ControlPlaneError as error:
        raise ArtifactError(str(error)) from error


_GENERATED_PUBLICATION_NAMES = frozenset(
    {
        "agent-run.json",
        "trajectory.json",
        "partial-trajectory.json",
        "emergency-prefix.json",
        "runtime-usage-receipt.json",
    }
)


def _publish_generated_direct(
    *,
    logs_dir: Path,
    generated: Mapping[str, bytes],
) -> Mapping[str, Path]:
    if "agent-run.json" not in generated or not set(generated) <= (
        _GENERATED_PUBLICATION_NAMES
    ):
        raise ArtifactError("artifact_publication_set_invalid")
    paths = {name: logs_dir / name for name in generated}
    marker_path = paths["agent-run.json"]
    if marker_path.exists() or marker_path.is_symlink():
        for name, payload in generated.items():
            if (
                _read_regular(
                    paths[name],
                    _MAX_EVENTS_BYTES,
                    "existing_publication_invalid",
                )
                != payload
            ):
                raise ArtifactError("existing_publication_mismatch")
        unexpected = _GENERATED_PUBLICATION_NAMES - set(generated)
        if any((logs_dir / name).exists() for name in unexpected):
            raise ArtifactError("existing_publication_mismatch")
        return paths
    if any((logs_dir / name).exists() for name in _GENERATED_PUBLICATION_NAMES):
        raise ArtifactError("uncommitted_trajectory_exists")
    for name in sorted(generated):
        if name != "agent-run.json":
            _atomic_publish(paths[name], generated[name])
    _atomic_publish(marker_path, generated["agent-run.json"])
    return paths


def _usage_receipt(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": USAGE_RECEIPT_SCHEMA,
        "run_id": record["run_id"],
        "trial_id": record["trial_id"],
        "attempt_id": record["attempt_id"],
        "run_spec_sha256": record["run_spec_sha256"],
        "events_sha256": record["events_sha256"],
        "provider_call_coverage": record["provider_call_coverage"],
        "usage_totals": record["usage_totals"],
    }


def _validate_emergency_receipt(
    logs_dir: Path,
    run_spec: Mapping[str, Any],
) -> dict[str, Any]:
    raw = _read_regular(
        logs_dir / "runtime-emergency.json",
        _MAX_RECEIPT_BYTES,
        "emergency_receipt_missing_or_invalid",
    )
    value = _load_json(raw, "emergency_receipt_json_invalid")
    keys = {
        "schema_version",
        "run_id",
        "trial_id",
        "attempt_id",
        "run_spec_sha256",
        "status",
        "code",
        "bridge_completed",
        "events_sha256",
        "events_byte_length",
    }
    if (
        not isinstance(value, dict)
        or set(value) != keys
        or value["schema_version"] != "nano-runtime-emergency-v1"
        or value["status"] != "runtime_record_missing"
        or not _is_string(value["code"])
        or not isinstance(value["bridge_completed"], bool)
        or value["run_spec_sha256"] != rust_run_spec_sha256(run_spec)
        or any(
            value[field] != run_spec[field]
            for field in ("run_id", "trial_id", "attempt_id")
        )
        or raw != canonical_json(value)
    ):
        raise ArtifactError("emergency_receipt_invalid")
    events_sha256 = value["events_sha256"]
    events_byte_length = value["events_byte_length"]
    if (events_sha256 is None) != (events_byte_length is None):
        raise ArtifactError("emergency_receipt_invalid")
    if events_sha256 is not None and (
        not _is_sha256(events_sha256) or not _is_uint(events_byte_length)
    ):
        raise ArtifactError("emergency_receipt_invalid")
    return value


def _valid_prefix_relation(
    event: Mapping[str, Any],
    *,
    provider_states: dict[int, str],
    tool_states: dict[str, tuple[str, str, bool]],
    assistant_final_seen: bool,
) -> tuple[bool, bool]:
    event_type = event["type"]
    data = event["data"]
    if event_type == "provider.requested":
        turn_index = data["turn_index"]
        if turn_index in provider_states:
            return False, assistant_final_seen
        provider_states[turn_index] = "in_flight"
    elif event_type in {"provider.completed", "provider.failed"}:
        turn_index = data["turn_index"]
        if provider_states.get(turn_index) != "in_flight":
            return False, assistant_final_seen
        provider_states[turn_index] = event_type.removeprefix("provider.")
    elif event_type == "tool.registered":
        call_id = data["call_id"]
        if call_id in tool_states:
            return False, assistant_final_seen
        try:
            arguments = _load_json(
                data["arguments_json"].encode("utf-8"),
                "emergency_tool_arguments_invalid",
            )
        except ArtifactError:
            return False, assistant_final_seen
        if not isinstance(arguments, dict):
            return False, assistant_final_seen
        tool_states[call_id] = (data["provider_name"], "in_flight", False)
    elif event_type == "tool.dispatched":
        call_id = data["call_id"]
        state = tool_states.get(call_id)
        if (
            state is None
            or state[0] != data["provider_name"]
            or state[1] != "in_flight"
            or state[2]
        ):
            return False, assistant_final_seen
        tool_states[call_id] = (state[0], state[1], True)
    elif event_type in {"tool.completed", "tool.failed"}:
        call_id = data["call_id"]
        state = tool_states.get(call_id)
        if (
            state is None
            or state[0] != data["provider_name"]
            or state[1] != "in_flight"
        ):
            return False, assistant_final_seen
        tool_states[call_id] = (
            state[0],
            event_type.removeprefix("tool."),
            state[2],
        )
    elif event_type == "assistant.final":
        if assistant_final_seen:
            return False, assistant_final_seen
        assistant_final_seen = True
    return True, assistant_final_seen


def _read_emergency_prefix(
    logs_dir: Path,
    run_spec: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> tuple[
    list[dict[str, Any]],
    bytes,
    bytes,
    str,
    Mapping[str, Any] | None,
]:
    events_path = logs_dir / "runtime" / "events.jsonl"
    if receipt["events_sha256"] is None:
        if events_path.exists():
            raise ArtifactError("emergency_event_binding_mismatch")
        return [], b"", b"", "event_log_missing", None
    raw = _read_regular(
        events_path,
        _MAX_EVENTS_BYTES,
        "emergency_event_log_missing_or_invalid",
    )
    if (
        len(raw) != receipt["events_byte_length"]
        or hashlib.sha256(raw).hexdigest() != receipt["events_sha256"]
    ):
        raise ArtifactError("emergency_event_binding_mismatch")

    chunks = raw.splitlines(keepends=True)
    events: list[dict[str, Any]] = []
    accepted = bytearray()
    previous_elapsed = -1
    provider_states: dict[int, str] = {}
    tool_states: dict[str, tuple[str, str, bool]] = {}
    registered_tools: list[str] = []
    valid_receipt_samples: list[ToolReceiptTelemetrySample] = []
    previous_receipt_ordinal = 0
    receipt_signal = False
    receipt_invalid = False
    receipt_omitted_samples = 0
    receipt_suffix_started = False
    assistant_final_seen = False
    terminal_seen = False
    stop_reason = "missing_terminal"
    observed_event_schema: str | None = None
    for seq, chunk in enumerate(chunks):
        if not chunk.endswith(b"\n"):
            stop_reason = "incomplete_event_line"
            break
        try:
            event, advisory_issue = _load_event_json(
                chunk,
                "emergency_event_json_invalid",
            )
            event_type = event.get("type") if isinstance(event, dict) else None
            data = event.get("data") if isinstance(event, dict) else None
            event_schema = (
                event.get("schema_version") if isinstance(event, dict) else None
            )
            if (
                not isinstance(event, dict)
                or set(event) != _EVENT_KEYS
                or event_schema not in {PREVIOUS_EVENT_SCHEMA, EVENT_SCHEMA}
                or observed_event_schema is not None
                and event_schema != observed_event_schema
                or not _is_uint(event["seq"])
                or event["seq"] != seq
                or not isinstance(event_type, str)
                or event_type not in _EVENT_TYPES
                or (not isinstance(data, dict) and event_type != "tool.receipt")
                or any(
                    event[field] != run_spec[field]
                    for field in ("run_id", "trial_id", "attempt_id")
                )
                or not _is_uint(event["elapsed_ms"])
                or event["elapsed_ms"] < previous_elapsed
                or terminal_seen
            ):
                raise ArtifactError("emergency_event_invalid")
            assert isinstance(event_schema, str)
            observed_event_schema = event_schema
            if receipt_suffix_started and event_type not in {
                "tool.receipt",
                "run.completed",
                "run.failed",
            }:
                receipt_invalid = True
            if event_type == "tool.receipt":
                receipt_signal = True
                receipt_suffix_started = True
                sample = (
                    _parse_tool_receipt_sample(
                        data,
                        event_schema=event_schema,
                    )
                    if isinstance(data, dict) and not advisory_issue
                    else None
                )
                relation_valid = sample is not None
                if relation_valid and sample is not None:
                    ordinal = sample.tool_call_ordinal
                    call_id = (
                        registered_tools[ordinal - 1]
                        if ordinal <= len(registered_tools)
                        else None
                    )
                    state = tool_states.get(call_id) if call_id is not None else None
                    relation_valid = bool(
                        ordinal > previous_receipt_ordinal
                        and call_id is not None
                        and state is not None
                        and state[1] in {"completed", "failed"}
                        and _bounded_identity(call_id)
                        and _bounded_identity(state[0])
                        and sample.tool_identity_sha256
                        == _tool_identity_sha256(call_id, state[0])
                        and len(valid_receipt_samples) < _MAX_TOOL_RECEIPT_SAMPLES
                    )
                    if relation_valid:
                        previous_receipt_ordinal = ordinal
                        valid_receipt_samples.append(sample)
                if not relation_valid:
                    receipt_invalid = True
                    event["data"] = {}
                elif sample is not None:
                    event["data"] = sample.as_dict()
            else:
                omitted_field = _receipt_omitted_field(event_schema)
                present_omitted_fields = (
                    _TOOL_RECEIPT_OMITTED_FIELDS & set(data)
                    if isinstance(data, dict)
                    else set()
                )
                if present_omitted_fields:
                    receipt_signal = True
                    omitted_samples = _positive_u64(
                        data.get(omitted_field) if omitted_field is not None else None
                    )
                    if (
                        present_omitted_fields != {omitted_field}
                        or event_type not in {"run.completed", "run.failed"}
                        or omitted_samples is None
                        or advisory_issue
                    ):
                        receipt_invalid = True
                    else:
                        receipt_omitted_samples = omitted_samples
                    data = dict(data)
                    for field in _TOOL_RECEIPT_OMITTED_FIELDS:
                        data.pop(field, None)
                    event["data"] = data
                elif advisory_issue:
                    receipt_signal = True
                    receipt_invalid = True
                _validate_v2_event_data(event_type, event["data"])
            if seq == 0:
                started = event["data"]
                contract = run_spec["contract"]
                if (
                    event["type"] != "run.started"
                    or started["task_id"] != run_spec["task"]["id"]
                    or started["contract_id"] != contract["id"]
                    or started["profile_id"] != contract["profile_id"]
                    or started["contract_set_sha256"] != contract["contract_set_sha256"]
                    or started["model"] != run_spec["provider"]["model"]
                    or started["run_spec_sha256"] != rust_run_spec_sha256(run_spec)
                ):
                    raise ArtifactError("emergency_run_started_invalid")
            elif event["type"] == "run.started":
                raise ArtifactError("emergency_duplicate_run_started")
            valid, assistant_final_seen = _valid_prefix_relation(
                event,
                provider_states=provider_states,
                tool_states=tool_states,
                assistant_final_seen=assistant_final_seen,
            )
            if not valid:
                raise ArtifactError("emergency_event_relation_invalid")
            if event_type == "tool.registered":
                registered_tools.append(event["data"]["call_id"])
        except ArtifactError:
            stop_reason = "invalid_event_after_prefix"
            break
        previous_elapsed = event["elapsed_ms"]
        terminal_seen = event["type"] in {"run.completed", "run.failed"}
        events.append(event)
        accepted.extend(chunk)
    else:
        if terminal_seen:
            stop_reason = "terminal_event_without_run_record"
    if receipt_suffix_started and not terminal_seen:
        receipt_invalid = True
    tool_receipt_telemetry = _tool_receipt_projection(
        signal=receipt_signal,
        invalid=receipt_invalid,
        omitted_samples=receipt_omitted_samples,
        samples=tuple(valid_receipt_samples),
    )
    return events, raw, bytes(accepted), stop_reason, tool_receipt_telemetry


def _emergency_usage(
    events: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    requested = 0
    completed = 0
    failed = 0
    usage_present = 0
    usage_absent = 0
    cost_present = 0
    cost_absent = 0
    input_tokens = 0
    cached_input_tokens = 0
    output_tokens = 0
    provider_cost_ticks = 0
    invalid = False
    maximum = 2**64 - 1

    def add(current: int, value: int) -> int:
        nonlocal invalid
        total = current + value
        if total > maximum:
            invalid = True
            return maximum
        return total

    for event in events:
        data = event["data"]
        if event["type"] == "provider.requested":
            requested += 1
            continue
        if event["type"] == "provider.failed":
            failed += 1
            usage = data.get("response_usage")
        elif event["type"] == "provider.completed":
            completed += 1
            usage = data["usage"]
        else:
            continue
        input_value = usage.get("input_tokens") if isinstance(usage, dict) else None
        output_value = usage.get("output_tokens") if isinstance(usage, dict) else None
        if _is_uint(input_value) and _is_uint(output_value):
            details = usage.get("input_tokens_details", {})
            cached_value = (
                details.get("cached_tokens", 0) if isinstance(details, dict) else 0
            )
            cached = cached_value if _is_uint(cached_value) else 0
            usage_present += 1
            input_tokens = add(input_tokens, input_value)
            cached_input_tokens = add(cached_input_tokens, cached)
            output_tokens = add(output_tokens, output_value)
        else:
            usage_absent += 1
            invalid = invalid or usage is not None
        cost_value = (
            usage.get("provider_cost_ticks", usage.get("cost_ticks"))
            if isinstance(usage, dict)
            else None
        )
        if cost_value is None:
            cost_absent += 1
        elif _is_uint(cost_value):
            cost_present += 1
            provider_cost_ticks = add(provider_cost_ticks, cost_value)
        else:
            cost_absent += 1
            invalid = True
    in_flight = requested - completed - failed
    if in_flight < 0:
        raise ArtifactError("emergency_provider_coverage_invalid")
    if invalid:
        state = "invalid"
    elif requested == 0:
        state = "unavailable"
    elif in_flight or usage_present != requested:
        state = "partial"
    else:
        state = "complete"
    coverage = {
        "requested": requested,
        "completed": completed,
        "failed": failed,
        "in_flight": in_flight,
        "usage_present": usage_present,
        "usage_absent": usage_absent,
        "usage_covered": usage_present,
        "cost_present": cost_present,
        "cost_absent": cost_absent,
        "state": state,
    }
    totals = {
        "input_tokens": input_tokens if usage_present else None,
        "cached_input_tokens": cached_input_tokens if usage_present else None,
        "output_tokens": output_tokens if usage_present else None,
        "provider_cost_ticks": provider_cost_ticks if cost_present else None,
    }
    return coverage, totals


def _emergency_terminal(code: str) -> tuple[str, str, str]:
    if code == "adapter_cancelled":
        return "cancelled", "cancellation", code
    if "deadline" in code or "timeout" in code:
        return "deadline_failure", "deadline", code
    if code == "runtime_record_missing_after_bridge_completion":
        return "runtime_failure", "artifact", code
    if code.startswith(("external_bridge", "terminal_actor")):
        return "tool_failure", "bridge", code
    return "runtime_failure", "runtime", code


def _atif_eligibility(
    *,
    publication_kind: str,
    terminal_status: str,
    terminal_code: str,
    trajectory_name: str,
    trajectory_sha256: str,
    pinned_harbor_validated: bool,
) -> AtifEligibility:
    """Classify judgeability without consulting reward or workspace quality."""

    if publication_kind in {"success_atif", "failure_atif", "emergency_atif"}:
        if pinned_harbor_validated:
            return AtifEligibility(
                leaderboard_eligible=True,
                conformance="pinned_harbor_valid",
                trajectory_path=trajectory_name,
                trajectory_sha256=trajectory_sha256,
                ineligibility_reason=None,
            )
        return AtifEligibility(
            leaderboard_eligible=False,
            conformance="minimal_atif_only",
            trajectory_path=None,
            trajectory_sha256=None,
            ineligibility_reason="pinned_harbor_validation_not_requested",
        )
    return AtifEligibility(
        leaderboard_eligible=False,
        conformance="diagnostic_only",
        trajectory_path=None,
        trajectory_sha256=None,
        ineligibility_reason=(f"runtime_not_success:{terminal_status}:{terminal_code}"),
    )


def _publish_emergency_artifacts(
    *,
    logs_dir: Path,
    publication_dir: Path | None,
    run_spec: Mapping[str, Any],
    instruction: str,
    agent_name: str,
    agent_version: str,
    model_name: str,
    background: BackgroundManifestReceipt | None,
    require_harbor_validator: bool,
) -> ArtifactPublication:
    receipt = _validate_emergency_receipt(logs_dir, run_spec)
    (
        events,
        source_bytes,
        prefix_bytes,
        stop_reason,
        tool_receipt_telemetry,
    ) = _read_emergency_prefix(logs_dir, run_spec, receipt)
    coverage, totals = _emergency_usage(events)
    terminal_status, terminal_phase, terminal_code = _emergency_terminal(
        receipt["code"]
    )
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    prefix_sha256 = hashlib.sha256(prefix_bytes).hexdigest()
    identity = {
        "run_id": run_spec["run_id"],
        "trial_id": run_spec["trial_id"],
        "attempt_id": run_spec["attempt_id"],
        "run_spec_sha256": rust_run_spec_sha256(run_spec),
    }
    diagnostic = project_emergency_prefix(
        instruction=instruction,
        events=events,
        identity=identity,
        terminal_status=terminal_status,
        terminal_phase=terminal_phase,
        terminal_code=terminal_code,
        usage_coverage=coverage,
        usage_totals=totals,
        source_events_sha256=source_sha256,
        source_events_byte_length=len(source_bytes),
        validated_prefix_sha256=prefix_sha256,
        validated_prefix_byte_length=len(prefix_bytes),
        stop_reason=stop_reason,
        agent_name=agent_name,
        agent_version=agent_version,
        model_name=model_name,
    )
    trajectory = project_emergency_trajectory(
        instruction=instruction,
        events=events,
        identity=identity,
        terminal_status=terminal_status,
        terminal_phase=terminal_phase,
        terminal_code=terminal_code,
        usage_coverage=coverage,
        usage_totals=totals,
        source_events_sha256=source_sha256,
        source_events_byte_length=len(source_bytes),
        validated_prefix_sha256=prefix_sha256,
        validated_prefix_byte_length=len(prefix_bytes),
        stop_reason=stop_reason,
        agent_name=agent_name,
        agent_version=agent_version,
        model_name=model_name,
    )
    if require_harbor_validator:
        validate_with_pinned_harbor(trajectory)
    trajectory_bytes = canonical_json(trajectory)
    trajectory_path = logs_dir / "trajectory.json"
    trajectory_sha256 = hashlib.sha256(trajectory_bytes).hexdigest()
    diagnostic_bytes = canonical_json(diagnostic)
    diagnostic_path = logs_dir / "emergency-prefix.json"
    diagnostic_sha256 = hashlib.sha256(diagnostic_bytes).hexdigest()
    usage_receipt_path = logs_dir / "runtime-usage-receipt.json"
    usage_receipt = {
        "schema_version": USAGE_RECEIPT_SCHEMA,
        **identity,
        "events_sha256": source_sha256,
        "provider_call_coverage": coverage,
        "usage_totals": totals,
    }
    usage_receipt_bytes = canonical_json(usage_receipt)
    marker: dict[str, Any] = {
        "schema_version": TERMINAL_ATIF_MARKER_SCHEMA,
        "publication_kind": "emergency_atif",
        **identity,
        "run_record_schema": None,
        "events_sha256": source_sha256,
        "terminal_status": terminal_status,
        "terminal_phase": terminal_phase,
        "terminal_code": terminal_code,
        "trajectory_path": trajectory_path.name,
        "trajectory_sha256": trajectory_sha256,
        "diagnostic_path": diagnostic_path.name,
        "diagnostic_sha256": diagnostic_sha256,
        "usage_receipt_sha256": hashlib.sha256(usage_receipt_bytes).hexdigest(),
    }
    if background is not None:
        marker["background_manifest_sha256"] = background.sha256
        marker["background_task_count"] = background.task_count
    workspace_receipt_path = logs_dir / "workspace-receipt.json"
    if workspace_receipt_path.exists():
        workspace_receipt_bytes = _read_regular(
            workspace_receipt_path,
            _MAX_RECEIPT_BYTES,
            "workspace_receipt_invalid",
        )
        marker["workspace_receipt_sha256"] = hashlib.sha256(
            workspace_receipt_bytes
        ).hexdigest()
    marker_bytes = canonical_json(marker)
    marker_path = logs_dir / "agent-run.json"
    generated = {
        usage_receipt_path.name: usage_receipt_bytes,
        trajectory_path.name: trajectory_bytes,
        diagnostic_path.name: diagnostic_bytes,
        marker_path.name: marker_bytes,
    }
    if publication_dir is not None:
        published = _publish_from_private_control(
            source_dir=logs_dir,
            publication_dir=publication_dir,
            run_spec_sha256=identity["run_spec_sha256"],
            generated=generated,
        )
    else:
        published = _publish_generated_direct(
            logs_dir=logs_dir,
            generated=generated,
        )
    trajectory_path = published[trajectory_path.name]
    diagnostic_path = published[diagnostic_path.name]
    usage_receipt_path = published[usage_receipt_path.name]
    marker_path = published[marker_path.name]
    return ArtifactPublication(
        trajectory_path=trajectory_path,
        marker_path=marker_path,
        trajectory=trajectory,
        context=usage_context(trajectory),
        marker_bytes=marker_bytes,
        background_manifest=background,
        publication_kind="emergency_atif",
        success_artifact_valid=False,
        diagnostic_package_valid=True,
        atif_eligibility=_atif_eligibility(
            publication_kind="emergency_atif",
            terminal_status=terminal_status,
            terminal_code=terminal_code,
            trajectory_name=trajectory_path.name,
            trajectory_sha256=trajectory_sha256,
            pinned_harbor_validated=require_harbor_validator,
        ),
        usage_receipt_path=usage_receipt_path,
        usage_coverage=coverage,
        tool_receipt_telemetry=tool_receipt_telemetry,
    )


def publish_artifacts(
    *,
    logs_dir: Path,
    publication_dir: Path | None = None,
    run_spec: Mapping[str, Any],
    instruction: str,
    agent_name: str,
    agent_version: str,
    model_name: str,
    require_harbor_validator: bool = True,
    require_background_manifest: bool = False,
) -> ArtifactPublication:
    """Publish evidence files, then ``agent-run.json`` as the sole commit marker."""

    runtime_dir = logs_dir / "runtime"
    background_path = logs_dir / "runtime-background-manifest.json"
    background = (
        validate_background_manifest(logs_dir=logs_dir, run_spec=run_spec)
        if require_background_manifest or background_path.exists()
        else None
    )
    run_record_path = runtime_dir / "run.json"
    if not run_record_path.exists():
        return _publish_emergency_artifacts(
            logs_dir=logs_dir,
            publication_dir=publication_dir,
            run_spec=run_spec,
            instruction=instruction,
            agent_name=agent_name,
            agent_version=agent_version,
            model_name=model_name,
            background=background,
            require_harbor_validator=require_harbor_validator,
        )
    record, events, _, _, tool_receipt_telemetry = _validate_run_and_events(
        runtime_dir,
        run_spec,
    )
    legacy = record["schema_version"] == LEGACY_RUN_SCHEMA
    success = record["terminal_status"] == "success"
    diagnostic_name: str | None = None
    diagnostic_bytes: bytes | None = None
    if success:
        publication_kind = "success_atif"
        trajectory_name = "trajectory.json"
        trajectory = project_trajectory(
            instruction=instruction,
            events=events,
            run_record=record,
            agent_name=agent_name,
            agent_version=agent_version,
            model_name=model_name,
        )
        if require_harbor_validator:
            validate_with_pinned_harbor(trajectory)
    else:
        publication_kind = "failure_atif"
        trajectory_name = "trajectory.json"
        diagnostic_name = "partial-trajectory.json"
        diagnostic = project_partial_trajectory(
            instruction=instruction,
            events=events,
            run_record=record,
            agent_name=agent_name,
            agent_version=agent_version,
            model_name=model_name,
        )
        diagnostic_bytes = canonical_json(diagnostic)
        trajectory = project_failure_trajectory(
            instruction=instruction,
            events=events,
            run_record=record,
            agent_name=agent_name,
            agent_version=agent_version,
            model_name=model_name,
        )
        if require_harbor_validator:
            validate_with_pinned_harbor(trajectory)
    trajectory_bytes = canonical_json(trajectory)
    trajectory_sha256 = hashlib.sha256(trajectory_bytes).hexdigest()
    usage_receipt_path: Path | None = None
    usage_receipt_bytes: bytes | None = None
    if legacy:
        marker = {
            "schema_version": LEGACY_MARKER_SCHEMA,
            "run_id": record["run_id"],
            "trial_id": record["trial_id"],
            "attempt_id": record["attempt_id"],
            "run_spec_sha256": record["run_spec_sha256"],
            "events_sha256": record["events_sha256"],
            "trajectory_sha256": trajectory_sha256,
        }
    else:
        usage_receipt_path = logs_dir / "runtime-usage-receipt.json"
        usage_receipt_bytes = canonical_json(_usage_receipt(record))
        v3 = record["schema_version"] == RUN_V3_SCHEMA
        marker = {
            "schema_version": (
                (MARKER_V3_SCHEMA if v3 else MARKER_SCHEMA)
                if success
                else TERMINAL_ATIF_MARKER_SCHEMA
            ),
            "publication_kind": publication_kind,
            "run_id": record["run_id"],
            "trial_id": record["trial_id"],
            "attempt_id": record["attempt_id"],
            "run_spec_sha256": record["run_spec_sha256"],
            "run_record_schema": record["schema_version"],
            "events_sha256": record["events_sha256"],
            "terminal_status": record["terminal_status"],
            "terminal_phase": record["terminal_phase"],
            "terminal_code": record["terminal_code"],
            "trajectory_path": trajectory_name,
            "trajectory_sha256": trajectory_sha256,
            "usage_receipt_sha256": hashlib.sha256(usage_receipt_bytes).hexdigest(),
        }
        if diagnostic_name is not None and diagnostic_bytes is not None:
            marker["diagnostic_path"] = diagnostic_name
            marker["diagnostic_sha256"] = hashlib.sha256(diagnostic_bytes).hexdigest()
        if v3:
            marker[_DEADLINE_RECEIPT_FIELD] = record[_DEADLINE_RECEIPT_FIELD]
    if background is not None:
        marker["background_manifest_sha256"] = background.sha256
        marker["background_task_count"] = background.task_count
    workspace_receipt_path = logs_dir / "workspace-receipt.json"
    if not legacy and workspace_receipt_path.exists():
        workspace_receipt_bytes = _read_regular(
            workspace_receipt_path,
            _MAX_RECEIPT_BYTES,
            "workspace_receipt_invalid",
        )
        marker["workspace_receipt_sha256"] = hashlib.sha256(
            workspace_receipt_bytes
        ).hexdigest()
    marker_bytes = canonical_json(marker)
    trajectory_path = logs_dir / trajectory_name
    marker_path = logs_dir / "agent-run.json"
    generated = {
        trajectory_path.name: trajectory_bytes,
        marker_path.name: marker_bytes,
    }
    if diagnostic_name is not None and diagnostic_bytes is not None:
        generated[diagnostic_name] = diagnostic_bytes
    if usage_receipt_path is not None and usage_receipt_bytes is not None:
        generated[usage_receipt_path.name] = usage_receipt_bytes
    if publication_dir is not None:
        published = _publish_from_private_control(
            source_dir=logs_dir,
            publication_dir=publication_dir,
            run_spec_sha256=str(record["run_spec_sha256"]),
            generated=generated,
        )
    else:
        published = _publish_generated_direct(
            logs_dir=logs_dir,
            generated=generated,
        )
    trajectory_path = published[trajectory_path.name]
    marker_path = published[marker_path.name]
    if usage_receipt_path is not None:
        usage_receipt_path = published[usage_receipt_path.name]
    return ArtifactPublication(
        trajectory_path=trajectory_path,
        marker_path=marker_path,
        trajectory=trajectory,
        context=usage_context(trajectory),
        marker_bytes=marker_bytes,
        background_manifest=background,
        publication_kind=publication_kind,
        success_artifact_valid=success,
        diagnostic_package_valid=True,
        atif_eligibility=_atif_eligibility(
            publication_kind=publication_kind,
            terminal_status=str(record["terminal_status"]),
            terminal_code=str(record["terminal_code"]),
            trajectory_name=trajectory_name,
            trajectory_sha256=trajectory_sha256,
            pinned_harbor_validated=require_harbor_validator,
        ),
        usage_receipt_path=usage_receipt_path,
        usage_coverage=(None if legacy else dict(record["provider_call_coverage"])),
        tool_receipt_telemetry=tool_receipt_telemetry,
    )
