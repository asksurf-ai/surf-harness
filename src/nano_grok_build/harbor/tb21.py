"""Thin Terminal-Bench 2.1 runner and deterministic result collector."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
import tomllib
from collections import Counter
from collections.abc import Mapping, MutableMapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import uuid4

from nano_grok_build.adapter.artifactizer import (
    ArtifactError,
    run_event_elapsed_bounds_valid,
    rust_run_spec_sha256,
    validate_background_manifest,
)
from nano_grok_build.adapter.atif import (
    AtifError,
    validate_minimal_trajectory,
    validate_with_pinned_harbor,
)
from nano_grok_build.adapter.deadline import (
    DeadlineContractError,
    RunDeadlineReceiptV1,
)
from nano_grok_build.adapter.terminal_actor import (
    SnapshotFailureSubtypeV1,
)
from nano_grok_build.adapter.workspace_snapshot import (
    WorkspaceSnapshotError,
    load_workspace_receipt,
)
from nano_grok_build.harbor import git_history_audit, protected_target
from nano_grok_build.harbor.compat_v020 import HARBOR_VERSION, RuntimeInputs
from nano_grok_build.harbor.dispatch import create_bound_job, load_runtime_inputs
from nano_grok_build.harbor.git_history_capability import (
    compile_git_history_capability,
)
from nano_grok_build.harbor.live_smoke import (
    HARBOR_COMMIT,
    LIVE_MODEL,
    select_runtime_binary,
)
from nano_grok_build.harbor.prelaunch import (
    PrelaunchError,
    admit_contract,
    admit_prelaunch,
    verify_docker_image_bindings,
)
from nano_grok_build.harbor.provider import HostProviderLaunch
from nano_grok_build.harbor.runtime_entry import (
    RUNTIME_ENTRY_NAME,
    RuntimeEntryError,
    load_runtime_entry,
)

TB21_SOURCE_COMMIT = "5c8eadf1f393183288fa08b8f73ca9a469cc5e00"
TB21_SOURCE_TREE = "49ca0b26221536dd9f60d8e66938873bda4bf37b"
TB21_SOURCE_REPOSITORY = "https://github.com/harbor-framework/terminal-bench-2-1.git"
HARBOR_TREE = "09557fdc853ce5826f5b69643034ac20d1ff80b6"
HARBOR_REPOSITORY = "https://github.com/harbor-framework/harbor.git"
TB21_DATASET_REF = (
    "sha256:7d7bdc1cbedad549fc1140404bd4dc45e5fd0ea7c4186773687d177ad3a0699a"
)
TB21_DATASET = "terminal-bench/terminal-bench-2-1"
TB21_TASK_COUNT = 89
TB21_MAX_TURNS = 64
OFFICIAL_TASK_CHECKSUMS_SCHEMA = "tb21-official-task-checksums-v1"
OFFICIAL_TASK_CHECKSUMS_PATH = Path("evaluation/tb21-2-1-task-checksums.json")
LEADERBOARD_AGENT = "nano-grok-build"
LEADERBOARD_MODEL = f"xai/{LIVE_MODEL}"
DEFAULT_CONCURRENCY = 4
TERMINALIZATION_SCHEMA = "nano-tb21-terminalization-v1"
INTERRUPTION_TERMINALIZATION_SCHEMA = "nano-tb21-terminalization-v2"
ALLOWED_CONCURRENCY = (1, 2, 4, 8)
ACTIVE_TOOLS = (
    "run_terminal_command",
    "read_file",
    "search_replace",
    "write",
    "list_dir",
    "grep",
    "kill_terminal_command",
    "get_terminal_command_output",
)
SUMMARY_SCHEMA_V6 = "nano-tb21-baseline-summary-v6"
ROW_SCHEMA_V6 = "nano-tb21-row-v6"
SUMMARY_SCHEMA = "nano-tb21-baseline-summary-v7"
ROW_SCHEMA = "nano-tb21-row-v7"
COHORT_SCHEMA = "nano-tb21-cohort-v1"
PRICING_SCHEMA = "nano-token-pricing-v1"
CAPABILITY_MANIFEST_SCHEMA = "nano-tb21-capability-manifest-v1"
CAPABILITY_PROBE_SCHEMA = "nano-generic-capability-probe-v1"
CAPABILITY_PROBE_MAX_BYTES = 64 * 1024
INVENTORY_AUTHORITY_SCHEMA = "nano-tb21-inventory-authority-v1"
PUBLIC_TASK_METADATA_SCHEMA = "nano-public-task-metadata-v1"
_PUBLIC_TASK_METADATA_PATHS = (
    "environment/Dockerfile",
    "instruction.md",
    "task.toml",
)
USD_TICKS_PER_USD = 10_000_000_000
_MAX_JSON_BYTES = 64 * 1024 * 1024
_SAFE_TASK_ID = re.compile(r"^terminal-bench/[a-z0-9][a-z0-9.-]*$")
_CAPABILITY_VERSION = re.compile(
    r"^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){0,3}$"
)
_CAPABILITY_SECRET_FRAGMENTS = ("AUTHORIZATION", "KEY", "SECRET", "TOKEN")
_CAPABILITY_STATES = frozenset({"present", "missing", "unknown"})
_CAPABILITY_CAPTURE_STATES = _CAPABILITY_STATES | {"invalid"}
_CAPABILITY_ARCHITECTURES = frozenset({"aarch64", "x86_64"})
_CAPABILITY_CPU_FEATURES = frozenset({"avx", "avx2", "neon", "sse4_2"})
_CAPABILITY_DEPENDENCIES = frozenset({"docker", "git"})
_CAPABILITY_RUNTIMES = frozenset({"node", "python", "rust"})
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
_EVENT_TYPES = {
    "run.started",
    "provider.requested",
    "provider.completed",
    "provider.failed",
    "context.checkpointed",
    "context.checkpoint_rejected",
    "tool.registered",
    "tool.dispatched",
    "tool.completed",
    "tool.failed",
    "tool.receipt",
    "assistant.final",
    "run.completed",
    "run.failed",
}
_CONTEXT_CHECKPOINT_POLICY_VERSION = "fresh-context-checkpoint-v1"
_SEMANTIC_CHECKPOINT_POLICY_VERSION = "semantic-context-checkpoint-v1"
_SEMANTIC_CHECKPOINT_CAPSULE_SCHEMA = "semantic-checkpoint-capsule-v1"
_SEMANTIC_CHECKPOINT_ACTION_TURN_CAP = 40
_SEMANTIC_CHECKPOINT_POST_ACTION_PROVIDER_RESPONSES = 6
_CHECKPOINT_SOURCE_HISTORY_FIELD = "checkpoint_source_history_sha256"
_CONTEXT_CHECKPOINT_KEYS = {
    "policy_version",
    "source_history_sha256",
    "checkpoint_history_sha256",
    "source_history_items",
    "checkpoint_history_items",
    "provider_turn_count",
    "tool_call_count",
    "observed_input_tokens",
}
_SEMANTIC_CONTEXT_CHECKPOINT_KEYS = _CONTEXT_CHECKPOINT_KEYS | {
    "capsule_schema_version",
    "capsule_sha256",
    "capsule_bytes",
    "prepare_turn_index",
    "prepare_history_sha256",
    "action_turn_cutoff",
    "action_lease_ms",
    "tail_reserve_ms",
}
_CONTEXT_CHECKPOINT_REJECTED_KEYS = {
    "policy_version",
    "source_history_sha256",
    "prepare_history_sha256",
    "prepare_turn_index",
    "provider_turn_count",
    "reason",
    "request_emitted",
    "response_received",
}
_CONTEXT_CHECKPOINT_REJECTED_DIAGNOSTIC_KEYS = {
    "capsule_content_sha256",
    "capsule_content_bytes",
    "capsule_content_excerpt",
}
_TOOL_RECEIPT_TELEMETRY_SCHEMA = "nano-tool-receipt-telemetry-v1"
_TOOL_RECEIPT_SCHEMA = "nano-tool-receipt-v1"
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
_TOOL_RECEIPT_PHASES = frozenset(
    {
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
)
_TOOL_RECEIPT_ORIGINS = frozenset({"semantic", "transport", "protocol", "actor"})
_TOOL_RECEIPT_PRIMARY_SUBTYPES = frozenset(
    {
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
)
_TOOL_RECEIPT_RECOVERY_SUBTYPES = frozenset(
    {
        "recovered_settled",
        "recovery_download_failed",
        "meta_invalid",
        "output_download_failed",
        "output_limit_exceeded",
        "cleanup_unverified",
        "actor_deadline_exceeded",
    }
)
_TOOL_RECEIPT_RECOVERY_PRIMARIES = frozenset(
    {"run_transport_timeout", "run_transport_failed", "run_response_nonzero"}
)
_TOOL_RECEIPT_MAX_SAMPLES = 256
_U64_MAX = (1 << 64) - 1
_V1_RUN_KEYS = {
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
_V2_RUN_KEYS = (_V1_RUN_KEYS - {"raw_usage"}) | {
    "terminal_phase",
    "provider_call_coverage",
    "usage_totals",
}
_DEADLINE_RUN_KEYS = _V2_RUN_KEYS | {"deadline_receipt_sha256"}
_RUN_RECORD_VARIANTS = {
    ("nano-run-record-alpha-1", frozenset(_V1_RUN_KEYS)): "legacy_v1",
    ("nano-run-record-v2", frozenset(_V2_RUN_KEYS)): "legacy_v2",
    (
        "nano-run-record-v2",
        frozenset(_DEADLINE_RUN_KEYS),
    ): "v2_deadline_compat",
    ("nano-run-record-v3", frozenset(_DEADLINE_RUN_KEYS)): "v3",
}
_V2_MARKER_REQUIRED_KEYS = {
    "schema_version",
    "publication_kind",
    "run_id",
    "trial_id",
    "attempt_id",
    "run_spec_sha256",
    "run_record_schema",
    "events_sha256",
    "terminal_status",
    "terminal_phase",
    "terminal_code",
    "trajectory_path",
    "trajectory_sha256",
    "usage_receipt_sha256",
}
_V2_MARKER_OPTIONAL_KEYS = {
    "background_manifest_sha256",
    "background_task_count",
    "workspace_receipt_sha256",
}
_V3_MARKER_REQUIRED_KEYS = _V2_MARKER_REQUIRED_KEYS | {
    "deadline_receipt_sha256",
}
_V4_TERMINAL_MARKER_REQUIRED_KEYS = _V2_MARKER_REQUIRED_KEYS | {
    "diagnostic_path",
    "diagnostic_sha256",
}
_V4_TERMINAL_MARKER_OPTIONAL_KEYS = _V2_MARKER_OPTIONAL_KEYS | {
    "deadline_receipt_sha256",
}
_USAGE_RECEIPT_KEYS = {
    "schema_version",
    "run_id",
    "trial_id",
    "attempt_id",
    "run_spec_sha256",
    "events_sha256",
    "provider_call_coverage",
    "usage_totals",
}
_WORKSPACE_ARTIFACT_NAMES = {
    "workspace-before.json",
    "workspace-after.json",
    "workspace-delta.json",
    "workspace-diff.patch",
    "workspace-changed.tar",
}
_INTERRUPTION_EVIDENCE_PATHS = (
    "result.json",
    "config.json",
    "agent/runtime/events.jsonl",
    "agent/runtime/run.json",
    "agent/runtime/deadline.json",
    "agent/agent-run.json",
    "agent/trajectory.json",
    "agent/partial-trajectory.json",
    "agent/emergency-prefix.json",
    "agent/runtime-emergency.json",
    "agent/runtime-usage-receipt.json",
    "agent/runtime-background-manifest.json",
    "agent/workspace-receipt.json",
    "agent/workspace-before.json",
    "agent/workspace-after.json",
    "agent/workspace-delta.json",
    "agent/workspace-diff.patch",
    "agent/workspace-changed.tar",
)
_FAILURE_BUCKETS = (
    "none",
    "agent_semantic",
    "provider",
    "action_deadline",
    "tool_transport",
    "background_lifecycle",
    "verifier_setup_network",
    "verifier_runtime",
    "verifier_timeout",
    "environment_infra",
    "artifact",
    "missing",
    "duplicate",
    "cancelled",
    "uncertain",
)
_INTERRUPTION_ROW_FAILURES = {
    "operator_interrupted": (
        "cancelled",
        "cancellation",
        "operator_interrupted",
        "recoverable",
    ),
    "runner_exception": (
        "environment_infra",
        "runtime",
        "runner_exception",
        "recoverable",
    ),
}
_VERIFIER_RESULT_KINDS = (
    "passed",
    "assertion_failed",
    "setup_failed",
    "timed_out",
    "runtime_failed",
    "completed_negative_unknown",
    "not_run",
    "invalid",
)
_PUBLICATION_KINDS = (
    "success_atif",
    "failure_partial",
    "emergency_prefix",
    "failure_atif",
    "emergency_atif",
)
_VERIFIER_INFRA_MARKERS = (
    "could not resolve host",
    "connection refused",
    "connection reset",
    "failed to download",
    "name or service not known",
    "network is unreachable",
    "temporary failure in name resolution",
    "the requested url returned error: 5",
    "synthetic url returned error: 5",
    "uvx: command not found",
    "uvx: not found",
    "pip: command not found",
    "pip: not found",
)
_VERIFIER_STRONG_SETUP_MARKERS = _VERIFIER_INFRA_MARKERS + (
    "sessionnotcreatedexception",
    "chrome instance exited",
    "connectionerror",
    "networkerror",
    "verifiersetuperror",
)


class TB21Error(RuntimeError):
    """A stable, credential-safe TB2.1 runner error."""


@dataclass(frozen=True)
class InventoryTask:
    task_id: str
    short_name: str
    path: Path
    task_digest: str
    source_sha256: str
    docker_image: str
    cpus: int | float
    memory_mb: int
    storage_mb: int | None
    gpus: int
    agent_timeout_sec: int
    verifier_timeout_sec: int


@dataclass(frozen=True)
class Pricing:
    as_of: str
    model: str
    input_per_million_usd: Decimal
    cached_input_per_million_usd: Decimal
    output_per_million_usd: Decimal
    source_sha256: str


@dataclass(frozen=True)
class _UsageTotals:
    input_tokens: int | None
    cache_tokens: int | None
    output_tokens: int | None
    call_count: int
    provider_cost_ticks: int
    provider_cost_ticks_covered_calls: int
    provider_cost_ticks_valid: bool
    requested_count: int
    completed_count: int
    failed_count: int
    in_flight_count: int
    usage_present_count: int
    usage_absent_count: int
    usage_covered_calls: int
    state: str
    source: str
    record_valid: bool


@dataclass(frozen=True)
class _EventPrefix:
    raw: bytes
    events: tuple[Mapping[str, Any], ...]
    requested_count: int
    completed_count: int
    failed_count: int
    in_flight_count: int
    usage_present_count: int
    usage_absent_count: int
    usage_covered_calls: int
    input_tokens: int
    cache_tokens: int
    output_tokens: int
    provider_cost_ticks: int
    provider_cost_ticks_covered_calls: int
    failed_usage_present_count: int
    failed_usage_absent_count: int
    failed_input_tokens: int
    failed_cache_tokens: int
    failed_output_tokens: int
    failed_provider_cost_ticks: int
    failed_provider_cost_ticks_covered_calls: int
    usage_valid: bool
    tool_receipt_samples: tuple[Mapping[str, object], ...]
    tool_receipt_coverage: str
    tool_receipt_omitted_samples: int
    tool_receipt_signal: bool


@dataclass(frozen=True)
class _EventPrefixRead:
    state: str
    raw: bytes | None
    prefix: _EventPrefix | None


@dataclass(frozen=True)
class _CostResult:
    value_usd: float | None
    source: str
    covered: bool


@dataclass(frozen=True)
class _RuntimeEvidence:
    terminal_status: str
    terminal_phase: str | None
    terminal_code: str
    provider_failure_code: str | None
    recoverability: str | None


@dataclass(frozen=True)
class _ParsedRunRecord:
    variant: str
    schema_version: str
    run_id: str
    trial_id: str
    attempt_id: str
    run_spec_sha256: str
    events_sha256: str
    deadline_receipt_sha256: str | None
    usage: _UsageTotals
    runtime: _RuntimeEvidence | None
    tool_receipt_samples: tuple[Mapping[str, object], ...]
    tool_receipt_coverage: str
    tool_receipt_omitted_samples: int
    tool_receipt_signal: bool


@dataclass(frozen=True)
class _RunRecordRead:
    state: str
    parsed: _ParsedRunRecord | None
    record: Mapping[str, Any] | None
    events_state: str
    events_raw: bytes | None
    prefix_usage: _UsageTotals | None
    tool_receipt_samples: tuple[Mapping[str, object], ...]
    tool_receipt_coverage: str
    tool_receipt_omitted_samples: int
    tool_receipt_signal: bool


_WorkspaceFailureProjection = tuple[
    str,
    str,
    bool,
    bool,
    bool,
    bool,
    bool | None,
]


@dataclass(frozen=True)
class _ArtifactEvidence:
    artifacts_valid: bool
    success_valid: bool
    direct_atif_valid: bool
    diagnostic_valid: bool
    publication_valid: bool
    trajectory_valid: bool
    publication_kind: str | None
    workspace_receipt_valid: bool
    workspace_snapshot_complete: bool
    workspace_status: str | None
    workspace_failure_stage: str | None
    workspace_failure_category: str | None
    workspace_failure_v3: _WorkspaceFailureProjection | None
    usage_receipt_valid: bool
    terminal_status: str | None = None
    terminal_phase: str | None = None
    terminal_code: str | None = None
    run_record_read: _RunRecordRead | None = None
    usage_fallback: _UsageTotals | None = None


@dataclass(frozen=True)
class _WorkspaceEvidence:
    receipt_valid: bool = False
    snapshot_usable: bool = False
    snapshot_complete: bool = False
    status: str | None = None
    failure_stage: str | None = None
    failure_category: str | None = None
    failure_v3: _WorkspaceFailureProjection | None = None


@dataclass(frozen=True)
class PreparedRun:
    repository: Path
    harbor_checkout: Path
    source_checkout: Path
    output_dir: Path
    inventory: tuple[InventoryTask, ...]
    selected: tuple[InventoryTask, ...]
    concurrency: int
    inputs: RuntimeInputs
    runtime_source_sha256: str
    runtime_git_head: str
    runtime_binary_sha256: str
    official_task_checksums: Mapping[str, str]
    capability_manifest: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class _ResultCandidate:
    path: Path
    trial_name: str
    value: Mapping[str, Any] | None
    error: str | None


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


def _read_regular(path: Path, *, limit: int = _MAX_JSON_BYTES) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise TB21Error("required_input_unavailable") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
        raise TB21Error("required_input_unavailable")
    try:
        return path.read_bytes()
    except OSError as error:
        raise TB21Error("required_input_unavailable") from error


def _load_json(path: Path) -> Any:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value

    try:
        return json.loads(
            _read_regular(path),
            object_pairs_hook=unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise TB21Error("json_invalid") from error


def _atomic_write(path: Path, content: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{uuid4().hex}")
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
        raise TB21Error("result_publish_failed") from error


def _positive_number(value: object, code: str) -> int | float:
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(float(value))
        or value <= 0
    ):
        raise TB21Error(code)
    return value


def _positive_integer(value: object, code: str) -> int:
    number = _positive_number(value, code)
    if not float(number).is_integer():
        raise TB21Error(code)
    return int(number)


def _directory_digests(path: Path) -> tuple[str, str]:
    """Hash only the closed public metadata needed before task execution."""

    rows: list[dict[str, object]] = []
    for relative in _PUBLIC_TASK_METADATA_PATHS:
        candidate = path / relative
        for parent in candidate.parents:
            if parent == path:
                break
            try:
                metadata = parent.lstat()
            except OSError as error:
                raise TB21Error("task_source_unavailable") from error
            if not stat.S_ISDIR(metadata.st_mode):
                raise TB21Error("task_source_unavailable")
        raw = _read_regular(candidate)
        rows.append(
            {
                "path": relative,
                "byte_length": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    manifest_sha256 = hashlib.sha256(_canonical(rows)).hexdigest()
    metadata_digest = hashlib.sha256(
        _canonical(
            {
                "schema_version": PUBLIC_TASK_METADATA_SCHEMA,
                "files": rows,
            }
        )
    ).hexdigest()
    return metadata_digest, manifest_sha256


def _load_task(path: Path) -> InventoryTask:
    if path.is_symlink() or not path.is_dir():
        raise TB21Error("task_directory_invalid")
    try:
        value = tomllib.loads(_read_regular(path / "task.toml").decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise TB21Error("task_config_invalid") from error
    if not isinstance(value, dict):
        raise TB21Error("task_config_invalid")
    task = value.get("task")
    environment = value.get("environment")
    agent = value.get("agent")
    verifier = value.get("verifier")
    if not all(
        isinstance(section, dict) for section in (task, environment, agent, verifier)
    ):
        raise TB21Error("task_config_invalid")
    assert isinstance(task, dict)
    assert isinstance(environment, dict)
    assert isinstance(agent, dict)
    assert isinstance(verifier, dict)
    task_id = task.get("name")
    docker_image = environment.get("docker_image")
    if (
        not isinstance(task_id, str)
        or _SAFE_TASK_ID.fullmatch(task_id) is None
        or not isinstance(docker_image, str)
        or not docker_image
        or "\x00" in docker_image
    ):
        raise TB21Error("task_config_invalid")
    for required in (
        path / "instruction.md",
        path / "environment" / "Dockerfile",
    ):
        _read_regular(required)
    cpus = _positive_number(environment.get("cpus"), "task_resource_invalid")
    memory_mb = _positive_integer(environment.get("memory_mb"), "task_resource_invalid")
    storage_value = environment.get("storage_mb")
    storage_mb = (
        None
        if storage_value is None
        else _positive_integer(storage_value, "task_resource_invalid")
    )
    gpus_value = environment.get("gpus", 0)
    if (
        isinstance(gpus_value, bool)
        or not isinstance(gpus_value, int)
        or gpus_value < 0
    ):
        raise TB21Error("task_resource_invalid")
    task_digest, source_sha256 = _directory_digests(path)
    return InventoryTask(
        task_id=task_id,
        short_name=path.name,
        path=path.resolve(),
        task_digest=task_digest,
        source_sha256=source_sha256,
        docker_image=docker_image,
        cpus=cpus,
        memory_mb=memory_mb,
        storage_mb=storage_mb,
        gpus=gpus_value,
        agent_timeout_sec=_positive_integer(
            agent.get("timeout_sec"), "task_timeout_invalid"
        ),
        verifier_timeout_sec=_positive_integer(
            verifier.get("timeout_sec"), "task_timeout_invalid"
        ),
    )


def load_inventory(
    tasks_root: Path,
    *,
    expected_count: int = TB21_TASK_COUNT,
) -> tuple[InventoryTask, ...]:
    """Load a complete local task checkout in deterministic task-id order."""

    if (
        isinstance(expected_count, bool)
        or not isinstance(expected_count, int)
        or expected_count <= 0
        or not tasks_root.is_absolute()
        or tasks_root.is_symlink()
        or not tasks_root.is_dir()
    ):
        raise TB21Error("inventory_root_invalid")
    try:
        directories = [
            path for path in tasks_root.iterdir() if path.is_dir() or path.is_symlink()
        ]
    except OSError as error:
        raise TB21Error("inventory_root_invalid") from error
    if len(directories) != expected_count:
        raise TB21Error("inventory_count_mismatch")
    rows = tuple(
        sorted((_load_task(path) for path in directories), key=lambda r: r.task_id)
    )
    task_ids = [row.task_id for row in rows]
    if len(task_ids) != len(set(task_ids)):
        raise TB21Error("duplicate_inventory_task")
    return rows


def load_official_task_checksums(
    repository: Path,
    inventory: Sequence[InventoryTask],
) -> dict[str, str]:
    """Load the official Harbor-materialized task identities for the pinned dataset."""

    value = _load_json(repository / OFFICIAL_TASK_CHECKSUMS_PATH)
    expected_keys = {
        "schema_version",
        "dataset_name",
        "dataset_digest",
        "harbor_version",
        "harbor_commit",
        "terminal_bench_commit",
        "task_count",
        "checksums_sha256",
        "checksums",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise TB21Error("official_task_checksums_invalid")
    checksums = value.get("checksums")
    if not isinstance(checksums, dict) or any(
        not isinstance(task_id, str)
        or _SAFE_TASK_ID.fullmatch(task_id) is None
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        for task_id, digest in checksums.items()
    ):
        raise TB21Error("official_task_checksums_invalid")
    expected_ids = [row.task_id for row in inventory]
    if (
        value.get("schema_version") != OFFICIAL_TASK_CHECKSUMS_SCHEMA
        or value.get("dataset_name") != TB21_DATASET
        or value.get("dataset_digest") != TB21_DATASET_REF
        or value.get("harbor_version") != HARBOR_VERSION
        or value.get("harbor_commit") != HARBOR_COMMIT
        or value.get("terminal_bench_commit") != TB21_SOURCE_COMMIT
        or value.get("task_count") != TB21_TASK_COUNT
        or len(checksums) != TB21_TASK_COUNT
        or len(expected_ids) != TB21_TASK_COUNT
        or len(expected_ids) != len(set(expected_ids))
        or set(checksums) != set(expected_ids)
        or value.get("checksums_sha256")
        != hashlib.sha256(_canonical(checksums)).hexdigest()
    ):
        raise TB21Error("official_task_checksums_invalid")
    return {task_id: str(checksums[task_id]) for task_id in sorted(checksums)}


def _normalize_selector(value: str) -> str:
    if value.startswith("terminal-bench/"):
        return value
    return f"terminal-bench/{value}"


def select_tasks(
    inventory: Sequence[InventoryTask],
    selectors: Sequence[str],
) -> tuple[InventoryTask, ...]:
    """Resolve selectors while preserving frozen inventory order."""

    selected_ids: list[str] = []
    for selector in selectors:
        if not selector or "\x00" in selector:
            raise TB21Error("task_selector_invalid")
        selected_ids.append(_normalize_selector(selector))
    if len(selected_ids) != len(set(selected_ids)):
        raise TB21Error("duplicate_task_selector")
    by_id = {row.task_id: row for row in inventory}
    if any(task_id not in by_id for task_id in selected_ids):
        raise TB21Error("unknown_task_selector")
    selected = set(selected_ids)
    return tuple(row for row in inventory if row.task_id in selected)


def read_task_file(path: Path) -> tuple[str, ...]:
    try:
        text = _read_regular(path, limit=1024 * 1024).decode("utf-8")
    except UnicodeDecodeError as error:
        raise TB21Error("task_file_invalid") from error
    rows: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            rows.append(line)
    return tuple(rows)


def _inventory_row(task: InventoryTask) -> dict[str, object]:
    row = asdict(task)
    row["path"] = str(task.path)
    row["digest_scope"] = PUBLIC_TASK_METADATA_SCHEMA
    return row


def _inventory_history_capabilities(
    inventory: Sequence[InventoryTask],
    official_task_checksums: Mapping[str, str],
) -> list[dict[str, object]]:
    if set(official_task_checksums) != {task.task_id for task in inventory}:
        raise TB21Error("official_task_checksums_invalid")
    rows: list[dict[str, object]] = []
    for task in inventory:
        try:
            instruction = _read_regular(
                task.path / "instruction.md", limit=1024 * 1024
            ).decode("utf-8")
            capability = compile_git_history_capability(
                instruction,
                official_task_checksums[task.task_id],
            )
        except (UnicodeDecodeError, ValueError) as error:
            raise TB21Error("git_history_capability_invalid") from error
        rows.append({"task_id": task.task_id, **capability})
    return rows


def _empty_capability_manifest(
    capture_state: str,
    *,
    source: Mapping[str, object] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": CAPABILITY_MANIFEST_SCHEMA,
        "capture_state": capture_state,
        "source": dict(source) if source is not None else None,
        "cpu": None,
        "dependencies": [],
        "runtimes": [],
    }


def _capability_rows_valid(
    value: object,
    *,
    names: frozenset[str],
) -> bool:
    if not isinstance(value, list) or len(value) > len(names):
        return False
    observed: list[str] = []
    for row in value:
        if not isinstance(row, dict) or set(row) != {"name", "state", "version"}:
            return False
        name = row.get("name")
        state = row.get("state")
        version = row.get("version")
        if (
            not isinstance(name, str)
            or name not in names
            or not isinstance(state, str)
            or state not in _CAPABILITY_STATES
            or (
                version is not None
                and (
                    not isinstance(version, str)
                    or _CAPABILITY_VERSION.fullmatch(version) is None
                    or any(
                        fragment in version.upper()
                        for fragment in _CAPABILITY_SECRET_FRAGMENTS
                    )
                )
            )
            or (state != "present" and version is not None)
        ):
            return False
        observed.append(name)
    return observed == sorted(set(observed))


def validate_capability_manifest(value: object) -> bool:
    """Validate one bounded, closed, secret-free advisory capability projection."""

    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "capture_state",
        "source",
        "cpu",
        "dependencies",
        "runtimes",
    }:
        return False
    capture_state = value.get("capture_state")
    source = value.get("source")
    if (
        value.get("schema_version") != CAPABILITY_MANIFEST_SCHEMA
        or not isinstance(capture_state, str)
        or capture_state not in _CAPABILITY_CAPTURE_STATES
        or (capture_state == "missing" and source is not None)
        or (capture_state in {"present", "unknown"} and source is None)
        or (
            capture_state in {"missing", "invalid"}
            and (
                value.get("cpu") is not None
                or value.get("dependencies") != []
                or value.get("runtimes") != []
            )
        )
        or (
            source is not None
            and (
                not isinstance(source, dict)
                or set(source) != {"probe", "byte_length", "sha256"}
                or source.get("probe") != "generic-v1"
                or _nonnegative_integer(source.get("byte_length")) is None
                or not 0 < source["byte_length"] <= CAPABILITY_PROBE_MAX_BYTES
                or not _sha256_string(source.get("sha256"))
            )
        )
    ):
        return False
    cpu = value.get("cpu")
    if cpu is not None:
        state = cpu.get("state") if isinstance(cpu, dict) else None
        architecture = cpu.get("architecture") if isinstance(cpu, dict) else None
        features = cpu.get("features") if isinstance(cpu, dict) else None
        if (
            not isinstance(cpu, dict)
            or set(cpu) != {"state", "architecture", "features"}
            or not isinstance(state, str)
            or state not in _CAPABILITY_STATES
            or (
                architecture is not None
                and (
                    not isinstance(architecture, str)
                    or architecture not in _CAPABILITY_ARCHITECTURES
                )
            )
            or not isinstance(features, list)
            or any(
                not isinstance(feature, str) or feature not in _CAPABILITY_CPU_FEATURES
                for feature in features
            )
            or (
                isinstance(features, list)
                and (
                    features != sorted(features) or len(features) != len(set(features))
                )
            )
            or (state != "present" and (architecture is not None or features))
        ):
            return False
    return _capability_rows_valid(
        value.get("dependencies"),
        names=_CAPABILITY_DEPENDENCIES,
    ) and _capability_rows_valid(
        value.get("runtimes"),
        names=_CAPABILITY_RUNTIMES,
    )


def _normalized_capability_facts(
    value: object,
    *,
    source: Mapping[str, object],
) -> dict[str, object] | None:
    if not isinstance(value, dict) or set(value) != {
        "capture_state",
        "cpu",
        "dependencies",
        "runtimes",
    }:
        return None
    capture_state = value.get("capture_state")
    if not isinstance(capture_state, str) or capture_state not in {
        "present",
        "unknown",
    }:
        return None
    cpu = value.get("cpu")
    normalized_cpu: dict[str, object] | None
    if cpu is None:
        normalized_cpu = None
    elif isinstance(cpu, dict) and set(cpu) == {
        "state",
        "architecture",
        "features",
    }:
        features = cpu.get("features")
        if not isinstance(features, list) or any(
            not isinstance(feature, str) for feature in features
        ):
            return None
        normalized_cpu = {
            "state": cpu.get("state"),
            "architecture": cpu.get("architecture"),
            "features": sorted(features),
        }
    else:
        return None
    dependencies = value.get("dependencies")
    runtimes = value.get("runtimes")
    if not isinstance(dependencies, list) or not isinstance(runtimes, list):
        return None
    normalized: dict[str, object] = {
        "schema_version": CAPABILITY_MANIFEST_SCHEMA,
        "capture_state": value["capture_state"],
        "source": dict(source),
        "cpu": normalized_cpu,
        "dependencies": sorted(
            dependencies,
            key=lambda row: str(row.get("name")) if isinstance(row, dict) else "",
        ),
        "runtimes": sorted(
            runtimes,
            key=lambda row: str(row.get("name")) if isinstance(row, dict) else "",
        ),
    }
    return normalized if validate_capability_manifest(normalized) else None


def _read_capability_probe(path: Path) -> tuple[str, bytes | None]:
    """Read at most cap+1 bytes from one no-follow, stable regular-file fd."""

    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        return "invalid", None
    try:
        descriptor = os.open(path, os.O_RDONLY | nofollow)
    except (FileNotFoundError, NotADirectoryError):
        return "absent", None
    except OSError:
        return "invalid", None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > CAPABILITY_PROBE_MAX_BYTES
        ):
            return "invalid", None
        chunks: list[bytes] = []
        remaining = CAPABILITY_PROBE_MAX_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
    except OSError:
        return "invalid", None
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    stable_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if (
        not stable_identity
        or not raw
        or len(raw) > CAPABILITY_PROBE_MAX_BYTES
        or len(raw) != before.st_size
    ):
        return "invalid", None
    return "valid", raw


def capture_capability_manifest(probe_path: Path | None) -> dict[str, object]:
    """Capture a bounded generic receipt; every failure becomes advisory evidence."""

    if probe_path is None:
        return _empty_capability_manifest("missing")
    state, raw = _read_capability_probe(probe_path)
    if state == "absent":
        return _empty_capability_manifest("missing")
    if state != "valid" or raw is None:
        return _empty_capability_manifest("invalid")
    source = {
        "probe": "generic-v1",
        "byte_length": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = item
        return result

    try:
        receipt = json.loads(
            raw,
            object_pairs_hook=unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("invalid_json_constant")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        return _empty_capability_manifest("invalid", source=source)
    try:
        receipt_valid = bool(
            isinstance(receipt, dict)
            and raw == _canonical(receipt)
            and set(receipt) == {"schema_version", "facts", "facts_sha256"}
            and receipt.get("schema_version") == CAPABILITY_PROBE_SCHEMA
            and receipt.get("facts_sha256")
            == hashlib.sha256(_canonical(receipt.get("facts"))).hexdigest()
        )
    except (TypeError, ValueError, RecursionError):
        receipt_valid = False
    if not receipt_valid:
        return _empty_capability_manifest("invalid", source=source)
    normalized = _normalized_capability_facts(receipt.get("facts"), source=source)
    if normalized is None:
        return _empty_capability_manifest("invalid", source=source)
    return normalized


def _write_capability_manifest(path: Path, manifest: Mapping[str, Any]) -> None:
    if not validate_capability_manifest(manifest):
        raise TB21Error("capability_manifest_invalid")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(_canonical(manifest))
        handle.flush()
        os.fsync(handle.fileno())


def plan_payload(
    *,
    inventory: Sequence[InventoryTask],
    selected: Sequence[InventoryTask],
    concurrency: int,
    source_checkout: Path,
    capability_manifest: Mapping[str, Any] | None = None,
    inventory_authority: Mapping[str, Any] | None = None,
    git_history_capabilities: Sequence[Mapping[str, Any]] = (),
) -> dict[str, object]:
    """Build the secret-free plan emitted before any Harbor job is created."""

    if concurrency not in ALLOWED_CONCURRENCY:
        raise TB21Error("concurrency_invalid")
    inventory_rows = [_inventory_row(row) for row in inventory]
    digest_rows = [
        {key: value for key, value in row.items() if key != "path"}
        for row in inventory_rows
    ]
    capabilities = (
        dict(capability_manifest)
        if capability_manifest is not None
        else capture_capability_manifest(None)
    )
    if not validate_capability_manifest(capabilities):
        raise TB21Error("capability_manifest_invalid")
    authority = (
        dict(inventory_authority)
        if inventory_authority is not None
        else {
            "schema_version": INVENTORY_AUTHORITY_SCHEMA,
            "state": "unverified",
        }
    )
    history_capabilities = [dict(row) for row in git_history_capabilities]
    inventory_sha256 = hashlib.sha256(_canonical(digest_rows)).hexdigest()
    if inventory_authority is not None and authority.get("inventory") != {
        "task_count": len(inventory),
        "digest_scope": PUBLIC_TASK_METADATA_SCHEMA,
        "sha256": inventory_sha256,
    }:
        raise TB21Error("inventory_authority_invalid")
    return {
        "schema_version": "nano-tb21-plan-v1",
        "label": "full-eight-tool internal diagnostic; not a leaderboard claim",
        "dataset": TB21_DATASET,
        "dataset_ref": TB21_DATASET_REF,
        "source_commit": TB21_SOURCE_COMMIT,
        "source_checkout": str(source_checkout.resolve()),
        "harbor_commit": HARBOR_COMMIT,
        "model": LIVE_MODEL,
        "max_provider_turns": TB21_MAX_TURNS,
        "active_tools": list(ACTIVE_TOOLS),
        "n_attempts": 1,
        "retry_max": 0,
        "concurrency": concurrency,
        "expected_inventory_count": len(inventory),
        "selected_count": len(selected),
        "selected_task_ids": [row.task_id for row in selected],
        "inventory_sha256": inventory_sha256,
        "inventory": inventory_rows,
        "inventory_authority": authority,
        "git_history_capabilities": history_capabilities,
        "git_history_capabilities_sha256": hashlib.sha256(
            _canonical(history_capabilities)
        ).hexdigest(),
        "capability_manifest": capabilities,
        "capability_manifest_sha256": hashlib.sha256(
            _canonical(capabilities)
        ).hexdigest(),
        "network_calls": 0,
        "docker_calls": 0,
    }


def _canonical_github_repository(value: str) -> str | None:
    patterns = (
        r"https://github\.com/(?P<path>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?",
        r"git@github\.com:(?P<path>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?",
        r"ssh://git@github\.com/(?P<path>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?",
    )
    for pattern in patterns:
        match = re.fullmatch(pattern, value.strip())
        if match is not None:
            return f"https://github.com/{match.group('path').lower()}.git"
    return None


def _verified_upstream_identity(
    checkout: Path,
    *,
    repository: str,
    commit: str,
    tree: str,
    code: str,
) -> dict[str, str]:
    """Bind a complete clean checkout without opening non-public task blobs."""

    if (
        not checkout.is_absolute()
        or checkout.is_symlink()
        or not checkout.is_dir()
        or re.fullmatch(r"[0-9a-f]{40}", commit) is None
        or re.fullmatch(r"[0-9a-f]{40}", tree) is None
        or _canonical_github_repository(repository) != repository
    ):
        raise TB21Error(code)

    def git(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        try:
            return subprocess.run(
                ["git", *arguments],
                cwd=checkout,
                check=check,
                capture_output=True,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise TB21Error(code) from error

    root = git("rev-parse", "--show-toplevel").stdout.decode().strip()
    head = git("rev-parse", "HEAD").stdout.decode().strip()
    observed_tree = git("rev-parse", "HEAD^{tree}").stdout.decode().strip()
    origin = git("remote", "get-url", "origin").stdout.decode().strip()
    status = git("status", "--porcelain", "--untracked-files=all").stdout
    sparse = git("config", "--bool", "core.sparseCheckout", check=False)
    tracked = git("ls-files", "-v", "-z").stdout.split(b"\0")
    if (
        Path(root).resolve() != checkout
        or head != commit
        or observed_tree != tree
        or _canonical_github_repository(origin) != repository
        or status
        or sparse.returncode not in {0, 1}
        or sparse.returncode == 0
        and sparse.stdout.strip() == b"true"
        or not any(tracked)
        or any(row and not row.startswith(b"H ") for row in tracked)
    ):
        raise TB21Error(code)
    return {
        "repository": repository,
        "commit": commit,
        "tree": tree,
        "worktree": "complete_clean",
    }


def _git_head(checkout: Path, error_code: str) -> str:
    if not checkout.is_absolute() or checkout.is_symlink() or not checkout.is_dir():
        raise TB21Error(error_code)
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=checkout,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as error:
        raise TB21Error(error_code) from error


def assert_tb21_pin(checkout: Path) -> None:
    _verified_upstream_identity(
        checkout,
        repository=TB21_SOURCE_REPOSITORY,
        commit=TB21_SOURCE_COMMIT,
        tree=TB21_SOURCE_TREE,
        code="tb21_checkout_invalid",
    )


def load_xai_key(dotenv: Path, environment: MutableMapping[str, str]) -> bool:
    """Load only XAI_API_KEY, with an existing process value taking precedence."""

    if environment.get("XAI_API_KEY"):
        return True
    try:
        text = _read_regular(dotenv, limit=1024 * 1024).decode("utf-8")
    except (TB21Error, UnicodeDecodeError):
        return False
    selected: str | None = None
    for index, raw_line in enumerate(text.splitlines()):
        line = raw_line.lstrip("\ufeff") if index == 0 else raw_line
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        name, separator, raw_value = line.partition("=")
        if separator and name.strip() == "XAI_API_KEY":
            value = raw_value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            if (
                value
                and "\x00" not in value
                and "\r" not in value
                and "\n" not in value
            ):
                selected = value
    if selected is None:
        return False
    environment["XAI_API_KEY"] = selected
    return True


def _pricing_rate(value: object) -> Decimal:
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(float(value))
        or value < 0
    ):
        raise TB21Error("pricing_invalid")
    return Decimal(str(value))


def load_pricing(path: Path) -> Pricing:
    raw = _read_regular(path, limit=1024 * 1024)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TB21Error("pricing_invalid") from error
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "as_of",
        "currency",
        "model",
        "input_per_million_usd",
        "cached_input_per_million_usd",
        "output_per_million_usd",
    }:
        raise TB21Error("pricing_invalid")
    as_of = value["as_of"]
    model = value["model"]
    try:
        date.fromisoformat(as_of)
    except (TypeError, ValueError) as error:
        raise TB21Error("pricing_invalid") from error
    if (
        value["schema_version"] != PRICING_SCHEMA
        or value["currency"] != "USD"
        or not isinstance(model, str)
        or not model
    ):
        raise TB21Error("pricing_invalid")
    return Pricing(
        as_of=as_of,
        model=model,
        input_per_million_usd=_pricing_rate(value["input_per_million_usd"]),
        cached_input_per_million_usd=_pricing_rate(
            value["cached_input_per_million_usd"]
        ),
        output_per_million_usd=_pricing_rate(value["output_per_million_usd"]),
        source_sha256=hashlib.sha256(raw).hexdigest(),
    )


def _load_envelope(path: Path, schema: str) -> Mapping[str, Any]:
    value = _load_json(path)
    if not isinstance(value, dict) or set(value) != {"manifest", "manifest_sha256"}:
        raise TB21Error("manifest_invalid")
    manifest = value["manifest"]
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != schema
        or value["manifest_sha256"] != hashlib.sha256(_canonical(manifest)).hexdigest()
    ):
        raise TB21Error("manifest_invalid")
    return manifest


def _load_dispatch(job_dir: Path) -> tuple[Mapping[str, Any], ...]:
    from nano_grok_build.harbor.git_history_capability import (
        validate_git_history_capability,
    )

    manifest = _load_envelope(job_dir / "nano-dispatch.json", "nano-harbor-dispatch-v1")
    specs = manifest.get("run_specs")
    if (
        manifest.get("harbor_version") != "0.20.0"
        or manifest.get("retry_max") != 0
        or manifest.get("n_attempts") != 1
        or not isinstance(specs, list)
        or not specs
    ):
        raise TB21Error("dispatch_invalid")
    rows: list[Mapping[str, Any]] = []
    trials: set[str] = set()
    tasks: set[str] = set()
    for spec in specs:
        if not isinstance(spec, dict):
            raise TB21Error("dispatch_invalid")
        task = spec.get("task")
        provider = spec.get("provider")
        contract = spec.get("contract")
        trial = spec.get("trial_id")
        if (
            spec.get("schema_version")
            not in {"nano-run-spec-alpha-1", "nano-run-spec-alpha-2"}
            or spec.get("attempt_id") != "attempt-0"
            or spec.get("active_tools") != list(ACTIVE_TOOLS)
            or not isinstance(trial, str)
            or not trial
            or not isinstance(task, dict)
            or not isinstance(provider, dict)
            or not isinstance(contract, dict)
            or not isinstance(task.get("id"), str)
            or not isinstance(task.get("digest"), str)
            or len(task["digest"]) != 64
            or provider.get("kind") != "xai"
            or provider.get("model") != LIVE_MODEL
            or provider.get("max_turns") != TB21_MAX_TURNS
            or provider.get("retry_max") != 0
        ):
            if isinstance(spec, dict) and spec.get("active_tools") != list(
                ACTIVE_TOOLS
            ):
                raise TB21Error("dispatch_active_tools_mismatch")
            raise TB21Error("dispatch_invalid")
        if spec["schema_version"] == "nano-run-spec-alpha-2":
            try:
                validate_git_history_capability(
                    task.get("git_history_capability"),
                    task.get("instruction"),
                    task.get("digest"),
                )
            except ValueError as error:
                raise TB21Error("dispatch_invalid") from error
        elif "git_history_capability" in task:
            raise TB21Error("dispatch_invalid")
        if trial in trials or task["id"] in tasks:
            raise TB21Error("dispatch_duplicate_identity")
        trials.add(trial)
        tasks.add(task["id"])
        rows.append(spec)
    return tuple(sorted(rows, key=lambda row: str(row["task"]["id"])))


def _candidate(path: Path) -> _ResultCandidate:
    trial_from_path = path.parent.name
    try:
        value = _load_json(path)
    except TB21Error:
        return _ResultCandidate(path, trial_from_path, None, "result_invalid")
    if not isinstance(value, dict):
        return _ResultCandidate(path, trial_from_path, None, "result_invalid")
    trial = value.get("trial_name")
    if not isinstance(trial, str) or not trial:
        return _ResultCandidate(path, trial_from_path, value, "result_invalid")
    if trial != trial_from_path:
        return _ResultCandidate(path, trial, value, "result_path_mismatch")
    return _ResultCandidate(path, trial, value, None)


def _scan_results(job_dir: Path) -> tuple[_ResultCandidate, ...]:
    rows: list[_ResultCandidate] = []
    try:
        children = sorted(job_dir.iterdir(), key=lambda path: path.name)
    except OSError as error:
        raise TB21Error("job_directory_invalid") from error
    for child in children:
        if child.is_symlink() or not child.is_dir():
            continue
        result_path = child / "result.json"
        if result_path.exists() or result_path.is_symlink():
            rows.append(_candidate(result_path))
    return tuple(rows)


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _duration_ms(value: Mapping[str, Any]) -> int | None:
    started = _timestamp(value.get("started_at"))
    finished = _timestamp(value.get("finished_at"))
    if started is None or finished is None:
        return None
    duration = round((finished - started).total_seconds() * 1000)
    return duration if duration >= 0 else None


def _reward(value: Mapping[str, Any]) -> float | None:
    verifier = value.get("verifier_result")
    rewards = verifier.get("rewards") if isinstance(verifier, dict) else None
    reward = rewards.get("reward") if isinstance(rewards, dict) else None
    if (
        isinstance(reward, bool)
        or not isinstance(reward, int | float)
        or not math.isfinite(float(reward))
        or not 0 <= float(reward) <= 1
    ):
        return None
    return float(reward)


def _official_result_classification(
    value: Mapping[str, Any] | None,
    *,
    candidate_error: str | None,
    identity_valid: bool,
) -> tuple[str, float | None]:
    """Classify raw official result bytes without consulting rows or artifacts.

    A well-formed exception is terminal ``errored`` evidence with reward zero,
    not evidence that the surrounding campaign is invalid.
    """

    if value is None or candidate_error is not None or not identity_valid:
        return "invalid", None
    verifier = value.get("verifier_result")
    if verifier is not None:
        if not isinstance(verifier, Mapping):
            return "invalid", None
        rewards = verifier.get("rewards")
        raw_reward = rewards.get("reward") if isinstance(rewards, Mapping) else None
        if (
            isinstance(raw_reward, bool)
            or not isinstance(raw_reward, int | float)
            or not math.isfinite(float(raw_reward))
            or not 0 <= float(raw_reward) <= 1
        ):
            return "invalid", None
        reward = float(raw_reward)
        return ("rewarded" if reward > 0 else "zero"), reward
    exception = value.get("exception_info")
    if (
        isinstance(exception, Mapping)
        and isinstance(exception.get("exception_type"), str)
        and isinstance(exception.get("exception_message"), str)
    ):
        return "errored", None
    return "invalid", None


def _exception(value: Mapping[str, Any]) -> dict[str, str] | None:
    exception = value.get("exception_info")
    if exception is None:
        return None
    if not isinstance(exception, dict):
        return {"type": "InvalidExceptionInfo", "message": ""}
    exception_type = exception.get("exception_type")
    message = exception.get("exception_message")
    return {
        "type": exception_type if isinstance(exception_type, str) else "UnknownError",
        "message": message if isinstance(message, str) else "",
    }


def _nonnegative_integer(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _positive_u64(value: object) -> int | None:
    parsed = _nonnegative_integer(value)
    if parsed is None or parsed == 0 or parsed > _U64_MAX:
        return None
    return parsed


def _is_sha256(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


class _DuplicateAwareDict(dict[str, Any]):
    __slots__ = ("duplicate_keys",)

    def __init__(self, pairs: list[tuple[str, Any]]) -> None:
        super().__init__()
        duplicate_keys: set[str] = set()
        for key, value in pairs:
            if key in self:
                duplicate_keys.add(key)
            self[key] = value
        self.duplicate_keys = frozenset(duplicate_keys)


def _tool_receipt_primary_binding_valid(
    phase: str,
    origin: str,
    primary_subtype: str,
    recovery_subtype: str | None,
) -> bool:
    if (
        primary_subtype not in _TOOL_RECEIPT_PRIMARY_SUBTYPES
        or (recovery_subtype is not None)
        != (primary_subtype in _TOOL_RECEIPT_RECOVERY_PRIMARIES)
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
    event_schema: str,
) -> dict[str, object] | None:
    if isinstance(data, _DuplicateAwareDict) and bool(data.duplicate_keys):
        return None
    fields = set(data)
    if fields == _TOOL_RECEIPT_KEYS:
        if (
            event_schema != "event-v3"
            or data.get("schema_version") != _TOOL_RECEIPT_SCHEMA
        ):
            return None
    elif fields == _PREVIOUS_TOOL_RECEIPT_KEYS:
        if (
            event_schema != "event-v2"
            or data.get("schema_version") != _TOOL_RECEIPT_TELEMETRY_SCHEMA
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
    return {
        "schema_version": _TOOL_RECEIPT_TELEMETRY_SCHEMA,
        "coverage": "complete",
        "owner": "tool",
        "source": "actor_receipt",
        "phase": phase,
        "origin": origin,
        "primary_subtype": primary_subtype,
        "recovery_subtype": recovery_subtype,
        "receipt_digest_sha256": str(data["receipt_digest_sha256"]),
        "relation": "settles",
        "tool_identity_sha256": str(data["tool_identity_sha256"]),
        "tool_call_ordinal": ordinal,
    }


def _tool_identity_sha256(call_id: str, provider_name: str) -> str:
    encoded = json.dumps(
        {"call_id": call_id, "provider_name": provider_name},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _usage_value(
    value: object,
) -> tuple[int, int, int, int | None] | None:
    if not isinstance(value, dict):
        return None
    input_tokens = _nonnegative_integer(value.get("input_tokens"))
    output_tokens = _nonnegative_integer(value.get("output_tokens"))
    details = value.get("input_tokens_details")
    cached_value = details.get("cached_tokens") if isinstance(details, dict) else 0
    cached_tokens = _nonnegative_integer(cached_value)
    if (
        input_tokens is None
        or output_tokens is None
        or cached_tokens is None
        or cached_tokens > input_tokens
    ):
        return None
    ticks: int | None = None
    if "cost_in_usd_ticks" in value:
        ticks = _nonnegative_integer(value["cost_in_usd_ticks"])
        if ticks is None:
            return None
        if "provider_cost_ticks" in value:
            provider_ticks = _nonnegative_integer(value["provider_cost_ticks"])
            if provider_ticks is None or provider_ticks != ticks:
                return None
    return input_tokens, cached_tokens, output_tokens, ticks


def _valid_context_checkpoint(data: object) -> bool:
    if (
        not isinstance(data, dict)
        or isinstance(data, _DuplicateAwareDict)
        and bool(data.duplicate_keys)
        or data.get("policy_version")
        not in {
            _CONTEXT_CHECKPOINT_POLICY_VERSION,
            _SEMANTIC_CHECKPOINT_POLICY_VERSION,
        }
    ):
        return False
    semantic = data["policy_version"] == _SEMANTIC_CHECKPOINT_POLICY_VERSION
    expected_keys = (
        _SEMANTIC_CONTEXT_CHECKPOINT_KEYS if semantic else _CONTEXT_CHECKPOINT_KEYS
    )
    if (
        set(data) != expected_keys
        or not _is_sha256(data.get("source_history_sha256"))
        or not _is_sha256(data.get("checkpoint_history_sha256"))
        or any(
            _nonnegative_integer(data.get(field)) is None
            for field in (
                "source_history_items",
                "checkpoint_history_items",
                "provider_turn_count",
                "tool_call_count",
                "observed_input_tokens",
            )
        )
        or int(data["source_history_items"]) == 0
        or not 0
        < int(data["checkpoint_history_items"])
        < int(data["source_history_items"])
        or int(data["provider_turn_count"]) == 0
        or int(data["observed_input_tokens"]) == 0
    ):
        return False
    return bool(
        not semantic
        or data.get("capsule_schema_version") == _SEMANTIC_CHECKPOINT_CAPSULE_SCHEMA
        and _is_sha256(data.get("capsule_sha256"))
        and (capsule_bytes := _nonnegative_integer(data.get("capsule_bytes")))
        is not None
        and 0 < capsule_bytes <= 8192
        and (prepare_turn := _nonnegative_integer(data.get("prepare_turn_index")))
        is not None
        and prepare_turn < int(data["provider_turn_count"])
        and _is_sha256(data.get("prepare_history_sha256"))
        and (action_turn := _nonnegative_integer(data.get("action_turn_cutoff")))
        is not None
        and action_turn > int(data["provider_turn_count"])
        and (action_lease := _nonnegative_integer(data.get("action_lease_ms")))
        is not None
        and action_lease > 0
        and data.get("tail_reserve_ms") == 900_000
    )


def _valid_context_checkpoint_rejection(data: object) -> bool:
    present_diagnostic_keys = (
        _CONTEXT_CHECKPOINT_REJECTED_DIAGNOSTIC_KEYS & set(data)
        if isinstance(data, dict)
        else set()
    )
    expected_keys = _CONTEXT_CHECKPOINT_REJECTED_KEYS | (
        _CONTEXT_CHECKPOINT_REJECTED_DIAGNOSTIC_KEYS
        if present_diagnostic_keys
        else set()
    )
    if (
        not isinstance(data, dict)
        or isinstance(data, _DuplicateAwareDict)
        and bool(data.duplicate_keys)
        or set(data) != expected_keys
        or data.get("policy_version") != _SEMANTIC_CHECKPOINT_POLICY_VERSION
        or not _is_sha256(data.get("source_history_sha256"))
        or not _is_sha256(data.get("prepare_history_sha256"))
        or (prepare_turn := _nonnegative_integer(data.get("prepare_turn_index")))
        is None
        or (provider_turns := _nonnegative_integer(data.get("provider_turn_count")))
        is None
        or not isinstance(data.get("reason"), str)
        or not data["reason"]
        or not isinstance(data.get("request_emitted"), bool)
        or not isinstance(data.get("response_received"), bool)
    ):
        return False
    if present_diagnostic_keys:
        digest = data.get("capsule_content_sha256")
        content_bytes = _nonnegative_integer(data.get("capsule_content_bytes"))
        excerpt = data.get("capsule_content_excerpt")
        if (
            data["response_received"] is not True
            or not _is_sha256(digest)
            or content_bytes is None
            or not isinstance(excerpt, str)
            or not excerpt
            or len(excerpt.encode("utf-8")) > 2_048
            or content_bytes < len(excerpt.encode("utf-8"))
        ):
            return False
    if data["request_emitted"]:
        return prepare_turn < provider_turns
    return not data["response_received"] and prepare_turn == provider_turns


def _event_prefix_from_raw(
    raw: bytes,
    spec: Mapping[str, Any],
) -> tuple[_EventPrefix | None, bool]:
    if not raw or not raw.endswith(b"\n"):
        return None, True
    expected_identity = (
        spec.get("run_id"),
        spec.get("trial_id"),
        spec.get("attempt_id"),
    )
    events: list[Mapping[str, Any]] = []
    requests: dict[int, str] = {}
    completed = 0
    failed = 0
    usage_present = 0
    usage_absent = 0
    usage_covered = 0
    input_total = 0
    cache_total = 0
    output_total = 0
    cost_ticks = 0
    cost_covered = 0
    failed_usage_present = 0
    failed_usage_absent = 0
    failed_input_total = 0
    failed_cache_total = 0
    failed_output_total = 0
    failed_cost_ticks = 0
    failed_cost_covered = 0
    usage_valid = True
    registered_tools: list[tuple[str, str] | None] = []
    registered_tool_ordinals: dict[tuple[str, str], int] = {}
    ambiguous_tool_bindings: set[tuple[str, str]] = set()
    settled_tool_bindings: set[tuple[str, str]] = set()
    tool_receipt_samples: list[Mapping[str, object]] = []
    tool_receipt_omitted_samples = 0
    tool_receipt_signal = False
    tool_receipt_invalid = False
    tool_receipt_suffix_started = False
    previous_tool_receipt_ordinal = 0
    previous_elapsed = -1
    terminal_seen = False
    checkpoint_resolution_seen = False
    checkpoint_prepare: dict[str, object] | None = None
    checkpoint_expected_history: tuple[str, int] | None = None
    late_review_request_count = 0
    schema: str | None = None
    for sequence, line in enumerate(raw.splitlines()):
        try:
            event = json.loads(line, object_pairs_hook=_DuplicateAwareDict)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, True
        if (
            not isinstance(event, dict)
            or (isinstance(event, _DuplicateAwareDict) and bool(event.duplicate_keys))
            or set(event) != _EVENT_KEYS
            or event.get("schema_version")
            not in {
                "event-v1",
                "event-v2",
                "event-v3",
            }
            or event.get("seq") != sequence
            or event.get("type") not in _EVENT_TYPES
            or event.get("type")
            in {"context.checkpointed", "context.checkpoint_rejected"}
            and event.get("schema_version") != "event-v3"
            or (
                not isinstance(event.get("data"), dict)
                and event.get("type") != "tool.receipt"
            )
        ):
            return None, True
        if schema is None:
            schema = str(event["schema_version"])
        elif event["schema_version"] != schema:
            return None, True
        if schema == "event-v1" and event["type"] == "tool.failed":
            return None, True
        identity = (
            event.get("run_id"),
            event.get("trial_id"),
            event.get("attempt_id"),
        )
        elapsed = _nonnegative_integer(event.get("elapsed_ms"))
        if (
            identity != expected_identity
            or elapsed is None
            or elapsed < previous_elapsed
            or terminal_seen
        ):
            return None, True
        previous_elapsed = elapsed
        event_type = str(event["type"])
        data = event["data"]
        if tool_receipt_suffix_started and event_type not in {
            "tool.receipt",
            "run.completed",
            "run.failed",
        }:
            tool_receipt_invalid = True
        if (
            checkpoint_expected_history is not None
            and event_type != "provider.requested"
        ):
            return None, True
        if checkpoint_prepare is not None:
            checkpoint_state = requests.get(int(checkpoint_prepare["turn_index"]))
            checkpoint_phase = checkpoint_prepare["phase"]
            inline_intermediate = (
                checkpoint_phase == "checkpoint_inline"
                and checkpoint_state == "completed"
                and event_type
                in {
                    "tool.registered",
                    "tool.dispatched",
                    "tool.completed",
                    "tool.failed",
                }
            )
            inline_terminal_failure = (
                checkpoint_phase == "checkpoint_inline"
                and checkpoint_state == "failed"
                and event_type == "run.failed"
            )
            if (
                checkpoint_state in {"completed", "failed"}
                and event_type
                not in {"context.checkpointed", "context.checkpoint_rejected"}
                and not inline_intermediate
                and not inline_terminal_failure
            ):
                return None, True
        if event_type in {"run.completed", "run.failed"}:
            terminal_seen = True
            omitted_fields = {
                "tool_receipt_telemetry_omitted_samples",
                "tool_receipt_omitted_count",
            } & set(data)
            if omitted_fields:
                tool_receipt_signal = True
                expected_omitted_field = (
                    "tool_receipt_omitted_count"
                    if event["schema_version"] == "event-v3"
                    else "tool_receipt_telemetry_omitted_samples"
                )
                omitted = _positive_u64(data.get(expected_omitted_field))
                if (
                    omitted_fields != {expected_omitted_field}
                    or event["schema_version"] not in {"event-v2", "event-v3"}
                    or omitted is None
                    or (
                        isinstance(data, _DuplicateAwareDict)
                        and expected_omitted_field in data.duplicate_keys
                    )
                ):
                    tool_receipt_invalid = True
                else:
                    tool_receipt_omitted_samples = omitted
        elif event_type == "provider.requested":
            turn = _nonnegative_integer(data.get("turn_index"))
            if turn is None or turn != len(requests) or turn in requests:
                return None, True
            if checkpoint_expected_history is not None:
                expected_history_sha, expected_history_items = (
                    checkpoint_expected_history
                )
                media_receipt = data.get("media_history_receipt")
                if (
                    not isinstance(media_receipt, dict)
                    or media_receipt.get("history_sha256") != expected_history_sha
                    or data.get("history_item_count") != expected_history_items
                    or data.get("function_output_call_ids") != []
                ):
                    return None, True
                checkpoint_expected_history = None
            checkpoint_source = data.get(_CHECKPOINT_SOURCE_HISTORY_FIELD)
            observation = data.get("budget_observation")
            checkpoint_phase = (
                observation.get("phase") if isinstance(observation, dict) else None
            )
            if checkpoint_phase == "completion_late_review":
                late_review_request_count += 1
                started = events[0]["data"] if events else {}
                if (
                    started.get("completion_review_policy")
                    not in {"semantic-checkpoint-v7", "semantic-checkpoint-v8"}
                    or late_review_request_count > 2
                ):
                    return None, True
            elif late_review_request_count:
                return None, True
            checkpoint_bound_phase = isinstance(
                observation, dict
            ) and checkpoint_phase in {"checkpoint_prepare", "checkpoint_inline"}
            if checkpoint_bound_phase != (checkpoint_source is not None):
                return None, True
            if checkpoint_source is not None:
                media_receipt = data.get("media_history_receipt")
                started = events[0]["data"] if events else {}
                review_policy = started.get("completion_review_policy")
                expected_checkpoint_phase = {
                    "semantic-checkpoint-v5": "checkpoint_prepare",
                    "semantic-checkpoint-v6": "checkpoint_inline",
                    "semantic-checkpoint-v7": "checkpoint_inline",
                    "semantic-checkpoint-v8": "checkpoint_inline",
                }.get(review_policy)
                if (
                    checkpoint_resolution_seen
                    or checkpoint_prepare is not None
                    or not _is_sha256(checkpoint_source)
                    or not isinstance(media_receipt, dict)
                    or not _is_sha256(media_receipt.get("history_sha256"))
                    or checkpoint_phase != expected_checkpoint_phase
                    or checkpoint_phase == "checkpoint_prepare"
                    and data.get("tool_count") != 0
                    or checkpoint_phase == "checkpoint_inline"
                    and data.get("tool_count") == 0
                    or expected_checkpoint_phase is None
                    or started.get("context_checkpoint_policy_version")
                    != _SEMANTIC_CHECKPOINT_POLICY_VERSION
                    or started.get("checkpoint_capsule_schema_version")
                    != _SEMANTIC_CHECKPOINT_CAPSULE_SCHEMA
                ):
                    return None, True
                checkpoint_prepare = {
                    "turn_index": turn,
                    "phase": checkpoint_phase,
                    "source_history_sha256": checkpoint_source,
                    "prepare_history_sha256": media_receipt["history_sha256"],
                    "prepare_history_items": data.get("history_item_count"),
                }
            requests[turn] = "requested"
        elif event_type in {"provider.completed", "provider.failed"}:
            turn = _nonnegative_integer(data.get("turn_index"))
            if turn is None or requests.get(turn) != "requested":
                return None, True
            is_failed = event_type == "provider.failed"
            if event_type == "provider.failed":
                requests[turn] = "failed"
                failed += 1
                native_usage = data.get("response_usage")
            else:
                requests[turn] = "completed"
                completed += 1
                native_usage = data.get("usage")
            if native_usage is None:
                usage_absent += 1
                failed_usage_absent += int(is_failed)
            else:
                parsed = _usage_value(native_usage)
                if parsed is None:
                    usage_absent += 1
                    failed_usage_absent += int(is_failed)
                    usage_valid = False
                else:
                    usage_present += 1
                    (
                        input_tokens,
                        cache_tokens,
                        output_tokens,
                        ticks,
                    ) = parsed
                    input_total += input_tokens
                    cache_total += cache_tokens
                    output_total += output_tokens
                    usage_covered += 1
                    if is_failed:
                        failed_usage_present += 1
                        failed_input_total += input_tokens
                        failed_cache_total += cache_tokens
                        failed_output_total += output_tokens
                    if ticks is not None:
                        cost_ticks += ticks
                        cost_covered += 1
                        if is_failed:
                            failed_cost_ticks += ticks
                            failed_cost_covered += 1
        elif event_type == "context.checkpointed":
            started = events[0]["data"] if events else {}
            if (
                checkpoint_resolution_seen
                or not _valid_context_checkpoint(data)
                or any(state == "requested" for state in requests.values())
                or data["provider_turn_count"] != len(requests)
                or data["tool_call_count"] != len(registered_tools)
                or data["observed_input_tokens"] != input_total
            ):
                return None, True
            if data["policy_version"] == _SEMANTIC_CHECKPOINT_POLICY_VERSION:
                provider = spec.get("provider")
                max_provider_turns = (
                    provider.get("max_turns") if isinstance(provider, Mapping) else None
                )
                expected_action_turn_cutoff = (
                    min(
                        _SEMANTIC_CHECKPOINT_ACTION_TURN_CAP,
                        int(max_provider_turns)
                        - _SEMANTIC_CHECKPOINT_POST_ACTION_PROVIDER_RESPONSES,
                    )
                    if _nonnegative_integer(max_provider_turns) is not None
                    and int(max_provider_turns)
                    >= _SEMANTIC_CHECKPOINT_POST_ACTION_PROVIDER_RESPONSES
                    else None
                )
                if (
                    started.get("completion_review_policy")
                    not in {
                        "semantic-checkpoint-v5",
                        "semantic-checkpoint-v6",
                        "semantic-checkpoint-v7",
                        "semantic-checkpoint-v8",
                    }
                    or started.get("context_checkpoint_policy_version")
                    != _SEMANTIC_CHECKPOINT_POLICY_VERSION
                    or started.get("checkpoint_capsule_schema_version")
                    != _SEMANTIC_CHECKPOINT_CAPSULE_SCHEMA
                    or checkpoint_prepare is None
                    or data["prepare_turn_index"] != checkpoint_prepare["turn_index"]
                    or data["source_history_sha256"]
                    != checkpoint_prepare["source_history_sha256"]
                    or data["prepare_history_sha256"]
                    != checkpoint_prepare["prepare_history_sha256"]
                    or data["source_history_items"] + 1
                    != checkpoint_prepare["prepare_history_items"]
                    or data["action_turn_cutoff"] != expected_action_turn_cutoff
                ):
                    return None, True
                expected_history_items = 4
            else:
                provenance = (
                    started.get("completion_review_policy"),
                    started.get("context_checkpoint_policy_version"),
                    started.get("checkpoint_capsule_schema_version"),
                )
                if (
                    provenance
                    not in {
                        (None, None, None),
                        (
                            "fresh-checkpoint-v4",
                            _CONTEXT_CHECKPOINT_POLICY_VERSION,
                            None,
                        ),
                    }
                    or checkpoint_prepare is not None
                ):
                    return None, True
                expected_history_items = 3
            checkpoint_resolution_seen = True
            checkpoint_prepare = None
            checkpoint_expected_history = (
                data["checkpoint_history_sha256"],
                expected_history_items,
            )
        elif event_type == "context.checkpoint_rejected":
            started = events[0]["data"] if events else {}
            if (
                checkpoint_resolution_seen
                or not _valid_context_checkpoint_rejection(data)
                or started.get("completion_review_policy")
                not in {
                    "semantic-checkpoint-v5",
                    "semantic-checkpoint-v6",
                    "semantic-checkpoint-v7",
                    "semantic-checkpoint-v8",
                }
                or started.get("context_checkpoint_policy_version")
                != _SEMANTIC_CHECKPOINT_POLICY_VERSION
                or started.get("checkpoint_capsule_schema_version")
                != _SEMANTIC_CHECKPOINT_CAPSULE_SCHEMA
                or data["provider_turn_count"] != len(requests)
            ):
                return None, True
            if data["request_emitted"]:
                if (
                    checkpoint_prepare is None
                    or data["prepare_turn_index"] != checkpoint_prepare["turn_index"]
                    or data["source_history_sha256"]
                    != checkpoint_prepare["source_history_sha256"]
                    or data["prepare_history_sha256"]
                    != checkpoint_prepare["prepare_history_sha256"]
                    or requests.get(data["prepare_turn_index"])
                    not in {"completed", "failed"}
                ):
                    return None, True
            elif checkpoint_prepare is not None:
                return None, True
            checkpoint_resolution_seen = True
            checkpoint_prepare = None
        elif event_type == "tool.registered":
            call_id = data.get("call_id")
            provider_name = data.get("provider_name")
            binding = (
                (call_id, provider_name)
                if isinstance(call_id, str) and isinstance(provider_name, str)
                else None
            )
            registered_tools.append(binding)
            if binding is not None:
                if binding in registered_tool_ordinals:
                    ambiguous_tool_bindings.add(binding)
                else:
                    registered_tool_ordinals[binding] = len(registered_tools)
        elif event_type in {"tool.completed", "tool.failed"}:
            call_id = data.get("call_id")
            provider_name = data.get("provider_name")
            if isinstance(call_id, str) and isinstance(provider_name, str):
                settled_tool_bindings.add((call_id, provider_name))
        elif event_type == "tool.receipt":
            tool_receipt_signal = True
            tool_receipt_suffix_started = True
            sample = (
                _parse_tool_receipt_sample(
                    data,
                    event_schema=str(event["schema_version"]),
                )
                if isinstance(data, dict)
                else None
            )
            relation_valid = sample is not None
            if relation_valid and sample is not None:
                ordinal = int(sample["tool_call_ordinal"])
                binding = (
                    registered_tools[ordinal - 1]
                    if ordinal <= len(registered_tools)
                    else None
                )
                relation_valid = bool(
                    ordinal > previous_tool_receipt_ordinal
                    and binding is not None
                    and binding not in ambiguous_tool_bindings
                    and registered_tool_ordinals.get(binding) == ordinal
                    and binding in settled_tool_bindings
                    and sample["tool_identity_sha256"]
                    == _tool_identity_sha256(*binding)
                    and len(tool_receipt_samples) < _TOOL_RECEIPT_MAX_SAMPLES
                )
                if relation_valid:
                    previous_tool_receipt_ordinal = ordinal
                    tool_receipt_samples.append(sample)
            if not relation_valid:
                tool_receipt_invalid = True
                event["data"] = {}
            elif sample is not None:
                event["data"] = dict(sample)
        events.append(event)
    if checkpoint_expected_history is not None:
        return None, True
    if not events or events[0]["type"] != "run.started":
        return None, True
    if tool_receipt_suffix_started and not terminal_seen:
        tool_receipt_invalid = True
    if tool_receipt_invalid:
        tool_receipt_coverage = "invalid"
    elif tool_receipt_samples and tool_receipt_omitted_samples == 0:
        tool_receipt_coverage = "complete"
    elif tool_receipt_samples or tool_receipt_omitted_samples:
        tool_receipt_coverage = "partial"
    else:
        tool_receipt_coverage = "unavailable"
    in_flight = sum(1 for state in requests.values() if state == "requested")
    return (
        _EventPrefix(
            raw=raw,
            events=tuple(events),
            requested_count=len(requests),
            completed_count=completed,
            failed_count=failed,
            in_flight_count=in_flight,
            usage_present_count=usage_present,
            usage_absent_count=usage_absent,
            usage_covered_calls=usage_covered,
            input_tokens=input_total,
            cache_tokens=cache_total,
            output_tokens=output_total,
            provider_cost_ticks=cost_ticks,
            provider_cost_ticks_covered_calls=cost_covered,
            failed_usage_present_count=failed_usage_present,
            failed_usage_absent_count=failed_usage_absent,
            failed_input_tokens=failed_input_total,
            failed_cache_tokens=failed_cache_total,
            failed_output_tokens=failed_output_total,
            failed_provider_cost_ticks=failed_cost_ticks,
            failed_provider_cost_ticks_covered_calls=failed_cost_covered,
            usage_valid=usage_valid,
            tool_receipt_samples=tuple(tool_receipt_samples),
            tool_receipt_coverage=tool_receipt_coverage,
            tool_receipt_omitted_samples=tool_receipt_omitted_samples,
            tool_receipt_signal=tool_receipt_signal,
        ),
        False,
    )


def _read_event_prefix_outcome(
    runtime_dir: Path,
    spec: Mapping[str, Any],
) -> _EventPrefixRead:
    path = runtime_dir / "events.jsonl"
    if not path.exists() and not path.is_symlink():
        return _EventPrefixRead("absent", None, None)
    try:
        raw = _read_regular(path)
    except TB21Error:
        return _EventPrefixRead("invalid", None, None)
    prefix, invalid = _event_prefix_from_raw(raw, spec)
    return _EventPrefixRead("invalid" if invalid else "valid", raw, prefix)


def _read_event_prefix(
    runtime_dir: Path,
    spec: Mapping[str, Any],
) -> tuple[_EventPrefix | None, bool]:
    read = _read_event_prefix_outcome(runtime_dir, spec)
    return read.prefix, read.state == "invalid"


def _usage_state(
    *,
    requested: int,
    in_flight: int,
    failed: int,
    usage_covered: int,
    valid: bool,
) -> str:
    if not valid:
        return "invalid"
    if requested == 0:
        return "unavailable"
    if in_flight or usage_covered != requested:
        return "partial"
    return "complete"


def _from_prefix(prefix: _EventPrefix, *, record_valid: bool) -> _UsageTotals:
    state = _usage_state(
        requested=prefix.requested_count,
        in_flight=prefix.in_flight_count,
        failed=prefix.failed_count,
        usage_covered=prefix.usage_covered_calls,
        valid=prefix.usage_valid,
    )
    observed = prefix.usage_covered_calls > 0
    return _UsageTotals(
        input_tokens=prefix.input_tokens if observed else None,
        cache_tokens=prefix.cache_tokens if observed else None,
        output_tokens=prefix.output_tokens if observed else None,
        call_count=prefix.requested_count,
        provider_cost_ticks=prefix.provider_cost_ticks,
        provider_cost_ticks_covered_calls=(prefix.provider_cost_ticks_covered_calls),
        provider_cost_ticks_valid=prefix.usage_valid,
        requested_count=prefix.requested_count,
        completed_count=prefix.completed_count,
        failed_count=prefix.failed_count,
        in_flight_count=prefix.in_flight_count,
        usage_present_count=prefix.usage_present_count,
        usage_absent_count=prefix.usage_absent_count,
        usage_covered_calls=prefix.usage_covered_calls,
        state=state,
        source="event_prefix",
        record_valid=record_valid,
    )


def _invalid_usage(source: str) -> _UsageTotals:
    return _UsageTotals(
        input_tokens=None,
        cache_tokens=None,
        output_tokens=None,
        call_count=0,
        provider_cost_ticks=0,
        provider_cost_ticks_covered_calls=0,
        provider_cost_ticks_valid=False,
        requested_count=0,
        completed_count=0,
        failed_count=0,
        in_flight_count=0,
        usage_present_count=0,
        usage_absent_count=0,
        usage_covered_calls=0,
        state="invalid",
        source=source,
        record_valid=False,
    )


def _unavailable_usage() -> _UsageTotals:
    return _UsageTotals(
        input_tokens=None,
        cache_tokens=None,
        output_tokens=None,
        call_count=0,
        provider_cost_ticks=0,
        provider_cost_ticks_covered_calls=0,
        provider_cost_ticks_valid=True,
        requested_count=0,
        completed_count=0,
        failed_count=0,
        in_flight_count=0,
        usage_present_count=0,
        usage_absent_count=0,
        usage_covered_calls=0,
        state="unavailable",
        source="unavailable",
        record_valid=False,
    )


def _record_identity_valid(
    record: Mapping[str, Any],
    spec: Mapping[str, Any],
) -> bool:
    return bool(
        record.get("run_id") == spec.get("run_id")
        and record.get("trial_id") == spec.get("trial_id")
        and record.get("attempt_id") == spec.get("attempt_id")
        and record.get("run_spec_sha256") == rust_run_spec_sha256(spec)
    )


def _usage_from_v1(
    record: Mapping[str, Any],
    spec: Mapping[str, Any],
    event_bytes: bytes | None,
) -> _UsageTotals | None:
    if (
        set(record) != _V1_RUN_KEYS
        or record.get("schema_version") != "nano-run-record-alpha-1"
        or not _record_identity_valid(record, spec)
        or record.get("terminal_status") not in {"success", "provider_failure"}
        or not isinstance(record.get("terminal_code"), str)
        or not record["terminal_code"]
        or not isinstance(record.get("raw_usage"), list)
    ):
        return None
    requested = _nonnegative_integer(record.get("provider_turn_count"))
    if requested is None:
        return None
    raw_usage = record["raw_usage"]
    completed = len(raw_usage)
    if completed > requested:
        return None
    terminal_status = record["terminal_status"]
    if terminal_status == "success" and completed != requested:
        return None
    failed = requested - completed if terminal_status == "provider_failure" else 0
    if terminal_status == "provider_failure" and failed == 0:
        return None
    if event_bytes is not None:
        expected_hash = record.get("events_sha256")
        if (
            not isinstance(expected_hash, str)
            or expected_hash != hashlib.sha256(event_bytes).hexdigest()
        ):
            return None
    input_total = 0
    cache_total = 0
    output_total = 0
    cost_ticks = 0
    cost_covered = 0
    usage_present = 0
    usage_absent = 0
    usage_covered = 0
    valid = True
    for native in raw_usage:
        if native is None:
            usage_absent += 1
            continue
        usage_present += 1
        parsed = _usage_value(native)
        if parsed is None:
            valid = False
            continue
        input_tokens, cache_tokens, output_tokens, ticks = parsed
        input_total += input_tokens
        cache_total += cache_tokens
        output_total += output_tokens
        usage_covered += 1
        if ticks is not None:
            cost_ticks += ticks
            cost_covered += 1
    state = _usage_state(
        requested=requested,
        in_flight=0,
        failed=failed,
        usage_covered=usage_covered,
        valid=valid,
    )
    observed = usage_covered > 0
    return _UsageTotals(
        input_tokens=input_total if observed else None,
        cache_tokens=cache_total if observed else None,
        output_tokens=output_total if observed else None,
        call_count=requested,
        provider_cost_ticks=cost_ticks,
        provider_cost_ticks_covered_calls=cost_covered,
        provider_cost_ticks_valid=valid,
        requested_count=requested,
        completed_count=completed,
        failed_count=failed,
        in_flight_count=0,
        usage_present_count=usage_present,
        usage_absent_count=usage_absent,
        usage_covered_calls=usage_covered,
        state=state,
        source="run_record_v1",
        record_valid=True,
    )


def _coverage_values(value: object) -> dict[str, int | str] | None:
    integer_fields = {
        "requested",
        "completed",
        "failed",
        "in_flight",
        "usage_present",
        "usage_absent",
        "usage_covered",
        "cost_present",
        "cost_absent",
    }
    if (
        not isinstance(value, dict)
        or set(value) != integer_fields | {"state"}
        or value.get("state")
        not in {
            "complete",
            "partial",
            "unavailable",
            "invalid",
        }
    ):
        return None
    result: dict[str, int | str] = {"state": str(value["state"])}
    for field in integer_fields:
        parsed = _nonnegative_integer(value[field])
        if parsed is None:
            return None
        result[field] = parsed
    requested = int(result["requested"])
    completed = int(result["completed"])
    failed = int(result["failed"])
    in_flight = int(result["in_flight"])
    usage_present = int(result["usage_present"])
    usage_absent = int(result["usage_absent"])
    cost_present = int(result["cost_present"])
    cost_absent = int(result["cost_absent"])
    usage_covered = int(result["usage_covered"])
    settled = completed + failed
    usage_observed = usage_present + usage_absent
    cost_observed = cost_present + cost_absent
    if (
        settled + in_flight != requested
        or usage_observed not in {completed, settled}
        or cost_observed not in {completed, settled}
        or usage_covered > requested
        or (
            result["state"] == "complete"
            and (in_flight != 0 or usage_covered != requested)
        )
    ):
        return None
    return result


def _usage_from_v2(
    record: Mapping[str, Any],
    spec: Mapping[str, Any],
    prefix: _EventPrefix | None,
) -> _UsageTotals | None:
    if (
        prefix is None
        or not _record_identity_valid(record, spec)
        or record.get("events_sha256") != hashlib.sha256(prefix.raw).hexdigest()
        or record.get("final_event_seq") != len(prefix.events) - 1
        or record.get("terminal_status")
        not in {
            "success",
            "provider_failure",
            "tool_failure",
            "deadline_failure",
            "cancelled",
            "runtime_failure",
        }
        or not isinstance(record.get("terminal_code"), str)
        or not record["terminal_code"]
    ):
        return None
    status = record["terminal_status"]
    phase = record.get("terminal_phase")
    valid_phase = {
        "success": {None},
        "provider_failure": {"provider"},
        "tool_failure": {"tool", "bridge"},
        "deadline_failure": {"deadline"},
        "cancelled": {"cancellation"},
        "runtime_failure": {"runtime", "artifact"},
    }
    if phase not in valid_phase[status]:
        return None
    coverage = _coverage_values(record.get("provider_call_coverage"))
    totals = record.get("usage_totals")
    if (
        coverage is None
        or not isinstance(totals, dict)
        or set(totals)
        != {
            "input_tokens",
            "cached_input_tokens",
            "output_tokens",
            "provider_cost_ticks",
        }
    ):
        return None
    settled_usage_shape = (
        int(coverage["usage_present"]) + int(coverage["usage_absent"])
        == prefix.completed_count + prefix.failed_count
    )
    settled_cost_shape = (
        int(coverage["cost_present"]) + int(coverage["cost_absent"])
        == prefix.completed_count + prefix.failed_count
    )
    expected_usage_present = prefix.usage_present_count
    expected_usage_absent = prefix.usage_absent_count
    expected_cost_present = prefix.provider_cost_ticks_covered_calls
    expected_cost_observed_calls = prefix.completed_count + prefix.failed_count
    if not settled_usage_shape:
        expected_usage_present -= prefix.failed_usage_present_count
        expected_usage_absent -= prefix.failed_usage_absent_count
    if not settled_cost_shape:
        expected_cost_present -= prefix.failed_provider_cost_ticks_covered_calls
        expected_cost_observed_calls = prefix.completed_count
    expected_counts = (
        prefix.requested_count,
        prefix.completed_count,
        prefix.failed_count,
        prefix.in_flight_count,
        expected_usage_present,
        expected_usage_absent,
        expected_usage_present,
        expected_cost_present,
        expected_cost_observed_calls - expected_cost_present,
    )
    actual_counts = tuple(
        int(coverage[field])
        for field in (
            "requested",
            "completed",
            "failed",
            "in_flight",
            "usage_present",
            "usage_absent",
            "usage_covered",
            "cost_present",
            "cost_absent",
        )
    )
    if expected_counts != actual_counts:
        return None
    token_values = (
        totals.get("input_tokens"),
        totals.get("cached_input_tokens"),
        totals.get("output_tokens"),
    )
    tokens: tuple[int, int, int] | None
    if token_values == (None, None, None):
        tokens = None
    else:
        parsed_tokens = tuple(_nonnegative_integer(item) for item in token_values)
        if any(item is None for item in parsed_tokens):
            return None
        tokens = (
            int(parsed_tokens[0]),
            int(parsed_tokens[1]),
            int(parsed_tokens[2]),
        )
        if tokens[1] > tokens[0]:
            return None
    expected_tokens = (
        (
            prefix.input_tokens
            - (0 if settled_usage_shape else prefix.failed_input_tokens),
            prefix.cache_tokens
            - (0 if settled_usage_shape else prefix.failed_cache_tokens),
            prefix.output_tokens
            - (0 if settled_usage_shape else prefix.failed_output_tokens),
        )
        if expected_usage_present > 0
        else None
    )
    if tokens != expected_tokens:
        return None
    raw_ticks = totals.get("provider_cost_ticks")
    provider_ticks = None if raw_ticks is None else _nonnegative_integer(raw_ticks)
    if raw_ticks is not None and provider_ticks is None:
        return None
    expected_ticks_value = prefix.provider_cost_ticks - (
        0 if settled_cost_shape else prefix.failed_provider_cost_ticks
    )
    expected_ticks = expected_ticks_value if expected_cost_present > 0 else None
    if provider_ticks != expected_ticks:
        return None
    requested = int(coverage["requested"])
    completed = int(coverage["completed"])
    failed = int(coverage["failed"])
    in_flight = int(coverage["in_flight"])
    usage_present = int(coverage["usage_present"])
    usage_absent = int(coverage["usage_absent"])
    usage_covered = int(coverage["usage_covered"])
    cost_present = int(coverage["cost_present"])
    return _UsageTotals(
        input_tokens=tokens[0] if tokens is not None else None,
        cache_tokens=tokens[1] if tokens is not None else None,
        output_tokens=tokens[2] if tokens is not None else None,
        call_count=requested,
        provider_cost_ticks=provider_ticks or 0,
        provider_cost_ticks_covered_calls=cost_present,
        provider_cost_ticks_valid=coverage["state"] != "invalid",
        requested_count=requested,
        completed_count=completed,
        failed_count=failed,
        in_flight_count=in_flight,
        usage_present_count=usage_present,
        usage_absent_count=usage_absent,
        usage_covered_calls=usage_covered,
        state=str(coverage["state"]),
        source="run_record_v2",
        record_valid=True,
    )


def _usage_without_run_record(
    runtime_dir: Path,
    spec: Mapping[str, Any],
    *,
    read: _RunRecordRead,
    usage_fallback: _UsageTotals | None = None,
    receipt_checked: bool = False,
) -> _UsageTotals:
    if usage_fallback is not None:
        return usage_fallback
    if not receipt_checked:
        receipt_usage = _usage_from_bound_receipt(runtime_dir, spec, read)
        if receipt_usage is not None:
            return receipt_usage
    if read.prefix_usage is not None:
        return read.prefix_usage
    if read.events_state == "invalid" or read.state == "invalid":
        return _invalid_usage(
            "event_prefix" if read.events_state == "invalid" else "run_record"
        )
    return _unavailable_usage()


def _usage(
    runtime_dir: Path,
    spec: Mapping[str, Any],
) -> _UsageTotals:
    read = _read_run_record(runtime_dir, spec)
    if read.parsed is not None:
        return read.parsed.usage
    return _usage_without_run_record(
        runtime_dir,
        spec,
        read=read,
    )


def _runtime_evidence(
    runtime_dir: Path,
    spec: Mapping[str, Any],
) -> _RuntimeEvidence | None:
    parsed = _parse_run_record(runtime_dir, spec)
    return parsed.runtime if parsed is not None else None


def _sha256_string(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _canonical_mapping(
    path: Path,
    *,
    limit: int = _MAX_JSON_BYTES,
) -> tuple[Mapping[str, Any], bytes] | None:
    try:
        raw = _read_regular(path, limit=limit)
        value = json.loads(raw)
    except (TB21Error, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or raw != _canonical(value):
        return None
    return value, raw


def _run_record_mapping(
    path: Path,
    *,
    limit: int = _MAX_JSON_BYTES,
) -> tuple[Mapping[str, Any], bytes] | None:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate_json_key")
            value[key] = item
        return value

    def reject_constant(_value: str) -> Any:
        raise ValueError("invalid_json_constant")

    try:
        raw = _read_regular(path, limit=limit)
        value = json.loads(
            raw,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (TB21Error, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(value, dict):
        return None
    return value, raw


def _deadline_receipt_binding_valid(
    *,
    runtime_dir: Path,
    spec: Mapping[str, Any],
    record: Mapping[str, Any],
    prefix: _EventPrefix,
) -> bool:
    bound_sha256 = record.get("deadline_receipt_sha256")
    if not _sha256_string(bound_sha256):
        return False
    try:
        raw = _read_regular(runtime_dir / "deadline.json", limit=1024 * 1024)
        receipt = RunDeadlineReceiptV1.from_bytes(raw)
    except (TB21Error, DeadlineContractError):
        return False
    started = prefix.events[0]
    expected_identity = (
        spec.get("run_id"),
        spec.get("trial_id"),
        spec.get("attempt_id"),
    )
    return bool(
        raw == receipt.to_bytes()
        and hashlib.sha256(raw).hexdigest() == bound_sha256
        and (
            receipt.run_id,
            receipt.trial_id,
            receipt.attempt_id,
        )
        == expected_identity
        == (
            record.get("run_id"),
            record.get("trial_id"),
            record.get("attempt_id"),
        )
        and receipt.run_spec_sha256 == rust_run_spec_sha256(spec)
        and started["type"] == "run.started"
        and started["data"].get("deadline_receipt_sha256") == bound_sha256
    )


def _legacy_runtime_evidence(
    record: Mapping[str, Any],
    events: _EventPrefixRead,
) -> _RuntimeEvidence | None:
    prefix = events.prefix
    code = record.get("terminal_code")
    if (
        events.state != "valid"
        or prefix is None
        or prefix.events[0]["schema_version"] != "event-v1"
        or not isinstance(code, str)
        or not code
    ):
        return None
    last = prefix.events[-1]
    if (
        record.get("final_event_seq") != len(prefix.events) - 1
        or last["data"].get("code") != code
    ):
        return None
    status = record.get("terminal_status")
    if status == "success" and last["type"] == "run.completed":
        return _RuntimeEvidence("success", None, code, None, None)
    provider_codes = [
        event["data"].get("code")
        for event in prefix.events
        if event["type"] == "provider.failed"
    ]
    if (
        status != "provider_failure"
        or last["type"] != "run.failed"
        or code not in provider_codes
    ):
        return None
    return _RuntimeEvidence("provider_failure", "provider", code, code, None)


def _parse_run_record_document(
    runtime_dir: Path,
    spec: Mapping[str, Any],
    document: tuple[Mapping[str, Any], bytes],
    events: _EventPrefixRead,
) -> _ParsedRunRecord | None:
    record, _raw = document
    schema = record.get("schema_version")
    if not isinstance(schema, str):
        return None
    variant = _RUN_RECORD_VARIANTS.get((schema, frozenset(record)))
    if variant is None or not _record_identity_valid(record, spec):
        return None

    prefix = events.prefix
    deadline_path = runtime_dir / "deadline.json"
    if variant == "legacy_v1":
        if deadline_path.exists() or deadline_path.is_symlink():
            return None
        event_bytes = events.raw
        usage = _usage_from_v1(record, spec, event_bytes)
        code = record.get("terminal_code")
        if usage is None or not isinstance(code, str):
            return None
        return _ParsedRunRecord(
            variant=variant,
            schema_version=schema,
            run_id=str(record["run_id"]),
            trial_id=str(record["trial_id"]),
            attempt_id=str(record["attempt_id"]),
            run_spec_sha256=str(record["run_spec_sha256"]),
            events_sha256=str(record["events_sha256"]),
            deadline_receipt_sha256=None,
            usage=usage,
            runtime=_legacy_runtime_evidence(record, events),
            tool_receipt_samples=(
                prefix.tool_receipt_samples if prefix is not None else ()
            ),
            tool_receipt_coverage=(
                prefix.tool_receipt_coverage if prefix is not None else "unavailable"
            ),
            tool_receipt_omitted_samples=(
                prefix.tool_receipt_omitted_samples if prefix is not None else 0
            ),
            tool_receipt_signal=(
                prefix.tool_receipt_signal if prefix is not None else False
            ),
        )

    if events.state == "invalid" or prefix is None:
        return None
    usage = _usage_from_v2(record, spec, prefix)
    status = record.get("terminal_status")
    phase = record.get("terminal_phase")
    code = record.get("terminal_code")
    last = prefix.events[-1]
    numeric_fields = (
        "final_event_seq",
        "provider_turn_count",
        "tool_call_count",
        "start_elapsed_ms",
        "end_elapsed_ms",
    )
    registered_tools = sum(
        event["type"] == "tool.registered" for event in prefix.events
    )
    artifact_prefix_gap = status == "runtime_failure" and phase == "artifact"
    if (
        usage is None
        or not isinstance(code, str)
        or prefix.events[0]["schema_version"] not in {"event-v2", "event-v3"}
        or record.get("final_event_seq") != len(prefix.events) - 1
        or last["data"].get("code") != code
        or any(
            _nonnegative_integer(record.get(field)) is None for field in numeric_fields
        )
        or record.get("provider_turn_count") != prefix.requested_count
        or not run_event_elapsed_bounds_valid(
            start_elapsed_ms=record.get("start_elapsed_ms"),
            end_elapsed_ms=record.get("end_elapsed_ms"),
            first_event_elapsed_ms=prefix.events[0]["elapsed_ms"],
            terminal_event_elapsed_ms=last["elapsed_ms"],
        )
        or registered_tools > record["tool_call_count"]
        or (registered_tools != record["tool_call_count"] and not artifact_prefix_gap)
    ):
        return None
    expected_terminal = "run.completed" if status == "success" else "run.failed"
    if last["type"] != expected_terminal:
        return None
    if variant in {"v2_deadline_compat", "v3"}:
        if not _deadline_receipt_binding_valid(
            runtime_dir=runtime_dir,
            spec=spec,
            record=record,
            prefix=prefix,
        ):
            return None
    elif deadline_path.exists() or deadline_path.is_symlink():
        return None

    runtime = _RuntimeEvidence(
        terminal_status=str(status),
        terminal_phase=str(phase) if phase is not None else None,
        terminal_code=code,
        provider_failure_code=code if status == "provider_failure" else None,
        recoverability=next(
            (
                str(event["data"]["recoverability"])
                for event in reversed(prefix.events)
                if event["type"] == "tool.failed"
                and event["data"].get("code") == code
                and event["data"].get("recoverability") in {"recoverable", "fatal"}
            ),
            None,
        ),
    )
    return _ParsedRunRecord(
        variant=variant,
        schema_version=schema,
        run_id=str(record["run_id"]),
        trial_id=str(record["trial_id"]),
        attempt_id=str(record["attempt_id"]),
        run_spec_sha256=str(record["run_spec_sha256"]),
        events_sha256=str(record["events_sha256"]),
        deadline_receipt_sha256=(
            str(record["deadline_receipt_sha256"])
            if variant in {"v2_deadline_compat", "v3"}
            else None
        ),
        usage=usage,
        runtime=runtime,
        tool_receipt_samples=prefix.tool_receipt_samples,
        tool_receipt_coverage=prefix.tool_receipt_coverage,
        tool_receipt_omitted_samples=prefix.tool_receipt_omitted_samples,
        tool_receipt_signal=prefix.tool_receipt_signal,
    )


def _run_record_read(
    *,
    state: str,
    parsed: _ParsedRunRecord | None,
    record: Mapping[str, Any] | None,
    events: _EventPrefixRead,
) -> _RunRecordRead:
    prefix = events.prefix
    return _RunRecordRead(
        state=state,
        parsed=parsed,
        record=record,
        events_state=events.state,
        events_raw=events.raw,
        prefix_usage=(
            _from_prefix(events.prefix, record_valid=state != "invalid")
            if events.prefix is not None
            else None
        ),
        tool_receipt_samples=(
            prefix.tool_receipt_samples if prefix is not None else ()
        ),
        tool_receipt_coverage=(
            prefix.tool_receipt_coverage if prefix is not None else "unavailable"
        ),
        tool_receipt_omitted_samples=(
            prefix.tool_receipt_omitted_samples if prefix is not None else 0
        ),
        tool_receipt_signal=(
            prefix.tool_receipt_signal if prefix is not None else False
        ),
    )


def _compact_run_record_read(read: _RunRecordRead) -> _RunRecordRead:
    return _RunRecordRead(
        state=read.state,
        parsed=read.parsed,
        record=None,
        events_state=read.events_state,
        events_raw=None,
        prefix_usage=read.prefix_usage,
        tool_receipt_samples=read.tool_receipt_samples,
        tool_receipt_coverage=read.tool_receipt_coverage,
        tool_receipt_omitted_samples=read.tool_receipt_omitted_samples,
        tool_receipt_signal=read.tool_receipt_signal,
    )


def _read_run_record(
    runtime_dir: Path,
    spec: Mapping[str, Any],
) -> _RunRecordRead:
    events = _read_event_prefix_outcome(runtime_dir, spec)
    path = runtime_dir / "run.json"
    if not path.exists() and not path.is_symlink():
        return _run_record_read(
            state="absent",
            parsed=None,
            record=None,
            events=events,
        )
    document = _run_record_mapping(path)
    if document is None:
        return _run_record_read(
            state="invalid",
            parsed=None,
            record=None,
            events=events,
        )
    parsed = _parse_run_record_document(runtime_dir, spec, document, events)
    return _run_record_read(
        state="valid" if parsed is not None else "invalid",
        parsed=parsed,
        record=document[0] if parsed is not None else None,
        events=events,
    )


def _parse_run_record(
    runtime_dir: Path,
    spec: Mapping[str, Any],
) -> _ParsedRunRecord | None:
    parsed = _read_run_record(runtime_dir, spec).parsed
    return parsed if parsed is not None and parsed.runtime is not None else None


def _empty_artifact_evidence(
    *,
    publication_kind: str | None = None,
    workspace_receipt_valid: bool = False,
    workspace_snapshot_complete: bool = False,
    workspace_status: str | None = None,
    workspace_failure_stage: str | None = None,
    workspace_failure_category: str | None = None,
    workspace_failure_v3: _WorkspaceFailureProjection | None = None,
    usage_receipt_valid: bool = False,
    terminal_status: str | None = None,
    terminal_phase: str | None = None,
    terminal_code: str | None = None,
    run_record_read: _RunRecordRead | None = None,
    usage_fallback: _UsageTotals | None = None,
) -> _ArtifactEvidence:
    return _ArtifactEvidence(
        artifacts_valid=False,
        success_valid=False,
        direct_atif_valid=False,
        diagnostic_valid=False,
        publication_valid=False,
        trajectory_valid=False,
        publication_kind=publication_kind,
        workspace_receipt_valid=workspace_receipt_valid,
        workspace_snapshot_complete=workspace_snapshot_complete,
        workspace_status=workspace_status,
        workspace_failure_stage=workspace_failure_stage,
        workspace_failure_category=workspace_failure_category,
        workspace_failure_v3=workspace_failure_v3,
        usage_receipt_valid=usage_receipt_valid,
        terminal_status=terminal_status,
        terminal_phase=terminal_phase,
        terminal_code=terminal_code,
        run_record_read=(
            _compact_run_record_read(run_record_read)
            if run_record_read is not None
            else None
        ),
        usage_fallback=usage_fallback,
    )


def _workspace_receipt_evidence(
    logs_dir: Path,
    expected_sha256: object,
) -> _WorkspaceEvidence:
    if not _sha256_string(expected_sha256):
        return _WorkspaceEvidence()
    try:
        receipt = load_workspace_receipt(logs_dir / "workspace-receipt.json")
    except WorkspaceSnapshotError:
        return _WorkspaceEvidence()
    if receipt.canonical_sha256 != expected_sha256:
        return _WorkspaceEvidence()
    if receipt.status == "failed":
        failure = receipt.failure
        if failure is None:
            return _WorkspaceEvidence()
        failure_v3: _WorkspaceFailureProjection | None = None
        if receipt.schema_version in {
            "nano-workspace-receipt-v3",
            "nano-workspace-receipt-v4",
            "nano-workspace-receipt-v5",
        }:
            failure_v3 = (
                failure.subtype.value,
                failure.timeout_origin.value,
                failure.stage_validated,
                failure.termination_verified,
                failure.cleanup_verified,
                failure.zero_census_verified,
                (
                    failure.execution_binding_verified
                    if receipt.schema_version == "nano-workspace-receipt-v5"
                    else None
                ),
            )
        return _WorkspaceEvidence(
            receipt_valid=True,
            snapshot_complete=False,
            status="failed",
            failure_stage=failure.stage,
            failure_category=failure.category,
            failure_v3=failure_v3,
        )
    if receipt.status != "complete":
        return _WorkspaceEvidence()
    for name in sorted(_WORKSPACE_ARTIFACT_NAMES):
        try:
            payload = _read_regular(
                logs_dir / name,
                limit=128 * 1024 * 1024,
            )
        except TB21Error:
            return _WorkspaceEvidence()
        if len(payload) != receipt.artifact_byte_lengths.get(name) or hashlib.sha256(
            payload
        ).hexdigest() != receipt.artifact_hashes.get(name):
            return _WorkspaceEvidence()
        if name.endswith(".json"):
            try:
                value = json.loads(payload)
            except (UnicodeDecodeError, json.JSONDecodeError):
                return _WorkspaceEvidence()
            if not isinstance(value, dict) or payload != _canonical(value):
                return _WorkspaceEvidence()
    return _WorkspaceEvidence(
        receipt_valid=True,
        snapshot_usable=True,
        snapshot_complete=not receipt.truncated,
        status="partial_valid" if receipt.truncated else "complete",
    )


def _usage_from_receipt(
    *,
    logs_dir: Path,
    marker: Mapping[str, Any],
    spec: Mapping[str, Any],
    record: Mapping[str, Any] | None,
) -> _UsageTotals | None:
    document = _canonical_mapping(
        logs_dir / "runtime-usage-receipt.json",
        limit=1024 * 1024,
    )
    if document is None:
        return None
    receipt, raw = document
    coverage = _coverage_values(receipt.get("provider_call_coverage"))
    totals = receipt.get("usage_totals")
    expected_identity = (
        spec.get("run_id"),
        spec.get("trial_id"),
        spec.get("attempt_id"),
    )
    if (
        set(receipt) != _USAGE_RECEIPT_KEYS
        or receipt.get("schema_version") != "nano-usage-receipt-v1"
        or hashlib.sha256(raw).hexdigest() != marker.get("usage_receipt_sha256")
        or (
            receipt.get("run_id"),
            receipt.get("trial_id"),
            receipt.get("attempt_id"),
        )
        != expected_identity
        or receipt.get("run_spec_sha256") != rust_run_spec_sha256(spec)
        or receipt.get("events_sha256") != marker.get("events_sha256")
        or coverage is None
        or not isinstance(totals, dict)
        or set(totals)
        != {
            "input_tokens",
            "cached_input_tokens",
            "output_tokens",
            "provider_cost_ticks",
        }
        or any(
            value is not None and _nonnegative_integer(value) is None
            for value in totals.values()
        )
    ):
        return None
    token_fields = ("input_tokens", "cached_input_tokens", "output_tokens")
    usage_present = int(coverage["usage_present"])
    token_values = tuple(totals[field] for field in token_fields)
    if usage_present == 0:
        tokens_valid = token_values == (None, None, None)
    else:
        tokens_valid = all(value is not None for value in token_values)
    if not tokens_valid or (int(coverage["cost_present"]) == 0) != (
        totals["provider_cost_ticks"] is None
    ):
        return None
    if (
        totals["input_tokens"] is not None
        and totals["cached_input_tokens"] > totals["input_tokens"]
    ):
        return None
    if record is not None and (
        receipt["provider_call_coverage"] != record.get("provider_call_coverage")
        or receipt["usage_totals"] != record.get("usage_totals")
    ):
        return None
    return _UsageTotals(
        input_tokens=totals["input_tokens"],
        cache_tokens=totals["cached_input_tokens"],
        output_tokens=totals["output_tokens"],
        call_count=int(coverage["requested"]),
        provider_cost_ticks=totals["provider_cost_ticks"] or 0,
        provider_cost_ticks_covered_calls=int(coverage["cost_present"]),
        provider_cost_ticks_valid=coverage["state"] != "invalid",
        requested_count=int(coverage["requested"]),
        completed_count=int(coverage["completed"]),
        failed_count=int(coverage["failed"]),
        in_flight_count=int(coverage["in_flight"]),
        usage_present_count=int(coverage["usage_present"]),
        usage_absent_count=int(coverage["usage_absent"]),
        usage_covered_calls=int(coverage["usage_covered"]),
        state=str(coverage["state"]),
        source="usage_receipt_v2",
        record_valid=True,
    )


def _usage_from_bound_receipt(
    runtime_dir: Path,
    spec: Mapping[str, Any],
    read: _RunRecordRead | None = None,
) -> _UsageTotals | None:
    logs_dir = runtime_dir.parent
    marker_document = _canonical_mapping(logs_dir / "agent-run.json")
    if marker_document is None:
        return None
    marker = marker_document[0]
    if (
        marker.get("schema_version") != "nano-agent-run-v2"
        or marker.get("publication_kind") != "emergency_prefix"
        or marker.get("run_record_schema") is not None
        or (
            marker.get("run_id"),
            marker.get("trial_id"),
            marker.get("attempt_id"),
        )
        != (
            spec.get("run_id"),
            spec.get("trial_id"),
            spec.get("attempt_id"),
        )
        or marker.get("run_spec_sha256") != rust_run_spec_sha256(spec)
    ):
        return None
    selected_read = read or _read_run_record(runtime_dir, spec)
    if selected_read.events_state == "absent":
        events = b""
    elif selected_read.events_raw is not None:
        events = selected_read.events_raw
    else:
        return None
    if hashlib.sha256(events).hexdigest() != marker.get("events_sha256"):
        return None
    return _usage_from_receipt(
        logs_dir=logs_dir,
        marker=marker,
        spec=spec,
        record=None,
    )


def _background_binding_valid(
    *,
    logs_dir: Path,
    marker: Mapping[str, Any],
    spec: Mapping[str, Any],
) -> bool:
    has_digest = "background_manifest_sha256" in marker
    has_count = "background_task_count" in marker
    if has_digest != has_count:
        return False
    if not has_digest:
        return True
    try:
        background = validate_background_manifest(logs_dir=logs_dir, run_spec=spec)
    except ArtifactError:
        return False
    return bool(
        marker.get("background_manifest_sha256") == background.sha256
        and marker.get("background_task_count") == background.task_count
    )


def _legacy_artifact_evidence(
    *,
    logs_dir: Path,
    marker: Mapping[str, Any],
    marker_raw: bytes,
    spec: Mapping[str, Any],
    read: _RunRecordRead,
) -> _ArtifactEvidence:
    parsed = read.parsed
    required_marker = {
        "schema_version",
        "run_id",
        "trial_id",
        "attempt_id",
        "run_spec_sha256",
        "events_sha256",
        "trajectory_sha256",
        "background_manifest_sha256",
        "background_task_count",
    }
    trajectory_document = _canonical_mapping(logs_dir / "trajectory.json")
    events = read.events_raw
    if events is None:
        return _empty_artifact_evidence(
            publication_kind="success_atif",
            run_record_read=read,
        )
    if (
        parsed is None
        or parsed.variant != "legacy_v1"
        or read.record is None
        or trajectory_document is None
    ):
        return _empty_artifact_evidence(
            publication_kind="success_atif",
            run_record_read=read,
        )
    record = read.record
    _trajectory, trajectory_raw = trajectory_document
    spec_sha256 = rust_run_spec_sha256(spec)
    identity = (
        spec.get("run_id"),
        spec.get("trial_id"),
        spec.get("attempt_id"),
    )
    valid = bool(
        marker_raw == _canonical(marker)
        and set(marker) == required_marker
        and record.get("schema_version") == "nano-run-record-alpha-1"
        and marker.get("schema_version") == "nano-agent-run-v1"
        and record.get("terminal_status") == "success"
        and record.get("terminal_code") == "completed"
        and record.get("run_spec_sha256") == spec_sha256
        and marker.get("run_spec_sha256") == spec_sha256
        and identity
        == (
            record.get("run_id"),
            record.get("trial_id"),
            record.get("attempt_id"),
        )
        == (
            marker.get("run_id"),
            marker.get("trial_id"),
            marker.get("attempt_id"),
        )
        and parsed.usage.record_valid
        and record.get("events_sha256") == hashlib.sha256(events).hexdigest()
        and marker.get("events_sha256") == record.get("events_sha256")
        and marker.get("trajectory_sha256")
        == hashlib.sha256(trajectory_raw).hexdigest()
        and not (logs_dir / "partial-trajectory.json").exists()
        and not (logs_dir / "emergency-prefix.json").exists()
        and _background_binding_valid(
            logs_dir=logs_dir,
            marker=marker,
            spec=spec,
        )
    )
    return _ArtifactEvidence(
        artifacts_valid=valid,
        success_valid=False,
        direct_atif_valid=False,
        diagnostic_valid=valid,
        publication_valid=valid,
        trajectory_valid=valid,
        publication_kind="success_atif",
        workspace_receipt_valid=False,
        workspace_snapshot_complete=False,
        workspace_status=None,
        workspace_failure_stage=None,
        workspace_failure_category=None,
        workspace_failure_v3=None,
        usage_receipt_valid=False,
        terminal_status="success" if valid else None,
        terminal_phase=None,
        terminal_code="completed" if valid else None,
        run_record_read=_compact_run_record_read(read),
    )


def _terminal_atif_artifact_evidence(
    *,
    logs_dir: Path,
    marker: Mapping[str, Any],
    marker_raw: bytes,
    spec: Mapping[str, Any],
    read: _RunRecordRead,
) -> _ArtifactEvidence:
    """Validate the v4 direct-ATIF failure publication without reward input."""

    kind = marker.get("publication_kind")
    status = marker.get("terminal_status")
    phase = marker.get("terminal_phase")
    code = marker.get("terminal_code")
    base = _empty_artifact_evidence(
        publication_kind=str(kind) if isinstance(kind, str) else None,
        terminal_status=str(status) if isinstance(status, str) else None,
        terminal_phase=str(phase) if isinstance(phase, str) else None,
        terminal_code=str(code) if isinstance(code, str) else None,
        run_record_read=_compact_run_record_read(read),
    )
    if kind not in {"failure_atif", "emergency_atif"}:
        return base
    expected_diagnostic = {
        "failure_atif": ("partial-trajectory.json", "nano-partial-trajectory-v1"),
        "emergency_atif": ("emergency-prefix.json", "nano-emergency-prefix-v1"),
    }[str(kind)]
    diagnostic_name, diagnostic_schema = expected_diagnostic
    marker_fields = set(marker)
    optional_fields = marker_fields - _V4_TERMINAL_MARKER_REQUIRED_KEYS
    expected_identity = (
        spec.get("run_id"),
        spec.get("trial_id"),
        spec.get("attempt_id"),
    )
    terminal_phases = {
        "provider_failure": {"provider"},
        "tool_failure": {"tool", "bridge"},
        "deadline_failure": {"deadline"},
        "cancelled": {"cancellation"},
        "runtime_failure": {"artifact", "runtime"},
    }
    if (
        marker_raw != _canonical(marker)
        or not _V4_TERMINAL_MARKER_REQUIRED_KEYS.issubset(marker_fields)
        or not optional_fields.issubset(_V4_TERMINAL_MARKER_OPTIONAL_KEYS)
        or (
            ("background_manifest_sha256" in marker)
            != ("background_task_count" in marker)
        )
        or (
            marker.get("run_id"),
            marker.get("trial_id"),
            marker.get("attempt_id"),
        )
        != expected_identity
        or marker.get("run_spec_sha256") != rust_run_spec_sha256(spec)
        or marker.get("trajectory_path") != "trajectory.json"
        or marker.get("diagnostic_path") != diagnostic_name
        or not all(
            _sha256_string(marker.get(field))
            for field in (
                "events_sha256",
                "trajectory_sha256",
                "diagnostic_sha256",
                "usage_receipt_sha256",
            )
        )
        or (
            "deadline_receipt_sha256" in marker
            and not _sha256_string(marker.get("deadline_receipt_sha256"))
        )
        or (
            "background_manifest_sha256" in marker
            and not _sha256_string(marker.get("background_manifest_sha256"))
        )
        or (
            "workspace_receipt_sha256" in marker
            and not _sha256_string(marker.get("workspace_receipt_sha256"))
        )
        or status not in terminal_phases
        or phase not in terminal_phases[status]
        or not isinstance(code, str)
        or not code
    ):
        return base

    parsed = read.parsed
    record: Mapping[str, Any] | None = None
    if kind == "failure_atif":
        if (
            parsed is None
            or parsed.runtime is None
            or read.record is None
            or read.events_raw is None
        ):
            return base
        record = read.record
        runtime = parsed.runtime
        deadline_field_present = "deadline_receipt_sha256" in marker
        if (
            marker.get("run_record_schema") != parsed.schema_version
            or marker.get("events_sha256") != parsed.events_sha256
            or marker.get("events_sha256")
            != hashlib.sha256(read.events_raw).hexdigest()
            or marker.get("terminal_status") != runtime.terminal_status
            or marker.get("terminal_phase") != runtime.terminal_phase
            or marker.get("terminal_code") != runtime.terminal_code
            or deadline_field_present != (parsed.variant == "v3")
            or (
                deadline_field_present
                and marker.get("deadline_receipt_sha256")
                != parsed.deadline_receipt_sha256
            )
        ):
            return base
        events = read.events_raw
    else:
        if (
            read.state != "absent"
            or parsed is not None
            or marker.get("run_record_schema") is not None
            or "deadline_receipt_sha256" in marker
        ):
            return base
        events = read.events_raw if read.events_raw is not None else b""
        if marker.get("events_sha256") != hashlib.sha256(events).hexdigest():
            return base

    trajectory_document = _canonical_mapping(logs_dir / "trajectory.json")
    diagnostic_document = _canonical_mapping(logs_dir / diagnostic_name)
    if trajectory_document is None or diagnostic_document is None:
        return base
    trajectory, trajectory_raw = trajectory_document
    diagnostic, diagnostic_raw = diagnostic_document
    failure_identity = {
        "status": status,
        "phase": phase,
        "code": code,
    }
    trajectory_extra = trajectory.get("extra")
    diagnostic_extra = diagnostic.get("extra")
    trajectory_failure = (
        trajectory_extra.get("terminal_failure")
        if isinstance(trajectory_extra, dict)
        else None
    )
    diagnostic_failure = diagnostic.get("terminal_failure")
    binding_fields = {
        "trial_id": spec.get("trial_id"),
        "attempt_id": spec.get("attempt_id"),
        "run_spec_sha256": rust_run_spec_sha256(spec),
    }
    if (
        hashlib.sha256(trajectory_raw).hexdigest() != marker.get("trajectory_sha256")
        or hashlib.sha256(diagnostic_raw).hexdigest() != marker.get("diagnostic_sha256")
        or trajectory.get("schema_version") != "ATIF-v1.7"
        or trajectory.get("session_id") != spec.get("run_id")
        or not isinstance(trajectory_extra, dict)
        or any(
            trajectory_extra.get(field) != value
            for field, value in binding_fields.items()
        )
        or diagnostic.get("schema_version") != diagnostic_schema
        or diagnostic.get("session_id") != spec.get("run_id")
        or not isinstance(diagnostic_extra, dict)
        or any(
            diagnostic_extra.get(field) != value
            for field, value in binding_fields.items()
        )
        or not isinstance(trajectory_failure, dict)
        or not isinstance(diagnostic_failure, dict)
        or any(
            trajectory_failure.get(field) != value
            for field, value in failure_identity.items()
        )
        or any(
            diagnostic_failure.get(field) != value
            for field, value in failure_identity.items()
        )
        or (
            kind == "failure_atif"
            and (
                trajectory_extra.get("events_sha256") != marker.get("events_sha256")
                or diagnostic_extra.get("events_sha256") != marker.get("events_sha256")
            )
        )
        or (
            kind == "emergency_atif"
            and (
                not isinstance(trajectory_extra.get("event_prefix"), dict)
                or not isinstance(diagnostic.get("event_prefix"), dict)
                or trajectory_extra["event_prefix"].get("source_sha256")
                != marker.get("events_sha256")
                or diagnostic["event_prefix"].get("source_sha256")
                != marker.get("events_sha256")
            )
        )
        or any(
            (logs_dir / other).exists()
            for other in {"partial-trajectory.json", "emergency-prefix.json"}
            - {diagnostic_name}
        )
        or not _background_binding_valid(logs_dir=logs_dir, marker=marker, spec=spec)
    ):
        return base
    receipt_usage = _usage_from_receipt(
        logs_dir=logs_dir,
        marker=marker,
        spec=spec,
        record=record,
    )
    if receipt_usage is None:
        return base
    workspace = _WorkspaceEvidence()
    if "workspace_receipt_sha256" in marker:
        workspace = _workspace_receipt_evidence(
            logs_dir,
            marker["workspace_receipt_sha256"],
        )
        if not workspace.receipt_valid:
            return base
    return _ArtifactEvidence(
        artifacts_valid=False,
        success_valid=False,
        direct_atif_valid=False,
        diagnostic_valid=True,
        publication_valid=True,
        trajectory_valid=True,
        publication_kind=str(kind),
        workspace_receipt_valid=workspace.receipt_valid,
        workspace_snapshot_complete=workspace.snapshot_complete,
        workspace_status=workspace.status,
        workspace_failure_stage=workspace.failure_stage,
        workspace_failure_category=workspace.failure_category,
        workspace_failure_v3=workspace.failure_v3,
        usage_receipt_valid=True,
        terminal_status=str(status),
        terminal_phase=str(phase),
        terminal_code=str(code),
        run_record_read=_compact_run_record_read(read),
        usage_fallback=receipt_usage,
    )


def _artifact_evidence(
    trial_dir: Path,
    spec: Mapping[str, Any],
) -> _ArtifactEvidence:
    logs_dir = trial_dir / "agent"
    runtime_dir = logs_dir / "runtime"
    read = _read_run_record(runtime_dir, spec)
    parsed = read.parsed
    marker_document = _canonical_mapping(logs_dir / "agent-run.json")
    if marker_document is None:
        return _empty_artifact_evidence(run_record_read=read)
    marker, marker_raw = marker_document
    if marker.get("schema_version") == "nano-agent-run-v1":
        return _legacy_artifact_evidence(
            logs_dir=logs_dir,
            marker=marker,
            marker_raw=marker_raw,
            spec=spec,
            read=read,
        )
    if marker.get("schema_version") == "nano-agent-run-v4":
        return _terminal_atif_artifact_evidence(
            logs_dir=logs_dir,
            marker=marker,
            marker_raw=marker_raw,
            spec=spec,
            read=read,
        )
    kind = marker.get("publication_kind")
    kind_value = str(kind) if isinstance(kind, str) else None
    status = marker.get("terminal_status")
    phase = marker.get("terminal_phase")
    code = marker.get("terminal_code")
    base = _empty_artifact_evidence(
        publication_kind=kind_value,
        terminal_status=str(status) if isinstance(status, str) else None,
        terminal_phase=str(phase) if isinstance(phase, str) else None,
        terminal_code=str(code) if isinstance(code, str) else None,
        run_record_read=_compact_run_record_read(read),
    )
    marker_fields = set(marker)
    marker_schema = marker.get("schema_version")
    if marker_schema == "nano-agent-run-v2":
        required_fields = _V2_MARKER_REQUIRED_KEYS
    elif marker_schema == "nano-agent-run-v3":
        required_fields = _V3_MARKER_REQUIRED_KEYS
    else:
        return base
    optional_fields = marker_fields - required_fields
    expected_identity = (
        spec.get("run_id"),
        spec.get("trial_id"),
        spec.get("attempt_id"),
    )
    if (
        not required_fields.issubset(marker_fields)
        or not optional_fields.issubset(_V2_MARKER_OPTIONAL_KEYS)
        or (
            ("background_manifest_sha256" in marker)
            != ("background_task_count" in marker)
        )
        or kind not in {"success_atif", "failure_partial", "emergency_prefix"}
        or (kind == "emergency_prefix" and marker_schema != "nano-agent-run-v2")
        or (
            marker.get("run_id"),
            marker.get("trial_id"),
            marker.get("attempt_id"),
        )
        != expected_identity
        or marker.get("run_spec_sha256") != rust_run_spec_sha256(spec)
        or not all(
            _sha256_string(marker.get(field))
            for field in (
                "events_sha256",
                "trajectory_sha256",
                "usage_receipt_sha256",
            )
        )
        or (
            marker_schema == "nano-agent-run-v3"
            and not _sha256_string(marker.get("deadline_receipt_sha256"))
        )
        or (
            "background_manifest_sha256" in marker
            and not _sha256_string(marker["background_manifest_sha256"])
        )
        or (
            "workspace_receipt_sha256" in marker
            and not _sha256_string(marker["workspace_receipt_sha256"])
        )
        or not isinstance(status, str)
        or (phase is not None and not isinstance(phase, str))
        or not isinstance(code, str)
        or not code
    ):
        return base
    terminal_phases = {
        "success": {None},
        "provider_failure": {"provider"},
        "tool_failure": {"tool", "bridge"},
        "deadline_failure": {"deadline"},
        "cancelled": {"cancellation"},
        "runtime_failure": {"artifact", "runtime"},
    }
    expected_trajectory = {
        "success_atif": ("success", "trajectory.json"),
        "failure_partial": (
            "failure",
            "partial-trajectory.json",
        ),
        "emergency_prefix": ("failure", "emergency-prefix.json"),
    }[str(kind)]
    success_shape, trajectory_name = expected_trajectory
    if (
        marker.get("trajectory_path") != trajectory_name
        or status not in terminal_phases
        or phase not in terminal_phases[status]
        or (success_shape == "success") != (status == "success")
    ):
        return base
    trajectory_document = _canonical_mapping(logs_dir / trajectory_name)
    if kind == "emergency_prefix" and read.events_state == "absent":
        events = b""
    elif read.events_raw is not None:
        events = read.events_raw
    else:
        return base
    if hashlib.sha256(events).hexdigest() != marker[
        "events_sha256"
    ] or not _background_binding_valid(
        logs_dir=logs_dir,
        marker=marker,
        spec=spec,
    ):
        return base
    trajectory_valid = bool(
        trajectory_document is not None
        and hashlib.sha256(trajectory_document[1]).hexdigest()
        == marker["trajectory_sha256"]
        and not any(
            (logs_dir / other).exists()
            for other in {
                "trajectory.json",
                "partial-trajectory.json",
                "emergency-prefix.json",
            }
            - {trajectory_name}
        )
    )
    record: Mapping[str, Any] | None = None
    if kind != "emergency_prefix":
        if parsed is None or parsed.runtime is None or read.record is None:
            return base
        record = read.record
        runtime = parsed.runtime
        if (
            marker.get("run_record_schema") != parsed.schema_version
            or marker.get("events_sha256") != record.get("events_sha256")
            or marker.get("terminal_status") != runtime.terminal_status
            or marker.get("terminal_phase") != runtime.terminal_phase
            or marker.get("terminal_code") != runtime.terminal_code
            or (
                parsed.variant == "v3"
                and (
                    marker_schema != "nano-agent-run-v3"
                    or marker.get("deadline_receipt_sha256")
                    != parsed.deadline_receipt_sha256
                )
            )
            or (parsed.variant != "v3" and marker_schema != "nano-agent-run-v2")
        ):
            return base
    elif (
        parsed is not None
        or read.state != "absent"
        or marker.get("run_record_schema") is not None
    ):
        return base
    receipt_usage = _usage_from_receipt(
        logs_dir=logs_dir,
        marker=marker,
        spec=spec,
        record=record,
    )
    usage_valid = receipt_usage is not None
    workspace = _WorkspaceEvidence()
    if "workspace_receipt_sha256" in marker:
        workspace = _workspace_receipt_evidence(
            logs_dir,
            marker["workspace_receipt_sha256"],
        )
    workspace_binding_valid = (
        "workspace_receipt_sha256" not in marker or workspace.receipt_valid
    )
    diagnostic = bool(trajectory_valid and usage_valid and workspace_binding_valid)
    direct_atif_valid = bool(diagnostic and kind == "success_atif")
    # Preserve the v6 reusable-success meaning independently from direct ATIF.
    success_valid = bool(direct_atif_valid and workspace.snapshot_usable)
    return _ArtifactEvidence(
        artifacts_valid=success_valid,
        success_valid=success_valid,
        direct_atif_valid=direct_atif_valid,
        diagnostic_valid=diagnostic,
        publication_valid=True,
        trajectory_valid=trajectory_valid,
        publication_kind=kind_value,
        workspace_receipt_valid=workspace.receipt_valid,
        workspace_snapshot_complete=workspace.snapshot_complete,
        workspace_status=workspace.status,
        workspace_failure_stage=workspace.failure_stage,
        workspace_failure_category=workspace.failure_category,
        workspace_failure_v3=workspace.failure_v3,
        usage_receipt_valid=usage_valid,
        terminal_status=str(status),
        terminal_phase=str(phase) if phase is not None else None,
        terminal_code=str(code),
        run_record_read=_compact_run_record_read(read),
        usage_fallback=receipt_usage,
    )


def _rewarded_atif_eligible(
    trial_dir: Path,
    spec: Mapping[str, Any],
    artifacts: _ArtifactEvidence,
) -> bool:
    """Recompute the direct ATIF release gate from the immutable trajectory."""

    if not artifacts.direct_atif_valid:
        return False
    document = _canonical_mapping(trial_dir / "agent" / "trajectory.json")
    if document is None:
        return False
    trajectory, _raw = document
    extra = trajectory.get("extra")
    if (
        trajectory.get("schema_version") != "ATIF-v1.7"
        or trajectory.get("session_id") != spec.get("run_id")
        or not isinstance(extra, dict)
        or extra.get("trial_id") != spec.get("trial_id")
        or extra.get("attempt_id") != spec.get("attempt_id")
        or extra.get("run_spec_sha256") != rust_run_spec_sha256(spec)
    ):
        return False
    try:
        validate_minimal_trajectory(trajectory)
        validate_with_pinned_harbor(trajectory)
    except AtifError:
        return False
    return True


def _artifacts_valid(trial_dir: Path, spec: Mapping[str, Any]) -> bool:
    return _artifact_evidence(trial_dir, spec).success_valid


def _is_verifier_exception(value: Mapping[str, Any]) -> bool:
    exception = value.get("exception_info")
    if not isinstance(exception, dict):
        return False
    text = " ".join(
        field
        for field in (
            exception.get("exception_type"),
            exception.get("exception_message"),
            exception.get("exception_traceback"),
        )
        if isinstance(field, str)
    ).lower()
    if "verifier" in text:
        return True
    verifier = value.get("verifier")
    if value.get("verifier_result") is not None or not isinstance(verifier, dict):
        return False
    started = _timestamp(verifier.get("started_at"))
    occurred = _timestamp(exception.get("occurred_at"))
    return started is not None and occurred is not None and occurred >= started


def _verifier_output_bucket(trial_dir: Path) -> str | None:
    ctrf_available, ctrf_kind = _ctrf_result_kind(trial_dir)
    if ctrf_available and ctrf_kind == "assertion_failed":
        return "agent_semantic"
    try:
        text = _bounded_verifier_text(trial_dir)
    except TB21Error:
        return "verifier_runtime"
    if text is None:
        return None
    lowered = text.lower()
    if _strong_verifier_signal(text) == "assertion_failed":
        return "agent_semantic"
    if any(marker in lowered for marker in _VERIFIER_INFRA_MARKERS):
        return "verifier_setup_network"
    if any(
        marker in lowered
        for marker in (
            "sessionnotcreatedexception",
            "chrome instance exited",
            "chromedriver",
            "browser failed to start",
            "browser launch failure",
        )
    ):
        return "verifier_runtime"
    if "timeout" in lowered or "timed out" in lowered:
        return "verifier_timeout"
    if any(
        marker in lowered
        for marker in (
            "assertionerror",
            " failed ",
            "\nfailed ",
            "failures\n",
        )
    ):
        return "agent_semantic"
    if "traceback (most recent call last)" in lowered:
        return "uncertain"
    return None


def _contamination_audit(
    trial_dir: Path,
    *,
    rewarded: bool = False,
) -> dict[str, object]:
    """Compatibility entry point for the shared protected-target audit."""

    return protected_target.audit_trial(trial_dir, rewarded=rewarded)


def _bounded_verifier_text(trial_dir: Path) -> str | None:
    path = trial_dir / "verifier" / "test-stdout.txt"
    if not path.exists() and not path.is_symlink():
        return None
    return _read_regular(path, limit=16 * 1024 * 1024).decode("utf-8", errors="replace")


def _strong_verifier_signal(text: str) -> str | None:
    lowered = text.lower()
    if (
        "assertionerror" in lowered
        or "due to an assertion error" in lowered
        or "assertion failed" in lowered
    ):
        return "assertion_failed"
    if any(marker in lowered for marker in _VERIFIER_STRONG_SETUP_MARKERS):
        return "setup_failed"
    return None


def _ctrf_result_kind(trial_dir: Path) -> tuple[bool, str | None]:
    path = trial_dir / "verifier" / "ctrf.json"
    if not path.exists() and not path.is_symlink():
        return False, None
    try:
        value = json.loads(_read_regular(path, limit=16 * 1024 * 1024))
    except (TB21Error, UnicodeDecodeError, json.JSONDecodeError):
        return False, None
    results = value.get("results") if isinstance(value, dict) else None
    tests = results.get("tests") if isinstance(results, dict) else None
    if not isinstance(tests, list):
        return False, None
    failed: list[Mapping[str, Any]] = []
    for test in tests:
        if not isinstance(test, dict) or not isinstance(test.get("status"), str):
            return False, None
        if test["status"].lower() in {"failed", "error"}:
            failed.append(test)
    signals = [
        _strong_verifier_signal(
            " ".join(
                str(test.get(field, "")) for field in ("raw_status", "message", "trace")
            )
        )
        for test in failed
    ]
    if "assertion_failed" in signals:
        return True, "assertion_failed"
    if "setup_failed" in signals:
        return True, "setup_failed"
    return True, None


def _classify_verifier_result_kind(
    *,
    invalid: bool,
    reward: float | None,
    verifier_started: bool,
    typed_timeout: bool,
    ctrf_kind: str | None,
    stdout_kind: str | None,
) -> str:
    if invalid:
        return "invalid"
    if reward is not None and reward > 0:
        return "passed"
    if reward is not None:
        return ctrf_kind or stdout_kind or "completed_negative_unknown"
    if not verifier_started:
        return "not_run"
    if typed_timeout:
        return "timed_out"
    if stdout_kind == "setup_failed":
        return "setup_failed"
    return "runtime_failed"


def _verifier_result_kind(
    *,
    trial_dir: Path,
    value: Mapping[str, Any] | None,
    missing: bool,
    duplicate: bool,
    candidate_error: str | None,
    result_binding_valid: bool,
    reward: float | None,
) -> str:
    if (
        missing
        or duplicate
        or candidate_error is not None
        or value is None
        or not result_binding_valid
    ):
        return "invalid"
    completed = value.get("verifier_result") is not None
    exception_info = value.get("exception_info")
    verifier = value.get("verifier") if value is not None else None
    verifier_started = bool(
        isinstance(verifier, dict)
        and _timestamp(verifier.get("started_at")) is not None
    )
    invalid = bool(
        (completed and reward is None)
        or (exception_info is not None and not isinstance(exception_info, dict))
        or (
            reward is None
            and verifier is not None
            and (
                not isinstance(verifier, dict)
                or (verifier.get("started_at") is not None and not verifier_started)
            )
        )
    )
    exception_type = (
        exception_info.get("exception_type")
        if isinstance(exception_info, dict)
        else None
    )
    typed_timeout = exception_type == "VerifierTimeoutError"
    ctrf_available, ctrf_kind = _ctrf_result_kind(trial_dir)
    try:
        stdout = _bounded_verifier_text(trial_dir)
    except TB21Error:
        stdout = None
    stdout_kind = (
        None if completed and ctrf_available else _strong_verifier_signal(stdout or "")
    )
    if (
        _is_verifier_exception(value)
        and stdout_kind is None
        and isinstance(exception_info, dict)
    ):
        stdout_kind = _strong_verifier_signal(
            " ".join(
                str(exception_info.get(field, ""))
                for field in (
                    "exception_type",
                    "exception_message",
                    "exception_traceback",
                )
            )
        )
    return _classify_verifier_result_kind(
        invalid=invalid,
        reward=reward,
        verifier_started=verifier_started,
        typed_timeout=typed_timeout,
        ctrf_kind=ctrf_kind if completed else None,
        stdout_kind=stdout_kind,
    )


def _classify(
    *,
    missing: bool,
    duplicate: bool,
    candidate_error: str | None,
    exception: Mapping[str, str] | None,
    reward: float | None,
    artifacts_valid: bool,
    result_binding_valid: bool,
    runtime: _RuntimeEvidence | None,
    verifier_exception: bool,
    verifier_result_kind: str,
    verifier_output_bucket: str | None,
) -> str:
    if missing:
        return "missing"
    if duplicate:
        return "duplicate"
    if candidate_error is not None or not result_binding_valid:
        return "environment_infra"
    if runtime is not None:
        status = runtime.terminal_status
        code = runtime.terminal_code.lower()
        if status == "provider_failure":
            return "provider"
        if status in {"deadline_failure", "cancelled"}:
            return "action_deadline"
        if status == "tool_failure":
            if "background" in code:
                return "background_lifecycle"
            return "tool_transport"
        if status == "runtime_failure":
            return (
                "artifact"
                if runtime.terminal_phase == "artifact"
                else "environment_infra"
            )
    if verifier_result_kind == "assertion_failed":
        return "agent_semantic"
    if verifier_result_kind == "timed_out":
        return "verifier_timeout"
    if verifier_result_kind == "setup_failed":
        return verifier_output_bucket or "verifier_runtime"
    if exception is not None:
        text = (exception.get("type", "") + " " + exception.get("message", "")).lower()
        if verifier_exception:
            if "timeout" in text or "timed out" in text:
                return "verifier_timeout"
            if verifier_output_bucket is not None:
                return verifier_output_bucket
            return "verifier_runtime"
        if "timeout" in text or "timed out" in text:
            return "action_deadline"
        if "background" in text:
            return "background_lifecycle"
        if any(
            marker in text
            for marker in (
                "bridge",
                "external_runtime_nonzero",
                "terminal_actor",
                "transport",
                "exit status 135",
                "status 135",
            )
        ):
            return "tool_transport"
        if any(
            marker in text
            for marker in ("provider", "xai", "http", "sse", "api", "rate limit")
        ):
            return "provider"
        if any(
            marker in text
            for marker in (
                "docker",
                "environment",
                "compose",
                "image",
                "connection",
                "setup",
            )
        ):
            return "environment_infra"
        return "uncertain"
    if reward is None:
        return "verifier_runtime"
    if reward <= 0:
        return verifier_output_bucket or "agent_semantic"
    if not artifacts_valid:
        return "artifact"
    return "none"


def _failure_details(
    *,
    bucket: str,
    runtime: _RuntimeEvidence | None,
    exception: Mapping[str, str] | None,
) -> tuple[str | None, str | None, str | None]:
    if bucket == "none":
        return None, None, None
    phase_by_bucket = {
        "agent_semantic": "verifier",
        "provider": "provider",
        "action_deadline": "deadline",
        "tool_transport": "bridge",
        "background_lifecycle": "tool",
        "verifier_setup_network": "verifier",
        "verifier_runtime": "verifier",
        "verifier_timeout": "verifier",
        "environment_infra": "environment",
        "artifact": "artifact",
        "missing": "collection",
        "duplicate": "collection",
        "cancelled": "cancellation",
        "uncertain": "unknown",
    }
    recoverability_by_bucket = {
        "agent_semantic": "fatal",
        "provider": "recoverable",
        "action_deadline": "recoverable",
        "tool_transport": "recoverable",
        "background_lifecycle": "recoverable",
        "verifier_setup_network": "recoverable",
        "verifier_runtime": "recoverable",
        "verifier_timeout": "recoverable",
        "environment_infra": "recoverable",
        "artifact": "fatal",
        "missing": "unknown",
        "duplicate": "unknown",
        "cancelled": "recoverable",
        "uncertain": "unknown",
    }
    phase = (
        runtime.terminal_phase
        if runtime is not None and runtime.terminal_phase is not None
        else phase_by_bucket[bucket]
    )
    if runtime is not None:
        code = runtime.terminal_code
    elif exception is not None and exception.get("type"):
        code = exception["type"]
    else:
        code = bucket
    recoverability = (
        runtime.recoverability
        if runtime is not None and runtime.recoverability is not None
        else recoverability_by_bucket[bucket]
    )
    return phase, code, recoverability


def _cost(
    *,
    pricing: Pricing | None,
    model: str,
    usage: _UsageTotals,
) -> _CostResult:
    if not usage.provider_cost_ticks_valid:
        return _CostResult(None, "invalid_provider_ticks", False)
    if (
        usage.call_count > 0
        and usage.provider_cost_ticks_covered_calls == usage.call_count
    ):
        exact = Decimal(usage.provider_cost_ticks) / Decimal(USD_TICKS_PER_USD)
        return _CostResult(float(exact), "provider_ticks", True)
    if usage.provider_cost_ticks_covered_calls > 0:
        return _CostResult(None, "partial_provider_ticks", False)
    if (
        pricing is None
        or usage.call_count == 0
        or usage.input_tokens is None
        or usage.cache_tokens is None
        or usage.output_tokens is None
    ):
        return _CostResult(None, "unavailable", False)
    if pricing.model != model:
        raise TB21Error("pricing_model_mismatch")
    uncached = usage.input_tokens - usage.cache_tokens
    value = (
        Decimal(uncached) * pricing.input_per_million_usd
        + Decimal(usage.cache_tokens) * pricing.cached_input_per_million_usd
        + Decimal(usage.output_tokens) * pricing.output_per_million_usd
    ) / Decimal(1_000_000)
    return _CostResult(
        float(value),
        "dated_pricing_fallback",
        usage.state == "complete" and usage.usage_covered_calls == usage.call_count,
    )


def _cohort_manifest(job_dir: Path) -> Mapping[str, Any] | None:
    path = job_dir / "nano-tb21-cohort.json"
    if not path.exists():
        return None
    return _load_envelope(path, COHORT_SCHEMA)


def _capability_summary(
    job_dir: Path,
    cohort: Mapping[str, Any] | None,
) -> dict[str, object]:
    path = job_dir / "nano-capability-manifest.json"
    bound_sha256 = (
        cohort.get("capability_manifest_sha256") if isinstance(cohort, dict) else None
    )
    bound_state = (
        cohort.get("capability_capture_state") if isinstance(cohort, dict) else None
    )
    binding_present = bound_sha256 is not None and bound_state is not None
    binding_partial = (bound_sha256 is None) != (bound_state is None)
    if not path.exists() and not path.is_symlink():
        return {
            "capture_state": "unavailable",
            "evidence_state": (
                "invalid" if binding_present or binding_partial else "unavailable"
            ),
            "manifest_sha256": None,
        }
    try:
        raw = _read_regular(path, limit=CAPABILITY_PROBE_MAX_BYTES)
        value = json.loads(raw)
    except (
        TB21Error,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
    ):
        return {
            "capture_state": "invalid",
            "evidence_state": "invalid",
            "manifest_sha256": None,
        }
    digest = hashlib.sha256(raw).hexdigest()
    try:
        manifest_valid = bool(
            isinstance(value, dict)
            and raw == _canonical(value)
            and validate_capability_manifest(value)
        )
    except (TypeError, ValueError, RecursionError):
        manifest_valid = False
    binding_valid = bool(
        manifest_valid
        and binding_present
        and bound_sha256 == digest
        and bound_state == value.get("capture_state")
    )
    if binding_valid:
        evidence_state = "present"
    elif manifest_valid and not binding_present and not binding_partial:
        evidence_state = "unbound"
    else:
        evidence_state = "invalid"
    return {
        "capture_state": (
            value.get("capture_state")
            if manifest_valid and isinstance(value, dict)
            else "invalid"
        ),
        "evidence_state": evidence_state,
        "manifest_sha256": digest,
    }


def _result_binding_valid(
    value: Mapping[str, Any],
    spec: Mapping[str, Any],
) -> bool:
    task = spec["task"]
    return bool(
        value.get("trial_name") == spec["trial_id"]
        and value.get("task_name") == task["id"]
        and value.get("task_checksum") == task["digest"]
    )


def _row(
    *,
    job_dir: Path,
    spec: Mapping[str, Any],
    candidates: Sequence[_ResultCandidate],
    pricing: Pricing | None,
    source: Mapping[str, Any] | None,
    artifacts: _ArtifactEvidence | None = None,
    interruption_state: str | None = None,
    interruption_reason: str | None = None,
) -> dict[str, object]:
    task = spec["task"]
    provider = spec["provider"]
    missing = not candidates
    duplicate = len(candidates) > 1
    candidate = candidates[0] if candidates else None
    value = candidate.value if candidate is not None else None
    exception = _exception(value) if value is not None else None
    reward = _reward(value) if value is not None else None
    trial_dir = job_dir / str(spec["trial_id"])
    runtime_dir = trial_dir / "agent" / "runtime"
    if artifacts is None:
        artifacts = _artifact_evidence(trial_dir, spec)
    read = artifacts.run_record_read
    if read is None:
        read = _read_run_record(runtime_dir, spec)
    if spec.get("schema_version") == "nano-run-spec-alpha-2":
        try:
            runtime_entry = load_runtime_entry(
                trial_dir / "agent" / RUNTIME_ENTRY_NAME,
                spec,
            )
            runtime_entry_state = (
                runtime_entry.state if runtime_entry is not None else "invalid"
            )
        except RuntimeEntryError:
            runtime_entry_state = "invalid"
    else:
        runtime_entry_state = {
            "valid": "started",
            "invalid": "invalid",
            "absent": "not_observed",
        }[read.events_state]
    parsed = read.parsed
    runtime = parsed.runtime if parsed is not None else None
    if (
        runtime is None
        and artifacts.diagnostic_valid
        and artifacts.terminal_status is not None
        and artifacts.terminal_code is not None
    ):
        runtime = _RuntimeEvidence(
            terminal_status=artifacts.terminal_status,
            terminal_phase=artifacts.terminal_phase,
            terminal_code=artifacts.terminal_code,
            provider_failure_code=(
                artifacts.terminal_code
                if artifacts.terminal_status == "provider_failure"
                else None
            ),
            recoverability=None,
        )
    usage = (
        parsed.usage
        if parsed is not None
        else _usage_without_run_record(
            runtime_dir,
            spec,
            read=read,
            usage_fallback=artifacts.usage_fallback,
            receipt_checked=artifacts.run_record_read is not None,
        )
    )
    binding_valid = value is not None and _result_binding_valid(value, spec)
    result_classification, classified_reward = _official_result_classification(
        value,
        candidate_error=candidate.error if candidate is not None else None,
        identity_valid=bool(binding_valid and not missing and not duplicate),
    )
    reward = classified_reward
    runtime_result_contradiction = bool(
        runtime_entry_state == "not_started" and result_classification == "rewarded"
    )
    verifier_result_kind = _verifier_result_kind(
        trial_dir=trial_dir,
        value=value,
        missing=missing,
        duplicate=duplicate,
        candidate_error=candidate.error if candidate is not None else None,
        result_binding_valid=binding_valid,
        reward=reward,
    )
    verifier_output_bucket = _verifier_output_bucket(trial_dir)
    failure_bucket = _classify(
        missing=missing,
        duplicate=duplicate,
        candidate_error=candidate.error if candidate is not None else None,
        exception=exception,
        reward=reward,
        artifacts_valid=artifacts.success_valid,
        result_binding_valid=binding_valid,
        runtime=runtime,
        verifier_exception=(
            _is_verifier_exception(value) if value is not None else False
        ),
        verifier_result_kind=verifier_result_kind,
        verifier_output_bucket=verifier_output_bucket,
    )
    if runtime_result_contradiction:
        failure_bucket = "environment_infra"
    interrupted_before_terminal = interruption_state in {
        "not_started",
        "incomplete",
    }
    interruption_failure = (
        _INTERRUPTION_ROW_FAILURES.get(interruption_reason)
        if interruption_state is not None
        else None
    )
    if interruption_state is not None and interruption_failure is None:
        raise TB21Error("job_terminalization_invalid")
    if interrupted_before_terminal:
        failure_bucket = interruption_failure[0]
    reliable = bool(
        not interrupted_before_terminal
        and not missing
        and not duplicate
        and candidate is not None
        and candidate.error is None
        and exception is None
        and reward is not None
        and artifacts.success_valid
        and binding_valid
        and not runtime_result_contradiction
    )
    raw_score_valid = bool(
        not interrupted_before_terminal
        and not missing
        and not duplicate
        and candidate is not None
        and candidate.error is None
        and binding_valid
        and reward is not None
    )
    collector_pass = bool(raw_score_valid and reward is not None and reward > 0)
    rewarded_atif_valid = bool(
        collector_pass
        and not runtime_result_contradiction
        and _rewarded_atif_eligible(trial_dir, spec, artifacts)
    )
    strict_pass = rewarded_atif_valid
    measurement_complete = bool(
        not interrupted_before_terminal
        and not missing
        and not duplicate
        and candidate is not None
        and candidate.error is None
        and binding_valid
        and artifacts.diagnostic_valid
        and artifacts.workspace_snapshot_complete
        and artifacts.usage_receipt_valid
        and runtime is not None
    )
    failure_phase, failure_code, failure_recoverability = _failure_details(
        bucket=failure_bucket,
        runtime=runtime,
        exception=exception,
    )
    if interrupted_before_terminal:
        failure_phase = interruption_failure[1]
        failure_code = f"{interruption_failure[2]}_{interruption_state}"
        failure_recoverability = interruption_failure[3]
    elif runtime_result_contradiction:
        failure_phase = "runtime"
        failure_code = "runtime_result_contradiction"
        failure_recoverability = "fatal"
    duration = _duration_ms(value) if value is not None else None
    cost = _cost(
        pricing=pricing,
        model=str(provider["model"]),
        usage=usage,
    )
    provider_cost_usd_observed = float(
        Decimal(usage.provider_cost_ticks if usage.provider_cost_ticks_valid else 0)
        / Decimal(USD_TICKS_PER_USD)
    )
    resource = source.get("resources") if isinstance(source, dict) else None
    contamination = _contamination_audit(trial_dir, rewarded=collector_pass)
    git_history = git_history_audit.audit_trial(
        trial_dir,
        instruction=task.get("instruction"),
        capability=task.get("git_history_capability"),
        trusted_manifest_sha256=task.get("digest"),
        run_spec_sha256=rust_run_spec_sha256(spec),
    )
    audit_not_applicable = bool(
        result_classification == "errored"
        and runtime_entry_state == "not_started"
        and contamination.get("state") in {"available", "unavailable"}
        and git_history.get("state") in {"available", "unavailable"}
        and (
            git_history.get("evidence_complete") is True
            if git_history.get("state") == "available"
            else git_history.get("evidence_complete") is False
        )
    )
    if audit_not_applicable:
        contamination = {
            "schema_version": protected_target.AUDIT_SCHEMA,
            "policy_schema_version": protected_target.POLICY_SCHEMA,
            "policy_sha256": protected_target.POLICY_SHA256,
            "state": "not_applicable",
            "signals": [],
            "counts": {
                "findings": 0,
                "strong": 0,
                "attempted": 0,
                "access_blocked": 0,
                "dispatched": 0,
                "bytes_returned": 0,
                "causal_benefit": 0,
            },
            "findings": [],
        }
        git_history = {
            "schema_version": git_history_audit.AUDIT_SCHEMA,
            "finding_schema_version": git_history_audit.FINDING_SCHEMA,
            "state": "not_applicable",
            "history_required": git_history.get("history_required"),
            "evidence_complete": False,
            "findings": [],
            "counts": {
                "findings": 0,
                "attempted": 0,
                "dispatched": 0,
                "bytes_returned": 0,
                "causal_reuse": 0,
                "warnings": 0,
                "blocking": 0,
            },
            "submission_blocking": False,
        }
    protected_findings = contamination["findings"]
    assert isinstance(protected_findings, list)
    submission_blocking_count = sum(
        protected_target.submission_blocking_finding(finding)
        for finding in protected_findings
    )
    submission_warning_count = len(protected_findings) - submission_blocking_count
    submission_integrity_blocking = bool(
        contamination["state"] not in {"available", "not_applicable"}
        or submission_blocking_count
        or runtime_result_contradiction
    )
    workspace_failure_v3 = artifacts.workspace_failure_v3
    row: dict[str, object] = {
        "schema_version": ROW_SCHEMA,
        "pins": {
            "contract_id": spec["contract"]["id"],
            "contract_set_sha256": spec["contract"]["contract_set_sha256"],
            "profile_id": spec["contract"]["profile_id"],
            "provider": provider["kind"],
            "model": provider["model"],
            "max_provider_turns": provider["max_turns"],
            "active_tools": list(ACTIVE_TOOLS),
        },
        "cohort": "tb21-k1-full-eight",
        "task": task["id"],
        "digest": task["digest"],
        "task_digest": task["digest"],
        "source_digest": source.get("source_sha256")
        if isinstance(source, dict)
        else None,
        "trial": spec["trial_id"],
        "reward": reward,
        "raw_score_valid": raw_score_valid,
        "pass": strict_pass,
        "collector_pass": collector_pass,
        "strict_pass": strict_pass,
        "contamination_audit_state": contamination["state"],
        "contamination_signals": contamination["signals"],
        "contamination_signal": bool(contamination["findings"]),
        "protected_target_audit_schema": contamination["schema_version"],
        "protected_target_policy_schema": contamination["policy_schema_version"],
        "protected_target_policy_sha256": contamination["policy_sha256"],
        "protected_target_counts": contamination["counts"],
        "protected_target_findings": protected_findings,
        "submission_integrity_blocking": submission_integrity_blocking,
        "submission_integrity_blocking_count": submission_blocking_count,
        "submission_integrity_warning_count": submission_warning_count,
        "git_history_audit_schema": git_history["schema_version"],
        "git_history_finding_schema": git_history["finding_schema_version"],
        "git_history_audit_state": git_history["state"],
        "git_history_required": git_history["history_required"],
        "git_history_evidence_complete": git_history["evidence_complete"],
        "git_history_findings": git_history["findings"],
        "git_history_counts": git_history["counts"],
        "git_history_submission_blocking": git_history["submission_blocking"],
        "reliable": reliable,
        "artifacts_valid": artifacts.artifacts_valid,
        "success_artifact_valid": artifacts.success_valid,
        "direct_atif_valid": artifacts.direct_atif_valid,
        "rewarded_atif_valid": rewarded_atif_valid,
        "diagnostic_package_valid": artifacts.diagnostic_valid,
        "publication_kind": artifacts.publication_kind,
        "workspace_receipt_valid": artifacts.workspace_receipt_valid,
        "workspace_snapshot_complete": artifacts.workspace_snapshot_complete,
        "workspace_status": artifacts.workspace_status,
        "workspace_failure_stage": artifacts.workspace_failure_stage,
        "workspace_failure_category": artifacts.workspace_failure_category,
        "workspace_failure_subtype": (
            workspace_failure_v3[0] if workspace_failure_v3 else None
        ),
        "workspace_failure_timeout_origin": (
            workspace_failure_v3[1] if workspace_failure_v3 else None
        ),
        "workspace_failure_stage_validated": (
            workspace_failure_v3[2] if workspace_failure_v3 else None
        ),
        "workspace_failure_termination_verified": (
            workspace_failure_v3[3] if workspace_failure_v3 else None
        ),
        "workspace_failure_cleanup_verified": (
            workspace_failure_v3[4] if workspace_failure_v3 else None
        ),
        "workspace_failure_zero_census_verified": (
            workspace_failure_v3[5] if workspace_failure_v3 else None
        ),
        "workspace_failure_execution_binding_verified": (
            workspace_failure_v3[6] if workspace_failure_v3 else None
        ),
        "usage_receipt_valid": artifacts.usage_receipt_valid,
        "measurement_complete": measurement_complete,
        "result_binding_valid": binding_valid,
        "terminal_record_valid": runtime is not None,
        "exception": exception,
        "verifier_result_kind": verifier_result_kind,
        "failure_bucket": failure_bucket,
        "failure_phase": failure_phase,
        "failure_code": failure_code,
        "failure_recoverability": failure_recoverability,
        "runtime_terminal_status": (
            runtime.terminal_status if runtime is not None else None
        ),
        "runtime_terminal_phase": (
            runtime.terminal_phase if runtime is not None else None
        ),
        "runtime_terminal_code": runtime.terminal_code if runtime is not None else None,
        "runtime_provider_failure_code": (
            runtime.provider_failure_code if runtime is not None else None
        ),
        "runtime_entry_state": runtime_entry_state,
        "duration_ms": duration,
        "input_tokens": usage.input_tokens,
        "cache_tokens": usage.cache_tokens,
        "output_tokens": usage.output_tokens,
        "token_coverage": usage.input_tokens is not None,
        "usage_state": usage.state,
        "usage_source": usage.source,
        "usage_record_valid": usage.record_valid,
        "usage_call_count": usage.call_count,
        "provider_calls_requested": usage.requested_count,
        "provider_calls_completed": usage.completed_count,
        "provider_calls_failed": usage.failed_count,
        "provider_calls_in_flight": usage.in_flight_count,
        "provider_calls_usage_present": usage.usage_present_count,
        "provider_calls_usage_absent": usage.usage_absent_count,
        "provider_calls_usage_covered": usage.usage_covered_calls,
        "provider_cost_ticks": usage.provider_cost_ticks,
        "provider_cost_ticks_covered_calls": (usage.provider_cost_ticks_covered_calls),
        "provider_cost_ticks_coverage": (
            f"{usage.provider_cost_ticks_covered_calls}/{usage.call_count}"
        ),
        "provider_cost_usd_observed": provider_cost_usd_observed,
        "cost_source": cost.source,
        "cost_usd": cost.value_usd,
        "cost_coverage": cost.covered,
        "retry": 0,
        "resources": resource,
    }
    if read.tool_receipt_signal:
        row["tool_receipt_telemetry"] = {
            "coverage": read.tool_receipt_coverage,
            "sample_count": len(read.tool_receipt_samples),
            "omitted_samples": read.tool_receipt_omitted_samples,
            "samples": [dict(sample) for sample in read.tool_receipt_samples],
        }
    if interruption_state is not None:
        row["interruption_state"] = interruption_state
        row["interruption_reason"] = interruption_reason
    return row


def _percentile(values: Sequence[int], fraction: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(math.ceil(fraction * len(ordered)) - 1, 0)
    return ordered[rank]


def _job_retries(job_dir: Path) -> int:
    path = job_dir / "result.json"
    if not path.exists():
        return 0
    try:
        value = _load_json(path)
    except TB21Error:
        return 0
    stats = value.get("stats") if isinstance(value, dict) else None
    retries = stats.get("n_retries") if isinstance(stats, dict) else 0
    return retries if isinstance(retries, int) and not isinstance(retries, bool) else 0


def _job_wall_duration_ms(job_dir: Path) -> int | None:
    path = job_dir / "result.json"
    if not path.exists():
        return None
    try:
        value = _load_json(path)
    except TB21Error:
        return None
    return _duration_ms(value) if isinstance(value, dict) else None


def _terminalization_value(
    job_dir: Path,
    specs: Sequence[Mapping[str, Any]],
    *,
    finished_at: str,
) -> dict[str, object]:
    job_raw = _read_regular(job_dir / "result.json")
    try:
        job = json.loads(job_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TB21Error("job_not_terminal") from error
    stats = job.get("stats") if isinstance(job, dict) else None
    total = len(specs)
    if (
        not isinstance(job, dict)
        or job.get("finished_at") is not None
        or job.get("n_total_trials") != total
        or not isinstance(stats, dict)
        or stats.get("n_completed_trials") != total
        or stats.get("n_running_trials") != 0
        or stats.get("n_pending_trials") != 0
        or stats.get("n_retries") != 0
    ):
        raise TB21Error("job_not_terminal")
    cancelled = _nonnegative_integer(stats.get("n_cancelled_trials"))
    errored = _nonnegative_integer(stats.get("n_errored_trials"))
    if cancelled is None or errored is None:
        raise TB21Error("job_not_terminal")
    expected = {str(spec["trial_id"]): spec for spec in specs}
    candidates = _scan_results(job_dir)
    if len(candidates) != total or {row.trial_name for row in candidates} != set(
        expected
    ):
        raise TB21Error("job_not_terminal")
    trials: list[dict[str, object]] = []
    for candidate in sorted(candidates, key=lambda row: row.trial_name):
        spec = expected[candidate.trial_name]
        task = spec.get("task")
        value = candidate.value
        if (
            candidate.error is not None
            or not isinstance(task, Mapping)
            or not isinstance(value, Mapping)
            or value.get("trial_name") != candidate.trial_name
            or value.get("task_name") != task.get("id")
            or value.get("task_checksum") != task.get("digest")
            or _timestamp(value.get("started_at")) is None
            or _timestamp(value.get("finished_at")) is None
            or _duration_ms(value) is None
        ):
            raise TB21Error("job_not_terminal")
        trials.append(
            {
                "trial_id": candidate.trial_name,
                "task_id": task["id"],
                "task_digest": task["digest"],
                "result_sha256": hashlib.sha256(
                    _read_regular(candidate.path)
                ).hexdigest(),
                "finished_at": value["finished_at"],
            }
        )
    cohort_path = job_dir / "nano-tb21-cohort.json"
    cohort_sha256 = (
        hashlib.sha256(_read_regular(cohort_path)).hexdigest()
        if cohort_path.exists() or cohort_path.is_symlink()
        else None
    )
    return {
        "schema_version": TERMINALIZATION_SCHEMA,
        "status": "aborted",
        "reason": "operator_interrupted",
        "finished_at": finished_at,
        "job_result_sha256": hashlib.sha256(job_raw).hexdigest(),
        "dispatch_sha256": hashlib.sha256(
            _read_regular(job_dir / "nano-dispatch.json")
        ).hexdigest(),
        "cohort_sha256": cohort_sha256,
        "n_total_trials": total,
        "n_completed_trials": total,
        "n_cancelled_trials": cancelled,
        "n_errored_trials": errored,
        "n_retries": 0,
        "trials": trials,
    }


def _interruption_evidence_manifest(
    trial_dir: Path,
) -> tuple[str, int, int, str]:
    rows: list[dict[str, object]] = []
    byte_count = 0
    invalid = False
    for relative in _INTERRUPTION_EVIDENCE_PATHS:
        path = trial_dir / relative
        if not path.exists() and not path.is_symlink():
            continue
        try:
            raw = _read_regular(path, limit=128 * 1024 * 1024)
        except TB21Error:
            invalid = True
            rows.append(
                {
                    "path": relative,
                    "byte_length": None,
                    "sha256": None,
                }
            )
            continue
        byte_count += len(raw)
        rows.append(
            {
                "path": relative,
                "byte_length": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    return (
        hashlib.sha256(_canonical(rows)).hexdigest(),
        len(rows),
        byte_count,
        "invalid" if invalid else "complete",
    )


def _interruption_trial_value(
    job_dir: Path,
    spec: Mapping[str, Any],
    *,
    pricing: Pricing | None,
) -> dict[str, object]:
    trial_id = str(spec["trial_id"])
    task = spec["task"]
    provider = spec["provider"]
    trial_dir = job_dir / trial_id
    result_path = trial_dir / "result.json"
    candidate = (
        _candidate(result_path)
        if result_path.exists() or result_path.is_symlink()
        else None
    )
    value = candidate.value if candidate is not None else None
    result_sha256: str | None = None
    if candidate is not None:
        try:
            result_sha256 = hashlib.sha256(_read_regular(result_path)).hexdigest()
        except TB21Error:
            pass
    started_at = (
        value.get("started_at")
        if isinstance(value, Mapping)
        and _timestamp(value.get("started_at")) is not None
        else None
    )
    finished_at = (
        value.get("finished_at")
        if isinstance(value, Mapping)
        and _timestamp(value.get("finished_at")) is not None
        else None
    )
    result_terminal = bool(
        candidate is not None
        and candidate.error is None
        and isinstance(value, Mapping)
        and _result_binding_valid(value, spec)
        and started_at is not None
        and finished_at is not None
        and _duration_ms(value) is not None
    )
    artifacts = _artifact_evidence(trial_dir, spec)
    read = artifacts.run_record_read
    if read is None:
        read = _read_run_record(trial_dir / "agent" / "runtime", spec)
    parsed = read.parsed
    usage = (
        parsed.usage
        if parsed is not None
        else _usage_without_run_record(
            trial_dir / "agent" / "runtime",
            spec,
            read=read,
            usage_fallback=artifacts.usage_fallback,
            receipt_checked=artifacts.run_record_read is not None,
        )
    )
    (
        evidence_manifest_sha256,
        evidence_file_count,
        evidence_byte_count,
        evidence_manifest_state,
    ) = _interruption_evidence_manifest(trial_dir)
    started = bool(
        result_terminal
        or started_at is not None
        or read.events_state != "absent"
        or evidence_file_count > 0
    )
    state = (
        "terminal" if result_terminal else "incomplete" if started else "not_started"
    )
    matching_pricing = (
        pricing
        if pricing is not None and pricing.model == provider.get("model")
        else None
    )
    cost = _cost(
        pricing=matching_pricing,
        model=str(provider["model"]),
        usage=usage,
    )
    provider_lower_bound = (
        Decimal(usage.provider_cost_ticks) / Decimal(USD_TICKS_PER_USD)
        if usage.provider_cost_ticks_valid
        else Decimal(0)
    )
    fallback_lower_bound = (
        Decimal(str(cost.value_usd))
        if cost.source == "dated_pricing_fallback" and cost.value_usd is not None
        else Decimal(0)
    )
    observed_cost_lower_bound = float(provider_lower_bound + fallback_lower_bound)
    trajectory_paths = (
        trial_dir / "agent" / "trajectory.json",
        trial_dir / "agent" / "partial-trajectory.json",
        trial_dir / "agent" / "emergency-prefix.json",
    )
    trajectory_state = (
        "complete"
        if artifacts.trajectory_valid
        else (
            "invalid"
            if any(path.exists() or path.is_symlink() for path in trajectory_paths)
            else "unavailable"
        )
    )
    workspace_path = trial_dir / "agent" / "workspace-receipt.json"
    workspace_state = (
        "complete"
        if artifacts.workspace_snapshot_complete
        else (
            "failed"
            if artifacts.workspace_receipt_valid
            and artifacts.workspace_status == "failed"
            else (
                "invalid"
                if workspace_path.exists() or workspace_path.is_symlink()
                else "unavailable"
            )
        )
    )
    return {
        "trial_id": trial_id,
        "task_id": task["id"],
        "task_digest": task["digest"],
        "state": state,
        "result_sha256": result_sha256,
        "started_at": started_at,
        "finished_at": finished_at,
        "runtime_entry_state": {
            "valid": "started",
            "invalid": "invalid",
            "absent": "not_observed",
        }[read.events_state],
        "usage_state": usage.state,
        "tokens_observed": {
            "input": usage.input_tokens,
            "cache": usage.cache_tokens,
            "output": usage.output_tokens,
        },
        "trajectory_state": trajectory_state,
        "workspace_snapshot_state": workspace_state,
        "cost_usd_observed_lower_bound": observed_cost_lower_bound,
        "cost_covered": cost.covered,
        "evidence_manifest_sha256": evidence_manifest_sha256,
        "evidence_file_count": evidence_file_count,
        "evidence_byte_count": evidence_byte_count,
        "evidence_manifest_state": evidence_manifest_state,
    }


def _interruption_value(
    job_dir: Path,
    specs: Sequence[Mapping[str, Any]],
    *,
    finished_at: str,
    reason: str,
    pricing: Pricing | None,
) -> dict[str, object]:
    if reason not in {
        "operator_interrupted",
        "runner_exception",
    }:
        raise TB21Error("job_not_terminal")
    if _timestamp(finished_at) is None:
        raise TB21Error("job_not_terminal")
    job_raw = _read_regular(job_dir / "result.json")
    try:
        job = json.loads(job_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TB21Error("job_not_terminal") from error
    stats = job.get("stats") if isinstance(job, dict) else None
    total = len(specs)
    stat_fields = (
        "n_completed_trials",
        "n_errored_trials",
        "n_running_trials",
        "n_pending_trials",
        "n_cancelled_trials",
        "n_retries",
    )
    parsed_stats = (
        {field: _nonnegative_integer(stats.get(field)) for field in stat_fields}
        if isinstance(stats, dict)
        else {}
    )
    if (
        not isinstance(job, dict)
        or job.get("finished_at") is not None
        or job.get("n_total_trials") != total
        or not isinstance(stats, dict)
        or any(parsed_stats.get(field) is None for field in stat_fields)
        or parsed_stats["n_retries"] != 0
        or (
            int(parsed_stats["n_completed_trials"])
            + int(parsed_stats["n_running_trials"])
            + int(parsed_stats["n_pending_trials"])
            != total
        )
        or int(parsed_stats["n_errored_trials"])
        > int(parsed_stats["n_completed_trials"])
        or int(parsed_stats["n_cancelled_trials"])
        > int(parsed_stats["n_completed_trials"])
    ):
        raise TB21Error("job_not_terminal")
    trials = [
        _interruption_trial_value(job_dir, spec, pricing=pricing)
        for spec in sorted(specs, key=lambda row: str(row["trial_id"]))
    ]
    state_counts = Counter(str(trial["state"]) for trial in trials)
    started_count = state_counts["terminal"] + state_counts["incomplete"]
    usage_states = Counter(str(trial["usage_state"]) for trial in trials)
    trajectory_states = Counter(str(trial["trajectory_state"]) for trial in trials)
    workspace_states = Counter(
        str(trial["workspace_snapshot_state"]) for trial in trials
    )
    cost_covered = sum(bool(trial["cost_covered"]) for trial in trials)
    token_covered = sum(
        isinstance(trial["tokens_observed"], dict)
        and trial["tokens_observed"].get("input") is not None
        for trial in trials
    )
    observed_tokens = {
        key: sum(
            int(trial["tokens_observed"][key])
            for trial in trials
            if isinstance(trial["tokens_observed"], dict)
            and trial["tokens_observed"].get(key) is not None
        )
        for key in ("input", "cache", "output")
    }
    cohort_path = job_dir / "nano-tb21-cohort.json"
    cohort_sha256 = (
        hashlib.sha256(_read_regular(cohort_path)).hexdigest()
        if cohort_path.exists() or cohort_path.is_symlink()
        else None
    )
    return {
        "schema_version": INTERRUPTION_TERMINALIZATION_SCHEMA,
        "status": "interrupted",
        "reason": reason,
        "finished_at": finished_at,
        "job_result_sha256": hashlib.sha256(job_raw).hexdigest(),
        "dispatch_sha256": hashlib.sha256(
            _read_regular(job_dir / "nano-dispatch.json")
        ).hexdigest(),
        "cohort_sha256": cohort_sha256,
        "pricing_sha256": pricing.source_sha256 if pricing is not None else None,
        "census": {
            "n_total_trials": total,
            "n_started_trials": started_count,
            "n_terminal_trials": state_counts["terminal"],
            "n_not_started_trials": state_counts["not_started"],
            "n_incomplete_trials": state_counts["incomplete"],
            "n_pending_trials": int(parsed_stats["n_pending_trials"]),
            "n_cancelled_trials": int(parsed_stats["n_cancelled_trials"]),
            "n_errored_trials": int(parsed_stats["n_errored_trials"]),
            "n_retries": 0,
        },
        "evidence": {
            "usage_state_counts": {
                state: usage_states.get(state, 0)
                for state in ("complete", "partial", "unavailable", "invalid")
            },
            "usage_task_coverage": f"{token_covered}/{total}",
            "tokens_observed_lower_bound": observed_tokens,
            "trajectory_state_counts": {
                state: trajectory_states.get(state, 0)
                for state in ("complete", "unavailable", "invalid")
            },
            "trajectory_coverage": (f"{trajectory_states['complete']}/{started_count}"),
            "workspace_snapshot_state_counts": {
                state: workspace_states.get(state, 0)
                for state in ("complete", "failed", "unavailable", "invalid")
            },
            "workspace_snapshot_coverage": (
                f"{workspace_states['complete']}/{started_count}"
            ),
            "cost_usd_observed_lower_bound": float(
                sum(
                    Decimal(str(trial["cost_usd_observed_lower_bound"]))
                    for trial in trials
                )
            ),
            "cost_task_coverage": f"{cost_covered}/{total}",
        },
        "trials": trials,
    }


def _validate_terminalization(
    job_dir: Path,
    specs: Sequence[Mapping[str, Any]],
    *,
    pricing: Pricing | None = None,
) -> Mapping[str, Any]:
    try:
        receipt = _load_json(job_dir / "nano-terminalization.json")
        if (
            not isinstance(receipt, dict)
            or _timestamp(receipt.get("finished_at")) is None
        ):
            raise TB21Error("job_terminalization_invalid")
        if receipt.get("schema_version") == TERMINALIZATION_SCHEMA:
            expected = _terminalization_value(
                job_dir,
                specs,
                finished_at=str(receipt["finished_at"]),
            )
        elif receipt.get("schema_version") == INTERRUPTION_TERMINALIZATION_SCHEMA:
            expected = _interruption_value(
                job_dir,
                specs,
                finished_at=str(receipt["finished_at"]),
                reason=str(receipt.get("reason")),
                pricing=pricing,
            )
        else:
            raise TB21Error("job_terminalization_invalid")
    except TB21Error as error:
        raise TB21Error("job_terminalization_invalid") from error
    if receipt != expected:
        raise TB21Error("job_terminalization_invalid")
    return receipt


def _terminalize_interruption(
    job_dir: Path,
    specs: Sequence[Mapping[str, Any]],
    error: BaseException,
    *,
    pricing: Pricing | None = None,
) -> bool:
    if isinstance(error, asyncio.CancelledError | KeyboardInterrupt):
        reason = "operator_interrupted"
    elif isinstance(error, Exception):
        reason = "runner_exception"
    else:
        raise TB21Error("job_not_terminal")
    persisted = _load_dispatch(job_dir)
    if {str(row["trial_id"]): row for row in persisted} != {
        str(row["trial_id"]): row for row in specs
    }:
        raise TB21Error("job_not_terminal")
    path = job_dir / "nano-terminalization.json"
    if path.exists() or path.is_symlink():
        _validate_terminalization(job_dir, persisted, pricing=pricing)
        return False
    finished_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    value = _interruption_value(
        job_dir,
        persisted,
        finished_at=finished_at,
        reason=reason,
        pricing=pricing,
    )
    _atomic_write(path, _canonical(value))
    return True


def _terminalize_drained_interruption(
    job_dir: Path,
    specs: Sequence[Mapping[str, Any]],
    error: BaseException,
) -> bool:
    return _terminalize_interruption(job_dir, specs, error)


def _require_job_terminal(
    job_dir: Path,
    specs: Sequence[Mapping[str, Any]],
    *,
    pricing: Pricing | None = None,
) -> Mapping[str, Any] | None:
    try:
        value = _load_json(job_dir / "result.json")
    except TB21Error as error:
        raise TB21Error("job_not_terminal") from error
    receipt = job_dir / "nano-terminalization.json"
    if isinstance(value, dict) and _timestamp(value.get("finished_at")) is not None:
        if receipt.exists() or receipt.is_symlink():
            raise TB21Error("job_terminalization_invalid")
        return None
    if receipt.exists() or receipt.is_symlink():
        return _validate_terminalization(job_dir, specs, pricing=pricing)
    raise TB21Error("job_not_terminal")


def _summary_pins(
    specs: Sequence[Mapping[str, Any]],
    cohort: Mapping[str, Any] | None,
) -> dict[str, object]:
    first = specs[0]
    contract = first["contract"]
    provider = first["provider"]
    runtime = cohort.get("runtime") if isinstance(cohort, dict) else None
    pins: dict[str, object] = {
        "dataset": cohort.get("dataset") if cohort else None,
        "dataset_ref": cohort.get("dataset_ref") if cohort else None,
        "source_commit": cohort.get("source_commit") if cohort else None,
        "harbor_commit": cohort.get("harbor_commit") if cohort else HARBOR_COMMIT,
        "runtime_git_head": runtime.get("git_head")
        if isinstance(runtime, dict)
        else None,
        "runtime_source_sha256": runtime.get("source_sha256")
        if isinstance(runtime, dict)
        else None,
        "runtime_binary_sha256": runtime.get("binary_sha256")
        if isinstance(runtime, dict)
        else None,
        "contract_id": contract["id"],
        "contract_set_sha256": contract["contract_set_sha256"],
        "profile_id": contract["profile_id"],
        "provider": provider["kind"],
        "model": provider["model"],
        "max_provider_turns": provider["max_turns"],
        "active_tools": list(ACTIVE_TOOLS),
    }
    if isinstance(runtime, dict):
        for legacy_key in ("approved_contract", "approved_r2_prospective"):
            if legacy_key in runtime:
                pins[legacy_key] = runtime[legacy_key]
    return pins


def collect_job(
    job_dir: Path,
    *,
    pricing: Pricing | None = None,
) -> dict[str, object]:
    """Recompute stable rows and summary from one immutable Harbor job directory."""

    job_dir = job_dir.resolve()
    if job_dir.is_symlink() or not job_dir.is_dir():
        raise TB21Error("job_directory_invalid")
    specs = _load_dispatch(job_dir)
    terminalization = _require_job_terminal(job_dir, specs, pricing=pricing)
    interrupted = bool(
        terminalization is not None
        and terminalization.get("schema_version") == INTERRUPTION_TERMINALIZATION_SCHEMA
    )
    interruption_by_trial = (
        {
            str(trial["trial_id"]): str(trial["state"])
            for trial in terminalization["trials"]
            if isinstance(trial, dict)
        }
        if interrupted and terminalization is not None
        else {}
    )
    interruption_reason = (
        str(terminalization["reason"])
        if interrupted and terminalization is not None
        else None
    )
    cohort = _cohort_manifest(job_dir)
    source_by_task: dict[str, Mapping[str, Any]] = {}
    if cohort is not None:
        tasks = cohort.get("tasks")
        if (
            cohort.get("dataset") != TB21_DATASET
            or cohort.get("dataset_ref") != TB21_DATASET_REF
            or cohort.get("source_commit") != TB21_SOURCE_COMMIT
            or cohort.get("harbor_commit") != HARBOR_COMMIT
            or cohort.get("n_attempts") != 1
            or cohort.get("retry_max") != 0
            or cohort.get("active_tools") != list(ACTIVE_TOOLS)
            or not isinstance(tasks, list)
        ):
            raise TB21Error("cohort_invalid")
        for task in tasks:
            if not isinstance(task, dict) or not isinstance(task.get("task_id"), str):
                raise TB21Error("cohort_invalid")
            if task["task_id"] in source_by_task:
                raise TB21Error("cohort_invalid")
            source_by_task[task["task_id"]] = task
        expected_by_task = {
            str(spec["task"]["id"]): spec["task"]["digest"] for spec in specs
        }
        if set(source_by_task) != set(expected_by_task) or any(
            source_by_task[task_id].get("task_digest") != digest
            for task_id, digest in expected_by_task.items()
        ):
            raise TB21Error("cohort_invalid")
    candidates = _scan_results(job_dir)
    expected_trials = {str(spec["trial_id"]) for spec in specs}
    by_trial: dict[str, list[_ResultCandidate]] = {}
    unexpected: list[str] = []
    for candidate in candidates:
        if candidate.trial_name not in expected_trials:
            unexpected.append(candidate.trial_name)
            continue
        by_trial.setdefault(candidate.trial_name, []).append(candidate)
    official_results: dict[str, tuple[str, float | None]] = {}
    for spec in specs:
        trial_id = str(spec["trial_id"])
        matches = by_trial.get(trial_id, [])
        candidate = matches[0] if len(matches) == 1 else None
        value = candidate.value if candidate is not None else None
        identity_valid = bool(
            value is not None
            and _result_binding_valid(value, spec)
            and _duration_ms(value) is not None
        )
        official_results[trial_id] = _official_result_classification(
            value,
            candidate_error=(
                candidate.error if candidate is not None else "result_inventory_invalid"
            ),
            identity_valid=identity_valid,
        )
    artifact_rows = [
        _artifact_evidence(job_dir / str(spec["trial_id"]), spec) for spec in specs
    ]
    rows = [
        _row(
            job_dir=job_dir,
            spec=spec,
            candidates=tuple(
                sorted(
                    by_trial.get(str(spec["trial_id"]), []),
                    key=lambda candidate: str(candidate.path),
                )
            ),
            pricing=pricing,
            source=source_by_task.get(str(spec["task"]["id"])),
            artifacts=artifacts,
            interruption_state=interruption_by_trial.get(str(spec["trial_id"])),
            interruption_reason=interruption_reason,
        )
        for spec, artifacts in zip(specs, artifact_rows, strict=True)
    ]
    missing_tasks = [
        str(row["task"]) for row in rows if row["failure_bucket"] == "missing"
    ]
    duplicate_trials = [
        trial
        for trial, matches in sorted(by_trial.items())
        if len(matches) > 1
        for _ in range(len(matches) - 1)
    ]
    durations = [
        int(row["duration_ms"]) for row in rows if row["duration_ms"] is not None
    ]
    token_rows = [row for row in rows if row["token_coverage"]]
    cost_rows = [row for row in rows if row["cost_coverage"]]
    usage_call_count = sum(int(row["usage_call_count"]) for row in rows)
    provider_ticks_covered_calls = sum(
        int(row["provider_cost_ticks_covered_calls"]) for row in rows
    )
    provider_cost_ticks = sum(
        int(row["provider_cost_ticks"])
        for row in rows
        if row["cost_source"] != "invalid_provider_ticks"
    )
    provider_cost_usd_observed = float(
        Decimal(provider_cost_ticks) / Decimal(USD_TICKS_PER_USD)
    )
    fallback_observed = sum(
        Decimal(str(row["cost_usd"]))
        for row in rows
        if row["cost_source"] == "dated_pricing_fallback"
        and row["cost_usd"] is not None
    )
    observed_cost_lower_bound = float(
        Decimal(provider_cost_ticks) / Decimal(USD_TICKS_PER_USD) + fallback_observed
    )
    cost_sources = Counter(str(row["cost_source"]) for row in rows)
    usage_states = Counter(str(row["usage_state"]) for row in rows)
    usage_sources = Counter(str(row["usage_source"]) for row in rows)
    usage_state_counts = {
        state: usage_states.get(state, 0)
        for state in ("complete", "partial", "unavailable", "invalid")
    }
    usage_source_counts = {
        source: usage_sources.get(source, 0)
        for source in (
            "run_record_v2",
            "run_record_v1",
            "event_prefix",
            "run_record",
            "usage_receipt_v2",
            "unavailable",
        )
    }
    verifier_result_kinds = Counter(str(row["verifier_result_kind"]) for row in rows)
    runtime_entry_states = Counter(str(row["runtime_entry_state"]) for row in rows)
    publication_kinds = Counter(
        (
            str(row["publication_kind"])
            if artifacts.publication_valid
            and row["publication_kind"] in _PUBLICATION_KINDS
            else "unavailable"
            if row["publication_kind"] is None
            else "invalid"
        )
        for row, artifacts in zip(rows, artifact_rows, strict=True)
    )
    workspace_failure_subtypes = Counter(
        str(row["workspace_failure_subtype"] or "legacy_or_none") for row in rows
    )
    provider_calls = {
        "requested": sum(int(row["provider_calls_requested"]) for row in rows),
        "completed": sum(int(row["provider_calls_completed"]) for row in rows),
        "failed": sum(int(row["provider_calls_failed"]) for row in rows),
        "in_flight": sum(int(row["provider_calls_in_flight"]) for row in rows),
        "usage_present": sum(int(row["provider_calls_usage_present"]) for row in rows),
        "usage_absent": sum(int(row["provider_calls_usage_absent"]) for row in rows),
        "usage_covered": sum(int(row["provider_calls_usage_covered"]) for row in rows),
    }
    failure_counts = Counter(str(row["failure_bucket"]) for row in rows)
    observed = sum(1 for spec in specs if str(spec["trial_id"]) in by_trial)
    passed = sum(1 for row in rows if row["pass"])
    collector_passed = sum(1 for row in rows if row["collector_pass"])
    rewarded_atif_valid = sum(1 for row in rows if row["rewarded_atif_valid"])
    runtime_result_contradictions = sum(
        row["failure_code"] == "runtime_result_contradiction" for row in rows
    )
    contamination_audited = sum(
        1 for row in rows if row["contamination_audit_state"] == "available"
    )
    contamination_signaled = sum(1 for row in rows if row["contamination_signal"])
    contamination_signaled_passes = sum(
        1 for row in rows if row["contamination_signal"] and row["collector_pass"]
    )
    contamination_strong = sum(
        int(row["protected_target_counts"]["strong"]) > 0 for row in rows
    )
    contamination_strong_passes = sum(
        int(row["protected_target_counts"]["strong"]) > 0
        and bool(row["collector_pass"])
        for row in rows
    )
    protected_target_counts = {
        field: sum(int(row["protected_target_counts"][field]) for row in rows)
        for field in (
            "findings",
            "strong",
            "attempted",
            "access_blocked",
            "dispatched",
            "bytes_returned",
            "causal_benefit",
        )
    }
    submission_integrity_blocking_trials = sum(
        bool(row["submission_integrity_blocking"]) for row in rows
    )
    submission_integrity_blocking_findings = sum(
        int(row["submission_integrity_blocking_count"]) for row in rows
    )
    submission_integrity_warning_trials = sum(
        int(row["submission_integrity_warning_count"]) > 0 for row in rows
    )
    submission_integrity_warning_findings = sum(
        int(row["submission_integrity_warning_count"]) for row in rows
    )
    git_history_blocking_trials = sum(
        bool(row["git_history_submission_blocking"]) for row in rows
    )
    git_history_counts = {
        field: sum(int(row["git_history_counts"][field]) for row in rows)
        for field in (
            "findings",
            "attempted",
            "dispatched",
            "bytes_returned",
            "causal_reuse",
            "warnings",
            "blocking",
        )
    }
    reliable = sum(1 for row in rows if row["reliable"])
    measurement_complete = sum(1 for row in rows if row["measurement_complete"])
    expected = len(specs)
    official_results_valid = all(
        classification in {"rewarded", "zero", "errored"}
        for classification, _reward_value in official_results.values()
    )
    official_numerator = (
        float(
            sum(
                (
                    Decimal(str(reward_value))
                    for classification, reward_value in official_results.values()
                    if classification in {"rewarded", "zero"}
                    and reward_value is not None
                ),
                Decimal(0),
            )
        )
        if official_results_valid
        else None
    )
    started_rows = [
        (row, artifacts)
        for row, artifacts in zip(rows, artifact_rows, strict=True)
        if row["runtime_entry_state"] == "started"
    ]
    terminalized_started = sum(
        artifacts.publication_valid for _row_value, artifacts in started_rows
    )
    usage_receipts_for_started = sum(
        bool(row["usage_receipt_valid"])
        or (row["usage_source"] == "run_record_v1" and bool(row["usage_record_valid"]))
        for row, _artifacts in started_rows
    )
    wall_duration = _job_wall_duration_ms(job_dir)
    capability_summary = _capability_summary(job_dir, cohort)
    summed_duration = sum(durations) if durations else None
    complete_rows_subtotal = (
        float(
            sum(
                (
                    Decimal(int(row["provider_cost_ticks"]))
                    / Decimal(USD_TICKS_PER_USD)
                    if row["cost_source"] == "provider_ticks"
                    else Decimal(str(row["cost_usd"]))
                )
                for row in cost_rows
            )
        )
        if cost_rows
        else None
    )
    cost_value = complete_rows_subtotal if len(cost_rows) == expected else None
    tool_receipt_rows = [
        row["tool_receipt_telemetry"]
        for row in rows
        if isinstance(row.get("tool_receipt_telemetry"), dict)
    ]
    summary: dict[str, object] = {
        "schema_version": SUMMARY_SCHEMA,
        "label": "full-eight-tool internal diagnostic; not a leaderboard claim",
        "pins": _summary_pins(specs, cohort),
        "cohort": {
            "job_id": cohort.get("job_id") if cohort else None,
            "label": cohort.get("label") if cohort else None,
            "concurrency": cohort.get("concurrency") if cohort else None,
            "n_attempts": 1,
            "retry_max": 0,
        },
        "cohort_manifest_sha256": (
            hashlib.sha256(_canonical(cohort)).hexdigest()
            if cohort is not None
            else None
        ),
        "capabilities": capability_summary,
        "counts": {
            "expected": expected,
            "observed": observed,
            "passed": passed,
            "reliable": reliable,
            "missing": len(missing_tasks),
            "duplicates": len(duplicate_trials),
            "unexpected": len(unexpected),
            "retries": _job_retries(job_dir),
        },
        "accuracy": {
            "numerator": passed,
            "denominator": expected,
            "percent": round(100 * passed / expected, 6),
        },
        "strict_accuracy": {
            "numerator": passed,
            "denominator": expected,
            "percent": round(100 * passed / expected, 6),
        },
        "collector_accuracy": (
            {
                "numerator": official_numerator,
                "denominator": expected,
                "percent": round(100 * official_numerator / expected, 6),
            }
            if official_numerator is not None
            else {
                "numerator": None,
                "denominator": expected,
                "percent": None,
                "availability": "unavailable",
            }
        ),
        "rewarded_atif_coverage": {
            "numerator": rewarded_atif_valid,
            "denominator": collector_passed,
            "percent": (
                round(100 * rewarded_atif_valid / collector_passed, 6)
                if collector_passed
                else 100.0
            ),
        },
        "contamination": {
            "schema_version": protected_target.AUDIT_SCHEMA,
            "finding_schema_version": protected_target.FINDING_SCHEMA,
            "policy_schema_version": protected_target.POLICY_SCHEMA,
            "policy_sha256": protected_target.POLICY_SHA256,
            "audit_available": contamination_audited,
            "audit_denominator": expected,
            "finding_trial_count": contamination_signaled,
            "finding_trial_passes": contamination_signaled_passes,
            "strong_signal_count": contamination_strong,
            "strong_signal_passes": contamination_strong_passes,
            "finding_counts": protected_target_counts,
            "submission_blocking_trial_count": (submission_integrity_blocking_trials),
            "submission_blocking_finding_count": (
                submission_integrity_blocking_findings
            ),
            "submission_warning_trial_count": submission_integrity_warning_trials,
            "submission_warning_finding_count": (submission_integrity_warning_findings),
            "signal_adjusted_collector_numerator": (
                collector_passed - contamination_signaled_passes
            ),
            "signal_adjusted_collector_denominator": expected,
            "signal_adjusted_collector_percent": round(
                100 * (collector_passed - contamination_signaled_passes) / expected,
                6,
            ),
        },
        "git_history_integrity": {
            "schema_version": git_history_audit.AUDIT_SCHEMA,
            "finding_schema_version": git_history_audit.FINDING_SCHEMA,
            "audit_available": sum(
                row["git_history_audit_state"] == "available" for row in rows
            ),
            "audit_denominator": expected,
            "blocking_trial_count": git_history_blocking_trials,
            "finding_counts": git_history_counts,
        },
        "reliability": {
            "numerator": reliable,
            "denominator": expected,
            "percent": round(100 * reliable / expected, 6),
        },
        "measurement_completeness": {
            "numerator": measurement_complete,
            "denominator": expected,
            "percent": round(100 * measurement_complete / expected, 6),
        },
        "gates": {
            "job_terminal": True,
            "contamination_clean": contamination_signaled == 0,
            "submission_integrity_clean": (
                submission_integrity_blocking_trials == 0
                and git_history_blocking_trials == 0
            ),
            "git_history_integrity_clean": git_history_blocking_trials == 0,
            "exact_inventory": (
                observed == expected
                and not missing_tasks
                and not duplicate_trials
                and not unexpected
            ),
            "result_identity": all(bool(row["result_binding_valid"]) for row in rows),
            "official_results": official_results_valid,
            "runtime_result_consistency": runtime_result_contradictions == 0,
            "terminal_record": all(bool(row["terminal_record_valid"]) for row in rows),
            "terminalized_runtime_starts": (terminalized_started == len(started_rows)),
            "usage_receipts_for_runtime_starts": (
                usage_receipts_for_started == len(started_rows)
            ),
            "diagnostic_package": all(
                bool(row["diagnostic_package_valid"]) for row in rows
            ),
            "rewarded_atif": rewarded_atif_valid == collector_passed,
            "workspace_snapshot": all(
                bool(row["workspace_snapshot_complete"]) for row in rows
            ),
            "measurement_complete": measurement_complete == expected,
            "collect_idempotent": True,
        },
        "failure_buckets": {
            bucket: failure_counts.get(bucket, 0) for bucket in _FAILURE_BUCKETS
        },
        "verifier_result_kinds": {
            kind: verifier_result_kinds.get(kind, 0) for kind in _VERIFIER_RESULT_KINDS
        },
        "workspace_failure_subtypes": {
            kind: workspace_failure_subtypes.get(kind, 0)
            for kind in (
                "legacy_or_none",
                *(member.value for member in SnapshotFailureSubtypeV1),
            )
        },
        "terminal_evidence": {
            "runtime_entry_states": {
                state: runtime_entry_states.get(state, 0)
                for state in ("started", "not_observed", "invalid")
            },
            "publication_kinds": {
                kind: publication_kinds.get(kind, 0)
                for kind in (*_PUBLICATION_KINDS, "unavailable", "invalid")
            },
            "usage_states": usage_state_counts,
            "usage_sources": usage_source_counts,
            "observed_runtime_starts": len(started_rows),
            "terminalized_started": terminalized_started,
            "valid_usage_receipts_for_started": usage_receipts_for_started,
        },
        "duration_ms": {
            "p50": _percentile(durations, 0.50),
            "p95": _percentile(durations, 0.95),
            "total": wall_duration if wall_duration is not None else summed_duration,
            "wall_clock": wall_duration,
            "sum_tasks": summed_duration,
            "coverage": f"{len(durations)}/{expected}",
        },
        "usage": {
            "state_counts": usage_state_counts,
            "source_counts": usage_source_counts,
            "provider_calls": provider_calls,
        },
        "tokens": {
            "input": sum(int(row["input_tokens"]) for row in token_rows),
            "cache": sum(int(row["cache_tokens"]) for row in token_rows),
            "output": sum(int(row["output_tokens"]) for row in token_rows),
            "coverage": f"{len(token_rows)}/{expected}",
        },
        "cost_usd": {
            "value": cost_value,
            "coverage": f"{len(cost_rows)}/{expected}",
            "is_lower_bound": len(cost_rows) != expected,
            "complete_rows_subtotal": complete_rows_subtotal,
            "provider_cost_ticks": provider_cost_ticks,
            "provider_cost_usd_observed": provider_cost_usd_observed,
            "observed_lower_bound": observed_cost_lower_bound,
            "provider_ticks_coverage": (
                f"{provider_ticks_covered_calls}/{usage_call_count}"
            ),
            "provider_ticks_per_usd": USD_TICKS_PER_USD,
            "sources": {
                source: cost_sources.get(source, 0)
                for source in (
                    "provider_ticks",
                    "partial_provider_ticks",
                    "dated_pricing_fallback",
                    "unavailable",
                    "invalid_provider_ticks",
                )
            },
            "pricing_sha256": pricing.source_sha256 if pricing is not None else None,
            "pricing_as_of": pricing.as_of if pricing is not None else None,
            "pricing_model": pricing.model if pricing is not None else None,
            "input_per_million_usd": (
                float(pricing.input_per_million_usd) if pricing is not None else None
            ),
            "cached_input_per_million_usd": (
                float(pricing.cached_input_per_million_usd)
                if pricing is not None
                else None
            ),
            "output_per_million_usd": (
                float(pricing.output_per_million_usd) if pricing is not None else None
            ),
        },
        "missing_tasks": missing_tasks,
        "duplicate_trials": duplicate_trials,
        "unexpected_trials": sorted(unexpected),
    }
    if interrupted and terminalization is not None:
        interruption_counts = Counter(interruption_by_trial.values())
        counts = summary["counts"]
        gates = summary["gates"]
        terminal_evidence = summary["terminal_evidence"]
        cost_summary = summary["cost_usd"]
        token_summary = summary["tokens"]
        duration_summary = summary["duration_ms"]
        assert isinstance(counts, dict)
        assert isinstance(gates, dict)
        assert isinstance(terminal_evidence, dict)
        assert isinstance(cost_summary, dict)
        assert isinstance(token_summary, dict)
        assert isinstance(duration_summary, dict)
        counts.update(
            {
                "completed": interruption_counts["terminal"],
                "not_started": interruption_counts["not_started"],
                "incomplete": interruption_counts["incomplete"],
            }
        )
        unavailable_metric = {
            "numerator": None,
            "denominator": expected,
            "percent": None,
            "availability": "unavailable",
        }
        for key in (
            "accuracy",
            "strict_accuracy",
            "collector_accuracy",
            "reliability",
            "measurement_completeness",
        ):
            summary[key] = dict(unavailable_metric)
        summary["run_outcome"] = {
            "status": "interrupted",
            "reason": terminalization["reason"],
            "complete": False,
            "receipt_schema": INTERRUPTION_TERMINALIZATION_SCHEMA,
        }
        gates.update(
            {
                "run_complete": False,
                "interruption_receipt": True,
            }
        )
        terminal_evidence["interruption"] = {
            "receipt_sha256": hashlib.sha256(_canonical(terminalization)).hexdigest(),
            "census": terminalization["census"],
            "evidence": terminalization["evidence"],
        }
        cost_summary["value"] = None
        cost_summary["is_lower_bound"] = True
        token_summary["is_lower_bound"] = True
        duration_summary["total"] = None
        duration_summary["wall_clock"] = None
    if tool_receipt_rows:
        coverage_counts = Counter(
            (
                str(telemetry["coverage"])
                if isinstance(telemetry, dict)
                else "unavailable"
            )
            for telemetry in (row.get("tool_receipt_telemetry") for row in rows)
        )
        samples = [
            sample
            for telemetry in tool_receipt_rows
            if isinstance(telemetry.get("samples"), list)
            for sample in telemetry["samples"]
            if isinstance(sample, dict)
        ]
        terminal_evidence = summary["terminal_evidence"]
        assert isinstance(terminal_evidence, dict)
        terminal_evidence["tool_receipt_telemetry"] = {
            "coverage_counts": {
                coverage: coverage_counts.get(coverage, 0)
                for coverage in (
                    "complete",
                    "partial",
                    "unavailable",
                    "invalid",
                )
            },
            "sample_count": len(samples),
            "omitted_samples": sum(
                int(telemetry["omitted_samples"]) for telemetry in tool_receipt_rows
            ),
            "owner_counts": {
                "tool": sum(sample.get("owner") == "tool" for sample in samples)
            },
            "phase_counts": {
                phase: sum(sample.get("phase") == phase for sample in samples)
                for phase in sorted(_TOOL_RECEIPT_PHASES)
            },
        }
    rows_bytes = b"".join(_canonical(row) for row in rows)
    _atomic_write(job_dir / "rows.jsonl", rows_bytes)
    _atomic_write(job_dir / "summary.json", _canonical(summary))
    return summary


def _cohort_receipt(
    *,
    prepared: PreparedRun,
    job: Any,
    specs: Sequence[Mapping[str, Any]],
) -> Mapping[str, Any]:
    inventory = {row.task_id: row for row in prepared.selected}
    tasks: list[dict[str, object]] = []
    for spec in sorted(specs, key=lambda row: str(row["task"]["id"])):
        task = spec["task"]
        source = inventory.get(task["id"])
        official_digest = prepared.official_task_checksums.get(str(task["id"]))
        if (
            source is None
            or official_digest is None
            or task["digest"] != official_digest
        ):
            raise TB21Error("task_digest_binding_mismatch")
        tasks.append(
            {
                "task_id": source.task_id,
                "task_digest": task["digest"],
                "source_task_digest": source.task_digest,
                "source_sha256": source.source_sha256,
                "trial_id": spec["trial_id"],
                "run_spec_sha256": rust_run_spec_sha256(spec),
                "resources": {
                    "docker_image": source.docker_image,
                    "cpus": source.cpus,
                    "memory_mb": source.memory_mb,
                    "storage_mb": source.storage_mb,
                    "gpus": source.gpus,
                },
            }
        )
    runtime: dict[str, object] = {
        "git_head": prepared.runtime_git_head,
        "source_sha256": prepared.runtime_source_sha256,
        "binary_sha256": prepared.runtime_binary_sha256,
        "contract_set_sha256": prepared.inputs.contract_set_sha256,
        "profile_id": prepared.inputs.profile_id,
        "model": prepared.inputs.provider_model,
        "max_provider_turns": prepared.inputs.max_turns,
    }
    manifest: dict[str, object] = {
        "schema_version": COHORT_SCHEMA,
        "label": "full-eight-tool internal diagnostic; not a leaderboard claim",
        "dataset": TB21_DATASET,
        "dataset_ref": TB21_DATASET_REF,
        "source_commit": TB21_SOURCE_COMMIT,
        "harbor_commit": HARBOR_COMMIT,
        "job_id": str(job.id),
        "job_name": str(job.config.job_name),
        "n_attempts": 1,
        "retry_max": 0,
        "concurrency": prepared.concurrency,
        "active_tools": list(ACTIVE_TOOLS),
        "runtime": runtime,
        "tasks": tasks,
    }
    capabilities = getattr(prepared, "capability_manifest", None)
    if capabilities is not None:
        if not validate_capability_manifest(capabilities):
            raise TB21Error("capability_manifest_invalid")
        manifest["capability_capture_state"] = capabilities["capture_state"]
        manifest["capability_manifest_sha256"] = hashlib.sha256(
            _canonical(capabilities)
        ).hexdigest()
    return manifest


def _write_cohort(path: Path, manifest: Mapping[str, Any]) -> None:
    envelope = {
        "manifest": manifest,
        "manifest_sha256": hashlib.sha256(_canonical(manifest)).hexdigest(),
    }
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(_canonical(envelope))
        handle.flush()
        os.fsync(handle.fileno())


def prepare_run(
    *,
    repository: Path,
    harbor_checkout: Path,
    source_checkout: Path,
    output_dir: Path,
    contract_dir: Path,
    inventory: tuple[InventoryTask, ...],
    selected: tuple[InventoryTask, ...],
    concurrency: int,
    binary_path: Path | None,
    cargo: str,
    capability_manifest: Mapping[str, Any] | None = None,
) -> PreparedRun:
    """Perform local preflight without creating the requested output directory."""

    if output_dir.exists() or output_dir.is_symlink():
        raise TB21Error("fresh_output_required")
    official_task_checksums = load_official_task_checksums(repository, inventory)
    capabilities = (
        dict(capability_manifest)
        if capability_manifest is not None
        else capture_capability_manifest(None)
    )
    if not validate_capability_manifest(capabilities):
        raise TB21Error("capability_manifest_invalid")
    selected_binary, source_sha256, git_head = select_runtime_binary(
        repository,
        binary_path=binary_path,
        cargo=cargo,
    )
    inputs = load_runtime_inputs(
        binary_path=selected_binary,
        contract_dir=contract_dir,
        provider_launch=HostProviderLaunch.xai(),
        active_tools=ACTIVE_TOOLS,
    )
    if (
        inputs.provider_model != LIVE_MODEL
        or inputs.reasoning_effort != "high"
        or inputs.max_turns != TB21_MAX_TURNS
        or inputs.active_tools != ACTIVE_TOOLS
    ):
        raise TB21Error("runtime_binding_invalid")
    return PreparedRun(
        repository=repository,
        harbor_checkout=harbor_checkout,
        source_checkout=source_checkout,
        output_dir=output_dir,
        inventory=inventory,
        selected=selected,
        concurrency=concurrency,
        inputs=inputs,
        runtime_source_sha256=source_sha256,
        runtime_git_head=git_head,
        runtime_binary_sha256=hashlib.sha256(
            _read_regular(selected_binary)
        ).hexdigest(),
        official_task_checksums=official_task_checksums,
        capability_manifest=capabilities,
    )


async def run_baseline(
    prepared: PreparedRun,
    *,
    pricing: Pricing | None = None,
) -> tuple[Path, dict[str, object]]:
    """Create one native Harbor queue, run it once, then collect all expected rows."""

    sys.path.insert(0, str(prepared.harbor_checkout / "src"))
    from harbor.models.job.config import DatasetConfig, JobConfig, RetryConfig
    from harbor.models.trial.config import (
        AgentConfig,
        EnvironmentConfig,
    )

    prepared.output_dir.mkdir(parents=True, exist_ok=False)
    config = JobConfig(
        job_name="nano-tb21-baseline",
        jobs_dir=prepared.output_dir / "jobs",
        n_attempts=1,
        n_concurrent_trials=prepared.concurrency,
        quiet=True,
        retry=RetryConfig(max_retries=0),
        environment=EnvironmentConfig(type="docker", delete=True),
        agents=[
            AgentConfig(
                name=LEADERBOARD_AGENT,
                import_path="nano_grok_build.adapter.harbor:NanoGrokBuildAgent",
                model_name=LEADERBOARD_MODEL,
                kwargs={"reasoning_effort": prepared.inputs.reasoning_effort},
            )
        ],
        datasets=[
            DatasetConfig(
                name=TB21_DATASET,
                ref=TB21_DATASET_REF,
                task_names=[task.task_id for task in prepared.selected],
            )
        ],
        tasks=[],
    )
    bound = await create_bound_job(config, prepared.inputs)
    if len(bound.run_specs) != len(prepared.selected):
        raise TB21Error("bound_trial_count_mismatch")
    expected_ids = [task.task_id for task in prepared.selected]
    actual_ids = sorted(str(spec["task"]["id"]) for spec in bound.run_specs)
    if actual_ids != expected_ids:
        raise TB21Error("bound_task_identity_mismatch")
    manifest = _cohort_receipt(
        prepared=prepared,
        job=bound.job,
        specs=bound.run_specs,
    )
    capabilities = getattr(prepared, "capability_manifest", None)
    if capabilities is not None:
        _write_capability_manifest(
            bound.job.job_dir / "nano-capability-manifest.json",
            capabilities,
        )
    _write_cohort(bound.job.job_dir / "nano-tb21-cohort.json", manifest)
    try:
        await bound.job.run()
    except (asyncio.CancelledError, KeyboardInterrupt, Exception) as error:
        try:
            _terminalize_interruption(
                bound.job.job_dir,
                bound.run_specs,
                error,
                pricing=pricing,
            )
        except TB21Error as finalization_error:
            raise TB21Error("interruption_finalization_failed") from finalization_error
        raise
    return bound.job.job_dir, collect_job(
        bound.job.job_dir,
        pricing=pricing,
    )


def _selectors(args: argparse.Namespace) -> tuple[str, ...]:
    rows = list(args.task or [])
    for path in args.task_file or []:
        rows.extend(read_task_file(path.resolve()))
    if args.all_tasks:
        if rows:
            raise TB21Error("task_selection_ambiguous")
        return ()
    if not rows:
        raise TB21Error("task_selection_required")
    return tuple(rows)


def parse_args(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--harbor-checkout", type=Path)
    parser.add_argument("--tb21-checkout", type=Path)
    parser.add_argument("--contract-dir", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--task", action="append")
    parser.add_argument("--task-file", type=Path, action="append")
    parser.add_argument("--all", dest="all_tasks", action="store_true")
    parser.add_argument(
        "--concurrency",
        type=int,
        choices=ALLOWED_CONCURRENCY,
        default=DEFAULT_CONCURRENCY,
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plan-only", action="store_true")
    mode.add_argument("--prelaunch-only", action="store_true")
    mode.add_argument("--collect-only", type=Path)
    parser.add_argument("--pricing-json", type=Path)
    parser.add_argument("--capability-probe", type=Path)
    parser.add_argument("--runtime-python", type=Path)
    parser.add_argument("--runtime-python-sha256")
    parser.add_argument("--harbor-lock-sha256")
    parser.add_argument("--carrier", choices=("foreground", "screen"))
    parser.add_argument("--controller-pid-file", type=Path)
    return parser.parse_args(arguments)


def _prelaunch_arguments_present(args: argparse.Namespace) -> bool:
    return any(
        value is not None
        for value in (
            args.runtime_python,
            args.runtime_python_sha256,
            args.harbor_lock_sha256,
            args.carrier,
            args.controller_pid_file,
        )
    )


def _validate_prelaunch_arguments(args: argparse.Namespace) -> bool:
    enabled = args.prelaunch_only or _prelaunch_arguments_present(args)
    if not enabled:
        if args.all_tasks and not args.plan_only and args.collect_only is None:
            raise TB21Error("prelaunch_arguments_required")
        return False
    if args.plan_only or args.collect_only is not None:
        raise TB21Error("prelaunch_mode_invalid")
    if (
        args.runtime_python is None
        or args.runtime_python_sha256 is None
        or args.harbor_lock_sha256 is None
        or args.carrier is None
        or args.controller_pid_file is None
        or args.binary is None
        or args.output_dir is None
    ):
        raise TB21Error("prelaunch_arguments_required")
    return True


def _prepare_inventory(
    args: argparse.Namespace,
    *,
    repository: Path | None = None,
) -> tuple[
    Path,
    Path,
    tuple[InventoryTask, ...],
    tuple[InventoryTask, ...],
    dict[str, object],
]:
    if args.harbor_checkout is None or args.tb21_checkout is None:
        raise TB21Error("checkout_required")
    harbor_checkout = args.harbor_checkout.resolve()
    source_checkout = args.tb21_checkout.resolve()
    upstreams = {
        "harbor": _verified_upstream_identity(
            harbor_checkout,
            repository=HARBOR_REPOSITORY,
            commit=HARBOR_COMMIT,
            tree=HARBOR_TREE,
            code="harbor_checkout_invalid",
        ),
        "terminal_bench": _verified_upstream_identity(
            source_checkout,
            repository=TB21_SOURCE_REPOSITORY,
            commit=TB21_SOURCE_COMMIT,
            tree=TB21_SOURCE_TREE,
            code="tb21_checkout_invalid",
        ),
    }
    inventory = load_inventory(source_checkout / "tasks")
    official_checksums = load_official_task_checksums(
        repository or Path(__file__).resolve().parents[3],
        inventory,
    )
    history_capabilities = _inventory_history_capabilities(
        inventory,
        official_checksums,
    )
    inventory_rows = [_inventory_row(task) for task in inventory]
    inventory_digest_rows = [
        {key: value for key, value in row.items() if key != "path"}
        for row in inventory_rows
    ]
    authority = {
        "schema_version": INVENTORY_AUTHORITY_SCHEMA,
        "state": "verified",
        "official_task_checksums_sha256": hashlib.sha256(
            _canonical(official_checksums)
        ).hexdigest(),
        "inventory": {
            "task_count": len(inventory),
            "digest_scope": PUBLIC_TASK_METADATA_SCHEMA,
            "sha256": hashlib.sha256(_canonical(inventory_digest_rows)).hexdigest(),
        },
        "upstreams": upstreams,
    }
    selectors = _selectors(args)
    selected = inventory if args.all_tasks else select_tasks(inventory, selectors)
    if not selected:
        raise TB21Error("task_selection_required")
    payload = plan_payload(
        inventory=inventory,
        selected=selected,
        concurrency=args.concurrency,
        source_checkout=source_checkout,
        capability_manifest=capture_capability_manifest(
            args.capability_probe.resolve()
            if args.capability_probe is not None
            else None
        ),
        inventory_authority=authority,
        git_history_capabilities=history_capabilities,
    )
    if args.output_dir is not None and (
        args.output_dir.exists() or args.output_dir.is_symlink()
    ):
        raise TB21Error("fresh_output_required")
    return harbor_checkout, source_checkout, inventory, selected, payload


def main(arguments: list[str] | None = None) -> int:
    args = parse_args(arguments)
    repository = Path(__file__).resolve().parents[3]
    try:
        prelaunch_enabled = _validate_prelaunch_arguments(args)
        pricing = (
            load_pricing(args.pricing_json.resolve())
            if args.pricing_json is not None
            else None
        )
        if args.collect_only is not None:
            if args.task or args.task_file or args.all_tasks:
                raise TB21Error("collect_selection_invalid")
            if args.contract_dir is not None:
                raise TB21Error("collect_contract_invalid")
            summary = collect_job(
                args.collect_only,
                pricing=pricing,
            )
            print(
                json.dumps(
                    {
                        "status": "collected",
                        "job_dir": str(args.collect_only.resolve()),
                        "summary": summary,
                    },
                    sort_keys=True,
                )
            )
            return 0
        (
            harbor_checkout,
            source_checkout,
            inventory,
            selected,
            payload,
        ) = _prepare_inventory(args)
        if args.plan_only:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
            return 0
        if args.output_dir is None or args.contract_dir is None:
            raise TB21Error("run_paths_required")
        prepared = prepare_run(
            repository=repository,
            harbor_checkout=harbor_checkout,
            source_checkout=source_checkout,
            output_dir=args.output_dir.resolve(),
            contract_dir=args.contract_dir.resolve(),
            inventory=inventory,
            selected=selected,
            concurrency=args.concurrency,
            binary_path=args.binary.resolve() if args.binary is not None else None,
            cargo=args.cargo,
            capability_manifest=payload["capability_manifest"],
        )
        admission = None
        if prelaunch_enabled:
            assert args.runtime_python is not None
            assert args.runtime_python_sha256 is not None
            assert args.harbor_lock_sha256 is not None
            assert args.carrier is not None
            assert args.controller_pid_file is not None
            try:
                admission = admit_prelaunch(
                    harbor_checkout=harbor_checkout,
                    runtime_python=args.runtime_python,
                    runtime_python_sha256=args.runtime_python_sha256,
                    harbor_lock_sha256=args.harbor_lock_sha256,
                    expected_harbor_commit=HARBOR_COMMIT,
                    binary_path=prepared.inputs.binary_path,
                    contract_dir=prepared.inputs.contract_dir,
                    output_dir=args.output_dir.resolve(),
                    pid_file=args.controller_pid_file,
                    carrier=args.carrier,
                    docker_images=tuple(task.docker_image for task in selected),
                    selected_storage_mb=tuple(task.storage_mb for task in selected),
                    concurrency=args.concurrency,
                )
            except PrelaunchError as error:
                raise TB21Error(str(error)) from error
        else:
            try:
                admit_contract(
                    binary_path=prepared.inputs.binary_path,
                    contract_dir=prepared.inputs.contract_dir,
                )
            except PrelaunchError as error:
                raise TB21Error(str(error)) from error
        if args.prelaunch_only:
            assert admission is not None
            print(
                json.dumps(
                    {
                        "status": "prelaunch-passed",
                        "plan": {
                            "schema_version": payload["schema_version"],
                            "inventory_sha256": payload["inventory_sha256"],
                            "expected_inventory_count": payload[
                                "expected_inventory_count"
                            ],
                            "selected_count": payload["selected_count"],
                            "concurrency": payload["concurrency"],
                            "n_attempts": payload["n_attempts"],
                            "retry_max": payload["retry_max"],
                        },
                        "admission": admission,
                    },
                    sort_keys=True,
                )
            )
            return 0
        if admission is not None:
            operations = admission.get("operations")
            image_bindings = (
                operations.get("image_bindings")
                if isinstance(operations, Mapping)
                else None
            )
            try:
                verify_docker_image_bindings(image_bindings)
            except PrelaunchError as error:
                raise TB21Error(str(error)) from error
        if not load_xai_key(repository / ".env", os.environ):
            raise TB21Error("xai_credential_unavailable")
        job_dir, summary = asyncio.run(run_baseline(prepared, pricing=pricing))
        print(
            json.dumps(
                {
                    "status": "completed",
                    "job_dir": str(job_dir),
                    "summary": summary,
                },
                sort_keys=True,
            )
        )
        return 0
    except TB21Error as error:
        print(json.dumps({"status": "failed", "error": str(error)}, sort_keys=True))
        return 1
    except BaseException as error:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "error": "tb21_failed",
                    "exception_type": (
                        f"{type(error).__module__}.{type(error).__qualname__}"
                    ),
                },
                sort_keys=True,
            )
        )
        return 1
