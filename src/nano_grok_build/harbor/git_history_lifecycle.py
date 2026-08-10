"""Strict lifecycle proof for physical pre-existing Git-history isolation."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nano_grok_build.harbor.git_history_capability import (
    GIT_HISTORY_ACCESS_NOT_REQUIRED,
    GIT_HISTORY_ACCESS_REQUIRED,
)
from nano_grok_build.harbor.git_history_receipt import git_history_access

EXPOSURE_RECEIPT = "git-history-exposure-v1.json"
REHYDRATION_RECEIPT = "git-history-rehydration-v1.json"
EXPOSURE_SCHEMA = "nano-git-history-exposure-v1"
REHYDRATION_SCHEMA = "nano-git-history-rehydration-v1"
LIFECYCLE_POLICY = "nano-git-history-lifecycle-v1"

_MAX_BYTES = 64 * 1024
_MAX_EVENTS_BYTES = 64 * 1024 * 1024
_HEX = frozenset("0123456789abcdef")
_EXPOSURE_KEYS = {
    "schema_version",
    "policy_version",
    "run_spec_sha256",
    "capability_instruction_sha256",
    "trusted_manifest_sha256",
    "baseline_receipt_sha256",
    "baseline_status",
    "archive_state",
    "archive_sha256",
    "archive_size",
    "source_commit_oid",
    "source_tree_oid",
    "isolated_guard_sha256",
    "remote_archive_deleted",
    "controller_storage_kind",
    "controller_archive_path_sha256",
    "controller_archive_outside_control_plane",
    "controller_archive_outside_workspace",
    "agent_remote_archive_absent",
    "control_plane_not_agent_mounted",
    "pre_agent_monotonic_ns",
    "agent_dispatch_started",
}
_REHYDRATION_KEYS = {
    "schema_version",
    "policy_version",
    "run_spec_sha256",
    "capability_instruction_sha256",
    "trusted_manifest_sha256",
    "baseline_receipt_sha256",
    "exposure_receipt_sha256",
    "run_record_sha256",
    "events_sha256",
    "terminal_status",
    "agent_closed",
    "provider_closed",
    "provider_in_flight",
    "background_manifest_sha256",
    "background_count",
    "workspace_receipt_sha256",
    "isolated_guard_sha256",
    "restore_result",
    "verifier_started",
    "post_agent_monotonic_ns",
    "rehydration_started_monotonic_ns",
    "rehydration_finished_monotonic_ns",
}


@dataclass(frozen=True)
class GitHistoryLifecycleProof:
    original_history_exposure_possible: bool
    diagnostic_only: bool
    exposure_receipt_sha256: str
    rehydration_receipt_sha256: str


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hex(value: object, lengths: set[int] = {64}) -> bool:
    return isinstance(value, str) and len(value) in lengths and set(value) <= _HEX


def _uint(value: object, *, positive: bool = False) -> bool:
    return type(value) is int and value >= (1 if positive else 0)


def _read_canonical(path: Path) -> tuple[dict[str, Any], bytes]:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_BYTES:
            raise RuntimeError("git_history_lifecycle_invalid")
        raw = os.read(descriptor, _MAX_BYTES + 1)
        if len(raw) != metadata.st_size:
            raise RuntimeError("git_history_lifecycle_invalid")

        def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError("duplicate")
                result[key] = item
            return result

        value = json.loads(
            raw,
            object_pairs_hook=unique,
            parse_constant=lambda _item: (_ for _ in ()).throw(ValueError()),
        )
        if not isinstance(value, dict) or canonical_json(value) != raw:
            raise RuntimeError("git_history_lifecycle_invalid")
        return value, raw
    except FileNotFoundError as error:
        raise RuntimeError("git_history_lifecycle_missing") from error
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeError("git_history_lifecycle_invalid") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_regular_bytes(path: Path) -> bytes:
    _value, raw = _read_canonical(path)
    return raw


def _identity_matches(
    value: Mapping[str, Any], capability: Mapping[str, Any], run_hash: str
) -> bool:
    return (
        value.get("run_spec_sha256") == run_hash
        and value.get("capability_instruction_sha256")
        == capability.get("canonical_instruction_sha256")
        and value.get("trusted_manifest_sha256")
        == capability.get("trusted_manifest_sha256")
    )


def load_git_history_lifecycle_proof(
    agent_dir: Path,
    *,
    capability: object,
    run_spec_sha256: str,
    baseline_receipt: Mapping[str, object],
) -> GitHistoryLifecycleProof:
    """Validate a complete immutable chain; absence is never silently upgraded."""

    try:
        access = git_history_access(capability)
    except RuntimeError as error:
        raise RuntimeError("git_history_lifecycle_invalid") from error
    if not isinstance(capability, Mapping) or not _hex(run_spec_sha256):
        raise RuntimeError("git_history_lifecycle_invalid")
    baseline_raw = _read_regular_bytes(agent_dir / "git-history-baseline.json")
    baseline_sha = sha256_bytes(baseline_raw)
    exposure, exposure_raw = _read_canonical(agent_dir / EXPOSURE_RECEIPT)
    if (
        set(exposure) != _EXPOSURE_KEYS
        or exposure.get("schema_version") != EXPOSURE_SCHEMA
        or exposure.get("policy_version") != LIFECYCLE_POLICY
        or not _identity_matches(exposure, capability, run_spec_sha256)
        or exposure.get("baseline_receipt_sha256") != baseline_sha
        or exposure.get("baseline_status") != baseline_receipt.get("status")
        or exposure.get("remote_archive_deleted") is not True
        or exposure.get("agent_remote_archive_absent") is not True
        or exposure.get("control_plane_not_agent_mounted") is not True
        or exposure.get("controller_archive_outside_control_plane") is not True
        or exposure.get("controller_archive_outside_workspace") is not True
        or exposure.get("agent_dispatch_started") is not False
        or not _uint(exposure.get("pre_agent_monotonic_ns"), positive=True)
    ):
        raise RuntimeError("git_history_lifecycle_invalid")
    status = baseline_receipt.get("status")
    isolated = status == "isolated"
    if isolated:
        if (
            access != GIT_HISTORY_ACCESS_NOT_REQUIRED
            or exposure.get("archive_state") != "controller_private"
            or exposure.get("controller_storage_kind") != "private_regular_file"
            or not _hex(exposure.get("archive_sha256"))
            or not _uint(exposure.get("archive_size"), positive=True)
            or exposure.get("source_commit_oid")
            != baseline_receipt.get("source_commit_oid")
            or exposure.get("source_tree_oid")
            != baseline_receipt.get("source_tree_oid")
            or not _hex(exposure.get("source_commit_oid"), {40, 64})
            or not _hex(exposure.get("source_tree_oid"), {40, 64})
            or not _hex(exposure.get("isolated_guard_sha256"))
            or not _hex(exposure.get("controller_archive_path_sha256"))
        ):
            raise RuntimeError("git_history_lifecycle_invalid")
    elif (
        exposure.get("archive_state") != "absent"
        or exposure.get("archive_sha256") is not None
        or exposure.get("archive_size") != 0
        or exposure.get("isolated_guard_sha256") is not None
        or exposure.get("controller_storage_kind") != "none"
        or exposure.get("controller_archive_path_sha256") is not None
        or status == "preserved"
        and access != GIT_HISTORY_ACCESS_REQUIRED
        or status not in {"absent_clean", "created", "preserved"}
    ):
        raise RuntimeError("git_history_lifecycle_invalid")

    rehydration, rehydration_raw = _read_canonical(agent_dir / REHYDRATION_RECEIPT)
    run, run_raw = _read_canonical(agent_dir / "runtime" / "run.json")
    _events, events_raw = _read_canonical_lines(agent_dir / "runtime" / "events.jsonl")
    background, background_raw = _read_canonical(
        agent_dir / "runtime-background-manifest.json"
    )
    workspace_raw = _read_regular_bytes(agent_dir / "workspace-receipt.json")
    coverage = run.get("provider_call_coverage")
    tasks = background.get("tasks")
    if (
        set(rehydration) != _REHYDRATION_KEYS
        or rehydration.get("schema_version") != REHYDRATION_SCHEMA
        or rehydration.get("policy_version") != LIFECYCLE_POLICY
        or not _identity_matches(rehydration, capability, run_spec_sha256)
        or rehydration.get("baseline_receipt_sha256") != baseline_sha
        or rehydration.get("exposure_receipt_sha256") != sha256_bytes(exposure_raw)
        or rehydration.get("run_record_sha256") != sha256_bytes(run_raw)
        or rehydration.get("events_sha256") != sha256_bytes(events_raw)
        or run.get("events_sha256") != sha256_bytes(events_raw)
        or run.get("run_spec_sha256") != run_spec_sha256
        or rehydration.get("terminal_status") != run.get("terminal_status")
        or rehydration.get("agent_closed") is not True
        or rehydration.get("provider_closed") is not True
        or not isinstance(coverage, Mapping)
        or coverage.get("in_flight") != 0
        or rehydration.get("provider_in_flight") != 0
        or rehydration.get("background_manifest_sha256") != sha256_bytes(background_raw)
        or not isinstance(tasks, list)
        or rehydration.get("background_count") != len(tasks)
        or len(tasks) != 0
        or rehydration.get("workspace_receipt_sha256") != sha256_bytes(workspace_raw)
        or rehydration.get("isolated_guard_sha256")
        != exposure.get("isolated_guard_sha256")
        or rehydration.get("restore_result")
        != ("restored" if isolated else "not_applicable")
        or rehydration.get("verifier_started") is not False
        or not all(
            _uint(rehydration.get(key), positive=True)
            for key in (
                "post_agent_monotonic_ns",
                "rehydration_started_monotonic_ns",
                "rehydration_finished_monotonic_ns",
            )
        )
        or not (
            exposure["pre_agent_monotonic_ns"]
            < rehydration["post_agent_monotonic_ns"]
            <= rehydration["rehydration_started_monotonic_ns"]
            <= rehydration["rehydration_finished_monotonic_ns"]
        )
    ):
        raise RuntimeError("git_history_lifecycle_invalid")
    return GitHistoryLifecycleProof(
        original_history_exposure_possible=False,
        diagnostic_only=False,
        exposure_receipt_sha256=sha256_bytes(exposure_raw),
        rehydration_receipt_sha256=sha256_bytes(rehydration_raw),
    )


def _read_canonical_lines(path: Path) -> tuple[tuple[object, ...], bytes]:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_EVENTS_BYTES:
            raise RuntimeError("git_history_lifecycle_invalid")
        raw = os.read(descriptor, _MAX_EVENTS_BYTES + 1)
        if len(raw) != metadata.st_size or not raw.endswith(b"\n"):
            raise RuntimeError("git_history_lifecycle_invalid")
        rows = tuple(json.loads(line) for line in raw.decode().splitlines())
        return rows, raw
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("git_history_lifecycle_invalid") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
