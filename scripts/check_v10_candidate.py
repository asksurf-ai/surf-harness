#!/usr/bin/env python3
"""Provider-free, read-only V10 candidate and result admission.

This command never launches Harbor, Docker, or a model provider.  It consumes
the immutable job records produced by the pinned TB2.1 runner, verifies the
candidate/configuration identity, and reports release metrics without changing
rewards or artifacts.  Contamination signals are post-run evidence only; this
module deliberately does not claim that they enforce execution-time egress.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import math
import os
import re
import stat
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from nano_grok_build.adapter.atif import (  # noqa: E402
    AtifError,
    validate_minimal_trajectory,
    validate_with_pinned_harbor,
)
from nano_grok_build.harbor import tb21  # noqa: E402
from nano_grok_build.harbor.compat_v020 import HARBOR_VERSION  # noqa: E402
from nano_grok_build.harbor.git_history_capability import (  # noqa: E402
    validate_git_history_capability,
)
from nano_grok_build.harbor.git_history_receipt import (  # noqa: E402
    HISTORY_BASELINE_RECEIPT,
)
from nano_grok_build.harbor.runtime_entry import (  # noqa: E402
    RUNTIME_ENTRY_NAME,
    RuntimeEntryError,
    load_runtime_entry,
)

CANDIDATE_REPORT_SCHEMA = "nano-v10-candidate-report-v3"
_MAX_JSON_BYTES = 64 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_TASK_ID = re.compile(r"^terminal-bench/[a-z0-9][a-z0-9.-]*$")
_TRIAL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
_OFFICIAL_CHECKSUMS_FILE_SHA256 = (
    "6f17fc1e73019e4af3d2889e8f310bce222ddab9100f8f9ee0a76578811fcc5f"
)


_JOB_CONFIG_KEYS = {
    "job_name",
    "jobs_dir",
    "n_concurrent_trials",
    "quiet",
    "agents",
    "datasets",
}
_JOB_AGENT_KEYS = {"name", "import_path", "model_name", "kwargs"}
_JOB_DATASET_KEYS = {"name", "ref", "task_names"}
_LOCK_KEYS = {
    "schema_version",
    "created_at",
    "harbor",
    "n_concurrent_trials",
    "retry",
    "trials",
}
_LOCK_HARBOR_KEYS = {"version", "git_commit_hash", "is_editable"}
_LOCK_RETRY_KEYS = {
    "max_retries",
    "exclude_exceptions",
    "wait_multiplier",
    "min_wait_sec",
    "max_wait_sec",
}
_LOCK_TRIAL_KEYS = {
    "schema_version",
    "task",
    "install_only",
    "timeout_multiplier",
    "agent",
    "skills",
    "environment",
    "verifier",
}
_LOCK_TASK_KEYS = {"name", "type", "digest", "source"}
_LOCK_AGENT_KEYS = {
    "name",
    "import_path",
    "model_name",
    "skills",
    "resume_trajectory",
    "extra_allowed_hosts",
    "kwargs",
    "mcp_servers",
}
_LOCK_AGENT_KWARGS = {
    "binary_path",
    "contract_dir",
    "provider_launch",
    "run_spec",
    "deadline_mode",
    "reasoning_effort",
}
_LOCK_ENVIRONMENT_KEYS = {
    "type",
    "force_build",
    "delete",
    "cpu_enforcement_policy",
    "memory_enforcement_policy",
    "extra_docker_compose",
    "kwargs",
    "extra_allowed_hosts",
}
_COHORT_BASE_KEYS = {
    "schema_version",
    "label",
    "dataset",
    "dataset_ref",
    "source_commit",
    "harbor_commit",
    "job_id",
    "job_name",
    "n_attempts",
    "retry_max",
    "concurrency",
    "active_tools",
    "runtime",
    "tasks",
}
_COHORT_CAPABILITY_KEYS = {
    "capability_capture_state",
    "capability_manifest_sha256",
}
_COHORT_RUNTIME_KEYS = {
    "git_head",
    "source_sha256",
    "binary_sha256",
    "contract_set_sha256",
    "profile_id",
    "model",
    "max_provider_turns",
}
_COHORT_TASK_KEYS = {
    "task_id",
    "task_digest",
    "source_task_digest",
    "source_sha256",
    "trial_id",
    "run_spec_sha256",
    "resources",
}
_RESOURCE_KEYS = {
    "docker_image",
    "cpus",
    "memory_mb",
    "storage_mb",
    "gpus",
}
_DISPATCH_KEYS = {
    "schema_version",
    "harbor_version",
    "job_id",
    "retry_max",
    "n_attempts",
    "run_specs",
}
_RUN_SPEC_KEYS = {
    "schema_version",
    "run_id",
    "trial_id",
    "attempt_id",
    "task",
    "contract",
    "provider",
    "workspace_dir",
    "artifact_dir",
    "agent_timeout_sec",
    "active_tools",
}
_ROW_REQUIRED_KEYS = {
    "schema_version",
    "task",
    "trial",
    "digest",
    "reward",
    "raw_score_valid",
    "collector_pass",
    "strict_pass",
    "reliable",
    "measurement_complete",
    "publication_kind",
    "success_artifact_valid",
    "diagnostic_package_valid",
    "workspace_snapshot_complete",
    "usage_receipt_valid",
    "terminal_record_valid",
    "result_binding_valid",
    "runtime_terminal_status",
    "runtime_terminal_phase",
    "runtime_terminal_code",
    "contamination_audit_state",
    "contamination_signals",
    "contamination_signal",
    "protected_target_audit_schema",
    "protected_target_policy_schema",
    "protected_target_policy_sha256",
    "protected_target_counts",
    "protected_target_findings",
    "submission_integrity_blocking",
    "submission_integrity_blocking_count",
    "submission_integrity_warning_count",
    "git_history_audit_schema",
    "git_history_finding_schema",
    "git_history_audit_state",
    "git_history_required",
    "git_history_evidence_complete",
    "git_history_findings",
    "git_history_counts",
    "git_history_submission_blocking",
    "exception",
    "failure_bucket",
    "failure_phase",
    "failure_code",
    "provider_calls_requested",
    "provider_calls_completed",
    "provider_calls_failed",
    "provider_calls_in_flight",
    "provider_calls_usage_covered",
    "usage_call_count",
    "provider_cost_ticks",
    "provider_cost_ticks_covered_calls",
    "provider_cost_usd_observed",
    "cost_usd",
    "cost_source",
    "cost_coverage",
}


class CandidateError(RuntimeError):
    """Stable candidate admission failure with no path or credential payload."""


@dataclass(frozen=True)
class StagePolicy:
    task_ids: tuple[str, ...]
    expected_jobs: int


@dataclass(frozen=True)
class _LoadedJob:
    job_id: str
    run_ids: tuple[str, ...]
    task_ids: tuple[str, ...]
    rows: tuple[dict[str, object], ...]
    complete_trials: int
    stopped_trials: int
    identity: Mapping[str, object]
    evidence_sha256: str
    projected_interruption_rows: int


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _strict_json_bytes(raw: bytes, code: str) -> object:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value

    try:
        return json.loads(
            raw,
            object_pairs_hook=unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("invalid constant")
            ),
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
    ) as error:
        raise CandidateError(code) from error


def _read_regular(path: Path, code: str, *, limit: int = _MAX_JSON_BYTES) -> bytes:
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise OSError
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            raw = handle.read(limit + 1)
        if len(raw) > limit:
            raise OSError
        return raw
    except OSError as error:
        raise CandidateError(code) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_json(path: Path, code: str) -> tuple[object, bytes]:
    raw = _read_regular(path, code)
    return _strict_json_bytes(raw, code), raw


def _mapping(value: object, code: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise CandidateError(code)
    return value


def _exact_keys(value: Mapping[str, object], keys: set[str], code: str) -> None:
    if set(value) != keys:
        raise CandidateError(code)


def _sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _positive_int(value: object) -> bool:
    return _nonnegative_int(value) and value > 0


def _absolute_path_string(value: object) -> bool:
    return (
        isinstance(value, str)
        and value
        and "\x00" not in value
        and Path(value).is_absolute()
    )


def _load_envelope(
    path: Path, schema: str, code: str
) -> tuple[Mapping[str, object], bytes]:
    value, raw = _read_json(path, code)
    envelope = _mapping(value, code)
    _exact_keys(envelope, {"manifest", "manifest_sha256"}, code)
    manifest = _mapping(envelope["manifest"], code)
    if (
        manifest.get("schema_version") != schema
        or envelope.get("manifest_sha256")
        != hashlib.sha256(_canonical(manifest)).hexdigest()
    ):
        raise CandidateError(code)
    return manifest, raw


def load_official_checksums(path: Path) -> dict[str, str]:
    """Load the one pinned 89-task identity map without materializing tasks."""

    value, raw = _read_json(path, "official_task_checksums_invalid")
    manifest = _mapping(value, "official_task_checksums_invalid")
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
    _exact_keys(manifest, expected_keys, "official_task_checksums_invalid")
    checksums = manifest.get("checksums")
    if not isinstance(checksums, dict) or any(
        not isinstance(task_id, str)
        or _TASK_ID.fullmatch(task_id) is None
        or not _sha256(digest)
        for task_id, digest in checksums.items()
    ):
        raise CandidateError("official_task_checksums_invalid")
    if (
        hashlib.sha256(raw).hexdigest() != _OFFICIAL_CHECKSUMS_FILE_SHA256
        or path.resolve() != (ROOT / tb21.OFFICIAL_TASK_CHECKSUMS_PATH).resolve()
        or manifest.get("schema_version") != tb21.OFFICIAL_TASK_CHECKSUMS_SCHEMA
        or manifest.get("dataset_name") != tb21.TB21_DATASET
        or manifest.get("dataset_digest") != tb21.TB21_DATASET_REF
        or manifest.get("harbor_version") != HARBOR_VERSION
        or manifest.get("harbor_commit") != tb21.HARBOR_COMMIT
        or manifest.get("terminal_bench_commit") != tb21.TB21_SOURCE_COMMIT
        or manifest.get("task_count") != tb21.TB21_TASK_COUNT
        or len(checksums) != tb21.TB21_TASK_COUNT
        or manifest.get("checksums_sha256")
        != hashlib.sha256(_canonical(checksums)).hexdigest()
    ):
        raise CandidateError("official_task_checksums_invalid")
    return {task_id: str(checksums[task_id]) for task_id in sorted(checksums)}


def require_pinned_harbor_validator() -> None:
    """Fail before audit when the exact validator distribution is unavailable."""

    try:
        version = importlib.metadata.version("harbor")
        from harbor.utils.trajectory_validator import TrajectoryValidator
    except (ImportError, importlib.metadata.PackageNotFoundError) as error:
        raise CandidateError("pinned_harbor_validator_unavailable") from error
    if version != HARBOR_VERSION or TrajectoryValidator is None:
        raise CandidateError("pinned_harbor_validator_version_mismatch")


def _validate_spec(spec: object, job_id: object, code: str) -> Mapping[str, object]:
    row = _mapping(spec, code)
    _exact_keys(row, _RUN_SPEC_KEYS, code)
    task = _mapping(row.get("task"), code)
    contract = _mapping(row.get("contract"), code)
    provider = _mapping(row.get("provider"), code)
    trial_id = row.get("trial_id")
    schema = row.get("schema_version")
    task_keys = {"id", "digest", "instruction"}
    if schema == "nano-run-spec-alpha-2":
        task_keys.add("git_history_capability")
    if (
        set(task) != task_keys
        or set(contract) != {"id", "contract_set_sha256", "profile_id"}
        or set(provider) != {"kind", "model", "max_turns", "retry_max"}
        or schema not in {"nano-run-spec-alpha-1", "nano-run-spec-alpha-2"}
        or row.get("attempt_id") != "attempt-0"
        or not isinstance(trial_id, str)
        or _TRIAL_ID.fullmatch(trial_id) is None
        or row.get("run_id") != f"{job_id}:{trial_id}"
        or row.get("workspace_dir") != "/workspace"
        or not _absolute_path_string(row.get("artifact_dir"))
        or not _positive_int(row.get("agent_timeout_sec"))
        or row.get("active_tools") != list(tb21.ACTIVE_TOOLS)
        or not isinstance(task.get("id"), str)
        or _TASK_ID.fullmatch(str(task["id"])) is None
        or not _sha256(task.get("digest"))
        or not isinstance(task.get("instruction"), str)
        or not task["instruction"]
        or contract.get("id") != "nano-v1"
        or not _sha256(contract.get("contract_set_sha256"))
        or not isinstance(contract.get("profile_id"), str)
        or not contract["profile_id"]
        or provider
        != {
            "kind": "xai",
            "model": "grok-4.5",
            "max_turns": 64,
            "retry_max": 0,
        }
    ):
        raise CandidateError(code)
    if schema == "nano-run-spec-alpha-2":
        try:
            validate_git_history_capability(
                task.get("git_history_capability"),
                str(task["instruction"]),
                str(task["digest"]),
            )
        except ValueError as error:
            raise CandidateError(code) from error
    return row


def _validate_dispatch(
    manifest: Mapping[str, object],
) -> tuple[Mapping[str, object], ...]:
    code = "candidate_dispatch_invalid"
    _exact_keys(manifest, _DISPATCH_KEYS, code)
    specs = manifest.get("run_specs")
    job_id = manifest.get("job_id")
    if (
        manifest.get("schema_version") != "nano-harbor-dispatch-v1"
        or manifest.get("harbor_version") != HARBOR_VERSION
        or manifest.get("retry_max") != 0
        or manifest.get("n_attempts") != 1
        or not isinstance(job_id, str)
        or not job_id
        or not isinstance(specs, list)
        or not specs
    ):
        raise CandidateError(code)
    rows = tuple(_validate_spec(spec, job_id, code) for spec in specs)
    task_ids = [str(row["task"]["id"]) for row in rows]  # type: ignore[index]
    trial_ids = [str(row["trial_id"]) for row in rows]
    if len(set(task_ids)) != len(rows) or len(set(trial_ids)) != len(rows):
        raise CandidateError(code)
    return tuple(sorted(rows, key=lambda row: str(row["task"]["id"])))  # type: ignore[index]


def _validate_job_config(
    value: object,
    task_ids: tuple[str, ...],
) -> Mapping[str, object]:
    code = "candidate_job_config_override"
    config = _mapping(value, code)
    _exact_keys(config, _JOB_CONFIG_KEYS, code)
    agents = config.get("agents")
    datasets = config.get("datasets")
    if (
        config.get("job_name") != "nano-tb21-baseline"
        or not _absolute_path_string(config.get("jobs_dir"))
        or config.get("n_concurrent_trials") != 2
        or config.get("quiet") is not True
        or not isinstance(agents, list)
        or len(agents) != 1
        or not isinstance(datasets, list)
        or len(datasets) != 1
    ):
        raise CandidateError(code)
    agent = _mapping(agents[0], code)
    dataset = _mapping(datasets[0], code)
    _exact_keys(agent, _JOB_AGENT_KEYS, code)
    _exact_keys(dataset, _JOB_DATASET_KEYS, code)
    if agent != {
        "name": "nano-grok-build",
        "import_path": "nano_grok_build.adapter.harbor:NanoGrokBuildAgent",
        "model_name": "xai/grok-4.5",
        "kwargs": {"reasoning_effort": "high"},
    } or dataset != {
        "name": tb21.TB21_DATASET,
        "ref": tb21.TB21_DATASET_REF,
        "task_names": list(task_ids),
    }:
        raise CandidateError(code)
    return {
        "job_name": config["job_name"],
        "n_concurrent_trials": config["n_concurrent_trials"],
        "quiet": config["quiet"],
        "agents": agents,
        "datasets": datasets,
    }


def _validate_lock(
    value: object,
    specs: Sequence[Mapping[str, object]],
) -> tuple[Mapping[str, object], Mapping[str, str]]:
    code = "candidate_harbor_lock_invalid"
    lock = _mapping(value, code)
    _exact_keys(lock, _LOCK_KEYS, code)
    harbor = _mapping(lock.get("harbor"), code)
    retry = _mapping(lock.get("retry"), code)
    _exact_keys(harbor, _LOCK_HARBOR_KEYS, code)
    _exact_keys(retry, _LOCK_RETRY_KEYS, code)
    if retry.get("max_retries") != 0:
        raise CandidateError("harbor_retry_override")
    if (
        lock.get("schema_version") != 2
        or not isinstance(lock.get("created_at"), str)
        or harbor
        != {
            "version": HARBOR_VERSION,
            "git_commit_hash": tb21.HARBOR_COMMIT,
            "is_editable": True,
        }
        or lock.get("n_concurrent_trials") != 2
        or not isinstance(retry.get("exclude_exceptions"), list)
        or retry.get("wait_multiplier") != 1.0
        or retry.get("min_wait_sec") != 1.0
        or retry.get("max_wait_sec") != 60.0
        or not isinstance(lock.get("trials"), list)
        or len(lock["trials"]) != len(specs)
    ):
        raise CandidateError(code)
    expected_by_trial = {str(spec["trial_id"]): spec for spec in specs}
    roots: dict[str, str] | None = None
    task_package_digests: dict[str, str] = {}
    seen: set[str] = set()
    for raw_trial in lock["trials"]:
        trial = _mapping(raw_trial, code)
        _exact_keys(trial, _LOCK_TRIAL_KEYS, code)
        task = _mapping(trial.get("task"), code)
        agent = _mapping(trial.get("agent"), code)
        environment = _mapping(trial.get("environment"), code)
        verifier = _mapping(trial.get("verifier"), code)
        _exact_keys(task, _LOCK_TASK_KEYS, code)
        _exact_keys(agent, _LOCK_AGENT_KEYS, code)
        _exact_keys(environment, _LOCK_ENVIRONMENT_KEYS, code)
        _exact_keys(verifier, {"disable"}, code)
        kwargs = _mapping(agent.get("kwargs"), code)
        _exact_keys(kwargs, _LOCK_AGENT_KWARGS, code)
        spec = _mapping(kwargs.get("run_spec"), code)
        trial_id = str(spec.get("trial_id", ""))
        expected = expected_by_trial.get(trial_id)
        if (
            expected is None
            or spec != expected
            or trial_id in seen
            or trial.get("schema_version") != 1
            or trial.get("install_only") is not False
            or trial.get("timeout_multiplier") != 1.0
            or trial.get("skills") != []
            or set(task) != _LOCK_TASK_KEYS
            or task.get("name") != expected["task"]["id"]  # type: ignore[index]
            or task.get("type") != "package"
            or not isinstance(task.get("digest"), str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", str(task["digest"])) is None
            or task.get("source") != tb21.TB21_DATASET
            or agent.get("name") != "nano-grok-build"
            or agent.get("import_path")
            != "nano_grok_build.adapter.harbor:NanoGrokBuildAgent"
            or agent.get("model_name") != "xai/grok-4.5"
            or agent.get("skills") != []
            or agent.get("resume_trajectory") is not False
            or agent.get("extra_allowed_hosts") != []
            or agent.get("mcp_servers") != []
            or kwargs.get("provider_launch") != {"kind": "xai"}
            or kwargs.get("deadline_mode") != "harbor-root-v1"
            or kwargs.get("reasoning_effort") != "high"
            or not _absolute_path_string(kwargs.get("binary_path"))
            or not _absolute_path_string(kwargs.get("contract_dir"))
            or environment
            != {
                "type": "docker",
                "force_build": False,
                "delete": True,
                "cpu_enforcement_policy": "auto",
                "memory_enforcement_policy": "auto",
                "extra_docker_compose": [],
                "kwargs": {},
                "extra_allowed_hosts": [],
            }
            or verifier != {"disable": False}
        ):
            raise CandidateError(code)
        selected_roots = {
            "binary_path": str(kwargs["binary_path"]),
            "contract_dir": str(kwargs["contract_dir"]),
        }
        if roots is None:
            roots = selected_roots
        elif roots != selected_roots:
            raise CandidateError("mixed_candidate_config_roots")
        task_package_digests[str(expected["task"]["id"])] = str(task["digest"])
        seen.add(trial_id)
    if seen != set(expected_by_trial) or roots is None:
        raise CandidateError(code)
    return {
        "schema_version": lock["schema_version"],
        "harbor": harbor,
        "n_concurrent_trials": lock["n_concurrent_trials"],
        "retry": retry,
        "task_package_digests": dict(sorted(task_package_digests.items())),
    }, roots


def _validate_cohort(
    manifest: Mapping[str, object],
    specs: Sequence[Mapping[str, object]],
    official_checksums: Mapping[str, str],
) -> tuple[Mapping[str, object], Mapping[str, object]]:
    code = "candidate_cohort_invalid"
    observed_keys = set(manifest)
    if observed_keys not in {
        frozenset(_COHORT_BASE_KEYS),
        frozenset(_COHORT_BASE_KEYS | _COHORT_CAPABILITY_KEYS),
    }:
        raise CandidateError(code)
    runtime = _mapping(manifest.get("runtime"), code)
    _exact_keys(runtime, _COHORT_RUNTIME_KEYS, code)
    tasks = manifest.get("tasks")
    if (
        manifest.get("schema_version") != tb21.COHORT_SCHEMA
        or manifest.get("dataset") != tb21.TB21_DATASET
        or manifest.get("dataset_ref") != tb21.TB21_DATASET_REF
        or manifest.get("source_commit") != tb21.TB21_SOURCE_COMMIT
        or manifest.get("harbor_commit") != tb21.HARBOR_COMMIT
        or manifest.get("n_attempts") != 1
        or manifest.get("retry_max") != 0
        or manifest.get("concurrency") != 2
        or manifest.get("active_tools") != list(tb21.ACTIVE_TOOLS)
        or not isinstance(manifest.get("job_id"), str)
        or not isinstance(manifest.get("job_name"), str)
        or not isinstance(tasks, list)
        or len(tasks) != len(specs)
        or _GIT_SHA.fullmatch(str(runtime.get("git_head", ""))) is None
        or not all(
            _sha256(runtime.get(field))
            for field in (
                "source_sha256",
                "binary_sha256",
                "contract_set_sha256",
            )
        )
        or runtime.get("model") != "grok-4.5"
        or runtime.get("max_provider_turns") != 64
        or not isinstance(runtime.get("profile_id"), str)
        or not runtime["profile_id"]
    ):
        raise CandidateError(code)
    if observed_keys == _COHORT_BASE_KEYS | _COHORT_CAPABILITY_KEYS and (
        not isinstance(manifest.get("capability_capture_state"), str)
        or not _sha256(manifest.get("capability_manifest_sha256"))
    ):
        raise CandidateError(code)
    specs_by_task = {str(spec["task"]["id"]): spec for spec in specs}  # type: ignore[index]
    resources: dict[str, object] = {}
    seen: set[str] = set()
    for raw_task in tasks:
        task = _mapping(raw_task, code)
        _exact_keys(task, _COHORT_TASK_KEYS, code)
        task_id = str(task.get("task_id", ""))
        spec = specs_by_task.get(task_id)
        resource = _mapping(task.get("resources"), code)
        _exact_keys(resource, _RESOURCE_KEYS, code)
        if (
            spec is None
            or task_id in seen
            or official_checksums.get(task_id) != task.get("task_digest")
            or spec["task"]["digest"] != task.get("task_digest")  # type: ignore[index]
            or task.get("trial_id") != spec.get("trial_id")
            or task.get("run_spec_sha256") != tb21.rust_run_spec_sha256(spec)
            or not _sha256(task.get("source_task_digest"))
            or not _sha256(task.get("source_sha256"))
            or not isinstance(resource.get("docker_image"), str)
            or not resource["docker_image"]
            or not _positive_int(resource.get("cpus"))
            or not _positive_int(resource.get("memory_mb"))
            or not _positive_int(resource.get("storage_mb"))
            or not _nonnegative_int(resource.get("gpus"))
        ):
            if spec is not None and official_checksums.get(task_id) != task.get(
                "task_digest"
            ):
                raise CandidateError("official_task_digest_mismatch")
            raise CandidateError(code)
        resources[task_id] = resource
        seen.add(task_id)
    if seen != set(specs_by_task):
        raise CandidateError(code)
    contract_ids = {str(spec["contract"]["id"]) for spec in specs}  # type: ignore[index]
    contract_hashes = {
        str(spec["contract"]["contract_set_sha256"])
        for spec in specs  # type: ignore[index]
    }
    profiles = {str(spec["contract"]["profile_id"]) for spec in specs}  # type: ignore[index]
    if (
        contract_ids != {"nano-v1"}
        or contract_hashes != {str(runtime["contract_set_sha256"])}
        or profiles != {str(runtime["profile_id"])}
    ):
        raise CandidateError("mixed_candidate_runtime_identity")
    identity = {
        "dataset": manifest["dataset"],
        "dataset_ref": manifest["dataset_ref"],
        "source_commit": manifest["source_commit"],
        "harbor_commit": manifest["harbor_commit"],
        "active_tools": manifest["active_tools"],
        "runtime": runtime,
        "resources": resources,
        "agent_timeout_sec": {
            str(spec["task"]["id"]): int(spec["agent_timeout_sec"]) for spec in specs
        },
    }
    return identity, resources


def _read_rows(path: Path) -> tuple[tuple[dict[str, object], ...], bytes]:
    raw = _read_regular(path, "candidate_rows_invalid")
    if not raw or not raw.endswith(b"\n"):
        raise CandidateError("candidate_rows_invalid")
    rows: list[dict[str, object]] = []
    for line in raw.splitlines(keepends=True):
        value = _strict_json_bytes(line, "candidate_rows_invalid")
        row = dict(_mapping(value, "candidate_rows_invalid"))
        if line != _canonical(row) or not _ROW_REQUIRED_KEYS.issubset(row):
            raise CandidateError("candidate_rows_invalid")
        rows.append(row)
    return tuple(rows), raw


def _reward_from_result(result: Mapping[str, object]) -> float | None:
    verifier = result.get("verifier_result")
    if verifier is None:
        return None
    verifier_mapping = _mapping(verifier, "candidate_trial_result_invalid")
    rewards = _mapping(
        verifier_mapping.get("rewards"), "candidate_trial_result_invalid"
    )
    reward = rewards.get("reward")
    if reward is None:
        return None
    if (
        isinstance(reward, bool)
        or not isinstance(reward, int | float)
        or not math.isfinite(float(reward))
        or float(reward) < 0
        or float(reward) > 1
    ):
        raise CandidateError("candidate_trial_result_invalid")
    return float(reward)


def _validate_row(
    row: dict[str, object],
    spec: Mapping[str, object],
) -> None:
    code = "candidate_row_invalid"
    schema = row.get("schema_version")
    if schema not in {tb21.ROW_SCHEMA_V6, tb21.ROW_SCHEMA}:
        raise CandidateError(code)
    v7 = schema == tb21.ROW_SCHEMA
    reward = row.get("reward")
    if reward is not None and (
        isinstance(reward, bool)
        or not isinstance(reward, int | float)
        or not math.isfinite(float(reward))
        or not 0 <= float(reward) <= 1
    ):
        raise CandidateError(code)
    booleans = (
        "raw_score_valid",
        "collector_pass",
        "strict_pass",
        "reliable",
        "measurement_complete",
        "success_artifact_valid",
        "diagnostic_package_valid",
        "workspace_snapshot_complete",
        "usage_receipt_valid",
        "terminal_record_valid",
        "result_binding_valid",
        "contamination_signal",
        "submission_integrity_blocking",
        "git_history_evidence_complete",
        "git_history_submission_blocking",
        "cost_coverage",
    )
    if v7:
        booleans += ("direct_atif_valid", "rewarded_atif_valid")
    elif "direct_atif_valid" in row or "rewarded_atif_valid" in row:
        raise CandidateError(code)
    counts = (
        "provider_calls_requested",
        "provider_calls_completed",
        "provider_calls_failed",
        "provider_calls_in_flight",
        "provider_calls_usage_covered",
        "usage_call_count",
        "provider_cost_ticks",
        "provider_cost_ticks_covered_calls",
    )
    signals = row.get("contamination_signals")
    protected_counts = row.get("protected_target_counts")
    protected_findings = row.get("protected_target_findings")
    blocking_count = (
        sum(
            tb21.protected_target.submission_blocking_finding(finding)
            for finding in protected_findings
        )
        if isinstance(protected_findings, list)
        else -1
    )
    warning_count = (
        len(protected_findings) - blocking_count
        if isinstance(protected_findings, list) and blocking_count >= 0
        else -1
    )
    git_findings = row.get("git_history_findings")
    git_counts = row.get("git_history_counts")
    git_blocking_count = (
        sum(
            tb21.git_history_audit.submission_blocking_finding(finding)
            for finding in git_findings
        )
        if isinstance(git_findings, list)
        else -1
    )
    exception = row.get("exception")
    runtime_result_contradiction = bool(
        spec.get("schema_version") == "nano-run-spec-alpha-2"
        and row.get("runtime_entry_state") == "not_started"
        and reward is not None
        and float(reward) > 0
    )
    requested = row.get("provider_calls_requested")
    completed = row.get("provider_calls_completed")
    failed = row.get("provider_calls_failed")
    in_flight = row.get("provider_calls_in_flight")
    if (
        row.get("task") != spec["task"]["id"]  # type: ignore[index]
        or row.get("trial") != spec.get("trial_id")
        or row.get("digest") != spec["task"]["digest"]  # type: ignore[index]
        or any(not isinstance(row.get(field), bool) for field in booleans)
        or any(not _nonnegative_int(row.get(field)) for field in counts)
        or not isinstance(signals, list)
        or any(not isinstance(signal, str) or not signal for signal in signals)
        or row.get("contamination_audit_state")
        not in {"available", "not_applicable", "unavailable", "invalid"}
        or row.get("contamination_signal") != bool(signals)
        or row.get("protected_target_audit_schema")
        != tb21.protected_target.AUDIT_SCHEMA
        or row.get("protected_target_policy_schema")
        != tb21.protected_target.POLICY_SCHEMA
        or row.get("protected_target_policy_sha256")
        != tb21.protected_target.POLICY_SHA256
        or not isinstance(protected_counts, dict)
        or set(protected_counts)
        != {
            "findings",
            "strong",
            "attempted",
            "access_blocked",
            "dispatched",
            "bytes_returned",
            "causal_benefit",
        }
        or any(not _nonnegative_int(value) for value in protected_counts.values())
        or not isinstance(protected_findings, list)
        or protected_counts.get("findings") != len(protected_findings)
        or row.get("contamination_signal") != bool(protected_findings)
        or not _nonnegative_int(row.get("submission_integrity_blocking_count"))
        or not _nonnegative_int(row.get("submission_integrity_warning_count"))
        or row.get("submission_integrity_blocking_count") != blocking_count
        or row.get("submission_integrity_warning_count") != warning_count
        or row.get("submission_integrity_blocking")
        != bool(
            row.get("contamination_audit_state") not in {"available", "not_applicable"}
            or blocking_count
            or runtime_result_contradiction
        )
        or row.get("git_history_audit_schema") != tb21.git_history_audit.AUDIT_SCHEMA
        or row.get("git_history_finding_schema")
        != tb21.git_history_audit.FINDING_SCHEMA
        or row.get("git_history_audit_state")
        not in {"available", "not_applicable", "unavailable", "invalid"}
        or (
            row.get("git_history_required") is not None
            and not isinstance(row.get("git_history_required"), bool)
        )
        or not isinstance(git_findings, list)
        or not isinstance(git_counts, dict)
        or set(git_counts)
        != {
            "findings",
            "attempted",
            "dispatched",
            "bytes_returned",
            "causal_reuse",
            "warnings",
            "blocking",
        }
        or any(not _nonnegative_int(value) for value in git_counts.values())
        or git_counts.get("findings") != len(git_findings)
        or git_counts.get("blocking") != git_blocking_count
        or row.get("git_history_submission_blocking")
        != (
            False
            if row.get("git_history_audit_state") == "not_applicable"
            else bool(
                row.get("git_history_audit_state") != "available"
                or row.get("git_history_required") is None
                or not row.get("git_history_evidence_complete")
                or git_blocking_count
            )
        )
        or (exception is not None and not isinstance(exception, dict))
        or (
            isinstance(exception, dict)
            and (
                set(exception) != {"type", "message"}
                or not all(isinstance(exception.get(key), str) for key in exception)
            )
        )
        or not isinstance(row.get("failure_bucket"), str)
        or (
            (row.get("failure_code") == "runtime_result_contradiction")
            is not runtime_result_contradiction
        )
        or (
            runtime_result_contradiction
            and (
                row.get("failure_bucket") != "environment_infra"
                or row.get("failure_phase") != "runtime"
                or row.get("failure_recoverability") != "fatal"
            )
        )
        or row.get("raw_score_valid") != (reward is not None)
        or row.get("collector_pass")
        != bool(row.get("raw_score_valid") and reward is not None and reward > 0)
        or (
            v7
            and row.get("rewarded_atif_valid") is True
            and not (row.get("collector_pass") and row.get("direct_atif_valid"))
        )
        or (v7 and row.get("strict_pass") != row.get("rewarded_atif_valid"))
        or (not v7 and row.get("strict_pass") and not row.get("collector_pass"))
        or (not v7 and row.get("strict_pass") and not row.get("reliable"))
        or requested != completed + failed + in_flight
        or row.get("provider_calls_usage_covered", 0) > requested
        or row.get("provider_cost_ticks_covered_calls", 0)
        > row.get("usage_call_count", 0)
        or (
            not isinstance(row.get("provider_cost_usd_observed"), int | float)
            or isinstance(row.get("provider_cost_usd_observed"), bool)
            or float(row["provider_cost_usd_observed"]) < 0
        )
        or (
            row.get("cost_usd") is not None
            and (
                not isinstance(row.get("cost_usd"), int | float)
                or isinstance(row.get("cost_usd"), bool)
                or float(row["cost_usd"]) < 0
            )
        )
    ):
        raise CandidateError(code)


def _eligible_rewarded_atif(
    trial_dir: Path,
    spec: Mapping[str, object],
    row: Mapping[str, object],
    evidence: list[dict[str, str]],
) -> bool:
    if (
        row.get("publication_kind") != "success_atif"
        or row.get("runtime_terminal_status") != "success"
        or row.get("runtime_terminal_phase") is not None
        or row.get("runtime_terminal_code") != "completed"
        or row.get("diagnostic_package_valid") is not True
        or row.get("terminal_record_valid") is not True
    ):
        return False
    marker_path = trial_dir / "agent" / "agent-run.json"
    try:
        artifacts = tb21._artifact_evidence(trial_dir, spec)
        if (
            not artifacts.publication_valid
            or not artifacts.trajectory_valid
            or not artifacts.diagnostic_valid
            or artifacts.publication_kind != "success_atif"
            or artifacts.terminal_status != "success"
            or artifacts.terminal_phase is not None
            or artifacts.terminal_code != "completed"
        ):
            return False
        marker_value, marker_raw = _read_json(marker_path, "rewarded_atif_invalid")
        marker = _mapping(marker_value, "rewarded_atif_invalid")
        schema = marker.get("schema_version")
        if schema == "nano-agent-run-v2":
            required = tb21._V2_MARKER_REQUIRED_KEYS
        elif schema == "nano-agent-run-v3":
            required = tb21._V3_MARKER_REQUIRED_KEYS
        else:
            return False
        marker_sha_fields = {
            "events_sha256",
            "trajectory_sha256",
            "usage_receipt_sha256",
        }
        if schema == "nano-agent-run-v3":
            marker_sha_fields.add("deadline_receipt_sha256")
        marker_sha_fields.update(
            field
            for field in (
                "background_manifest_sha256",
                "workspace_receipt_sha256",
            )
            if field in marker
        )
        if (
            marker_raw != _canonical(marker)
            or not required.issubset(marker)
            or not (set(marker) - required).issubset(tb21._V2_MARKER_OPTIONAL_KEYS)
            or any(not _sha256(marker.get(field)) for field in marker_sha_fields)
            or (
                ("background_manifest_sha256" in marker)
                != ("background_task_count" in marker)
            )
            or marker.get("publication_kind") != "success_atif"
            or marker.get("run_id") != spec.get("run_id")
            or marker.get("trial_id") != spec.get("trial_id")
            or marker.get("attempt_id") != "attempt-0"
            or marker.get("run_spec_sha256") != tb21.rust_run_spec_sha256(spec)
            or marker.get("terminal_status") != "success"
            or marker.get("terminal_phase") is not None
            or marker.get("terminal_code") != "completed"
            or marker.get("trajectory_path") != "trajectory.json"
            or not _sha256(marker.get("trajectory_sha256"))
        ):
            return False
        trajectory_path = marker_path.parent / "trajectory.json"
        trajectory_value, trajectory_raw = _read_json(
            trajectory_path, "rewarded_atif_invalid"
        )
        trajectory = _mapping(trajectory_value, "rewarded_atif_invalid")
        if (
            trajectory_raw != _canonical(trajectory)
            or hashlib.sha256(trajectory_raw).hexdigest()
            != marker.get("trajectory_sha256")
            or trajectory.get("session_id") != spec.get("run_id")
        ):
            return False
        extra = trajectory.get("extra")
        if (
            not isinstance(extra, dict)
            or extra.get("trial_id") != spec.get("trial_id")
            or extra.get("attempt_id") != "attempt-0"
            or extra.get("run_spec_sha256") != tb21.rust_run_spec_sha256(spec)
            or extra.get("events_sha256") != marker.get("events_sha256")
        ):
            return False
        validate_minimal_trajectory(trajectory)
        validate_with_pinned_harbor(trajectory)
        evidence.extend(
            [
                {
                    "path": f"{spec['trial_id']}/agent/agent-run.json",
                    "sha256": hashlib.sha256(marker_raw).hexdigest(),
                },
                {
                    "path": f"{spec['trial_id']}/agent/trajectory.json",
                    "sha256": hashlib.sha256(trajectory_raw).hexdigest(),
                },
            ]
        )
        return True
    except (CandidateError, AtifError, KeyError, TypeError, ValueError):
        return False


def _safe_trial_dir(job_dir: Path, trial_id: str, *, required: bool) -> Path:
    """Return one direct, non-symlink trial directory beneath the job root."""

    if _TRIAL_ID.fullmatch(trial_id) is None:
        raise CandidateError("candidate_trial_path_invalid")
    trial_dir = job_dir / trial_id
    if not required and not trial_dir.exists() and not trial_dir.is_symlink():
        return trial_dir
    try:
        metadata = trial_dir.lstat()
        resolved = trial_dir.resolve(strict=True)
    except OSError as error:
        raise CandidateError("candidate_trial_path_invalid") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or resolved.parent != job_dir
        or resolved != trial_dir
    ):
        raise CandidateError("candidate_trial_path_invalid")
    return trial_dir


def _validate_row_evidence(
    trial_dir: Path,
    spec: Mapping[str, object],
    row: Mapping[str, object],
    *,
    official_result_classification: str,
    runtime_entry_state: str,
    runtime_result_contradiction: bool,
) -> None:
    """Recompute release-critical row projections from immutable artifacts."""

    artifacts = tb21._artifact_evidence(trial_dir, spec)
    expected = {
        "publication_kind": artifacts.publication_kind,
        "success_artifact_valid": artifacts.success_valid,
        "diagnostic_package_valid": artifacts.diagnostic_valid,
        "workspace_snapshot_complete": artifacts.workspace_snapshot_complete,
        "usage_receipt_valid": artifacts.usage_receipt_valid,
        "terminal_record_valid": artifacts.terminal_status is not None,
        "runtime_terminal_status": artifacts.terminal_status,
        "runtime_terminal_phase": artifacts.terminal_phase,
        "runtime_terminal_code": artifacts.terminal_code,
    }
    v7 = row.get("schema_version") == tb21.ROW_SCHEMA
    if v7:
        expected["direct_atif_valid"] = artifacts.direct_atif_valid
    if any(row.get(field) != value for field, value in expected.items()):
        raise CandidateError("candidate_row_artifact_projection_mismatch")
    if (
        (row.get("failure_code") == "runtime_result_contradiction")
        is not runtime_result_contradiction
        or runtime_result_contradiction
        and (
            row.get("failure_bucket") != "environment_infra"
            or row.get("failure_phase") != "runtime"
            or row.get("failure_recoverability") != "fatal"
        )
    ):
        raise CandidateError("candidate_row_runtime_result_projection_mismatch")
    exception_absent = row.get("exception") is None
    expected_reliable = bool(
        row.get("raw_score_valid")
        and exception_absent
        and artifacts.success_valid
        and artifacts.artifacts_valid
        and row.get("result_binding_valid")
        and not runtime_result_contradiction
    )
    expected_strict = bool(row.get("collector_pass") and expected_reliable)
    expected_measurement = bool(
        row.get("result_binding_valid")
        and artifacts.diagnostic_valid
        and artifacts.workspace_snapshot_complete
        and artifacts.usage_receipt_valid
        and artifacts.terminal_status is not None
    )
    if (
        row.get("reliable") is not expected_reliable
        or (not v7 and row.get("strict_pass") is not expected_strict)
        or row.get("measurement_complete") is not expected_measurement
    ):
        raise CandidateError("candidate_row_measurement_projection_mismatch")
    contamination, git_history = tb21._submission_audit_projection(
        trial_dir,
        spec=spec,
        rewarded=bool(row.get("collector_pass")),
        result_classification=official_result_classification,
        runtime_entry_state=runtime_entry_state,
    )
    findings = contamination.get("findings")
    blocking_count = (
        sum(
            tb21.protected_target.submission_blocking_finding(finding)
            for finding in findings
        )
        if isinstance(findings, list)
        else 1
    )
    warning_count = len(findings) - blocking_count if isinstance(findings, list) else 0
    if (
        row.get("contamination_audit_state") != contamination.get("state")
        or row.get("contamination_signals") != contamination.get("signals")
        or row.get("contamination_signal") != bool(contamination.get("findings"))
        or row.get("protected_target_audit_schema")
        != contamination.get("schema_version")
        or row.get("protected_target_policy_schema")
        != contamination.get("policy_schema_version")
        or row.get("protected_target_policy_sha256")
        != contamination.get("policy_sha256")
        or row.get("protected_target_counts") != contamination.get("counts")
        or row.get("protected_target_findings") != contamination.get("findings")
        or row.get("submission_integrity_blocking_count") != blocking_count
        or row.get("submission_integrity_warning_count") != warning_count
        or row.get("submission_integrity_blocking")
        != bool(
            contamination.get("state") not in {"available", "not_applicable"}
            or blocking_count
            or runtime_result_contradiction
        )
        or row.get("git_history_audit_schema") != git_history.get("schema_version")
        or row.get("git_history_finding_schema")
        != git_history.get("finding_schema_version")
        or row.get("git_history_audit_state") != git_history.get("state")
        or row.get("git_history_required") != git_history.get("history_required")
        or row.get("git_history_evidence_complete")
        != git_history.get("evidence_complete")
        or row.get("git_history_findings") != git_history.get("findings")
        or row.get("git_history_counts") != git_history.get("counts")
        or row.get("git_history_submission_blocking")
        != git_history.get("submission_blocking")
    ):
        raise CandidateError("candidate_row_contamination_projection_mismatch")


def _project_interrupted_rows(
    job_dir: Path,
    specs: Sequence[Mapping[str, object]],
    cohort: Mapping[str, object],
    terminalization: Mapping[str, object],
) -> tuple[dict[str, object], ...]:
    """Project the existing collector rows in memory; never persist them."""

    terminal_trials = terminalization.get("trials")
    cohort_tasks = cohort.get("tasks")
    if not isinstance(terminal_trials, list) or not isinstance(cohort_tasks, list):
        raise CandidateError("candidate_interruption_receipt_invalid")
    states = {
        str(row["trial_id"]): str(row["state"])
        for raw in terminal_trials
        for row in (_mapping(raw, "candidate_interruption_receipt_invalid"),)
    }
    sources = {
        str(row["task_id"]): row
        for raw in cohort_tasks
        for row in (_mapping(raw, "candidate_cohort_invalid"),)
    }
    candidates = tb21._scan_results(job_dir)
    expected_trials = {str(spec["trial_id"]) for spec in specs}
    by_trial: dict[str, list[object]] = {}
    for result in candidates:
        if result.trial_name not in expected_trials:
            raise CandidateError("candidate_trial_result_invalid")
        by_trial.setdefault(result.trial_name, []).append(result)
    rows: list[dict[str, object]] = []
    try:
        for spec in specs:
            trial_id = str(spec["trial_id"])
            state = states.get(trial_id)
            if state not in {"terminal", "incomplete", "not_started"}:
                raise CandidateError("candidate_interruption_receipt_invalid")
            if state != "not_started":
                _safe_trial_dir(job_dir, trial_id, required=True)
            artifacts = tb21._artifact_evidence(job_dir / trial_id, spec)
            projected = tb21._row(
                job_dir=job_dir,
                spec=spec,
                candidates=tuple(
                    sorted(
                        by_trial.get(trial_id, []),
                        key=lambda candidate: str(candidate.path),
                    )
                ),
                pricing=None,
                source=sources.get(str(spec["task"]["id"])),  # type: ignore[index]
                artifacts=artifacts,
                interruption_state=state,
                interruption_reason=str(terminalization["reason"]),
            )
            rows.append(dict(projected))
    except tb21.TB21Error as error:
        raise CandidateError("candidate_interruption_projection_invalid") from error
    return tuple(rows)


def _load_job(
    job_path: Path,
    official_checksums: Mapping[str, str],
) -> _LoadedJob:
    try:
        if job_path.is_symlink() or not job_path.is_dir():
            raise OSError
        job_dir = job_path.resolve(strict=True)
    except OSError as error:
        raise CandidateError("candidate_job_directory_invalid") from error
    evidence: list[dict[str, str]] = []

    def capture(relative: str, raw: bytes) -> None:
        evidence.append({"path": relative, "sha256": hashlib.sha256(raw).hexdigest()})

    dispatch, dispatch_raw = _load_envelope(
        job_dir / "nano-dispatch.json",
        "nano-harbor-dispatch-v1",
        "candidate_dispatch_invalid",
    )
    capture("nano-dispatch.json", dispatch_raw)
    specs = _validate_dispatch(dispatch)
    task_ids = tuple(str(spec["task"]["id"]) for spec in specs)  # type: ignore[index]
    for spec in specs:
        task_id = str(spec["task"]["id"])  # type: ignore[index]
        if official_checksums.get(task_id) != spec["task"]["digest"]:  # type: ignore[index]
            raise CandidateError("official_task_digest_mismatch")

    cohort, cohort_raw = _load_envelope(
        job_dir / "nano-tb21-cohort.json",
        tb21.COHORT_SCHEMA,
        "candidate_cohort_invalid",
    )
    capture("nano-tb21-cohort.json", cohort_raw)
    cohort_identity, _resources = _validate_cohort(cohort, specs, official_checksums)
    if cohort.get("job_id") != dispatch.get("job_id"):
        raise CandidateError("candidate_cohort_invalid")
    if _COHORT_CAPABILITY_KEYS.issubset(cohort):
        capability_value, capability_raw = _read_json(
            job_dir / "nano-capability-manifest.json",
            "candidate_capability_manifest_invalid",
        )
        capability = _mapping(capability_value, "candidate_capability_manifest_invalid")
        if (
            capability_raw != _canonical(capability)
            or not tb21.validate_capability_manifest(capability)
            or hashlib.sha256(capability_raw).hexdigest()
            != cohort.get("capability_manifest_sha256")
            or capability.get("capture_state") != cohort.get("capability_capture_state")
        ):
            raise CandidateError("candidate_capability_manifest_invalid")
        capture("nano-capability-manifest.json", capability_raw)

    config_value, config_raw = _read_json(
        job_dir / "config.json", "candidate_job_config_override"
    )
    capture("config.json", config_raw)
    config_identity = _validate_job_config(config_value, task_ids)

    lock_value, lock_raw = _read_json(
        job_dir / "lock.json", "candidate_harbor_lock_invalid"
    )
    capture("lock.json", lock_raw)
    lock_identity, roots = _validate_lock(lock_value, specs)

    job_result_value, job_result_raw = _read_json(
        job_dir / "result.json", "candidate_job_result_invalid"
    )
    capture("result.json", job_result_raw)
    job_result = _mapping(job_result_value, "candidate_job_result_invalid")
    stats = _mapping(job_result.get("stats"), "candidate_job_result_invalid")
    if (
        job_result.get("n_total_trials") != len(specs)
        or stats.get("n_retries") != 0
        or not all(
            _nonnegative_int(stats.get(field))
            for field in (
                "n_completed_trials",
                "n_errored_trials",
                "n_running_trials",
                "n_pending_trials",
                "n_cancelled_trials",
            )
        )
        or stats.get("n_running_trials") != 0
    ):
        if stats.get("n_retries") != 0:
            raise CandidateError("harbor_retry_override")
        raise CandidateError("candidate_job_result_invalid")

    terminalization: Mapping[str, object] | None = None
    terminal_states: dict[str, str] = {}
    projected_interruption_rows = 0
    if job_result.get("finished_at") is None:
        terminal_value, terminal_raw = _read_json(
            job_dir / "nano-terminalization.json",
            "candidate_interruption_receipt_invalid",
        )
        capture("nano-terminalization.json", terminal_raw)
        terminalization = _mapping(
            terminal_value, "candidate_interruption_receipt_invalid"
        )
        if terminal_raw != _canonical(terminalization):
            raise CandidateError("candidate_interruption_receipt_invalid")
        try:
            validated_terminalization = tb21._validate_terminalization(
                job_dir,
                specs,
                pricing=None,
            )
        except tb21.TB21Error as error:
            raise CandidateError("candidate_interruption_receipt_invalid") from error
        if validated_terminalization != terminalization:
            raise CandidateError("candidate_interruption_receipt_invalid")
        terminal_trials = terminalization.get("trials")
        if (
            terminalization.get("schema_version")
            != tb21.INTERRUPTION_TERMINALIZATION_SCHEMA
            or terminalization.get("status") != "interrupted"
            or terminalization.get("reason")
            not in {"operator_interrupted", "runner_exception"}
            or not isinstance(terminal_trials, list)
            or len(terminal_trials) != len(specs)
        ):
            raise CandidateError("candidate_interruption_receipt_invalid")
        for raw_trial in terminal_trials:
            trial = _mapping(raw_trial, "candidate_interruption_receipt_invalid")
            trial_id = trial.get("trial_id")
            state = trial.get("state")
            if (
                not isinstance(trial_id, str)
                or state not in {"terminal", "incomplete", "not_started"}
                or trial_id in terminal_states
            ):
                raise CandidateError("candidate_interruption_receipt_invalid")
            terminal_states[trial_id] = str(state)
        if set(terminal_states) != {str(spec["trial_id"]) for spec in specs}:
            raise CandidateError("candidate_interruption_receipt_invalid")
    elif (
        stats.get("n_completed_trials") != len(specs)
        or stats.get("n_pending_trials") != 0
        or stats.get("n_cancelled_trials") != 0
    ):
        raise CandidateError("candidate_job_result_invalid")

    rows_path = job_dir / "rows.jsonl"
    if rows_path.exists() or rows_path.is_symlink():
        rows, rows_raw = _read_rows(rows_path)
        capture("rows.jsonl", rows_raw)
    elif terminalization is not None:
        rows = _project_interrupted_rows(job_dir, specs, cohort, terminalization)
        projected_interruption_rows = len(rows)
    else:
        raise CandidateError("candidate_rows_invalid")
    if len(rows) != len(specs):
        raise CandidateError("candidate_row_inventory_invalid")
    row_schemas = {row.get("schema_version") for row in rows}
    if len(row_schemas) != 1 or not row_schemas.issubset(
        {tb21.ROW_SCHEMA_V6, tb21.ROW_SCHEMA}
    ):
        raise CandidateError("candidate_row_schema_mismatch")
    row_schema = next(iter(row_schemas))
    summary_path = job_dir / "summary.json"
    summary: Mapping[str, object] | None = None
    if summary_path.exists() or summary_path.is_symlink():
        summary_value, summary_raw = _read_json(
            summary_path, "candidate_collector_summary_invalid"
        )
        summary = _mapping(summary_value, "candidate_collector_summary_invalid")
        capture("summary.json", summary_raw)
        expected_summary_schema = {
            tb21.ROW_SCHEMA_V6: tb21.SUMMARY_SCHEMA_V6,
            tb21.ROW_SCHEMA: tb21.SUMMARY_SCHEMA,
        }[row_schema]
        if (
            summary_raw != _canonical(summary)
            or summary.get("schema_version") != expected_summary_schema
        ):
            raise CandidateError("candidate_row_schema_mismatch")
    rows_by_trial = {str(row.get("trial")): row for row in rows}
    if len(rows_by_trial) != len(rows):
        raise CandidateError("candidate_row_inventory_invalid")

    completed = 0
    stopped = 0
    terminal_result_count = 0
    ordered_rows: list[dict[str, object]] = []
    for spec in specs:
        trial_id = str(spec["trial_id"])
        row = rows_by_trial.get(trial_id)
        if row is None:
            raise CandidateError("candidate_row_inventory_invalid")
        _validate_row(row, spec)
        state = terminal_states.get(trial_id)
        if state in {"not_started", "incomplete"}:
            if row.get("interruption_state") != state:
                raise CandidateError("candidate_interruption_receipt_invalid")
            stopped += 1
            ordered_rows.append(row)
            continue
        if terminalization is not None and row.get("interruption_state") != state:
            raise CandidateError("candidate_interruption_receipt_invalid")
        trial_dir = _safe_trial_dir(job_dir, trial_id, required=True)
        result_path = trial_dir / "result.json"
        result_value, result_raw = _read_json(
            result_path, "candidate_trial_result_invalid"
        )
        capture(f"{trial_id}/result.json", result_raw)
        result = _mapping(result_value, "candidate_trial_result_invalid")
        reward = _reward_from_result(result)
        exception_info = result.get("exception_info")
        exception_projection: dict[str, str] | None = None
        if exception_info is not None:
            exception = _mapping(exception_info, "candidate_trial_result_invalid")
            exception_type = exception.get("exception_type")
            exception_message = exception.get("exception_message")
            if not isinstance(exception_type, str) or not isinstance(
                exception_message, str
            ):
                raise CandidateError("candidate_trial_result_invalid")
            exception_projection = {
                "type": exception_type,
                "message": exception_message,
            }
        if (
            result.get("task_name") != spec["task"]["id"]  # type: ignore[index]
            or result.get("trial_name") != trial_id
            or result.get("task_checksum") != spec["task"]["digest"]  # type: ignore[index]
            or result.get("finished_at") is None
            or row.get("reward") != reward
            or row.get("exception") != exception_projection
            or row.get("result_binding_valid") is not True
        ):
            raise CandidateError("candidate_trial_result_invalid")
        runtime_entry_state: str | None = None
        if spec.get("schema_version") == "nano-run-spec-alpha-2":
            runtime_entry_path = trial_dir / "agent" / RUNTIME_ENTRY_NAME
            try:
                runtime_entry = load_runtime_entry(runtime_entry_path, spec)
                runtime_entry_raw = _read_regular(
                    runtime_entry_path, "candidate_runtime_entry_invalid"
                )
                capture(f"{trial_id}/agent/{RUNTIME_ENTRY_NAME}", runtime_entry_raw)
                if runtime_entry is None:
                    raise CandidateError("candidate_runtime_entry_invalid")
                runtime_entry_state = runtime_entry.state
                if row.get("runtime_entry_state") != runtime_entry.state:
                    raise CandidateError("candidate_runtime_entry_projection_mismatch")
                if runtime_entry.terminalization_path:
                    terminal_raw = _read_regular(
                        trial_dir / "agent" / runtime_entry.terminalization_path,
                        "candidate_runtime_entry_invalid",
                    )
                    capture(
                        f"{trial_id}/agent/{runtime_entry.terminalization_path}",
                        terminal_raw,
                    )
                baseline_raw = _read_regular(
                    trial_dir / "agent" / HISTORY_BASELINE_RECEIPT,
                    "candidate_git_history_receipt_invalid",
                )
                capture(f"{trial_id}/agent/{HISTORY_BASELINE_RECEIPT}", baseline_raw)
            except RuntimeEntryError as error:
                raise CandidateError("candidate_runtime_entry_invalid") from error
        verifier_present = result.get("verifier_result") is not None
        if (verifier_present and reward is None) or (
            not verifier_present and exception_projection is None
        ):
            raise CandidateError("candidate_trial_result_invalid")
        official_result_classification = (
            "errored"
            if not verifier_present
            else "rewarded"
            if reward is not None and reward > 0
            else "zero"
        )
        runtime_result_contradiction = bool(
            runtime_entry_state == "not_started"
            and official_result_classification == "rewarded"
        )
        row["_runtime_result_contradiction"] = runtime_result_contradiction
        _validate_row_evidence(
            trial_dir,
            spec,
            row,
            official_result_classification=official_result_classification,
            runtime_entry_state=runtime_entry_state or "invalid",
            runtime_result_contradiction=runtime_result_contradiction,
        )
        terminal_result_count += 1
        stop_caused_cancellation = bool(
            terminalization is not None
            and terminalization.get("reason") == "operator_interrupted"
            and state == "terminal"
            and exception_projection is not None
            and exception_projection.get("type") == "CancelledError"
        )
        row["_interruption_excluded"] = stop_caused_cancellation
        if stop_caused_cancellation:
            stopped += 1
        else:
            completed += 1
        if reward is not None and reward > 0 and not stop_caused_cancellation:
            row["_atif_eligible"] = bool(
                not runtime_result_contradiction
                and _eligible_rewarded_atif(trial_dir, spec, row, evidence)
            )
        else:
            row["_atif_eligible"] = None
        if row_schema == tb21.ROW_SCHEMA:
            expected_rewarded = row.get("_atif_eligible") is True
            if (
                row.get("rewarded_atif_valid") is not expected_rewarded
                or row.get("strict_pass") is not expected_rewarded
            ):
                raise CandidateError("candidate_row_artifact_projection_mismatch")
        ordered_rows.append(row)

    if int(stats["n_completed_trials"]) != terminal_result_count:
        raise CandidateError("candidate_job_result_invalid")
    if (
        summary is not None
        and terminalization is None
        and row_schema == tb21.ROW_SCHEMA
    ):
        official_numerator = float(
            sum(
                (
                    Decimal(str(row["reward"]))
                    for row in ordered_rows
                    if isinstance(row.get("reward"), int | float)
                    and not isinstance(row.get("reward"), bool)
                ),
                Decimal(0),
            )
        )
        rewarded_rows = [
            row
            for row in ordered_rows
            if isinstance(row.get("reward"), int | float)
            and not isinstance(row.get("reward"), bool)
            and float(row["reward"]) > 0
        ]
        eligible_rows = sum(row.get("_atif_eligible") is True for row in rewarded_rows)
        runtime_result_consistent = not any(
            row.get("_runtime_result_contradiction") is True for row in ordered_rows
        )
        typed_runtime_authority = any(
            spec.get("schema_version") == "nano-run-spec-alpha-2" for spec in specs
        )
        expected_accuracy = {
            "numerator": official_numerator,
            "denominator": len(specs),
            "percent": round(100 * official_numerator / len(specs), 6),
        }
        expected_coverage = {
            "numerator": eligible_rows,
            "denominator": len(rewarded_rows),
            "percent": (
                round(100 * eligible_rows / len(rewarded_rows), 6)
                if rewarded_rows
                else 100.0
            ),
        }
        gates = summary.get("gates")
        if (
            summary.get("collector_accuracy") != expected_accuracy
            or summary.get("rewarded_atif_coverage") != expected_coverage
            or not isinstance(gates, Mapping)
            or gates.get("official_results") is not True
            or gates.get("rewarded_atif") is not (eligible_rows == len(rewarded_rows))
            or typed_runtime_authority
            and gates.get("runtime_result_consistency") is not runtime_result_consistent
        ):
            raise CandidateError("candidate_collector_summary_invalid")
    identity = {
        "cohort": cohort_identity,
        "job_config": config_identity,
        "harbor_lock": lock_identity,
        "candidate_roots": roots,
        "collector_row_schema": row_schema,
    }
    evidence_sha256 = hashlib.sha256(
        _canonical(sorted(evidence, key=lambda item: item["path"]))
    ).hexdigest()
    return _LoadedJob(
        job_id=str(dispatch["job_id"]),
        run_ids=tuple(str(spec["run_id"]) for spec in specs),
        task_ids=task_ids,
        rows=tuple(ordered_rows),
        complete_trials=completed,
        stopped_trials=stopped,
        identity=identity,
        evidence_sha256=evidence_sha256,
        projected_interruption_rows=projected_interruption_rows,
    )


def _metric(
    numerator: int | float, denominator: int, available: bool
) -> dict[str, object]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "percent": round(100 * numerator / denominator, 6)
        if available and denominator
        else None,
        "availability": "available" if available else "unavailable",
    }


def _counter(values: Sequence[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def audit_jobs(
    job_dirs: Sequence[Path],
    *,
    policy: StagePolicy,
    official_checksums: Mapping[str, str],
) -> dict[str, object]:
    """Audit fixed candidate jobs without changing any input artifact."""

    if (
        not policy.task_ids
        or len(policy.task_ids) != len(set(policy.task_ids))
        or policy.expected_jobs <= 0
        or any(official_checksums.get(task_id) is None for task_id in policy.task_ids)
    ):
        raise CandidateError("candidate_policy_invalid")
    resolved = tuple(path.resolve() for path in job_dirs)
    if len(resolved) != len(set(resolved)):
        raise CandidateError("duplicate_candidate_job")
    jobs = tuple(_load_job(path, official_checksums) for path in resolved)
    job_ids = [job.job_id for job in jobs]
    run_ids = [run_id for job in jobs for run_id in job.run_ids]
    if len(job_ids) != len(set(job_ids)) or len(run_ids) != len(set(run_ids)):
        raise CandidateError("duplicate_candidate_job_identity")
    if jobs:
        identity = jobs[0].identity
        if any(job.identity != identity for job in jobs[1:]):
            raise CandidateError("mixed_candidate_runtime_identity")
        candidate_identity_sha256 = hashlib.sha256(_canonical(identity)).hexdigest()
    else:
        identity = None
        candidate_identity_sha256 = None

    violations: list[str] = []
    if len(jobs) != policy.expected_jobs:
        violations.append("job_count_mismatch")
    if any(job.task_ids != policy.task_ids for job in jobs):
        violations.append("task_set_mismatch")
    expected_task_trials = len(policy.task_ids) * policy.expected_jobs
    dispatched = sum(len(job.task_ids) for job in jobs)
    complete_trials = sum(job.complete_trials for job in jobs)
    stopped_trials = sum(job.stopped_trials for job in jobs)
    coverage_complete = bool(
        len(jobs) == policy.expected_jobs
        and all(job.task_ids == policy.task_ids for job in jobs)
        and complete_trials == expected_task_trials
        and stopped_trials == 0
    )
    if not coverage_complete:
        violations.append("incomplete_task_trials")

    mechanism_rows = [
        row
        for job in jobs
        for row in job.rows
        if row.get("interruption_state") not in {"not_started", "incomplete"}
        and row.get("_interruption_excluded") is not True
    ]
    error_rows = [row for row in mechanism_rows if row.get("exception") is not None]

    def effective_pass(row: Mapping[str, object]) -> bool:
        return bool(row.get("collector_pass") and row.get("exception") is None)

    raw = float(
        sum(
            (
                Decimal(str(row["reward"]))
                for row in mechanism_rows
                if effective_pass(row)
            ),
            Decimal(0),
        )
    )
    trusted_raw = float(
        sum(
            (
                Decimal(str(row["reward"]))
                for row in mechanism_rows
                if effective_pass(row) and not row.get("contamination_signal")
            ),
            Decimal(0),
        )
    )
    submission_eligible_raw = float(
        sum(
            (
                Decimal(str(row["reward"]))
                for row in mechanism_rows
                if effective_pass(row)
                and not row.get("submission_integrity_blocking")
                and not row.get("git_history_submission_blocking")
            ),
            Decimal(0),
        )
    )
    strict = sum(bool(row.get("strict_pass")) for row in mechanism_rows)
    reliable = sum(bool(row.get("reliable")) for row in mechanism_rows)
    measurement = sum(bool(row.get("measurement_complete")) for row in mechanism_rows)

    legacy_integrity_rows = [
        row for row in mechanism_rows if bool(row.get("contamination_signal"))
    ]
    integrity_rows = [
        row for row in mechanism_rows if bool(row.get("submission_integrity_blocking"))
    ]
    git_integrity_rows = [
        row
        for row in mechanism_rows
        if bool(row.get("git_history_submission_blocking"))
    ]
    warning_integrity_rows = [
        row
        for row in mechanism_rows
        if int(row.get("submission_integrity_warning_count", 0)) > 0
    ]
    integrity_findings = [
        finding
        for row in legacy_integrity_rows
        for finding in row.get("protected_target_findings", [])
        if isinstance(finding, dict)
    ]
    unavailable_integrity_rows = [
        row
        for row in mechanism_rows
        if row.get("contamination_audit_state") not in {"available", "not_applicable"}
    ]
    runtime_result_contradiction_rows = [
        row
        for row in mechanism_rows
        if row.get("_runtime_result_contradiction") is True
    ]
    if integrity_rows or git_integrity_rows:
        violations.append("integrity_policy_violation")
    if unavailable_integrity_rows:
        violations.append("contamination_evidence_unavailable")
    if runtime_result_contradiction_rows:
        violations.append("runtime_result_contradiction")
    rewarded_rows = [
        row
        for row in mechanism_rows
        if isinstance(row.get("reward"), int | float)
        and not isinstance(row.get("reward"), bool)
        and float(row["reward"]) > 0
    ]
    eligible_rows = sum(row.get("_atif_eligible") is True for row in rewarded_rows)
    unjudgeable = len(rewarded_rows) - eligible_rows
    if unjudgeable:
        violations.append("unjudgeable_rewarded_row")
    violations = list(dict.fromkeys(violations))
    metrics = {
        "raw": _metric(raw, expected_task_trials, coverage_complete),
        "trusted_raw": _metric(trusted_raw, expected_task_trials, coverage_complete),
        "submission_eligible_raw": _metric(
            submission_eligible_raw, expected_task_trials, coverage_complete
        ),
        "strict": _metric(strict, expected_task_trials, coverage_complete),
        "reliable": _metric(reliable, expected_task_trials, coverage_complete),
        "measurement_complete": _metric(
            measurement, expected_task_trials, coverage_complete
        ),
    }
    mechanism_denominator = len(mechanism_rows)
    mechanism_rates = {
        "denominator": mechanism_denominator,
        "excluded_stopped_or_incomplete": stopped_trials,
        "raw_percent": round(100 * raw / mechanism_denominator, 6)
        if mechanism_denominator
        else None,
        "trusted_raw_percent": round(100 * trusted_raw / mechanism_denominator, 6)
        if mechanism_denominator
        else None,
        "submission_eligible_raw_percent": round(
            100 * submission_eligible_raw / mechanism_denominator, 6
        )
        if mechanism_denominator
        else None,
        "strict_percent": round(100 * strict / mechanism_denominator, 6)
        if mechanism_denominator
        else None,
        "reliable_percent": round(100 * reliable / mechanism_denominator, 6)
        if mechanism_denominator
        else None,
        "measurement_complete_percent": round(
            100 * measurement / mechanism_denominator, 6
        )
        if mechanism_denominator
        else None,
    }
    provider_calls = {
        "requested": sum(
            int(row["provider_calls_requested"]) for row in mechanism_rows
        ),
        "completed": sum(
            int(row["provider_calls_completed"]) for row in mechanism_rows
        ),
        "failed": sum(int(row["provider_calls_failed"]) for row in mechanism_rows),
        "in_flight": sum(
            int(row["provider_calls_in_flight"]) for row in mechanism_rows
        ),
        "usage_covered": sum(
            int(row["provider_calls_usage_covered"]) for row in mechanism_rows
        ),
    }
    cost_covered = sum(bool(row.get("cost_coverage")) for row in mechanism_rows)
    cost = {
        "observed_lower_bound": round(
            sum(float(row["provider_cost_usd_observed"]) for row in mechanism_rows),
            10,
        ),
        "complete_rows": cost_covered,
        "row_coverage": f"{cost_covered}/{mechanism_denominator}",
    }
    error_types = [
        str(row["exception"]["type"])  # type: ignore[index]
        for row in error_rows
    ]
    failure_buckets = [str(row["failure_bucket"]) for row in error_rows]
    failure_codes = [str(row["failure_code"]) for row in error_rows]
    evidence_sha256 = hashlib.sha256(
        _canonical([job.evidence_sha256 for job in jobs])
    ).hexdigest()
    gate_passed = not violations
    return {
        "schema_version": CANDIDATE_REPORT_SCHEMA,
        "status": "passed" if gate_passed else "failed",
        "gate_passed": gate_passed,
        "leaderboard_publishable": False,
        "provider_free": True,
        "inputs_mutated": False,
        "execution_isolation_claimed": False,
        "candidate_identity_sha256": candidate_identity_sha256,
        "evidence_sha256": evidence_sha256,
        "coverage": {
            "expected_jobs": policy.expected_jobs,
            "observed_jobs": len(jobs),
            "tasks_per_job": len(policy.task_ids),
            "expected_task_trials": expected_task_trials,
            "dispatched_task_trials": dispatched,
            "complete_task_trials": complete_trials,
            "stopped_or_incomplete_task_trials": stopped_trials,
            "complete": coverage_complete,
        },
        "metrics": metrics,
        "mechanism_rates": mechanism_rates,
        "provider_calls": provider_calls,
        "cost_usd": cost,
        "errors": {
            "count": len(error_rows),
            "scoring": "zero",
            "static_rejection": False,
            "by_type": _counter(error_types),
            "by_failure_bucket": _counter(failure_buckets),
            "by_failure_code": _counter(failure_codes),
        },
        "integrity": {
            "audit_kind": "post_run_evidence_only",
            "audit_schema": tb21.protected_target.AUDIT_SCHEMA,
            "finding_schema": tb21.protected_target.FINDING_SCHEMA,
            "policy_schema": tb21.protected_target.POLICY_SCHEMA,
            "policy_sha256": tb21.protected_target.POLICY_SHA256,
            "execution_isolation": False,
            "violation_count": len(integrity_rows),
            "legacy_finding_trial_count": len(legacy_integrity_rows),
            "blocking_trial_count": len(integrity_rows),
            "blocking_finding_count": sum(
                int(row.get("submission_integrity_blocking_count", 0))
                for row in mechanism_rows
            ),
            "warning_trial_count": len(warning_integrity_rows),
            "warning_finding_count": sum(
                int(row.get("submission_integrity_warning_count", 0))
                for row in mechanism_rows
            ),
            "finding_count": len(integrity_findings),
            "evidence_unavailable_count": len(unavailable_integrity_rows),
            "runtime_result_contradiction_count": len(
                runtime_result_contradiction_rows
            ),
            "classifications": _counter(
                [str(finding.get("classification")) for finding in integrity_findings]
            ),
            "signals": _counter(
                [
                    str(signal)
                    for row in legacy_integrity_rows
                    for signal in row.get("contamination_signals", [])
                ]
            ),
        },
        "git_history_integrity": {
            "audit_schema": tb21.git_history_audit.AUDIT_SCHEMA,
            "finding_schema": tb21.git_history_audit.FINDING_SCHEMA,
            "blocking_trial_count": len(git_integrity_rows),
            "finding_count": sum(
                len(row.get("git_history_findings", [])) for row in mechanism_rows
            ),
            "causal_reuse_count": sum(
                int(row.get("git_history_counts", {}).get("causal_reuse", 0))
                for row in mechanism_rows
            ),
            "warning_count": sum(
                int(row.get("git_history_counts", {}).get("warnings", 0))
                for row in mechanism_rows
            ),
        },
        "atif_eligibility": {
            "rewarded_rows": len(rewarded_rows),
            "eligible_rows": eligible_rows,
            "unjudgeable_rewarded_rows": unjudgeable,
            "basis": "hash_bound_success_atif_marker",
        },
        "interruption": {
            "rows_projected_in_memory": sum(
                job.projected_interruption_rows for job in jobs
            ),
            "stopped_or_incomplete_task_trials": stopped_trials,
        },
        "violations": violations,
    }


def parse_args(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    audit = subparsers.add_parser("audit")
    audit.add_argument("--job-dir", type=Path, action="append", default=[])
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    args = parse_args(arguments)
    try:
        require_pinned_harbor_validator()
        checksums = load_official_checksums(ROOT / tb21.OFFICIAL_TASK_CHECKSUMS_PATH)
        policy = StagePolicy(
            task_ids=tuple(checksums),
            expected_jobs=len(args.job_dir),
        )
        report = audit_jobs(
            tuple(args.job_dir),
            policy=policy,
            official_checksums=checksums,
        )
        exit_code = 0 if report["gate_passed"] else 1
    except CandidateError as error:
        report = {
            "schema_version": CANDIDATE_REPORT_SCHEMA,
            "status": "rejected",
            "error": str(error),
            "provider_free": True,
            "inputs_mutated": False,
        }
        exit_code = 1
    sys.stdout.buffer.write(_canonical(report))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
