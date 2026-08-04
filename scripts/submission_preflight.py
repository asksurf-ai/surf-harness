#!/usr/bin/env python3
"""Read-only, provider-free TB2.1 submission admission.

The command inspects immutable Harbor job records and agent-authored evidence.
It never starts Harbor, Docker, a model provider, or a network client; it never
opens task solution files or files below a trial's verifier directory.  Every
missing, malformed, mixed-identity, retry, protected-target, or direct-ATIF gap
is a hard failure.  Output is a canonical, timestamp-free JSON receipt so the
same input bytes produce the same output bytes.

Example::

    python scripts/submission_preflight.py \
      --job-dir /absolute/path/to/job \
      --expected-agent-version 0.2.0 \
      --expected-runtime-git-head "$GIT_SHA" \
      --expected-runtime-binary-sha256 "$BINARY_SHA256" \
      --expected-contract-set-sha256 "$CONTRACT_SHA256"

Run this command with the repository's pinned Harbor environment.  There is no
CLI bypass for its pinned-validator requirement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from nano_grok_build.adapter.atif import (  # noqa: E402
    AtifError,
    validate_minimal_trajectory,
    validate_with_pinned_harbor,
)
from nano_grok_build.harbor import protected_target, tb21  # noqa: E402
from scripts import check_v10_candidate as candidate  # noqa: E402

SUBMISSION_PREFLIGHT_SCHEMA = "nano-submission-preflight-v1"
UPLOADER_TRAJECTORY_PATH = Path("agent/trajectory.json")
_EXPECTED_MARKER_SHAPES = {
    ("nano-agent-run-v2", "success_atif"),
    ("nano-agent-run-v3", "success_atif"),
    ("nano-agent-run-v4", "failure_atif"),
    ("nano-agent-run-v4", "emergency_atif"),
}
_BLOCKED_CLASSIFICATIONS = {"strong", "attempted", "access_blocked"}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class ReleaseExpectation:
    """The one release identity allowed in every submitted trial."""

    agent_version: str
    runtime_git_head: str
    runtime_binary_sha256: str
    contract_set_sha256: str

    def valid(self) -> bool:
        return bool(
            self.agent_version
            and _GIT_SHA.fullmatch(self.runtime_git_head)
            and _SHA256.fullmatch(self.runtime_binary_sha256)
            and _SHA256.fullmatch(self.contract_set_sha256)
        )

    def receipt(self) -> dict[str, str]:
        return {
            "agent_version": self.agent_version,
            "contract_set_sha256": self.contract_set_sha256,
            "runtime_binary_sha256": self.runtime_binary_sha256,
            "runtime_git_head": self.runtime_git_head,
        }


@dataclass(frozen=True)
class _Scan:
    receipt: dict[str, object]
    job_id: str
    run_ids: tuple[str, ...]
    agent_versions: tuple[str, ...]


class _Issues:
    def __init__(self) -> None:
        self._items: set[tuple[str, str, str]] = set()

    def add(
        self,
        code: str,
        *,
        task: str | None = None,
        trial: str | None = None,
    ) -> None:
        self._items.add((code, task or "", trial or ""))

    def values(self) -> list[dict[str, object]]:
        return [
            {
                "code": code,
                "task": task or None,
                "trial": trial or None,
            }
            for code, task, trial in sorted(self._items)
        ]

    def __bool__(self) -> bool:
        return bool(self._items)


def receipt_bytes(value: object) -> bytes:
    """Serialize a receipt canonically; it deliberately contains no timestamp."""

    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _read_json(path: Path, code: str) -> tuple[Mapping[str, object], bytes]:
    value, raw = candidate._read_json(path, code)
    return candidate._mapping(value, code), raw


def _canonical_json(path: Path, code: str) -> tuple[Mapping[str, object], bytes]:
    value, raw = _read_json(path, code)
    if raw != receipt_bytes(value):
        raise candidate.CandidateError(code)
    return value, raw


def _reward(result: Mapping[str, object]) -> float | None:
    verifier_result = result.get("verifier_result")
    if verifier_result is None:
        return None
    if not isinstance(verifier_result, dict):
        raise candidate.CandidateError("trial_result_invalid")
    rewards = verifier_result.get("rewards")
    if not isinstance(rewards, dict):
        raise candidate.CandidateError("trial_result_invalid")
    value = rewards.get("reward")
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(float(value))
        or not 0 <= float(value) <= 1
    ):
        raise candidate.CandidateError("trial_result_invalid")
    return float(value)


def _hash_feed(entries: list[tuple[str, str]], name: str, raw: bytes) -> None:
    entries.append((name, hashlib.sha256(raw).hexdigest()))


def _hash_missing(entries: list[tuple[str, str]], name: str) -> None:
    entries.append((name, "missing"))


def _validate_root_result(
    job_dir: Path,
    *,
    job_id: str,
    expected_trials: int,
    issues: _Issues,
    hashes: list[tuple[str, str]],
) -> None:
    try:
        value, raw = _read_json(job_dir / "result.json", "job_result_invalid")
        _hash_feed(hashes, "result.json", raw)
    except candidate.CandidateError:
        issues.add("job_result_invalid")
        return
    stats = value.get("stats")
    if not isinstance(stats, dict):
        issues.add("job_result_invalid")
        return
    if value.get("id") != job_id:
        issues.add("job_identity_invalid")
    terminal = (
        isinstance(value.get("finished_at"), str)
        and value.get("n_total_trials") == expected_trials
        and stats.get("n_completed_trials") == expected_trials
        and stats.get("n_running_trials") == 0
        and stats.get("n_pending_trials") == 0
        and stats.get("n_cancelled_trials") == 0
    )
    if not terminal:
        issues.add("job_not_terminal")
    if stats.get("n_retries") != 0:
        issues.add("unexpected_retry")


def _validate_release_identity(
    cohort: Mapping[str, object],
    expectation: ReleaseExpectation,
    issues: _Issues,
) -> None:
    runtime = cohort.get("runtime")
    if not isinstance(runtime, dict):
        issues.add("release_identity_mismatch")
        return
    if runtime.get("git_head") != expectation.runtime_git_head:
        issues.add("runtime_git_head_mismatch")
    if runtime.get("binary_sha256") != expectation.runtime_binary_sha256:
        issues.add("runtime_binary_sha256_mismatch")
    if runtime.get("contract_set_sha256") != expectation.contract_set_sha256:
        issues.add("contract_set_sha256_mismatch")


def _validate_trajectory(
    value: Mapping[str, object],
    *,
    spec: Mapping[str, object],
    expectation: ReleaseExpectation,
    require_pinned_harbor: bool,
    issues: _Issues,
    task_id: str,
    trial_id: str,
) -> str | None:
    try:
        validate_minimal_trajectory(value)
    except AtifError:
        issues.add("atif_invalid", task=task_id, trial=trial_id)
        return None
    if require_pinned_harbor:
        try:
            validate_with_pinned_harbor(value)
        except AtifError:
            issues.add(
                "pinned_harbor_validator_unavailable_or_invalid",
                task=task_id,
                trial=trial_id,
            )
            return None
    agent = value.get("agent")
    extra = value.get("extra")
    version = agent.get("version") if isinstance(agent, dict) else None
    identity_valid = bool(
        value.get("session_id") == spec.get("run_id")
        and isinstance(agent, dict)
        and agent.get("name") == "nano-grok-build"
        and agent.get("model_name") == "grok-4.5"
        and isinstance(version, str)
        and isinstance(extra, dict)
        and extra.get("trial_id") == spec.get("trial_id")
        and extra.get("attempt_id") == spec.get("attempt_id")
        and extra.get("run_spec_sha256") == tb21.rust_run_spec_sha256(spec)
    )
    if not identity_valid:
        issues.add("trajectory_identity_invalid", task=task_id, trial=trial_id)
        return str(version) if isinstance(version, str) else None
    if version != expectation.agent_version:
        issues.add("agent_version_mismatch", task=task_id, trial=trial_id)
    return str(version)


def _audit_projection(audit: Mapping[str, object]) -> dict[str, object]:
    findings = audit.get("findings")
    return {
        "contamination_audit_state": audit.get("state"),
        "contamination_signal": bool(findings),
        "contamination_signals": audit.get("signals"),
        "protected_target_audit_schema": audit.get("schema_version"),
        "protected_target_counts": audit.get("counts"),
        "protected_target_findings": audit.get("findings"),
        "protected_target_policy_schema": audit.get("policy_schema_version"),
        "protected_target_policy_sha256": audit.get("policy_sha256"),
    }


def _audit_protected_target(
    trial_dir: Path,
    *,
    rewarded: bool,
    issues: _Issues,
    task_id: str,
    trial_id: str,
) -> dict[str, object]:
    try:
        audit = tb21._contamination_audit(trial_dir, rewarded=rewarded)
    except (OSError, RuntimeError, TypeError, ValueError):
        issues.add("protected_evidence_unavailable", task=task_id, trial=trial_id)
        return {}
    if (
        not isinstance(audit, dict)
        or audit.get("state") != "available"
        or audit.get("schema_version") != protected_target.AUDIT_SCHEMA
        or audit.get("policy_schema_version") != protected_target.POLICY_SCHEMA
        or audit.get("policy_sha256") != protected_target.POLICY_SHA256
        or not isinstance(audit.get("findings"), list)
    ):
        issues.add("protected_evidence_unavailable", task=task_id, trial=trial_id)
        return dict(audit) if isinstance(audit, dict) else {}
    for finding in audit["findings"]:
        classification = (
            finding.get("classification") if isinstance(finding, dict) else None
        )
        if classification in _BLOCKED_CLASSIFICATIONS:
            issues.add(
                f"protected_target_{classification}",
                task=task_id,
                trial=trial_id,
            )
        elif classification is not None:
            issues.add(
                "protected_target_classification_invalid",
                task=task_id,
                trial=trial_id,
            )
    return dict(audit)


def _scan_trial(
    job_dir: Path,
    spec: Mapping[str, object],
    *,
    expectation: ReleaseExpectation,
    require_pinned_harbor: bool,
    issues: _Issues,
    hashes: list[tuple[str, str]],
) -> tuple[float | None, str | None, dict[str, object]]:
    task = spec.get("task")
    task_id = str(task.get("id", "")) if isinstance(task, dict) else ""
    digest = str(task.get("digest", "")) if isinstance(task, dict) else ""
    trial_id = str(spec.get("trial_id", ""))
    trial_dir = job_dir / trial_id
    if trial_dir.is_symlink() or not trial_dir.is_dir():
        issues.add("trial_directory_invalid", task=task_id, trial=trial_id)
        return None, None, {}

    reward: float | None = None
    result: Mapping[str, object] | None = None
    try:
        result, raw = _read_json(trial_dir / "result.json", "trial_result_invalid")
        _hash_feed(hashes, f"{trial_id}/result.json", raw)
        reward = _reward(result)
    except candidate.CandidateError:
        issues.add("trial_result_invalid", task=task_id, trial=trial_id)
    if result is not None and (
        result.get("task_name") != task_id
        or result.get("trial_name") != trial_id
        or result.get("task_checksum") != digest
        or not isinstance(result.get("finished_at"), str)
    ):
        issues.add("result_identity_invalid", task=task_id, trial=trial_id)

    marker: Mapping[str, object] | None = None
    marker_path = trial_dir / "agent" / "agent-run.json"
    try:
        marker, marker_raw = _canonical_json(marker_path, "terminal_marker_invalid")
        _hash_feed(hashes, f"{trial_id}/agent-run.json", marker_raw)
    except candidate.CandidateError:
        if not marker_path.exists() and not marker_path.is_symlink():
            issues.add("terminal_marker_missing", task=task_id, trial=trial_id)
            _hash_missing(hashes, f"{trial_id}/agent-run.json")
        else:
            issues.add("terminal_marker_invalid", task=task_id, trial=trial_id)

    if marker is not None:
        shape = (marker.get("schema_version"), marker.get("publication_kind"))
        if shape not in _EXPECTED_MARKER_SHAPES:
            issues.add("marker_schema_invalid", task=task_id, trial=trial_id)
        try:
            evidence = tb21._artifact_evidence(trial_dir, spec)
            if not (
                evidence.publication_valid
                and evidence.trajectory_valid
                and evidence.diagnostic_valid
                and evidence.terminal_status is not None
            ):
                issues.add("terminal_evidence_invalid", task=task_id, trial=trial_id)
        except (OSError, RuntimeError, TypeError, ValueError):
            issues.add("terminal_evidence_invalid", task=task_id, trial=trial_id)

    direct_path = trial_dir / UPLOADER_TRAJECTORY_PATH
    trajectory: Mapping[str, object] | None = None
    version: str | None = None
    try:
        trajectory, trajectory_raw = _canonical_json(
            direct_path, "terminal_direct_trajectory_invalid"
        )
        _hash_feed(hashes, f"{trial_id}/agent/trajectory.json", trajectory_raw)
    except candidate.CandidateError:
        _hash_missing(hashes, f"{trial_id}/agent/trajectory.json")
        issues.add(
            "terminal_direct_trajectory_missing",
            task=task_id,
            trial=trial_id,
        )
        if reward is not None and reward > 0:
            issues.add(
                "rewarded_direct_trajectory_missing",
                task=task_id,
                trial=trial_id,
            )
    if trajectory is not None:
        version = _validate_trajectory(
            trajectory,
            spec=spec,
            expectation=expectation,
            require_pinned_harbor=require_pinned_harbor,
            issues=issues,
            task_id=task_id,
            trial_id=trial_id,
        )
        if marker is not None and (
            marker.get("trajectory_path") != "trajectory.json"
            or marker.get("trajectory_sha256")
            != hashlib.sha256(receipt_bytes(trajectory)).hexdigest()
        ):
            issues.add(
                "direct_trajectory_binding_invalid", task=task_id, trial=trial_id
            )

    audit = _audit_protected_target(
        trial_dir,
        rewarded=bool(reward is not None and reward > 0),
        issues=issues,
        task_id=task_id,
        trial_id=trial_id,
    )
    return reward, version, audit


def _read_rows(
    path: Path,
    *,
    issues: _Issues,
    hashes: list[tuple[str, str]],
) -> tuple[dict[str, object], ...]:
    try:
        raw = candidate._read_regular(path, "collector_malformed")
    except candidate.CandidateError:
        issues.add("collector_malformed")
        return ()
    _hash_feed(hashes, "rows.jsonl", raw)
    if not raw or not raw.endswith(b"\n"):
        issues.add("collector_malformed")
        return ()
    rows: list[dict[str, object]] = []
    for line in raw.splitlines(keepends=True):
        try:
            value = candidate._strict_json_bytes(line, "collector_malformed")
            row = dict(candidate._mapping(value, "collector_malformed"))
        except candidate.CandidateError:
            issues.add("collector_malformed")
            return ()
        if line != receipt_bytes(row):
            issues.add("collector_malformed")
            return ()
        rows.append(row)
    return tuple(rows)


def _validate_collector(
    job_dir: Path,
    *,
    specs: Sequence[Mapping[str, object]],
    rewards: Mapping[str, float | None],
    audits: Mapping[str, Mapping[str, object]],
    cohort: Mapping[str, object],
    issues: _Issues,
    hashes: list[tuple[str, str]],
) -> str:
    rows = _read_rows(job_dir / "rows.jsonl", issues=issues, hashes=hashes)
    expected_trials = {str(spec["trial_id"]): spec for spec in specs}
    row_trials = [str(row.get("trial", "")) for row in rows]
    if len(row_trials) != len(set(row_trials)):
        issues.add("collector_duplicate_row")
    if set(row_trials) != set(expected_trials) or len(rows) != len(specs):
        issues.add("collector_inventory_mismatch")
    for row in rows:
        trial_id = str(row.get("trial", ""))
        spec = expected_trials.get(trial_id)
        if row.get("schema_version") != tb21.ROW_SCHEMA:
            issues.add("collector_schema_mismatch", trial=trial_id or None)
        if spec is None:
            continue
        task = spec["task"]
        task_id = str(task["id"])  # type: ignore[index]
        expected_audit = _audit_projection(audits.get(trial_id, {}))
        if (
            row.get("task") != task_id
            or row.get("digest") != task["digest"]  # type: ignore[index]
            or row.get("result_binding_valid") is not True
            or row.get("reward") != rewards.get(trial_id)
        ):
            issues.add("collector_projection_mismatch", task=task_id, trial=trial_id)
        if any(row.get(key) != value for key, value in expected_audit.items()):
            issues.add("collector_projection_mismatch", task=task_id, trial=trial_id)

    try:
        summary, summary_raw = _canonical_json(
            job_dir / "summary.json", "collector_malformed"
        )
        _hash_feed(hashes, "summary.json", summary_raw)
    except candidate.CandidateError:
        issues.add("collector_malformed")
        summary = {}
    if summary.get("schema_version") != tb21.SUMMARY_SCHEMA:
        issues.add("collector_schema_mismatch")
    runtime = cohort.get("runtime")
    runtime = runtime if isinstance(runtime, dict) else {}
    expected_pins = {
        "active_tools": list(tb21.ACTIVE_TOOLS),
        "contract_set_sha256": runtime.get("contract_set_sha256"),
        "dataset": tb21.TB21_DATASET,
        "dataset_ref": tb21.TB21_DATASET_REF,
        "harbor_commit": tb21.HARBOR_COMMIT,
        "max_provider_turns": 64,
        "model": "grok-4.5",
        "runtime_binary_sha256": runtime.get("binary_sha256"),
        "runtime_git_head": runtime.get("git_head"),
        "source_commit": tb21.TB21_SOURCE_COMMIT,
    }
    pins = summary.get("pins")
    if not isinstance(pins, dict) or any(
        pins.get(key) != value for key, value in expected_pins.items()
    ):
        issues.add("collector_summary_invalid")
    summary_cohort = summary.get("cohort")
    if not isinstance(summary_cohort, dict) or any(
        summary_cohort.get(key) != value
        for key, value in {
            "job_id": cohort.get("job_id"),
            "n_attempts": 1,
            "retry_max": 0,
        }.items()
    ):
        issues.add("collector_summary_invalid")
    counts = summary.get("counts")
    gates = summary.get("gates")
    if not isinstance(counts, dict) or any(
        counts.get(key) != value
        for key, value in {
            "expected": tb21.TB21_TASK_COUNT,
            "observed": tb21.TB21_TASK_COUNT,
            "missing": 0,
            "duplicates": 0,
            "unexpected": 0,
            "retries": 0,
        }.items()
    ):
        issues.add("collector_summary_invalid")
    if not isinstance(gates, dict) or any(
        gates.get(key) is not True
        for key in (
            "job_terminal",
            "exact_inventory",
            "result_identity",
            "collect_idempotent",
            "contamination_clean",
        )
    ):
        issues.add("collector_summary_invalid")

    # The on-disk rows/summary are the automatic collector output.  Re-read
    # them and independently repeat every agent-only protected-evidence audit
    # for the second collect-only projection.  No pass opens verifier or
    # solution paths.
    first_projection = receipt_bytes(
        {"rows": list(rows), "summary": dict(summary), "audits": dict(audits)}
    )
    second_rows = _read_rows(job_dir / "rows.jsonl", issues=issues, hashes=hashes)
    try:
        second_summary, second_summary_raw = _canonical_json(
            job_dir / "summary.json", "collector_malformed"
        )
        _hash_feed(hashes, "summary.json#collect-only-2", second_summary_raw)
    except candidate.CandidateError:
        issues.add("collector_malformed")
        second_summary = {}
    second_audits: dict[str, Mapping[str, object]] = {}
    for spec in specs:
        task = spec["task"]
        task_id = str(task["id"])  # type: ignore[index]
        trial_id = str(spec["trial_id"])
        second_audits[trial_id] = _audit_protected_target(
            job_dir / trial_id,
            rewarded=bool(rewards.get(trial_id, 0) and rewards[trial_id] > 0),
            issues=issues,
            task_id=task_id,
            trial_id=trial_id,
        )
    second_projection = receipt_bytes(
        {
            "rows": list(second_rows),
            "summary": dict(second_summary),
            "audits": second_audits,
        }
    )
    if first_projection != second_projection:
        issues.add("collect_projection_not_idempotent")
    return hashlib.sha256(first_projection).hexdigest()


def _scan_job(
    job_dir: Path,
    *,
    expectation: ReleaseExpectation,
    require_pinned_harbor: bool,
    official_checksums: Mapping[str, str],
) -> _Scan:
    issues = _Issues()
    hashes: list[tuple[str, str]] = []
    empty = _Scan(
        receipt={
            "agent_versions": [],
            "collector_projection_sha256": hashlib.sha256(b"").hexdigest(),
            "evidence_sha256": hashlib.sha256(b"").hexdigest(),
            "issues": [],
            "job_id": "invalid",
            "trial_count": 0,
        },
        job_id="invalid",
        run_ids=(),
        agent_versions=(),
    )
    if job_dir.is_symlink() or not job_dir.is_absolute() or not job_dir.is_dir():
        issues.add("job_directory_invalid")
        empty.receipt["issues"] = issues.values()
        return empty

    try:
        dispatch, dispatch_raw = candidate._load_envelope(
            job_dir / "nano-dispatch.json",
            "nano-harbor-dispatch-v1",
            "candidate_dispatch_invalid",
        )
        _hash_feed(hashes, "nano-dispatch.json", dispatch_raw)
        specs = candidate._validate_dispatch(dispatch)
    except candidate.CandidateError:
        issues.add("dispatch_invalid")
        empty.receipt["issues"] = issues.values()
        return empty

    job_id = str(dispatch["job_id"])
    task_ids = tuple(str(spec["task"]["id"]) for spec in specs)  # type: ignore[index]
    if len(specs) != tb21.TB21_TASK_COUNT or task_ids != tuple(official_checksums):
        issues.add("exact_inventory_mismatch")
    for spec in specs:
        task = spec["task"]
        if official_checksums.get(str(task["id"])) != task["digest"]:  # type: ignore[index]
            issues.add(
                "official_task_digest_mismatch",
                task=str(task["id"]),  # type: ignore[index]
                trial=str(spec["trial_id"]),
            )

    try:
        config, config_raw = _read_json(
            job_dir / "config.json", "candidate_job_config_override"
        )
        _hash_feed(hashes, "config.json", config_raw)
        candidate._validate_job_config(config, task_ids)
    except candidate.CandidateError:
        issues.add("job_identity_or_default_config_invalid")

    try:
        lock, lock_raw = _read_json(
            job_dir / "lock.json", "candidate_harbor_lock_invalid"
        )
        _hash_feed(hashes, "lock.json", lock_raw)
        retry = lock.get("retry")
        if not isinstance(retry, dict) or retry.get("max_retries") != 0:
            issues.add("unexpected_retry")
        candidate._validate_lock(lock, specs)
    except candidate.CandidateError as error:
        if str(error) == "harbor_retry_override":
            issues.add("unexpected_retry")
        issues.add("job_identity_or_default_config_invalid")

    cohort: Mapping[str, object] = {}
    try:
        cohort, cohort_raw = candidate._load_envelope(
            job_dir / "nano-tb21-cohort.json",
            tb21.COHORT_SCHEMA,
            "candidate_cohort_invalid",
        )
        _hash_feed(hashes, "nano-tb21-cohort.json", cohort_raw)
        candidate._validate_cohort(cohort, specs, official_checksums)
        if cohort.get("job_id") != job_id:
            issues.add("job_identity_invalid")
        _validate_release_identity(cohort, expectation, issues)
    except candidate.CandidateError as error:
        if str(error) == "official_task_digest_mismatch":
            issues.add("official_task_digest_mismatch")
        else:
            issues.add("cohort_invalid")

    _validate_root_result(
        job_dir,
        job_id=job_id,
        expected_trials=len(specs),
        issues=issues,
        hashes=hashes,
    )

    expected_trial_ids = {str(spec["trial_id"]) for spec in specs}
    for child in sorted(job_dir.iterdir(), key=lambda path: path.name):
        if child.is_dir() and (child / "result.json").exists():
            if child.name not in expected_trial_ids:
                issues.add("unexpected_trial", trial=child.name)

    rewards: dict[str, float | None] = {}
    audits: dict[str, Mapping[str, object]] = {}
    versions: list[str] = []
    for spec in specs:
        trial_id = str(spec["trial_id"])
        reward, version, audit = _scan_trial(
            job_dir,
            spec,
            expectation=expectation,
            require_pinned_harbor=require_pinned_harbor,
            issues=issues,
            hashes=hashes,
        )
        rewards[trial_id] = reward
        audits[trial_id] = audit
        if version is not None:
            versions.append(version)
    if len(set(versions)) > 1:
        issues.add("mixed_agent_version")

    projection_sha256 = _validate_collector(
        job_dir,
        specs=specs,
        rewards=rewards,
        audits=audits,
        cohort=cohort,
        issues=issues,
        hashes=hashes,
    )
    evidence_sha256 = hashlib.sha256(receipt_bytes(sorted(hashes))).hexdigest()
    receipt: dict[str, object] = {
        "agent_versions": sorted(set(versions)),
        "collector_projection_sha256": projection_sha256,
        "evidence_sha256": evidence_sha256,
        "issues": issues.values(),
        "job_id": job_id,
        "trial_count": len(specs),
    }
    return _Scan(
        receipt=receipt,
        job_id=job_id,
        run_ids=tuple(str(spec["run_id"]) for spec in specs),
        agent_versions=tuple(sorted(set(versions))),
    )


def audit_jobs(
    job_dirs: Sequence[Path],
    *,
    expectation: ReleaseExpectation,
    require_pinned_harbor: bool = True,
) -> dict[str, object]:
    """Audit one or more full jobs without mutating or executing them."""

    if not expectation.valid():
        raise ValueError("release_expectation_invalid")
    official_checksums = candidate.load_official_checksums(
        ROOT / tb21.OFFICIAL_TASK_CHECKSUMS_PATH
    )
    scans = [
        _scan_job(
            path,
            expectation=expectation,
            require_pinned_harbor=require_pinned_harbor,
            official_checksums=official_checksums,
        )
        for path in job_dirs
    ]
    job_ids = [scan.job_id for scan in scans]
    run_ids = [run_id for scan in scans for run_id in scan.run_ids]
    if len(job_ids) != len(set(job_ids)):
        for scan in scans:
            if job_ids.count(scan.job_id) > 1:
                issues = _Issues()
                for issue in scan.receipt["issues"]:
                    issues.add(
                        str(issue["code"]),
                        task=issue.get("task"),
                        trial=issue.get("trial"),
                    )
                issues.add("duplicate_job_identity")
                scan.receipt["issues"] = issues.values()
    if len(run_ids) != len(set(run_ids)):
        for scan in scans:
            issues = _Issues()
            for issue in scan.receipt["issues"]:
                issues.add(
                    str(issue["code"]),
                    task=issue.get("task"),
                    trial=issue.get("trial"),
                )
            issues.add("duplicate_run_identity")
            scan.receipt["issues"] = issues.values()
    jobs = sorted(
        (scan.receipt for scan in scans),
        key=lambda row: (str(row["job_id"]), str(row["evidence_sha256"])),
    )
    submit_ready = bool(jobs) and all(not row["issues"] for row in jobs)
    return {
        "expectation": expectation.receipt(),
        "inputs_mutated": False,
        "jobs": jobs,
        "network_calls": 0,
        "provider_free": True,
        "schema_version": SUBMISSION_PREFLIGHT_SCHEMA,
        "status": "passed" if submit_ready else "failed",
        "submit_ready": submit_ready,
        "uploader_trajectory_path": UPLOADER_TRAJECTORY_PATH.as_posix(),
    }


def static_errors(root: Path) -> list[str]:
    """Check the immutable policy anchors used by submission admission."""

    errors: list[str] = []
    resolved = root.resolve()
    policy_path = resolved / "policy/protected-targets-v1.json"
    try:
        policy_raw = candidate._read_regular(policy_path, "policy_missing")
    except candidate.CandidateError:
        errors.append("submission preflight: protected-target policy missing")
    else:
        if hashlib.sha256(policy_raw).hexdigest() != protected_target.POLICY_SHA256:
            errors.append("submission preflight: protected-target policy hash drift")
    if UPLOADER_TRAJECTORY_PATH.as_posix() != "agent/trajectory.json":
        errors.append("submission preflight: uploader trajectory path drift")
    if SUBMISSION_PREFLIGHT_SCHEMA != "nano-submission-preflight-v1":
        errors.append("submission preflight: receipt schema drift")
    if not (resolved / "scripts/submission_preflight.py").is_file():
        errors.append("submission preflight: CLI missing")
    return errors


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only, provider-free TB2.1 submission admission; emits a stable "
            "canonical JSON receipt and fails closed on every evidence gap."
        )
    )
    parser.add_argument(
        "--job-dir",
        action="append",
        required=True,
        type=Path,
        help="absolute Harbor job directory; repeat for multiple rounds",
    )
    parser.add_argument("--expected-agent-version", required=True)
    parser.add_argument("--expected-runtime-git-head", required=True)
    parser.add_argument("--expected-runtime-binary-sha256", required=True)
    parser.add_argument("--expected-contract-set-sha256", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    expectation = ReleaseExpectation(
        agent_version=args.expected_agent_version,
        runtime_git_head=args.expected_runtime_git_head,
        runtime_binary_sha256=args.expected_runtime_binary_sha256,
        contract_set_sha256=args.expected_contract_set_sha256,
    )
    try:
        receipt = audit_jobs(tuple(args.job_dir), expectation=expectation)
    except (candidate.CandidateError, ValueError) as error:
        receipt = {
            "error": str(error),
            "inputs_mutated": False,
            "jobs": [],
            "network_calls": 0,
            "provider_free": True,
            "schema_version": SUBMISSION_PREFLIGHT_SCHEMA,
            "status": "failed",
            "submit_ready": False,
            "uploader_trajectory_path": UPLOADER_TRAJECTORY_PATH.as_posix(),
        }
    sys.stdout.buffer.write(receipt_bytes(receipt))
    return 0 if receipt.get("submit_ready") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
