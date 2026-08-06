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
      --expected-agent-version 0.4.4 \
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
from decimal import Decimal
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
from nano_grok_build.harbor.git_history_receipt import (  # noqa: E402
    HISTORY_BASELINE_RECEIPT,
)
from nano_grok_build.harbor.runtime_entry import (  # noqa: E402
    RUNTIME_ENTRY_NAME,
    RuntimeEntryError,
    load_runtime_entry,
)
from scripts import check_v10_candidate as candidate  # noqa: E402

SUBMISSION_PREFLIGHT_SCHEMA = "nano-submission-preflight-v3"
UPLOADER_TRAJECTORY_PATH = Path("agent/trajectory.json")
_EXPECTED_MARKER_SHAPES = {
    ("nano-agent-run-v2", "success_atif"),
    ("nano-agent-run-v3", "success_atif"),
    ("nano-agent-run-v4", "failure_atif"),
    ("nano-agent-run-v4", "emergency_atif"),
}
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


def _result_classification(
    result: Mapping[str, object] | None,
    reward: float | None,
    *,
    identity_valid: bool,
) -> str:
    """Classify official result evidence without consulting agent artifacts."""

    if result is None or not identity_valid:
        return "invalid"
    if reward is not None:
        return "rewarded" if reward > 0 else "zero"
    exception = result.get("exception_info")
    exception_type = (
        exception.get("exception_type") if isinstance(exception, dict) else None
    )
    exception_message = (
        exception.get("exception_message") if isinstance(exception, dict) else None
    )
    if (
        result.get("verifier_result") is None
        and isinstance(exception_type, str)
        and isinstance(exception_message, str)
    ):
        return "errored"
    return "invalid"


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
    blocking_count = (
        sum(
            protected_target.submission_blocking_finding(finding)
            for finding in findings
        )
        if isinstance(findings, list)
        else 0
    )
    warning_count = len(findings) - blocking_count if isinstance(findings, list) else 0
    return {
        "contamination_audit_state": audit.get("state"),
        "contamination_signal": bool(findings),
        "contamination_signals": audit.get("signals"),
        "protected_target_audit_schema": audit.get("schema_version"),
        "protected_target_counts": audit.get("counts"),
        "protected_target_findings": audit.get("findings"),
        "protected_target_policy_schema": audit.get("policy_schema_version"),
        "protected_target_policy_sha256": audit.get("policy_sha256"),
        "submission_integrity_blocking": bool(
            audit.get("state") not in {"available", "not_applicable"} or blocking_count
        ),
        "submission_integrity_blocking_count": blocking_count,
        "submission_integrity_warning_count": warning_count,
    }


def _audit_protected_target(
    trial_dir: Path,
    *,
    rewarded: bool,
    issues: _Issues,
    task_id: str,
    trial_id: str,
    not_applicable: bool = False,
    typed_runtime_entry: bool = False,
) -> dict[str, object]:
    try:
        audit = tb21._contamination_audit(trial_dir, rewarded=rewarded)
    except (OSError, RuntimeError, TypeError, ValueError):
        issues.add("protected_evidence_unavailable", task=task_id, trial=trial_id)
        return {}
    envelope_invalid = (
        not isinstance(audit, dict)
        or audit.get("schema_version") != protected_target.AUDIT_SCHEMA
        or audit.get("policy_schema_version") != protected_target.POLICY_SCHEMA
        or audit.get("policy_sha256") != protected_target.POLICY_SHA256
        or not isinstance(audit.get("findings"), list)
    )
    if envelope_invalid:
        issues.add("protected_evidence_unavailable", task=task_id, trial=trial_id)
        return dict(audit) if isinstance(audit, dict) else {}
    if not_applicable:
        allowed_states = (
            {"available", "unavailable"} if typed_runtime_entry else {"unavailable"}
        )
        if audit.get("state") not in allowed_states:
            issues.add("protected_evidence_unavailable", task=task_id, trial=trial_id)
            return dict(audit)
        return {
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
    if audit.get("state") != "available":
        issues.add("protected_evidence_unavailable", task=task_id, trial=trial_id)
        return dict(audit)
    for finding in audit["findings"]:
        if not protected_target.submission_blocking_finding(finding):
            continue
        if not isinstance(finding, dict):
            code = "protected_target_finding_invalid"
        elif finding.get("classification") == "strong":
            code = "protected_target_strong"
        elif finding.get("dispatched") is True:
            code = "protected_target_dispatched"
        elif finding.get("bytes_returned") is True:
            code = "protected_target_bytes_returned"
        elif finding.get("causal_benefit") is True:
            code = "protected_target_causal_benefit"
        else:
            code = "protected_target_finding_invalid"
        issues.add(code, task=task_id, trial=trial_id)
    return dict(audit)


def _git_audit_projection(audit: Mapping[str, object]) -> dict[str, object]:
    return {
        "git_history_audit_schema": audit.get("schema_version"),
        "git_history_finding_schema": audit.get("finding_schema_version"),
        "git_history_audit_state": audit.get("state"),
        "git_history_required": audit.get("history_required"),
        "git_history_evidence_complete": audit.get("evidence_complete"),
        "git_history_findings": audit.get("findings"),
        "git_history_counts": audit.get("counts"),
        "git_history_submission_blocking": audit.get("submission_blocking"),
    }


def _audit_git_history(
    trial_dir: Path,
    *,
    instruction: object,
    capability: object | None,
    trusted_manifest_sha256: object,
    run_spec_sha256: str,
    issues: _Issues,
    task_id: str,
    trial_id: str,
    not_applicable: bool = False,
    typed_runtime_entry: bool = False,
) -> dict[str, object]:
    audit = tb21.git_history_audit.audit_trial(
        trial_dir,
        instruction=instruction,
        capability=capability,
        trusted_manifest_sha256=trusted_manifest_sha256,
        run_spec_sha256=run_spec_sha256,
    )
    envelope_invalid = (
        audit.get("schema_version") != tb21.git_history_audit.AUDIT_SCHEMA
        or audit.get("finding_schema_version") != tb21.git_history_audit.FINDING_SCHEMA
        or not isinstance(audit.get("findings"), list)
    )
    if envelope_invalid:
        issues.add("git_history_evidence_unavailable", task=task_id, trial=trial_id)
        return dict(audit)
    if not_applicable:
        allowed_states = (
            {"available", "unavailable"} if typed_runtime_entry else {"unavailable"}
        )
        if audit.get("state") not in allowed_states or (
            audit.get("evidence_complete") is not True
            if audit.get("state") == "available"
            else audit.get("evidence_complete") is not False
        ):
            issues.add("git_history_evidence_unavailable", task=task_id, trial=trial_id)
            return dict(audit)
        return {
            "schema_version": tb21.git_history_audit.AUDIT_SCHEMA,
            "finding_schema_version": tb21.git_history_audit.FINDING_SCHEMA,
            "state": "not_applicable",
            "history_required": audit.get("history_required"),
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
    if audit.get("state") != "available" or audit.get("evidence_complete") is not True:
        issues.add("git_history_evidence_unavailable", task=task_id, trial=trial_id)
        return dict(audit)
    if audit.get("history_required") is None:
        issues.add("git_history_intent_ambiguous", task=task_id, trial=trial_id)
    for finding in audit["findings"]:
        if not tb21.git_history_audit.submission_blocking_finding(finding):
            continue
        if (
            isinstance(finding, dict)
            and finding.get("causal_reuse") is True
            and finding.get("history_required") is False
        ):
            code = "git_history_oracle_reuse"
        elif (
            isinstance(finding, dict)
            and finding.get("bytes_returned") is True
            and finding.get("history_required") is False
        ):
            code = "git_history_oracle_access"
        else:
            code = "git_history_finding_invalid"
        issues.add(code, task=task_id, trial=trial_id)
    return dict(audit)


def _scan_trial(
    job_dir: Path,
    spec: Mapping[str, object],
    *,
    expectation: ReleaseExpectation,
    require_pinned_harbor: bool,
    issues: _Issues,
    hashes: list[tuple[str, str]],
    legacy_runtime_not_started: bool,
) -> tuple[
    float | None,
    str,
    str | None,
    bool,
    bool,
    dict[str, object],
    dict[str, object],
]:
    task = spec.get("task")
    task_id = str(task.get("id", "")) if isinstance(task, dict) else ""
    digest = str(task.get("digest", "")) if isinstance(task, dict) else ""
    trial_id = str(spec.get("trial_id", ""))
    trial_dir = job_dir / trial_id
    if trial_dir.is_symlink() or not trial_dir.is_dir():
        issues.add("trial_directory_invalid", task=task_id, trial=trial_id)
        return None, "invalid", None, False, False, {}, {}

    reward: float | None = None
    result: Mapping[str, object] | None = None
    try:
        result, raw = _read_json(trial_dir / "result.json", "trial_result_invalid")
        _hash_feed(hashes, f"{trial_id}/result.json", raw)
        reward = _reward(result)
    except candidate.CandidateError:
        issues.add("trial_result_invalid", task=task_id, trial=trial_id)
    result_identity_valid = bool(
        result is not None
        and result.get("task_name") == task_id
        and result.get("trial_name") == trial_id
        and result.get("task_checksum") == digest
        and isinstance(result.get("finished_at"), str)
    )
    if result is not None and not result_identity_valid:
        issues.add("result_identity_invalid", task=task_id, trial=trial_id)
    result_classification = _result_classification(
        result,
        reward,
        identity_valid=result_identity_valid,
    )
    if result is not None and result_classification == "invalid":
        issues.add("trial_result_invalid", task=task_id, trial=trial_id)
    trajectory_required = result_classification == "rewarded"
    durable_runtime_not_started = False
    runtime_entry_path = trial_dir / "agent" / RUNTIME_ENTRY_NAME
    if spec.get("schema_version") == "nano-run-spec-alpha-2":
        try:
            runtime_entry = load_runtime_entry(runtime_entry_path, spec)
            runtime_entry_raw = candidate._read_regular(
                runtime_entry_path, "runtime_entry_invalid"
            )
            _hash_feed(
                hashes,
                f"{trial_id}/agent/{RUNTIME_ENTRY_NAME}",
                runtime_entry_raw,
            )
            if runtime_entry is not None and runtime_entry.terminalization_path:
                terminalization_path = (
                    runtime_entry_path.parent / runtime_entry.terminalization_path
                )
                terminalization_raw = candidate._read_regular(
                    terminalization_path, "runtime_entry_invalid"
                )
                _hash_feed(
                    hashes,
                    f"{trial_id}/agent/{runtime_entry.terminalization_path}",
                    terminalization_raw,
                )
            durable_runtime_not_started = bool(
                runtime_entry is not None and runtime_entry.state == "not_started"
            )
            baseline_raw = candidate._read_regular(
                trial_dir / "agent" / HISTORY_BASELINE_RECEIPT,
                "git_history_receipt_invalid",
            )
            _hash_feed(
                hashes,
                f"{trial_id}/agent/{HISTORY_BASELINE_RECEIPT}",
                baseline_raw,
            )
        except (RuntimeEntryError, candidate.CandidateError):
            issues.add("runtime_entry_invalid", task=task_id, trial=trial_id)
    else:
        durable_runtime_not_started = legacy_runtime_not_started

    runtime_result_contradiction = bool(
        spec.get("schema_version") == "nano-run-spec-alpha-2"
        and durable_runtime_not_started
        and result_classification == "rewarded"
    )
    if runtime_result_contradiction:
        issues.add("runtime_result_contradiction", task=task_id, trial=trial_id)

    marker: Mapping[str, object] | None = None
    marker_binding_valid = False
    artifact_direct = False
    marker_path = trial_dir / "agent" / "agent-run.json"
    try:
        marker, marker_raw = _canonical_json(marker_path, "terminal_marker_invalid")
        _hash_feed(hashes, f"{trial_id}/agent-run.json", marker_raw)
    except candidate.CandidateError:
        if not marker_path.exists() and not marker_path.is_symlink():
            _hash_missing(hashes, f"{trial_id}/agent-run.json")
            if trajectory_required:
                issues.add("terminal_marker_missing", task=task_id, trial=trial_id)
        else:
            issues.add("terminal_marker_invalid", task=task_id, trial=trial_id)

    if marker is not None:
        shape = (marker.get("schema_version"), marker.get("publication_kind"))
        if shape not in _EXPECTED_MARKER_SHAPES:
            issues.add("marker_schema_invalid", task=task_id, trial=trial_id)
        try:
            evidence = tb21._artifact_evidence(trial_dir, spec)
            artifact_direct = evidence.direct_atif_valid
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
        if direct_path.exists() or direct_path.is_symlink():
            issues.add(
                "terminal_direct_trajectory_invalid",
                task=task_id,
                trial=trial_id,
            )
        else:
            _hash_missing(hashes, f"{trial_id}/agent/trajectory.json")
            if trajectory_required:
                issues.add(
                    "terminal_direct_trajectory_missing",
                    task=task_id,
                    trial=trial_id,
                )
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
        if marker is not None:
            marker_binding_valid = bool(
                marker.get("trajectory_path") == "trajectory.json"
                and marker.get("trajectory_sha256")
                == hashlib.sha256(receipt_bytes(trajectory)).hexdigest()
            )
            if not marker_binding_valid:
                issues.add(
                    "direct_trajectory_binding_invalid", task=task_id, trial=trial_id
                )

    marker_present = marker_path.exists() or marker_path.is_symlink()
    trajectory_present = direct_path.exists() or direct_path.is_symlink()
    if trajectory_present and not marker_present:
        issues.add("terminal_marker_missing", task=task_id, trial=trial_id)
    if marker_present and not trajectory_present:
        issues.add("terminal_direct_trajectory_missing", task=task_id, trial=trial_id)

    audit_not_applicable = bool(
        result_classification == "errored"
        and durable_runtime_not_started
        and (
            spec.get("schema_version") == "nano-run-spec-alpha-2"
            or (not marker_present and not trajectory_present)
        )
    )

    audit = _audit_protected_target(
        trial_dir,
        rewarded=bool(reward is not None and reward > 0),
        issues=issues,
        task_id=task_id,
        trial_id=trial_id,
        not_applicable=audit_not_applicable,
        typed_runtime_entry=(spec.get("schema_version") == "nano-run-spec-alpha-2"),
    )
    git_audit = _audit_git_history(
        trial_dir,
        instruction=task.get("instruction") if isinstance(task, dict) else None,
        capability=(
            task.get("git_history_capability") if isinstance(task, dict) else None
        ),
        trusted_manifest_sha256=(
            task.get("digest") if isinstance(task, dict) else None
        ),
        run_spec_sha256=tb21.rust_run_spec_sha256(spec),
        issues=issues,
        task_id=task_id,
        trial_id=trial_id,
        not_applicable=audit_not_applicable,
        typed_runtime_entry=(spec.get("schema_version") == "nano-run-spec-alpha-2"),
    )
    rewarded_atif_eligible = bool(
        result_classification == "rewarded"
        and not runtime_result_contradiction
        and artifact_direct
        and marker_binding_valid
        and version is not None
    )
    return (
        reward,
        result_classification,
        version,
        rewarded_atif_eligible,
        runtime_result_contradiction,
        audit,
        git_audit,
    )


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
    result_classifications: Mapping[str, str],
    rewarded_atif_eligibility: Mapping[str, bool],
    runtime_result_contradictions: Mapping[str, bool],
    audits: Mapping[str, Mapping[str, object]],
    git_audits: Mapping[str, Mapping[str, object]],
    cohort: Mapping[str, object],
    issues: _Issues,
    hashes: list[tuple[str, str]],
    rows: tuple[dict[str, object], ...],
) -> str:
    expected_trials = {str(spec["trial_id"]): spec for spec in specs}
    row_trials = [str(row.get("trial", "")) for row in rows]
    if len(row_trials) != len(set(row_trials)):
        issues.add("collector_duplicate_row")
    if set(row_trials) != set(expected_trials) or len(rows) != len(specs):
        issues.add("collector_inventory_mismatch")
    row_schemas = {row.get("schema_version") for row in rows}
    supported_row_schemas = {tb21.ROW_SCHEMA_V6, tb21.ROW_SCHEMA}
    if len(row_schemas) != 1 or not row_schemas.issubset(supported_row_schemas):
        issues.add("collector_schema_mismatch")
    row_schema = next(iter(row_schemas)) if len(row_schemas) == 1 else None
    for row in rows:
        trial_id = str(row.get("trial", ""))
        spec = expected_trials.get(trial_id)
        schema = row.get("schema_version")
        if schema not in supported_row_schemas:
            issues.add("collector_schema_mismatch", trial=trial_id or None)
        if spec is None:
            continue
        task = spec["task"]
        task_id = str(task["id"])  # type: ignore[index]
        expected_audit = _audit_projection(audits.get(trial_id, {}))
        expected_git_audit = _git_audit_projection(git_audits.get(trial_id, {}))
        runtime_result_contradiction = runtime_result_contradictions.get(
            trial_id, False
        )
        expected_audit["submission_integrity_blocking"] = bool(
            expected_audit.get("submission_integrity_blocking")
            or runtime_result_contradiction
        )
        if (
            row.get("task") != task_id
            or row.get("digest") != task["digest"]  # type: ignore[index]
            or row.get("result_binding_valid") is not True
            or row.get("reward") != rewards.get(trial_id)
        ):
            issues.add("collector_projection_mismatch", task=task_id, trial=trial_id)
        if spec.get("schema_version") == "nano-run-spec-alpha-2":
            try:
                runtime_entry = load_runtime_entry(
                    job_dir / trial_id / "agent" / RUNTIME_ENTRY_NAME,
                    spec,
                )
                expected_runtime_entry = (
                    runtime_entry.state if runtime_entry is not None else "invalid"
                )
            except RuntimeEntryError:
                expected_runtime_entry = "invalid"
            if row.get("runtime_entry_state") != expected_runtime_entry:
                issues.add(
                    "collector_projection_mismatch", task=task_id, trial=trial_id
                )
        reward = rewards.get(trial_id)
        expected_raw = reward is not None
        expected_collector = bool(expected_raw and reward is not None and reward > 0)
        try:
            artifact = tb21._artifact_evidence(job_dir / trial_id, spec)
            expected_success = artifact.success_valid
            expected_direct = artifact.direct_atif_valid
        except (OSError, RuntimeError, TypeError, ValueError):
            expected_success = False
            expected_direct = False
        expected_reliable = bool(
            expected_raw
            and row.get("exception") is None
            and expected_success
            and row.get("result_binding_valid")
            and not runtime_result_contradiction
        )
        if (
            row.get("raw_score_valid") is not expected_raw
            or row.get("collector_pass") is not expected_collector
            or row.get("success_artifact_valid") is not expected_success
            or row.get("reliable") is not expected_reliable
        ):
            issues.add("collector_projection_mismatch", task=task_id, trial=trial_id)
        if schema == tb21.ROW_SCHEMA:
            expected_rewarded = rewarded_atif_eligibility.get(trial_id, False)
            if (
                row.get("direct_atif_valid") is not expected_direct
                or row.get("rewarded_atif_valid") is not expected_rewarded
                or row.get("strict_pass") is not expected_rewarded
            ):
                issues.add(
                    "collector_projection_mismatch", task=task_id, trial=trial_id
                )
        elif schema == tb21.ROW_SCHEMA_V6:
            if (
                "direct_atif_valid" in row
                or "rewarded_atif_valid" in row
                or row.get("strict_pass")
                is not bool(expected_collector and expected_reliable)
            ):
                issues.add(
                    "collector_projection_mismatch", task=task_id, trial=trial_id
                )
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
            issues.add("collector_projection_mismatch", task=task_id, trial=trial_id)
        if any(row.get(key) != value for key, value in expected_audit.items()):
            issues.add("collector_projection_mismatch", task=task_id, trial=trial_id)
        if any(row.get(key) != value for key, value in expected_git_audit.items()):
            issues.add("collector_projection_mismatch", task=task_id, trial=trial_id)

    try:
        summary, summary_raw = _canonical_json(
            job_dir / "summary.json", "collector_malformed"
        )
        _hash_feed(hashes, "summary.json", summary_raw)
    except candidate.CandidateError:
        issues.add("collector_malformed")
        summary = {}
    expected_summary_schema = {
        tb21.ROW_SCHEMA_V6: tb21.SUMMARY_SCHEMA_V6,
        tb21.ROW_SCHEMA: tb21.SUMMARY_SCHEMA,
    }.get(row_schema)
    if summary.get("schema_version") != expected_summary_schema:
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
    strict_passed = sum(row.get("strict_pass") is True for row in rows)
    reliable_rows = sum(row.get("reliable") is True for row in rows)
    collector_passed = sum(row.get("collector_pass") is True for row in rows)
    rewarded_atif_rows = sum(row.get("rewarded_atif_valid") is True for row in rows)
    typed_runtime_authority = any(
        spec.get("schema_version") == "nano-run-spec-alpha-2" for spec in specs
    )
    runtime_result_consistent = not any(runtime_result_contradictions.values())
    if not isinstance(counts, dict) or any(
        counts.get(key) != value
        for key, value in {
            "expected": tb21.TB21_TASK_COUNT,
            "observed": tb21.TB21_TASK_COUNT,
            "passed": strict_passed,
            "reliable": reliable_rows,
            "missing": 0,
            "duplicates": 0,
            "unexpected": 0,
            "retries": 0,
        }.items()
    ):
        issues.add("collector_summary_invalid")
    official_results_valid = all(
        result_classifications.get(trial_id) in {"rewarded", "zero", "errored"}
        for trial_id in expected_trials
    )
    official_numerator = (
        float(
            sum(
                (
                    Decimal(str(reward))
                    for trial_id, reward in rewards.items()
                    if result_classifications.get(trial_id) in {"rewarded", "zero"}
                    and reward is not None
                ),
                Decimal(0),
            )
        )
        if official_results_valid
        else None
    )
    expected_collector_accuracy: dict[str, object] = {
        "numerator": official_numerator,
        "denominator": len(specs),
        "percent": (
            round(100 * official_numerator / len(specs), 6)
            if official_numerator is not None
            else None
        ),
    }
    if not official_results_valid:
        expected_collector_accuracy["availability"] = "unavailable"
    if (
        row_schema == tb21.ROW_SCHEMA
        and summary.get("collector_accuracy") != expected_collector_accuracy
    ):
        issues.add("collector_summary_invalid")
    if row_schema == tb21.ROW_SCHEMA:
        expected_coverage = {
            "numerator": rewarded_atif_rows,
            "denominator": collector_passed,
            "percent": (
                round(100 * rewarded_atif_rows / collector_passed, 6)
                if collector_passed
                else 100.0
            ),
        }
        if (
            summary.get("rewarded_atif_coverage") != expected_coverage
            or not isinstance(gates, dict)
            or gates.get("rewarded_atif")
            is not (rewarded_atif_rows == collector_passed)
            or typed_runtime_authority
            and gates.get("runtime_result_consistency") is not runtime_result_consistent
        ):
            issues.add("collector_summary_invalid")
    elif (
        "rewarded_atif_coverage" in summary
        or isinstance(gates, dict)
        and "rewarded_atif" in gates
    ):
        issues.add("collector_summary_invalid")
    required_true_gates = [
        "job_terminal",
        "exact_inventory",
        "result_identity",
        "collect_idempotent",
        "submission_integrity_clean",
    ]
    if row_schema == tb21.ROW_SCHEMA:
        required_true_gates.extend(("official_results", "rewarded_atif"))
        if typed_runtime_authority:
            required_true_gates.append("runtime_result_consistency")
    if not isinstance(gates, dict) or any(
        gates.get(key) is not True for key in required_true_gates
    ):
        issues.add("collector_summary_invalid")

    # The on-disk rows/summary are the automatic collector output.  Re-read
    # them and independently repeat every agent-only protected-evidence audit
    # for the second collect-only projection.  No pass opens verifier or
    # solution paths.
    first_projection = receipt_bytes(
        {
            "rows": list(rows),
            "summary": dict(summary),
            "audits": dict(audits),
            "git_audits": dict(git_audits),
        }
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
    second_git_audits: dict[str, Mapping[str, object]] = {}
    for spec in specs:
        task = spec["task"]
        task_id = str(task["id"])  # type: ignore[index]
        trial_id = str(spec["trial_id"])
        audit_not_applicable = audits.get(trial_id, {}).get("state") == "not_applicable"
        second_audits[trial_id] = _audit_protected_target(
            job_dir / trial_id,
            rewarded=bool(rewards.get(trial_id, 0) and rewards[trial_id] > 0),
            issues=issues,
            task_id=task_id,
            trial_id=trial_id,
            not_applicable=audit_not_applicable,
            typed_runtime_entry=(spec.get("schema_version") == "nano-run-spec-alpha-2"),
        )
        second_git_audits[trial_id] = _audit_git_history(
            job_dir / trial_id,
            instruction=task.get("instruction"),  # type: ignore[union-attr]
            capability=task.get("git_history_capability"),  # type: ignore[union-attr]
            trusted_manifest_sha256=task.get("digest"),  # type: ignore[union-attr]
            run_spec_sha256=tb21.rust_run_spec_sha256(spec),
            issues=issues,
            task_id=task_id,
            trial_id=trial_id,
            not_applicable=audit_not_applicable,
            typed_runtime_entry=(spec.get("schema_version") == "nano-run-spec-alpha-2"),
        )
    second_projection = receipt_bytes(
        {
            "rows": list(second_rows),
            "summary": dict(second_summary),
            "audits": second_audits,
            "git_audits": second_git_audits,
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

    collector_rows = _read_rows(job_dir / "rows.jsonl", issues=issues, hashes=hashes)
    row_counts: dict[str, int] = {}
    for row in collector_rows:
        trial_id = str(row.get("trial", ""))
        row_counts[trial_id] = row_counts.get(trial_id, 0) + 1
    legacy_not_started_trials = {
        str(row.get("trial"))
        for row in collector_rows
        if row_counts.get(str(row.get("trial", ""))) == 1
        and row.get("runtime_entry_state") == "not_observed"
        and row.get("result_binding_valid") is True
        and row.get("reward") is None
    }

    rewards: dict[str, float | None] = {}
    result_classifications: dict[str, str] = {}
    rewarded_atif_eligibility: dict[str, bool] = {}
    runtime_result_contradictions: dict[str, bool] = {}
    audits: dict[str, Mapping[str, object]] = {}
    git_audits: dict[str, Mapping[str, object]] = {}
    versions: list[str] = []
    for spec in specs:
        trial_id = str(spec["trial_id"])
        (
            reward,
            classification,
            version,
            rewarded_eligible,
            runtime_result_contradiction,
            audit,
            git_audit,
        ) = _scan_trial(
            job_dir,
            spec,
            expectation=expectation,
            require_pinned_harbor=require_pinned_harbor,
            issues=issues,
            hashes=hashes,
            legacy_runtime_not_started=trial_id in legacy_not_started_trials,
        )
        rewards[trial_id] = reward
        result_classifications[trial_id] = classification
        rewarded_atif_eligibility[trial_id] = rewarded_eligible
        runtime_result_contradictions[trial_id] = runtime_result_contradiction
        audits[trial_id] = audit
        git_audits[trial_id] = git_audit
        if version is not None:
            versions.append(version)
    if len(set(versions)) > 1:
        issues.add("mixed_agent_version")

    projection_sha256 = _validate_collector(
        job_dir,
        specs=specs,
        rewards=rewards,
        result_classifications=result_classifications,
        rewarded_atif_eligibility=rewarded_atif_eligibility,
        runtime_result_contradictions=runtime_result_contradictions,
        audits=audits,
        git_audits=git_audits,
        cohort=cohort,
        issues=issues,
        hashes=hashes,
        rows=collector_rows,
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
    if SUBMISSION_PREFLIGHT_SCHEMA != "nano-submission-preflight-v3":
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
