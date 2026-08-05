from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from nano_grok_build.harbor import protected_target, tb21
from scripts import check_v10_candidate as candidate
from scripts import submission_preflight as preflight

R1 = Path(
    "/Users/yahaha/Users/zhimao/tb21-results/surf-harness/"
    "v10-1-75670b6-k5/round-1/jobs/nano-tb21-baseline"
)
R2 = Path(
    "/Users/yahaha/Users/zhimao/tb21-results/surf-harness/"
    "v10-1-75670b6-k5/round-2-rerun-1/jobs/nano-tb21-baseline"
)


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()


def _envelope(manifest: dict[str, object]) -> bytes:
    return _canonical(
        {
            "manifest": manifest,
            "manifest_sha256": hashlib.sha256(_canonical(manifest)).hexdigest(),
        }
    )


def _clean_audit() -> dict[str, object]:
    return {
        "schema_version": protected_target.AUDIT_SCHEMA,
        "policy_schema_version": protected_target.POLICY_SCHEMA,
        "policy_sha256": protected_target.POLICY_SHA256,
        "state": "available",
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


def _clean_git_audit() -> dict[str, object]:
    return {
        "schema_version": tb21.git_history_audit.AUDIT_SCHEMA,
        "finding_schema_version": tb21.git_history_audit.FINDING_SCHEMA,
        "state": "available",
        "history_required": False,
        "evidence_complete": True,
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


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical(value))


def _synthetic_job(tmp_path: Path) -> tuple[Path, preflight.ReleaseExpectation]:
    job = tmp_path / "job"
    job.mkdir()
    checksums = candidate.load_official_checksums(
        Path(__file__).parents[1] / tb21.OFFICIAL_TASK_CHECKSUMS_PATH
    )
    task_ids = tuple(checksums)
    job_id = "00000000-0000-0000-0000-000000000102"
    runtime_git_head = "1" * 40
    runtime_binary_sha256 = "2" * 64
    contract_set_sha256 = "3" * 64
    profile_id = "nano-v1-grok-4-5-high-v1"
    specs: list[dict[str, object]] = []
    cohort_tasks: list[dict[str, object]] = []
    lock_trials: list[dict[str, object]] = []
    rows: list[dict[str, object]] = []
    for index, task_id in enumerate(task_ids):
        trial_id = f"task-{index:02d}__trial"
        spec: dict[str, object] = {
            "schema_version": "nano-run-spec-alpha-1",
            "run_id": f"{job_id}:{trial_id}",
            "trial_id": trial_id,
            "attempt_id": "attempt-0",
            "task": {
                "id": task_id,
                "digest": checksums[task_id],
                "instruction": "Synthetic submission preflight fixture.",
            },
            "contract": {
                "id": "nano-v1",
                "contract_set_sha256": contract_set_sha256,
                "profile_id": profile_id,
            },
            "provider": {
                "kind": "xai",
                "model": "grok-4.5",
                "max_turns": 64,
                "retry_max": 0,
            },
            "workspace_dir": "/workspace",
            "artifact_dir": f"/jobs/{trial_id}/.nano-control-v2",
            "agent_timeout_sec": 900,
            "active_tools": list(tb21.ACTIVE_TOOLS),
        }
        specs.append(spec)
        resource = {
            "docker_image": f"example.invalid/{index}:pinned",
            "cpus": 1,
            "memory_mb": 2048,
            "storage_mb": 10240,
            "gpus": 0,
        }
        cohort_tasks.append(
            {
                "task_id": task_id,
                "task_digest": checksums[task_id],
                "source_task_digest": f"{index:064x}",
                "source_sha256": f"{index + 89:064x}",
                "trial_id": trial_id,
                "run_spec_sha256": tb21.rust_run_spec_sha256(spec),
                "resources": resource,
            }
        )
        lock_trials.append(
            {
                "schema_version": 1,
                "task": {
                    "name": task_id,
                    "type": "package",
                    "digest": f"sha256:{index + 178:064x}",
                    "source": tb21.TB21_DATASET,
                },
                "install_only": False,
                "timeout_multiplier": 1.0,
                "agent": {
                    "name": "nano-grok-build",
                    "import_path": (
                        "nano_grok_build.adapter.harbor:NanoGrokBuildAgent"
                    ),
                    "model_name": "xai/grok-4.5",
                    "skills": [],
                    "resume_trajectory": False,
                    "extra_allowed_hosts": [],
                    "kwargs": {
                        "binary_path": "/release/nano-cli",
                        "contract_dir": "/release/contracts/nano-v1",
                        "provider_launch": {"kind": "xai"},
                        "run_spec": spec,
                        "deadline_mode": "harbor-root-v1",
                        "reasoning_effort": "high",
                    },
                    "mcp_servers": [],
                },
                "skills": [],
                "environment": {
                    "type": "docker",
                    "force_build": False,
                    "delete": True,
                    "cpu_enforcement_policy": "auto",
                    "memory_enforcement_policy": "auto",
                    "extra_docker_compose": [],
                    "kwargs": {},
                    "extra_allowed_hosts": [],
                },
                "verifier": {"disable": False},
            }
        )
        events_sha256 = f"{index + 267:064x}"
        trajectory = {
            "schema_version": "ATIF-v1.7",
            "session_id": spec["run_id"],
            "agent": {
                "name": "nano-grok-build",
                "version": "0.3.0",
                "model_name": "grok-4.5",
            },
            "steps": [
                {"step_id": 1, "source": "user", "message": "Synthetic task."},
                {
                    "step_id": 2,
                    "source": "agent",
                    "model_name": "grok-4.5",
                    "message": "done",
                    "llm_call_count": 1,
                },
            ],
            "final_metrics": {
                "total_prompt_tokens": 1,
                "total_completion_tokens": 1,
                "total_cached_tokens": 0,
                "total_steps": 2,
            },
            "extra": {
                "trial_id": trial_id,
                "attempt_id": "attempt-0",
                "run_spec_sha256": tb21.rust_run_spec_sha256(spec),
                "events_sha256": events_sha256,
            },
        }
        trajectory_raw = _canonical(trajectory)
        agent_dir = job / trial_id / "agent"
        agent_dir.mkdir(parents=True)
        (agent_dir / "trajectory.json").write_bytes(trajectory_raw)
        _write_json(
            agent_dir / "agent-run.json",
            {
                "schema_version": "nano-agent-run-v3",
                "publication_kind": "success_atif",
                "run_id": spec["run_id"],
                "trial_id": trial_id,
                "attempt_id": "attempt-0",
                "run_spec_sha256": tb21.rust_run_spec_sha256(spec),
                "run_record_schema": "nano-run-record-v3",
                "events_sha256": events_sha256,
                "terminal_status": "success",
                "terminal_phase": None,
                "terminal_code": "completed",
                "trajectory_path": "trajectory.json",
                "trajectory_sha256": hashlib.sha256(trajectory_raw).hexdigest(),
                "usage_receipt_sha256": "4" * 64,
                "deadline_receipt_sha256": "5" * 64,
            },
        )
        _write_json(
            job / trial_id / "result.json",
            {
                "task_name": task_id,
                "trial_name": trial_id,
                "task_checksum": checksums[task_id],
                "verifier_result": {"rewards": {"reward": 1.0}},
                "exception_info": None,
                "started_at": "2026-08-03T00:00:00Z",
                "finished_at": "2026-08-03T00:00:01Z",
            },
        )
        audit = _clean_audit()
        git_audit = _clean_git_audit()
        rows.append(
            {
                "schema_version": tb21.ROW_SCHEMA,
                "task": task_id,
                "trial": trial_id,
                "digest": checksums[task_id],
                "reward": 1.0,
                "result_binding_valid": True,
                "publication_kind": "success_atif",
                "contamination_audit_state": audit["state"],
                "contamination_signals": audit["signals"],
                "contamination_signal": False,
                "protected_target_audit_schema": audit["schema_version"],
                "protected_target_policy_schema": audit["policy_schema_version"],
                "protected_target_policy_sha256": audit["policy_sha256"],
                "protected_target_counts": audit["counts"],
                "protected_target_findings": audit["findings"],
                "submission_integrity_blocking": False,
                "submission_integrity_blocking_count": 0,
                "submission_integrity_warning_count": 0,
                "git_history_audit_schema": git_audit["schema_version"],
                "git_history_finding_schema": git_audit["finding_schema_version"],
                "git_history_audit_state": git_audit["state"],
                "git_history_required": git_audit["history_required"],
                "git_history_evidence_complete": git_audit["evidence_complete"],
                "git_history_findings": git_audit["findings"],
                "git_history_counts": git_audit["counts"],
                "git_history_submission_blocking": git_audit["submission_blocking"],
            }
        )

    dispatch = {
        "schema_version": "nano-harbor-dispatch-v1",
        "harbor_version": "0.20.0",
        "job_id": job_id,
        "retry_max": 0,
        "n_attempts": 1,
        "run_specs": specs,
    }
    (job / "nano-dispatch.json").write_bytes(_envelope(dispatch))
    cohort = {
        "schema_version": tb21.COHORT_SCHEMA,
        "label": "full-eight-tool internal diagnostic; not a leaderboard claim",
        "dataset": tb21.TB21_DATASET,
        "dataset_ref": tb21.TB21_DATASET_REF,
        "source_commit": tb21.TB21_SOURCE_COMMIT,
        "harbor_commit": tb21.HARBOR_COMMIT,
        "job_id": job_id,
        "job_name": "nano-tb21-baseline",
        "n_attempts": 1,
        "retry_max": 0,
        "concurrency": 2,
        "active_tools": list(tb21.ACTIVE_TOOLS),
        "runtime": {
            "git_head": runtime_git_head,
            "source_sha256": "6" * 64,
            "binary_sha256": runtime_binary_sha256,
            "contract_set_sha256": contract_set_sha256,
            "profile_id": profile_id,
            "model": "grok-4.5",
            "max_provider_turns": 64,
        },
        "tasks": cohort_tasks,
    }
    (job / "nano-tb21-cohort.json").write_bytes(_envelope(cohort))
    _write_json(
        job / "config.json",
        {
            "job_name": "nano-tb21-baseline",
            "jobs_dir": "/jobs",
            "n_concurrent_trials": 2,
            "quiet": True,
            "agents": [
                {
                    "name": "nano-grok-build",
                    "import_path": (
                        "nano_grok_build.adapter.harbor:NanoGrokBuildAgent"
                    ),
                    "model_name": "xai/grok-4.5",
                    "kwargs": {"reasoning_effort": "high"},
                }
            ],
            "datasets": [
                {
                    "name": tb21.TB21_DATASET,
                    "ref": tb21.TB21_DATASET_REF,
                    "task_names": list(task_ids),
                }
            ],
        },
    )
    _write_json(
        job / "lock.json",
        {
            "schema_version": 2,
            "created_at": "2026-08-03T00:00:00Z",
            "harbor": {
                "version": "0.20.0",
                "git_commit_hash": tb21.HARBOR_COMMIT,
                "is_editable": True,
            },
            "n_concurrent_trials": 2,
            "retry": {
                "max_retries": 0,
                "exclude_exceptions": [],
                "wait_multiplier": 1.0,
                "min_wait_sec": 1.0,
                "max_wait_sec": 60.0,
            },
            "trials": lock_trials,
        },
    )
    _write_json(
        job / "result.json",
        {
            "id": job_id,
            "started_at": "2026-08-03T00:00:00Z",
            "updated_at": "2026-08-03T00:01:00Z",
            "finished_at": "2026-08-03T00:01:00Z",
            "n_total_trials": 89,
            "stats": {
                "n_completed_trials": 89,
                "n_errored_trials": 0,
                "n_running_trials": 0,
                "n_pending_trials": 0,
                "n_cancelled_trials": 0,
                "n_retries": 0,
            },
        },
    )
    (job / "rows.jsonl").write_bytes(b"".join(_canonical(row) for row in rows))
    _write_json(
        job / "summary.json",
        {
            "schema_version": tb21.SUMMARY_SCHEMA,
            "pins": {
                "dataset": tb21.TB21_DATASET,
                "dataset_ref": tb21.TB21_DATASET_REF,
                "source_commit": tb21.TB21_SOURCE_COMMIT,
                "harbor_commit": tb21.HARBOR_COMMIT,
                "runtime_git_head": runtime_git_head,
                "runtime_binary_sha256": runtime_binary_sha256,
                "contract_set_sha256": contract_set_sha256,
                "model": "grok-4.5",
                "max_provider_turns": 64,
                "active_tools": list(tb21.ACTIVE_TOOLS),
            },
            "cohort": {"job_id": job_id, "n_attempts": 1, "retry_max": 0},
            "counts": {
                "expected": 89,
                "observed": 89,
                "missing": 0,
                "duplicates": 0,
                "unexpected": 0,
                "retries": 0,
            },
            "gates": {
                "job_terminal": True,
                "exact_inventory": True,
                "result_identity": True,
                "collect_idempotent": True,
                "contamination_clean": True,
                "submission_integrity_clean": True,
                "git_history_integrity_clean": True,
            },
            "contamination": {
                "schema_version": protected_target.AUDIT_SCHEMA,
                "finding_schema_version": protected_target.FINDING_SCHEMA,
                "policy_schema_version": protected_target.POLICY_SCHEMA,
                "policy_sha256": protected_target.POLICY_SHA256,
                "audit_available": 89,
                "audit_denominator": 89,
                "finding_trial_count": 0,
                "finding_counts": _clean_audit()["counts"],
            },
        },
    )
    return job, preflight.ReleaseExpectation(
        agent_version="0.3.0",
        runtime_git_head=runtime_git_head,
        runtime_binary_sha256=runtime_binary_sha256,
        contract_set_sha256=contract_set_sha256,
    )


@pytest.fixture
def valid_artifacts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        tb21,
        "_artifact_evidence",
        lambda _trial, _spec: SimpleNamespace(
            publication_valid=True,
            trajectory_valid=True,
            diagnostic_valid=True,
            publication_kind="success_atif",
            terminal_status="success",
            terminal_phase=None,
            terminal_code="completed",
        ),
    )


def _codes(receipt: dict[str, object]) -> set[str]:
    return {str(issue["code"]) for job in receipt["jobs"] for issue in job["issues"]}


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_clean_job_is_read_only_and_receipt_is_byte_stable(
    tmp_path: Path,
    valid_artifacts: None,
) -> None:
    job, expectation = _synthetic_job(tmp_path)
    before = _tree_hashes(job)

    first = preflight.audit_jobs(
        (job,), expectation=expectation, require_pinned_harbor=False
    )
    second = preflight.audit_jobs(
        (job,), expectation=expectation, require_pinned_harbor=False
    )

    assert first["status"] == "passed"
    assert first["submit_ready"] is True
    assert first["jobs"][0]["trial_count"] == 89
    assert preflight.receipt_bytes(first) == preflight.receipt_bytes(second)
    assert _tree_hashes(job) == before


def test_ordinary_terminal_error_remains_in_denominator_and_is_not_replaced(
    tmp_path: Path,
    valid_artifacts: None,
) -> None:
    job, expectation = _synthetic_job(tmp_path)
    trial_id = "task-00__trial"
    result_path = job / trial_id / "result.json"
    result = json.loads(result_path.read_bytes())
    result["verifier_result"] = None
    result["exception_info"] = {"exception_type": "VerifierTimeoutError"}
    result_path.write_bytes(_canonical(result))
    rows_path = job / "rows.jsonl"
    rows = [json.loads(line) for line in rows_path.read_bytes().splitlines()]
    rows[0]["reward"] = None
    rows_path.write_bytes(b"".join(_canonical(row) for row in rows))

    receipt = preflight.audit_jobs(
        (job,), expectation=expectation, require_pinned_harbor=False
    )

    assert receipt["status"] == "passed"
    assert receipt["jobs"][0]["trial_count"] == 89


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("missing_direct", "rewarded_direct_trajectory_missing"),
        ("retry", "unexpected_retry"),
        ("duplicate_row", "collector_duplicate_row"),
        ("mixed_version", "agent_version_mismatch"),
        ("marker_schema", "marker_schema_invalid"),
        ("missing_marker", "terminal_marker_missing"),
        ("malformed_collector", "collector_malformed"),
    ],
)
def test_dirty_jobs_fail_closed(
    tmp_path: Path,
    valid_artifacts: None,
    mutation: str,
    expected_code: str,
) -> None:
    job, expectation = _synthetic_job(tmp_path)
    first_trial = "task-00__trial"
    if mutation == "missing_direct":
        (job / first_trial / "agent" / "trajectory.json").unlink()
    elif mutation == "retry":
        result_path = job / "result.json"
        result = json.loads(result_path.read_bytes())
        result["stats"]["n_retries"] = 1
        result_path.write_bytes(_canonical(result))
    elif mutation == "duplicate_row":
        rows_path = job / "rows.jsonl"
        rows_path.write_bytes(
            rows_path.read_bytes() + rows_path.read_bytes().splitlines(True)[0]
        )
    elif mutation == "mixed_version":
        trajectory_path = job / first_trial / "agent" / "trajectory.json"
        trajectory = json.loads(trajectory_path.read_bytes())
        trajectory["agent"]["version"] = "0.2.1"
        trajectory_path.write_bytes(_canonical(trajectory))
        marker_path = job / first_trial / "agent" / "agent-run.json"
        marker = json.loads(marker_path.read_bytes())
        marker["trajectory_sha256"] = hashlib.sha256(
            trajectory_path.read_bytes()
        ).hexdigest()
        marker_path.write_bytes(_canonical(marker))
    elif mutation == "marker_schema":
        marker_path = job / first_trial / "agent" / "agent-run.json"
        marker = json.loads(marker_path.read_bytes())
        marker["schema_version"] = "nano-agent-run-v99"
        marker_path.write_bytes(_canonical(marker))
    elif mutation == "missing_marker":
        (job / first_trial / "agent" / "agent-run.json").unlink()
    else:
        (job / "rows.jsonl").write_bytes(b"{\n")

    receipt = preflight.audit_jobs(
        (job,), expectation=expectation, require_pinned_harbor=False
    )

    assert receipt["status"] == "failed"
    assert receipt["submit_ready"] is False
    assert expected_code in _codes(receipt)


@pytest.mark.parametrize(
    ("classification", "access_blocked", "expected_code"),
    [
        ("strong", False, "protected_target_strong"),
        ("attempted", False, None),
        ("access_blocked", True, None),
    ],
)
def test_protected_target_projection_only_blocks_actual_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    classification: str,
    access_blocked: bool,
    expected_code: str | None,
) -> None:
    def classified(_trial_dir: Path, *, rewarded: bool = False) -> dict[str, object]:
        audit = _clean_audit()
        audit["signals"] = [f"synthetic_{classification}"]
        finding = {
            "schema_version": protected_target.FINDING_SCHEMA,
            "classification": classification,
            "call_id": "call-0",
            "tool_name": "read_file",
            "target_kind": "protected_path",
            "target_field": "path",
            "policy_value": "/logs",
            "attempted": True,
            "dispatched": classification == "strong",
            "bytes_returned": classification == "strong",
            "causal_benefit": bool(rewarded and classification == "strong"),
            "access_blocked": access_blocked,
            "evidence_sources": [
                {"kind": "atif", "path": "trajectory.json", "sha256": "a" * 64}
            ],
        }
        audit["findings"] = [finding]
        audit["counts"] = {
            **audit["counts"],
            "findings": 1,
            classification: 1,
            "dispatched": int(classification == "strong"),
            "bytes_returned": int(classification == "strong"),
            "causal_benefit": int(rewarded and classification == "strong"),
        }
        return audit

    monkeypatch.setattr(tb21, "_contamination_audit", classified)
    issues = preflight._Issues()
    audit = preflight._audit_protected_target(
        tmp_path,
        rewarded=True,
        issues=issues,
        task_id="terminal-bench/synthetic",
        trial_id="synthetic__trial",
    )

    codes = {str(row["code"]) for row in issues.values()}
    assert audit["findings"]
    if expected_code is None:
        assert not codes
    else:
        assert expected_code in codes


def test_blocked_before_dispatch_is_disclosed_and_submission_ready(
    tmp_path: Path,
    valid_artifacts: None,
) -> None:
    job, expectation = _synthetic_job(tmp_path)
    trial_id = "task-00__trial"
    agent_dir = job / trial_id / "agent"
    events = b"".join(
        _canonical(event)
        for event in (
            {
                "type": "tool.registered",
                "data": {
                    "call_id": "call-blocked",
                    "provider_name": "run_terminal_command",
                    "arguments_json": json.dumps({"command": "ls /logs"}),
                },
            },
            {
                "type": "tool.failed",
                "data": {
                    "call_id": "call-blocked",
                    "provider_name": "run_terminal_command",
                    "code": protected_target.BLOCKED_CODE,
                },
            },
        )
    )
    runtime = agent_dir / "runtime"
    runtime.mkdir()
    (runtime / "events.jsonl").write_bytes(events)
    marker_path = agent_dir / "agent-run.json"
    marker = json.loads(marker_path.read_bytes())
    marker["events_sha256"] = hashlib.sha256(events).hexdigest()
    marker_path.write_bytes(_canonical(marker))

    audit = protected_target.audit_trial(job / trial_id, rewarded=True)
    assert audit["findings"][0]["classification"] == "access_blocked"
    rows_path = job / "rows.jsonl"
    rows = [json.loads(line) for line in rows_path.read_bytes().splitlines()]
    rows[0].update(preflight._audit_projection(audit))
    rows_path.write_bytes(b"".join(_canonical(row) for row in rows))
    summary_path = job / "summary.json"
    summary = json.loads(summary_path.read_bytes())
    summary["gates"]["contamination_clean"] = False
    summary["gates"]["submission_integrity_clean"] = True
    summary_path.write_bytes(_canonical(summary))

    receipt = preflight.audit_jobs(
        (job,), expectation=expectation, require_pinned_harbor=False
    )

    assert receipt["status"] == "passed"
    assert receipt["submit_ready"] is True
    assert not _codes(receipt)


def test_actual_git_history_bytes_fail_submission_preflight(
    tmp_path: Path,
    valid_artifacts: None,
) -> None:
    job, expectation = _synthetic_job(tmp_path)
    trial_id = "task-00__trial"
    trajectory_path = job / trial_id / "agent" / "trajectory.json"
    trajectory = json.loads(trajectory_path.read_bytes())
    trajectory["steps"].append(
        {
            "step_id": len(trajectory["steps"]) + 1,
            "source": "agent",
            "message": "",
            "tool_calls": [
                {
                    "tool_call_id": "history-call",
                    "function_name": "run_terminal_command",
                    "arguments": {"command": "git log -p -1"},
                }
            ],
            "observation": {
                "results": [
                    {"source_call_id": "history-call", "content": "history bytes"}
                ]
            },
        }
    )
    trajectory_path.write_bytes(_canonical(trajectory))
    marker_path = job / trial_id / "agent" / "agent-run.json"
    marker = json.loads(marker_path.read_bytes())
    marker["trajectory_sha256"] = hashlib.sha256(
        trajectory_path.read_bytes()
    ).hexdigest()
    marker_path.write_bytes(_canonical(marker))
    audit = tb21.git_history_audit.audit_trial(
        job / trial_id, instruction="Synthetic submission preflight fixture."
    )
    rows_path = job / "rows.jsonl"
    rows = [json.loads(line) for line in rows_path.read_bytes().splitlines()]
    rows[0].update(preflight._git_audit_projection(audit))
    rows_path.write_bytes(b"".join(_canonical(row) for row in rows))
    summary_path = job / "summary.json"
    summary = json.loads(summary_path.read_bytes())
    summary["gates"]["submission_integrity_clean"] = False
    summary["gates"]["git_history_integrity_clean"] = False
    summary_path.write_bytes(_canonical(summary))

    receipt = preflight.audit_jobs(
        (job,), expectation=expectation, require_pinned_harbor=False
    )

    assert receipt["submit_ready"] is False
    assert "git_history_oracle_access" in _codes(receipt)


def test_split_protected_target_attempt_fails_submission_preflight(
    tmp_path: Path,
    valid_artifacts: None,
) -> None:
    job, expectation = _synthetic_job(tmp_path)
    trial_id = "task-00__trial"
    trajectory_path = job / trial_id / "agent" / "trajectory.json"
    trajectory = json.loads(trajectory_path.read_bytes())
    trajectory["steps"].append(
        {
            "step_id": 3,
            "source": "agent",
            "model_name": "grok-4.5",
            "message": "",
            "tool_calls": [
                {
                    "tool_call_id": "call-protected-split",
                    "function_name": "run_terminal_command",
                    "arguments": {
                        "command": 'p=/logs; cat "$p/agent/input/run-spec.json"'
                    },
                }
            ],
            "observation": {
                "results": [
                    {
                        "source_call_id": "call-protected-split",
                        "content": "ordinary command failure",
                    }
                ]
            },
        }
    )
    trajectory_path.write_bytes(_canonical(trajectory))
    marker_path = job / trial_id / "agent" / "agent-run.json"
    marker = json.loads(marker_path.read_bytes())
    marker["trajectory_sha256"] = hashlib.sha256(
        trajectory_path.read_bytes()
    ).hexdigest()
    marker_path.write_bytes(_canonical(marker))

    receipt = preflight.audit_jobs(
        (job,), expectation=expectation, require_pinned_harbor=False
    )

    assert receipt["status"] == "failed"
    assert receipt["submit_ready"] is False
    assert "protected_target_strong" in _codes(receipt)


@pytest.mark.skipif(not R1.is_dir() or not R2.is_dir(), reason="frozen V10.1 absent")
def test_frozen_v10_1_rounds_fail_for_known_self_log_and_direct_atif_gaps() -> None:
    expectation = preflight.ReleaseExpectation(
        agent_version="0.1.0",
        runtime_git_head="75670b62bbb1b8dd8a7d67fc246839154b58eedf",
        runtime_binary_sha256=(
            "7ef143453b8051817fe9bad89951a14f332033af48c41eccabf172963cccd886"
        ),
        contract_set_sha256=(
            "5556083eb942a3f438538f7bc5b153afa0f7760fe2e4ccd365dec5b95f9d2288"
        ),
    )

    receipt = preflight.audit_jobs(
        (R1, R2), expectation=expectation, require_pinned_harbor=False
    )

    codes = _codes(receipt)
    assert receipt["status"] == "failed"
    assert "protected_target_strong" in codes
    assert "rewarded_direct_trajectory_missing" in codes
    assert "collector_schema_mismatch" in codes


def test_static_contract_documents_read_only_cli() -> None:
    errors = preflight.static_errors(Path(__file__).parents[1])

    assert errors == []
