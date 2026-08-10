from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from nano_grok_build.adapter.artifactizer import canonical_json, publish_artifacts
from nano_grok_build.harbor import protected_target, tb21
from nano_grok_build.harbor.git_history_capability import (
    compile_git_history_capability,
)
from nano_grok_build.harbor.git_history_receipt import (
    HISTORY_BASELINE_POLICY,
    HISTORY_BASELINE_RECEIPT,
    HISTORY_BASELINE_SCHEMA,
)
from nano_grok_build.harbor.runtime_entry import (
    RUNTIME_ENTRY_NAME,
    write_not_started,
    write_started,
)
from scripts import check_v10_candidate as candidate
from scripts import submission_preflight as preflight


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


def _not_applicable_audit() -> dict[str, object]:
    audit = _clean_audit()
    audit["state"] = "not_applicable"
    return audit


def _not_applicable_git_audit() -> dict[str, object]:
    audit = _clean_git_audit()
    audit["state"] = "not_applicable"
    audit["evidence_complete"] = False
    return audit


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
                "version": "0.5.7",
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
                "raw_score_valid": True,
                "collector_pass": True,
                "strict_pass": True,
                "reliable": True,
                "result_binding_valid": True,
                "publication_kind": "success_atif",
                "success_artifact_valid": True,
                "direct_atif_valid": True,
                "rewarded_atif_valid": True,
                "exception": None,
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
                "passed": 89,
                "reliable": 89,
                "missing": 0,
                "duplicates": 0,
                "unexpected": 0,
                "retries": 0,
            },
            "gates": {
                "job_terminal": True,
                "exact_inventory": True,
                "result_identity": True,
                "official_results": True,
                "collect_idempotent": True,
                "contamination_clean": True,
                "submission_integrity_clean": True,
                "git_history_integrity_clean": True,
                "rewarded_atif": True,
            },
            "collector_accuracy": {
                "numerator": 89.0,
                "denominator": 89,
                "percent": 100.0,
            },
            "rewarded_atif_coverage": {
                "numerator": 89,
                "denominator": 89,
                "percent": 100.0,
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
        agent_version="0.5.7",
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
            success_valid=True,
            direct_atif_valid=True,
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


def _missing_artifact_projection(trial_id: str):
    def evidence(trial: Path, _spec: object) -> SimpleNamespace:
        present = trial.name != trial_id
        return SimpleNamespace(
            publication_valid=present,
            trajectory_valid=present,
            diagnostic_valid=present,
            success_valid=present,
            direct_atif_valid=present,
            publication_kind="success_atif" if present else None,
            terminal_status="success" if present else None,
            terminal_phase=None,
            terminal_code="completed" if present else None,
        )

    return evidence


def _project_one_nonrewarded_summary(job: Path) -> None:
    summary_path = job / "summary.json"
    summary = json.loads(summary_path.read_bytes())
    summary["counts"]["passed"] = 88
    summary["counts"]["reliable"] = 88
    summary["rewarded_atif_coverage"] = {
        "numerator": 88,
        "denominator": 88,
        "percent": 100.0,
    }
    summary["collector_accuracy"] = {
        "numerator": 88.0,
        "denominator": 89,
        "percent": round(100 * 88 / 89, 6),
    }
    summary_path.write_bytes(_canonical(summary))


def _write_pipeline_baseline(agent: Path, spec: dict[str, object]) -> None:
    task = spec["task"]
    assert isinstance(task, dict)
    capability = task["git_history_capability"]
    assert isinstance(capability, dict)
    tree = "1" * 40
    _write_json(
        agent / "git-history-baseline.json",
        {
            "schema_version": HISTORY_BASELINE_SCHEMA,
            "policy_version": HISTORY_BASELINE_POLICY,
            "run_spec_sha256": tb21.rust_run_spec_sha256(spec),
            "capability_instruction_sha256": capability["canonical_instruction_sha256"],
            "trusted_manifest_sha256": capability["trusted_manifest_sha256"],
            "topology_before": "zero",
            "topology_after": "root",
            "admitted_repo_relative_path": ".",
            "status": "created",
            "census_before_sha256": "4" * 64,
            "census_after_sha256": "5" * 64,
            "filesystem_manifest_before_sha256": "6" * 64,
            "filesystem_manifest_after_sha256": "6" * 64,
            "source_commit_oid": None,
            "source_tree_oid": None,
            "root_commit_oid": "3" * 40,
            "root_tree_oid": tree,
            "preexisting_commit_count": 0,
            "root_commit_count": 1,
            "ref_count": 1,
            "remote_count": 0,
            "alternate_count": 0,
            "old_metadata_removed": False,
        },
    )


def _write_pipeline_success(agent: Path, spec: dict[str, object]) -> None:
    runtime = agent / "runtime"
    runtime.mkdir()
    bodies = [
        (
            "run.started",
            {
                "task_id": spec["task"]["id"],  # type: ignore[index]
                "contract_id": spec["contract"]["id"],  # type: ignore[index]
                "profile_id": spec["contract"]["profile_id"],  # type: ignore[index]
                "contract_set_sha256": spec["contract"][  # type: ignore[index]
                    "contract_set_sha256"
                ],
                "model": spec["provider"]["model"],  # type: ignore[index]
                "run_spec_sha256": tb21.rust_run_spec_sha256(spec),
            },
        ),
        (
            "provider.requested",
            {
                "turn_index": 0,
                "history_item_count": 2,
                "tool_count": len(tb21.ACTIVE_TOOLS),
                "function_output_call_ids": [],
            },
        ),
        (
            "provider.completed",
            {
                "turn_index": 0,
                "response_id": "response-1",
                "model": "grok-4.5",
                "call_ids": [],
                "has_final_text": True,
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 2,
                    "input_tokens_details": {"cached_tokens": 1},
                },
            },
        ),
        ("assistant.final", {"text": "Done."}),
        ("run.completed", {"code": "completed"}),
    ]
    event_raw = b"".join(
        canonical_json(
            {
                "schema_version": "event-v2",
                "run_id": spec["run_id"],
                "trial_id": spec["trial_id"],
                "attempt_id": spec["attempt_id"],
                "seq": sequence,
                "elapsed_ms": sequence,
                "type": event_type,
                "data": data,
            }
        )
        for sequence, (event_type, data) in enumerate(bodies)
    )
    (runtime / "events.jsonl").write_bytes(event_raw)
    _write_json(
        runtime / "run.json",
        {
            "schema_version": "nano-run-record-v2",
            "run_id": spec["run_id"],
            "trial_id": spec["trial_id"],
            "attempt_id": spec["attempt_id"],
            "run_spec_sha256": tb21.rust_run_spec_sha256(spec),
            "contract_id": spec["contract"]["id"],  # type: ignore[index]
            "contract_set_sha256": spec["contract"][  # type: ignore[index]
                "contract_set_sha256"
            ],
            "profile_id": spec["contract"]["profile_id"],  # type: ignore[index]
            "terminal_status": "success",
            "terminal_phase": None,
            "terminal_code": "completed",
            "final_event_seq": len(bodies) - 1,
            "provider_turn_count": 1,
            "tool_call_count": 0,
            "provider_call_coverage": {
                "requested": 1,
                "completed": 1,
                "failed": 0,
                "in_flight": 0,
                "usage_present": 1,
                "usage_absent": 0,
                "usage_covered": 1,
                "cost_present": 0,
                "cost_absent": 1,
                "state": "complete",
            },
            "usage_totals": {
                "input_tokens": 10,
                "cached_input_tokens": 1,
                "output_tokens": 2,
                "provider_cost_ticks": None,
            },
            "start_elapsed_ms": 0,
            "end_elapsed_ms": len(bodies) - 1,
            "events_sha256": hashlib.sha256(event_raw).hexdigest(),
        },
    )
    publish_artifacts(
        logs_dir=agent,
        run_spec=spec,
        instruction=str(spec["task"]["instruction"]),  # type: ignore[index]
        agent_name="nano-grok-build",
        agent_version="0.5.7",
        model_name="grok-4.5",
        require_harbor_validator=True,
    )


def _production_pipeline_job(
    tmp_path: Path,
) -> tuple[Path, preflight.ReleaseExpectation, tuple[dict[str, object], ...]]:
    job, expectation = _synthetic_job(tmp_path)
    dispatch_path = job / "nano-dispatch.json"
    dispatch = json.loads(dispatch_path.read_bytes())["manifest"]
    specs = dispatch["run_specs"]
    for spec in specs:
        spec["schema_version"] = "nano-run-spec-alpha-2"
        task = spec["task"]
        task["git_history_capability"] = compile_git_history_capability(
            task["instruction"], task["digest"]
        )
    dispatch_path.write_bytes(_envelope(dispatch))

    cohort_path = job / "nano-tb21-cohort.json"
    cohort = json.loads(cohort_path.read_bytes())["manifest"]
    cohort_by_trial = {row["trial_id"]: row for row in cohort["tasks"]}
    for spec in specs:
        cohort_by_trial[spec["trial_id"]]["run_spec_sha256"] = (
            tb21.rust_run_spec_sha256(spec)
        )
    cohort_path.write_bytes(_envelope(cohort))

    lock_path = job / "lock.json"
    lock = json.loads(lock_path.read_bytes())
    for trial, spec in zip(lock["trials"], specs, strict=True):
        trial["agent"]["kwargs"]["run_spec"] = spec
    lock_path.write_text(json.dumps(lock, indent=2))

    for index, spec in enumerate(specs):
        trial_dir = job / spec["trial_id"]
        agent = trial_dir / "agent"
        shutil.rmtree(agent)
        agent.mkdir()
        _write_pipeline_baseline(agent, spec)
        if index == 2:
            result_path = trial_dir / "result.json"
            result = json.loads(result_path.read_bytes())
            result["verifier_result"] = None
            result["exception_info"] = {
                "exception_type": "BridgeError",
                "exception_message": "deadline_before_dispatch",
            }
            result_path.write_bytes(_canonical(result))
            emergency_path = agent / "runtime-emergency.json"
            _write_json(
                emergency_path,
                {
                    "schema_version": "nano-runtime-emergency-v1",
                    "run_id": spec["run_id"],
                    "trial_id": spec["trial_id"],
                    "attempt_id": spec["attempt_id"],
                    "run_spec_sha256": tb21.rust_run_spec_sha256(spec),
                    "status": "runtime_record_missing",
                    "code": "deadline_before_dispatch",
                    "bridge_completed": False,
                    "events_sha256": None,
                    "events_byte_length": None,
                },
            )
            write_not_started(
                agent,
                spec,
                terminalization_path=emergency_path,
                terminal_code="deadline_before_dispatch",
            )
            publish_artifacts(
                logs_dir=agent,
                run_spec=spec,
                instruction=str(spec["task"]["instruction"]),  # type: ignore[index]
                agent_name="nano-grok-build",
                agent_version="0.5.7",
                model_name="grok-4.5",
                require_harbor_validator=True,
            )
        else:
            write_started(agent, spec)
            _write_pipeline_success(agent, spec)
    root_result_path = job / "result.json"
    root_result = json.loads(root_result_path.read_bytes())
    root_result["stats"]["n_errored_trials"] = 1
    root_result_path.write_bytes(_canonical(root_result))
    tb21.collect_job(job)
    return job, expectation, tuple(specs)


@pytest.mark.parametrize("schema", [tb21.ROW_SCHEMA_V6, tb21.ROW_SCHEMA])
def test_clean_job_is_read_only_and_receipt_is_byte_stable(
    tmp_path: Path,
    valid_artifacts: None,
    schema: str,
) -> None:
    job, expectation = _synthetic_job(tmp_path)
    if schema == tb21.ROW_SCHEMA_V6:
        rows_path = job / "rows.jsonl"
        rows = [json.loads(line) for line in rows_path.read_bytes().splitlines()]
        for row in rows:
            row["schema_version"] = schema
            row.pop("direct_atif_valid")
            row.pop("rewarded_atif_valid")
        rows_path.write_bytes(b"".join(_canonical(row) for row in rows))
        summary_path = job / "summary.json"
        summary = json.loads(summary_path.read_bytes())
        summary["schema_version"] = tb21.SUMMARY_SCHEMA_V6
        summary.pop("rewarded_atif_coverage")
        summary["gates"].pop("rewarded_atif")
        summary_path.write_bytes(_canonical(summary))
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


@pytest.fixture
def controlled_pinned_validator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def controlled_pinned_validator(trajectory: object) -> None:
        assert isinstance(trajectory, dict)
        candidate.validate_minimal_trajectory(trajectory)

    for target in (
        "nano_grok_build.adapter.artifactizer.validate_with_pinned_harbor",
        "nano_grok_build.harbor.tb21.validate_with_pinned_harbor",
        "scripts.check_v10_candidate.validate_with_pinned_harbor",
        "scripts.submission_preflight.validate_with_pinned_harbor",
    ):
        monkeypatch.setattr(target, controlled_pinned_validator)


def _raw_admission_policy() -> tuple[dict[str, str], candidate.StagePolicy]:
    checksums = candidate.load_official_checksums(
        Path(__file__).parents[1] / tb21.OFFICIAL_TASK_CHECKSUMS_PATH
    )
    return checksums, candidate.StagePolicy(
        task_ids=tuple(checksums),
        expected_jobs=1,
    )


def test_real_writer_collector_candidate_preflight_pipeline(
    tmp_path: Path,
    controlled_pinned_validator: None,
) -> None:
    job, expectation, specs = _production_pipeline_job(tmp_path)
    checksums, policy = _raw_admission_policy()

    candidate_report = candidate.audit_jobs(
        (job,), policy=policy, official_checksums=checksums
    )
    preflight_report = preflight.audit_jobs(
        (job,), expectation=expectation, require_pinned_harbor=True
    )
    rows = {
        row["trial"]: row
        for row in map(json.loads, (job / "rows.jsonl").read_text().splitlines())
    }

    assert candidate_report["status"] == "passed"
    assert preflight_report["status"] == "passed", preflight_report["jobs"][0]["issues"]
    assert rows[str(specs[2]["trial_id"])]["runtime_entry_state"] == "not_started"
    assert (
        rows[str(specs[2]["trial_id"])]["contamination_audit_state"] == "not_applicable"
    )


@pytest.mark.parametrize(
    ("runtime_state", "classification", "expected_numerator", "expected_pass"),
    [
        ("started", "rewarded", 88.0, True),
        ("started", "zero", 87.0, True),
        ("started", "errored", 87.0, True),
        ("not_started", "rewarded", 89.0, False),
        ("not_started", "zero", 88.0, True),
        ("not_started", "errored", 88.0, True),
    ],
)
def test_real_raw_admission_runtime_result_matrix(
    tmp_path: Path,
    controlled_pinned_validator: None,
    runtime_state: str,
    classification: str,
    expected_numerator: float,
    expected_pass: bool,
) -> None:
    job, expectation, specs = _production_pipeline_job(tmp_path)
    spec = specs[0] if runtime_state == "started" else specs[2]
    agent_dir = job / str(spec["trial_id"]) / "agent"
    if runtime_state == "not_started" and classification == "rewarded":
        for name in (
            "agent-run.json",
            "emergency-prefix.json",
            "runtime-usage-receipt.json",
            "trajectory.json",
        ):
            (agent_dir / name).unlink(missing_ok=True)
        _write_pipeline_success(agent_dir, spec)
    result_path = job / str(spec["trial_id"]) / "result.json"
    result = json.loads(result_path.read_bytes())
    if classification == "errored":
        result["verifier_result"] = None
        result["exception_info"] = {
            "exception_type": "BridgeError",
            "exception_message": "typed synthetic error",
        }
    else:
        result["verifier_result"] = {
            "rewards": {"reward": 1.0 if classification == "rewarded" else 0.0}
        }
        result["exception_info"] = None
    result_path.write_bytes(_canonical(result))
    summary = tb21.collect_job(job)

    checksums, policy = _raw_admission_policy()
    candidate_report = candidate.audit_jobs(
        (job,), policy=policy, official_checksums=checksums
    )
    preflight_report = preflight.audit_jobs(
        (job,), expectation=expectation, require_pinned_harbor=True
    )
    rows = {
        row["trial"]: row
        for row in map(json.loads, (job / "rows.jsonl").read_text().splitlines())
    }
    row = rows[str(spec["trial_id"])]

    assert row["runtime_entry_state"] == runtime_state
    assert summary["collector_accuracy"]["numerator"] == expected_numerator
    assert summary["collector_accuracy"]["denominator"] == 89
    contradiction = runtime_state == "not_started" and classification == "rewarded"
    if contradiction:
        assert row["failure_code"] == "runtime_result_contradiction"
    else:
        assert row["failure_code"] != "runtime_result_contradiction"
    assert summary["gates"]["runtime_result_consistency"] is (not contradiction)
    expected_audit_state = (
        "not_applicable"
        if runtime_state == "not_started" and classification == "errored"
        else "available"
    )
    assert row["contamination_audit_state"] == expected_audit_state
    assert row["git_history_audit_state"] == expected_audit_state
    if runtime_state == "not_started" and classification == "rewarded":
        assert row["direct_atif_valid"] is True
        assert row["rewarded_atif_valid"] is False
    assert candidate_report["status"] == ("passed" if expected_pass else "failed")
    assert preflight_report["status"] == ("passed" if expected_pass else "failed")
    if not expected_pass:
        assert "runtime_result_contradiction" in candidate_report["violations"]
        assert "runtime_result_contradiction" in _codes(preflight_report)


@pytest.mark.parametrize(
    "tamper",
    ["receipt", "runtime_entry", "result", "summary", "atif", "row_consistency"],
)
def test_real_raw_admission_tamper_matrix_fails_closed(
    tmp_path: Path,
    controlled_pinned_validator: None,
    tamper: str,
) -> None:
    job, expectation, specs = _production_pipeline_job(tmp_path)
    trial_dir = job / str(specs[0]["trial_id"])
    if tamper == "receipt":
        path = trial_dir / "agent" / HISTORY_BASELINE_RECEIPT
        value = json.loads(path.read_bytes())
        value["root_commit_count"] = 2
        path.write_bytes(_canonical(value))
    elif tamper == "runtime_entry":
        path = trial_dir / "agent" / RUNTIME_ENTRY_NAME
        value = json.loads(path.read_bytes())
        value["run_spec_sha256"] = "0" * 64
        path.write_bytes(_canonical(value))
    elif tamper == "result":
        path = trial_dir / "result.json"
        value = json.loads(path.read_bytes())
        value["verifier_result"]["rewards"]["reward"] = True
        path.write_bytes(_canonical(value))
    elif tamper == "summary":
        path = job / "summary.json"
        value = json.loads(path.read_bytes())
        value["collector_accuracy"]["numerator"] = 87.0
        path.write_bytes(_canonical(value))
    elif tamper == "row_consistency":
        path = job / "rows.jsonl"
        rows = [json.loads(line) for line in path.read_bytes().splitlines()]
        rows[0]["failure_code"] = "runtime_result_contradiction"
        path.write_bytes(b"".join(_canonical(row) for row in rows))
    else:
        path = trial_dir / "agent" / "trajectory.json"
        path.write_bytes(path.read_bytes() + b" ")

    checksums, policy = _raw_admission_policy()
    with pytest.raises(candidate.CandidateError):
        candidate.audit_jobs((job,), policy=policy, official_checksums=checksums)
    preflight_report = preflight.audit_jobs(
        (job,), expectation=expectation, require_pinned_harbor=True
    )
    assert preflight_report["status"] == "failed"


def test_ordinary_terminal_error_remains_in_denominator_and_is_not_replaced(
    tmp_path: Path,
    valid_artifacts: None,
) -> None:
    job, expectation = _synthetic_job(tmp_path)
    trial_id = "task-00__trial"
    result_path = job / trial_id / "result.json"
    result = json.loads(result_path.read_bytes())
    result["verifier_result"] = None
    result["exception_info"] = {
        "exception_type": "VerifierTimeoutError",
        "exception_message": "synthetic timeout",
    }
    result_path.write_bytes(_canonical(result))
    rows_path = job / "rows.jsonl"
    rows = [json.loads(line) for line in rows_path.read_bytes().splitlines()]
    rows[0].update(
        {
            "reward": None,
            "raw_score_valid": False,
            "collector_pass": False,
            "strict_pass": False,
            "reliable": False,
            "rewarded_atif_valid": False,
        }
    )
    rows_path.write_bytes(b"".join(_canonical(row) for row in rows))
    summary_path = job / "summary.json"
    summary = json.loads(summary_path.read_bytes())
    summary["counts"]["passed"] = 88
    summary["counts"]["reliable"] = 88
    summary["rewarded_atif_coverage"] = {
        "numerator": 88,
        "denominator": 88,
        "percent": 100.0,
    }
    summary["collector_accuracy"] = {
        "numerator": 88.0,
        "denominator": 89,
        "percent": round(100 * 88 / 89, 6),
    }
    summary_path.write_bytes(_canonical(summary))

    receipt = preflight.audit_jobs(
        (job,), expectation=expectation, require_pinned_harbor=False
    )

    assert receipt["status"] == "passed"
    assert receipt["jobs"][0]["trial_count"] == 89


def test_type_only_terminal_error_is_not_an_official_error_identity(
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

    assert receipt["status"] == "failed"
    assert "trial_result_invalid" in _codes(receipt)


@pytest.mark.parametrize("classification", ("zero", "errored"))
def test_nonrewarded_trial_may_omit_agent_trajectory_and_marker(
    tmp_path: Path,
    valid_artifacts: None,
    monkeypatch: pytest.MonkeyPatch,
    classification: str,
) -> None:
    job, expectation = _synthetic_job(tmp_path)
    trial_id = "task-00__trial"
    result_path = job / trial_id / "result.json"
    result = json.loads(result_path.read_bytes())
    if classification == "zero":
        result["verifier_result"]["rewards"]["reward"] = 0
    else:
        result["verifier_result"] = None
        result["exception_info"] = {
            "exception_type": "VerifierTimeoutError",
            "exception_message": "synthetic timeout",
        }
    result_path.write_bytes(_canonical(result))
    rows_path = job / "rows.jsonl"
    rows = [json.loads(line) for line in rows_path.read_bytes().splitlines()]
    rows[0].update(
        {
            "reward": 0.0 if classification == "zero" else None,
            "raw_score_valid": classification == "zero",
            "collector_pass": False,
            "strict_pass": False,
            "reliable": False,
            "success_artifact_valid": False,
            "direct_atif_valid": False,
            "rewarded_atif_valid": False,
        }
    )
    rows_path.write_bytes(b"".join(_canonical(row) for row in rows))
    _project_one_nonrewarded_summary(job)
    (job / trial_id / "agent" / "trajectory.json").unlink()
    (job / trial_id / "agent" / "agent-run.json").unlink()
    monkeypatch.setattr(
        tb21, "_artifact_evidence", _missing_artifact_projection(trial_id)
    )
    monkeypatch.setattr(
        tb21,
        "_contamination_audit",
        lambda _trial, *, rewarded=False: _clean_audit(),
    )
    monkeypatch.setattr(
        tb21.git_history_audit,
        "audit_trial",
        lambda _trial, **_kwargs: _clean_git_audit(),
    )

    receipt = preflight.audit_jobs(
        (job,), expectation=expectation, require_pinned_harbor=False
    )

    assert receipt["status"] == "passed"
    assert receipt["submit_ready"] is True
    assert not {
        "terminal_marker_missing",
        "terminal_direct_trajectory_missing",
        "rewarded_direct_trajectory_missing",
    } & _codes(receipt)


def test_present_nonrewarded_trajectory_still_must_validate(
    tmp_path: Path,
    valid_artifacts: None,
) -> None:
    job, expectation = _synthetic_job(tmp_path)
    trial_id = "task-00__trial"
    result_path = job / trial_id / "result.json"
    result = json.loads(result_path.read_bytes())
    result["verifier_result"]["rewards"]["reward"] = 0
    result_path.write_bytes(_canonical(result))
    rows_path = job / "rows.jsonl"
    rows = [json.loads(line) for line in rows_path.read_bytes().splitlines()]
    rows[0]["reward"] = 0.0
    rows_path.write_bytes(b"".join(_canonical(row) for row in rows))
    trajectory_path = job / trial_id / "agent" / "trajectory.json"
    trajectory_path.write_bytes(b"not-json\n")

    receipt = preflight.audit_jobs(
        (job,), expectation=expectation, require_pinned_harbor=False
    )

    assert receipt["status"] == "failed"
    assert "terminal_direct_trajectory_invalid" in _codes(receipt)


def test_present_optional_trajectory_requires_copresent_bound_marker(
    tmp_path: Path,
    valid_artifacts: None,
) -> None:
    job, expectation = _synthetic_job(tmp_path)
    trial_id = "task-00__trial"
    result_path = job / trial_id / "result.json"
    result = json.loads(result_path.read_bytes())
    result["verifier_result"]["rewards"]["reward"] = 0
    result_path.write_bytes(_canonical(result))
    rows_path = job / "rows.jsonl"
    rows = [json.loads(line) for line in rows_path.read_bytes().splitlines()]
    rows[0]["reward"] = 0.0
    rows_path.write_bytes(b"".join(_canonical(row) for row in rows))
    (job / trial_id / "agent" / "agent-run.json").unlink()

    receipt = preflight.audit_jobs(
        (job,), expectation=expectation, require_pinned_harbor=False
    )

    assert receipt["status"] == "failed"
    assert "terminal_marker_missing" in _codes(receipt)


def test_present_optional_marker_requires_copresent_direct_trajectory(
    tmp_path: Path,
    valid_artifacts: None,
) -> None:
    job, expectation = _synthetic_job(tmp_path)
    trial_id = "task-00__trial"
    result_path = job / trial_id / "result.json"
    result = json.loads(result_path.read_bytes())
    result["verifier_result"]["rewards"]["reward"] = 0
    result_path.write_bytes(_canonical(result))
    rows_path = job / "rows.jsonl"
    rows = [json.loads(line) for line in rows_path.read_bytes().splitlines()]
    rows[0]["reward"] = 0.0
    rows_path.write_bytes(b"".join(_canonical(row) for row in rows))
    (job / trial_id / "agent" / "trajectory.json").unlink()

    receipt = preflight.audit_jobs(
        (job,), expectation=expectation, require_pinned_harbor=False
    )

    assert receipt["status"] == "failed"
    assert "terminal_direct_trajectory_missing" in _codes(receipt)


@pytest.mark.parametrize(
    ("durable_not_started", "audit_unavailable", "expected_pass"),
    ((True, True, True), (False, True, False), (True, False, False)),
)
def test_errored_audit_not_applicable_requires_durable_not_started(
    tmp_path: Path,
    valid_artifacts: None,
    monkeypatch: pytest.MonkeyPatch,
    durable_not_started: bool,
    audit_unavailable: bool,
    expected_pass: bool,
) -> None:
    job, expectation = _synthetic_job(tmp_path)
    trial_id = "task-00__trial"
    result_path = job / trial_id / "result.json"
    result = json.loads(result_path.read_bytes())
    result["verifier_result"] = None
    result["exception_info"] = {
        "exception_type": "EnvironmentSetupError",
        "exception_message": "runtime was not launched",
    }
    result_path.write_bytes(_canonical(result))
    shutil.rmtree(job / trial_id / "agent")

    rows_path = job / "rows.jsonl"
    rows = [json.loads(line) for line in rows_path.read_bytes().splitlines()]
    row = rows[0]
    row.update(
        {
            "reward": None,
            "raw_score_valid": False,
            "collector_pass": False,
            "strict_pass": False,
            "reliable": False,
            "success_artifact_valid": False,
            "direct_atif_valid": False,
            "rewarded_atif_valid": False,
        }
    )
    if durable_not_started:
        row["runtime_entry_state"] = "not_observed"
        row.update(preflight._audit_projection(_not_applicable_audit()))
        row.update(preflight._git_audit_projection(_not_applicable_git_audit()))
    rows_path.write_bytes(b"".join(_canonical(value) for value in rows))
    _project_one_nonrewarded_summary(job)
    monkeypatch.setattr(
        tb21, "_artifact_evidence", _missing_artifact_projection(trial_id)
    )

    def protected_audit(path: Path, **_kwargs: object) -> dict[str, object]:
        if path.name != trial_id:
            return _clean_audit()
        if audit_unavailable:
            return {**_clean_audit(), "state": "unavailable"}
        return _clean_audit()

    def history_audit(path: Path, **_kwargs: object) -> dict[str, object]:
        if path.name != trial_id:
            return _clean_git_audit()
        if audit_unavailable:
            return {
                **_clean_git_audit(),
                "state": "unavailable",
                "evidence_complete": False,
            }
        return _clean_git_audit()

    monkeypatch.setattr(tb21, "_contamination_audit", protected_audit)
    monkeypatch.setattr(tb21.git_history_audit, "audit_trial", history_audit)

    receipt = preflight.audit_jobs(
        (job,), expectation=expectation, require_pinned_harbor=False
    )

    if expected_pass:
        assert receipt["status"] == "passed", _codes(receipt)
        assert receipt["submit_ready"] is True
        assert not {
            "protected_evidence_unavailable",
            "git_history_evidence_unavailable",
        } & _codes(receipt)
    else:
        assert receipt["status"] == "failed"
        assert {
            "protected_evidence_unavailable",
            "git_history_evidence_unavailable",
        } <= _codes(receipt)


def test_nonrewarded_missing_trajectory_does_not_waive_unavailable_audits(
    tmp_path: Path,
    valid_artifacts: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job, expectation = _synthetic_job(tmp_path)
    trial_id = "task-00__trial"
    result_path = job / trial_id / "result.json"
    result = json.loads(result_path.read_bytes())
    result["verifier_result"]["rewards"]["reward"] = 0
    result_path.write_bytes(_canonical(result))
    rows_path = job / "rows.jsonl"
    rows = [json.loads(line) for line in rows_path.read_bytes().splitlines()]
    rows[0]["reward"] = 0.0
    rows_path.write_bytes(b"".join(_canonical(row) for row in rows))
    (job / trial_id / "agent" / "trajectory.json").unlink()
    (job / trial_id / "agent" / "agent-run.json").unlink()
    monkeypatch.setattr(
        tb21,
        "_contamination_audit",
        lambda _trial, *, rewarded=False: {"state": "unavailable"},
    )
    monkeypatch.setattr(
        tb21.git_history_audit,
        "audit_trial",
        lambda _trial, **_kwargs: {
            "state": "unavailable",
            "evidence_complete": False,
        },
    )

    receipt = preflight.audit_jobs(
        (job,), expectation=expectation, require_pinned_harbor=False
    )

    assert receipt["status"] == "failed"
    assert {
        "protected_evidence_unavailable",
        "git_history_evidence_unavailable",
    } <= _codes(receipt)


@pytest.mark.parametrize(
    "mutation",
    [
        "stored_direct",
        "stored_rewarded",
        "stored_strict",
        "mixed_schema",
        "v6_only_fields",
        "summary_numerator",
        "summary_denominator",
        "summary_gate",
        "raw_numerator",
        "raw_denominator",
        "raw_gate",
    ],
)
def test_v7_collector_projection_and_summary_fail_closed(
    tmp_path: Path,
    valid_artifacts: None,
    mutation: str,
) -> None:
    job, expectation = _synthetic_job(tmp_path)
    if mutation in {
        "stored_direct",
        "stored_rewarded",
        "stored_strict",
        "mixed_schema",
        "v6_only_fields",
    }:
        rows_path = job / "rows.jsonl"
        rows = [json.loads(line) for line in rows_path.read_bytes().splitlines()]
        if mutation == "stored_direct":
            rows[0].update(
                {
                    "direct_atif_valid": False,
                    "rewarded_atif_valid": False,
                    "strict_pass": False,
                }
            )
        elif mutation == "stored_rewarded":
            rows[0]["rewarded_atif_valid"] = False
        elif mutation == "stored_strict":
            rows[0]["strict_pass"] = False
        else:
            rows[0]["schema_version"] = tb21.ROW_SCHEMA_V6
            if mutation == "mixed_schema":
                rows[0].pop("direct_atif_valid")
                rows[0].pop("rewarded_atif_valid")
        rows_path.write_bytes(b"".join(_canonical(row) for row in rows))
    else:
        summary_path = job / "summary.json"
        summary = json.loads(summary_path.read_bytes())
        if mutation == "summary_numerator":
            summary["rewarded_atif_coverage"]["numerator"] = 88
        elif mutation == "summary_denominator":
            summary["rewarded_atif_coverage"]["denominator"] = 88
        elif mutation == "summary_gate":
            summary["gates"]["rewarded_atif"] = False
        elif mutation == "raw_numerator":
            summary["collector_accuracy"]["numerator"] = 88
        elif mutation == "raw_denominator":
            summary["collector_accuracy"]["denominator"] = 88
        else:
            summary["gates"]["official_results"] = False
        summary_path.write_bytes(_canonical(summary))

    receipt = preflight.audit_jobs(
        (job,), expectation=expectation, require_pinned_harbor=False
    )

    assert receipt["status"] == "failed"
    assert "collector_projection_mismatch" in _codes(receipt) or {
        "collector_schema_mismatch",
        "collector_summary_invalid",
    }.intersection(_codes(receipt))


def test_preflight_recomputes_fractional_official_numerator(
    tmp_path: Path,
    valid_artifacts: None,
) -> None:
    job, expectation = _synthetic_job(tmp_path)
    trial_id = "task-00__trial"
    result_path = job / trial_id / "result.json"
    result = json.loads(result_path.read_bytes())
    result["verifier_result"]["rewards"]["reward"] = 0.5
    result_path.write_bytes(_canonical(result))
    rows_path = job / "rows.jsonl"
    rows = [json.loads(line) for line in rows_path.read_bytes().splitlines()]
    rows[0]["reward"] = 0.5
    rows_path.write_bytes(b"".join(_canonical(row) for row in rows))
    summary_path = job / "summary.json"
    summary = json.loads(summary_path.read_bytes())
    summary["collector_accuracy"] = {
        "numerator": 88.5,
        "denominator": 89,
        "percent": round(100 * 88.5 / 89, 6),
    }
    summary_path.write_bytes(_canonical(summary))

    receipt = preflight.audit_jobs(
        (job,), expectation=expectation, require_pinned_harbor=False
    )

    assert receipt["status"] == "passed"


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


@pytest.mark.parametrize("reward", (1.0, 0.0))
def test_actual_git_history_bytes_fail_submission_preflight(
    tmp_path: Path,
    valid_artifacts: None,
    reward: float,
) -> None:
    job, expectation = _synthetic_job(tmp_path)
    trial_id = "task-00__trial"
    result_path = job / trial_id / "result.json"
    result = json.loads(result_path.read_bytes())
    result["verifier_result"]["rewards"]["reward"] = reward
    result_path.write_bytes(_canonical(result))
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
                    {
                        "source_call_id": "history-call",
                        "content": "history bytes",
                        "extra": {
                            "execution_attempted": True,
                            "outcome": "succeeded",
                        },
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
    audit = tb21.git_history_audit.audit_trial(
        job / trial_id, instruction="Synthetic submission preflight fixture."
    )
    rows_path = job / "rows.jsonl"
    rows = [json.loads(line) for line in rows_path.read_bytes().splitlines()]
    rows[0]["reward"] = reward
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


def test_static_contract_documents_read_only_cli() -> None:
    errors = preflight.static_errors(Path(__file__).parents[1])

    assert errors == []
