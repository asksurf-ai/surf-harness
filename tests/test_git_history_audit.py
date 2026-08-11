from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from nano_grok_build.harbor import git_history_audit
from nano_grok_build.harbor.git_history_capability import (
    compile_git_history_capability,
)


def _trajectory(
    *calls: tuple[str, str, dict[str, object], str | None],
) -> dict[str, object]:
    steps: list[dict[str, object]] = [
        {"step_id": 1, "source": "user", "message": "Synthetic instruction."}
    ]
    for index, (call_id, tool_name, arguments, output) in enumerate(calls, start=2):
        step: dict[str, object] = {
            "step_id": index,
            "source": "agent",
            "message": "",
            "tool_calls": [
                {
                    "tool_call_id": call_id,
                    "function_name": tool_name,
                    "arguments": arguments,
                }
            ],
        }
        if output is not None:
            step["observation"] = {
                "results": [
                    {
                        "source_call_id": call_id,
                        "content": output,
                        "extra": {
                            "execution_attempted": True,
                            "outcome": "succeeded",
                        },
                    }
                ]
            }
        steps.append(step)
    return {"schema_version": "ATIF-v1.7", "steps": steps}


def test_current_status_and_worktree_diff_are_clean() -> None:
    audit = git_history_audit.audit_public_evidence(
        instruction="Update the current implementation and run its tests.",
        trajectory=_trajectory(
            ("status", "run_terminal_command", {"command": "git status --short"}, ""),
            ("diff", "run_terminal_command", {"command": "git diff -- src/app.c"}, ""),
        ),
    )

    assert audit["state"] == "available"
    assert audit["history_required"] is False
    assert audit["findings"] == []
    assert audit["submission_blocking"] is False


def test_commit_created_during_run_may_be_inspected() -> None:
    audit = git_history_audit.audit_public_evidence(
        instruction="Update the current implementation and run its tests.",
        trajectory=_trajectory(
            (
                "commit",
                "run_terminal_command",
                {"command": "git commit -am 'synthetic change'"},
                "[main abcdef1] synthetic change",
            ),
            (
                "show",
                "run_terminal_command",
                {"command": "git show abcdef1 --stat"},
                "new commit summary",
            ),
        ),
    )

    assert audit["findings"] == []
    assert audit["submission_blocking"] is False


def test_explicit_history_instruction_allows_history_access_and_reuse() -> None:
    source = "synthetic historical payload line with enough entropy 0123456789"
    audit = git_history_audit.audit_public_evidence(
        instruction="Inspect the Git commit history and restore the previous revision.",
        trajectory=_trajectory(
            (
                "show",
                "run_terminal_command",
                {"command": "git show HEAD~1:src/app.c"},
                source,
            ),
            ("write", "write", {"file_path": "src/app.c", "content": source}, "ok"),
        ),
    )

    assert audit["history_required"] is True
    assert audit["findings"][0]["causal_reuse"] is True
    assert audit["submission_blocking"] is False


def test_nonrequired_causal_history_reuse_blocks_submission() -> None:
    source = "synthetic historical payload line with enough entropy abcdefghij"
    audit = git_history_audit.audit_public_evidence(
        instruction="Fix the current parser behavior.",
        trajectory=_trajectory(
            (
                "show",
                "run_terminal_command",
                {"command": "git show deadbeef:src/parser.c"},
                source,
            ),
            ("write", "write", {"file_path": "src/parser.c", "content": source}, "ok"),
        ),
    )

    finding = audit["findings"][0]
    assert finding["attempted"] is True
    assert finding["dispatched"] is True
    assert finding["bytes_returned"] is True
    assert finding["causal_reuse"] is True
    assert audit["submission_blocking"] is True


def test_noncausal_history_bytes_still_block_actual_oracle_access() -> None:
    audit = git_history_audit.audit_public_evidence(
        instruction="Fix the current parser behavior.",
        trajectory=_trajectory(
            (
                "log",
                "run_terminal_command",
                {"command": "git log -p -1"},
                "historical output that is not reused anywhere",
            ),
            (
                "write",
                "write",
                {"file_path": "src/parser.c", "content": "independent implementation"},
                "ok",
            ),
        ),
    )

    assert audit["findings"][0]["bytes_returned"] is True
    assert audit["findings"][0]["causal_reuse"] is False
    assert audit["counts"]["blocking"] == 1
    assert audit["submission_blocking"] is True


def test_history_attempt_without_returned_bytes_is_warning_only() -> None:
    audit = git_history_audit.audit_public_evidence(
        instruction="Fix the current parser behavior.",
        trajectory=_trajectory(
            ("log", "run_terminal_command", {"command": "git log -p -1"}, None),
        ),
    )

    assert audit["findings"][0]["dispatched"] is False
    assert audit["findings"][0]["bytes_returned"] is False
    assert audit["counts"]["warnings"] == 1
    assert audit["submission_blocking"] is False


def test_typed_guard_rejection_is_attempted_but_never_dispatched_or_bytes() -> None:
    trajectory = _trajectory(
        (
            "log",
            "run_terminal_command",
            {"command": "git log --oneline -5; git diff HEAD~1 --stat"},
            "git_history_not_required",
        ),
        (
            "write",
            "write",
            {"file_path": "notes.txt", "content": "git_history_not_required"},
            "ok",
        ),
    )
    result = trajectory["steps"][1]["observation"]["results"][0]  # type: ignore[index]
    result["extra"] = {"execution_attempted": False, "outcome": "rejected"}

    audit = git_history_audit.audit_public_evidence(
        instruction="Fix the current parser behavior.",
        trajectory=trajectory,
    )

    finding = audit["findings"][0]
    assert finding["attempted"] is True
    assert finding["dispatched"] is False
    assert finding["bytes_returned"] is False
    assert finding["causal_reuse"] is False
    assert audit["counts"]["blocking"] == 0
    assert audit["submission_blocking"] is False


@pytest.mark.parametrize(
    "command",
    [
        "python solve.py --start 3145700: --end 3145800:",
        "python -c 'x = 0x80800000; print(x)'",
        "awk '$2 == \"0100007F:1A09\"' /proc/net/tcp",
        "python inspect.py # check git log briefly without using as oracle",
    ],
)
def test_non_git_numeric_and_comment_text_is_not_a_historical_revision(
    command: str,
) -> None:
    audit = git_history_audit.audit_public_evidence(
        instruction="Complete the current task.",
        trajectory=_trajectory(
            ("inspect", "run_terminal_command", {"command": command}, "ordinary bytes"),
        ),
    )

    assert audit["findings"] == []
    assert audit["submission_blocking"] is False


@pytest.mark.parametrize(
    "command",
    ["git show", "git show HEAD", "git show HEAD:algo.py", "git diff HEAD"],
)
def test_current_head_and_worktree_views_are_not_pre_solution_history(
    command: str,
) -> None:
    audit = git_history_audit.audit_public_evidence(
        instruction="Complete the current task.",
        trajectory=_trajectory(
            ("inspect", "run_terminal_command", {"command": command}, "current bytes"),
        ),
    )

    assert audit["findings"] == []


def test_truly_historical_git_revision_remains_blocking() -> None:
    audit = git_history_audit.audit_public_evidence(
        instruction="Complete the current task.",
        trajectory=_trajectory(
            (
                "inspect",
                "run_terminal_command",
                {"command": "git show HEAD~1:algo.py"},
                "historical bytes",
            ),
        ),
    )

    assert audit["findings"][0]["access_kind"] == "git_history_command"
    assert audit["submission_blocking"] is True


def test_unparseable_non_git_terminal_command_does_not_invalidate_audit() -> None:
    audit = git_history_audit.audit_public_evidence(
        instruction="Complete the current task.",
        trajectory=_trajectory(
            ("inspect", "run_terminal_command", {"command": "printf '%s"}, ""),
        ),
    )

    assert audit["state"] == "available"
    assert audit["findings"] == []
    assert audit["submission_blocking"] is False


@pytest.mark.parametrize(
    "command",
    [
        "python3 <<'PY'\nprint(\"there's no shell quote contract here\")\nPY",
        (
            "cat > /tmp/program.c <<'EOF'\n"
            'char *s = "can\'t parse this as shell";\nEOF\ncc /tmp/program.c'
        ),
        "python3 <<'PY'\nskip={'.git'}\n# git log is prose inside Python\nPY",
        "python3 -c '\nprint(\"there\\'s valid embedded source\")\n'",
        "printf '; git log is quoted prose",
        "printf \"<<'STOP' is quoted prose\"\ngit status --short",
        "which helper || (cd /tmp && git clone --depth 1 https://example.invalid/lib.git)",
    ],
)
def test_embedded_source_and_safe_outer_git_do_not_invalidate_audit(
    command: str,
) -> None:
    audit = git_history_audit.audit_public_evidence(
        instruction="Complete the current task.",
        trajectory=_trajectory(
            ("inspect", "run_terminal_command", {"command": command}, "ordinary"),
        ),
    )

    assert audit["state"] == "available"
    assert audit["findings"] == []
    assert audit["submission_blocking"] is False


def test_malformed_actual_git_command_remains_fail_closed() -> None:
    audit = git_history_audit.audit_public_evidence(
        instruction="Complete the current task.",
        trajectory=_trajectory(
            (
                "inspect",
                "run_terminal_command",
                {"command": "git show 'HEAD~1:src/app.c"},
                "shell parse failure",
            ),
        ),
    )

    assert audit["state"] == "invalid"
    assert audit["evidence_complete"] is False
    assert audit["submission_blocking"] is True


@pytest.mark.parametrize(
    "command",
    [
        (
            "python3 <<'PY'\nprint('validation')\nPY\n"
            "git describe --tags || git log -1 --oneline"
        ),
        "git --git-dir=/srv/repository log -1 --oneline",
    ],
)
def test_compound_executed_history_controls_remain_blocking(command: str) -> None:
    audit = git_history_audit.audit_public_evidence(
        instruction="Validate the current result.",
        trajectory=_trajectory(
            ("history", "run_terminal_command", {"command": command}, "history bytes"),
        ),
    )

    assert audit["state"] == "available"
    assert audit["findings"][0]["dispatched"] is True
    assert audit["findings"][0]["bytes_returned"] is True
    assert audit["submission_blocking"] is True


def test_direct_object_database_read_is_detected_without_command_blacklist() -> None:
    audit = git_history_audit.audit_public_evidence(
        instruction="Fix the current parser behavior.",
        trajectory=_trajectory(
            (
                "objects",
                "run_terminal_command",
                {"command": "python -c \"open('.git/objects/aa/bb','rb').read()\""},
                "object bytes",
            ),
        ),
    )

    assert audit["findings"][0]["access_kind"] == "object_database"
    assert audit["submission_blocking"] is True


def test_generic_language_uses_shared_non_grant_and_evidence_gap_fails_closed() -> None:
    generic = git_history_audit.audit_public_evidence(
        instruction="Check whether an earlier version matters, then fix the parser.",
        trajectory=_trajectory(),
    )
    assert generic["history_required"] is False
    assert generic["submission_blocking"] is False

    malformed = _trajectory(
        ("show", "run_terminal_command", {"command": "git show HEAD~1:file"}, "bytes")
    )
    malformed["steps"][1]["observation"]["results"][0]["source_call_id"] = "unknown"  # type: ignore[index]
    invalid = git_history_audit.audit_public_evidence(
        instruction="Fix the current parser behavior.",
        trajectory=malformed,
    )
    assert invalid["state"] == "invalid"
    assert invalid["evidence_complete"] is False
    assert invalid["submission_blocking"] is True


def test_audit_consumes_exact_shared_capability_including_negation_and_bisect() -> None:
    for instruction, digest, required in [
        ("Do not inspect Git history; fix the parser.", "a" * 64, False),
        ("Use git bisect to find the regression.", "b" * 64, True),
    ]:
        capability = compile_git_history_capability(instruction, digest)
        audit = git_history_audit.audit_public_evidence(
            instruction=instruction,
            capability=capability,
            trusted_manifest_sha256=digest,
            trajectory=_trajectory(),
        )
        assert audit["history_required"] is required
        assert audit["submission_blocking"] is False

        tampered = dict(capability)
        tampered["canonical_instruction_sha256"] = "c" * 64
        invalid = git_history_audit.audit_public_evidence(
            instruction=instruction,
            capability=tampered,
            trusted_manifest_sha256=digest,
            trajectory=_trajectory(),
        )
        assert invalid["history_required"] is None
        assert invalid["submission_blocking"] is True


def test_stored_projection_tampering_is_detectable_by_recomputation() -> None:
    source = "synthetic historical payload line with enough entropy klmnopqrst"
    trajectory = _trajectory(
        (
            "show",
            "run_terminal_command",
            {"command": "git show cafe1234:src/a.c"},
            source,
        ),
        ("write", "write", {"file_path": "src/a.c", "content": source}, "ok"),
    )
    canonical = git_history_audit.audit_public_evidence(
        instruction="Fix the current parser behavior.", trajectory=trajectory
    )
    stored = copy.deepcopy(canonical)
    stored["submission_blocking"] = False

    assert (
        git_history_audit.audit_public_evidence(
            instruction="Fix the current parser behavior.", trajectory=trajectory
        )
        != stored
    )


def test_trial_requires_complete_lifecycle_receipts_not_only_baseline(
    tmp_path: Path,
) -> None:
    instruction = "Fix the current parser behavior."
    manifest_sha256 = "a" * 64
    run_spec_sha256 = "b" * 64
    capability = compile_git_history_capability(instruction, manifest_sha256)
    agent_dir = tmp_path / "agent"
    agent_dir.mkdir()
    trajectory = _trajectory(
        (
            "objects",
            "run_terminal_command",
            {"command": "python -c \"open('.git/objects/aa/bb','rb').read()\""},
            "injected pre-existing object bytes 0123456789",
        )
    )
    trajectory_raw = (
        json.dumps(trajectory, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    (agent_dir / "trajectory.json").write_bytes(trajectory_raw)
    (agent_dir / "agent-run.json").write_text(
        json.dumps(
            {
                "trajectory_path": "trajectory.json",
                "trajectory_sha256": hashlib.sha256(trajectory_raw).hexdigest(),
            }
        )
    )

    missing = git_history_audit.audit_trial(
        tmp_path,
        instruction=instruction,
        capability=capability,
        trusted_manifest_sha256=manifest_sha256,
        run_spec_sha256=run_spec_sha256,
    )
    assert missing["state"] == "invalid"
    assert missing["submission_blocking"] is True

    receipt = {
        "schema_version": "nano-git-history-baseline-v2",
        "policy_version": "nano-git-history-topology-v2",
        "run_spec_sha256": run_spec_sha256,
        "capability_instruction_sha256": capability["canonical_instruction_sha256"],
        "trusted_manifest_sha256": manifest_sha256,
        "topology_before": "root",
        "topology_after": "root",
        "admitted_repo_relative_path": ".",
        "status": "isolated",
        "census_before_sha256": "c" * 64,
        "census_after_sha256": "c" * 64,
        "filesystem_manifest_before_sha256": "d" * 64,
        "filesystem_manifest_after_sha256": "d" * 64,
        "source_commit_oid": "1" * 40,
        "source_tree_oid": "2" * 40,
        "root_commit_oid": "3" * 40,
        "root_tree_oid": "2" * 40,
        "preexisting_commit_count": 2,
        "root_commit_count": 1,
        "ref_count": 1,
        "remote_count": 0,
        "alternate_count": 0,
        "old_metadata_removed": True,
    }
    (agent_dir / "git-history-baseline.json").write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
    )
    audit = git_history_audit.audit_trial(
        tmp_path,
        instruction=instruction,
        capability=capability,
        trusted_manifest_sha256=manifest_sha256,
        run_spec_sha256=run_spec_sha256,
    )
    assert audit["state"] == "invalid"
    assert audit["findings"] == []
    assert audit["submission_blocking"] is True


def test_physical_isolation_proof_makes_synthetic_history_diagnostic() -> None:
    audit = git_history_audit.audit_public_evidence(
        instruction="Fix the current parser behavior.",
        trajectory=_trajectory(
            (
                "objects",
                "run_terminal_command",
                {"command": "python -c \"open('.git/objects/aa/bb','rb').read()\""},
                "synthetic one-commit object bytes",
            )
        ),
        original_history_exposure_possible=False,
    )
    assert audit["state"] == "available"
    assert audit["findings"][0]["bytes_returned"] is True
    assert audit["counts"]["blocking"] == 0
    assert audit["submission_blocking"] is False
