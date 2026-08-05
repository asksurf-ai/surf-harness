from __future__ import annotations

import copy

from nano_grok_build.harbor import git_history_audit


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
                "results": [{"source_call_id": call_id, "content": output}]
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


def test_ambiguous_instruction_and_evidence_gap_fail_closed() -> None:
    ambiguous = git_history_audit.audit_public_evidence(
        instruction="Check whether an earlier version matters, then fix the parser.",
        trajectory=_trajectory(),
    )
    assert ambiguous["history_required"] is None
    assert ambiguous["submission_blocking"] is True

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
