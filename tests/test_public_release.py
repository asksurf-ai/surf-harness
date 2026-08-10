from __future__ import annotations

from pathlib import Path

from scripts.check_public_release import check_public_content, check_public_release

ROOT = Path(__file__).resolve().parents[1]


def test_public_release_is_hash_bound_and_complete() -> None:
    assert check_public_release(ROOT) == []


def test_public_content_gate_rejects_host_and_private_process_residue(
    tmp_path: Path,
) -> None:
    marker = "/".join(("", "Users", "developer", "private-results"))
    (tmp_path / "notes.md").write_text(
        f"{marker}\n" + "." + "claude/team-dev\n" + "Mi" + "mir\n"
    )

    errors = check_public_content(
        tmp_path,
        {"notes.md"},
        official_task_ids=frozenset(),
    )

    assert {error.split(":", 1)[0] for error in errors} == {
        "personal absolute path exported",
        "private process marker exported",
    }


def test_public_content_gate_rejects_official_task_literals_outside_records(
    tmp_path: Path,
) -> None:
    task = "terminal-bench/" + "synthetic-official-task"
    (tmp_path / "diagnostic.py").write_text(
        "TASK = " + repr(task.removeprefix("terminal-bench/")) + "\n"
    )

    errors = check_public_content(
        tmp_path,
        {"diagnostic.py"},
        official_task_ids=frozenset({task}),
    )

    assert errors == [
        "official task literal outside integrity allowlist: diagnostic.py"
    ]
