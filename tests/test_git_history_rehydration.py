from __future__ import annotations

import asyncio
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from nano_grok_build.harbor.git_history_capability import (
    compile_git_history_capability,
)
from nano_grok_build.harbor.git_history_isolation import (
    isolate_preexisting_git_history,
)
from nano_grok_build.harbor.git_history_rehydration import (
    REHYDRATION_RESTORED,
    REHYDRATION_SKIPPED_BACKGROUND,
    REHYDRATION_SKIPPED_METADATA_CHANGED,
    bind_git_history_escrow_to_isolated_state,
    create_git_history_escrow,
    rehydrate_git_history_for_verifier,
)


def _git(workspace: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=workspace,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


class _LocalActor:
    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace

    def snapshot_workspace_root(self) -> str:
        return str(self.workspace.resolve())

    async def exec_snapshot(self, command: str, *, timeout_sec: float) -> object:
        result = subprocess.run(
            ["/bin/bash", "-c", command],
            cwd=self.workspace,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        return SimpleNamespace(
            return_code=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    async def download_snapshot(
        self, source_path: str, target_path: Path | str
    ) -> None:
        shutil.copyfile(source_path, target_path)

    async def upload_snapshot(self, source_path: Path | str, target_path: str) -> None:
        shutil.copyfile(source_path, target_path)


def _repository(tmp_path: Path) -> tuple[Path, str, str]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _git(workspace, "init", "-q")
    _git(workspace, "config", "user.name", "Rehydration Test")
    _git(workspace, "config", "user.email", "rehydration@example.invalid")
    secret = "PREEXISTING_VERIFIER_ONLY_BYTES_8f5721"
    (workspace / "answer.py").write_text(secret + "\n", encoding="utf-8")
    _git(workspace, "add", "answer.py")
    _git(workspace, "commit", "-qm", "old answer")
    old_commit = _git(workspace, "rev-parse", "HEAD").strip()
    (workspace / "answer.py").write_text("current baseline\n", encoding="utf-8")
    _git(workspace, "add", "answer.py")
    _git(workspace, "commit", "-qm", "current baseline")
    return workspace, old_commit, secret


def _capability(
    instruction: str = "Fix the current working tree.",
) -> dict[str, object]:
    return compile_git_history_capability(instruction, "a" * 64)


def _bind(actor: _LocalActor, escrow: object, baseline: object):
    return asyncio.run(
        bind_git_history_escrow_to_isolated_state(
            actor=actor,
            escrow=escrow,
            baseline_receipt=baseline,
        )
    )


def test_history_is_host_escrowed_during_agent_then_restored_for_verifier(
    tmp_path: Path,
) -> None:
    workspace, old_commit, secret = _repository(tmp_path)
    actor = _LocalActor(workspace)
    escrow_dir = tmp_path / "host-escrow"
    escrow_dir.mkdir(mode=0o700)
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()

    escrow = asyncio.run(
        create_git_history_escrow(
            actor=actor,
            local_dir=escrow_dir,
            capability=_capability(),
            run_spec_sha256="b" * 64,
        )
    )
    assert escrow is not None
    assert escrow.local_archive.is_file()
    assert escrow.local_archive.parent == escrow_dir

    baseline = asyncio.run(
        isolate_preexisting_git_history(
            actor=actor,
            artifact_dir=artifact_dir,
            capability=_capability(),
            run_spec_sha256="b" * 64,
        )
    )
    assert baseline["status"] == "isolated"
    escrow = _bind(actor, escrow, baseline)
    assert escrow is not None
    assert secret not in _git(workspace, "log", "-p", "--all")
    (workspace / "answer.py").write_text("agent result\n", encoding="utf-8")

    status = asyncio.run(
        rehydrate_git_history_for_verifier(
            actor=actor,
            escrow=escrow,
            baseline_receipt=baseline,
            background_process_count=0,
        )
    )

    assert status == REHYDRATION_RESTORED
    assert secret in _git(workspace, "show", f"{old_commit}:answer.py")
    assert (workspace / "answer.py").read_text(encoding="utf-8") == "agent result\n"
    assert not escrow.local_archive.exists()


def test_background_process_keeps_history_physically_isolated(tmp_path: Path) -> None:
    workspace, _old_commit, secret = _repository(tmp_path)
    actor = _LocalActor(workspace)
    escrow_dir = tmp_path / "host-escrow"
    escrow_dir.mkdir(mode=0o700)
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    capability = _capability()
    escrow = asyncio.run(
        create_git_history_escrow(
            actor=actor,
            local_dir=escrow_dir,
            capability=capability,
            run_spec_sha256="b" * 64,
        )
    )
    assert escrow is not None
    baseline = asyncio.run(
        isolate_preexisting_git_history(
            actor=actor,
            artifact_dir=artifact_dir,
            capability=capability,
            run_spec_sha256="b" * 64,
        )
    )
    escrow = _bind(actor, escrow, baseline)
    assert escrow is not None

    status = asyncio.run(
        rehydrate_git_history_for_verifier(
            actor=actor,
            escrow=escrow,
            baseline_receipt=baseline,
            background_process_count=1,
        )
    )

    assert status == REHYDRATION_SKIPPED_BACKGROUND
    assert secret not in _git(workspace, "log", "-p", "--all")
    assert escrow.local_archive.is_file()


def test_agent_git_metadata_change_is_not_overwritten(tmp_path: Path) -> None:
    workspace, _old_commit, secret = _repository(tmp_path)
    actor = _LocalActor(workspace)
    escrow_dir = tmp_path / "host-escrow"
    escrow_dir.mkdir(mode=0o700)
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    capability = _capability()
    escrow = asyncio.run(
        create_git_history_escrow(
            actor=actor,
            local_dir=escrow_dir,
            capability=capability,
            run_spec_sha256="b" * 64,
        )
    )
    assert escrow is not None
    baseline = asyncio.run(
        isolate_preexisting_git_history(
            actor=actor,
            artifact_dir=artifact_dir,
            capability=capability,
            run_spec_sha256="b" * 64,
        )
    )
    escrow = _bind(actor, escrow, baseline)
    assert escrow is not None
    (workspace / "answer.py").write_text("committed agent result\n", encoding="utf-8")
    _git(workspace, "add", "answer.py")
    _git(
        workspace,
        "-c",
        "user.name=Agent",
        "-c",
        "user.email=agent@example.invalid",
        "commit",
        "-qm",
        "agent commit",
    )

    status = asyncio.run(
        rehydrate_git_history_for_verifier(
            actor=actor,
            escrow=escrow,
            baseline_receipt=baseline,
            background_process_count=0,
        )
    )

    assert status == REHYDRATION_SKIPPED_METADATA_CHANGED
    assert _git(workspace, "show", "-s", "--format=%s", "HEAD").strip() == (
        "agent commit"
    )
    assert secret not in _git(workspace, "log", "-p", "--all")


@pytest.mark.parametrize(
    "instruction",
    [
        "Fix these files in a workspace without a Git repository.",
        "Inspect the Git commit history before making the repair.",
    ],
)
def test_plain_or_history_required_workspace_creates_no_escrow(
    tmp_path: Path, instruction: str
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    if "Inspect" in instruction:
        _git(workspace, "init", "-q")
        _git(workspace, "config", "user.name", "Required Test")
        _git(workspace, "config", "user.email", "required@example.invalid")
        (workspace / "file").write_text("content\n", encoding="utf-8")
        _git(workspace, "add", "file")
        _git(workspace, "commit", "-qm", "baseline")
    escrow_dir = tmp_path / "host-escrow"
    escrow_dir.mkdir(mode=0o700)

    escrow = asyncio.run(
        create_git_history_escrow(
            actor=_LocalActor(workspace),
            local_dir=escrow_dir,
            capability=_capability(instruction),
            run_spec_sha256="b" * 64,
        )
    )

    assert escrow is None
    assert not list(escrow_dir.iterdir())


def test_tampered_host_escrow_fails_without_exposing_history(tmp_path: Path) -> None:
    workspace, _old_commit, secret = _repository(tmp_path)
    actor = _LocalActor(workspace)
    escrow_dir = tmp_path / "host-escrow"
    escrow_dir.mkdir(mode=0o700)
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    capability = _capability()
    escrow = asyncio.run(
        create_git_history_escrow(
            actor=actor,
            local_dir=escrow_dir,
            capability=capability,
            run_spec_sha256="b" * 64,
        )
    )
    assert escrow is not None
    baseline = asyncio.run(
        isolate_preexisting_git_history(
            actor=actor,
            artifact_dir=artifact_dir,
            capability=capability,
            run_spec_sha256="b" * 64,
        )
    )
    escrow = _bind(actor, escrow, baseline)
    assert escrow is not None
    escrow.local_archive.write_bytes(b"tampered")

    with pytest.raises(RuntimeError, match="git_history_rehydration_invalid"):
        asyncio.run(
            rehydrate_git_history_for_verifier(
                actor=actor,
                escrow=escrow,
                baseline_receipt=baseline,
                background_process_count=0,
            )
        )

    assert secret not in _git(workspace, "log", "-p", "--all")


@pytest.mark.parametrize("mutation", ["stage", "config"])
def test_agent_semantic_git_metadata_change_skips_restore(
    tmp_path: Path, mutation: str
) -> None:
    workspace, _old_commit, secret = _repository(tmp_path)
    actor = _LocalActor(workspace)
    escrow_dir = tmp_path / "host-escrow"
    escrow_dir.mkdir(mode=0o700)
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    capability = _capability()
    escrow = asyncio.run(
        create_git_history_escrow(
            actor=actor,
            local_dir=escrow_dir,
            capability=capability,
            run_spec_sha256="b" * 64,
        )
    )
    assert escrow is not None
    baseline = asyncio.run(
        isolate_preexisting_git_history(
            actor=actor,
            artifact_dir=artifact_dir,
            capability=capability,
            run_spec_sha256="b" * 64,
        )
    )
    escrow = _bind(actor, escrow, baseline)
    assert escrow is not None
    if mutation == "stage":
        (workspace / "answer.py").write_text("staged agent result\n", encoding="utf-8")
        _git(workspace, "add", "answer.py")
    else:
        _git(workspace, "config", "nano.agent-marker", "changed")

    status = asyncio.run(
        rehydrate_git_history_for_verifier(
            actor=actor,
            escrow=escrow,
            baseline_receipt=baseline,
            background_process_count=0,
        )
    )

    assert status == REHYDRATION_SKIPPED_METADATA_CHANGED
    assert secret not in _git(workspace, "log", "-p", "--all")
