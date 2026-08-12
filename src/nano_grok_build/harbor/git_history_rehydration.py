"""Host-only escrow and post-agent Git metadata rehydration for verifiers."""

# ruff: noqa: E501 - trusted shell programs remain line-auditable verbatim

from __future__ import annotations

import asyncio
import hashlib
import shlex
import stat
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol

from nano_grok_build.harbor.git_history_capability import (
    GIT_HISTORY_ACCESS_REQUIRED,
)
from nano_grok_build.harbor.git_history_isolation import _topology, _topology_script
from nano_grok_build.harbor.git_history_receipt import (
    _hex,
    git_history_access,
)

REHYDRATION_RESTORED = "restored"
REHYDRATION_SKIPPED_BACKGROUND = "skipped_background"
REHYDRATION_SKIPPED_METADATA_CHANGED = "skipped_metadata_changed"

_MAX_ESCROW_BYTES = 512 * 1024 * 1024
_COMMAND_OUTPUT_BYTES = 16 * 1024


class _TrustedActor(Protocol):
    def snapshot_workspace_root(self) -> str: ...

    async def exec_snapshot(self, command: str, *, timeout_sec: float) -> object: ...

    async def download_snapshot(
        self, source_path: str, target_path: Path | str
    ) -> None: ...

    async def upload_snapshot(
        self, source_path: Path | str, target_path: str
    ) -> None: ...


@dataclass(frozen=True)
class GitHistoryEscrow:
    """One original Git admin directory held outside the task environment."""

    local_archive: Path
    archive_sha256: str
    archive_size: int
    workspace: str
    repo_relative_path: str
    source_commit_oid: str
    source_tree_oid: str
    preexisting_commit_count: int
    run_spec_sha256: str
    isolated_guard_sha256: str | None = None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _sha256_shell() -> str:
    return """sha256_stream() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 | awk '{print $NF}'
  else return 1; fi
}
"""


def _workspace(actor: _TrustedActor) -> str:
    value = actor.snapshot_workspace_root()
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or "\x00" in value
        or len(value.encode("utf-8")) > 4096
    ):
        raise RuntimeError("git_history_rehydration_invalid")
    return value


async def _execute(actor: _TrustedActor, program: str, *, timeout: float) -> str:
    result = await actor.exec_snapshot(program, timeout_sec=timeout)
    stdout = getattr(result, "stdout", None)
    stderr = getattr(result, "stderr", None)
    if (
        getattr(result, "return_code", None) != 0
        or not isinstance(stdout, str)
        or not isinstance(stderr, str)
        or len(stdout.encode("utf-8")) > _COMMAND_OUTPUT_BYTES
        or len(stderr.encode("utf-8")) > _COMMAND_OUTPUT_BYTES
    ):
        raise RuntimeError("git_history_rehydration_invalid")
    return stdout


def _validate_local_dir(local_dir: Path) -> Path:
    try:
        resolved = local_dir.resolve(strict=True)
        mode = stat.S_IMODE(resolved.stat().st_mode)
    except OSError as error:
        raise RuntimeError("git_history_rehydration_invalid") from error
    if (
        not local_dir.is_absolute()
        or local_dir.is_symlink()
        or not resolved.is_dir()
        or mode & 0o077
    ):
        raise RuntimeError("git_history_rehydration_invalid")
    return resolved


def _remote_path(prefix: str, run_spec_sha256: str) -> str:
    if not _hex(run_spec_sha256, {64}):
        raise RuntimeError("git_history_rehydration_invalid")
    return f"/tmp/nano-{prefix}-{run_spec_sha256}.tar"


def _repo_path(workspace: str, repo_relative_path: str) -> str:
    return (
        workspace if repo_relative_path == "." else f"{workspace}/{repo_relative_path}"
    )


async def _delete_remote_archive(actor: _TrustedActor, remote_path: str) -> None:
    await _execute(
        actor,
        f"""set -eu
archive={shlex.quote(remote_path)}
if test -e "$archive" || test -L "$archive"; then
  test -f "$archive" && test ! -L "$archive"
  find "$archive" -maxdepth 0 -type f -delete
fi
test ! -e "$archive" && test ! -L "$archive"
""",
        timeout=30.0,
    )


async def create_git_history_escrow(
    *,
    actor: _TrustedActor,
    local_dir: Path,
    capability: object,
    run_spec_sha256: str,
) -> GitHistoryEscrow | None:
    """Move no bytes yet; copy original Git admin state to a host-only file."""

    if git_history_access(capability) == GIT_HISTORY_ACCESS_REQUIRED:
        return None
    workspace = _workspace(actor)
    local_root = _validate_local_dir(local_dir)
    topology, repo_relative_path, _census, _manifest = _topology(
        await _execute(actor, _topology_script(workspace), timeout=120.0)
    )
    if topology == "zero":
        return None
    assert repo_relative_path is not None
    repo = _repo_path(workspace, repo_relative_path)
    remote_archive = _remote_path("git-history-escrow", run_spec_sha256)
    local_archive = local_root / f"git-history-{run_spec_sha256}.tar"
    if local_archive.exists() or local_archive.is_symlink():
        raise RuntimeError("git_history_rehydration_invalid")

    raw = await _execute(
        actor,
        f"""set -eu
set -o pipefail
umask 077
repo={shlex.quote(repo)}
archive={shlex.quote(remote_archive)}
test -d "$repo" && test ! -L "$repo"
cd -- "$repo"
test -d .git && test ! -L .git
test ! -e "$archive" && test ! -L "$archive"
source_commit=$(git rev-parse --verify 'HEAD^{{commit}}')
source_tree=$(git rev-parse --verify 'HEAD^{{tree}}')
source_count=$(git rev-list --all --count)
tar -cf "$archive" .git
test -f "$archive" && test ! -L "$archive"
size=$(wc -c < "$archive" | tr -d ' ')
case "$size" in *[!0-9]*|'') exit 41;; esac
test "$size" -gt 0 && test "$size" -le {_MAX_ESCROW_BYTES}
{_sha256_shell()}
digest=$(sha256_stream < "$archive")
printf '%s\t%s\t%s\t%s\t%s\n' "$size" "$digest" "$source_commit" "$source_tree" "$source_count"
""",
        timeout=180.0,
    )
    fields = raw.removesuffix("\n").split("\t")
    if (
        len(fields) != 5
        or not fields[0].isdigit()
        or not 0 < int(fields[0]) <= _MAX_ESCROW_BYTES
        or not _hex(fields[1], {64})
        or not _hex(fields[2], {40, 64})
        or not _hex(fields[3], {40, 64})
        or not fields[4].isdigit()
        or int(fields[4]) <= 0
    ):
        await _delete_remote_archive(actor, remote_archive)
        raise RuntimeError("git_history_rehydration_invalid")
    try:
        await actor.download_snapshot(remote_archive, local_archive)
        local_archive.chmod(0o600)
        if (
            local_archive.is_symlink()
            or not local_archive.is_file()
            or local_archive.stat().st_size != int(fields[0])
            or _sha256_file(local_archive) != fields[1]
        ):
            raise RuntimeError("git_history_rehydration_invalid")
    except BaseException:
        local_archive.unlink(missing_ok=True)
        raise
    finally:
        await _delete_remote_archive(actor, remote_archive)
    return GitHistoryEscrow(
        local_archive=local_archive,
        archive_sha256=fields[1],
        archive_size=int(fields[0]),
        workspace=workspace,
        repo_relative_path=repo_relative_path,
        source_commit_oid=fields[2],
        source_tree_oid=fields[3],
        preexisting_commit_count=int(fields[4]),
        run_spec_sha256=run_spec_sha256,
    )


def _baseline_matches(escrow: GitHistoryEscrow, receipt: object) -> bool:
    return (
        isinstance(receipt, Mapping)
        and receipt.get("status") == "isolated"
        and receipt.get("run_spec_sha256") == escrow.run_spec_sha256
        and receipt.get("admitted_repo_relative_path") == escrow.repo_relative_path
        and receipt.get("source_commit_oid") == escrow.source_commit_oid
        and receipt.get("source_tree_oid") == escrow.source_tree_oid
        and receipt.get("preexisting_commit_count") == escrow.preexisting_commit_count
        and _hex(receipt.get("root_commit_oid"), {40, 64})
        and _hex(receipt.get("root_tree_oid"), {40, 64})
    )


def _synthetic_state_script(
    *, repo: str, root_commit_oid: str, source_commit_oid: str
) -> str:
    return f"""set -eu
repo={shlex.quote(repo)}
root_commit={shlex.quote(root_commit_oid)}
source_commit={shlex.quote(source_commit_oid)}
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null LC_ALL=C
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR
cd -- "$repo"
if test -d .git && test ! -L .git \
  && test "$(git rev-parse --verify 'HEAD^{{commit}}')" = "$root_commit" \
  && test "$(git rev-list --all --count)" = 1 \
  && test "$(git for-each-ref --format='%(refname)' | wc -l | tr -d ' ')" = 1 \
  && test -z "$(git remote)" \
  && test ! -e .git/objects/info/alternates \
  && ! git cat-file -e "$source_commit^{{commit}}" 2>/dev/null \
  && test -z "$(git fsck --unreachable --no-reflogs 2>/dev/null)"; then
  printf 'unchanged\n'
else
  printf 'changed\n'
fi
"""


def _synthetic_guard_script(repo: str) -> str:
    return f"""set -eu
set -o pipefail
umask 077
repo={shlex.quote(repo)}
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null LC_ALL=C
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR
cd -- "$repo"
test -d .git && test ! -L .git
test -z "$(find .git -type l -print -quit)"
test -z "$(find .git ! -type d ! -type f -print -quit)"
guard=$(mktemp /tmp/nano-git-guard.XXXXXXXX)
trap 'find "$guard" -maxdepth 0 -type f -delete 2>/dev/null || true' EXIT HUP INT TERM
{{
  printf 'index-tree\t%s\n' "$(git write-tree)"
  git for-each-ref --format='ref\t%(refname)\t%(objectname)\t%(objecttype)'
  find .git \
    -path .git/objects -prune -o \
    -path .git/index -prune -o \
    -path .git/logs -prune -o \
    -print | LC_ALL=C sort | while IFS= read -r path; do
      if mode=$(stat -c %a "$path" 2>/dev/null); then :; else mode=$(stat -f %Lp "$path"); fi
      if test -f "$path"; then digest=$({_sha256_shell()} sha256_stream < "$path"); printf 'F\t%s\t%s\t%s\n' "$mode" "$path" "$digest"
      elif test -d "$path"; then printf 'D\t%s\t%s\n' "$mode" "$path"
      else exit 51; fi
    done
}} > "$guard"
{_sha256_shell()}
sha256_stream < "$guard"
"""


async def bind_git_history_escrow_to_isolated_state(
    *,
    actor: _TrustedActor,
    escrow: GitHistoryEscrow | None,
    baseline_receipt: object,
) -> GitHistoryEscrow | None:
    """Bind verifier restoration to the exact post-isolation Git semantics."""

    if escrow is None:
        return None
    if type(escrow) is not GitHistoryEscrow or not _baseline_matches(
        escrow, baseline_receipt
    ):
        raise RuntimeError("git_history_rehydration_invalid")
    repo = _repo_path(escrow.workspace, escrow.repo_relative_path)
    digest = (
        await _execute(actor, _synthetic_guard_script(repo), timeout=120.0)
    ).removesuffix("\n")
    if not _hex(digest, {64}):
        raise RuntimeError("git_history_rehydration_invalid")
    return replace(escrow, isolated_guard_sha256=digest)


async def rehydrate_git_history_for_verifier(
    *,
    actor: _TrustedActor,
    escrow: GitHistoryEscrow,
    baseline_receipt: object,
    background_process_count: int,
    timeout_sec: float = 120.0,
) -> str:
    """Restore exact original metadata only after agent isolation has closed."""

    if (
        type(escrow) is not GitHistoryEscrow
        or isinstance(background_process_count, bool)
        or not isinstance(background_process_count, int)
        or background_process_count < 0
        or isinstance(timeout_sec, bool)
        or not isinstance(timeout_sec, int | float)
        or timeout_sec <= 0
        or timeout_sec == float("inf")
        or timeout_sec != timeout_sec
        or not _baseline_matches(escrow, baseline_receipt)
        or not _hex(escrow.isolated_guard_sha256, {64})
    ):
        raise RuntimeError("git_history_rehydration_invalid")
    if background_process_count:
        return REHYDRATION_SKIPPED_BACKGROUND
    deadline = time.monotonic() + float(timeout_sec)

    def remaining(limit: float) -> float:
        value = min(limit, deadline - time.monotonic())
        if value <= 0:
            raise RuntimeError("git_history_rehydration_invalid")
        return value

    archive = escrow.local_archive
    if (
        archive.is_symlink()
        or not archive.is_file()
        or archive.stat().st_size != escrow.archive_size
        or _sha256_file(archive) != escrow.archive_sha256
    ):
        raise RuntimeError("git_history_rehydration_invalid")
    assert isinstance(baseline_receipt, Mapping)
    root_commit_oid = baseline_receipt["root_commit_oid"]
    root_tree_oid = baseline_receipt["root_tree_oid"]
    assert isinstance(root_commit_oid, str)
    assert isinstance(root_tree_oid, str)
    repo = _repo_path(escrow.workspace, escrow.repo_relative_path)
    guard = (
        await _execute(
            actor,
            _synthetic_guard_script(repo),
            timeout=remaining(120.0),
        )
    ).removesuffix("\n")
    if guard != escrow.isolated_guard_sha256:
        return REHYDRATION_SKIPPED_METADATA_CHANGED
    state = await _execute(
        actor,
        _synthetic_state_script(
            repo=repo,
            root_commit_oid=root_commit_oid,
            source_commit_oid=escrow.source_commit_oid,
        ),
        timeout=remaining(120.0),
    )
    if state == "changed\n":
        return REHYDRATION_SKIPPED_METADATA_CHANGED
    if state != "unchanged\n":
        raise RuntimeError("git_history_rehydration_invalid")

    remote_archive = _remote_path("git-history-rehydrate", escrow.run_spec_sha256)
    await _execute(
        actor,
        f"test ! -e {shlex.quote(remote_archive)} && test ! -L {shlex.quote(remote_archive)}\n",
        timeout=remaining(30.0),
    )
    try:
        await asyncio.wait_for(
            actor.upload_snapshot(archive, remote_archive),
            timeout=remaining(120.0),
        )
        result = await _execute(
            actor,
            f"""set -eu
set -o pipefail
umask 077
repo={shlex.quote(repo)}
archive={shlex.quote(remote_archive)}
expected_size={escrow.archive_size}
expected_digest={shlex.quote(escrow.archive_sha256)}
source_commit={shlex.quote(escrow.source_commit_oid)}
source_tree={shlex.quote(escrow.source_tree_oid)}
source_count={escrow.preexisting_commit_count}
root_commit={shlex.quote(root_commit_oid)}
root_tree={shlex.quote(root_tree_oid)}
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null LC_ALL=C
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR
test -d "$repo" && test ! -L "$repo"
cd -- "$repo"
test -f "$archive" && test ! -L "$archive"
test "$(wc -c < "$archive" | tr -d ' ')" = "$expected_size"
{_sha256_shell()}
test "$(sha256_stream < "$archive")" = "$expected_digest"
test "$(git rev-parse --verify 'HEAD^{{commit}}')" = "$root_commit"
test "$(git rev-parse --verify 'HEAD^{{tree}}')" = "$root_tree"
test "$(git rev-list --all --count)" = 1
test "$(git for-each-ref --format='%(refname)' | wc -l | tr -d ' ')" = 1
test -z "$(git remote)"
test ! -e .git/objects/info/alternates
! git cat-file -e "$source_commit^{{commit}}" 2>/dev/null
test -z "$(git fsck --unreachable --no-reflogs 2>/dev/null)"
stage=$(mktemp -d "$repo/.nano-git-rehydrate.XXXXXXXX")
old_admin=$(mktemp -d "$repo/.nano-git-isolated.XXXXXXXX")
rmdir "$old_admin"
swapped=false
cleanup() {{
  code=$?
  if test "$swapped" = true; then
    test ! -e .git || find .git -depth -delete 2>/dev/null || true
    test ! -d "$old_admin" || mv "$old_admin" .git 2>/dev/null || true
  fi
  test ! -e "$stage" || find "$stage" -depth -delete 2>/dev/null || true
  test ! -e "$archive" || find "$archive" -maxdepth 0 -type f -delete 2>/dev/null || true
  exit "$code"
}}
trap cleanup EXIT HUP INT TERM
tar -xf "$archive" -C "$stage"
test "$(find "$stage" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d ' ')" = 1
test -d "$stage/.git" && test ! -L "$stage/.git"
test -z "$(find "$stage/.git" -type l -print -quit)"
test -z "$(find "$stage/.git" ! -type d ! -type f -print -quit)"
for name in commondir gitdir; do test ! -e "$stage/.git/$name"; done
test ! -e "$stage/.git/modules" && test ! -e "$stage/.git/worktrees"
test ! -e "$stage/.git/shallow"
test ! -e "$stage/.git/objects/info/alternates"
test "$(GIT_DIR="$stage/.git" GIT_WORK_TREE="$repo" git rev-parse --verify 'HEAD^{{commit}}')" = "$source_commit"
test "$(GIT_DIR="$stage/.git" GIT_WORK_TREE="$repo" git rev-parse --verify 'HEAD^{{tree}}')" = "$source_tree"
test "$(GIT_DIR="$stage/.git" GIT_WORK_TREE="$repo" git rev-list --all --count)" = "$source_count"
mv .git "$old_admin"
swapped=true
mv "$stage/.git" .git
test "$(git rev-parse --verify 'HEAD^{{commit}}')" = "$source_commit"
test "$(git rev-parse --verify 'HEAD^{{tree}}')" = "$source_tree"
test "$(git rev-list --all --count)" = "$source_count"
find "$old_admin" -depth -delete
swapped=false
find "$stage" -depth -delete
find "$archive" -maxdepth 0 -type f -delete
trap - EXIT HUP INT TERM
printf 'restored\n'
""",
            timeout=remaining(180.0),
        )
    except BaseException:
        try:
            await _delete_remote_archive(actor, remote_archive)
        except BaseException:
            pass
        raise
    if result != "restored\n":
        raise RuntimeError("git_history_rehydration_invalid")
    archive.unlink()
    return REHYDRATION_RESTORED
