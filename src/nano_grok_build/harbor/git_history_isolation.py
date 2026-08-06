"""Trusted prelaunch removal of pre-existing Git history."""

# ruff: noqa: E501 - the trusted shell program remains line-auditable verbatim
from __future__ import annotations

import json
import os
import shlex
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol

from nano_grok_build.harbor.git_history_capability import GIT_HISTORY_ACCESS_REQUIRED
from nano_grok_build.harbor.git_history_receipt import (
    HISTORY_BASELINE_POLICY,
    HISTORY_BASELINE_RECEIPT,
    HISTORY_BASELINE_SCHEMA,
    _hex,
)
from nano_grok_build.harbor.git_history_receipt import git_history_access as _access
from nano_grok_build.harbor.git_history_receipt import (
    parse_git_history_baseline_receipt as _receipt,
)


class _TrustedActor(Protocol):
    def snapshot_workspace_root(self) -> str: ...

    async def exec_snapshot(self, command: str, *, timeout_sec: float) -> object: ...


def _script(
    workspace: str,
    access: str,
    run_spec_sha256: str,
    capability: Mapping[str, object],
) -> str:
    preserved = "true" if access == GIT_HISTORY_ACCESS_REQUIRED else "false"
    return f"""set -eu
umask 077
workspace={shlex.quote(workspace)}
run_hash={shlex.quote(run_spec_sha256)}
instruction_hash={shlex.quote(str(capability["canonical_instruction_sha256"]))}
manifest_hash={shlex.quote(str(capability["trusted_manifest_sha256"]))}
preserved={preserved}
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR
test -d "$workspace" && test ! -L "$workspace"
cd -- "$workspace"
test "$(git rev-parse --show-toplevel)" = "$workspace"
test -d .git && test ! -L .git
for name in commondir gitdir; do test ! -e ".git/$name"; test ! -L ".git/$name"; done
root_admin=$(CDPATH= cd -- .git && pwd -P)
common_admin=$(git rev-parse --git-common-dir)
case "$common_admin" in /*) ;; *) common_admin="$workspace/$common_admin" ;; esac
common_admin=$(CDPATH= cd -- "$common_admin" && pwd -P)
test "$common_admin" = "$root_admin"
source_commit=$(git rev-parse --verify 'HEAD^{{commit}}')
source_tree=$(git rev-parse --verify 'HEAD^{{tree}}')
source_count=$(git rev-list --all --count)
if test "$preserved" = false; then
  test -z "$(find . -path './.git' -prune -o -name .git -print -quit)"
  test -z "$(find . -path './.git' -prune -o -type d -exec sh -c 'test -f "$1/HEAD" && test -d "$1/objects" && test -d "$1/refs"' sh {{}} \\; -print -quit)"
  test -z "$(find . -path './.git' -prune -o -type f \\( -path '*/objects/pack/*.pack' -o -path '*/objects/pack/*.idx' \\) -print -quit)"
  test -z "$(find . -path './.git' -prune -o -type d -name objects -exec sh -c 'cd "$1" && find . -mindepth 2 -maxdepth 2 -type f | LC_ALL=C grep -Eq "^\\./[0-9a-f]{{2}}/([0-9a-f]{{38}}|[0-9a-f]{{62}})$"' sh {{}} \\; -print -quit)"
  test ! -e .git/modules
  test ! -L .git/modules
  test ! -e .git/worktrees
  test ! -L .git/worktrees
  test -z "$(find .git -type l -print -quit)"
  test ! -e .git/shallow
  test ! -e .git/objects/info/alternates
  test -z "$(git ls-files -u)"
  test -z "$(git ls-files --stage | awk '$1 == 160000 {{print; exit}}')"
  test -z "$(git ls-files --stage | awk '$1 == 000000 {{print; exit}}')"
  test "$(git config --bool core.sparseCheckout 2>/dev/null || printf false)" != true
  test -z "$(git ls-files -v | awk 'substr($0,1,1) ~ /[a-zS]/ {{print; exit}}')"
  state_dir=$(mktemp -d /tmp/nano-git-state.XXXXXXXX)
  new_admin= old_admin=
  trap 'if test ! -e .git && test -n "$old_admin" && test -d "$old_admin"; then mv "$old_admin" .git 2>/dev/null || true; fi; for path in "$state_dir" "$new_admin" "$old_admin"; do test -z "$path" || test ! -e "$path" || find "$path" -depth -delete 2>/dev/null || true; done' EXIT HUP INT TERM
  git status --porcelain=v2 -z --untracked-files=all > "$state_dir/status"
  git diff --binary --cached > "$state_dir/cached"
  git diff --binary > "$state_dir/worktree"
  filemode=$(git config --bool core.filemode 2>/dev/null || printf true)
  symlinks=$(git config --bool core.symlinks 2>/dev/null || printf true)
  ignorecase=$(git config --bool core.ignorecase 2>/dev/null || printf false)
  object_format=$(git rev-parse --show-object-format)
  new_admin=$(mktemp -d .nano-git-new.XXXXXXXX)
  git init -q --bare --object-format="$object_format" "$new_admin"
  printf '%s\n' "$source_tree" | git pack-objects --revs --stdout > "$state_dir/tree.pack"
  GIT_DIR="$new_admin" GIT_OBJECT_DIRECTORY="$new_admin/objects" git index-pack --stdin < "$state_dir/tree.pack" >/dev/null
  format_version=0
  test "$object_format" = sha1 || format_version=1
  printf '[core]\n\trepositoryformatversion = %s\n\tfilemode = %s\n\tsymlinks = %s\n\tignorecase = %s\n\tbare = false\n\tlogallrefupdates = false\n\thooksPath = /dev/null\n[user]\n\tname = Nano Baseline\n\temail = baseline@invalid.local\n' \
    "$format_version" "$filemode" "$symlinks" "$ignorecase" > "$new_admin/config"
  test "$object_format" = sha1 || printf '[extensions]\n\tobjectFormat = %s\n' "$object_format" >> "$new_admin/config"
  GIT_DIR="$new_admin" GIT_WORK_TREE="$workspace" git read-tree "$source_tree"
  test ! -s "$state_dir/cached" || GIT_DIR="$new_admin" GIT_WORK_TREE="$workspace" git apply --cached --binary "$state_dir/cached"
  root_commit=$(printf 'Trusted current baseline %s\n' "$run_hash" | \
    GIT_AUTHOR_NAME='Nano Baseline' GIT_AUTHOR_EMAIL='baseline@invalid.local' \
    GIT_COMMITTER_NAME='Nano Baseline' GIT_COMMITTER_EMAIL='baseline@invalid.local' \
    GIT_AUTHOR_DATE='2000-01-01T00:00:00Z' GIT_COMMITTER_DATE='2000-01-01T00:00:00Z' \
    GIT_DIR="$new_admin" GIT_WORK_TREE="$workspace" git commit-tree "$source_tree")
  GIT_DIR="$new_admin" GIT_WORK_TREE="$workspace" git update-ref refs/heads/nano-baseline "$root_commit"
  GIT_DIR="$new_admin" GIT_WORK_TREE="$workspace" git symbolic-ref HEAD refs/heads/nano-baseline
  GIT_DIR="$new_admin" GIT_WORK_TREE="$workspace" git repack -Adq --unpack-unreachable=now
  GIT_DIR="$new_admin" GIT_WORK_TREE="$workspace" git prune --expire now
  test -z "$(GIT_DIR="$new_admin" GIT_WORK_TREE="$workspace" git fsck --unreachable --no-reflogs 2>/dev/null)"
  ! GIT_DIR="$new_admin" GIT_WORK_TREE="$workspace" git cat-file -e "$source_commit^{{commit}}" 2>/dev/null
  test "$(GIT_DIR="$new_admin" GIT_WORK_TREE="$workspace" git rev-list --all --count)" = 1
  old_admin=$(mktemp -d .nano-git-old.XXXXXXXX)
  rmdir "$old_admin"
  mv .git "$old_admin"
  mv "$new_admin" .git
  new_admin=
  find "$old_admin" -depth -delete
  old_admin=
  git status --porcelain=v2 -z --untracked-files=all > "$state_dir/status.after"
  git diff --binary --cached > "$state_dir/cached.after"
  git diff --binary > "$state_dir/worktree.after"
  cmp "$state_dir/status" "$state_dir/status.after"
  cmp "$state_dir/cached" "$state_dir/cached.after"
  cmp "$state_dir/worktree" "$state_dir/worktree.after"
  status=isolated
  old_metadata_removed=true
else
  root_commit=$source_commit
  status=preserved
  old_metadata_removed=false
fi
root_tree=$(git rev-parse "$root_commit^{{tree}}")
root_count=$(git rev-list --all --count)
ref_count=$(git for-each-ref --format='%(refname)' | wc -l | tr -d ' ')
remote_count=$(git remote | wc -l | tr -d ' ')
if test -f .git/objects/info/alternates; then alternate_count=$(wc -l < .git/objects/info/alternates | tr -d ' '); else alternate_count=0; fi
test "$preserved" = true || {{ test "$root_count" = 1 && test "$ref_count" = 1 && test "$remote_count" = 0 && test "$alternate_count" = 0 && test "$root_tree" = "$source_tree"; }}
printf '{{"schema_version":"{HISTORY_BASELINE_SCHEMA}","policy_version":"{HISTORY_BASELINE_POLICY}","run_spec_sha256":"%s","capability_instruction_sha256":"%s","trusted_manifest_sha256":"%s","status":"%s","source_commit_oid":"%s","source_tree_oid":"%s","root_commit_oid":"%s","root_tree_oid":"%s","preexisting_commit_count":%s,"root_commit_count":%s,"ref_count":%s,"remote_count":%s,"alternate_count":%s,"old_metadata_removed":%s}}\n' \
  "$run_hash" "$instruction_hash" "$manifest_hash" "$status" "$source_commit" "$source_tree" "$root_commit" "$root_tree" "$source_count" "$root_count" "$ref_count" "$remote_count" "$alternate_count" "$old_metadata_removed"
"""


async def isolate_preexisting_git_history(
    *,
    actor: _TrustedActor,
    artifact_dir: Path,
    capability: object,
    run_spec_sha256: str,
) -> dict[str, object]:
    """Transform once before capture/agent dispatch, or fail the trial closed."""

    access = _access(capability)
    if (
        not _hex(run_spec_sha256, {64})
        or not artifact_dir.is_absolute()
        or artifact_dir.is_symlink()
        or not artifact_dir.is_dir()
    ):
        raise RuntimeError("git_history_baseline_binding_invalid")
    workspace = actor.snapshot_workspace_root()
    if (
        not isinstance(workspace, str)
        or not workspace.startswith("/")
        or "\x00" in workspace
    ):
        raise RuntimeError("git_history_baseline_workspace_invalid")
    assert isinstance(capability, Mapping)
    result = await actor.exec_snapshot(
        _script(workspace, access, run_spec_sha256, capability), timeout_sec=120.0
    )
    stdout, stderr = getattr(result, "stdout", None), getattr(result, "stderr", None)
    if (
        getattr(result, "return_code", None) != 0
        or not isinstance(stdout, str)
        or not isinstance(stderr, str)
        or len(stdout) > 16 * 1024
        or len(stderr) > 16 * 1024
    ):
        raise RuntimeError("git_history_baseline_failed")
    receipt = _receipt(stdout, run_spec_sha256, access)
    if (
        receipt["capability_instruction_sha256"]
        != capability["canonical_instruction_sha256"]
        or receipt["trusted_manifest_sha256"] != capability["trusted_manifest_sha256"]
    ):
        raise RuntimeError("git_history_baseline_receipt_invalid")
    payload = (
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    descriptor = os.open(
        artifact_dir / HISTORY_BASELINE_RECEIPT,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    return receipt
