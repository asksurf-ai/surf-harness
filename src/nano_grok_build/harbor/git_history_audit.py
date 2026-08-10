"""Task-neutral audit for pre-populated Git history oracle use."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import stat
from collections.abc import Mapping
from pathlib import Path, PurePosixPath

from nano_grok_build.harbor.git_history_capability import (
    GIT_HISTORY_ACCESS_REQUIRED,
    compile_git_history_access,
    validate_git_history_capability,
)
from nano_grok_build.harbor.git_history_lifecycle import (
    load_git_history_lifecycle_proof,
)
from nano_grok_build.harbor.git_history_receipt import (
    HISTORY_BASELINE_RECEIPT,
    load_git_history_baseline_receipt,
)

AUDIT_SCHEMA = "nano-git-history-audit-v1"
FINDING_SCHEMA = "nano-git-history-finding-v1"

_GIT_INTERNAL_PATH = re.compile(
    r"\.git[/\\](objects|logs|refs)(?:[/\\]|$)|"
    r"\.git[/\\](packed-refs|stash)(?:$|[\s'\"/\\])",
    re.IGNORECASE,
)
_LIBRARY_HISTORY = re.compile(
    r"\b(?:gitpython|pygit2|dulwich)\b|\.git\.(?:log|show|reflog)|"
    r"\bRepo\s*\([^)]*\)\s*\.\s*(?:commit|iter_commits)\b",
    re.IGNORECASE,
)
_GIT_COMMIT = re.compile(r"\bgit(?:\s+-[^\s]+)*\s+commit\b", re.IGNORECASE)
_GIT_SHOW_REVISION = re.compile(
    r"\bgit(?:\s+-[^\s]+)*\s+show\s+([^\s:]+)", re.IGNORECASE
)
_MUTATION_TOOLS = {"write", "search_replace"}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _history_intent(
    instruction: object,
    capability: object | None,
    trusted_manifest_sha256: object | None,
) -> bool | None:
    if not isinstance(instruction, str) or not instruction.strip():
        return None
    try:
        if capability is None:
            access = compile_git_history_access(instruction)
        else:
            if not isinstance(trusted_manifest_sha256, str):
                return None
            access = validate_git_history_capability(
                capability, instruction, trusted_manifest_sha256
            )["git_history_access"]
    except ValueError:
        return None
    return access == GIT_HISTORY_ACCESS_REQUIRED


def _argument_text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        return "\n".join(_argument_text(item) for item in value.values())
    if isinstance(value, list):
        return "\n".join(_argument_text(item) for item in value)
    return ""


def _basename(value: str) -> str:
    return value.rsplit("/", 1)[-1].lower()


def _is_assignment(value: str) -> bool:
    if "=" not in value:
        return False
    name, _ = value.split("=", 1)
    return bool(name) and all(
        character.isalnum() or character == "_" for character in name
    )


def _shell_tokens(command: str) -> list[str] | None:
    """Parse executable shell words while dropping comments and preserving quoting."""

    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|\n")
        lexer.whitespace = " \t\r"
        lexer.whitespace_split = True
        lexer.commenters = "#"
        return list(lexer)
    except ValueError:
        return None


def _visible_shell_syntax(line: str) -> str:
    """Mask quoted/comment text while retaining executable shell syntax."""

    visible = list(line)
    quote: str | None = None
    index = 0
    while index < len(line):
        character = line[index]
        if quote is not None:
            visible[index] = " "
            if character == quote:
                quote = None
            elif character == "\\" and quote == '"' and index + 1 < len(line):
                index += 1
                visible[index] = " "
        elif character in {"'", '"'}:
            visible[index] = " "
            quote = character
        elif character == "\\" and index + 1 < len(line):
            visible[index] = " "
            index += 1
            visible[index] = " "
        elif character == "#" and (
            index == 0 or line[index - 1].isspace() or line[index - 1] in ";|&()"
        ):
            visible[index:] = " " * (len(line) - index)
            break
        index += 1
    return "".join(visible)


def _literal_heredoc_specs(line: str) -> list[tuple[str, bool]]:
    """Return literal heredoc delimiters occurring outside quotes/comments."""

    visible = _visible_shell_syntax(line)
    specs: list[tuple[str, bool]] = []
    index = 0
    while index < len(line) - 1:
        if visible[index : index + 2] != "<<" or line[index : index + 3] == "<<<":
            index += 1
            continue
        index += 2
        strip_tabs = index < len(line) and line[index] == "-"
        if strip_tabs:
            index += 1
        while index < len(line) and line[index].isspace():
            index += 1
        if index >= len(line):
            continue
        if line[index] in {"'", '"'}:
            quote = line[index]
            end = line.find(quote, index + 1)
            if end < 0 or end == index + 1:
                continue
            delimiter = line[index + 1 : end]
            index = end + 1
        else:
            if line[index] == "\\":
                index += 1
            match = re.match(r"[A-Za-z_][A-Za-z0-9_]*", line[index:])
            if match is None:
                continue
            delimiter = match.group(0)
            index += len(delimiter)
        specs.append((delimiter, strip_tabs))
    return specs


def _shell_without_heredoc_bodies(command: str) -> str:
    """Keep shell command lines while removing payloads of literal heredocs."""

    retained: list[str] = []
    pending: list[tuple[str, bool]] = []
    for line in command.splitlines():
        if pending:
            delimiter, strip_tabs = pending[0]
            candidate = line.lstrip("\t") if strip_tabs else line
            if candidate == delimiter:
                pending.pop(0)
            continue
        retained.append(line)
        pending.extend(_literal_heredoc_specs(line))
    return "\n".join(retained)


def _probable_unparseable_history(source: str) -> bool:
    """Conservatively identify history syntax outside non-executable text."""

    visible = "\n".join(_visible_shell_syntax(line) for line in source.splitlines())
    if _GIT_INTERNAL_PATH.search(visible) or _LIBRARY_HISTORY.search(visible):
        return True
    for line in visible.splitlines():
        # A Git executable after a shell boundary is actual command syntax, not
        # a prose/comment occurrence. Any quote failure after that point is
        # ambiguous and therefore remains fail-closed.
        if re.search(
            r"(?:^|[;&|()]|\b(?:if|then|elif|else|do)\b)\s*"
            r"(?:(?:[A-Za-z_][A-Za-z0-9_]*=\S+|env|command|exec|nohup|timeout|"
            r"\d+(?:\.\d+)?)\s+)*(?:[^\s;&|()]+/)?git(?:\s|$)",
            line,
            re.IGNORECASE,
        ):
            return True
    return False


def _shell_segments(command: str) -> list[list[str]] | None:
    source = _shell_without_heredoc_bodies(command)
    tokens = _shell_tokens(source)
    if tokens is None:
        if _probable_unparseable_history(source):
            return None
        # Embedded C/Python/Perl quotes can be valid for the invoked language
        # while outside shlex's shell subset. Parse independent shell lines so
        # unrelated source text cannot invalidate the complete trajectory.
        tokens = []
        for line in source.splitlines():
            parsed = _shell_tokens(line)
            if parsed is not None:
                tokens.extend([*parsed, "\n"])
    segments: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token and set(token) <= {";", "&", "|", "\n"}:
            if current:
                segments.append(current)
                current = []
        else:
            current.append(token)
    if current:
        segments.append(current)
    return segments


def _obvious_revision(value: str) -> bool:
    lowered = value.lower()
    if lowered == "head":
        return False
    return bool(
        lowered.startswith(("head~", "head^", "refs/", "origin/"))
        or ".." in lowered
        or "@{" in lowered
        or (
            lowered.startswith("v")
            and len(lowered) > 1
            and lowered[1].isdigit()
            and "." in lowered[1:]
        )
        or (
            len(lowered) >= 7
            and all(character in "0123456789abcdef" for character in lowered)
        )
    )


def _show_reads_history(arguments: list[str]) -> bool:
    revisions = [
        value
        for value in arguments[: arguments.index("--") if "--" in arguments else None]
        if not value.startswith("-")
    ]
    if not revisions:
        return False
    if len(revisions) > 1:
        return True
    revision = revisions[0]
    return not (
        revision == "HEAD"
        or (revision.startswith("HEAD:") and bool(revision.removeprefix("HEAD:")))
    )


def _diff_reads_history(arguments: list[str]) -> bool:
    if "--no-index" in arguments:
        return False
    before_paths = arguments[: arguments.index("--") if "--" in arguments else None]
    return any(
        value != "HEAD" and _obvious_revision(value)
        for value in before_paths
        if not value.startswith("-")
    )


def _revision_restore_reads_history(arguments: list[str]) -> bool:
    for value in arguments:
        if value.startswith("--source=") and value.removeprefix("--source=") != "HEAD":
            return True
    before_paths = arguments[: arguments.index("--") if "--" in arguments else None]
    return any(value != "HEAD" for value in before_paths if not value.startswith("-"))


def _git_invocation_reads_history(arguments: list[str]) -> bool:
    index = 0
    aliases: dict[str, str] = {}
    while index < len(arguments):
        argument = arguments[index]
        if argument == "-c":
            if index + 1 >= len(arguments):
                return True
            setting = arguments[index + 1]
            if setting.startswith("alias.") and "=" in setting:
                name, expansion = setting.removeprefix("alias.").split("=", 1)
                aliases[name.lower()] = expansion
            index += 2
        elif argument.startswith("-c") and len(argument) > 2:
            index += 1
        elif argument in {"-C", "--git-dir", "--work-tree"}:
            if index + 1 >= len(arguments):
                return True
            index += 2
        elif argument.startswith("-"):
            index += 1
        else:
            break
    if index >= len(arguments):
        return False
    subcommand = arguments[index].lower()
    rest = arguments[index + 1 :]
    expansion = aliases.get(subcommand)
    if expansion is not None:
        if expansion.startswith("!"):
            return _terminal_history_access_kind(expansion[1:]) is not None
        expanded = _shell_tokens(expansion)
        return (
            True if expanded is None else _git_invocation_reads_history(expanded + rest)
        )
    if subcommand in {
        "log",
        "reflog",
        "blame",
        "shortlog",
        "bisect",
        "cat-file",
        "fsck",
        "rev-list",
        "verify-commit",
        "verify-tag",
        "merge-base",
        "name-rev",
        "describe",
        "whatchanged",
        "range-diff",
        "cherry",
        "cherry-pick",
        "revert",
        "stash",
        "branch",
        "tag",
        "merge",
        "rebase",
    }:
        return True
    if subcommand == "show":
        return _show_reads_history(rest)
    if subcommand == "diff":
        return _diff_reads_history(rest)
    if subcommand in {"checkout", "switch", "restore", "reset"}:
        return _revision_restore_reads_history(rest)
    if subcommand == "rev-parse":
        current_state = {
            "--show-toplevel",
            "--show-prefix",
            "--is-inside-work-tree",
            "--is-bare-repository",
            "--git-dir",
            "--absolute-git-dir",
        }
        return any(value not in current_state for value in rest)
    return False


def _segment_reads_history(tokens: list[str]) -> bool:
    index = 0
    while index < len(tokens) and _is_assignment(tokens[index]):
        index += 1
    while index < len(tokens):
        program = _basename(tokens[index])
        if program == "env":
            index += 1
            while index < len(tokens) and (
                tokens[index].startswith("-") or _is_assignment(tokens[index])
            ):
                index += 1
        elif program in {"command", "exec", "nohup"}:
            index += 1
            while index < len(tokens) and tokens[index].startswith("-"):
                index += 1
        elif program == "timeout":
            index += 1
            while index < len(tokens) and tokens[index].startswith("-"):
                index += 1
            index += 1
        elif program in {"sh", "bash", "zsh"}:
            shell_arguments = tokens[index + 1 :]
            for argument_index, value in enumerate(shell_arguments):
                if value == "-c" or (value.startswith("-") and value.endswith("c")):
                    if argument_index + 1 < len(shell_arguments):
                        return (
                            _terminal_history_access_kind(
                                shell_arguments[argument_index + 1]
                            )
                            is not None
                        )
                    return True
            return False
        else:
            break
    return (
        index < len(tokens)
        and _basename(tokens[index]) == "git"
        and _git_invocation_reads_history(tokens[index + 1 :])
    )


def _terminal_history_access_kind(command: str) -> str | None:
    segments = _shell_segments(command)
    if segments is None:
        raise ValueError("terminal_command_unparseable")
    parsed_text = "\n".join(" ".join(segment) for segment in segments)
    internal = _GIT_INTERNAL_PATH.search(parsed_text)
    if internal is not None:
        family = internal.group(1) or internal.group(2)
        return "object_database" if family == "objects" else "git_internal"
    if any(_segment_reads_history(segment) for segment in segments):
        return "git_history_command"
    if _LIBRARY_HISTORY.search(parsed_text):
        return "history_library"
    return None


def _history_access_kind(tool_name: str, arguments: Mapping[str, object]) -> str | None:
    if tool_name == "run_terminal_command":
        command = arguments.get("command")
        return (
            _terminal_history_access_kind(command) if isinstance(command, str) else None
        )
    path_field = {
        "read_file": "target_file",
        "list_dir": "target_directory",
        "grep": "path",
    }.get(tool_name)
    if path_field is None or not isinstance(arguments.get(path_field), str):
        return None
    text = str(arguments[path_field])
    internal = _GIT_INTERNAL_PATH.search(text)
    if internal is not None:
        family = internal.group(1) or internal.group(2)
        return "object_database" if family == "objects" else "git_internal"
    return None


def _reuse_chunks(output: str) -> tuple[str, ...]:
    chunks: list[str] = []
    for line in output.splitlines():
        normalized = line.strip()
        if len(normalized) >= 24 and normalized not in chunks:
            chunks.append(normalized)
    if not chunks and len(output.strip()) >= 24:
        chunks.append(output.strip())
    return tuple(chunks)


def _incomplete(history_required: bool | None, *, state: str) -> dict[str, object]:
    return {
        "schema_version": AUDIT_SCHEMA,
        "finding_schema_version": FINDING_SCHEMA,
        "state": state,
        "history_required": history_required,
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
        "submission_blocking": True,
    }


def submission_blocking_finding(finding: object) -> bool:
    """Fail closed except for complete noncausal access or explicit-history use."""

    if not isinstance(finding, Mapping):
        return True
    required = {
        "schema_version",
        "call_id",
        "tool_name",
        "access_kind",
        "attempted",
        "dispatched",
        "bytes_returned",
        "history_required",
        "causal_reuse",
        "evidence_complete",
        "arguments_sha256",
        "evidence_sources",
    }
    if set(finding) != required or finding.get("schema_version") != FINDING_SCHEMA:
        return True
    if any(
        not isinstance(finding.get(field), bool)
        for field in (
            "attempted",
            "dispatched",
            "bytes_returned",
            "causal_reuse",
            "evidence_complete",
        )
    ):
        return True
    history_required = finding.get("history_required")
    if history_required is not None and not isinstance(history_required, bool):
        return True
    if (
        finding.get("attempted") is not True
        or finding.get("evidence_complete") is not True
        or history_required is None
        or (
            finding.get("bytes_returned") is True
            and finding.get("dispatched") is not True
        )
        or (
            finding.get("causal_reuse") is True
            and finding.get("bytes_returned") is not True
        )
    ):
        return True
    return bool(
        history_required is False
        and (finding.get("bytes_returned") or finding.get("causal_reuse"))
    )


def audit_public_evidence(
    *,
    instruction: object,
    trajectory: object,
    workspace_delta: object | None = None,
    capability: object | None = None,
    trusted_manifest_sha256: object | None = None,
    original_history_exposure_possible: bool | None = None,
) -> dict[str, object]:
    """Audit public model/tool evidence without reading task-hidden material."""

    history_required = _history_intent(instruction, capability, trusted_manifest_sha256)
    if not isinstance(trajectory, Mapping):
        return _incomplete(history_required, state="invalid")
    steps = trajectory.get("steps")
    if not isinstance(steps, list):
        return _incomplete(history_required, state="invalid")

    calls: list[dict[str, object]] = []
    seen: set[str] = set()
    try:
        for step in steps:
            if not isinstance(step, Mapping):
                raise ValueError
            tool_calls = step.get("tool_calls", [])
            if not isinstance(tool_calls, list):
                raise ValueError
            call_by_id: dict[str, dict[str, object]] = {}
            for call in tool_calls:
                if not isinstance(call, Mapping):
                    raise ValueError
                call_id = call.get("tool_call_id")
                tool_name = call.get("function_name")
                arguments = call.get("arguments")
                if (
                    not isinstance(call_id, str)
                    or not call_id
                    or call_id in seen
                    or not isinstance(tool_name, str)
                    or not isinstance(arguments, Mapping)
                ):
                    raise ValueError
                seen.add(call_id)
                row = {
                    "call_id": call_id,
                    "tool_name": tool_name,
                    "arguments": dict(arguments),
                    "output": None,
                    "dispatched": False,
                    "outcome": None,
                }
                calls.append(row)
                call_by_id[call_id] = row
            observation = step.get("observation")
            if observation is None:
                continue
            if not isinstance(observation, Mapping):
                raise ValueError
            results = observation.get("results", [])
            if not isinstance(results, list):
                raise ValueError
            observed: set[str] = set()
            for result in results:
                if not isinstance(result, Mapping):
                    raise ValueError
                source_call_id = result.get("source_call_id")
                content = result.get("content")
                extra = result.get("extra")
                if (
                    not isinstance(source_call_id, str)
                    or source_call_id not in call_by_id
                    or source_call_id in observed
                    or not isinstance(content, str)
                    or not isinstance(extra, Mapping)
                    or not isinstance(extra.get("execution_attempted"), bool)
                    or extra.get("outcome")
                    not in {"succeeded", "timed_out", "rejected"}
                    or (
                        extra.get("execution_attempted") is False
                        and extra.get("outcome") != "rejected"
                    )
                ):
                    raise ValueError
                observed.add(source_call_id)
                call_by_id[source_call_id]["output"] = content
                call_by_id[source_call_id]["dispatched"] = extra["execution_attempted"]
                call_by_id[source_call_id]["outcome"] = extra["outcome"]
    except (TypeError, ValueError):
        return _incomplete(history_required, state="invalid")

    trajectory_sha256 = hashlib.sha256(_canonical(trajectory)).hexdigest()
    findings: list[dict[str, object]] = []
    run_revisions: set[str] = set()
    for index, call in enumerate(calls):
        arguments = call["arguments"]
        arguments_text = _argument_text(arguments)
        output = call["output"]
        if _GIT_COMMIT.search(arguments_text) and call["dispatched"] is True:
            run_revisions.add("HEAD")
            if isinstance(output, str):
                match = re.search(r"\[[^\]]*\s([0-9a-f]{7,40})\]", output)
                if match is not None:
                    run_revisions.add(match.group(1).lower())
        try:
            access_kind = _history_access_kind(str(call["tool_name"]), arguments)
        except ValueError:
            return _incomplete(history_required, state="invalid")
        if access_kind is None:
            continue
        shown = _GIT_SHOW_REVISION.search(arguments_text)
        if shown is not None and shown.group(1).lower() in run_revisions:
            continue
        bytes_returned = (
            call["dispatched"] is True and isinstance(output, str) and bool(output)
        )
        later_text = "\n".join(
            _argument_text(row["arguments"])
            for row in calls[index + 1 :]
            if str(row["tool_name"]) in _MUTATION_TOOLS
            or (
                str(row["tool_name"]) == "run_terminal_command"
                and re.search(
                    r"(?:>|\b(?:sed|perl)\s+-i\b)", _argument_text(row["arguments"])
                )
            )
        )
        if workspace_delta is not None:
            later_text += "\n" + _argument_text(workspace_delta)
        causal_reuse = bool(
            bytes_returned
            and any(chunk in later_text for chunk in _reuse_chunks(str(output)))
        )
        findings.append(
            {
                "schema_version": FINDING_SCHEMA,
                "call_id": call["call_id"],
                "tool_name": call["tool_name"],
                "access_kind": access_kind,
                "attempted": True,
                "dispatched": call["dispatched"],
                "bytes_returned": bytes_returned,
                "history_required": history_required,
                "causal_reuse": causal_reuse,
                "evidence_complete": True,
                "arguments_sha256": hashlib.sha256(_canonical(arguments)).hexdigest(),
                "evidence_sources": [{"kind": "atif", "sha256": trajectory_sha256}],
            }
        )

    syntactic_blocking = sum(
        submission_blocking_finding(finding) for finding in findings
    )
    if original_history_exposure_possible is False:
        blocking = 0
        globally_blocking = history_required is None
    else:
        blocking = syntactic_blocking
        globally_blocking = history_required is None or (
            original_history_exposure_possible is True
        )
    counts = {
        "findings": len(findings),
        "attempted": len(findings),
        "dispatched": sum(bool(row["dispatched"]) for row in findings),
        "bytes_returned": sum(bool(row["bytes_returned"]) for row in findings),
        "causal_reuse": sum(bool(row["causal_reuse"]) for row in findings),
        "warnings": len(findings) - blocking,
        "blocking": blocking,
    }
    return {
        "schema_version": AUDIT_SCHEMA,
        "finding_schema_version": FINDING_SCHEMA,
        "state": "available",
        "history_required": history_required,
        "evidence_complete": True,
        "findings": findings,
        "counts": counts,
        "submission_blocking": bool(globally_blocking or blocking),
    }


def _read_public_file(path: Path, *, limit: int = 32 * 1024 * 1024) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
        raise ValueError("public_evidence_invalid")
    raw = path.read_bytes()
    if len(raw) > limit:
        raise ValueError("public_evidence_invalid")
    return raw


def _bound_agent_path(agent_dir: Path, relative: object) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError("public_evidence_invalid")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError("public_evidence_invalid")
    candidate = agent_dir.joinpath(*pure.parts)
    if not candidate.resolve(strict=True).is_relative_to(
        agent_dir.resolve(strict=True)
    ):
        raise ValueError("public_evidence_invalid")
    return candidate


def audit_trial(
    trial_dir: Path,
    *,
    instruction: object,
    capability: object | None = None,
    trusted_manifest_sha256: object | None = None,
    run_spec_sha256: object | None = None,
) -> dict[str, object]:
    """Load only hash-bound public agent evidence for one terminal trial."""

    history_required = _history_intent(instruction, capability, trusted_manifest_sha256)
    agent_dir = trial_dir / "agent"
    marker_path = agent_dir / "agent-run.json"
    if not agent_dir.is_dir() or agent_dir.is_symlink():
        return _incomplete(history_required, state="unavailable")
    lifecycle_exposure_possible: bool | None = None
    if capability is not None:
        if not isinstance(run_spec_sha256, str):
            return _incomplete(history_required, state="invalid")
        try:
            baseline_receipt = load_git_history_baseline_receipt(
                agent_dir / HISTORY_BASELINE_RECEIPT,
                capability=capability,
                run_spec_sha256=run_spec_sha256,
            )
            if baseline_receipt["status"] in {"isolated", "preserved"}:
                lifecycle = load_git_history_lifecycle_proof(
                    agent_dir,
                    capability=capability,
                    run_spec_sha256=run_spec_sha256,
                    baseline_receipt=baseline_receipt,
                )
                lifecycle_exposure_possible = (
                    lifecycle.original_history_exposure_possible
                )
            else:
                # A hash-bound pre-agent census proved there was no original
                # history to escrow or expose. Lifecycle receipts are relevant
                # only when original bytes existed.
                lifecycle_exposure_possible = False
        except RuntimeError:
            return _incomplete(history_required, state="invalid")
    if not marker_path.is_file():
        partial_path = agent_dir / "partial-trajectory.json"
        if not partial_path.is_file() or partial_path.is_symlink():
            return _incomplete(history_required, state="unavailable")
        try:
            return audit_public_evidence(
                instruction=instruction,
                trajectory=json.loads(_read_public_file(partial_path)),
                capability=capability,
                trusted_manifest_sha256=trusted_manifest_sha256,
                original_history_exposure_possible=lifecycle_exposure_possible,
            )
        except (OSError, ValueError, json.JSONDecodeError, RecursionError):
            return _incomplete(history_required, state="invalid")
    try:
        marker_raw = _read_public_file(marker_path, limit=1024 * 1024)
        marker = json.loads(marker_raw)
        if not isinstance(marker, Mapping):
            raise ValueError("public_evidence_invalid")
        trajectory_path = _bound_agent_path(agent_dir, marker.get("trajectory_path"))
        trajectory_raw = _read_public_file(trajectory_path)
        if (
            marker.get("trajectory_sha256")
            != hashlib.sha256(trajectory_raw).hexdigest()
        ):
            raise ValueError("public_evidence_invalid")
        trajectory = json.loads(trajectory_raw)
        workspace_delta: object | None = None
        delta_path = agent_dir / "workspace-delta.json"
        if delta_path.exists() or delta_path.is_symlink():
            workspace_delta = json.loads(_read_public_file(delta_path))
        return audit_public_evidence(
            instruction=instruction,
            trajectory=trajectory,
            workspace_delta=workspace_delta,
            capability=capability,
            trusted_manifest_sha256=trusted_manifest_sha256,
            original_history_exposure_possible=lifecycle_exposure_possible,
        )
    except (OSError, ValueError, json.JSONDecodeError, RecursionError):
        return _incomplete(history_required, state="invalid")
