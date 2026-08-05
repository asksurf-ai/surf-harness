"""Task-neutral audit for pre-populated Git history oracle use."""

from __future__ import annotations

import hashlib
import json
import re
import stat
from collections.abc import Mapping
from pathlib import Path, PurePosixPath

AUDIT_SCHEMA = "nano-git-history-audit-v1"
FINDING_SCHEMA = "nano-git-history-finding-v1"

_EXPLICIT_HISTORY = re.compile(
    r"\b(?:git\s+(?:commit\s+)?history|commit\s+history|revision\s+history|"
    r"version\s+history|reflog|prior\s+commit|previous\s+revision|"
    r"recover\w*\s+(?:a\s+)?(?:deleted\s+)?commit)\b",
    re.IGNORECASE,
)
_AMBIGUOUS_HISTORY = re.compile(
    r"\b(?:history|earlier\s+version|previous\s+version|old\s+version)\b",
    re.IGNORECASE,
)
_GIT_HISTORY_COMMAND = re.compile(
    r"\bgit(?:\s+-[^\s]+(?:=[^\s]+)?)*\s+"
    r"(?:log|show|reflog|cat-file|fsck)\b",
    re.IGNORECASE,
)
_GIT_ALIAS_HISTORY = re.compile(
    r"\bgit\s+-c\s+alias\.[^\s=]+=(?:[^\s]*\b)?"
    r"(?:log|show|reflog|cat-file|fsck)\b",
    re.IGNORECASE,
)
_HISTORICAL_REVISION_PATH = re.compile(
    r"(?:\b[0-9a-f]{7,40}|\bHEAD(?:[~^]\d*)+|\brefs/[^\s:]+):[^\s]+",
    re.IGNORECASE,
)
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


def _history_intent(instruction: object) -> bool | None:
    if not isinstance(instruction, str) or not instruction.strip():
        return None
    if _EXPLICIT_HISTORY.search(instruction):
        return True
    if _AMBIGUOUS_HISTORY.search(instruction):
        return None
    return False


def _argument_text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        return "\n".join(_argument_text(item) for item in value.values())
    if isinstance(value, list):
        return "\n".join(_argument_text(item) for item in value)
    return ""


def _history_access_kind(text: str) -> str | None:
    internal = _GIT_INTERNAL_PATH.search(text)
    if internal is not None:
        family = internal.group(1) or internal.group(2)
        return "object_database" if family == "objects" else "git_internal"
    if _GIT_HISTORY_COMMAND.search(text) or _GIT_ALIAS_HISTORY.search(text):
        return "git_history_command"
    if _HISTORICAL_REVISION_PATH.search(text):
        return "historical_revision"
    if _LIBRARY_HISTORY.search(text):
        return "history_library"
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
) -> dict[str, object]:
    """Audit public model/tool evidence without reading task-hidden material."""

    history_required = _history_intent(instruction)
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
                if (
                    not isinstance(source_call_id, str)
                    or source_call_id not in call_by_id
                    or source_call_id in observed
                    or not isinstance(content, str)
                ):
                    raise ValueError
                observed.add(source_call_id)
                call_by_id[source_call_id]["output"] = content
                call_by_id[source_call_id]["dispatched"] = True
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
        access_kind = _history_access_kind(arguments_text)
        if access_kind is None:
            continue
        shown = _GIT_SHOW_REVISION.search(arguments_text)
        if shown is not None and shown.group(1).lower() in run_revisions:
            continue
        bytes_returned = isinstance(output, str) and bool(output)
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

    blocking = sum(submission_blocking_finding(finding) for finding in findings)
    globally_blocking = history_required is None
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


def audit_trial(trial_dir: Path, *, instruction: object) -> dict[str, object]:
    """Load only hash-bound public agent evidence for one terminal trial."""

    history_required = _history_intent(instruction)
    agent_dir = trial_dir / "agent"
    marker_path = agent_dir / "agent-run.json"
    if not agent_dir.is_dir() or agent_dir.is_symlink():
        return _incomplete(history_required, state="unavailable")
    if not marker_path.is_file():
        partial_path = agent_dir / "partial-trajectory.json"
        if not partial_path.is_file() or partial_path.is_symlink():
            return _incomplete(history_required, state="unavailable")
        try:
            return audit_public_evidence(
                instruction=instruction,
                trajectory=json.loads(_read_public_file(partial_path)),
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
        )
    except (OSError, ValueError, json.JSONDecodeError, RecursionError):
        return _incomplete(history_required, state="invalid")
