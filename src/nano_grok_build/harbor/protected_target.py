"""Shared-policy protected-target matching and post-run evidence classification."""

from __future__ import annotations

import hashlib
import json
import re
import stat
from collections.abc import Mapping
from importlib import resources
from pathlib import Path, PurePosixPath
from typing import Any

POLICY_SCHEMA = "protected-targets-v1"
AUDIT_SCHEMA = "nano-protected-target-audit-v1"
FINDING_SCHEMA = "nano-protected-target-finding-v1"
BLOCKED_CODE = "protected_harness_material_access_blocked"
_MAX_SURFACE_BYTES = 32 * 1024 * 1024
_TERMINAL_SPLIT = re.compile(r"[\s'\"`;|&()<>{}\[\],=]+")
_SOURCE_POLICY_PATH = (
    Path(__file__).resolve().parents[3] / "policy/protected-targets-v1.json"
)
_PACKAGE_POLICY_PATH = "policy/protected-targets-v1.json"


class ProtectedTargetError(ValueError):
    """The shared policy or an evidence surface is structurally invalid."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ProtectedTargetError("duplicate_json_key")
        value[key] = item
    return value


def _decode_json(raw: bytes) -> object:
    try:
        return json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ProtectedTargetError("invalid_json_constant")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ProtectedTargetError("json_invalid") from error


def _read_regular(path: Path, *, limit: int = _MAX_SURFACE_BYTES) -> bytes:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise ProtectedTargetError("evidence_file_invalid")
        raw = path.read_bytes()
    except OSError as error:
        raise ProtectedTargetError("evidence_file_unavailable") from error
    if len(raw) > limit:
        raise ProtectedTargetError("evidence_file_invalid")
    return raw


def _policy_bytes() -> bytes:
    if _SOURCE_POLICY_PATH.exists() or _SOURCE_POLICY_PATH.is_symlink():
        return _read_regular(_SOURCE_POLICY_PATH, limit=64 * 1024)
    try:
        raw = (
            resources.files("nano_grok_build")
            .joinpath(_PACKAGE_POLICY_PATH)
            .read_bytes()
        )
    except (FileNotFoundError, ModuleNotFoundError, OSError) as error:
        raise ProtectedTargetError("protected_target_policy_unavailable") from error
    if len(raw) > 64 * 1024:
        raise ProtectedTargetError("protected_target_policy_invalid")
    return raw


def _load_policy() -> tuple[dict[str, object], str]:
    raw = _policy_bytes()
    value = _decode_json(raw)
    if not isinstance(value, dict):
        raise ProtectedTargetError("protected_target_policy_invalid")
    expected = {
        "schema_version",
        "fatal_code",
        "workspace_root",
        "protected_path_families",
        "official_benchmark_repository_slugs",
        "terminal_command_fields",
        "filesystem_path_fields",
    }
    if (
        set(value) != expected
        or value.get("schema_version") != POLICY_SCHEMA
        or value.get("fatal_code") != BLOCKED_CODE
        or value.get("workspace_root") != "/workspace"
    ):
        raise ProtectedTargetError("protected_target_policy_invalid")
    roots = value.get("protected_path_families")
    slugs = value.get("official_benchmark_repository_slugs")
    terminal = value.get("terminal_command_fields")
    filesystem = value.get("filesystem_path_fields")
    if (
        not isinstance(roots, list)
        or not roots
        or any(not isinstance(root, str) or not root.startswith("/") for root in roots)
        or len(set(roots)) != len(roots)
        or not isinstance(slugs, list)
        or not slugs
        or any(
            not isinstance(slug, str)
            or not slug
            or slug != slug.lower()
            or "/" not in slug
            for slug in slugs
        )
        or len(set(slugs)) != len(slugs)
        or not isinstance(terminal, dict)
        or not isinstance(filesystem, dict)
        or set(terminal) & set(filesystem)
    ):
        raise ProtectedTargetError("protected_target_policy_invalid")
    for field_map in (terminal, filesystem):
        for tool, fields in field_map.items():
            if (
                not isinstance(tool, str)
                or not tool
                or not isinstance(fields, list)
                or not fields
                or any(not isinstance(field, str) or not field for field in fields)
                or len(set(fields)) != len(fields)
            ):
                raise ProtectedTargetError("protected_target_policy_invalid")
    return value, hashlib.sha256(raw).hexdigest()


_POLICY, POLICY_SHA256 = _load_policy()


def _normalize_syntax(value: str) -> str:
    normalized = value.lower()
    for _ in range(2):
        normalized = (
            normalized.replace(r"\u002f", "/")
            .replace(r"\u005c", "/")
            .replace(r"\/", "/")
            .replace("%2f", "/")
            .replace("%5c", "/")
            .replace("%2e", ".")
            .replace("%3a", ":")
        )
    normalized = normalized.replace("\\", "/")
    return re.sub(r"/+", "/", normalized)


def _lexical_path(path: str) -> str:
    workspace_root = str(_POLICY["workspace_root"])
    normalized = _normalize_syntax(path)
    if normalized.startswith("file:"):
        normalized = normalized.removeprefix("file:")
    rooted = (
        normalized if normalized.startswith("/") else f"{workspace_root}/{normalized}"
    )
    parts: list[str] = []
    for part in rooted.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts) if parts else "/"


def _path_within(path: str, root: str) -> bool:
    return path == root or path.startswith(f"{root}/")


def _linux_proc_root_alias(path: str) -> str | None:
    if not path.startswith("/"):
        return None
    parts = path.removeprefix("/").split("/")
    if len(parts) < 4 or parts[0] != "proc" or parts[2] != "root":
        return None
    process = parts[1]
    if process != "self" and not (process.isascii() and process.isdigit()):
        return None
    return "/" + "/".join(parts[3:])


def _match_path(path: str) -> str | None:
    syntax = _normalize_syntax(path)
    if syntax.startswith("file:"):
        syntax = syntax.removeprefix("file:")
    workspace_root = str(_POLICY["workspace_root"])
    rooted = syntax if syntax.startswith("/") else f"{workspace_root}/{syntax}"
    lexical = _lexical_path(rooted)
    for candidate in (rooted, lexical):
        aliases = (candidate, _linux_proc_root_alias(candidate))
        for alias in aliases:
            if alias is None:
                continue
            for root in _POLICY["protected_path_families"]:
                assert isinstance(root, str)
                if _path_within(alias, root):
                    return root
    return None


def match_protected_target(
    tool_name: object,
    arguments: object,
) -> dict[str, str] | None:
    """Return the exact shared-policy match for one tool call, if any."""

    if not isinstance(tool_name, str) or not isinstance(arguments, Mapping):
        return None
    terminal = _POLICY["terminal_command_fields"]
    filesystem = _POLICY["filesystem_path_fields"]
    assert isinstance(terminal, dict) and isinstance(filesystem, dict)
    fields = terminal.get(tool_name)
    if isinstance(fields, list):
        for field in fields:
            value = arguments.get(field)
            if not isinstance(field, str) or not isinstance(value, str):
                continue
            normalized = _normalize_syntax(value)
            for slug in _POLICY["official_benchmark_repository_slugs"]:
                assert isinstance(slug, str)
                if slug in normalized:
                    return {
                        "target_kind": "official_benchmark_repository",
                        "target_field": field,
                        "policy_value": slug,
                    }
            for fragment in _TERMINAL_SPLIT.split(normalized):
                if not fragment.startswith(("/", "./", "../", "file:")):
                    continue
                root = _match_path(fragment)
                if root is not None:
                    return {
                        "target_kind": "protected_path",
                        "target_field": field,
                        "policy_value": root,
                    }
    fields = filesystem.get(tool_name)
    if isinstance(fields, list):
        for field in fields:
            value = arguments.get(field)
            if not isinstance(field, str) or not isinstance(value, str):
                continue
            root = _match_path(value)
            if root is not None:
                return {
                    "target_kind": "protected_path",
                    "target_field": field,
                    "policy_value": root,
                }
    return None


def _safe_agent_path(agent_dir: Path, relative: object) -> Path:
    if not isinstance(relative, str) or not relative or "\x00" in relative:
        raise ProtectedTargetError("evidence_path_invalid")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ProtectedTargetError("evidence_path_invalid")
    candidate = agent_dir.joinpath(*pure.parts)
    try:
        root = agent_dir.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        metadata = candidate.lstat()
    except OSError as error:
        raise ProtectedTargetError("evidence_path_invalid") from error
    if not stat.S_ISREG(metadata.st_mode) or not resolved.is_relative_to(root):
        raise ProtectedTargetError("evidence_path_invalid")
    return candidate


def _source(kind: str, path: str, raw: bytes) -> dict[str, str]:
    return {
        "kind": kind,
        "path": path,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _merge_finding(
    findings: dict[tuple[str, str, str, str, str], dict[str, Any]],
    *,
    call_id: str,
    tool_name: str,
    match: Mapping[str, str],
    dispatched: bool,
    bytes_returned: bool,
    access_blocked: bool,
    source: Mapping[str, str],
) -> None:
    key = (
        call_id,
        tool_name,
        match["target_kind"],
        match["target_field"],
        match["policy_value"],
    )
    finding = findings.setdefault(
        key,
        {
            "call_id": call_id,
            "tool_name": tool_name,
            **match,
            "dispatched": False,
            "bytes_returned": False,
            "access_blocked": False,
            "evidence_sources": [],
        },
    )
    finding["dispatched"] = bool(finding["dispatched"] or dispatched)
    finding["bytes_returned"] = bool(finding["bytes_returned"] or bytes_returned)
    finding["access_blocked"] = bool(finding["access_blocked"] or access_blocked)
    sources = finding["evidence_sources"]
    assert isinstance(sources, list)
    if source not in sources:
        sources.append(dict(source))


def _atif_calls(value: object) -> list[dict[str, object]]:
    if not isinstance(value, dict):
        raise ProtectedTargetError("trajectory_invalid")
    calls: list[dict[str, object]] = []
    steps = value.get("steps")
    if steps is not None:
        if not isinstance(steps, list):
            raise ProtectedTargetError("trajectory_invalid")
        for step_index, step in enumerate(steps):
            if not isinstance(step, dict):
                raise ProtectedTargetError("trajectory_invalid")
            tool_calls = step.get("tool_calls", [])
            if not isinstance(tool_calls, list):
                raise ProtectedTargetError("trajectory_invalid")
            observations: dict[str, object] = {}
            observation = step.get("observation")
            if isinstance(observation, dict):
                results = observation.get("results", [])
                if not isinstance(results, list):
                    raise ProtectedTargetError("trajectory_invalid")
                for result in results:
                    if not isinstance(result, dict):
                        raise ProtectedTargetError("trajectory_invalid")
                    result_id = result.get("source_call_id")
                    if isinstance(result_id, str):
                        observations[result_id] = result.get("content")
            for call_index, call in enumerate(tool_calls):
                if not isinstance(call, dict):
                    raise ProtectedTargetError("trajectory_invalid")
                call_id = call.get("tool_call_id")
                if not isinstance(call_id, str) or not call_id:
                    call_id = f"atif-step-{step_index}-call-{call_index}"
                content = observations.get(call_id)
                calls.append(
                    {
                        "call_id": call_id,
                        "tool_name": call.get("function_name"),
                        "arguments": call.get("arguments"),
                        "dispatched": call_id in observations,
                        "bytes_returned": isinstance(content, str) and bool(content),
                        "access_blocked": False,
                    }
                )
    partial_calls = value.get("tool_calls")
    if partial_calls is not None:
        if not isinstance(partial_calls, list):
            raise ProtectedTargetError("trajectory_invalid")
        for call_index, call in enumerate(partial_calls):
            if not isinstance(call, dict):
                raise ProtectedTargetError("trajectory_invalid")
            call_id = call.get("call_id")
            if not isinstance(call_id, str) or not call_id:
                call_id = f"partial-call-{call_index}"
            observation = call.get("observation")
            content = (
                observation.get("output") if isinstance(observation, dict) else None
            )
            failure = call.get("failure")
            calls.append(
                {
                    "call_id": call_id,
                    "tool_name": call.get("function_name"),
                    "arguments": call.get("arguments"),
                    "dispatched": call.get("dispatched") is True,
                    "bytes_returned": isinstance(content, str) and bool(content),
                    "access_blocked": bool(
                        isinstance(failure, dict)
                        and failure.get("code") == BLOCKED_CODE
                    ),
                }
            )
    return calls


def _event_calls(events: list[object]) -> list[dict[str, object]]:
    calls: dict[str, dict[str, object]] = {}
    for event in events:
        if not isinstance(event, dict):
            raise ProtectedTargetError("event_prefix_invalid")
        event_type = event.get("type")
        data = event.get("data")
        if not isinstance(event_type, str) or not isinstance(data, dict):
            raise ProtectedTargetError("event_prefix_invalid")
        call_id = data.get("call_id")
        if event_type == "tool.registered":
            if not isinstance(call_id, str) or not call_id or call_id in calls:
                raise ProtectedTargetError("event_prefix_invalid")
            arguments_raw = data.get("arguments_json")
            if not isinstance(arguments_raw, str):
                raise ProtectedTargetError("event_prefix_invalid")
            arguments = _decode_json(arguments_raw.encode("utf-8"))
            if not isinstance(arguments, dict):
                raise ProtectedTargetError("event_prefix_invalid")
            calls[call_id] = {
                "call_id": call_id,
                "tool_name": data.get("provider_name"),
                "arguments": arguments,
                "dispatched": False,
                "bytes_returned": False,
                "access_blocked": False,
            }
        elif event_type in {"tool.dispatched", "tool.completed", "tool.failed"}:
            if not isinstance(call_id, str) or call_id not in calls:
                raise ProtectedTargetError("event_prefix_invalid")
            call = calls[call_id]
            if data.get("provider_name") != call["tool_name"]:
                raise ProtectedTargetError("event_prefix_invalid")
            if event_type == "tool.dispatched":
                call["dispatched"] = True
            elif event_type == "tool.completed":
                output = data.get("output")
                if not isinstance(output, str):
                    raise ProtectedTargetError("event_prefix_invalid")
                call["bytes_returned"] = bool(output)
            else:
                call["access_blocked"] = data.get("code") == BLOCKED_CODE
    return list(calls.values())


def _jsonl(raw: bytes) -> list[object]:
    if not raw or not raw.endswith(b"\n"):
        raise ProtectedTargetError("event_prefix_invalid")
    return [_decode_json(line) for line in raw.splitlines()]


def _trajectory_surface(
    agent_dir: Path,
    marker: Mapping[str, object] | None,
) -> tuple[object, dict[str, str]] | None:
    if marker is not None and "trajectory_path" in marker:
        path = _safe_agent_path(agent_dir, marker.get("trajectory_path"))
        raw = _read_regular(path)
        digest = marker.get("trajectory_sha256")
        if not isinstance(digest, str) or hashlib.sha256(raw).hexdigest() != digest:
            raise ProtectedTargetError("trajectory_binding_invalid")
        return _decode_json(raw), _source(
            "atif", path.relative_to(agent_dir).as_posix(), raw
        )
    for name in ("trajectory.json", "partial-trajectory.json", "emergency-prefix.json"):
        path = agent_dir / name
        if path.exists() or path.is_symlink():
            path = _safe_agent_path(agent_dir, name)
            raw = _read_regular(path)
            return _decode_json(raw), _source("atif", name, raw)
    return None


def _diagnostic_surface(
    agent_dir: Path,
    marker: Mapping[str, object],
) -> tuple[list[object] | None, dict[str, str]] | None:
    if marker.get("schema_version") != "nano-agent-run-v4":
        return None
    if marker.get("publication_kind") not in {"failure_atif", "emergency_atif"}:
        raise ProtectedTargetError("v4_marker_invalid")
    if marker.get("terminal_status") == "success":
        raise ProtectedTargetError("v4_marker_invalid")
    path = _safe_agent_path(agent_dir, marker.get("diagnostic_path"))
    raw = _read_regular(path)
    digest = marker.get("diagnostic_sha256")
    if not isinstance(digest, str) or hashlib.sha256(raw).hexdigest() != digest:
        raise ProtectedTargetError("diagnostic_binding_invalid")
    source = _source("diagnostic", path.relative_to(agent_dir).as_posix(), raw)
    if path.suffix == ".jsonl":
        return _jsonl(raw), source
    value = _decode_json(raw)
    if not isinstance(value, dict):
        raise ProtectedTargetError("diagnostic_invalid")
    events = value.get("events")
    if events is None:
        return None, source
    if not isinstance(events, list):
        raise ProtectedTargetError("diagnostic_invalid")
    return list(events), source


def audit_trial(trial_dir: Path, *, rewarded: bool) -> dict[str, object]:
    """Classify protected attempts from agent-owned, hash-bound surfaces only.

    Verifier, reward, solution, and task-source files are deliberately outside
    this function's read set.
    """

    findings: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    state = "unavailable"
    marker: Mapping[str, object] | None = None
    agent_dir = trial_dir / "agent"
    if not agent_dir.is_dir() or agent_dir.is_symlink():
        return _audit_document(state, findings, rewarded=rewarded)
    marker_path = agent_dir / "agent-run.json"
    try:
        if marker_path.exists() or marker_path.is_symlink():
            marker_raw = _read_regular(_safe_agent_path(agent_dir, "agent-run.json"))
            marker_value = _decode_json(marker_raw)
            if not isinstance(marker_value, dict):
                raise ProtectedTargetError("marker_invalid")
            marker = marker_value
            state = "available"

        trajectory = _trajectory_surface(agent_dir, marker)
        if trajectory is not None:
            value, source = trajectory
            state = "available"
            for call in _atif_calls(value):
                match = match_protected_target(call["tool_name"], call["arguments"])
                if match is not None:
                    _merge_finding(
                        findings,
                        call_id=str(call["call_id"]),
                        tool_name=str(call["tool_name"]),
                        match=match,
                        dispatched=bool(call["dispatched"]),
                        bytes_returned=bool(call["bytes_returned"]),
                        access_blocked=bool(call["access_blocked"]),
                        source=source,
                    )

        event_surfaces: list[tuple[list[object], dict[str, str]]] = []
        events_path = agent_dir / "runtime" / "events.jsonl"
        marker_schema = marker.get("schema_version") if marker is not None else None
        if marker_schema in {
            "nano-agent-run-v2",
            "nano-agent-run-v3",
            "nano-agent-run-v4",
        } and (events_path.exists() or events_path.is_symlink()):
            events_path = _safe_agent_path(agent_dir, "runtime/events.jsonl")
            events_raw = _read_regular(events_path)
            expected = marker.get("events_sha256") if marker is not None else None
            if (
                not isinstance(expected, str)
                or hashlib.sha256(events_raw).hexdigest() != expected
            ):
                raise ProtectedTargetError("event_binding_invalid")
            event_surfaces.append(
                (
                    _jsonl(events_raw),
                    _source("runtime_event", "runtime/events.jsonl", events_raw),
                )
            )
            state = "available"

        if marker is not None:
            diagnostic = _diagnostic_surface(agent_dir, marker)
            if diagnostic is not None:
                diagnostic_events, source = diagnostic
                state = "available"
                if diagnostic_events is not None:
                    event_surfaces.append((diagnostic_events, source))

        for events, source in event_surfaces:
            for call in _event_calls(events):
                match = match_protected_target(call["tool_name"], call["arguments"])
                if match is not None:
                    _merge_finding(
                        findings,
                        call_id=str(call["call_id"]),
                        tool_name=str(call["tool_name"]),
                        match=match,
                        dispatched=bool(call["dispatched"]),
                        bytes_returned=bool(call["bytes_returned"]),
                        access_blocked=bool(call["access_blocked"]),
                        source=source,
                    )

        if marker is not None and marker.get("terminal_code") == BLOCKED_CODE:
            for finding in findings.values():
                if not finding["dispatched"]:
                    finding["access_blocked"] = True
    except (ProtectedTargetError, TypeError, ValueError):
        state = "invalid"

    return _audit_document(state, findings, rewarded=rewarded)


def _audit_document(
    state: str,
    findings: Mapping[tuple[str, str, str, str, str], Mapping[str, Any]],
    *,
    rewarded: bool,
) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    signals: set[str] = set()
    for key in sorted(findings):
        source = findings[key]
        dispatched = bool(source["dispatched"])
        bytes_returned = bool(source["bytes_returned"])
        access_blocked = bool(source["access_blocked"] and not dispatched)
        if dispatched or bytes_returned:
            classification = "strong"
            signal = (
                "official_benchmark_repository_access"
                if source["target_kind"] == "official_benchmark_repository"
                else "protected_harness_material_access"
            )
        elif access_blocked:
            classification = "access_blocked"
            signal = BLOCKED_CODE
        else:
            classification = "attempted"
            signal = "protected_harness_material_access_attempted"
        causal_benefit = bool(rewarded and bytes_returned)
        signals.add(signal)
        rows.append(
            {
                "schema_version": FINDING_SCHEMA,
                "call_id": source["call_id"],
                "tool_name": source["tool_name"],
                "target_kind": source["target_kind"],
                "target_field": source["target_field"],
                "policy_value": source["policy_value"],
                "classification": classification,
                "attempted": True,
                "dispatched": dispatched,
                "bytes_returned": bytes_returned,
                "causal_benefit": causal_benefit,
                "access_blocked": access_blocked,
                "evidence_sources": sorted(
                    source["evidence_sources"],
                    key=lambda item: (item["kind"], item["path"], item["sha256"]),
                ),
            }
        )
    counts = {
        "findings": len(rows),
        "strong": sum(row["classification"] == "strong" for row in rows),
        "attempted": sum(row["classification"] == "attempted" for row in rows),
        "access_blocked": sum(
            row["classification"] == "access_blocked" for row in rows
        ),
        "dispatched": sum(bool(row["dispatched"]) for row in rows),
        "bytes_returned": sum(bool(row["bytes_returned"]) for row in rows),
        "causal_benefit": sum(bool(row["causal_benefit"]) for row in rows),
    }
    return {
        "schema_version": AUDIT_SCHEMA,
        "policy_schema_version": POLICY_SCHEMA,
        "policy_sha256": POLICY_SHA256,
        "state": state,
        "signals": sorted(signals),
        "counts": counts,
        "findings": rows,
    }
