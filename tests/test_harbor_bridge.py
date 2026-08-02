from __future__ import annotations

import asyncio
import base64
import gc
import hashlib
import importlib.util
import json
import os
import re
import sys
import tomllib
from dataclasses import replace
from pathlib import Path

import pytest

from nano_grok_build.adapter.deadline import (
    DeadlineContractError,
    DeadlineReservesV1,
    RunDeadlineReceiptV1,
    RunDeadlineV1,
)
from nano_grok_build.adapter.stdio_bridge import (
    BACKGROUND_START_PROOF_VERSION,
    LIVE_SCHEMA_VERSION,
    REMOTE_ENVIRONMENT_ALLOWLIST,
    SCHEMA_VERSION,
    TOOL_NAMES,
    BackgroundStartKind,
    BackgroundStartObservation,
    BridgeError,
    BridgeOutcome,
    MediaPayload,
    ProcessDisposition,
    TerminalActorOriginV1,
    TerminalActorPhaseV1,
    TerminalActorReceiptV1,
    TerminalActorSubtypeV1,
    ToolExecution,
    ToolFailure,
    ToolFatalError,
    _complete_shielded,
    _fallback_serialization_failure,
    _preflight_response_serialization,
    encode_tool_response,
    parse_tool_request,
    run_stdio_bridge,
)
from nano_grok_build.adapter.terminal_actor import (
    ProcessLeaseV1,
    RemoteTerminalActor,
    SnapshotTimeoutOriginV1,
    SnapshotTransportTimeout,
    WorkspaceReadinessV1,
)
from nano_grok_build.adapter.workspace_snapshot import (
    WorkspaceSnapshotError,
)
from nano_grok_build.adapter.workspace_snapshot import (
    capture_after as real_capture_after,
)
from nano_grok_build.adapter.workspace_snapshot import (
    capture_before as real_capture_before,
)

ROOT = Path(__file__).resolve().parents[1]


def _schema_target(root: dict[str, object], reference: str) -> object:
    assert reference.startswith("#/")
    target: object = root
    for token in reference[2:].split("/"):
        assert isinstance(target, dict)
        target = target[token.replace("~1", "/").replace("~0", "~")]
    return target


def _matches_schema(
    root: dict[str, object], schema: dict[str, object], instance: object
) -> bool:
    try:
        _assert_schema(root, schema, instance)
    except AssertionError:
        return False
    return True


def _assert_schema(
    root: dict[str, object], schema: dict[str, object], instance: object
) -> None:
    if "$ref" in schema:
        target = _schema_target(root, str(schema["$ref"]))
        assert isinstance(target, dict)
        _assert_schema(root, target, instance)
        return
    if "oneOf" in schema:
        branches = schema["oneOf"]
        assert isinstance(branches, list)
        assert (
            sum(
                isinstance(branch, dict) and _matches_schema(root, branch, instance)
                for branch in branches
            )
            == 1
        )
    for branch in schema.get("allOf", []):
        assert isinstance(branch, dict)
        _assert_schema(root, branch, instance)
    conditional = schema.get("if")
    if isinstance(conditional, dict) and _matches_schema(root, conditional, instance):
        then = schema.get("then")
        assert isinstance(then, dict)
        _assert_schema(root, then, instance)
    expected_type = schema.get("type")
    if expected_type == "object":
        assert isinstance(instance, dict)
    elif expected_type == "array":
        assert isinstance(instance, list)
    elif expected_type == "string":
        assert isinstance(instance, str)
    elif expected_type == "integer":
        assert isinstance(instance, int) and not isinstance(instance, bool)
    elif expected_type == "boolean":
        assert isinstance(instance, bool)
    elif expected_type == "null":
        assert instance is None
    if "const" in schema:
        assert instance == schema["const"]
    if "enum" in schema:
        assert instance in schema["enum"]
    if isinstance(instance, int) and not isinstance(instance, bool):
        if "minimum" in schema:
            assert instance >= schema["minimum"]
        if "maximum" in schema:
            assert instance <= schema["maximum"]
    if isinstance(instance, str):
        if "minLength" in schema:
            assert len(instance) >= schema["minLength"]
        if "maxLength" in schema:
            assert len(instance) <= schema["maxLength"]
        if "pattern" in schema:
            assert re.search(str(schema["pattern"]), instance)
        if "x-utf8-max-bytes" in schema:
            assert len(instance.encode("utf-8")) <= schema["x-utf8-max-bytes"]
    if isinstance(instance, dict):
        required = schema.get("required", [])
        assert isinstance(required, list)
        assert set(required).issubset(instance)
        properties = schema.get("properties", {})
        assert isinstance(properties, dict)
        if schema.get("additionalProperties") is False:
            assert set(instance).issubset(properties)
        for key, value in instance.items():
            property_schema = properties.get(key)
            if isinstance(property_schema, dict):
                _assert_schema(root, property_schema, value)
        strict_json_field = schema.get("x-strict-json-object-field")
        if isinstance(strict_json_field, dict):
            field = strict_json_field["field"]
            max_bytes_path = strict_json_field["utf8-max-bytes-from"]
            assert isinstance(field, str)
            assert isinstance(max_bytes_path, list)
            raw_json = instance[field]
            assert isinstance(raw_json, str)
            max_bytes: object = instance
            for token in max_bytes_path:
                assert isinstance(max_bytes, dict)
                max_bytes = max_bytes[token]
            assert isinstance(max_bytes, int) and not isinstance(max_bytes, bool)
            assert len(raw_json.encode("utf-8")) <= max_bytes

            def reject_duplicate_keys(
                pairs: list[tuple[str, object]],
            ) -> dict[str, object]:
                value: dict[str, object] = {}
                for key, item in pairs:
                    assert key not in value
                    value[key] = item
                return value

            parsed = json.loads(
                raw_json,
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=lambda _: (_ for _ in ()).throw(AssertionError()),
            )
            assert isinstance(parsed, dict)
    if isinstance(instance, list):
        if "minItems" in schema:
            assert len(instance) >= schema["minItems"]
        if "maxItems" in schema:
            assert len(instance) <= schema["maxItems"]
        prefix = schema.get("prefixItems", [])
        assert isinstance(prefix, list)
        for item_schema, value in zip(prefix, instance, strict=False):
            assert isinstance(item_schema, dict)
            _assert_schema(root, item_schema, value)
        if schema.get("items") is False:
            assert len(instance) <= len(prefix)


def request_value(
    tool_name: str = "run_terminal_command",
    arguments: dict[str, object] | None = None,
) -> dict[str, object]:
    if arguments is None:
        arguments = {
            "command": "printf ok",
            "description": "bridge test",
            "timeout": 1000,
            "background": False,
        }
    return {
        "schema_version": "external-tool-stdio-v2",
        "message_type": "tool.request",
        "seq": 0,
        "run_id": "run-1",
        "trial_id": "trial-1",
        "attempt_id": "attempt-0",
        "call_id": "call-1",
        "tool_name": tool_name,
        "arguments_json": json.dumps(arguments, separators=(",", ":")),
        "logical_cwd": "/workspace",
        "timeout_ms": 1000,
        "term_grace_ms": 100,
        "kill_confirmation_timeout_ms": 1000,
        "stdout_cap_bytes": 4096,
        "stderr_cap_bytes": 4096,
        "environment": {
            "clear": True,
            "inherit_remote": [
                "HOME",
                "LANG",
                "LC_ALL",
                "PATH",
                "TERM",
                "TMPDIR",
                "USER",
            ],
        },
        "limits": {
            "arguments_cap_bytes": 1024 * 1024,
            "max_path_bytes": 4096,
            "max_read_or_write_bytes": 4 * 1024 * 1024,
            "max_directory_entries": 10_000,
            "max_grep_matches": 10_000,
            "max_replacements": 10_000,
            "max_background_processes": 8,
            "process_spool_bytes_per_process": 16 * 1024 * 1024,
            "process_spool_bytes_per_run": 128 * 1024 * 1024,
            "background_output_wait_max_ms": 600_000,
            "read_file_media_enabled": True,
        },
    }


def live_request_value(
    *,
    background: bool,
) -> dict[str, object]:
    value = request_value(
        "run_terminal_command",
        {
            "command": "true",
            "description": "background proof",
            "timeout": 0,
            "background": background,
        },
    )
    value["schema_version"] = LIVE_SCHEMA_VERSION
    value["operation_timeout_ms"] = value.pop("timeout_ms")
    value.update(
        {
            "actor_done_monotonic_ns": 20_000_000_000,
            "tool_settled_monotonic_ns": 30_000_000_000,
            "last_send_monotonic_ns": 60_000_000_000,
            "runtime_final_monotonic_ns": 60_000_000_000,
            "cleanup_start_monotonic_ns": 75_000_000_000,
            "hard_deadline_monotonic_ns": 95_000_000_000,
            "cleanup_reserve_ms": 20_000,
            "terminalization_reserve_ms": 15_000,
            "provider_send_reserve_ms": 30_000,
            "process_settlement_reserve_ms": 10_000,
            "deadline_receipt_sha256": "d" * 64,
        }
    )
    return value


class Handler:
    def __init__(self) -> None:
        self.requests = []
        self.cleaned = False

    async def execute(self, request):
        self.requests.append(request)
        return ToolExecution(
            return_code=0,
            timed_out=False,
            stdout=b"\x00ok\xff",
            stderr=b"",
            stdout_truncated=False,
            stderr_truncated=False,
            cleanup_attempted=True,
            term_sent=False,
            kill_sent=False,
            cleanup_verified=True,
            census_verified=True,
            survivor_count=0,
            process_disposition=ProcessDisposition.FOREGROUND_CLEANED,
            target_task_id=None,
        )

    async def cleanup_active(self) -> bool:
        self.cleaned = True
        return True


def test_provider_free_synthetic_fixture_clears_frozen_deadline_boundaries(
    tmp_path: Path,
) -> None:
    reserves = DeadlineReservesV1()
    assert reserves.total_ms == 75_000
    with pytest.raises(
        DeadlineContractError,
        match="^deadline_reserve_underflow$",
    ):
        RunDeadlineV1.mint(
            source="test_host_phase",
            agent_timeout_ms=reserves.total_ms,
            now_monotonic_ns=1_000_000_000,
        )
    just_above = RunDeadlineV1.mint(
        source="test_host_phase",
        agent_timeout_ms=reserves.total_ms + 1,
        now_monotonic_ns=1_000_000_000,
    )
    just_above_receipt = RunDeadlineReceiptV1.bind(
        deadline=just_above,
        run_id="run-boundary",
        trial_id="trial-boundary",
        attempt_id="attempt-0",
        run_spec_sha256="a" * 64,
    )
    assert just_above_receipt.cutoffs.actor_done_monotonic_ns == 1_001_000_000

    task = tomllib.loads(
        (ROOT / "tests" / "harbor" / "toy-task" / "task.toml").read_text(
            encoding="utf-8"
        )
    )
    timeout_ms = int(task["agent"]["timeout_sec"] * 1_000)
    deadline = RunDeadlineV1.mint(
        source="test_host_phase",
        agent_timeout_ms=timeout_ms,
        now_monotonic_ns=1_000_000_000,
    )
    receipt = RunDeadlineReceiptV1.bind(
        deadline=deadline,
        run_id="run-synthetic",
        trial_id="trial-synthetic",
        attempt_id="attempt-0",
        run_spec_sha256="b" * 64,
    )
    assert receipt.cutoffs.last_send_monotonic_ns - 1_000_000_000 > 90_000_000_000

    helper_path = ROOT / "tests" / "harbor" / "run_synthetic.py"
    module_spec = importlib.util.spec_from_file_location(
        "_nano_bridge_run_synthetic",
        helper_path,
    )
    assert module_spec is not None and module_spec.loader is not None
    helper = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(helper)
    contract_dir = tmp_path / "contract"
    helper.write_synthetic_contract(contract_dir)
    profile = json.loads((contract_dir / "agent-profile.json").read_bytes())
    assert profile["deadlines"]["absolute_run_wall_cap_sec"] >= timeout_ms // 1_000
    assert profile["deadlines"]["terminalization_reserve_sec"] * 1_000 == (
        reserves.terminalization_ms
    )
    assert profile["deadlines"]["min_provider_send_window_sec"] * 1_000 == (
        reserves.provider_send_ms
    )
    assert profile["deadlines"]["process_control_timeout_sec"] * 1_000 == (
        reserves.process_settlement_ms
    )
    assert (
        profile["process"]["term_grace_ms"]
        + profile["process"]["kill_confirmation_timeout_ms"]
        + profile["deadlines"]["process_control_timeout_sec"] * 1_000
        == reserves.cleanup_ms
    )


def test_external_tool_v2_schema_matches_rust_and_python_envelopes() -> None:
    schema = json.loads((ROOT / "schemas" / "external-tool-stdio-v2.json").read_bytes())
    assert schema["$id"].endswith("/external-tool-stdio-v2.json")
    meta_schema = json.loads(
        (ROOT / "schemas" / "external-tool-schema-meta-v1.json").read_bytes()
    )
    assert schema["$schema"] == meta_schema["$id"]
    assert meta_schema["$dynamicAnchor"] == "meta"
    assert (
        meta_schema["$vocabulary"][
            "https://nano-grok-build.dev/vocab/external-tool-validation-v1"
        ]
        is True
    )
    assert SCHEMA_VERSION == "external-tool-stdio-v2"
    rust_source = (
        ROOT / "crates" / "nano-types" / "src" / "external_tool.rs"
    ).read_text(encoding="utf-8")
    assert (
        'pub const EXTERNAL_TOOL_STDIO_SCHEMA: &str = "external-tool-stdio-v2";'
        in rust_source
    )
    assert tuple(schema["$defs"]["tool_name"]["enum"]) == TOOL_NAMES

    foreground_value = request_value()
    foreground_raw = json.dumps(foreground_value, separators=(",", ":")).encode()
    foreground_request = parse_tool_request(foreground_raw)
    foreground_response = json.loads(
        encode_tool_response(
            foreground_request,
            asyncio.run(Handler().execute(foreground_request)),
        )
    )
    background_value = request_value(
        "run_terminal_command",
        {
            "command": "sleep 60",
            "description": "serve",
            "timeout": 0,
            "background": True,
        },
    )
    background_request = parse_tool_request(
        json.dumps(background_value, separators=(",", ":")).encode()
    )
    background_response = json.loads(
        encode_tool_response(
            background_request,
            ToolExecution(
                return_code=0,
                timed_out=False,
                stdout=b"<status>running</status>",
                stderr=b"",
                stdout_truncated=False,
                stderr_truncated=False,
                cleanup_attempted=False,
                term_sent=False,
                kill_sent=False,
                cleanup_verified=True,
                census_verified=True,
                survivor_count=1,
                process_disposition=ProcessDisposition.BACKGROUND_RETAINED,
                target_task_id="018f22d6-9f04-7cc0-8000-000000000001",
            ),
        )
    )
    for value in (
        foreground_value,
        foreground_response,
        background_value,
        background_response,
    ):
        _assert_schema(schema, schema, value)
    assert foreground_response["settlement"] == "completed"
    assert foreground_response["result"]["media"] is None
    rust_fixtures = json.loads(
        (ROOT / "tests" / "fixtures" / "external-tool-stdio-v2-rust.json").read_bytes()
    )
    assert set(rust_fixtures) == {"request", "response"}
    for value in rust_fixtures.values():
        _assert_schema(schema, schema, value)

    with pytest.raises(AssertionError):
        _assert_schema(
            schema,
            schema,
            {
                **foreground_value,
                "schema_version": "external-tool-stdio-" + "v1",
            },
        )
    with pytest.raises(AssertionError):
        _assert_schema(
            schema,
            schema,
            {**foreground_value, "logical_cwd": "/workspace/../tmp"},
        )
    for invalid_arguments_json in ("not-json", "[]", '{"key":1,"key":2}'):
        with pytest.raises((AssertionError, json.JSONDecodeError)):
            _assert_schema(
                schema,
                schema,
                {
                    **foreground_value,
                    "arguments_json": invalid_arguments_json,
                },
            )
    with pytest.raises(AssertionError):
        _assert_schema(
            schema,
            schema,
            {
                **foreground_value,
                "run_id": "é" * 200,
            },
        )


def test_request_parser_and_response_bind_exact_bytes() -> None:
    raw = json.dumps(request_value(), separators=(",", ":")).encode()
    request = parse_tool_request(raw)
    assert request.background_output_wait_max_ms == 600_000
    response = json.loads(
        encode_tool_response(request, asyncio.run(Handler().execute(request)))
    )
    assert response["request_sha256"] == hashlib.sha256(raw).hexdigest()
    assert response["settlement"] == "completed"
    result = response["result"]
    assert base64.b64decode(result["stdout_base64"]) == b"\x00ok\xff"
    assert result["cleanup"]["verified"] is True
    assert result["census"] == {"verified": True, "owned_processes_alive": 0}
    assert result["process_disposition"] == "foreground_cleaned"
    assert result["target_task_id"] is None
    assert result["media"] is None


def test_media_response_is_exactly_bound_and_base64_is_not_in_stdout() -> None:
    content = b"\x89PNG\r\n\x1a\nbounded-bridge-fixture"
    digest = hashlib.sha256(content).hexdigest()
    raw = json.dumps(
        request_value("read_file", {"target_file": "board.bin"}),
        separators=(",", ":"),
    ).encode()
    request = parse_tool_request(raw)
    response_bytes = encode_tool_response(
        request,
        ToolExecution(
            return_code=0,
            timed_out=False,
            stdout=(
                f"read_file returned an attached image: image/png, 2x1, sha256={digest}"
            ).encode(),
            stderr=b"",
            stdout_truncated=False,
            stderr_truncated=False,
            cleanup_attempted=True,
            term_sent=False,
            kill_sent=False,
            cleanup_verified=True,
            census_verified=True,
            survivor_count=0,
            media=MediaPayload(
                logical_path="board.bin",
                mime_type="image/png",
                width=2,
                height=1,
                source_byte_length=len(content),
                source_sha256=digest,
                canonical_byte_length=len(content),
                canonical_sha256=digest,
                content=content,
            ),
        ),
    )
    response = json.loads(response_bytes)
    media = response["result"]["media"]

    assert media == {
        "logical_path": "board.bin",
        "mime_type": "image/png",
        "width": 2,
        "height": 1,
        "source_byte_length": len(content),
        "source_sha256": digest,
        "canonical_byte_length": len(content),
        "canonical_sha256": digest,
        "content_base64": base64.b64encode(content).decode(),
    }
    assert b"data:image" not in response_bytes
    assert base64.b64encode(content) not in base64.b64decode(
        response["result"]["stdout_base64"]
    )


@pytest.mark.parametrize(
    "mutate",
    [
        {"mime_type": "image/webp"},
        {"canonical_sha256": "0" * 64},
        {"canonical_byte_length": 0},
        {"width": 8193},
        {"height": 8193},
    ],
)
def test_media_response_validation_fails_closed(mutate: dict[str, object]) -> None:
    content = b"\x89PNG\r\n\x1a\npayload"
    digest = hashlib.sha256(content).hexdigest()
    fields: dict[str, object] = {
        "logical_path": "board.png",
        "mime_type": "image/png",
        "width": 1,
        "height": 1,
        "source_byte_length": len(content),
        "source_sha256": digest,
        "canonical_byte_length": len(content),
        "canonical_sha256": digest,
        "content": content,
    }
    fields.update(mutate)
    raw = json.dumps(
        request_value("read_file", {"target_file": "board.png"}),
        separators=(",", ":"),
    ).encode()
    parsed = parse_tool_request(raw)
    execution = ToolExecution(
        return_code=0,
        timed_out=False,
        stdout=b"metadata",
        stderr=b"",
        stdout_truncated=False,
        stderr_truncated=False,
        cleanup_attempted=True,
        term_sent=False,
        kill_sent=False,
        cleanup_verified=True,
        census_verified=True,
        survivor_count=0,
        media=MediaPayload(**fields),
    )
    with pytest.raises(BridgeError, match="external_response_media_invalid"):
        encode_tool_response(parsed, execution)


def test_fatal_response_is_typed_and_request_bound() -> None:
    raw = json.dumps(request_value(), separators=(",", ":")).encode()
    request = parse_tool_request(raw)
    response = json.loads(
        encode_tool_response(
            request,
            ToolFailure(
                code="terminal_actor_cleanup_unverified",
                execution_may_have_started=True,
                cleanup_verified=False,
                census_verified=False,
            ),
        )
    )

    assert response == {
        "schema_version": SCHEMA_VERSION,
        "message_type": "tool.response",
        "seq": 0,
        "run_id": "run-1",
        "trial_id": "trial-1",
        "attempt_id": "attempt-0",
        "call_id": "call-1",
        "tool_name": "run_terminal_command",
        "request_sha256": hashlib.sha256(raw).hexdigest(),
        "settlement": "fatal",
        "failure": {
            "code": "terminal_actor_cleanup_unverified",
            "execution_may_have_started": True,
            "cleanup_verified": False,
            "census_verified": False,
            "recoverability": "fatal",
        },
    }


def test_v3_foreground_fatal_receipt_round_trips_schema() -> None:
    raw = json.dumps(
        live_request_value(background=False),
        separators=(",", ":"),
    ).encode()
    request = parse_tool_request(raw)
    receipt = TerminalActorReceiptV1.create(
        phase=TerminalActorPhaseV1.CLEANUP,
        origin=TerminalActorOriginV1.TRANSPORT,
        primary_subtype=TerminalActorSubtypeV1.RUN_TRANSPORT_TIMEOUT,
        recovery_subtype=TerminalActorSubtypeV1.META_INVALID,
        execution_may_have_started=True,
        effective_cutoff_monotonic_ns=request.actor_done_monotonic_ns,
        cleanup_verified=False,
        census_verified=False,
    )
    response = json.loads(
        encode_tool_response(
            request,
            ToolFailure(
                code="terminal_actor_cleanup_unverified",
                execution_may_have_started=True,
                cleanup_verified=False,
                census_verified=False,
                actor_receipt=receipt,
            ),
        )
    )

    schema = json.loads((ROOT / "schemas" / "external-tool-stdio-v3.json").read_bytes())
    _assert_schema(schema, schema, response)
    assert response["failure"]["actor_receipt"] == receipt.as_dict()


def test_terminal_actor_receipt_canonical_digest_golden() -> None:
    receipt = TerminalActorReceiptV1.create(
        phase=TerminalActorPhaseV1.META_VALIDATE,
        origin=TerminalActorOriginV1.ACTOR,
        primary_subtype=TerminalActorSubtypeV1.COMPLETED,
        recovery_subtype=None,
        execution_may_have_started=True,
        effective_cutoff_monotonic_ns=1_000_000_000_000,
        cleanup_verified=True,
        census_verified=True,
    )

    assert (
        receipt.diagnostic_digest_sha256
        == "c3ca3fed777ea18771ab3e92ab1df052ebd3bec7ee3e314e4d4d7a00fdea89ff"
    )


def test_v3_foreground_fatal_receipt_rejects_cross_field_matrix() -> None:
    raw = json.dumps(
        live_request_value(background=False),
        separators=(",", ":"),
    ).encode()
    request = parse_tool_request(raw)
    cutoff_ns = request.actor_done_monotonic_ns
    assert cutoff_ns is not None

    def receipt(
        *,
        phase: TerminalActorPhaseV1,
        origin: TerminalActorOriginV1,
        primary: TerminalActorSubtypeV1,
        recovery: TerminalActorSubtypeV1 | None,
        cleanup_verified: bool | None = False,
        census_verified: bool | None = False,
    ) -> TerminalActorReceiptV1:
        return TerminalActorReceiptV1.create(
            phase=phase,
            origin=origin,
            primary_subtype=primary,
            recovery_subtype=recovery,
            execution_may_have_started=True,
            effective_cutoff_monotonic_ns=cutoff_ns,
            cleanup_verified=cleanup_verified,
            census_verified=census_verified,
        )

    invalid = [
        receipt(
            phase=TerminalActorPhaseV1.META_VALIDATE,
            origin=TerminalActorOriginV1.ACTOR,
            primary=TerminalActorSubtypeV1.RUN_TRANSPORT_TIMEOUT,
            recovery=TerminalActorSubtypeV1.META_INVALID,
        ),
        receipt(
            phase=TerminalActorPhaseV1.REMOTE_EXEC,
            origin=TerminalActorOriginV1.TRANSPORT,
            primary=TerminalActorSubtypeV1.RUN_TRANSPORT_TIMEOUT,
            recovery=TerminalActorSubtypeV1.META_INVALID,
        ),
        receipt(
            phase=TerminalActorPhaseV1.CLEANUP,
            origin=TerminalActorOriginV1.TRANSPORT,
            primary=TerminalActorSubtypeV1.RUN_TRANSPORT_TIMEOUT,
            recovery=TerminalActorSubtypeV1.RECOVERED_SETTLED,
        ),
        receipt(
            phase=TerminalActorPhaseV1.META_VALIDATE,
            origin=TerminalActorOriginV1.ACTOR,
            primary=TerminalActorSubtypeV1.COMPLETED,
            recovery=None,
        ),
        receipt(
            phase=TerminalActorPhaseV1.META_VALIDATE,
            origin=TerminalActorOriginV1.PROTOCOL,
            primary=TerminalActorSubtypeV1.META_INVALID,
            recovery=TerminalActorSubtypeV1.META_INVALID,
        ),
        replace(
            receipt(
                phase=TerminalActorPhaseV1.CLEANUP,
                origin=TerminalActorOriginV1.TRANSPORT,
                primary=TerminalActorSubtypeV1.RUN_TRANSPORT_TIMEOUT,
                recovery=TerminalActorSubtypeV1.META_INVALID,
            ),
            diagnostic_digest_sha256="0" * 64,
        ),
        receipt(
            phase=TerminalActorPhaseV1.CENSUS,
            origin=TerminalActorOriginV1.ACTOR,
            primary=TerminalActorSubtypeV1.CLEANUP_UNVERIFIED,
            recovery=None,
            cleanup_verified=True,
            census_verified=False,
        ),
    ]

    for actor_receipt in invalid:
        failure = ToolFailure(
            code="terminal_actor_cleanup_unverified",
            execution_may_have_started=True,
            cleanup_verified=False,
            census_verified=False,
            actor_receipt=actor_receipt,
        )
        with pytest.raises(
            BridgeError,
            match="external_response_actor_receipt_invalid",
        ):
            encode_tool_response(request, failure)


@pytest.mark.parametrize(
    ("case", "expected_error", "preserve_receipt"),
    [
        ("completed", "external_response_return_code_invalid", False),
        ("semantic-timeout", "external_response_return_code_invalid", False),
        ("recovered-settled", "external_response_return_code_invalid", False),
        ("valid-fatal", "external_response_failure_invalid", True),
        ("invalid-typed-fatal", "external_response_actor_receipt_invalid", False),
    ],
)
def test_v3_preencode_failures_always_fallback_to_a_valid_typed_fatal(
    case: str,
    expected_error: str,
    preserve_receipt: bool,
) -> None:
    raw = json.dumps(
        live_request_value(background=False),
        separators=(",", ":"),
    ).encode()
    request = parse_tool_request(raw, allow_legacy_v2=False)
    actor_done_ns = request.actor_done_monotonic_ns
    assert actor_done_ns is not None
    cutoff_ns = actor_done_ns - 1_000

    if case == "valid-fatal":
        actor_receipt = TerminalActorReceiptV1.create(
            phase=TerminalActorPhaseV1.CLEANUP,
            origin=TerminalActorOriginV1.TRANSPORT,
            primary_subtype=TerminalActorSubtypeV1.RUN_TRANSPORT_TIMEOUT,
            recovery_subtype=TerminalActorSubtypeV1.CLEANUP_UNVERIFIED,
            execution_may_have_started=True,
            effective_cutoff_monotonic_ns=cutoff_ns,
            cleanup_verified=False,
            census_verified=False,
        )
        result: ToolExecution | ToolFailure = ToolFailure(
            code="INVALID CODE",
            execution_may_have_started=True,
            cleanup_verified=False,
            census_verified=False,
            actor_receipt=actor_receipt,
        )
    elif case == "invalid-typed-fatal":
        actor_receipt = replace(
            TerminalActorReceiptV1.create(
                phase=TerminalActorPhaseV1.ACTOR_DONE,
                origin=TerminalActorOriginV1.ACTOR,
                primary_subtype=TerminalActorSubtypeV1.UNEXPECTED_FAILURE,
                recovery_subtype=None,
                execution_may_have_started=False,
                effective_cutoff_monotonic_ns=cutoff_ns,
                cleanup_verified=None,
                census_verified=None,
            ),
            diagnostic_digest_sha256="0" * 64,
        )
        result = ToolFailure(
            code="terminal_actor_failure",
            execution_may_have_started=False,
            cleanup_verified=None,
            census_verified=None,
            actor_receipt=actor_receipt,
        )
    else:
        if case == "completed":
            origin = TerminalActorOriginV1.ACTOR
            primary = TerminalActorSubtypeV1.COMPLETED
            recovery = None
            timed_out = False
        elif case == "semantic-timeout":
            origin = TerminalActorOriginV1.SEMANTIC
            primary = TerminalActorSubtypeV1.SEMANTIC_EXECUTION_TIMED_OUT
            recovery = None
            timed_out = True
        else:
            origin = TerminalActorOriginV1.TRANSPORT
            primary = TerminalActorSubtypeV1.RUN_TRANSPORT_TIMEOUT
            recovery = TerminalActorSubtypeV1.RECOVERED_SETTLED
            timed_out = False
        actor_receipt = TerminalActorReceiptV1.create(
            phase=TerminalActorPhaseV1.META_VALIDATE,
            origin=origin,
            primary_subtype=primary,
            recovery_subtype=recovery,
            execution_may_have_started=True,
            effective_cutoff_monotonic_ns=cutoff_ns,
            cleanup_verified=True,
            census_verified=True,
        )
        result = ToolExecution(
            return_code=2**31,
            timed_out=timed_out,
            stdout=b"",
            stderr=b"",
            stdout_truncated=False,
            stderr_truncated=False,
            cleanup_attempted=True,
            term_sent=False,
            kill_sent=False,
            cleanup_verified=True,
            census_verified=True,
            survivor_count=0,
            process_disposition=ProcessDisposition.FOREGROUND_CLEANED,
            target_task_id=None,
            actor_receipt=actor_receipt,
        )

    if expected_error == "external_response_actor_receipt_invalid":
        with pytest.raises(BridgeError, match=expected_error) as first:
            _preflight_response_serialization(request, result)
    else:
        _preflight_response_serialization(request, result)
        with pytest.raises(BridgeError, match=expected_error) as first:
            encode_tool_response(request, result)

    fallback = _fallback_serialization_failure(
        request,
        result,
        code=str(first.value),
    )
    _preflight_response_serialization(request, fallback)
    response = json.loads(encode_tool_response(request, fallback))
    schema = json.loads((ROOT / "schemas" / "external-tool-stdio-v3.json").read_bytes())
    _assert_schema(schema, schema, response)

    assert response["settlement"] == "fatal"
    assert response["failure"]["code"] == expected_error
    fallback_receipt = fallback.actor_receipt
    assert fallback_receipt is not None
    assert response["failure"]["actor_receipt"] == fallback_receipt.as_dict()
    if preserve_receipt:
        assert fallback_receipt == actor_receipt
    else:
        assert fallback_receipt.phase is TerminalActorPhaseV1.ACTOR_DONE
        assert fallback_receipt.origin is TerminalActorOriginV1.ACTOR
        assert (
            fallback_receipt.primary_subtype
            is TerminalActorSubtypeV1.UNEXPECTED_FAILURE
        )
        assert fallback_receipt.recovery_subtype is None
        assert fallback_receipt.effective_cutoff_monotonic_ns == cutoff_ns
        assert (
            fallback_receipt.execution_may_have_started
            is fallback.execution_may_have_started
        )
        assert fallback_receipt.cleanup_verified is fallback.cleanup_verified
        assert fallback_receipt.census_verified is fallback.census_verified


@pytest.mark.parametrize(
    ("tool_name", "arguments"),
    [
        (
            "run_terminal_command",
            {"command": "true", "description": "test"},
        ),
        ("read_file", {"target_file": "notes.txt"}),
        (
            "search_replace",
            {"file_path": "notes.txt", "old_string": "a", "new_string": "b"},
        ),
        ("write", {"file_path": "notes.txt", "content": "hello"}),
        ("list_dir", {"target_directory": "."}),
        ("grep", {"pattern": "hello"}),
        (
            "kill_terminal_command",
            {"task_id": "018f22d6-9f04-7cc0-8000-000000000001"},
        ),
        (
            "get_terminal_command_output",
            {
                "task_ids": ["018f22d6-9f04-7cc0-8000-000000000001"],
                "timeout_ms": 0,
            },
        ),
    ],
)
def test_all_eight_tools_preserve_raw_arguments(
    tool_name: str, arguments: dict[str, object]
) -> None:
    value = request_value(tool_name, arguments)
    raw = json.dumps(value, separators=(",", ":")).encode()
    request = parse_tool_request(raw)
    assert request.tool_name == tool_name
    assert request.arguments == arguments
    assert request.arguments_json == value["arguments_json"]
    assert request.request_sha256 == hashlib.sha256(raw).hexdigest()


def test_background_response_disposition_binds_target_and_live_census() -> None:
    value = request_value(
        "run_terminal_command",
        {
            "command": "sleep 60",
            "description": "serve",
            "timeout": 0,
            "background": True,
        },
    )
    request = parse_tool_request(json.dumps(value, separators=(",", ":")).encode())
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    response = json.loads(
        encode_tool_response(
            request,
            ToolExecution(
                return_code=0,
                timed_out=False,
                stdout=b"<status>running</status>",
                stderr=b"",
                stdout_truncated=False,
                stderr_truncated=False,
                cleanup_attempted=False,
                term_sent=False,
                kill_sent=False,
                cleanup_verified=True,
                census_verified=True,
                survivor_count=1,
                process_disposition=ProcessDisposition.BACKGROUND_RETAINED,
                target_task_id=task_id,
            ),
        )
    )
    assert response["settlement"] == "completed"
    assert response["result"]["process_disposition"] == "background_retained"
    assert response["result"]["target_task_id"] == task_id
    assert response["result"]["census"]["owned_processes_alive"] == 1


@pytest.mark.parametrize(
    ("kind", "child_exit_code", "return_code", "cleanup_attempted"),
    [
        (BackgroundStartKind.NOT_STARTED, None, 2, False),
        (BackgroundStartKind.QUICK_EXIT, 0, 0, True),
        (BackgroundStartKind.QUICK_EXIT, 7, 2, True),
    ],
)
def test_v3_background_no_id_proof_is_request_aware_and_schema_bound(
    kind: BackgroundStartKind,
    child_exit_code: int | None,
    return_code: int,
    cleanup_attempted: bool,
) -> None:
    raw = json.dumps(
        live_request_value(background=True), separators=(",", ":")
    ).encode()
    request = parse_tool_request(raw, allow_legacy_v2=False)
    response = json.loads(
        encode_tool_response(
            request,
            ToolExecution(
                return_code=return_code,
                timed_out=False,
                stdout=b"<observation>background_start_not_running</observation>",
                stderr=b"",
                stdout_truncated=False,
                stderr_truncated=False,
                cleanup_attempted=cleanup_attempted,
                term_sent=False,
                kill_sent=False,
                cleanup_verified=True,
                census_verified=True,
                survivor_count=0,
                process_disposition=ProcessDisposition.NO_PROCESS,
                target_task_id=None,
                background_start_observation=BackgroundStartObservation(
                    proof_version=BACKGROUND_START_PROOF_VERSION,
                    kind=kind,
                    task_id_published=False,
                    child_exit_code=child_exit_code,
                ),
            ),
        )
    )
    observation = response["result"]["background_start_observation"]
    assert observation == {
        "proof_version": BACKGROUND_START_PROOF_VERSION,
        "kind": kind.value,
        "task_id_published": False,
        "child_exit_code": child_exit_code,
    }
    schema = json.loads((ROOT / "schemas" / "external-tool-stdio-v3.json").read_bytes())
    _assert_schema(schema, schema, response)


@pytest.mark.parametrize(
    ("background", "return_code", "cleanup_attempted", "observation"),
    [
        (True, 2, False, None),
        (
            True,
            0,
            True,
            BackgroundStartObservation(
                proof_version=BACKGROUND_START_PROOF_VERSION,
                kind=BackgroundStartKind.QUICK_EXIT,
                task_id_published=True,
                child_exit_code=0,
            ),
        ),
        (
            False,
            0,
            True,
            BackgroundStartObservation(
                proof_version=BACKGROUND_START_PROOF_VERSION,
                kind=BackgroundStartKind.QUICK_EXIT,
                task_id_published=False,
                child_exit_code=0,
            ),
        ),
        (
            True,
            0,
            True,
            BackgroundStartObservation(
                proof_version="background-start-no-id-proof-v0",
                kind=BackgroundStartKind.QUICK_EXIT,
                task_id_published=False,
                child_exit_code=0,
            ),
        ),
        (
            True,
            2,
            True,
            BackgroundStartObservation(
                proof_version=BACKGROUND_START_PROOF_VERSION,
                kind=BackgroundStartKind.QUICK_EXIT,
                task_id_published=False,
                child_exit_code=None,
            ),
        ),
        (
            True,
            2,
            False,
            BackgroundStartObservation(
                proof_version=BACKGROUND_START_PROOF_VERSION,
                kind=BackgroundStartKind.NOT_STARTED,
                task_id_published=False,
                child_exit_code=7,
            ),
        ),
    ],
    ids=[
        "rc2-missing-proof",
        "publish-race",
        "foreground-cross-mode",
        "wrong-proof-version",
        "quick-exit-missing-child-code",
        "not-started-with-child-code",
    ],
)
def test_v3_background_no_id_missing_forged_or_cross_mode_proof_fails_closed(
    background: bool,
    return_code: int,
    cleanup_attempted: bool,
    observation: BackgroundStartObservation | None,
) -> None:
    raw = json.dumps(
        live_request_value(background=background),
        separators=(",", ":"),
    ).encode()
    execution = ToolExecution(
        return_code=return_code,
        timed_out=False,
        stdout=b"forged",
        stderr=b"",
        stdout_truncated=False,
        stderr_truncated=False,
        cleanup_attempted=cleanup_attempted,
        term_sent=False,
        kill_sent=False,
        cleanup_verified=True,
        census_verified=True,
        survivor_count=0,
        process_disposition=ProcessDisposition.NO_PROCESS,
        target_task_id=None,
        background_start_observation=observation,
    )
    with pytest.raises(BridgeError, match="external_response_process_invalid"):
        encode_tool_response(
            parse_tool_request(raw, allow_legacy_v2=False),
            execution,
        )


@pytest.mark.parametrize(
    ("background", "disposition", "cleanup_attempted"),
    [
        (False, ProcessDisposition.NO_PROCESS, False),
        (True, ProcessDisposition.FOREGROUND_CLEANED, True),
    ],
    ids=["foreground-as-no-process", "background-as-foreground-cleaned"],
)
def test_v3_terminal_dispositions_are_bound_to_the_request_mode(
    background: bool,
    disposition: ProcessDisposition,
    cleanup_attempted: bool,
) -> None:
    request = parse_tool_request(
        json.dumps(
            live_request_value(background=background),
            separators=(",", ":"),
        ).encode(),
        allow_legacy_v2=False,
    )
    execution = ToolExecution(
        return_code=0,
        timed_out=False,
        stdout=b"cross-mode",
        stderr=b"",
        stdout_truncated=False,
        stderr_truncated=False,
        cleanup_attempted=cleanup_attempted,
        term_sent=False,
        kill_sent=False,
        cleanup_verified=True,
        census_verified=True,
        survivor_count=0,
        process_disposition=disposition,
        target_task_id=None,
    )
    with pytest.raises(BridgeError, match="external_response_process_invalid"):
        encode_tool_response(request, execution)


@pytest.mark.parametrize(
    (
        "tool_name",
        "arguments",
        "disposition",
        "target_task_id",
        "cleanup_attempted",
        "survivor_count",
    ),
    [
        (
            "read_file",
            {"path": "README.md"},
            ProcessDisposition.BACKGROUND_RETAINED,
            "018f22d6-9f04-7cc0-8000-000000000001",
            False,
            1,
        ),
        (
            "get_terminal_command_output",
            {"task_ids": [], "timeout_ms": 0},
            ProcessDisposition.FOREGROUND_CLEANED,
            None,
            True,
            0,
        ),
        (
            "run_terminal_command",
            {
                "command": "serve",
                "description": "wrong terminated mode",
                "timeout": 0,
                "background": True,
            },
            ProcessDisposition.BACKGROUND_TERMINATED,
            "018f22d6-9f04-7cc0-8000-000000000001",
            True,
            0,
        ),
        (
            "kill_terminal_command",
            {"task_id": "018f22d6-9f04-7cc0-8000-000000000001"},
            ProcessDisposition.BACKGROUND_RETAINED,
            "018f22d6-9f04-7cc0-8000-000000000001",
            False,
            1,
        ),
    ],
    ids=[
        "filesystem-as-retained",
        "status-as-foreground-cleaned",
        "background-start-as-terminated",
        "kill-as-retained",
    ],
)
def test_v3_every_process_disposition_is_bound_to_its_request_operation(
    tool_name: str,
    arguments: dict[str, object],
    disposition: ProcessDisposition,
    target_task_id: str | None,
    cleanup_attempted: bool,
    survivor_count: int,
) -> None:
    value = live_request_value(background=False)
    value["tool_name"] = tool_name
    value["arguments_json"] = json.dumps(arguments, separators=(",", ":"))
    request = parse_tool_request(
        json.dumps(value, separators=(",", ":")).encode(),
        allow_legacy_v2=False,
    )
    execution = ToolExecution(
        return_code=0,
        timed_out=False,
        stdout=b"cross-operation",
        stderr=b"",
        stdout_truncated=False,
        stderr_truncated=False,
        cleanup_attempted=cleanup_attempted,
        term_sent=False,
        kill_sent=False,
        cleanup_verified=True,
        census_verified=True,
        survivor_count=survivor_count,
        process_disposition=disposition,
        target_task_id=target_task_id,
    )
    with pytest.raises(BridgeError, match="external_response_process_invalid"):
        encode_tool_response(request, execution)


@pytest.mark.parametrize(
    "changes",
    [
        {"cleanup_verified": False},
        {"census_verified": False},
        {"survivor_count": 1},
        {"timed_out": True},
        {"target_task_id": "018f22d6-9f04-7cc0-8000-000000000001"},
        {"term_sent": True},
        {"kill_sent": True},
    ],
    ids=[
        "cleanup-unverified",
        "census-unverified",
        "survivor",
        "timed-out",
        "published-target-id",
        "term-sent",
        "kill-sent",
    ],
)
def test_v3_background_no_id_proof_requires_the_complete_zero_census_conjunction(
    changes: dict[str, object],
) -> None:
    request = parse_tool_request(
        json.dumps(
            live_request_value(background=True),
            separators=(",", ":"),
        ).encode(),
        allow_legacy_v2=False,
    )
    valid = ToolExecution(
        return_code=0,
        timed_out=False,
        stdout=b"<observation>background_start_quick_exit</observation>",
        stderr=b"",
        stdout_truncated=False,
        stderr_truncated=False,
        cleanup_attempted=True,
        term_sent=False,
        kill_sent=False,
        cleanup_verified=True,
        census_verified=True,
        survivor_count=0,
        process_disposition=ProcessDisposition.NO_PROCESS,
        target_task_id=None,
        background_start_observation=BackgroundStartObservation(
            proof_version=BACKGROUND_START_PROOF_VERSION,
            kind=BackgroundStartKind.QUICK_EXIT,
            task_id_published=False,
            child_exit_code=0,
        ),
    )
    with pytest.raises(BridgeError, match="external_response_process_invalid"):
        encode_tool_response(request, replace(valid, **changes))


@pytest.mark.parametrize(
    "execution",
    [
        ToolExecution(
            return_code=0,
            timed_out=False,
            stdout=b"",
            stderr=b"",
            stdout_truncated=False,
            stderr_truncated=False,
            cleanup_attempted=False,
            term_sent=False,
            kill_sent=False,
            cleanup_verified=True,
            census_verified=True,
            survivor_count=0,
            process_disposition=ProcessDisposition.BACKGROUND_RETAINED,
            target_task_id=None,
        ),
        ToolExecution(
            return_code=0,
            timed_out=False,
            stdout=b"",
            stderr=b"",
            stdout_truncated=False,
            stderr_truncated=False,
            cleanup_attempted=False,
            term_sent=False,
            kill_sent=False,
            cleanup_verified=True,
            census_verified=True,
            survivor_count=1,
            process_disposition=ProcessDisposition.NO_PROCESS,
            target_task_id=None,
        ),
    ],
)
def test_response_disposition_matrix_fails_closed(execution: ToolExecution) -> None:
    raw = json.dumps(request_value(), separators=(",", ":")).encode()
    with pytest.raises(BridgeError, match="external_response_process_invalid"):
        encode_tool_response(parse_tool_request(raw), execution)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":"external-tool-stdio-v2","schema_version":"x"}',
        b"{}\r",
        json.dumps({**request_value(), "unknown": True}).encode(),
        json.dumps({**request_value(), "logical_cwd": "/workspace/../tmp"}).encode(),
        json.dumps(
            {
                **request_value(),
                "arguments_json": '{"target_file":"a","target_file":"b"}',
                "tool_name": "read_file",
            }
        ).encode(),
    ],
)
def test_request_parser_fails_closed(raw: bytes) -> None:
    with pytest.raises(BridgeError):
        parse_tool_request(raw)


def test_real_child_round_trip_keeps_stdout_protocol_only(tmp_path: Path) -> None:
    raw = json.dumps(request_value(), separators=(",", ":")).encode()
    child = tmp_path / "child.py"
    child.write_text(
        "import base64,hashlib,json,sys\n"
        f"raw={raw!r}\n"
        "sys.stdout.buffer.write(raw+b'\\n');sys.stdout.buffer.flush()\n"
        "response=json.loads(sys.stdin.buffer.readline())\n"
        "assert response['request_sha256']==hashlib.sha256(raw).hexdigest()\n"
        "assert response['settlement']=='completed'\n"
        "output=base64.b64decode(response['result']['stdout_base64'])\n"
        "assert output==b'\\x00ok\\xff'\n"
        "sys.stderr.write('nano run status: artifact_published completed\\n')\n",
        encoding="utf-8",
    )
    handler = Handler()
    outcome = asyncio.run(
        run_stdio_bridge(
            [sys.executable, str(child)],
            handler,
            deadline_sec=5,
        )
    )
    assert outcome.request_count == 1
    assert len(handler.requests) == 1
    assert outcome.stderr.startswith(b"nano run status:")
    assert handler.cleaned is False


def test_known_handler_fatal_is_sent_once_without_replaying_effect(
    tmp_path: Path,
) -> None:
    raw = json.dumps(request_value(), separators=(",", ":")).encode()
    child = tmp_path / "fatal-child.py"
    child.write_text(
        "import json,sys\n"
        f"raw={raw!r}\n"
        "sys.stdout.buffer.write(raw+b'\\n');sys.stdout.buffer.flush()\n"
        "response=json.loads(sys.stdin.buffer.readline())\n"
        "assert response['settlement']=='fatal'\n"
        "assert response['failure']['code']=='terminal_actor_cleanup_unverified'\n"
        "assert response['failure']['cleanup_verified'] is False\n",
        encoding="utf-8",
    )

    class FatalHandler(Handler):
        async def execute(self, request):
            self.requests.append(request)
            raise ToolFatalError(
                ToolFailure(
                    code="terminal_actor_cleanup_unverified",
                    execution_may_have_started=True,
                    cleanup_verified=False,
                    census_verified=False,
                )
            )

    handler = FatalHandler()
    outcome = asyncio.run(
        run_stdio_bridge(
            [sys.executable, str(child)],
            handler,
            deadline_sec=5,
        )
    )

    assert outcome.request_count == 1
    assert len(handler.requests) == 1
    assert handler.cleaned is False


def test_handler_transport_timeout_is_not_misclassified_as_bridge_deadline(
    tmp_path: Path,
) -> None:
    raw = json.dumps(request_value(), separators=(",", ":")).encode()
    child = tmp_path / "transport-fatal-child.py"
    child.write_text(
        "import json,sys\n"
        f"raw={raw!r}\n"
        "sys.stdout.buffer.write(raw+b'\\n');sys.stdout.buffer.flush()\n"
        "response=json.loads(sys.stdin.buffer.readline())\n"
        "assert response['settlement']=='fatal'\n"
        "assert response['failure']['code']=='terminal_actor_unexpected_failure'\n",
        encoding="utf-8",
    )

    class TransportFailureHandler(Handler):
        async def execute(self, request):
            self.requests.append(request)
            raise TimeoutError("remote transport timed out")

    handler = TransportFailureHandler()
    outcome = asyncio.run(
        run_stdio_bridge(
            [sys.executable, str(child)],
            handler,
            deadline_sec=5,
        )
    )

    assert outcome.request_count == 1
    assert len(handler.requests) == 1
    assert handler.cleaned is False


def test_cancellation_cleans_active_handler_and_child(tmp_path: Path) -> None:
    raw = json.dumps(request_value(), separators=(",", ":")).encode()
    child = tmp_path / "child.py"
    child.write_text(
        "import sys,time\n"
        f"sys.stdout.buffer.write({raw!r}+b'\\n');sys.stdout.buffer.flush()\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )

    class BlockingHandler(Handler):
        def __init__(self) -> None:
            super().__init__()
            self.execute_cancelled = False

        async def execute(self, request):
            self.requests.append(request)
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.execute_cancelled = True
                raise

    async def scenario() -> BlockingHandler:
        handler = BlockingHandler()
        task = asyncio.create_task(
            run_stdio_bridge(
                [sys.executable, str(child)],
                handler,
                deadline_sec=60,
            )
        )
        while not handler.requests:
            await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return handler

    handler = asyncio.run(scenario())
    assert handler.cleaned is True
    assert handler.execute_cancelled is True


def test_handler_execute_is_bounded_by_bridge_remaining_deadline(
    tmp_path: Path,
) -> None:
    raw = json.dumps(request_value(), separators=(",", ":")).encode()
    child = tmp_path / "child.py"
    child.write_text(
        "import sys,time\n"
        f"sys.stdout.buffer.write({raw!r}+b'\\n');sys.stdout.buffer.flush()\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )

    class BlockingHandler(Handler):
        async def execute(self, request):
            self.requests.append(request)
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    async def scenario() -> tuple[BlockingHandler, float]:
        handler = BlockingHandler()
        loop = asyncio.get_running_loop()
        started = loop.time()
        with pytest.raises(
            BridgeError,
            match="external_bridge_handler_deadline_exceeded",
        ):
            await asyncio.wait_for(
                run_stdio_bridge(
                    [sys.executable, str(child)],
                    handler,
                    deadline_sec=0.25,
                ),
                timeout=1,
            )
        return handler, loop.time() - started

    handler, elapsed = asyncio.run(scenario())
    assert handler.cleaned is True
    assert len(handler.requests) == 1
    assert elapsed < 1


def test_shielded_cleanup_has_a_hard_bound() -> None:
    async def scenario() -> tuple[bool, object, asyncio.CancelledError | None, float]:
        loop = asyncio.get_running_loop()
        started = loop.time()
        result = await _complete_shielded(
            asyncio.Event().wait(),
            timeout_sec=0.05,
        )
        return *result, loop.time() - started

    completed, value, cancellation, elapsed = asyncio.run(scenario())
    assert completed is False
    assert value is None
    assert cancellation is None
    assert elapsed < 0.5


def test_shielded_cleanup_reasserts_cancellation_with_a_secondary_hard_bound() -> None:
    async def swallow_first_cancellation() -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await asyncio.sleep(0.5)

    async def scenario() -> tuple[
        bool,
        object,
        asyncio.CancelledError | None,
        float,
        int,
    ]:
        cleanup = asyncio.create_task(swallow_first_cancellation())
        await asyncio.sleep(0)
        loop = asyncio.get_running_loop()
        started = loop.time()
        result = await _complete_shielded(
            cleanup,
            timeout_sec=0.1,
        )
        pending = [
            task
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and not task.done()
        ]
        return *result, loop.time() - started, len(pending)

    completed, value, cancellation, elapsed, pending_count = asyncio.run(scenario())
    assert completed is False
    assert value is None
    assert cancellation is None
    # Cancellation settlement remains inside one total cutoff. The margin only
    # accommodates loaded CI schedulers; swallowing every cancel is covered
    # separately by the detachment-at-cutoff test below.
    assert elapsed < 0.15
    assert pending_count == 0


def test_shielded_cleanup_detaches_multi_cancel_swallower_at_total_cutoff() -> None:
    async def scenario() -> tuple[
        bool,
        object,
        asyncio.CancelledError | None,
        float,
        bool,
    ]:
        release = asyncio.Event()

        async def swallow_repeated_cancellation() -> None:
            while not release.is_set():
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    continue

        cleanup = asyncio.create_task(swallow_repeated_cancellation())
        loop = asyncio.get_running_loop()
        started = loop.time()
        result = await _complete_shielded(cleanup, timeout_sec=0.02)
        elapsed = loop.time() - started
        still_running = not cleanup.done()
        release.set()
        await cleanup
        return *result, elapsed, still_running

    completed, value, cancellation, elapsed, still_running = asyncio.run(scenario())
    assert completed is False
    assert value is None
    assert cancellation is None
    assert elapsed < 0.024
    assert still_running is True


def test_shielded_cleanup_consumes_cancelled_gather_exception() -> None:
    async def scenario() -> list[dict[str, object]]:
        loop = asyncio.get_running_loop()
        contexts: list[dict[str, object]] = []
        previous_handler = loop.get_exception_handler()
        loop.set_exception_handler(lambda _loop, context: contexts.append(context))
        try:
            cleanup = asyncio.gather(
                asyncio.Event().wait(),
                asyncio.Event().wait(),
            )
            completed, value, cancellation = await _complete_shielded(
                cleanup,
                timeout_sec=0.01,
            )
            assert completed is False
            assert value is None
            assert cancellation is None
            del cleanup
            gc.collect()
            await asyncio.sleep(0)
            return contexts
        finally:
            loop.set_exception_handler(previous_handler)

    contexts = asyncio.run(scenario())
    assert contexts == []


def test_cancellation_during_failure_cleanup_waits_for_cleanup(
    tmp_path: Path,
) -> None:
    child = tmp_path / "bad-child.py"
    child.write_text(
        "import sys,time\n"
        "sys.stdout.buffer.write(b'not-json\\n');sys.stdout.buffer.flush()\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )

    class SlowCleanupHandler(Handler):
        def __init__(self) -> None:
            super().__init__()
            self.cleanup_started = asyncio.Event()
            self.cleanup_release = asyncio.Event()

        async def cleanup_active(self) -> bool:
            self.cleanup_started.set()
            await self.cleanup_release.wait()
            self.cleaned = True
            return True

    async def scenario() -> SlowCleanupHandler:
        handler = SlowCleanupHandler()
        task = asyncio.create_task(
            run_stdio_bridge(
                [sys.executable, str(child)],
                handler,
                deadline_sec=60,
            )
        )
        await asyncio.wait_for(handler.cleanup_started.wait(), 2)
        task.cancel()
        await asyncio.sleep(0.1)
        assert not task.done(), "bridge returned before owned cleanup completed"
        handler.cleanup_release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        return handler

    assert asyncio.run(scenario()).cleaned is True


def test_host_child_inherits_credential_but_remote_allowlist_excludes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = "synthetic-" + "credential-marker"
    monkeypatch.setenv("XAI_API_KEY", marker)
    child = tmp_path / "child.py"
    child.write_text(
        "import os,sys\n"
        f"assert os.environ.get('XAI_API_KEY') == {marker!r}\n"
        "sys.stderr.write('credential-present\\n')\n",
        encoding="utf-8",
    )
    command = [sys.executable, str(child)]
    outcome = asyncio.run(run_stdio_bridge(command, Handler(), deadline_sec=5))
    assert marker not in "\0".join(command)
    assert marker.encode() not in outcome.stderr
    assert outcome.stderr == b"credential-present\n"
    assert "XAI_API_KEY" not in REMOTE_ENVIRONMENT_ALLOWLIST
    assert all(
        fragment not in name.upper()
        for name in REMOTE_ENVIRONMENT_ALLOWLIST
        for fragment in ("KEY", "TOKEN", "SECRET", "AUTHORIZATION")
    )
    assert os.environ["XAI_API_KEY"] == marker


def test_harbor_environment_proxy_normalizes_only_optional_exec_streams(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import ModuleType, SimpleNamespace

    for name in (
        "harbor",
        "harbor.agents",
        "harbor.agents.base",
        "harbor.environments",
        "harbor.environments.base",
        "harbor.models",
        "harbor.models.agent",
        "harbor.models.agent.context",
    ):
        module = ModuleType(name)
        if name.rsplit(".", 1)[-1] not in {"base", "context"}:
            module.__path__ = []
        monkeypatch.setitem(sys.modules, name, module)
    sys.modules["harbor.agents.base"].BaseAgent = object
    sys.modules["harbor.environments.base"].BaseEnvironment = object
    sys.modules["harbor.models.agent.context"].AgentContext = object
    monkeypatch.delitem(sys.modules, "nano_grok_build.adapter.harbor", raising=False)
    import nano_grok_build.adapter.harbor as harbor_adapter
    from nano_grok_build.adapter.terminal_actor import RemoteTerminalActor

    class Environment:
        def __init__(self) -> None:
            self.results = [
                SimpleNamespace(return_code=23, stdout=None, stderr=None),
                SimpleNamespace(return_code=0, stdout=b"invalid", stderr=None),
            ]
            self.uploads: list[tuple[object, object]] = []
            self.downloads: list[tuple[object, object]] = []

        async def exec(self, *_args, **_kwargs):
            return self.results.pop(0)

        async def upload_file(self, source, target) -> None:
            self.uploads.append((source, target))

        async def download_file(self, source, target) -> None:
            self.downloads.append((source, target))

    environment = Environment()
    proxy = harbor_adapter._HarborEnvironmentProxy(environment)
    actor = RemoteTerminalActor(proxy)
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app",
        "default_cwd": "/app",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }

    async def scenario() -> None:
        result = await actor.exec_snapshot("true", timeout_sec=1)
        assert result.return_code == 23
        assert result.stdout == result.stderr == ""
        with pytest.raises(
            BridgeError,
            match="^terminal_actor_snapshot_response_invalid$",
        ):
            await actor.exec_snapshot("true", timeout_sec=1)
        await proxy.upload_file(tmp_path / "source", "/remote")
        await proxy.download_file("/remote", tmp_path / "target")

    asyncio.run(scenario())
    assert environment.uploads == [(tmp_path / "source", "/remote")]
    assert environment.downloads == [("/remote", tmp_path / "target")]


def test_harbor_success_hands_off_background_but_diagnostic_failure_cleans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import ModuleType, SimpleNamespace

    for name in (
        "harbor",
        "harbor.agents",
        "harbor.agents.base",
        "harbor.environments",
        "harbor.environments.base",
        "harbor.models",
        "harbor.models.agent",
        "harbor.models.agent.context",
    ):
        module = ModuleType(name)
        if name.rsplit(".", 1)[-1] not in {"base", "context"}:
            module.__path__ = []
        monkeypatch.setitem(sys.modules, name, module)
    sys.modules["harbor.agents.base"].BaseAgent = object
    sys.modules["harbor.environments.base"].BaseEnvironment = object
    sys.modules["harbor.models.agent.context"].AgentContext = object
    import nano_grok_build.adapter.harbor as harbor_adapter

    async def handoff_budget_scenario():
        scale = 0.001
        below = await _complete_shielded(
            asyncio.sleep(100 * scale, result="settled"),
            timeout_sec=harbor_adapter._HANDOFF_TIMEOUT_SEC * scale,
        )
        above = await _complete_shielded(
            asyncio.sleep(200 * scale, result="late"),
            timeout_sec=harbor_adapter._HANDOFF_TIMEOUT_SEC * scale,
        )
        return below, above

    assert harbor_adapter._HANDOFF_TIMEOUT_SEC == 150.0
    below, above = asyncio.run(handoff_budget_scenario())
    assert below == (True, "settled", None)
    assert above == (False, None, None)

    task_id = "018f22d6-9f04-7cc0-8000-000000000001"

    class Actor:
        def __init__(self, *, has_background: bool = True) -> None:
            self.cleaned = False
            self.sealed = False
            self.liveness_calls = 0
            self.verifier_cleanup_calls = 0
            self.has_background = has_background

        async def background_manifest(self):
            if self.cleaned or not self.has_background:
                return []
            return [
                {
                    "task_id": task_id,
                    "pgid": 123,
                    "monitor_pgid": 124,
                    "output_path": f"/workspace/.terminals/{task_id}.log",
                    "state": "running",
                }
            ]

        def seal_process_lease_v1(self, rows):
            if not rows:
                assert self.cleaned or not self.has_background
                return ProcessLeaseV1(())
            assert not self.cleaned
            assert [row["task_id"] for row in rows] == [task_id]
            self.sealed = True
            return ProcessLeaseV1(())

        async def observe_process_lease_v1(
            self,
            lease,
            *,
            hard_deadline_monotonic_ns,
        ):
            assert type(lease) is ProcessLeaseV1
            if not self.sealed:
                return []
            self.liveness_calls += 1
            assert self.sealed
            assert hard_deadline_monotonic_ns > harbor_adapter.host_monotonic_ns()
            return [
                {
                    "task_id": task_id,
                    "leader_pid": 123,
                    "leader_starttime": 456,
                    "leader_pgid": 123,
                    "monitor_pid": 124,
                    "monitor_starttime": 457,
                    "monitor_pgid": 124,
                    "owner_token_sha256": "c" * 64,
                    "process_alive": False,
                }
            ]

        async def cleanup_active(self) -> bool:
            self.cleaned = True
            return True

        async def close_process_lease_until(self, lease, hard_cutoff_ns) -> bool:
            assert type(lease) is ProcessLeaseV1
            assert hard_cutoff_ns > harbor_adapter.host_monotonic_ns()
            self.verifier_cleanup_calls += 1
            self.cleaned = True
            return True

    class Context:
        @staticmethod
        def is_empty() -> bool:
            return True

    async def bridge(*args, **kwargs):
        del kwargs
        actor = next(value for value in args if isinstance(value, Actor))
        runtime = actor.logs / "runtime"
        runtime.mkdir(parents=True, exist_ok=True)
        (runtime / "run.json").write_bytes(b"{}\n")
        return BridgeOutcome(request_count=1, stderr=b"diagnostic")

    monkeypatch.setattr(harbor_adapter, "run_stdio_bridge", bridge)
    monkeypatch.setattr(
        harbor_adapter,
        "runtime_command",
        lambda **kwargs: ["synthetic-runtime"],
    )
    snapshot_phases: list[str] = []

    async def before_snapshot(target, policy):
        snapshot_phases.append("before")
        return object()

    async def after_snapshot(target, before, *, hard_deadline_monotonic_ns):
        assert hard_deadline_monotonic_ns > harbor_adapter.host_monotonic_ns()
        snapshot_phases.append("after")
        empty_sha256 = hashlib.sha256(b"").hexdigest()
        receipt = harbor_adapter.canonical_json(
            {
                "schema_version": "nano-workspace-receipt-v1",
                "status": "complete",
                "code": "completed",
                "policy": harbor_adapter.SnapshotPolicy().as_dict(),
                "truncated": False,
                "omitted_count": 0,
                "artifacts": {
                    name: {"byte_length": 0, "sha256": empty_sha256}
                    for name in (
                        "workspace-after.json",
                        "workspace-before.json",
                        "workspace-changed.tar",
                        "workspace-delta.json",
                        "workspace-diff.patch",
                    )
                },
            }
        )
        harbor_adapter.NanoGrokBuildAgent._write_immutable(
            target.artifact_dir / "workspace-receipt.json",
            receipt,
        )
        return harbor_adapter.load_workspace_receipt(
            target.artifact_dir / "workspace-receipt.json"
        )

    monkeypatch.setattr(harbor_adapter, "capture_before", before_snapshot)
    monkeypatch.setattr(harbor_adapter, "capture_after", after_snapshot)

    def agent(logs: Path, actor: Actor):
        value = object.__new__(harbor_adapter.NanoGrokBuildAgent)
        value.logs_dir = logs
        value._actor = actor
        actor.logs = logs
        value._run_spec = {
            "schema_version": "nano-run-spec-alpha-1",
            "run_id": "run-1",
            "trial_id": "trial-1",
            "attempt_id": "attempt-0",
            "task": {
                "id": "task",
                "digest": "a" * 64,
                "instruction": "serve",
            },
            "contract": {
                "id": "synthetic-v1",
                "contract_set_sha256": "b" * 64,
                "profile_id": "synthetic-profile-v1",
            },
            "provider": {
                "kind": "scripted",
                "model": "synthetic-model",
                "max_turns": 4,
                "retry_max": 0,
            },
            "workspace_dir": "/workspace",
            "artifact_dir": str((logs / "runtime").resolve()),
            "agent_timeout_sec": 60,
        }
        value._binary_path = Path("/synthetic/nano-cli")
        value._contract_dir = Path("/synthetic/contract")
        value._provider_launch = object()
        value._instruction = None
        value._post_agent_snapshot_task = None
        value._post_agent_snapshot_outcome = None
        value._post_snapshot_liveness_task = None
        value._post_snapshot_liveness_outcome = None
        value._post_snapshot_liveness_aborted = False
        value._post_verifier_cleanup_task = None
        value._post_verifier_cleanup_outcome = None
        value._process_lease_v1 = None
        value._background_manifest_handoff_v1 = None
        return value

    success_logs = tmp_path / "success"
    success_logs.mkdir()
    success_actor = Actor()
    success_agent = agent(success_logs, success_actor)
    asyncio.run(success_agent.run("serve", object(), Context()))
    assert success_actor.cleaned is False
    assert snapshot_phases == ["before"]
    success_hard_ns = harbor_adapter.host_monotonic_ns() + 150_000_000_000
    asyncio.run(
        success_agent.post_agent_workspace_snapshot_v1(
            hard_deadline_monotonic_ns=success_hard_ns,
        )
    )
    asyncio.run(
        success_agent.post_agent_workspace_snapshot_v1(
            hard_deadline_monotonic_ns=success_hard_ns,
        )
    )
    assert snapshot_phases == ["before", "after"]
    assert success_actor.sealed is True
    assert success_actor.liveness_calls == 1
    manifest = json.loads(
        (success_logs / "runtime-background-manifest.json").read_bytes()
    )
    assert manifest["tasks"][0]["task_id"] == task_id
    liveness = json.loads(
        (success_logs / "runtime-background-liveness-v1.json").read_bytes()
    )
    assert liveness["schema_version"] == "nano-background-liveness-v1"
    assert (
        liveness["background_manifest_sha256"]
        == hashlib.sha256(
            (success_logs / "runtime-background-manifest.json").read_bytes()
        ).hexdigest()
    )
    assert (
        liveness["workspace_receipt_sha256"]
        == hashlib.sha256(
            (success_logs / "workspace-receipt.json").read_bytes()
        ).hexdigest()
    )
    assert liveness["tasks"][0]["process_alive"] is False

    collision_logs = tmp_path / "collision"
    collision_logs.mkdir()
    collision_actor = Actor()
    collision_agent = agent(collision_logs, collision_actor)
    asyncio.run(collision_agent.run("serve", object(), Context()))
    collision_path = collision_logs / "runtime-background-liveness-v1.json"
    collision_bytes = b'{"forged":true}\n'
    collision_path.write_bytes(collision_bytes)
    with pytest.raises(
        BridgeError,
        match="^post_snapshot_background_liveness_invalid$",
    ):
        asyncio.run(
            collision_agent.post_agent_workspace_snapshot_v1(
                hard_deadline_monotonic_ns=(
                    harbor_adapter.host_monotonic_ns() + 150_000_000_000
                ),
            )
        )
    assert collision_actor.cleaned is True
    assert collision_path.read_bytes() == collision_bytes

    neutral_logs = tmp_path / "neutral"
    neutral_logs.mkdir()
    neutral_actor = Actor(has_background=False)
    neutral_agent = agent(neutral_logs, neutral_actor)
    asyncio.run(neutral_agent.run("serve", object(), Context()))
    asyncio.run(
        neutral_agent.post_agent_workspace_snapshot_v1(
            hard_deadline_monotonic_ns=(
                harbor_adapter.host_monotonic_ns() + 150_000_000_000
            ),
        )
    )
    assert neutral_actor.cleaned is False
    assert neutral_actor.sealed is False
    assert neutral_actor.liveness_calls == 0
    assert not (neutral_logs / "runtime-background-liveness-v1.json").exists()

    async def diagnostic_after_snapshot(target, before, *, hard_deadline_monotonic_ns):
        assert hard_deadline_monotonic_ns > harbor_adapter.host_monotonic_ns()
        snapshot_phases.append("after-diagnostic")
        receipt = harbor_adapter.canonical_json(
            {
                "schema_version": "nano-workspace-receipt-v3",
                "status": "failed",
                "code": "workspace_after_capture_failed",
                "policy": {"version": "nano-workspace-snapshot-policy-v1"},
                "truncated": False,
                "omitted_count": 0,
                "artifacts": {},
                "failure": {
                    "stage": "host-evidence",
                    "category": "evidence",
                    "subtype": "host_evidence_materialization_failed",
                    "timeout_origin": "not_a_timeout",
                    "errno": None,
                    "return_code": None,
                    "attempt": 1,
                    "stage_validated": True,
                    "termination_verified": True,
                    "cleanup_verified": True,
                    "zero_census_verified": True,
                },
            }
        )
        harbor_adapter.NanoGrokBuildAgent._write_immutable(
            target.artifact_dir / "workspace-receipt.json",
            receipt,
        )
        return harbor_adapter.load_workspace_receipt(
            target.artifact_dir / "workspace-receipt.json"
        )

    monkeypatch.setattr(
        harbor_adapter,
        "capture_after",
        diagnostic_after_snapshot,
    )
    diagnostic_logs = tmp_path / "after-diagnostic"
    diagnostic_logs.mkdir()
    diagnostic_actor = Actor()
    diagnostic_agent = agent(diagnostic_logs, diagnostic_actor)
    asyncio.run(diagnostic_agent.run("serve", object(), Context()))
    diagnostic_hard_ns = harbor_adapter.host_monotonic_ns() + 150_000_000_000
    asyncio.run(
        diagnostic_agent.post_agent_workspace_snapshot_v1(
            hard_deadline_monotonic_ns=diagnostic_hard_ns,
        )
    )
    asyncio.run(
        diagnostic_agent.post_agent_workspace_snapshot_v1(
            hard_deadline_monotonic_ns=diagnostic_hard_ns,
        )
    )
    assert diagnostic_actor.cleaned is False
    assert diagnostic_actor.sealed is True
    assert diagnostic_actor.liveness_calls == 1
    assert (diagnostic_logs / "workspace-receipt.json").is_file()
    assert snapshot_phases == [
        "before",
        "after",
        "before",
        "after",
        "before",
        "after",
        "before",
        "after-diagnostic",
    ]

    monkeypatch.setattr(harbor_adapter, "capture_after", after_snapshot)
    failure_logs = tmp_path / "failure"
    failure_logs.mkdir()
    failure_actor = Actor()
    failure_agent = agent(failure_logs, failure_actor)
    write = failure_agent._write_immutable

    def fail_manifest(path: Path, content: bytes) -> None:
        if path.name == "runtime-background-manifest.json":
            raise OSError("disk full")
        write(path, content)

    monkeypatch.setattr(failure_agent, "_write_immutable", fail_manifest)
    with pytest.raises(OSError, match="disk full"):
        asyncio.run(failure_agent.run("serve", object(), Context()))
    asyncio.run(
        failure_agent.post_agent_workspace_snapshot_v1(
            hard_deadline_monotonic_ns=(
                harbor_adapter.host_monotonic_ns() + 150_000_000_000
            ),
        )
    )
    assert failure_actor.cleaned is True
    assert failure_actor.sealed is True
    assert failure_actor.liveness_calls == 0
    assert (failure_logs / "runtime-stderr.json").is_file()
    assert (failure_logs / "workspace-receipt.json").is_file()
    assert snapshot_phases == [
        "before",
        "after",
        "before",
        "after",
        "before",
        "after",
        "before",
        "after-diagnostic",
        "before",
        "after",
    ]
    assert not (failure_logs / "runtime-background-manifest.json").exists()
    assert not (failure_logs / "runtime-background-liveness-v1.json").exists()

    class UncertainActor(Actor):
        async def background_manifest(self):
            raise BridgeError("terminal_actor_background_status_unavailable")

        async def cleanup_active(self) -> bool:
            self.cleaned = True
            return False

    uncertain_logs = tmp_path / "uncertain"
    uncertain_logs.mkdir()
    (uncertain_logs / "runtime").mkdir()
    (uncertain_logs / "runtime" / "run.json").write_bytes(b"{}\n")
    uncertain_actor = UncertainActor()
    uncertain_agent = agent(uncertain_logs, uncertain_actor)
    original = BridgeError("terminal_actor_cleanup_unverified")
    finalization_error = asyncio.run(
        uncertain_agent._finalize_handoff(
            outcome=BridgeOutcome(request_count=1, stderr=b"diagnostic"),
            original_error=original,
        )
    )
    assert isinstance(finalization_error, BridgeError)
    assert str(finalization_error) == "external_bridge_cleanup_unverified"
    failure_manifest = json.loads(
        (uncertain_logs / "runtime-background-manifest.json").read_bytes()
    )
    assert failure_manifest == {
        "schema_version": "nano-background-manifest-failure-v1",
        "run_id": "run-1",
        "trial_id": "trial-1",
        "attempt_id": "attempt-0",
        "run_spec_sha256": harbor_adapter.rust_run_spec_sha256(
            uncertain_agent._run_spec
        ),
        "status": "unavailable",
        "code": "external_bridge_cleanup_unverified",
        "cleanup_attempted": True,
        "cleanup_verified": False,
    }

    cancel_logs = tmp_path / "cancel"
    cancel_logs.mkdir()
    cancel_actor = Actor()
    bridge_started = asyncio.Event()
    bridge_never_finishes = asyncio.Event()
    after_started = asyncio.Event()
    after_release = asyncio.Event()

    async def cancelled_bridge(*args, **kwargs):
        bridge_started.set()
        await bridge_never_finishes.wait()
        raise AssertionError("unreachable")

    async def slow_after_snapshot(target, before, *, hard_deadline_monotonic_ns):
        snapshot_phases.append("after")
        after_started.set()
        await after_release.wait()
        return await after_snapshot(
            target,
            before,
            hard_deadline_monotonic_ns=hard_deadline_monotonic_ns,
        )

    monkeypatch.setattr(harbor_adapter, "run_stdio_bridge", cancelled_bridge)
    monkeypatch.setattr(harbor_adapter, "capture_after", slow_after_snapshot)

    async def cancellation_scenario() -> None:
        cancel_agent = agent(cancel_logs, cancel_actor)
        task = asyncio.create_task(cancel_agent.run("serve", object(), Context()))
        await asyncio.wait_for(bridge_started.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not after_started.is_set()
        hook_task = asyncio.create_task(
            cancel_agent.post_agent_workspace_snapshot_v1(
                hard_deadline_monotonic_ns=(
                    harbor_adapter.host_monotonic_ns() + 150_000_000_000
                ),
            )
        )
        await asyncio.wait_for(after_started.wait(), 1)
        assert not hook_task.done()
        after_release.set()
        await hook_task

    asyncio.run(cancellation_scenario())
    assert cancel_actor.cleaned is True
    assert cancel_actor.sealed is False
    assert cancel_actor.liveness_calls == 0
    assert (cancel_logs / "runtime-stderr.json").is_file()
    assert (cancel_logs / "runtime-background-manifest.json").is_file()
    assert (cancel_logs / "workspace-receipt.json").is_file()
    assert (cancel_logs / "runtime-emergency.json").is_file()
    cancelled_manifest = json.loads(
        (cancel_logs / "runtime-background-manifest.json").read_bytes()
    )
    assert cancelled_manifest["tasks"] == []
    assert not (cancel_logs / "runtime-background-liveness-v1.json").exists()

    monkeypatch.setattr(harbor_adapter, "run_stdio_bridge", bridge)
    monkeypatch.setattr(harbor_adapter, "capture_after", after_snapshot)
    tamper_logs = tmp_path / "manifest-tamper"
    tamper_logs.mkdir()
    tamper_actor = Actor()
    tamper_agent = agent(tamper_logs, tamper_actor)
    asyncio.run(tamper_agent.run("serve", object(), Context()))
    manifest_path = tamper_logs / "runtime-background-manifest.json"
    tampered_manifest = json.loads(manifest_path.read_bytes())
    tampered_manifest["tasks"][0]["pgid"] = 999
    manifest_path.unlink()
    manifest_path.write_bytes(harbor_adapter.canonical_json(tampered_manifest))
    with pytest.raises(
        BridgeError,
        match="^post_snapshot_background_liveness_invalid$",
    ):
        asyncio.run(
            tamper_agent.post_agent_workspace_snapshot_v1(
                hard_deadline_monotonic_ns=(
                    harbor_adapter.host_monotonic_ns() + 150_000_000_000
                ),
            )
        )
    assert tamper_actor.cleaned is True
    assert not (tamper_logs / "runtime-background-liveness-v1.json").exists()

    class SlowLivenessActor(Actor):
        def __init__(self) -> None:
            super().__init__()
            self.liveness_started = asyncio.Event()
            self.liveness_release = asyncio.Event()

        async def observe_process_lease_v1(
            self,
            lease,
            *,
            hard_deadline_monotonic_ns,
        ):
            self.liveness_started.set()
            await self.liveness_release.wait()
            return await super().observe_process_lease_v1(
                lease,
                hard_deadline_monotonic_ns=hard_deadline_monotonic_ns,
            )

    liveness_cancel_logs = tmp_path / "liveness-cancel"
    liveness_cancel_logs.mkdir()
    liveness_cancel_actor = SlowLivenessActor()

    async def liveness_cancellation_scenario() -> None:
        liveness_cancel_agent = agent(
            liveness_cancel_logs,
            liveness_cancel_actor,
        )
        await liveness_cancel_agent.run("serve", object(), Context())
        hook = asyncio.create_task(
            liveness_cancel_agent.post_agent_workspace_snapshot_v1(
                hard_deadline_monotonic_ns=(
                    harbor_adapter.host_monotonic_ns() + 150_000_000_000
                ),
            )
        )
        await asyncio.wait_for(liveness_cancel_actor.liveness_started.wait(), 1)
        hook.cancel()
        await asyncio.sleep(0)
        assert not hook.done()
        liveness_cancel_actor.liveness_release.set()
        with pytest.raises(asyncio.CancelledError):
            await hook
        with pytest.raises(asyncio.CancelledError):
            await liveness_cancel_agent.post_agent_workspace_snapshot_v1(
                hard_deadline_monotonic_ns=(
                    harbor_adapter.host_monotonic_ns() + 150_000_000_000
                ),
            )

    asyncio.run(liveness_cancellation_scenario())
    assert liveness_cancel_actor.cleaned is True
    assert liveness_cancel_actor.verifier_cleanup_calls == 1
    assert liveness_cancel_actor.liveness_calls == 1

    class SnapshotTimeoutEnvironment:
        def __init__(self) -> None:
            self.preflight_calls = 0
            self.capture_calls = 0
            self.snapshot_cleanup_calls = 0

        async def exec(self, command, *, cwd=None, timeout_sec=None, **_kwargs):
            assert cwd == "/workspace"
            if command.startswith("rm -rf -- "):
                self.snapshot_cleanup_calls += 1
                assert timeout_sec == 5.0
                return SimpleNamespace(return_code=0, stdout=None, stderr=None)
            if "mktemp -d " in command and "inventory=" not in command:
                self.preflight_calls += 1
                stage = f"/tmp/nano-workspace-snapshot-v1.fixture{self.preflight_calls}"
                assert timeout_sec == 5.0
                return SimpleNamespace(
                    return_code=0,
                    stdout=f"{stage}\n",
                    stderr=None,
                )
            if "inventory=" in command:
                self.capture_calls += 1
                assert timeout_sec == 120.0
                raise RuntimeError(f"Command timed out after {timeout_sec} seconds")
            raise AssertionError("unexpected snapshot command")

        async def upload_file(self, *_args, **_kwargs):
            raise AssertionError("actor setup upload was not bypassed")

        async def download_file(self, *_args, **_kwargs):
            raise AssertionError("download must not run after capture failure")

    async def setup_snapshot_actor(actor) -> None:
        actor._ready = True
        actor._workspace_mapping = {
            "canonical_cwd": "/workspace",
            "default_cwd": "/workspace",
            "logical_cwd": "/workspace",
            "mode": "existing_directory",
        }
        actor.exec_snapshot_owned = None

    async def setup_owned_snapshot_actor(actor) -> None:
        actor._ready = True
        actor._workspace_mapping = {
            "canonical_cwd": "/workspace",
            "default_cwd": "/workspace",
            "logical_cwd": "/workspace",
            "mode": "existing_directory",
        }

    provider_calls: list[str] = []

    def continued_runtime(**_kwargs):
        provider_calls.append("runtime-command")
        return ["synthetic-runtime"]

    async def continued_bridge(*_args, **_kwargs):
        provider_calls.append("provider")
        return BridgeOutcome(request_count=1, stderr=b"diagnostic")

    monkeypatch.setattr(
        harbor_adapter.RemoteTerminalActor,
        "setup",
        setup_snapshot_actor,
    )
    monkeypatch.setattr(harbor_adapter, "capture_before", real_capture_before)
    monkeypatch.setattr(harbor_adapter, "capture_after", real_capture_after)
    monkeypatch.setattr(harbor_adapter, "runtime_command", continued_runtime)
    monkeypatch.setattr(harbor_adapter, "run_stdio_bridge", continued_bridge)
    setup_logs = tmp_path / "setup-failure"
    setup_logs.mkdir()
    setup_agent = agent(setup_logs, Actor())
    setup_agent.session_id = "session"
    setup_agent.context_id = "context"
    environment = SnapshotTimeoutEnvironment()

    with pytest.raises(
        WorkspaceSnapshotError,
        match="^workspace_before_capture_failed$",
    ):
        asyncio.run(setup_agent.setup(environment))

    assert provider_calls == []
    assert isinstance(
        setup_agent._actor._environment,
        harbor_adapter._HarborEnvironmentProxy,
    )
    assert environment.preflight_calls == 1
    assert environment.capture_calls == 1
    assert environment.snapshot_cleanup_calls == 0
    receipt = json.loads((setup_logs / "workspace-receipt.json").read_bytes())
    assert receipt["failure"]["stage"] == "remote-exec"
    assert receipt["failure"]["category"] == "internal"
    assert receipt["failure"]["attempt"] == 1
    assert not any(
        (setup_logs / name).exists()
        for name in (
            "workspace-before.json",
            "workspace-after.json",
            "workspace-delta.json",
            "workspace-diff.patch",
            "workspace-changed.tar",
        )
    )

    async def proven_snapshot_timeout(
        actor,
        command,
        *,
        stage,
        timeout_sec,
    ):
        assert stage.startswith("/tmp/nano-workspace-snapshot-v1.fixture")
        try:
            await actor._environment.exec(
                command,
                cwd="/workspace",
                timeout_sec=timeout_sec,
            )
        except RuntimeError as error:
            raise SnapshotTransportTimeout(
                termination_verified=True,
                census_verified=True,
                survivor_count=0,
                stage_validated=True,
                timeout_origin=(SnapshotTimeoutOriginV1.SEMANTIC_EXECUTION_TIMED_OUT),
            ) from error
        raise AssertionError("fixture capture unexpectedly completed")

    monkeypatch.setattr(
        harbor_adapter.RemoteTerminalActor,
        "setup",
        setup_owned_snapshot_actor,
    )
    monkeypatch.setattr(
        harbor_adapter.RemoteTerminalActor,
        "exec_snapshot_owned",
        proven_snapshot_timeout,
    )
    proven_logs = tmp_path / "setup-proven-failure"
    proven_logs.mkdir()
    proven_agent = agent(proven_logs, Actor())
    proven_agent.session_id = "session-proven"
    proven_agent.context_id = "context-proven"
    proven_environment = SnapshotTimeoutEnvironment()

    asyncio.run(proven_agent.setup(proven_environment))
    asyncio.run(proven_agent.run("serve", object(), Context()))

    assert provider_calls == ["runtime-command", "provider"]
    assert proven_environment.preflight_calls == 1
    assert proven_environment.capture_calls == 1
    assert proven_environment.snapshot_cleanup_calls == 1
    assert proven_agent._before_snapshot is not None
    assert proven_agent._before_snapshot.status == "failed"
    assert proven_agent._before_snapshot.manifest is None
    assert proven_agent._before_snapshot.failure is not None
    assert proven_agent._before_snapshot.failure.stage == "remote-exec"
    assert proven_agent._before_snapshot.failure.category == "timeout"
    assert proven_agent._before_snapshot.failure.stage_validated is True
    assert proven_agent._before_snapshot.failure.termination_verified is True
    assert proven_agent._before_snapshot.failure.cleanup_verified is True
    assert proven_agent._before_snapshot.continuable is True
    proven_receipt = json.loads((proven_logs / "workspace-receipt.json").read_bytes())
    assert proven_receipt["failure"]["stage"] == "remote-exec"
    assert proven_receipt["failure"]["category"] == "timeout"
    assert proven_receipt["failure"]["attempt"] == 1


def test_harbor_adapter_keeps_root_deadline_across_17s_child_skew(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import ModuleType, SimpleNamespace

    for name in (
        "harbor",
        "harbor.agents",
        "harbor.agents.base",
        "harbor.environments",
        "harbor.environments.base",
        "harbor.models",
        "harbor.models.agent",
        "harbor.models.agent.context",
    ):
        module = ModuleType(name)
        if name.rsplit(".", 1)[-1] not in {"base", "context"}:
            module.__path__ = []
        monkeypatch.setitem(sys.modules, name, module)
    sys.modules["harbor.agents.base"].BaseAgent = object
    sys.modules["harbor.environments.base"].BaseEnvironment = object
    sys.modules["harbor.models.agent.context"].AgentContext = object
    monkeypatch.delitem(sys.modules, "nano_grok_build.adapter.harbor", raising=False)
    import nano_grok_build.adapter.harbor as harbor_adapter
    from nano_grok_build.adapter.deadline import RunDeadlineV1
    from nano_grok_build.harbor.deadline import mint_harbor_agent_phase

    logs = tmp_path / "agent"
    logs.mkdir()
    runtime_dir = logs / "runtime"
    observed: dict[str, object] = {}

    class Actor:
        async def background_manifest(self):
            return []

        @staticmethod
        def seal_process_lease_v1(rows):
            assert rows == []
            return ProcessLeaseV1(())

        async def cleanup_active(self):
            raise AssertionError("successful launch must not enter failure cleanup")

        @staticmethod
        def diagnostic_metadata():
            return {}

    class Context:
        @staticmethod
        def is_empty() -> bool:
            return True

    def command(**kwargs):
        observed["command"] = kwargs
        return ["synthetic-runtime"]

    async def bridge(*_args, **kwargs):
        observed["bridge"] = kwargs
        (runtime_dir / "run.json").write_bytes(b"{}\n")
        return BridgeOutcome(request_count=0, stderr=b"")

    async def after_snapshot(_target, _before):
        return SimpleNamespace(status="complete", code="completed")

    monkeypatch.setattr(harbor_adapter, "runtime_command", command)
    monkeypatch.setattr(harbor_adapter, "run_stdio_bridge", bridge)
    monkeypatch.setattr(harbor_adapter, "capture_after", after_snapshot)
    monkeypatch.setattr(
        harbor_adapter,
        "host_monotonic_ns",
        lambda: 27_000_000_000,
    )

    agent = object.__new__(harbor_adapter.NanoGrokBuildAgent)
    agent.logs_dir = logs
    agent._actor = Actor()
    agent._before_snapshot = object()
    agent._deadline_mode = harbor_adapter.DEADLINE_MODE_HARBOR_ROOT
    agent._run_spec = {
        "schema_version": "nano-run-spec-alpha-1",
        "run_id": "run-1",
        "trial_id": "trial-1",
        "attempt_id": "attempt-0",
        "task": {
            "id": "task",
            "digest": "a" * 64,
            "instruction": "serve",
        },
        "contract": {
            "id": "synthetic-v1",
            "contract_set_sha256": "b" * 64,
            "profile_id": "synthetic-profile-v1",
        },
        "provider": {
            "kind": "scripted",
            "model": "synthetic-model",
            "max_turns": 4,
            "retry_max": 0,
        },
        "workspace_dir": "/workspace",
        "artifact_dir": str(runtime_dir.resolve()),
        "agent_timeout_sec": 120,
    }
    agent._binary_path = Path("/synthetic/nano-cli")
    agent._contract_dir = Path("/synthetic/contract")
    agent._provider_launch = object()
    agent._instruction = None

    with pytest.raises(
        BridgeError,
        match="^deadline_contract_unavailable$",
    ):
        asyncio.run(agent.run("serve", object(), Context()))

    other_host_deadline = RunDeadlineV1.mint(
        source="another_host_phase",
        agent_timeout_ms=120_000,
        now_monotonic_ns=10_000_000_000,
    )
    with pytest.raises(BridgeError, match="^deadline_source_invalid$"):
        asyncio.run(
            agent.run_with_deadline(
                instruction="serve",
                environment=object(),
                context=Context(),
                deadline=other_host_deadline,
            )
        )

    deadline = mint_harbor_agent_phase(
        agent_timeout_ms=120_000,
        now_monotonic_ns=10_000_000_000,
    )
    asyncio.run(
        agent.run_with_deadline(
            instruction="serve",
            environment=object(),
            context=Context(),
            deadline=deadline,
        )
    )

    assert observed["command"]["deadline_monotonic_ns"] == 130_000_000_000
    assert observed["bridge"]["deadline_receipt"].deadline == deadline
    assert "deadline_sec" not in observed["bridge"]
    receipt = json.loads((runtime_dir / "deadline.json").read_bytes())
    assert receipt["deadline"] == deadline.as_dict()
    assert receipt["cutoffs"]["runtime_final_monotonic_ns"] == 95_000_000_000

    missing_logs = tmp_path / "missing-before"
    missing_logs.mkdir()
    missing = object.__new__(harbor_adapter.NanoGrokBuildAgent)
    missing.logs_dir = missing_logs
    missing._actor = Actor()
    missing._before_snapshot = None
    missing._deadline_mode = harbor_adapter.DEADLINE_MODE_HARBOR_ROOT
    missing._run_spec = dict(agent._run_spec)
    missing._run_spec["artifact_dir"] = str((missing_logs / "runtime").resolve())
    missing._binary_path = agent._binary_path
    missing._contract_dir = agent._contract_dir
    missing._provider_launch = agent._provider_launch
    missing._instruction = None

    async def capture_before_must_not_run(*_args, **_kwargs):
        raise AssertionError("live run must not recapture the before snapshot")

    async def finalize_without_io(**_kwargs):
        return None

    missing._finalize_handoff = finalize_without_io
    monkeypatch.setattr(
        harbor_adapter,
        "capture_before",
        capture_before_must_not_run,
    )
    with pytest.raises(
        BridgeError,
        match="^workspace_before_snapshot_unavailable$",
    ):
        asyncio.run(
            missing.run_with_deadline(
                instruction="serve",
                environment=object(),
                context=Context(),
                deadline=deadline,
            )
        )


def _load_harbor_adapter_for_workspace_receipt(
    monkeypatch: pytest.MonkeyPatch,
):
    import importlib
    from types import ModuleType

    for name in (
        "harbor",
        "harbor.agents",
        "harbor.agents.base",
        "harbor.environments",
        "harbor.environments.base",
        "harbor.models",
        "harbor.models.agent",
        "harbor.models.agent.context",
    ):
        module = ModuleType(name)
        if name.rsplit(".", 1)[-1] not in {"base", "context"}:
            module.__path__ = []
        monkeypatch.setitem(sys.modules, name, module)
    sys.modules["harbor.agents.base"].BaseAgent = object
    sys.modules["harbor.environments.base"].BaseEnvironment = object
    sys.modules["harbor.models.agent.context"].AgentContext = object
    monkeypatch.delitem(sys.modules, "nano_grok_build.adapter.harbor", raising=False)
    return importlib.import_module("nano_grok_build.adapter.harbor")


def test_workspace_receipt_projection_uses_shared_versioned_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nano_grok_build.adapter.workspace_snapshot as workspace_snapshot

    harbor_adapter = _load_harbor_adapter_for_workspace_receipt(monkeypatch)
    workspace = tmp_path / "workspace"
    logs = tmp_path / "agent"
    workspace.mkdir()
    logs.mkdir()

    class Actor:
        artifacts = logs

        def __init__(self) -> None:
            self.workspace = workspace

    actor = Actor()
    before = asyncio.run(
        workspace_snapshot.capture_before(actor, workspace_snapshot.SnapshotPolicy())
    )
    (workspace / "answer.txt").write_text("answer\n", encoding="utf-8")
    captured = asyncio.run(workspace_snapshot.capture_after(actor, before))
    calls: list[Path] = []
    real_loader = workspace_snapshot.load_workspace_receipt

    def observed_loader(path: Path):
        calls.append(path)
        return real_loader(path)

    monkeypatch.setattr(harbor_adapter, "load_workspace_receipt", observed_loader)
    agent = object.__new__(harbor_adapter.NanoGrokBuildAgent)
    agent.logs_dir = logs

    projected = agent._load_bound_workspace_receipt(captured)

    assert projected == captured
    assert projected is not captured
    assert calls == [logs / "workspace-receipt.json"]


def test_workspace_receipt_file_object_disagreement_is_fatal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nano_grok_build.adapter.workspace_snapshot as workspace_snapshot

    harbor_adapter = _load_harbor_adapter_for_workspace_receipt(monkeypatch)
    workspace = tmp_path / "workspace"
    logs = tmp_path / "agent"
    workspace.mkdir()
    logs.mkdir()

    class Actor:
        artifacts = logs

        def __init__(self) -> None:
            self.workspace = workspace

    actor = Actor()
    before = asyncio.run(
        workspace_snapshot.capture_before(actor, workspace_snapshot.SnapshotPolicy())
    )
    (workspace / "answer.txt").write_text("answer\n", encoding="utf-8")
    captured = asyncio.run(workspace_snapshot.capture_after(actor, before))
    disagreeing = replace(captured, status="failed")
    agent = object.__new__(harbor_adapter.NanoGrokBuildAgent)
    agent.logs_dir = logs

    with pytest.raises(
        BridgeError,
        match="^post_agent_workspace_receipt_binding_invalid$",
    ):
        agent._load_bound_workspace_receipt(disagreeing)

    from types import SimpleNamespace

    digest_only = SimpleNamespace(canonical_sha256=captured.canonical_sha256)
    with pytest.raises(
        BridgeError,
        match="^post_agent_workspace_receipt_binding_invalid$",
    ):
        agent._load_bound_workspace_receipt(digest_only)


def test_workspace_readiness_is_fixed_read_only_and_typed() -> None:
    calls: list[tuple[str, str | None, float | None]] = []

    class Environment:
        async def exec(self, command, *, cwd=None, timeout_sec=None):
            calls.append((command, cwd, timeout_sec))
            return type(
                "Result",
                (),
                {
                    "return_code": 0,
                    "stdout": "nano-workspace-ready-v1\n",
                    "stderr": "",
                },
            )()

    actor = RemoteTerminalActor(Environment())
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/task/workspace",
        "default_cwd": "/task/workspace",
        "logical_cwd": "/workspace",
        "mode": "existing_symlink",
    }
    proof = asyncio.run(
        actor.workspace_readiness_v1(
            hard_deadline_monotonic_ns=actor._monotonic_ns() + 5_000_000_000,
        )
    )

    assert type(proof) is WorkspaceReadinessV1
    assert proof == WorkspaceReadinessV1(
        canonical_workspace="/task/workspace",
        logical_workspace="/workspace",
        mapping_verified=True,
        environment_reachable=True,
        zero_owned_processes_verified=True,
    )
    assert len(calls) == 1
    command, cwd, timeout_sec = calls[0]
    assert "realpath -e -- /workspace" in command
    assert "test -d /workspace" in command
    assert cwd == "/task/workspace"
    assert timeout_sec is not None and 0 < timeout_sec <= 5


def test_verifier_opportunity_requires_runtime_receipt_result_and_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nano_grok_build.adapter.workspace_snapshot as workspace_snapshot
    from nano_grok_build.adapter.artifactizer import VerifierTerminalRuntimeV1

    harbor_adapter = _load_harbor_adapter_for_workspace_receipt(monkeypatch)
    workspace = tmp_path / "workspace"
    logs = tmp_path / "agent"
    workspace.mkdir()
    logs.mkdir()

    class CaptureActor:
        artifacts = logs

        def __init__(self) -> None:
            self.workspace = workspace

    capture_actor = CaptureActor()
    before = asyncio.run(
        workspace_snapshot.capture_before(
            capture_actor,
            workspace_snapshot.SnapshotPolicy(),
        )
    )
    (workspace / "answer.txt").write_text("answer\n", encoding="utf-8")
    receipt = asyncio.run(workspace_snapshot.capture_after(capture_actor, before))
    runtime = VerifierTerminalRuntimeV1(
        schema_version="nano-run-record-v3",
        run_id="run-1",
        trial_id="trial-1",
        attempt_id="attempt-0",
        run_spec_sha256="a" * 64,
        terminal_status="deadline_failure",
        terminal_phase="deadline",
        terminal_code="run_deadline_exceeded",
        run_record_sha256="b" * 64,
        events_sha256="c" * 64,
    )
    validation_calls: list[tuple[Path, object]] = []

    def validate(*, runtime_dir, run_spec):
        validation_calls.append((runtime_dir, run_spec))
        return runtime

    monkeypatch.setattr(
        harbor_adapter,
        "validate_verifier_terminal_runtime",
        validate,
    )

    class Actor:
        def __init__(self) -> None:
            self.cleanup_calls = 0
            self.readiness_calls = 0

        async def cleanup_active_until(self, _hard_deadline_monotonic_ns):
            self.cleanup_calls += 1
            return True

        async def workspace_readiness_v1(
            self,
            *,
            hard_deadline_monotonic_ns,
        ):
            assert hard_deadline_monotonic_ns > harbor_adapter.host_monotonic_ns()
            self.readiness_calls += 1
            return WorkspaceReadinessV1(
                canonical_workspace=str(workspace),
                logical_workspace="/workspace",
                mapping_verified=True,
                environment_reachable=True,
                zero_owned_processes_verified=True,
            )

    actor = Actor()
    agent = object.__new__(harbor_adapter.NanoGrokBuildAgent)
    agent.logs_dir = logs
    agent._run_spec = {"bound": True}
    agent._actor = actor
    hard_ns = harbor_adapter.host_monotonic_ns() + 5_000_000_000

    decision = asyncio.run(
        agent.verifier_opportunity_decision_v1(
            primary_error=RuntimeError("terminalized"),
            result_target=type("Target", (), {"agent_result": object()})(),
            workspace_receipt=receipt,
            hard_deadline_monotonic_ns=hard_ns,
        )
    )

    assert decision.eligible is True
    assert decision.runtime is runtime
    assert decision.workspace_receipt_sha256 == receipt.canonical_sha256
    assert decision.canonical_workspace == str(workspace)
    assert validation_calls == [(logs / "runtime", {"bound": True})]
    assert actor.cleanup_calls == 1
    assert actor.readiness_calls == 1

    denied = asyncio.run(
        agent.verifier_opportunity_decision_v1(
            primary_error=RuntimeError("terminalized"),
            result_target=type("Target", (), {"agent_result": None})(),
            workspace_receipt=receipt,
            hard_deadline_monotonic_ns=hard_ns,
        )
    )
    assert denied.eligible is False
    assert actor.cleanup_calls == 1

    denied = asyncio.run(
        agent.verifier_opportunity_decision_v1(
            primary_error=RuntimeError("terminalized"),
            result_target=type("Target", (), {"agent_result": object()})(),
            workspace_receipt=replace(receipt, status="failed"),
            hard_deadline_monotonic_ns=hard_ns,
        )
    )
    assert denied.eligible is False
    assert actor.cleanup_calls == 1
