"""Durable, identity-bound proof of whether the nano runtime launch was entered."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nano_grok_build.adapter.artifactizer import canonical_json, rust_run_spec_sha256

RUNTIME_ENTRY_NAME = "runtime-entry.json"
RUNTIME_ENTRY_SCHEMA = "nano-runtime-entry-v1"
_MAX_BYTES = 16 * 1024
_FACT_KEYS = {
    "schema_version",
    "state",
    "run_id",
    "trial_id",
    "attempt_id",
    "run_spec_sha256",
    "terminalization_path",
    "terminalization_sha256",
    "terminal_code",
}
_EMERGENCY_KEYS = {
    "schema_version",
    "run_id",
    "trial_id",
    "attempt_id",
    "run_spec_sha256",
    "status",
    "code",
    "bridge_completed",
    "events_sha256",
    "events_byte_length",
}
_HEX = frozenset("0123456789abcdef")


class RuntimeEntryError(RuntimeError):
    """The durable runtime-entry evidence is absent, ambiguous, or invalid."""


@dataclass(frozen=True)
class RuntimeEntryFact:
    schema_version: str
    state: str
    run_id: str
    trial_id: str
    attempt_id: str
    run_spec_sha256: str
    terminalization_path: str | None
    terminalization_sha256: str | None
    terminal_code: str | None

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "state": self.state,
            "run_id": self.run_id,
            "trial_id": self.trial_id,
            "attempt_id": self.attempt_id,
            "run_spec_sha256": self.run_spec_sha256,
            "terminalization_path": self.terminalization_path,
            "terminalization_sha256": self.terminalization_sha256,
            "terminal_code": self.terminal_code,
        }


def _sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _read_regular(path: Path) -> bytes:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_BYTES:
            raise RuntimeEntryError("runtime_entry_invalid")
        raw = os.read(descriptor, _MAX_BYTES + 1)
        after = os.fstat(descriptor)
        named = path.lstat()
        identity = lambda item: (  # noqa: E731 - compact immutable identity
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if (
            len(raw) != before.st_size
            or identity(before) != identity(after)
            or identity(after) != identity(named)
        ):
            raise RuntimeEntryError("runtime_entry_invalid")
        return raw
    except RuntimeEntryError:
        raise
    except OSError as error:
        raise RuntimeEntryError("runtime_entry_invalid") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _load_canonical(path: Path) -> tuple[Mapping[str, object], bytes]:
    raw = _read_regular(path)
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
    ) as error:
        raise RuntimeEntryError("runtime_entry_invalid") from error
    if not isinstance(value, dict) or raw != canonical_json(value):
        raise RuntimeEntryError("runtime_entry_invalid")
    return value, raw


def _identity(spec: Mapping[str, object]) -> dict[str, str]:
    try:
        values = {
            "run_id": spec["run_id"],
            "trial_id": spec["trial_id"],
            "attempt_id": spec["attempt_id"],
            "run_spec_sha256": rust_run_spec_sha256(spec),
        }
    except (KeyError, TypeError, ValueError) as error:
        raise RuntimeEntryError("runtime_entry_invalid") from error
    if not all(isinstance(value, str) and value for value in values.values()):
        raise RuntimeEntryError("runtime_entry_invalid")
    return values  # type: ignore[return-value]


def _write_exclusive(path: Path, payload: bytes) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError as error:
        raise RuntimeEntryError("runtime_entry_exists") from error
    except OSError as error:
        raise RuntimeEntryError("runtime_entry_write_failed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _fact(
    spec: Mapping[str, object],
    *,
    state: str,
    terminalization_path: str | None,
    terminalization_sha256: str | None,
    terminal_code: str | None,
) -> RuntimeEntryFact:
    return RuntimeEntryFact(
        schema_version=RUNTIME_ENTRY_SCHEMA,
        state=state,
        **_identity(spec),
        terminalization_path=terminalization_path,
        terminalization_sha256=terminalization_sha256,
        terminal_code=terminal_code,
    )


def write_started(root: Path, spec: Mapping[str, object]) -> RuntimeEntryFact:
    """Persist and fsync ``started`` immediately before irreversible launch."""

    fact = _fact(
        spec,
        state="started",
        terminalization_path=None,
        terminalization_sha256=None,
        terminal_code=None,
    )
    _write_exclusive(root / RUNTIME_ENTRY_NAME, canonical_json(fact.as_dict()))
    return fact


def write_not_started(
    root: Path,
    spec: Mapping[str, object],
    *,
    terminalization_path: Path,
    terminal_code: str,
) -> RuntimeEntryFact:
    """Persist a pre-launch failure bound to its durable terminalization."""

    terminal, terminal_raw = _load_canonical(terminalization_path)
    identity = _identity(spec)
    if (
        set(terminal) != _EMERGENCY_KEYS
        or terminal.get("schema_version") != "nano-runtime-emergency-v1"
        or any(terminal.get(key) != value for key, value in identity.items())
        or terminal.get("status") != "runtime_record_missing"
        or terminal.get("bridge_completed") is not False
        or terminal.get("code") != terminal_code
        or not isinstance(terminal_code, str)
        or not terminal_code
        or terminalization_path.parent.resolve() != root.resolve()
        or terminalization_path.name != "runtime-emergency.json"
    ):
        raise RuntimeEntryError("runtime_entry_invalid")
    fact = _fact(
        spec,
        state="not_started",
        terminalization_path=terminalization_path.name,
        terminalization_sha256=hashlib.sha256(terminal_raw).hexdigest(),
        terminal_code=terminal_code,
    )
    _write_exclusive(root / RUNTIME_ENTRY_NAME, canonical_json(fact.as_dict()))
    return fact


def load_runtime_entry(
    path: Path,
    spec: Mapping[str, object],
) -> RuntimeEntryFact | None:
    """Load alpha-2 evidence; preserve alpha-1 as receipt-free read compatibility."""

    if spec.get("schema_version") == "nano-run-spec-alpha-1":
        return None
    if spec.get("schema_version") != "nano-run-spec-alpha-2":
        raise RuntimeEntryError("runtime_entry_invalid")
    value, _raw = _load_canonical(path)
    identity = _identity(spec)
    if (
        set(value) != _FACT_KEYS
        or value.get("schema_version") != RUNTIME_ENTRY_SCHEMA
        or any(value.get(key) != expected for key, expected in identity.items())
    ):
        raise RuntimeEntryError("runtime_entry_invalid")
    state = value.get("state")
    terminalization_path = value.get("terminalization_path")
    terminalization_sha256 = value.get("terminalization_sha256")
    terminal_code = value.get("terminal_code")
    if state == "started":
        if any(
            item is not None
            for item in (terminalization_path, terminalization_sha256, terminal_code)
        ):
            raise RuntimeEntryError("runtime_entry_invalid")
    elif state == "not_started":
        if (
            terminalization_path != "runtime-emergency.json"
            or not _sha256(terminalization_sha256)
            or not isinstance(terminal_code, str)
            or not terminal_code
        ):
            raise RuntimeEntryError("runtime_entry_invalid")
        terminal, terminal_raw = _load_canonical(path.parent / terminalization_path)
        if (
            set(terminal) != _EMERGENCY_KEYS
            or terminal.get("schema_version") != "nano-runtime-emergency-v1"
            or any(terminal.get(key) != expected for key, expected in identity.items())
            or terminal.get("status") != "runtime_record_missing"
            or terminal.get("bridge_completed") is not False
            or terminal.get("code") != terminal_code
            or hashlib.sha256(terminal_raw).hexdigest() != terminalization_sha256
        ):
            raise RuntimeEntryError("runtime_entry_invalid")
    else:
        raise RuntimeEntryError("runtime_entry_invalid")
    return RuntimeEntryFact(
        schema_version=RUNTIME_ENTRY_SCHEMA,
        state=str(state),
        **identity,
        terminalization_path=(
            str(terminalization_path) if terminalization_path is not None else None
        ),
        terminalization_sha256=(
            str(terminalization_sha256) if terminalization_sha256 is not None else None
        ),
        terminal_code=str(terminal_code) if terminal_code is not None else None,
    )
