"""Framework-neutral host-monotonic wall-budget contracts."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, ClassVar

_U64_MAX = 2**64 - 1
_NS_PER_MS = 1_000_000
_IDENTITY_MAX_UTF8_BYTES = 512


def host_monotonic_ns() -> int:
    """Read the CLOCK_MONOTONIC domain shared with the Rust runtime."""

    try:
        return time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    except (AttributeError, OSError, ValueError) as error:
        raise DeadlineContractError("deadline_clock_unavailable") from error


def host_monotonic() -> float:
    """CLOCK_MONOTONIC seconds for actor-relative timing."""

    try:
        return time.clock_gettime(time.CLOCK_MONOTONIC)
    except (AttributeError, OSError, ValueError) as error:
        raise DeadlineContractError("deadline_clock_unavailable") from error


class DeadlineContractError(ValueError):
    """The absolute wall-budget contract is missing, invalid, or exhausted."""


def _u64(value: object, code: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= _U64_MAX
    ):
        raise DeadlineContractError(code)
    return value


def _positive_u64(value: object, code: str) -> int:
    parsed = _u64(value, code)
    if parsed == 0:
        raise DeadlineContractError(code)
    return parsed


def _exact_mapping(
    value: object,
    fields: set[str],
    code: str,
) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise DeadlineContractError(code)
    return value


def _identity(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > _IDENTITY_MAX_UTF8_BYTES
    ):
        raise DeadlineContractError(code)
    return value


def _sha256(value: object, code: str) -> str:
    parsed = _identity(value, code)
    if len(parsed) != 64 or any(
        character not in "0123456789abcdef" for character in parsed
    ):
        raise DeadlineContractError(code)
    return parsed


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _strict_json_object(raw: bytes) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise DeadlineContractError("deadline_receipt_json_invalid")
            value[key] = item
        return value

    try:
        return json.loads(
            raw,
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                DeadlineContractError("deadline_receipt_json_invalid")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DeadlineContractError("deadline_receipt_json_invalid") from error


@dataclass(frozen=True)
class DeadlineReservesV1:
    """Frozen R4 C/F/P/S reserves, expressed in integer milliseconds."""

    cleanup_ms: int = 20_000
    terminalization_ms: int = 15_000
    provider_send_ms: int = 30_000
    process_settlement_ms: int = 10_000

    _FIELDS: ClassVar[set[str]] = {
        "cleanup_ms",
        "terminalization_ms",
        "provider_send_ms",
        "process_settlement_ms",
    }

    def __post_init__(self) -> None:
        for value in (
            self.cleanup_ms,
            self.terminalization_ms,
            self.provider_send_ms,
            self.process_settlement_ms,
        ):
            _positive_u64(value, "deadline_reserves_invalid")
        if self.total_ms > _U64_MAX // _NS_PER_MS:
            raise DeadlineContractError("deadline_reserves_invalid")

    @property
    def total_ms(self) -> int:
        return (
            self.cleanup_ms
            + self.terminalization_ms
            + self.provider_send_ms
            + self.process_settlement_ms
        )

    def as_dict(self) -> dict[str, int]:
        return {
            "cleanup_ms": self.cleanup_ms,
            "terminalization_ms": self.terminalization_ms,
            "provider_send_ms": self.provider_send_ms,
            "process_settlement_ms": self.process_settlement_ms,
        }

    @classmethod
    def from_value(cls, value: object) -> DeadlineReservesV1:
        parsed = _exact_mapping(
            value,
            cls._FIELDS,
            "deadline_reserve_fields_invalid",
        )
        return cls(
            cleanup_ms=_positive_u64(
                parsed["cleanup_ms"],
                "deadline_reserves_invalid",
            ),
            terminalization_ms=_positive_u64(
                parsed["terminalization_ms"],
                "deadline_reserves_invalid",
            ),
            provider_send_ms=_positive_u64(
                parsed["provider_send_ms"],
                "deadline_reserves_invalid",
            ),
            process_settlement_ms=_positive_u64(
                parsed["process_settlement_ms"],
                "deadline_reserves_invalid",
            ),
        )


@dataclass(frozen=True)
class DeadlineCutoffsV1:
    actor_done_monotonic_ns: int
    tool_settled_monotonic_ns: int
    last_send_monotonic_ns: int
    runtime_final_monotonic_ns: int
    cleanup_start_monotonic_ns: int
    hard_deadline_monotonic_ns: int

    _FIELDS: ClassVar[set[str]] = {
        "actor_done_monotonic_ns",
        "tool_settled_monotonic_ns",
        "last_send_monotonic_ns",
        "runtime_final_monotonic_ns",
        "cleanup_start_monotonic_ns",
        "hard_deadline_monotonic_ns",
    }

    def __post_init__(self) -> None:
        values = tuple(self.as_dict().values())
        for value in values:
            _positive_u64(value, "deadline_cutoffs_invalid")
        if values != tuple(sorted(values)):
            raise DeadlineContractError("deadline_cutoffs_invalid")
        if self.last_send_monotonic_ns != self.runtime_final_monotonic_ns:
            raise DeadlineContractError("deadline_cutoffs_invalid")

    def as_dict(self) -> dict[str, int]:
        return {
            "actor_done_monotonic_ns": self.actor_done_monotonic_ns,
            "tool_settled_monotonic_ns": self.tool_settled_monotonic_ns,
            "last_send_monotonic_ns": self.last_send_monotonic_ns,
            "runtime_final_monotonic_ns": self.runtime_final_monotonic_ns,
            "cleanup_start_monotonic_ns": self.cleanup_start_monotonic_ns,
            "hard_deadline_monotonic_ns": self.hard_deadline_monotonic_ns,
        }

    @classmethod
    def derive(
        cls,
        deadline: RunDeadlineV1,
        reserves: DeadlineReservesV1,
    ) -> DeadlineCutoffsV1:
        if deadline.agent_timeout_ms <= reserves.total_ms:
            raise DeadlineContractError("deadline_reserve_underflow")

        hard = deadline.hard_deadline_monotonic_ns

        def subtract(value: int, milliseconds: int) -> int:
            delta = milliseconds * _NS_PER_MS
            if value <= delta:
                raise DeadlineContractError("deadline_reserve_underflow")
            return value - delta

        cleanup_start = subtract(hard, reserves.cleanup_ms)
        runtime_final = subtract(cleanup_start, reserves.terminalization_ms)
        last_send = runtime_final
        tool_settled = subtract(last_send, reserves.provider_send_ms)
        actor_done = subtract(tool_settled, reserves.process_settlement_ms)
        return cls(
            actor_done_monotonic_ns=actor_done,
            tool_settled_monotonic_ns=tool_settled,
            last_send_monotonic_ns=last_send,
            runtime_final_monotonic_ns=runtime_final,
            cleanup_start_monotonic_ns=cleanup_start,
            hard_deadline_monotonic_ns=hard,
        )

    @classmethod
    def from_value(cls, value: object) -> DeadlineCutoffsV1:
        parsed = _exact_mapping(
            value,
            cls._FIELDS,
            "deadline_cutoff_fields_invalid",
        )
        return cls(
            **{
                field: _positive_u64(
                    parsed[field],
                    "deadline_cutoffs_invalid",
                )
                for field in cls._FIELDS
            }
        )


@dataclass(frozen=True)
class RunDeadlineV1:
    """An absolute deadline minted beside an integration's outer timeout."""

    hard_deadline_monotonic_ns: int
    source: str
    agent_timeout_ms: int

    SCHEMA_VERSION: ClassVar[str] = "nano-run-deadline-v1"
    _FIELDS: ClassVar[set[str]] = {
        "schema_version",
        "hard_deadline_monotonic_ns",
        "source",
        "agent_timeout_ms",
    }

    def __post_init__(self) -> None:
        _positive_u64(
            self.hard_deadline_monotonic_ns,
            "deadline_hard_cutoff_invalid",
        )
        _positive_u64(self.agent_timeout_ms, "deadline_timeout_invalid")
        _identity(self.source, "deadline_source_invalid")

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.SCHEMA_VERSION,
            "hard_deadline_monotonic_ns": self.hard_deadline_monotonic_ns,
            "source": self.source,
            "agent_timeout_ms": self.agent_timeout_ms,
        }

    @classmethod
    def mint(
        cls,
        *,
        source: str,
        agent_timeout_ms: int,
        now_monotonic_ns: int,
        reserves: DeadlineReservesV1 | None = None,
    ) -> RunDeadlineV1:
        timeout = _positive_u64(agent_timeout_ms, "deadline_timeout_invalid")
        now = _positive_u64(now_monotonic_ns, "deadline_clock_invalid")
        source = _identity(source, "deadline_source_invalid")
        selected_reserves = reserves or DeadlineReservesV1()
        if timeout <= selected_reserves.total_ms:
            raise DeadlineContractError("deadline_reserve_underflow")
        if timeout > (_U64_MAX - now) // _NS_PER_MS:
            raise DeadlineContractError("deadline_clock_overflow")
        return cls(
            hard_deadline_monotonic_ns=now + timeout * _NS_PER_MS,
            source=source,
            agent_timeout_ms=timeout,
        )

    @classmethod
    def from_value(cls, value: object) -> RunDeadlineV1:
        parsed = _exact_mapping(
            value,
            cls._FIELDS,
            "deadline_fields_invalid",
        )
        if parsed["schema_version"] != cls.SCHEMA_VERSION:
            raise DeadlineContractError("deadline_schema_invalid")
        return cls(
            hard_deadline_monotonic_ns=_positive_u64(
                parsed["hard_deadline_monotonic_ns"],
                "deadline_hard_cutoff_invalid",
            ),
            source=_identity(parsed["source"], "deadline_source_invalid"),
            agent_timeout_ms=_positive_u64(
                parsed["agent_timeout_ms"],
                "deadline_timeout_invalid",
            ),
        )


@dataclass(frozen=True)
class RunDeadlineReceiptV1:
    """Hashable immutable launch receipt binding deadline, identity, and reserves."""

    run_id: str
    trial_id: str
    attempt_id: str
    run_spec_sha256: str
    deadline: RunDeadlineV1
    reserves: DeadlineReservesV1
    cutoffs: DeadlineCutoffsV1

    SCHEMA_VERSION: ClassVar[str] = "nano-run-deadline-receipt-v1"
    _FIELDS: ClassVar[set[str]] = {
        "schema_version",
        "run_id",
        "trial_id",
        "attempt_id",
        "run_spec_sha256",
        "deadline",
        "reserves",
        "cutoffs",
    }

    def __post_init__(self) -> None:
        _identity(self.run_id, "deadline_run_id_invalid")
        _identity(self.trial_id, "deadline_trial_id_invalid")
        _identity(self.attempt_id, "deadline_attempt_id_invalid")
        _sha256(self.run_spec_sha256, "deadline_run_spec_sha256_invalid")
        expected = DeadlineCutoffsV1.derive(self.deadline, self.reserves)
        if self.cutoffs != expected:
            raise DeadlineContractError("deadline_cutoffs_binding_invalid")

    @classmethod
    def bind(
        cls,
        *,
        deadline: RunDeadlineV1,
        run_id: str,
        trial_id: str,
        attempt_id: str,
        run_spec_sha256: str,
        reserves: DeadlineReservesV1 | None = None,
    ) -> RunDeadlineReceiptV1:
        selected = reserves or DeadlineReservesV1()
        return cls(
            run_id=run_id,
            trial_id=trial_id,
            attempt_id=attempt_id,
            run_spec_sha256=run_spec_sha256,
            deadline=deadline,
            reserves=selected,
            cutoffs=DeadlineCutoffsV1.derive(deadline, selected),
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.SCHEMA_VERSION,
            "run_id": self.run_id,
            "trial_id": self.trial_id,
            "attempt_id": self.attempt_id,
            "run_spec_sha256": self.run_spec_sha256,
            "deadline": self.deadline.as_dict(),
            "reserves": self.reserves.as_dict(),
            "cutoffs": self.cutoffs.as_dict(),
        }

    def to_bytes(self) -> bytes:
        return _canonical_json(self.as_dict())

    def sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_value(cls, value: object) -> RunDeadlineReceiptV1:
        parsed = _exact_mapping(
            value,
            cls._FIELDS,
            "deadline_receipt_fields_invalid",
        )
        if parsed["schema_version"] != cls.SCHEMA_VERSION:
            raise DeadlineContractError("deadline_receipt_schema_invalid")
        return cls(
            run_id=_identity(parsed["run_id"], "deadline_run_id_invalid"),
            trial_id=_identity(parsed["trial_id"], "deadline_trial_id_invalid"),
            attempt_id=_identity(
                parsed["attempt_id"],
                "deadline_attempt_id_invalid",
            ),
            run_spec_sha256=_sha256(
                parsed["run_spec_sha256"],
                "deadline_run_spec_sha256_invalid",
            ),
            deadline=RunDeadlineV1.from_value(parsed["deadline"]),
            reserves=DeadlineReservesV1.from_value(parsed["reserves"]),
            cutoffs=DeadlineCutoffsV1.from_value(parsed["cutoffs"]),
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> RunDeadlineReceiptV1:
        if not isinstance(raw, bytes):
            raise DeadlineContractError("deadline_receipt_json_invalid")
        return cls.from_value(_strict_json_object(raw))
