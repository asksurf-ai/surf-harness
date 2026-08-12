"""Typed, immutable process-closure evidence for verifier admission."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum

_HEX = frozenset("0123456789abcdef")


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX


def _is_optional_sha256(value: object) -> bool:
    return value is None or _is_sha256(value)


def _bounded_identity(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and "\x00" not in value
        and len(value.encode("utf-8")) <= 1024
    )


class HandlerCompletionStateV1(str, Enum):
    """Whether the dispatched actor handler acknowledged terminal completion."""

    COMPLETED = "completed"
    SETTLEMENT_DEADLINE = "settlement_deadline"
    UNVERIFIED = "unverified"


class ActorDispatchStateV1(str, Enum):
    """Whether the actor can still issue work for the settled request."""

    REVOKED = "revoked"
    UNVERIFIED = "unverified"


class BackgroundLeaseStateV1(str, Enum):
    """State of the exact background process lease at actor handoff."""

    EMPTY = "empty"
    SEALED_RETAINED = "sealed_retained"
    UNVERIFIED = "unverified"


@dataclass(frozen=True)
class RuntimeCleanupReceiptV1:
    """One immutable receipt binding closure facts to the post-quiescence snapshot."""

    run_id: str
    trial_id: str
    attempt_id: str
    run_spec_sha256: str
    runtime_run_sha256: str
    runtime_events_sha256: str
    git_baseline_sha256: str
    git_exposure_sha256: str
    process_lease_sha256: str | None
    background_manifest_sha256: str | None
    workspace_after_sha256: str | None
    handler_completion: HandlerCompletionStateV1
    actor_dispatch: ActorDispatchStateV1
    actor_quiescent: bool
    remote_census_verified: bool
    remote_survivor_count: int | None
    process_lease_sealed: bool
    background_state: BackgroundLeaseStateV1
    stdio_bridge_closed: bool
    runtime_child_closed: bool
    snapshot_after_quiescence: bool

    @property
    def verifier_permitted(self) -> bool:
        """Derive permission; handler acknowledgement remains diagnostic."""

        return (
            self.actor_dispatch is ActorDispatchStateV1.REVOKED
            and self.actor_quiescent
            and self.remote_census_verified
            and self.remote_survivor_count == 0
            and self.process_lease_sealed
            and self.background_state
            in {BackgroundLeaseStateV1.EMPTY, BackgroundLeaseStateV1.SEALED_RETAINED}
            and self.stdio_bridge_closed
            and self.runtime_child_closed
            and self.snapshot_after_quiescence
            and _is_sha256(self.workspace_after_sha256)
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "runtime-cleanup-closure-v1",
            "bindings": {
                "run_id": self.run_id,
                "trial_id": self.trial_id,
                "attempt_id": self.attempt_id,
                "run_spec_sha256": self.run_spec_sha256,
                "runtime_run_sha256": self.runtime_run_sha256,
                "runtime_events_sha256": self.runtime_events_sha256,
                "git_baseline_sha256": self.git_baseline_sha256,
                "git_exposure_sha256": self.git_exposure_sha256,
                "process_lease_sha256": self.process_lease_sha256,
                "background_manifest_sha256": self.background_manifest_sha256,
                "workspace_after_sha256": self.workspace_after_sha256,
            },
            "axes": {
                "handler_completion": self.handler_completion.value,
                "actor_dispatch": self.actor_dispatch.value,
                "actor_quiescent": self.actor_quiescent,
                "remote_census_verified": self.remote_census_verified,
                "remote_survivor_count": self.remote_survivor_count,
                "process_lease_sealed": self.process_lease_sealed,
                "background_state": self.background_state.value,
                "stdio_bridge_closed": self.stdio_bridge_closed,
                "runtime_child_closed": self.runtime_child_closed,
                "snapshot_after_quiescence": self.snapshot_after_quiescence,
            },
            "verifier_permitted": self.verifier_permitted,
        }

    def to_bytes(self) -> bytes:
        return (
            json.dumps(
                self.to_dict(),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")

    @classmethod
    def from_bytes(cls, raw: bytes) -> RuntimeCleanupReceiptV1:
        try:
            value = json.loads(raw)
            if raw != (
                json.dumps(
                    value,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                + "\n"
            ).encode("utf-8"):
                raise ValueError
            if type(value) is not dict or set(value) != {
                "schema_version",
                "bindings",
                "axes",
                "verifier_permitted",
            }:
                raise ValueError
            if value["schema_version"] != "runtime-cleanup-closure-v1":
                raise ValueError
            bindings = value["bindings"]
            axes = value["axes"]
            if type(bindings) is not dict or set(bindings) != {
                "run_id",
                "trial_id",
                "attempt_id",
                "run_spec_sha256",
                "runtime_run_sha256",
                "runtime_events_sha256",
                "git_baseline_sha256",
                "git_exposure_sha256",
                "process_lease_sha256",
                "background_manifest_sha256",
                "workspace_after_sha256",
            }:
                raise ValueError
            if type(axes) is not dict or set(axes) != {
                "handler_completion",
                "actor_dispatch",
                "actor_quiescent",
                "remote_census_verified",
                "remote_survivor_count",
                "process_lease_sealed",
                "background_state",
                "stdio_bridge_closed",
                "runtime_child_closed",
                "snapshot_after_quiescence",
            }:
                raise ValueError
            receipt = cls(
                **bindings,
                handler_completion=HandlerCompletionStateV1(axes["handler_completion"]),
                actor_dispatch=ActorDispatchStateV1(axes["actor_dispatch"]),
                actor_quiescent=axes["actor_quiescent"],
                remote_census_verified=axes["remote_census_verified"],
                remote_survivor_count=axes["remote_survivor_count"],
                process_lease_sealed=axes["process_lease_sealed"],
                background_state=BackgroundLeaseStateV1(axes["background_state"]),
                stdio_bridge_closed=axes["stdio_bridge_closed"],
                runtime_child_closed=axes["runtime_child_closed"],
                snapshot_after_quiescence=axes["snapshot_after_quiescence"],
            )
            facts = RuntimeCleanupFactsV1(
                run_id=receipt.run_id,
                trial_id=receipt.trial_id,
                attempt_id=receipt.attempt_id,
                run_spec_sha256=receipt.run_spec_sha256,
                runtime_run_sha256=receipt.runtime_run_sha256,
                runtime_events_sha256=receipt.runtime_events_sha256,
                git_baseline_sha256=receipt.git_baseline_sha256,
                git_exposure_sha256=receipt.git_exposure_sha256,
                process_lease_sha256=receipt.process_lease_sha256,
                background_manifest_sha256=receipt.background_manifest_sha256,
                handler_completion=receipt.handler_completion,
                actor_dispatch=receipt.actor_dispatch,
                actor_quiescent=receipt.actor_quiescent,
                remote_census_verified=receipt.remote_census_verified,
                remote_survivor_count=receipt.remote_survivor_count,
                process_lease_sealed=receipt.process_lease_sealed,
                background_state=receipt.background_state,
                stdio_bridge_closed=receipt.stdio_bridge_closed,
                runtime_child_closed=receipt.runtime_child_closed,
            )
            expected = facts.finalize(
                workspace_after_sha256=receipt.workspace_after_sha256
            )
            if (
                expected != receipt
                or value["verifier_permitted"] is not receipt.verifier_permitted
            ):
                raise ValueError
        except (
            KeyError,
            TypeError,
            ValueError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as error:
            raise ValueError("runtime_cleanup_receipt_invalid") from error
        return receipt


@dataclass(frozen=True)
class RuntimeCleanupFactsV1:
    """Closure facts collected by the single runtime cleanup coordinator."""

    run_id: str
    trial_id: str
    attempt_id: str
    run_spec_sha256: str
    runtime_run_sha256: str
    runtime_events_sha256: str
    git_baseline_sha256: str
    git_exposure_sha256: str
    process_lease_sha256: str | None
    background_manifest_sha256: str | None
    handler_completion: HandlerCompletionStateV1
    actor_dispatch: ActorDispatchStateV1
    actor_quiescent: bool
    remote_census_verified: bool
    remote_survivor_count: int | None
    process_lease_sealed: bool
    background_state: BackgroundLeaseStateV1
    stdio_bridge_closed: bool
    runtime_child_closed: bool

    def __post_init__(self) -> None:
        if not all(
            _bounded_identity(value)
            for value in (self.run_id, self.trial_id, self.attempt_id)
        ):
            raise ValueError("runtime_cleanup_identity_invalid")
        if not all(
            _is_optional_sha256(value)
            for value in (
                self.run_spec_sha256,
                self.runtime_run_sha256,
                self.runtime_events_sha256,
                self.git_baseline_sha256,
                self.git_exposure_sha256,
                self.process_lease_sha256,
                self.background_manifest_sha256,
            )
        ):
            raise ValueError("runtime_cleanup_binding_invalid")
        if not all(
            _is_sha256(value)
            for value in (
                self.run_spec_sha256,
                self.runtime_run_sha256,
                self.runtime_events_sha256,
                self.git_baseline_sha256,
                self.git_exposure_sha256,
            )
        ):
            raise ValueError("runtime_cleanup_required_binding_invalid")
        if type(self.handler_completion) is not HandlerCompletionStateV1:
            raise ValueError("runtime_cleanup_handler_state_invalid")
        if type(self.actor_dispatch) is not ActorDispatchStateV1:
            raise ValueError("runtime_cleanup_dispatch_state_invalid")
        if any(
            type(value) is not bool
            for value in (
                self.actor_quiescent,
                self.remote_census_verified,
                self.process_lease_sealed,
                self.stdio_bridge_closed,
                self.runtime_child_closed,
            )
        ):
            raise ValueError("runtime_cleanup_axis_invalid")
        if type(self.background_state) is not BackgroundLeaseStateV1:
            raise ValueError("runtime_cleanup_background_state_invalid")
        if self.remote_survivor_count is not None and (
            type(self.remote_survivor_count) is not int
            or self.remote_survivor_count < 0
        ):
            raise ValueError("runtime_cleanup_survivor_count_invalid")

    @property
    def quiescence_proven(self) -> bool:
        return (
            self.actor_dispatch is ActorDispatchStateV1.REVOKED
            and self.actor_quiescent
            and self.remote_census_verified
            and self.remote_survivor_count == 0
            and self.process_lease_sealed
            and _is_sha256(self.process_lease_sha256)
            and _is_sha256(self.background_manifest_sha256)
            and self.background_state
            in {BackgroundLeaseStateV1.EMPTY, BackgroundLeaseStateV1.SEALED_RETAINED}
            and self.stdio_bridge_closed
            and self.runtime_child_closed
        )

    def finalize(
        self,
        *,
        workspace_after_sha256: str | None,
    ) -> RuntimeCleanupReceiptV1:
        if workspace_after_sha256 is not None and not _is_sha256(
            workspace_after_sha256
        ):
            raise ValueError("runtime_cleanup_workspace_binding_invalid")
        if workspace_after_sha256 is not None and not self.quiescence_proven:
            raise ValueError("runtime_cleanup_snapshot_before_quiescence")
        return RuntimeCleanupReceiptV1(
            **self.__dict__,
            workspace_after_sha256=workspace_after_sha256,
            snapshot_after_quiescence=(
                workspace_after_sha256 is not None and self.quiescence_proven
            ),
        )
