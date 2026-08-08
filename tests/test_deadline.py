from __future__ import annotations

import json

import pytest

from nano_grok_build.adapter.deadline import (
    DeadlineContractError,
    DeadlineReservesV1,
    RunDeadlineReceiptV1,
    RunDeadlineV1,
)
from nano_grok_build.harbor.provider import (
    COMPLETION_REVIEW_POLICY,
    HostProviderLaunch,
    runtime_command,
)


def test_root_absolute_deadline_derives_one_ordered_cutoff_chain() -> None:
    deadline = RunDeadlineV1.mint(
        source="test_host_phase",
        agent_timeout_ms=120_000,
        now_monotonic_ns=10_000_000_000,
    )
    receipt = RunDeadlineReceiptV1.bind(
        deadline=deadline,
        run_id="run-1",
        trial_id="trial-1",
        attempt_id="attempt-0",
        run_spec_sha256="a" * 64,
        reserves=DeadlineReservesV1(),
    )

    assert deadline.hard_deadline_monotonic_ns == 130_000_000_000
    assert receipt.cutoffs.as_dict() == {
        "actor_done_monotonic_ns": 55_000_000_000,
        "tool_settled_monotonic_ns": 65_000_000_000,
        "last_send_monotonic_ns": 95_000_000_000,
        "runtime_final_monotonic_ns": 95_000_000_000,
        "cleanup_start_monotonic_ns": 110_000_000_000,
        "hard_deadline_monotonic_ns": 130_000_000_000,
    }
    assert list(receipt.cutoffs.as_dict().values()) == sorted(
        receipt.cutoffs.as_dict().values()
    )


def test_deadline_receipt_is_canonical_round_trippable_and_exact_keyed() -> None:
    deadline = RunDeadlineV1.mint(
        source="test_host_phase",
        agent_timeout_ms=95_000,
        now_monotonic_ns=1_000_000_000,
    )
    receipt = RunDeadlineReceiptV1.bind(
        deadline=deadline,
        run_id="run-1",
        trial_id="trial-1",
        attempt_id="attempt-0",
        run_spec_sha256="b" * 64,
    )

    encoded = receipt.to_bytes()
    assert encoded.endswith(b"\n")
    assert receipt == RunDeadlineReceiptV1.from_bytes(encoded)
    assert encoded == receipt.to_bytes()

    value = json.loads(encoded)
    value["unexpected"] = True
    with pytest.raises(
        DeadlineContractError,
        match="^deadline_receipt_fields_invalid$",
    ):
        RunDeadlineReceiptV1.from_value(value)

    tampered = json.loads(encoded)
    tampered["cutoffs"]["actor_done_monotonic_ns"] += 1
    with pytest.raises(
        DeadlineContractError,
        match="^deadline_cutoffs_binding_invalid$",
    ):
        RunDeadlineReceiptV1.from_value(tampered)

    duplicate_run_id = b'{"run_id":"replayed",' + encoded[1:]
    with pytest.raises(
        DeadlineContractError,
        match="^deadline_receipt_json_invalid$",
    ):
        RunDeadlineReceiptV1.from_bytes(duplicate_run_id)


@pytest.mark.parametrize("agent_timeout_ms", [1, 74_999, 75_000])
def test_deadline_reserve_underflow_fails_before_dispatch(
    agent_timeout_ms: int,
) -> None:
    with pytest.raises(
        DeadlineContractError,
        match="^deadline_reserve_underflow$",
    ):
        RunDeadlineV1.mint(
            source="test_host_phase",
            agent_timeout_ms=agent_timeout_ms,
            now_monotonic_ns=1_000_000_000,
        )


def test_deadline_rejects_bool_overflow_and_invalid_source() -> None:
    for timeout in (True, 2**64):
        with pytest.raises(DeadlineContractError):
            RunDeadlineV1.mint(
                source="test_host_phase",
                agent_timeout_ms=timeout,
                now_monotonic_ns=1,
            )

    generic = RunDeadlineV1.from_value(
        {
            "schema_version": "nano-run-deadline-v1",
            "hard_deadline_monotonic_ns": 120_000_000_000,
            "source": "another_host_entry",
            "agent_timeout_ms": 120_000,
        }
    )
    assert generic.source == "another_host_entry"

    for invalid_source in ("", "x" * 513):
        with pytest.raises(
            DeadlineContractError,
            match="^deadline_source_invalid$",
        ):
            RunDeadlineV1.from_value(
                {
                    "schema_version": "nano-run-deadline-v1",
                    "hard_deadline_monotonic_ns": 120_000_000_000,
                    "source": invalid_source,
                    "agent_timeout_ms": 120_000,
                }
            )


def test_runtime_command_propagates_only_a_valid_absolute_deadline(
    tmp_path,
) -> None:
    command = runtime_command(
        binary_path=tmp_path / "nano-cli",
        spec_path=tmp_path / "run-spec.json",
        contract_dir=tmp_path / "contract",
        provider=HostProviderLaunch.xai(),
        deadline_monotonic_ns=130_000_000_000,
    )
    index = command.index("--deadline-monotonic-ns")
    assert command[index + 1] == "130000000000"
    review_index = command.index("--completion-review")
    assert COMPLETION_REVIEW_POLICY == "semantic-checkpoint-v6"
    assert command[review_index + 1] == COMPLETION_REVIEW_POLICY
    assert command[-3:] == ("xai", "--executor", "external-stdio")

    for invalid in (True, 0, -1, 2**64):
        with pytest.raises(ValueError, match="^runtime deadline is invalid$"):
            runtime_command(
                binary_path=tmp_path / "nano-cli",
                spec_path=tmp_path / "run-spec.json",
                contract_dir=tmp_path / "contract",
                provider=HostProviderLaunch.xai(),
                deadline_monotonic_ns=invalid,
            )
