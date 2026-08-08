"""Harbor-specific binding for the framework-neutral deadline contract."""

from __future__ import annotations

from nano_grok_build.adapter.deadline import (
    DeadlineContractError,
    DeadlineReservesV1,
    RunDeadlineV1,
)

DEADLINE_MODE_HARBOR_ROOT = "harbor-root-v1"
HARBOR_AGENT_PHASE_DEADLINE_SOURCE = "harbor_agent_phase"


def mint_harbor_agent_phase(
    *,
    agent_timeout_ms: int,
    now_monotonic_ns: int,
    reserves: DeadlineReservesV1 | None = None,
) -> RunDeadlineV1:
    """Mint the generic deadline at Harbor's outer agent-phase timeout."""

    return RunDeadlineV1.mint(
        source=HARBOR_AGENT_PHASE_DEADLINE_SOURCE,
        agent_timeout_ms=agent_timeout_ms,
        now_monotonic_ns=now_monotonic_ns,
        reserves=reserves,
    )


def require_harbor_agent_phase(deadline: RunDeadlineV1) -> None:
    """Reject a generic receipt that was not minted by the Harbor seam."""

    if deadline.source != HARBOR_AGENT_PHASE_DEADLINE_SOURCE:
        raise DeadlineContractError("deadline_source_invalid")
