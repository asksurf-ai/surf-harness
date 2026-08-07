"""Typed host-only provider selection for the Harbor adapter."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

COMPLETION_REVIEW_POLICY = "fresh-evidence-debt-v3"


class HostProviderKind(StrEnum):
    SCRIPTED = "scripted"
    XAI = "xai"


@dataclass(frozen=True)
class HostProviderLaunch:
    """A provider selector containing paths only, never provider credentials."""

    kind: HostProviderKind
    script_path: Path | None = None

    def __post_init__(self) -> None:
        if self.kind is HostProviderKind.SCRIPTED:
            if self.script_path is None or not self.script_path.is_absolute():
                raise ValueError("scripted provider requires an absolute script path")
        elif self.kind is HostProviderKind.XAI:
            if self.script_path is not None:
                raise ValueError("xai provider cannot have a script path")
        else:
            raise ValueError("unsupported host provider")

    @classmethod
    def scripted(cls, script_path: Path) -> HostProviderLaunch:
        return cls(HostProviderKind.SCRIPTED, script_path)

    @classmethod
    def xai(cls) -> HostProviderLaunch:
        return cls(HostProviderKind.XAI)

    @classmethod
    def from_config(cls, value: object) -> HostProviderLaunch:
        if not isinstance(value, dict) or set(value) not in (
            {"kind"},
            {"kind", "script_path"},
        ):
            raise ValueError("provider launch fields are invalid")
        if value["kind"] == HostProviderKind.XAI.value and set(value) == {"kind"}:
            return cls.xai()
        if (
            value["kind"] == HostProviderKind.SCRIPTED.value
            and set(value) == {"kind", "script_path"}
            and isinstance(value["script_path"], str)
        ):
            return cls.scripted(Path(value["script_path"]))
        raise ValueError("provider launch is invalid")

    def to_config(self) -> dict[str, Any]:
        if self.kind is HostProviderKind.XAI:
            return {"kind": self.kind.value}
        assert self.script_path is not None
        return {
            "kind": self.kind.value,
            "script_path": str(self.script_path),
        }

    def cli_selector(self) -> str:
        if self.kind is HostProviderKind.XAI:
            return "xai"
        assert self.script_path is not None
        return f"scripted:{self.script_path}"


def runtime_command(
    *,
    binary_path: Path,
    spec_path: Path,
    contract_dir: Path,
    provider: HostProviderLaunch,
    deadline_monotonic_ns: int | None = None,
) -> tuple[str, ...]:
    """Build the exact non-secret host command used by dry-run and execution."""

    if isinstance(deadline_monotonic_ns, bool) or (
        deadline_monotonic_ns is not None
        and (
            not isinstance(deadline_monotonic_ns, int)
            or not 0 < deadline_monotonic_ns <= 2**64 - 1
        )
    ):
        raise ValueError("runtime deadline is invalid")
    deadline_arguments = (
        ()
        if deadline_monotonic_ns is None
        else ("--deadline-monotonic-ns", str(deadline_monotonic_ns))
    )
    completion_review_arguments = (
        ()
        if deadline_monotonic_ns is None
        else ("--completion-review", COMPLETION_REVIEW_POLICY)
    )
    return (
        str(binary_path),
        "run",
        "--spec",
        str(spec_path),
        "--contract-dir",
        str(contract_dir),
        *deadline_arguments,
        *completion_review_arguments,
        "--provider",
        provider.cli_selector(),
        "--executor",
        "external-stdio",
    )
