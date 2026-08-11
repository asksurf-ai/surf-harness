"""Strict write/read validation for the Git single-root receipt."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping
from pathlib import Path, PurePosixPath

from nano_grok_build.harbor.git_history_capability import (
    CAPABILITY_POLICY_VERSION,
    CAPABILITY_SCHEMA,
    GIT_HISTORY_ACCESS_NOT_REQUIRED,
    GIT_HISTORY_ACCESS_REQUIRED,
    permits_empty_history_baseline,
)

HISTORY_BASELINE_RECEIPT = "git-history-baseline.json"
HISTORY_BASELINE_SCHEMA = "nano-git-history-baseline-v2"
HISTORY_BASELINE_POLICY = "nano-git-history-topology-v2"
_HEX = frozenset("0123456789abcdef")
_CAPABILITY_KEYS = {
    "schema_version",
    "policy_version",
    "git_history_access",
    "canonical_instruction_sha256",
    "trusted_manifest_sha256",
    "supporting_span_sha256",
}
_RECEIPT_KEYS = {
    "schema_version",
    "policy_version",
    "run_spec_sha256",
    "capability_instruction_sha256",
    "trusted_manifest_sha256",
    "topology_before",
    "topology_after",
    "admitted_repo_relative_path",
    "status",
    "census_before_sha256",
    "census_after_sha256",
    "filesystem_manifest_before_sha256",
    "filesystem_manifest_after_sha256",
    "source_commit_oid",
    "source_tree_oid",
    "root_commit_oid",
    "root_tree_oid",
    "preexisting_commit_count",
    "root_commit_count",
    "ref_count",
    "remote_count",
    "alternate_count",
    "old_metadata_removed",
}


def _hex(value: object, lengths: set[int]) -> bool:
    return isinstance(value, str) and len(value) in lengths and set(value) <= _HEX


def _repo_relative_path(value: object) -> bool:
    if value == ".":
        return True
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 4096
        or "\x00" in value
        or "\n" in value
        or value.startswith("/")
    ):
        return False
    parsed = PurePosixPath(value)
    return parsed.as_posix() == value and all(
        part not in {"", ".", ".."} for part in parsed.parts
    )


def git_history_access(capability: object) -> str:
    if (
        not isinstance(capability, Mapping)
        or set(capability) != _CAPABILITY_KEYS
        or capability.get("schema_version") != CAPABILITY_SCHEMA
        or capability.get("policy_version") != CAPABILITY_POLICY_VERSION
        or not _hex(capability.get("canonical_instruction_sha256"), {64})
        or not _hex(capability.get("trusted_manifest_sha256"), {64})
    ):
        raise RuntimeError("git_history_capability_invalid")
    access = capability.get("git_history_access")
    span = capability.get("supporting_span_sha256")
    if (
        access == GIT_HISTORY_ACCESS_REQUIRED
        and not _hex(span, {64})
        or access == GIT_HISTORY_ACCESS_NOT_REQUIRED
        and span is not None
        or access not in {GIT_HISTORY_ACCESS_REQUIRED, GIT_HISTORY_ACCESS_NOT_REQUIRED}
    ):
        raise RuntimeError("git_history_capability_invalid")
    return str(access)


def parse_git_history_baseline_receipt(
    raw: str, run_hash: str, access: str
) -> dict[str, object]:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value

    try:
        value = json.loads(
            raw,
            object_pairs_hook=unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (json.JSONDecodeError, ValueError, RecursionError) as error:
        raise RuntimeError("git_history_baseline_receipt_invalid") from error
    status = value.get("status") if isinstance(value, dict) else None
    topology_before = value.get("topology_before") if isinstance(value, dict) else None
    topology_after = value.get("topology_after") if isinstance(value, dict) else None
    path = value.get("admitted_repo_relative_path") if isinstance(value, dict) else None
    absent_clean = status == "absent_clean"
    created = status == "created"
    isolated = status == "isolated"
    preserved = status == "preserved"
    if (
        not isinstance(value, dict)
        or set(value) != _RECEIPT_KEYS
        or value.get("schema_version") != HISTORY_BASELINE_SCHEMA
        or value.get("policy_version") != HISTORY_BASELINE_POLICY
        or value.get("run_spec_sha256") != run_hash
        or status not in {"absent_clean", "created", "isolated", "preserved"}
        or access == GIT_HISTORY_ACCESS_NOT_REQUIRED
        and status not in {"absent_clean", "created", "isolated"}
        or access == GIT_HISTORY_ACCESS_REQUIRED
        and status not in {"absent_clean", "preserved"}
        or topology_before not in {"zero", "root", "nested"}
        or topology_after not in {"zero", "root", "nested"}
        or absent_clean
        and path is not None
        or not absent_clean
        and not _repo_relative_path(path)
        or not all(
            _hex(value.get(key), {64})
            for key in (
                "capability_instruction_sha256",
                "trusted_manifest_sha256",
                "census_before_sha256",
                "census_after_sha256",
                "filesystem_manifest_before_sha256",
                "filesystem_manifest_after_sha256",
            )
        )
        or not absent_clean
        and not _hex(value.get("root_commit_oid"), {40, 64})
        or not absent_clean
        and not _hex(value.get("root_tree_oid"), {40, 64})
        or not (
            value.get("source_commit_oid") is None
            and value.get("source_tree_oid") is None
            or _hex(value.get("source_commit_oid"), {40, 64})
            and _hex(value.get("source_tree_oid"), {40, 64})
        )
        or not all(
            type(value.get(key)) is int and value[key] >= 0
            for key in (
                "preexisting_commit_count",
                "root_commit_count",
                "ref_count",
                "remote_count",
                "alternate_count",
            )
        )
        or type(value.get("old_metadata_removed")) is not bool
        or value.get("filesystem_manifest_before_sha256")
        != value.get("filesystem_manifest_after_sha256")
        or absent_clean
        and (
            topology_before != "zero"
            or topology_after != "zero"
            or path is not None
            or value.get("source_commit_oid") is not None
            or value.get("source_tree_oid") is not None
            or value.get("root_commit_oid") is not None
            or value.get("root_tree_oid") is not None
            or value.get("preexisting_commit_count") != 0
            or value.get("root_commit_count") != 0
            or value.get("ref_count") != 0
            or value.get("remote_count") != 0
            or value.get("alternate_count") != 0
            or value.get("old_metadata_removed") is not False
            or value.get("census_before_sha256") != value.get("census_after_sha256")
        )
        or created
        and (
            topology_before != "zero"
            or topology_after != "root"
            or path != "."
            or value.get("source_commit_oid") is not None
            or value.get("source_tree_oid") is not None
            or value.get("preexisting_commit_count") != 0
            or value.get("root_commit_count") != 1
            or value.get("ref_count") != 1
            or value.get("remote_count") != 0
            or value.get("alternate_count") != 0
            or value.get("old_metadata_removed") is not False
            or value.get("census_before_sha256") == value.get("census_after_sha256")
        )
        or isolated
        and (
            topology_before not in {"root", "nested"}
            or topology_after != topology_before
            or (path == ".") != (topology_before == "root")
            or not _hex(value.get("source_commit_oid"), {40, 64})
            or not _hex(value.get("source_tree_oid"), {40, 64})
            or value.get("root_commit_count") != 1
            or value.get("ref_count") != 1
            or value.get("remote_count") != 0
            or value.get("alternate_count") != 0
            or value.get("source_tree_oid") != value.get("root_tree_oid")
            or value.get("old_metadata_removed") is not True
        )
        or preserved
        and (
            topology_before not in {"root", "nested"}
            or topology_after != topology_before
            or (path == ".") != (topology_before == "root")
            or value.get("source_commit_oid") != value.get("root_commit_oid")
            or value.get("source_tree_oid") != value.get("root_tree_oid")
            or value.get("preexisting_commit_count") != value.get("root_commit_count")
            or value.get("old_metadata_removed") is not False
            or value.get("census_before_sha256") != value.get("census_after_sha256")
        )
    ):
        raise RuntimeError("git_history_baseline_receipt_invalid")
    return value


def load_git_history_baseline_receipt(
    path: Path, *, capability: object, run_spec_sha256: str
) -> dict[str, object]:
    """Read and validate the immutable receipt again at admission."""

    access = git_history_access(capability)
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 16 * 1024:
            raise RuntimeError("git_history_baseline_receipt_invalid")
        raw = os.read(descriptor, 16 * 1024 + 1)
        if len(raw) != metadata.st_size:
            raise RuntimeError("git_history_baseline_receipt_invalid")
        value = parse_git_history_baseline_receipt(
            raw.decode("utf-8"), run_spec_sha256, access
        )
        canonical = (
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        if (
            raw != canonical
            or not isinstance(capability, Mapping)
            or (
                value["status"] == "absent_clean"
                and access == GIT_HISTORY_ACCESS_REQUIRED
                and not permits_empty_history_baseline(capability)
            )
            or (
                value["capability_instruction_sha256"]
                != capability["canonical_instruction_sha256"]
                or value["trusted_manifest_sha256"]
                != capability["trusted_manifest_sha256"]
            )
        ):
            raise RuntimeError("git_history_baseline_receipt_invalid")
        return value
    except (OSError, UnicodeDecodeError, KeyError) as error:
        raise RuntimeError("git_history_baseline_receipt_invalid") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
