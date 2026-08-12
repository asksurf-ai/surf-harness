"""Host-private trial control plane and marker-last public evidence handoff."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from nano_grok_build.adapter.artifact_limits import (
    DEFAULT_PUBLICATION_FILE_MAX_BYTES,
    PUBLICATION_TOTAL_MAX_BYTES,
    publication_file_max_bytes,
)

CONTROL_DIR_NAME = ".nano-control-v2"
ISOLATION_RECEIPT_NAME = "isolation-receipt.json"
ISOLATION_SCHEMA = "nano-control-isolation-v2"
PUBLICATION_STAGE_NAME = ".publication-v1"
PUBLICATION_MARKER = "agent-run.json"

PUBLICATION_ALLOWLIST = frozenset(
    {
        "agent-run.json",
        "trajectory.json",
        "partial-trajectory.json",
        "emergency-prefix.json",
        "runtime-usage-receipt.json",
        "runtime-stderr.json",
        "runtime-emergency.json",
        "runtime-entry.json",
        "runtime-background-manifest.json",
        "runtime-background-liveness-v1.json",
        "runtime-process-lease-v1.json",
        "runtime-cleanup-closure-v1.json",
        "runtime/run.json",
        "runtime/events.jsonl",
        "runtime/deadline.json",
        "git-history-baseline.json",
        "git-history-exposure-v1.json",
        "git-history-rehydration-v1.json",
        "workspace-before.json",
        "workspace-after.json",
        "workspace-delta.json",
        "workspace-diff.patch",
        "workspace-changed.tar",
        "workspace-receipt.json",
    }
)

_EMPTY_PUBLIC_SHA256 = hashlib.sha256(b"[]\n").hexdigest()


class ControlPlaneError(RuntimeError):
    """The private/public isolation or immutable publication contract failed."""


def control_root_for(public_root: Path) -> Path:
    """Return the one sibling private root for a Harbor trial agent directory."""

    return public_root.parent / CONTROL_DIR_NAME


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


def _sha256_valid(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _regular_bytes(
    path: Path,
    *,
    limit: int = DEFAULT_PUBLICATION_FILE_MAX_BYTES,
) -> bytes:
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
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ControlPlaneError("control_private_evidence_invalid")
        payload = bytearray()
        while True:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > limit:
                raise ControlPlaneError("control_private_evidence_invalid")
        after = os.fstat(descriptor)
        named = path.lstat()
        identity = lambda value: (  # noqa: E731 - compact immutable identity
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if identity(before) != identity(after) or identity(after) != identity(named):
            raise ControlPlaneError("control_private_evidence_changed")
        return bytes(payload)
    except OSError as error:
        raise ControlPlaneError("control_private_evidence_invalid") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_private(path: Path, payload: bytes) -> None:
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
    except OSError as error:
        raise ControlPlaneError("control_private_write_failed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _public_entries(root: Path) -> list[str]:
    return sorted(path.relative_to(root).as_posix() for path in root.rglob("*"))


def _relative_name(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
        or value not in PUBLICATION_ALLOWLIST
    ):
        raise ControlPlaneError("control_publication_allowlist_invalid")
    return value


@dataclass(frozen=True)
class ControlPlane:
    """A hash-bound private root paired with one initially empty public root."""

    root: Path
    public_root: Path
    run_spec_sha256: str
    receipt_sha256: str

    @classmethod
    def create(cls, public_root: Path, *, run_spec_sha256: str) -> ControlPlane:
        if not _sha256_valid(run_spec_sha256):
            raise ControlPlaneError("control_run_spec_binding_invalid")
        if public_root.is_symlink() or not public_root.is_dir():
            raise ControlPlaneError("control_public_root_invalid")
        public = public_root.resolve()
        if _public_entries(public):
            raise ControlPlaneError("control_public_preflight_not_empty")
        root = control_root_for(public)
        if root.exists() or root.is_symlink():
            raise ControlPlaneError("control_private_root_exists")
        try:
            root.mkdir(mode=0o700)
            root.chmod(0o700)
            _fsync_directory(root.parent)
        except OSError as error:
            raise ControlPlaneError("control_private_root_create_failed") from error
        receipt = {
            "schema_version": ISOLATION_SCHEMA,
            "run_spec_sha256": run_spec_sha256,
            "public_root_name": public.name,
            "public_initial_entry_count": 0,
            "public_initial_entries_sha256": _EMPTY_PUBLIC_SHA256,
        }
        receipt_bytes = _canonical_json(receipt)
        try:
            _write_private(root / ISOLATION_RECEIPT_NAME, receipt_bytes)
            _fsync_directory(root)
        except BaseException:
            shutil.rmtree(root, ignore_errors=True)
            raise
        return cls(
            root=root,
            public_root=public,
            run_spec_sha256=run_spec_sha256,
            receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
        )

    @classmethod
    def open(
        cls,
        root: Path,
        public_root: Path,
        *,
        run_spec_sha256: str,
    ) -> ControlPlane:
        if not _sha256_valid(run_spec_sha256):
            raise ControlPlaneError("control_run_spec_binding_invalid")
        if root.is_symlink() or not root.is_dir():
            raise ControlPlaneError("control_private_root_invalid")
        private = root.resolve()
        if (
            private.name != CONTROL_DIR_NAME
            or stat.S_IMODE(private.stat().st_mode) != 0o700
        ):
            raise ControlPlaneError("control_private_root_invalid")
        if public_root.is_symlink() or not public_root.is_dir():
            raise ControlPlaneError("control_public_root_invalid")
        public = public_root.resolve()
        if control_root_for(public) != private:
            raise ControlPlaneError("control_root_relation_invalid")
        receipt_bytes = _regular_bytes(private / ISOLATION_RECEIPT_NAME)
        try:
            receipt = json.loads(receipt_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ControlPlaneError("control_isolation_receipt_invalid") from error
        expected = {
            "schema_version": ISOLATION_SCHEMA,
            "run_spec_sha256": run_spec_sha256,
            "public_root_name": public.name,
            "public_initial_entry_count": 0,
            "public_initial_entries_sha256": _EMPTY_PUBLIC_SHA256,
        }
        if receipt != expected or receipt_bytes != _canonical_json(expected):
            raise ControlPlaneError("control_isolation_receipt_invalid")
        return cls(
            root=private,
            public_root=public,
            run_spec_sha256=run_spec_sha256,
            receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
        )

    def publish(
        self,
        files: Mapping[str, bytes],
        *,
        marker_name: str = PUBLICATION_MARKER,
    ) -> Mapping[str, Path]:
        """Link staged private bytes into public paths, committing marker last."""

        current = type(self).open(
            self.root,
            self.public_root,
            run_spec_sha256=self.run_spec_sha256,
        )
        if current.receipt_sha256 != self.receipt_sha256:
            raise ControlPlaneError("control_isolation_receipt_changed")
        normalized: dict[str, bytes] = {}
        total = 0
        for raw_name, raw_payload in files.items():
            name = _relative_name(raw_name)
            if not isinstance(raw_payload, bytes) or name in normalized:
                raise ControlPlaneError("control_publication_payload_invalid")
            if len(raw_payload) > publication_file_max_bytes(name):
                raise ControlPlaneError("control_publication_payload_invalid")
            total += len(raw_payload)
            if total > PUBLICATION_TOTAL_MAX_BYTES:
                raise ControlPlaneError("control_publication_payload_invalid")
            normalized[name] = raw_payload
        marker = _relative_name(marker_name)
        if marker not in normalized:
            raise ControlPlaneError("control_publication_marker_missing")

        public_marker = self.public_root / marker
        if public_marker.exists() or public_marker.is_symlink():
            if set(_public_entries(self.public_root)) != {
                *normalized,
                *(
                    str(PurePosixPath(name).parent)
                    for name in normalized
                    if "/" in name
                ),
            }:
                raise ControlPlaneError("control_publication_existing_mismatch")
            for name, payload in normalized.items():
                if (
                    _regular_bytes(
                        self.public_root / name,
                        limit=publication_file_max_bytes(name),
                    )
                    != payload
                ):
                    raise ControlPlaneError("control_publication_existing_mismatch")
            return {name: self.public_root / name for name in normalized}
        if _public_entries(self.public_root):
            raise ControlPlaneError("control_publication_public_conflict")

        stage = self.root / PUBLICATION_STAGE_NAME
        if stage.exists() or stage.is_symlink():
            raise ControlPlaneError("control_publication_stage_exists")
        stage.mkdir(mode=0o700)
        ordered = sorted(name for name in normalized if name != marker) + [marker]
        for name in ordered:
            staged = stage / name
            staged.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            _write_private(staged, normalized[name])
        for directory in sorted(
            (path for path in stage.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts),
            reverse=True,
        ):
            _fsync_directory(directory)
        _fsync_directory(stage)

        published: dict[str, Path] = {}
        try:
            for name in ordered:
                source = stage / name
                destination = self.public_root / name
                destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                os.link(source, destination, follow_symlinks=False)
                _fsync_directory(destination.parent)
                published[name] = destination
        except OSError as error:
            raise ControlPlaneError("control_publication_public_conflict") from error
        return published

    def verify_pre_dispatch(self) -> None:
        """Recheck the receipt and the still-empty public mount before provider use."""

        current = type(self).open(
            self.root,
            self.public_root,
            run_spec_sha256=self.run_spec_sha256,
        )
        if current.receipt_sha256 != self.receipt_sha256:
            raise ControlPlaneError("control_isolation_receipt_changed")
        if _public_entries(self.public_root):
            raise ControlPlaneError("control_public_pre_dispatch_not_empty")

    def cleanup(self) -> None:
        """Remove only this validated private root after successful publication."""

        type(self).open(
            self.root,
            self.public_root,
            run_spec_sha256=self.run_spec_sha256,
        )
        if (
            self.root.name != CONTROL_DIR_NAME
            or self.root.parent != self.public_root.parent
        ):
            raise ControlPlaneError("control_cleanup_target_invalid")
        try:
            shutil.rmtree(self.root)
            _fsync_directory(self.root.parent)
        except OSError as error:
            raise ControlPlaneError("control_cleanup_failed") from error
