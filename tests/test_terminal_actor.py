from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json
import os
import shlex
import shutil
import stat
import subprocess
import tempfile
import time
import zlib
from fnmatch import fnmatch
from pathlib import Path
from types import SimpleNamespace

import pytest

from nano_grok_build.adapter import terminal_actor
from nano_grok_build.adapter.stdio_bridge import (
    BACKGROUND_START_PROOF_VERSION,
    BackgroundStartKind,
    BackgroundStartObservation,
    BridgeError,
    ProcessDisposition,
    ToolFailure,
    ToolFatalError,
    ToolRequest,
    encode_tool_response,
)
from nano_grok_build.adapter.terminal_actor import (
    _ACTOR,
    _BACKGROUND_ROOT,
    _REMOTE_ACTOR,
    BackgroundTask,
    RemoteTerminalActor,
    SnapshotCommandResult,
    SnapshotFailureSubtypeV1,
    SnapshotOperationFailure,
    SnapshotTerminationUnverified,
    SnapshotTimeoutOriginV1,
    SnapshotTransportTimeout,
    _BackgroundStartFailure,
    _MediaSourceSnapshot,
    _ToolRejected,
)

_BACKGROUND_FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "background-tool-cases-v1.json").read_text(
        encoding="utf-8"
    )
)
_TERMINAL_PHASE_FIXTURE = json.loads(
    (
        Path(__file__).parent / "fixtures" / "p0p1" / "terminal-phase-cases.json"
    ).read_text(encoding="utf-8")
)


def background_case(name: str) -> dict[str, object]:
    return next(case for case in _BACKGROUND_FIXTURE["cases"] if case["case"] == name)


class LocalFiles:
    async def exec(self, command, cwd=None, timeout_sec=None, user=None):
        if command.startswith("stat -c %s -- "):
            target = Path(command.removeprefix("stat -c %s -- ").strip("'"))
            return SimpleNamespace(return_code=0, stdout=f"{target.stat().st_size}\n")
        raise AssertionError(f"unexpected remote command: {command}")

    async def upload_file(self, source_path, target_path):
        target = Path(target_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, target)

    async def download_file(self, source_path, target_path):
        shutil.copyfile(source_path, target_path)


class ScriptedRemote:
    def __init__(self, results):
        self.results = iter(results)
        self.exec_calls = []
        self.uploads = []

    async def exec(self, command, cwd=None, timeout_sec=None, user=None):
        self.exec_calls.append((command, cwd, timeout_sec, user))
        return next(self.results)

    async def upload_file(self, source_path, target_path):
        self.uploads.append((Path(source_path), target_path))

    async def download_file(self, source_path, target_path):
        raise AssertionError("unexpected download")


class SnapshotRemote(ScriptedRemote):
    async def download_file(self, source_path, target_path):
        assert source_path == "/app/repo/.nano-snapshot"
        Path(target_path).write_bytes(b"snapshot")


class RaisingSnapshotRemote(ScriptedRemote):
    def __init__(self, error: BaseException):
        super().__init__([])
        self.error = error

    async def exec(self, command, cwd=None, timeout_sec=None, user=None):
        self.exec_calls.append((command, cwd, timeout_sec, user))
        raise self.error


class MappingPreflightRemote:
    def __init__(self, outcomes: list[object]) -> None:
        self.outcomes = iter(outcomes)
        self.exec_calls: list[tuple[str, str | None, float | None, object]] = []

    async def exec(self, command, cwd=None, timeout_sec=None, user=None):
        self.exec_calls.append((command, cwd, timeout_sec, user))
        outcome = next(self.outcomes)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    async def upload_file(self, source_path, target_path):
        raise AssertionError("user effect must be represented by the actor fixture")

    async def download_file(self, source_path, target_path):
        raise AssertionError("unexpected download")


class MappingPreflightActor(RemoteTerminalActor):
    def __init__(
        self,
        environment: MappingPreflightRemote,
        *,
        monotonic=None,
    ) -> None:
        super().__init__(environment, monotonic=monotonic)
        self._ready = True
        self._workspace_mapping = {
            "canonical_cwd": "/app/repo",
            "default_cwd": "/app/repo",
            "logical_cwd": "/workspace",
            "mode": "created_symlink",
        }
        self.user_effects: list[str] = []

    async def _list_dir(self, request: ToolRequest):
        self.user_effects.append(request.call_id)
        return self._settled(
            "mapping-preflight-user-effect",
            succeeded=True,
            request=request,
        )


class OwnedSnapshotRemote:
    def __init__(
        self,
        *,
        status: str = "completed",
        term_sent: bool = False,
        kill_sent: bool = False,
        wait_block: bool = False,
        launch_patch: dict[str, object] | None = None,
        terminal_patch: dict[str, object] | None = None,
        terminal_drop: set[str] | None = None,
        cancel_return_code: int = 0,
    ) -> None:
        self.status = status
        self.term_sent = term_sent
        self.kill_sent = kill_sent
        self.wait_block = wait_block
        self.launch_patch = launch_patch or {}
        self.terminal_patch = terminal_patch or {}
        self.terminal_drop = terminal_drop or set()
        self.cancel_return_code = cancel_return_code
        self.exec_calls: list[tuple[str, str | None, float | None, object]] = []
        self.uploads: list[str] = []
        self.tokens: list[str] = []
        self.identities: dict[str, dict[str, object]] = {}
        self.wait_entered = asyncio.Event()

    @staticmethod
    def _mode(parts: list[str]) -> tuple[str, int] | None:
        for index, value in enumerate(parts):
            if value.endswith("/actor.sh") and index + 1 < len(parts):
                return parts[index + 1], index + 1
        return None

    def _ready(self, token: str) -> dict[str, object]:
        identity = self.identities.setdefault(
            token,
            {
                "version": 1,
                "status": "running",
                "owner_token": token,
                "leader_pid": 3101 + len(self.identities) * 10,
                "leader_starttime": 70001 + len(self.identities) * 10,
                "pgid": 3101 + len(self.identities) * 10,
                "supervisor_pid": 3102 + len(self.identities) * 10,
                "supervisor_starttime": 70002 + len(self.identities) * 10,
                "supervisor_pgid": 3102 + len(self.identities) * 10,
            },
        )
        return {**identity, **self.launch_patch}

    def _terminal(self, token: str) -> dict[str, object]:
        ready = dict(self.identities[token])
        ready["status"] = self.status
        ready.update(
            {
                "return_code": (
                    124
                    if self.status == "timed_out"
                    else 125
                    if self.status == "cancelled"
                    else 0
                ),
                "timed_out": self.status == "timed_out",
                "term_sent": self.term_sent,
                "kill_sent": self.kill_sent,
                "termination_verified": True,
                "census_verified": True,
                "survivor_count": 0,
            }
        )
        ready.update(self.terminal_patch)
        for field in self.terminal_drop:
            ready.pop(field, None)
        return ready

    async def exec(self, command, cwd=None, timeout_sec=None, user=None):
        self.exec_calls.append((command, cwd, timeout_sec, user))
        if command.startswith("test -d /tmp/nano-workspace-snapshot-v1."):
            return SimpleNamespace(return_code=0, stdout="", stderr="")
        parts = shlex.split(command)
        located = self._mode(parts)
        if located is None:
            raise AssertionError(f"unexpected owned snapshot command: {command}")
        mode, mode_index = located
        if mode == "snapshot-start":
            token = parts[mode_index + 6]
            self.tokens.append(token)
            return SimpleNamespace(
                return_code=0,
                stdout=json.dumps(
                    self._ready(token),
                    separators=(",", ":"),
                )
                + "\n",
                stderr="",
            )
        control_dir = parts[mode_index + 1]
        token = parts[mode_index + 2]
        assert token in control_dir
        if mode == "snapshot-inspect":
            payload = self._ready(token)
        elif mode == "snapshot-release":
            return SimpleNamespace(
                return_code=0,
                stdout="released\n",
                stderr="",
            )
        elif mode == "snapshot-wait":
            if self.wait_block:
                self.wait_entered.set()
                await asyncio.Future()
            payload = self._terminal(token)
        elif mode == "snapshot-cancel":
            payload = self._terminal(token)
            payload["status"] = "cancelled"
            payload["return_code"] = 125
            for field in self.terminal_drop:
                payload.pop(field, None)
            return SimpleNamespace(
                return_code=self.cancel_return_code,
                stdout=json.dumps(payload, separators=(",", ":")) + "\n",
                stderr="",
            )
        else:
            raise AssertionError(f"unexpected owned snapshot mode: {mode}")
        return SimpleNamespace(
            return_code=0,
            stdout=json.dumps(payload, separators=(",", ":")) + "\n",
            stderr="",
        )

    async def upload_file(self, source_path, target_path):
        self.uploads.append(target_path)

    async def download_file(self, source_path, target_path):
        if source_path.endswith("/stdout.bin"):
            Path(target_path).write_bytes(b"owned-out")
        elif source_path.endswith("/stderr.bin"):
            Path(target_path).write_bytes(b"owned-err")
        else:
            raise AssertionError(f"unexpected owned snapshot download: {source_path}")


class OneShotOwnedFaultRemote(OwnedSnapshotRemote):
    def __init__(
        self,
        fault_point: str,
        *,
        cancel_return_code: int = 0,
    ) -> None:
        super().__init__(cancel_return_code=cancel_return_code)
        self.fault_point = fault_point
        self.fault_fired = False

    async def exec(self, command, cwd=None, timeout_sec=None, user=None):
        parts = shlex.split(command)
        located = self._mode(parts)
        if located is not None and not self.fault_fired:
            mode, mode_index = located
            if self.fault_point == "launch_nonzero" and mode == "snapshot-start":
                self.fault_fired = True
                token = parts[mode_index + 6]
                self.tokens.append(token)
                self._ready(token)
                self.exec_calls.append((command, cwd, timeout_sec, user))
                return SimpleNamespace(return_code=71, stdout="", stderr="")
            if self.fault_point == "lease_parse" and mode == "snapshot-start":
                self.fault_fired = True
                token = parts[mode_index + 6]
                self.tokens.append(token)
                self._ready(token)
                self.exec_calls.append((command, cwd, timeout_sec, user))
                return SimpleNamespace(return_code=0, stdout="{}\n", stderr="")
            if self.fault_point == "release" and mode == "snapshot-release":
                self.fault_fired = True
                self.exec_calls.append((command, cwd, timeout_sec, user))
                return SimpleNamespace(return_code=92, stdout="", stderr="")
            if self.fault_point == "wait_connection" and mode == "snapshot-wait":
                self.fault_fired = True
                self.exec_calls.append((command, cwd, timeout_sec, user))
                raise ConnectionError("secret wait transport")
            if self.fault_point == "wait_timeout" and mode == "snapshot-wait":
                self.fault_fired = True
                self.exec_calls.append((command, cwd, timeout_sec, user))
                raise RuntimeError(f"Command timed out after {timeout_sec} seconds")
            if self.fault_point == "wait_invalid" and mode == "snapshot-wait":
                self.fault_fired = True
                self.exec_calls.append((command, cwd, timeout_sec, user))
                return SimpleNamespace(return_code=74, stdout="", stderr="")
            if self.fault_point == "terminal_invalid" and mode == "snapshot-wait":
                self.fault_fired = True
                self.exec_calls.append((command, cwd, timeout_sec, user))
                token = parts[mode_index + 2]
                payload = self._terminal(token)
                payload.pop("status")
                return SimpleNamespace(
                    return_code=0,
                    stdout=json.dumps(payload, separators=(",", ":")) + "\n",
                    stderr="",
                )
        return await super().exec(
            command,
            cwd=cwd,
            timeout_sec=timeout_sec,
            user=user,
        )


class DockerExecRemote:
    def __init__(self, container_id: str):
        self.container_id = container_id
        self.exec_calls: list[tuple[str, str | None, float | None, object]] = []

    async def exec(self, command, cwd=None, timeout_sec=None, user=None):
        self.exec_calls.append((command, cwd, timeout_sec, user))
        argv = ["docker", "exec"]
        if cwd is not None:
            argv.extend(["--workdir", cwd])
        if user is not None:
            argv.extend(["--user", str(user)])
        argv.extend([self.container_id, "/bin/bash", "-c", command])
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        return SimpleNamespace(
            return_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    async def upload_file(self, source_path, target_path):
        subprocess.run(
            ["docker", "cp", str(source_path), f"{self.container_id}:{target_path}"],
            check=True,
            capture_output=True,
            text=True,
        )

    async def download_file(self, source_path, target_path):
        subprocess.run(
            ["docker", "cp", f"{self.container_id}:{source_path}", str(target_path)],
            check=True,
            capture_output=True,
            text=True,
        )


class InitialStatusLossDockerRemote(DockerExecRemote):
    def __init__(self, container_id: str):
        super().__init__(container_id)
        self.remaining_status_losses = 2

    async def exec(self, command, cwd=None, timeout_sec=None, user=None):
        if self.remaining_status_losses > 0 and "/actor.sh status " in command:
            self.remaining_status_losses -= 1
            self.exec_calls.append((command, cwd, timeout_sec, user))
            raise TimeoutError("injected initial status transport loss")
        return await super().exec(
            command,
            cwd=cwd,
            timeout_sec=timeout_sec,
            user=user,
        )


class C1DockerMappingActor(RemoteTerminalActor):
    def __init__(self, environment: DockerExecRemote) -> None:
        super().__init__(environment)
        self.user_effects: list[str] = []

    async def _list_dir(self, request: ToolRequest):
        self.user_effects.append(request.call_id)
        return self._settled(
            "c1-mapping-preflight-user-effect",
            succeeded=True,
            request=request,
        )


class FailedForegroundRemote:
    def __init__(
        self,
        evidence_return_code: int,
        *,
        cleanup_return_code: int = 73,
    ):
        self.evidence_return_code = evidence_return_code
        self.cleanup_return_code = cleanup_return_code
        self.exec_calls = []

    async def exec(self, command, cwd=None, timeout_sec=None, user=None):
        self.exec_calls.append((command, cwd))
        if command.startswith("mkdir -p "):
            return SimpleNamespace(return_code=0, stdout="")
        if command.startswith("/bin/bash -c "):
            return SimpleNamespace(return_code=0, stdout="")
        if "/actor.sh run " in command:
            return SimpleNamespace(return_code=126, stdout="", stderr="chdir failed")
        if "/pgid" in command and "/meta.json" in command:
            return SimpleNamespace(
                return_code=self.evidence_return_code,
                stdout="",
            )
        if "/actor.sh cleanup " in command:
            return SimpleNamespace(
                return_code=self.cleanup_return_code,
                stdout="",
            )
        raise AssertionError(f"unexpected remote command: {command}")

    async def upload_file(self, source_path, target_path):
        return None

    async def download_file(self, source_path, target_path):
        raise AssertionError("unexpected download")


class SettledForegroundTimeoutRemote:
    def __init__(self) -> None:
        self.exec_calls = []
        self.downloads = []

    async def exec(self, command, cwd=None, timeout_sec=None, user=None):
        self.exec_calls.append((command, cwd, timeout_sec, user))
        if command.startswith("/bin/bash -c "):
            return SimpleNamespace(return_code=0, stdout="")
        if command.startswith("mkdir -p "):
            return SimpleNamespace(return_code=0, stdout="")
        if "/actor.sh run " in command:
            raise TimeoutError("synthetic outer transport timeout")
        raise AssertionError(f"unexpected remote command: {command}")

    async def upload_file(self, source_path, target_path):
        return None

    async def download_file(self, source_path, target_path):
        self.downloads.append(source_path)
        name = Path(source_path).name
        payload = {
            "meta.json": json.dumps(
                {
                    "return_code": 124,
                    "timed_out": True,
                    "stdout_truncated": False,
                    "stderr_truncated": False,
                    "cleanup_attempted": True,
                    "term_sent": True,
                    "kill_sent": False,
                    "cleanup_verified": True,
                    "census_verified": True,
                    "survivor_count": 0,
                },
                separators=(",", ":"),
            ).encode(),
            "stdout.bin": b"partial output\n",
            "stderr.bin": b"",
        }[name]
        Path(target_path).write_bytes(payload)


class SettledForegroundSemanticTimeoutRemote(SettledForegroundTimeoutRemote):
    async def exec(self, command, cwd=None, timeout_sec=None, user=None):
        if "/actor.sh run " in command:
            self.exec_calls.append((command, cwd, timeout_sec, user))
            return SimpleNamespace(return_code=0, stdout="", stderr="")
        return await super().exec(
            command,
            cwd=cwd,
            timeout_sec=timeout_sec,
            user=user,
        )


class SettledForegroundResidualRemote(SettledForegroundSemanticTimeoutRemote):
    def __init__(self, *, kill_sent: bool) -> None:
        super().__init__()
        self.kill_sent = kill_sent

    async def download_file(self, source_path, target_path):
        self.downloads.append(source_path)
        name = Path(source_path).name
        payload = {
            "meta.json": json.dumps(
                {
                    "return_code": 0,
                    "timed_out": False,
                    "stdout_truncated": False,
                    "stderr_truncated": False,
                    "cleanup_attempted": True,
                    "term_sent": True,
                    "kill_sent": self.kill_sent,
                    "cleanup_verified": True,
                    "census_verified": True,
                    "survivor_count": 0,
                },
                separators=(",", ":"),
            ).encode(),
            "stdout.bin": b"leader settled\n",
            "stderr.bin": b"",
        }[name]
        Path(target_path).write_bytes(payload)


class CorruptRecoveryForegroundRemote(SettledForegroundTimeoutRemote):
    def __init__(
        self,
        *,
        evidence_return_code: int,
        cleanup_return_code: int,
    ) -> None:
        super().__init__()
        self.evidence_return_code = evidence_return_code
        self.cleanup_return_code = cleanup_return_code

    async def exec(self, command, cwd=None, timeout_sec=None, user=None):
        if command.startswith("if test -f ") and "/meta.json" in command:
            self.exec_calls.append((command, cwd, timeout_sec, user))
            return SimpleNamespace(
                return_code=self.evidence_return_code,
                stdout="",
                stderr="",
            )
        if "/actor.sh cleanup " in command:
            self.exec_calls.append((command, cwd, timeout_sec, user))
            return SimpleNamespace(
                return_code=self.cleanup_return_code,
                stdout=("cleanup-ok\n" if self.cleanup_return_code == 0 else ""),
                stderr="",
            )
        return await super().exec(
            command,
            cwd=cwd,
            timeout_sec=timeout_sec,
            user=user,
        )

    async def download_file(self, source_path, target_path):
        self.downloads.append(source_path)
        name = Path(source_path).name
        payload = {
            "meta.json": b'{"corrupt":true}',
            "stdout.bin": b"partial output\n",
            "stderr.bin": b"",
        }[name]
        Path(target_path).write_bytes(payload)


class CorruptDirectForegroundRemote(CorruptRecoveryForegroundRemote):
    async def exec(self, command, cwd=None, timeout_sec=None, user=None):
        if "/actor.sh run " in command:
            self.exec_calls.append((command, cwd, timeout_sec, user))
            return SimpleNamespace(return_code=0, stdout="", stderr="")
        return await super().exec(
            command,
            cwd=cwd,
            timeout_sec=timeout_sec,
            user=user,
        )


class DirectContainmentForegroundRemote(CorruptDirectForegroundRemote):
    def __init__(
        self,
        *,
        cleanup_verified: bool,
        census_verified: bool,
        cleanup_return_code: int,
    ) -> None:
        super().__init__(
            evidence_return_code=0,
            cleanup_return_code=cleanup_return_code,
        )
        self.meta_cleanup_verified = cleanup_verified
        self.meta_census_verified = census_verified

    async def download_file(self, source_path, target_path):
        name = Path(source_path).name
        if name == "meta.json":
            payload = json.dumps(
                {
                    "return_code": 0,
                    "timed_out": False,
                    "stdout_truncated": False,
                    "stderr_truncated": False,
                    "cleanup_attempted": True,
                    "term_sent": False,
                    "kill_sent": False,
                    "cleanup_verified": self.meta_cleanup_verified,
                    "census_verified": self.meta_census_verified,
                    "survivor_count": 0,
                },
                separators=(",", ":"),
            ).encode()
            Path(target_path).write_bytes(payload)
            return
        await SettledForegroundTimeoutRemote.download_file(
            self,
            source_path,
            target_path,
        )


def workspace_setup_stdout(
    mode: str,
    default_cwd: str,
    canonical_cwd: str,
    scratch_root: str = "/tmp",
) -> str:
    return "\n".join(
        (
            mode,
            base64.b64encode(default_cwd.encode()).decode(),
            base64.b64encode(canonical_cwd.encode()).decode(),
            base64.b64encode(scratch_root.encode()).decode(),
            "",
        )
    )


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    checksum = binascii.crc32(chunk_type + data) & 0xFFFFFFFF
    return (
        len(data).to_bytes(4, "big") + chunk_type + data + checksum.to_bytes(4, "big")
    )


def _png_bytes(
    width: int,
    height: int,
    *,
    metadata: bytes | None = None,
    animation: bool = False,
    pixel_data: bool = True,
) -> bytes:
    ihdr = width.to_bytes(4, "big") + height.to_bytes(4, "big") + bytes([8, 2, 0, 0, 0])
    chunks = [_png_chunk(b"IHDR", ihdr)]
    if metadata is not None:
        chunks.append(_png_chunk(b"tEXt", b"private\x00" + metadata))
    if animation:
        chunks.append(_png_chunk(b"acTL", (2).to_bytes(4, "big") * 2))
    raw = (
        b"".join(b"\x00" + (b"\xdc\x0a\x1e" * width) for _ in range(height))
        if pixel_data
        else b""
    )
    chunks.extend(
        [
            _png_chunk(b"IDAT", zlib.compress(raw)),
            _png_chunk(b"IEND", b""),
        ]
    )
    return b"\x89PNG\r\n\x1a\n" + b"".join(chunks)


def _jpeg_bytes(
    width: int,
    height: int,
    *,
    metadata: bytes | None = None,
) -> bytes:
    def segment(marker: int, data: bytes) -> bytes:
        return b"\xff" + bytes([marker]) + (len(data) + 2).to_bytes(2, "big") + data

    components = bytes(
        [
            3,
            1,
            0x11,
            0,
            2,
            0x11,
            0,
            3,
            0x11,
            0,
        ]
    )
    sof = bytes([8]) + height.to_bytes(2, "big") + width.to_bytes(2, "big") + components
    app = segment(0xE1, metadata) if metadata is not None else b""
    return b"\xff\xd8" + app + segment(0xC0, sof) + b"\xff\xd9"


class LocalFileActor(RemoteTerminalActor):
    def __init__(self, workspace: Path):
        super().__init__(LocalFiles())
        self.workspace = workspace.resolve()
        self._ready = True

    async def _prepare_request(self, request):
        return str(self.workspace)

    def _canonical_workspace(self):
        return str(self.workspace)

    async def _resolve_workspace_path(
        self,
        request,
        raw_path,
        *,
        expected,
        allow_create=False,
    ):
        if (
            not isinstance(raw_path, str)
            or not raw_path
            or "\x00" in raw_path
            or len(raw_path.encode()) > request.max_path_bytes
        ):
            raise _ToolRejected("invalid_path")
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = self.workspace / candidate
        try:
            resolved = candidate.resolve(strict=False)
            resolved.relative_to(self.workspace)
        except (OSError, ValueError):
            raise _ToolRejected("path_outside_workspace") from None
        if expected == "file" and not resolved.is_file():
            raise _ToolRejected(f"{request.tool_name}_target_invalid")
        if expected == "directory" and not resolved.is_dir():
            raise _ToolRejected(f"{request.tool_name}_target_invalid")
        if expected == "create":
            if resolved.exists() and not resolved.is_file():
                raise _ToolRejected("write_target_invalid")
            ancestor = resolved.parent
            while not ancestor.exists():
                ancestor = ancestor.parent
            if not ancestor.is_dir():
                raise _ToolRejected("write_target_invalid")
        return str(resolved)

    async def _remote_regular_file_exists(self, request, target):
        return Path(target).is_file()

    async def _media_source_snapshot(self, request, raw_path, target):
        assert isinstance(raw_path, str)
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = self.workspace / candidate
        lexical = Path(os.path.abspath(candidate))
        has_symlink = False
        current = self.workspace
        for component in lexical.relative_to(self.workspace).parts:
            current /= component
            has_symlink = has_symlink or current.is_symlink()
        path = Path(target)
        payload = path.read_bytes()
        metadata = path.stat()
        return _MediaSourceSnapshot(
            logical_path=lexical.relative_to(self.workspace).as_posix(),
            byte_length=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
            device=metadata.st_dev,
            inode=metadata.st_ino,
            has_symlink=has_symlink,
        )

    async def _atomic_upload(self, request, target, payload):
        destination = Path(target)
        destination.parent.mkdir(parents=True, exist_ok=True)
        prior_mode = (
            stat.S_IMODE(destination.stat().st_mode) if destination.exists() else None
        )
        descriptor, raw = tempfile.mkstemp(
            prefix=".nano-write.",
            dir=destination.parent,
        )
        temporary = Path(raw)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            if prior_mode is not None:
                temporary.chmod(prior_mode)
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)

    async def _remote_directory_inventory(self, request, target):
        root = Path(target)
        ignored = set()
        ignore_file = root / ".gitignore"
        if ignore_file.exists():
            ignored = {
                line.strip().rstrip("/")
                for line in ignore_file.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")
            }
        entries = []
        cutoff = False
        for current, directories, files in os.walk(root, followlinks=False):
            current_path = Path(current)
            directories[:] = sorted(
                [
                    name
                    for name in directories
                    if not name.startswith(".")
                    and name not in ignored
                    and not (current_path / name).is_symlink()
                ]
            )
            for name, is_directory in [
                *((name, True) for name in directories),
                *((name, False) for name in files),
            ]:
                path = current_path / name
                relative = path.relative_to(root).as_posix()
                if (
                    name.startswith(".")
                    or any(fnmatch(relative, pattern) for pattern in ignored)
                    or path.is_symlink()
                ):
                    continue
                if len(entries) >= request.max_directory_entries:
                    cutoff = True
                    return entries, cutoff
                entries.append((relative, is_directory))
        return entries, cutoff


class LocalMediaFiles(LocalFiles):
    def __init__(self, *, mutate_after_download: bool = False):
        self.mutate_after_download = mutate_after_download

    async def exec(self, command, cwd=None, timeout_sec=None, user=None):
        completed = subprocess.run(
            ["/bin/bash", "-c", command],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        return SimpleNamespace(
            return_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    async def download_file(self, source_path, target_path):
        shutil.copyfile(source_path, target_path)
        if self.mutate_after_download:
            Path(source_path).write_bytes(b"changed during download")


class LocalMediaActor(LocalFileActor):
    def __init__(self, workspace: Path, *, mutate_after_download: bool = False):
        RemoteTerminalActor.__init__(
            self,
            LocalMediaFiles(mutate_after_download=mutate_after_download),
        )
        self.workspace = workspace.resolve()
        self._ready = True


class ScriptedSearchActor(LocalFileActor):
    def __init__(
        self,
        workspace: Path,
        *,
        backend: str,
        code: int,
        lines: list[str],
    ):
        super().__init__(workspace)
        self.backend = backend
        self.code = code
        self.lines = lines
        self.argv = []

    async def _grep_backend(self, request):
        return self.backend

    async def _run_bounded_search(self, request, argv, line_limit):
        self.argv = argv
        return self.code, self.lines[:line_limit], len(self.lines) > line_limit


def request(
    workspace: Path,
    tool_name: str,
    arguments: dict[str, object],
    *,
    read_cap: int = 1024,
    output_cap: int = 4096,
    replacement_cap: int = 100,
    media_enabled: bool = False,
) -> ToolRequest:
    arguments_json = json.dumps(arguments, separators=(",", ":"))
    return ToolRequest(
        raw_json=b"{}",
        seq=0,
        run_id="run",
        trial_id="trial",
        attempt_id="attempt",
        call_id=f"call-{tool_name}",
        tool_name=tool_name,
        arguments_json=arguments_json,
        arguments=arguments,
        logical_cwd=str(workspace),
        timeout_ms=1000,
        term_grace_ms=100,
        kill_confirmation_timeout_ms=100,
        stdout_cap_bytes=output_cap,
        stderr_cap_bytes=output_cap,
        arguments_cap_bytes=1024 * 1024,
        max_path_bytes=4096,
        max_read_or_write_bytes=read_cap,
        max_directory_entries=100,
        max_grep_matches=100,
        max_replacements=replacement_cap,
        max_background_processes=8,
        process_spool_bytes_per_process=16 * 1024 * 1024,
        process_spool_bytes_per_run=128 * 1024 * 1024,
        background_output_wait_max_ms=600_000,
        read_file_media_enabled=media_enabled,
    )


def mapping_preflight_fixture(
    *outcomes: object,
    request_timeout_ms: int = 10_000,
) -> tuple[MappingPreflightActor, MappingPreflightRemote, ToolRequest]:
    environment = MappingPreflightRemote(list(outcomes))
    actor = MappingPreflightActor(environment)
    original = request(
        Path("/workspace"),
        "list_dir",
        {"target_directory": "/workspace"},
    )
    tool_request = ToolRequest(
        **{
            **original.__dict__,
            "raw_json": b'{"case":"mapping-preflight"}',
            "timeout_ms": request_timeout_ms,
        }
    )
    return actor, environment, tool_request


def test_setup_maps_logical_workspace_before_using_it_as_exec_cwd() -> None:
    environment = ScriptedRemote(
        [
            SimpleNamespace(
                return_code=0,
                stdout=workspace_setup_stdout(
                    "created_symlink",
                    "/app/personal-site",
                    "/app/personal-site",
                ),
            ),
            SimpleNamespace(return_code=0, stdout=""),
            SimpleNamespace(return_code=0, stdout=""),
        ]
    )
    actor = RemoteTerminalActor(environment)

    asyncio.run(actor.setup())

    assert environment.exec_calls[0][1] is None
    assert "/workspace" in environment.exec_calls[0][0]
    assert actor.diagnostic_metadata() == {
        "workspace_mapping": {
            "canonical_cwd": "/app/personal-site",
            "default_cwd": "/app/personal-site",
            "logical_cwd": "/workspace",
            "mode": "created_symlink",
            "scratch_root": "/tmp",
        },
        "allowed_roots": ["/app/personal-site", "/tmp"],
    }
    assert all(call[1] is None for call in environment.exec_calls)


def test_setup_fails_closed_before_upload_when_workspace_mapping_is_invalid() -> None:
    environment = ScriptedRemote(
        [SimpleNamespace(return_code=91, stdout="", stderr="unsafe default cwd")]
    )
    actor = RemoteTerminalActor(environment)

    with pytest.raises(BridgeError, match="terminal_actor_workspace_setup_failed"):
        asyncio.run(actor.setup())

    assert environment.uploads == []
    assert len(environment.exec_calls) == 1
    assert environment.exec_calls[0][1] is None


@pytest.mark.parametrize(
    ("mode", "default_cwd", "canonical_cwd"),
    [
        ("created_symlink", "/", "/"),
        ("created_symlink", "/app/logs", "/app/logs"),
        ("existing_symlink", "/app/repo", "/other/repo"),
        ("unknown", "/app/repo", "/app/repo"),
    ],
)
def test_setup_rejects_unsafe_or_inconsistent_mapping_evidence(
    mode: str,
    default_cwd: str,
    canonical_cwd: str,
) -> None:
    environment = ScriptedRemote(
        [
            SimpleNamespace(
                return_code=0,
                stdout=workspace_setup_stdout(mode, default_cwd, canonical_cwd),
            )
        ]
    )
    actor = RemoteTerminalActor(environment)

    with pytest.raises(BridgeError, match="terminal_actor_workspace_setup_invalid"):
        asyncio.run(actor.setup())

    assert environment.uploads == []


def test_setup_preserves_existing_real_workspace_over_different_default() -> None:
    environment = ScriptedRemote(
        [
            SimpleNamespace(
                return_code=0,
                stdout=workspace_setup_stdout(
                    "existing_directory",
                    "/app/image-default",
                    "/workspace",
                ),
            ),
            SimpleNamespace(return_code=0, stdout=""),
            SimpleNamespace(return_code=0, stdout=""),
        ]
    )
    actor = RemoteTerminalActor(environment)

    asyncio.run(actor.setup())

    assert actor.diagnostic_metadata()["workspace_mapping"] == {
        "canonical_cwd": "/workspace",
        "default_cwd": "/app/image-default",
        "logical_cwd": "/workspace",
        "mode": "existing_directory",
        "scratch_root": "/tmp",
    }


def test_snapshot_transport_exposes_only_canonical_bounded_operations(
    tmp_path: Path,
) -> None:
    environment = SnapshotRemote(
        [SimpleNamespace(return_code=7, stdout="out", stderr="err")]
    )
    actor = RemoteTerminalActor(environment)
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }

    assert actor.snapshot_workspace_root() == "/app/repo"
    result = asyncio.run(actor.exec_snapshot("printf snapshot", timeout_sec=2.5))
    assert result == SnapshotCommandResult(return_code=7, stdout="out", stderr="err")
    assert environment.exec_calls == [("printf snapshot", "/app/repo", 2.5, None)]
    target = tmp_path / "snapshot"
    asyncio.run(
        actor.download_snapshot(
            "/app/repo/.nano-snapshot",
            target,
        )
    )
    assert target.read_bytes() == b"snapshot"


def test_snapshot_transport_exposes_owned_execution_api() -> None:
    actor = _snapshot_actor(ScriptedRemote([]))

    assert callable(getattr(actor, "exec_snapshot_owned", None))


def _snapshot_actor(environment: ScriptedRemote) -> RemoteTerminalActor:
    actor = RemoteTerminalActor(environment)
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }
    return actor


def _owned_snapshot_actor(
    environment: OwnedSnapshotRemote,
    tokens: list[str] | None = None,
) -> RemoteTerminalActor:
    selected = iter(tokens or ["a" * 64])
    actor = RemoteTerminalActor(
        environment,
        snapshot_token_factory=lambda: next(selected),
    )
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }
    return actor


def test_snapshot_owned_success_returns_zero_census_and_distinct_leases() -> None:
    environment = OwnedSnapshotRemote()
    actor = _owned_snapshot_actor(environment, ["a" * 64, "b" * 64])
    stage = "/tmp/nano-workspace-snapshot-v1.fixture"

    first = asyncio.run(
        actor.exec_snapshot_owned("printf first", stage=stage, timeout_sec=120)
    )
    second = asyncio.run(
        actor.exec_snapshot_owned("printf second", stage=stage, timeout_sec=120)
    )

    assert first == SnapshotCommandResult(
        return_code=0,
        stdout="owned-out",
        stderr="owned-err",
        termination_verified=True,
        census_verified=True,
        survivor_count=0,
    )
    assert second == first
    assert environment.tokens == ["a" * 64, "b" * 64]
    assert actor._active_snapshots == {}
    start_commands = [
        command
        for command, _, _, _ in environment.exec_calls
        if " snapshot-start " in command
    ]
    assert len(start_commands) == 2
    semantic_timeouts = [int(shlex.split(command)[-5]) for command in start_commands]
    assert all(119_000 <= timeout_ms <= 120_000 for timeout_ms in semantic_timeouts)
    modes = [
        located[0]
        for command, _, _, _ in environment.exec_calls
        if (located := environment._mode(shlex.split(command))) is not None
    ]
    assert modes == [
        "snapshot-start",
        "snapshot-release",
        "snapshot-wait",
        "snapshot-start",
        "snapshot-release",
        "snapshot-wait",
    ]


def test_snapshot_owned_clamps_operations_to_absolute_cutoff() -> None:
    environment = OwnedSnapshotRemote()
    actor = RemoteTerminalActor(
        environment,
        snapshot_token_factory=lambda: "a" * 64,
        monotonic=lambda: 100.0,
    )
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }

    asyncio.run(
        actor.exec_snapshot_owned(
            "printf bounded",
            stage="/tmp/nano-workspace-snapshot-v1.fixture",
            timeout_sec=120,
            hard_deadline_monotonic_ns=105_000_000_000,
        )
    )

    assert all(
        timeout_sec is not None and 0 < timeout_sec <= 5.0
        for _, _, timeout_sec, _ in environment.exec_calls
    )
    launch = next(
        command
        for command, _, _, _ in environment.exec_calls
        if " snapshot-start " in command
    )
    assert " 5000 " in launch


def test_snapshot_owned_reserves_hard_cutoff_for_recovery_only() -> None:
    environment = OwnedSnapshotRemote()
    actor = RemoteTerminalActor(
        environment,
        snapshot_token_factory=lambda: "a" * 64,
        monotonic=lambda: 100.0,
    )
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }

    asyncio.run(
        actor.exec_snapshot_owned(
            "printf bounded",
            stage="/tmp/nano-workspace-snapshot-v1.fixture",
            timeout_sec=120,
            capture_deadline_monotonic_ns=103_000_000_000,
            hard_deadline_monotonic_ns=130_000_000_000,
        )
    )

    assert all(
        timeout_sec is not None and 0 < timeout_sec <= 3.0
        for _, _, timeout_sec, _ in environment.exec_calls
    )
    launch = next(
        command
        for command, _, _, _ in environment.exec_calls
        if " snapshot-start " in command
    )
    assert " 3000 " in launch


def test_snapshot_owned_cumulative_setup_uses_one_capture_cutoff() -> None:
    clock = [100.0]

    class CumulativeSetupRemote(OwnedSnapshotRemote):
        async def exec(self, command, cwd=None, timeout_sec=None, user=None):
            result = await super().exec(
                command,
                cwd=cwd,
                timeout_sec=timeout_sec,
                user=user,
            )
            if command.startswith("test -d /tmp/nano-workspace-snapshot-v1."):
                clock[0] += 2.0
            return result

        async def upload_file(self, source_path, target_path):
            await super().upload_file(source_path, target_path)
            clock[0] += 1.0

    environment = CumulativeSetupRemote()
    actor = RemoteTerminalActor(
        environment,
        snapshot_token_factory=lambda: "a" * 64,
        monotonic=lambda: clock[0],
    )
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }

    asyncio.run(
        actor.exec_snapshot_owned(
            "printf cumulative",
            stage="/tmp/nano-workspace-snapshot-v1.fixture",
            timeout_sec=120,
            capture_deadline_monotonic_ns=105_000_000_000,
            hard_deadline_monotonic_ns=127_000_000_000,
        )
    )

    launch = next(
        command
        for command, _, _, _ in environment.exec_calls
        if " snapshot-start " in command
    )
    assert " 2000 " in launch
    assert all(
        timeout_sec is not None and 0 < timeout_sec <= 5.0
        for _, _, timeout_sec, _ in environment.exec_calls
    )


@pytest.mark.parametrize(
    ("fault_point", "expected_subtype"),
    [
        ("upload", SnapshotFailureSubtypeV1.COMMAND_UPLOAD_FAILED),
        ("download", SnapshotFailureSubtypeV1.OUTPUT_DOWNLOAD_FAILED),
    ],
)
def test_snapshot_owned_stalled_transfer_stops_at_capture_cutoff(
    fault_point: str,
    expected_subtype: SnapshotFailureSubtypeV1,
) -> None:
    class StalledTransferRemote(OwnedSnapshotRemote):
        async def upload_file(self, source_path, target_path):
            if fault_point == "upload":
                await asyncio.Future()
            await super().upload_file(source_path, target_path)

        async def download_file(self, source_path, target_path):
            if fault_point == "download":
                await asyncio.Future()
            await super().download_file(source_path, target_path)

    environment = StalledTransferRemote()
    actor = _owned_snapshot_actor(environment)
    actor._monotonic = lambda: 100.0
    started = time.monotonic()

    with pytest.raises(SnapshotOperationFailure) as caught:
        asyncio.run(
            actor.exec_snapshot_owned(
                "printf stalled",
                stage="/tmp/nano-workspace-snapshot-v1.fixture",
                timeout_sec=120,
                capture_deadline_monotonic_ns=100_060_000_000,
                hard_deadline_monotonic_ns=100_500_000_000,
            )
        )

    elapsed = time.monotonic() - started
    assert caught.value.evidence.subtype is expected_subtype
    assert elapsed < 0.25
    assert actor._active_snapshots == {}
    assert not any(
        " snapshot-cancel " in command for command, _, _, _ in environment.exec_calls
    )


def test_snapshot_owned_wait_cutoff_recovers_inside_hard_reserve() -> None:
    environment = OwnedSnapshotRemote(wait_block=True)
    actor = _owned_snapshot_actor(environment)
    actor._monotonic = lambda: 100.0
    started = time.monotonic()

    with pytest.raises(SnapshotTransportTimeout) as caught:
        asyncio.run(
            actor.exec_snapshot_owned(
                "printf stalled",
                stage="/tmp/nano-workspace-snapshot-v1.fixture",
                timeout_sec=120,
                capture_deadline_monotonic_ns=100_060_000_000,
                hard_deadline_monotonic_ns=100_500_000_000,
            )
        )

    elapsed = time.monotonic() - started
    assert (
        caught.value.evidence.timeout_origin
        is SnapshotTimeoutOriginV1.WAIT_TRANSPORT_TIMED_OUT_RECOVERED
    )
    assert elapsed < 0.25
    assert actor._active_snapshots == {}
    wait_timeout = next(
        timeout_sec
        for command, _, timeout_sec, _ in environment.exec_calls
        if " snapshot-wait " in command
    )
    cancel_timeout = next(
        timeout_sec
        for command, _, timeout_sec, _ in environment.exec_calls
        if " snapshot-cancel " in command
    )
    assert wait_timeout is not None and wait_timeout <= 0.06
    assert cancel_timeout == 0.50


def test_snapshot_owned_known_lease_cancel_fits_terminal_reserve() -> None:
    environment = OneShotOwnedFaultRemote("wait_connection")
    actor = _owned_snapshot_actor(environment)
    actor._monotonic = lambda: 100.0

    with pytest.raises(SnapshotOperationFailure):
        asyncio.run(
            actor.exec_snapshot_owned(
                "printf recover",
                stage="/tmp/nano-workspace-snapshot-v1.fixture",
                timeout_sec=120,
                capture_deadline_monotonic_ns=110_000_000_000,
                hard_deadline_monotonic_ns=115_000_000_000,
            )
        )

    cancel_timeout = next(
        timeout_sec
        for command, _, timeout_sec, _ in environment.exec_calls
        if " snapshot-cancel " in command
    )
    assert cancel_timeout == 15.0


def test_snapshot_owned_unknown_lease_shares_one_recovery_cutoff() -> None:
    clock = [100.0]

    class MaxInspectRemote(OneShotOwnedFaultRemote):
        async def exec(self, command, cwd=None, timeout_sec=None, user=None):
            result = await super().exec(
                command,
                cwd=cwd,
                timeout_sec=timeout_sec,
                user=user,
            )
            located = self._mode(shlex.split(command))
            if located is not None and located[0] == "snapshot-inspect":
                clock[0] += 10.0
            return result

    environment = MaxInspectRemote("launch_nonzero")
    actor = _owned_snapshot_actor(environment)
    actor._monotonic = lambda: clock[0]

    with pytest.raises(SnapshotOperationFailure):
        asyncio.run(
            actor.exec_snapshot_owned(
                "printf recover",
                stage="/tmp/nano-workspace-snapshot-v1.fixture",
                timeout_sec=120,
                capture_deadline_monotonic_ns=110_000_000_000,
                hard_deadline_monotonic_ns=115_000_000_000,
            )
        )

    recovery_timeouts = {
        located[0]: timeout_sec
        for command, _, timeout_sec, _ in environment.exec_calls
        if (located := environment._mode(shlex.split(command))) is not None
        and located[0] in {"snapshot-inspect", "snapshot-cancel"}
    }
    assert recovery_timeouts == {
        "snapshot-inspect": 10.0,
        "snapshot-cancel": 5.0,
    }


def test_snapshot_owned_budget_expiry_before_setup_leaves_no_active_lease() -> None:
    ticks = iter((100.0, 106.0))
    environment = OwnedSnapshotRemote()
    actor = RemoteTerminalActor(
        environment,
        snapshot_token_factory=lambda: "a" * 64,
        monotonic=lambda: next(ticks),
    )
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }

    with pytest.raises(SnapshotTransportTimeout) as caught:
        asyncio.run(
            actor.exec_snapshot_owned(
                "printf bounded",
                stage="/tmp/nano-workspace-snapshot-v1.fixture",
                timeout_sec=120,
                hard_deadline_monotonic_ns=105_000_000_000,
            )
        )

    assert caught.value.evidence.termination_verified is True
    assert caught.value.evidence.zero_census_verified is True
    assert actor._active_snapshots == {}
    assert environment.exec_calls == []


@pytest.mark.parametrize(
    ("fault_point", "expected_subtype"),
    [
        ("launch_nonzero", SnapshotFailureSubtypeV1.LAUNCH_FAILED),
        ("lease_parse", SnapshotFailureSubtypeV1.LEASE_PARSE_FAILED),
        ("release", SnapshotFailureSubtypeV1.LEASE_RELEASE_FAILED),
        ("wait_connection", SnapshotFailureSubtypeV1.WAIT_TRANSPORT_FAILED),
        ("wait_invalid", SnapshotFailureSubtypeV1.WAIT_RESPONSE_INVALID),
        ("terminal_invalid", SnapshotFailureSubtypeV1.TERMINAL_RECORD_INVALID),
    ],
)
def test_snapshot_owned_recovery_preserves_exact_boundary_subtype(
    fault_point: str,
    expected_subtype: SnapshotFailureSubtypeV1,
) -> None:
    environment = OneShotOwnedFaultRemote(fault_point)
    actor = _owned_snapshot_actor(environment)

    with pytest.raises(SnapshotOperationFailure) as caught:
        asyncio.run(
            actor.exec_snapshot_owned(
                "printf fault",
                stage="/tmp/nano-workspace-snapshot-v1.fixture",
                timeout_sec=120,
            )
        )

    error = caught.value
    assert error.evidence.subtype is expected_subtype
    assert error.evidence.timeout_origin is SnapshotTimeoutOriginV1.NOT_A_TIMEOUT
    assert error.evidence.stage_validated is True
    assert error.evidence.termination_verified is True
    assert error.evidence.cleanup_verified is False
    assert error.evidence.zero_census_verified is True
    assert error.evidence.execution_binding_verified is True
    assert "secret wait transport" not in str(error)
    assert actor._active_snapshots == {}


def test_snapshot_recovery_preserves_known_reason_and_marks_unknown_input() -> None:
    actor = _owned_snapshot_actor(OwnedSnapshotRemote())
    known = SnapshotTerminationUnverified(
        terminal_actor.SnapshotFailureEvidenceV1(
            subtype=SnapshotFailureSubtypeV1.LEASE_PARSE_FAILED,
            reason=terminal_actor.SnapshotFailureReasonV1.TERMINAL_JSON_INVALID,
            observed_byte_length=1,
            observed_sha256=hashlib.sha256(b"{").hexdigest(),
        )
    )

    with pytest.raises(SnapshotOperationFailure) as known_caught:
        asyncio.run(
            actor._raise_after_snapshot_recovery(
                known,
                {"status": "completed"},
            )
        )
    assert (
        known_caught.value.evidence.subtype
        is SnapshotFailureSubtypeV1.LEASE_PARSE_FAILED
    )
    assert (
        known_caught.value.evidence.reason
        is terminal_actor.SnapshotFailureReasonV1.TERMINAL_JSON_INVALID
    )
    assert known_caught.value.evidence.termination_verified is True
    assert known_caught.value.evidence.zero_census_verified is True
    assert known_caught.value.evidence.execution_binding_verified is False

    class ForgedTerminal(dict[str, object]):
        execution_binding_verified = True

    with pytest.raises(SnapshotOperationFailure) as forged_caught:
        asyncio.run(
            actor._raise_after_snapshot_recovery(
                known,
                ForgedTerminal(status="completed"),
            )
        )
    assert forged_caught.value.evidence.execution_binding_verified is False

    with pytest.raises(SnapshotOperationFailure) as unknown_caught:
        asyncio.run(
            actor._raise_after_snapshot_recovery(
                RuntimeError("unclassified"),
                {"status": "completed"},
            )
        )
    assert (
        unknown_caught.value.evidence.subtype
        is SnapshotFailureSubtypeV1.UNKNOWN_INTERNAL
    )
    assert (
        unknown_caught.value.evidence.reason
        is terminal_actor.SnapshotFailureReasonV1.UNKNOWN
    )
    assert unknown_caught.value.evidence.execution_binding_verified is False


def test_snapshot_owned_recovered_wait_timeout_has_exact_origin() -> None:
    environment = OneShotOwnedFaultRemote("wait_timeout")
    actor = _owned_snapshot_actor(environment)

    with pytest.raises(SnapshotTransportTimeout) as caught:
        asyncio.run(
            actor.exec_snapshot_owned(
                "printf timeout",
                stage="/tmp/nano-workspace-snapshot-v1.fixture",
                timeout_sec=120,
            )
        )

    assert (
        caught.value.evidence.timeout_origin
        is SnapshotTimeoutOriginV1.WAIT_TRANSPORT_TIMED_OUT_RECOVERED
    )
    assert caught.value.evidence.termination_verified is True
    assert caught.value.evidence.zero_census_verified is True
    assert caught.value.evidence.execution_binding_verified is True
    assert actor._active_snapshots == {}


def test_snapshot_owned_setup_upload_and_output_faults_are_exact() -> None:
    class SetupFailureRemote(OwnedSnapshotRemote):
        async def exec(self, command, cwd=None, timeout_sec=None, user=None):
            if command.startswith("test -d /tmp/nano-workspace-snapshot-v1."):
                self.exec_calls.append((command, cwd, timeout_sec, user))
                return SimpleNamespace(return_code=71, stdout="", stderr="")
            return await super().exec(
                command,
                cwd=cwd,
                timeout_sec=timeout_sec,
                user=user,
            )

    class UploadFailureRemote(OwnedSnapshotRemote):
        async def upload_file(self, source_path, target_path):
            raise OSError("secret upload failure")

    class OutputFailureRemote(OwnedSnapshotRemote):
        async def download_file(self, source_path, target_path):
            raise OSError("secret output failure")

    for remote, subtype in (
        (
            SetupFailureRemote(),
            SnapshotFailureSubtypeV1.OWNED_STAGE_SETUP_FAILED,
        ),
        (
            UploadFailureRemote(),
            SnapshotFailureSubtypeV1.COMMAND_UPLOAD_FAILED,
        ),
        (
            OutputFailureRemote(),
            SnapshotFailureSubtypeV1.OUTPUT_DOWNLOAD_FAILED,
        ),
    ):
        actor = _owned_snapshot_actor(remote)
        with pytest.raises(SnapshotOperationFailure) as caught:
            asyncio.run(
                actor.exec_snapshot_owned(
                    "printf fault",
                    stage="/tmp/nano-workspace-snapshot-v1.fixture",
                    timeout_sec=120,
                )
            )
        assert caught.value.evidence.subtype is subtype
        assert caught.value.evidence.stage_validated is True
        assert caught.value.evidence.termination_verified is True
        assert caught.value.evidence.zero_census_verified is True
        assert "secret" not in str(caught.value)
        assert actor._active_snapshots == {}


def test_snapshot_owned_recovery_failure_dominates_with_closed_subtype() -> None:
    environment = OneShotOwnedFaultRemote(
        "wait_connection",
        cancel_return_code=92,
    )
    actor = _owned_snapshot_actor(environment)

    with pytest.raises(SnapshotTerminationUnverified) as caught:
        asyncio.run(
            actor.exec_snapshot_owned(
                "printf recovery",
                stage="/tmp/nano-workspace-snapshot-v1.fixture",
                timeout_sec=120,
            )
        )

    assert caught.value.evidence.subtype is SnapshotFailureSubtypeV1.RECOVERY_UNVERIFIED
    assert caught.value.evidence.termination_verified is False
    assert caught.value.evidence.zero_census_verified is False
    assert actor._active_snapshots


def test_unverified_snapshot_failure_proofs_default_closed() -> None:
    error = SnapshotTerminationUnverified()

    assert error.evidence.stage_validated is False
    assert error.evidence.termination_verified is False
    assert error.evidence.cleanup_verified is False
    assert error.evidence.zero_census_verified is False


@pytest.mark.parametrize(
    ("kill_sent", "expected_signals"),
    [(False, ("TERM",)), (True, ("TERM", "KILL"))],
    ids=["term-settles", "term-ignored-kill-settles"],
)
def test_snapshot_owned_timeout_requires_term_kill_zero_census(
    kill_sent: bool,
    expected_signals: tuple[str, ...],
) -> None:
    environment = OwnedSnapshotRemote(
        status="timed_out",
        term_sent=True,
        kill_sent=kill_sent,
    )
    actor = _owned_snapshot_actor(environment)

    with pytest.raises(SnapshotTransportTimeout) as caught:
        asyncio.run(
            actor.exec_snapshot_owned(
                "sleep 999",
                stage="/tmp/nano-workspace-snapshot-v1.fixture",
                timeout_sec=120,
            )
        )

    error = caught.value
    assert error.evidence.termination_verified is True
    assert error.evidence.zero_census_verified is True
    terminal = environment._terminal("a" * 64)
    observed = tuple(
        signal
        for signal, sent in (
            ("TERM", terminal["term_sent"]),
            ("KILL", terminal["kill_sent"]),
        )
        if sent
    )
    assert observed == expected_signals
    assert actor._active_snapshots == {}


def test_snapshot_owned_cancellation_settles_before_cancel_propagates() -> None:
    environment = OwnedSnapshotRemote(status="cancelled", wait_block=True)
    actor = _owned_snapshot_actor(environment)

    async def run() -> asyncio.CancelledError:
        task = asyncio.create_task(
            actor.exec_snapshot_owned(
                "sleep 999",
                stage="/tmp/nano-workspace-snapshot-v1.fixture",
                timeout_sec=120,
            )
        )
        await environment.wait_entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError) as caught:
            await task
        return caught.value

    error = asyncio.run(run())

    assert error.evidence.termination_verified is True
    assert error.evidence.zero_census_verified is True
    assert actor._active_snapshots == {}
    assert any(
        " snapshot-cancel " in command for command, _, _, _ in environment.exec_calls
    )


def test_snapshot_owned_repeated_cancellation_cannot_detach_recovery() -> None:
    class SlowCancelRemote(OwnedSnapshotRemote):
        def __init__(self) -> None:
            super().__init__(status="cancelled", wait_block=True)
            self.cancel_entered = asyncio.Event()
            self.cancel_release = asyncio.Event()

        async def exec(self, command, cwd=None, timeout_sec=None, user=None):
            located = self._mode(shlex.split(command))
            if located is not None and located[0] == "snapshot-cancel":
                self.cancel_entered.set()
                await self.cancel_release.wait()
            return await super().exec(
                command,
                cwd=cwd,
                timeout_sec=timeout_sec,
                user=user,
            )

    environment = SlowCancelRemote()
    actor = _owned_snapshot_actor(environment)

    async def run() -> BaseException:
        task = asyncio.create_task(
            actor.exec_snapshot_owned(
                "sleep 999",
                stage="/tmp/nano-workspace-snapshot-v1.fixture",
                timeout_sec=120,
            )
        )
        await environment.wait_entered.wait()
        task.cancel()
        await environment.cancel_entered.wait()
        task.cancel()
        environment.cancel_release.set()
        with pytest.raises(asyncio.CancelledError) as caught:
            await task
        return caught.value

    error = asyncio.run(run())

    assert error.evidence.termination_verified is True
    assert error.evidence.zero_census_verified is True
    assert actor._active_snapshots == {}


@pytest.mark.parametrize(
    "remote",
    [
        OwnedSnapshotRemote(terminal_patch={"leader_starttime": 99999}),
        OwnedSnapshotRemote(terminal_patch={"owner_token": "f" * 64}),
        OwnedSnapshotRemote(terminal_patch={"pgid": 4999}),
        OwnedSnapshotRemote(terminal_drop={"status"}),
        OwnedSnapshotRemote(terminal_patch={"termination_verified": False}),
        OwnedSnapshotRemote(terminal_patch={"census_verified": False}),
        OwnedSnapshotRemote(terminal_patch={"survivor_count": 1}),
        OwnedSnapshotRemote(terminal_patch={"timed_out": True}),
    ],
    ids=[
        "pid-reuse-starttime",
        "wrong-token",
        "wrong-pgid",
        "missing-status",
        "termination-failure",
        "census-failure",
        "survivor",
        "inconsistent-status",
    ],
)
def test_snapshot_owned_identity_status_or_census_failure_is_fatal(
    remote: OwnedSnapshotRemote,
) -> None:
    actor = _owned_snapshot_actor(remote)

    with pytest.raises(SnapshotTerminationUnverified) as caught:
        asyncio.run(
            actor.exec_snapshot_owned(
                "sleep 999",
                stage="/tmp/nano-workspace-snapshot-v1.fixture",
                timeout_sec=120,
            )
        )

    assert caught.value.evidence.termination_verified is False
    assert caught.value.evidence.zero_census_verified is False
    assert actor._active_snapshots


def test_snapshot_owned_cancel_cleanup_failure_dominates_cancellation() -> None:
    environment = OwnedSnapshotRemote(
        status="cancelled",
        wait_block=True,
        cancel_return_code=92,
    )
    actor = _owned_snapshot_actor(environment)

    async def run() -> BaseException:
        task = asyncio.create_task(
            actor.exec_snapshot_owned(
                "sleep 999",
                stage="/tmp/nano-workspace-snapshot-v1.fixture",
                timeout_sec=120,
            )
        )
        await environment.wait_entered.wait()
        task.cancel()
        with pytest.raises(SnapshotTerminationUnverified) as caught:
            await task
        return caught.value

    error = asyncio.run(run())

    assert isinstance(error.__cause__, BaseException)
    assert actor._active_snapshots


def test_snapshot_supervisor_targets_only_exact_identity() -> None:
    assert "pkill" not in _ACTOR
    assert "killall" not in _ACTOR
    assert 'kill -TERM -- "-$pgid"' in _ACTOR
    assert 'kill -KILL -- "-$pgid"' in _ACTOR
    assert 'NANO_NGB_OWNER="$owner_token"' in _ACTOR
    assert "snapshot_pid_identity_matches" in _ACTOR
    assert "snapshot_pid_identity_state" in _ACTOR
    assert "snapshot_identity_files_match" in _ACTOR
    wait_section = _ACTOR.split('if [ "$mode" = "snapshot-wait" ]; then', 1)[1].split(
        'if [ "$mode" = "snapshot-cleanup-signal" ]; then',
        1,
    )[0]
    assert 'if pid_alive "$expected_supervisor_pid"' not in wait_section
    assert 'snapshot_pid_identity_state \\\n      "$expected_supervisor_pid"' in (
        wait_section
    )


def test_snapshot_exact_harbor_timeout_wrapper_is_normalized() -> None:
    original = RuntimeError("Command timed out after 120.0 seconds")
    environment = RaisingSnapshotRemote(original)
    actor = _snapshot_actor(environment)

    with pytest.raises(BaseException) as caught:
        asyncio.run(actor.exec_snapshot("printf snapshot", timeout_sec=120))

    error = caught.value
    assert type(error) is SnapshotTransportTimeout
    assert isinstance(error, TimeoutError)
    assert error.code == "terminal_actor_snapshot_transport_timeout"
    assert str(error) == "terminal_actor_snapshot_transport_timeout"
    assert error.__cause__ is original
    assert environment.exec_calls == [("printf snapshot", "/app/repo", 120.0, None)]


class _RuntimeErrorSubclass(RuntimeError):
    pass


class _TimeoutErrorSubclass(TimeoutError):
    pass


class _TimeoutExpiredSubclass(subprocess.TimeoutExpired):
    pass


@pytest.mark.parametrize(
    "original",
    [
        RuntimeError("generic transport failure"),
        _RuntimeErrorSubclass("Command timed out after 120.0 seconds"),
        RuntimeError("Command timed out after 120 seconds"),
        RuntimeError("Command timed out after 119.0 seconds"),
    ],
    ids=["generic", "subclass", "near-miss", "timeout-mismatch"],
)
def test_snapshot_timeout_wrapper_mismatches_pass_through(
    original: RuntimeError,
) -> None:
    actor = _snapshot_actor(RaisingSnapshotRemote(original))

    with pytest.raises(type(original)) as caught:
        asyncio.run(actor.exec_snapshot("printf snapshot", timeout_sec=120))

    assert caught.value is original


def test_snapshot_native_timeout_and_non_snapshot_exec_are_unchanged() -> None:
    native = TimeoutError("Command timed out after 120.0 seconds")
    actor = _snapshot_actor(RaisingSnapshotRemote(native))
    with pytest.raises(TimeoutError) as caught:
        asyncio.run(actor.exec_snapshot("printf snapshot", timeout_sec=120))
    assert caught.value is native

    wrapper = RuntimeError("Command timed out after 1.0 seconds")
    actor = _snapshot_actor(RaisingSnapshotRemote(wrapper))
    with pytest.raises(
        BridgeError,
        match="^terminal_actor_workspace_mapping_changed$",
    ) as caught:
        asyncio.run(
            actor.execute(
                request(Path("/workspace"), "list_dir", {"path": "/workspace"})
            )
        )
    assert caught.value.__cause__ is wrapper


@pytest.mark.skipif(
    os.environ.get("NANO_RUN_DOCKER_TESTS") != "1",
    reason="set NANO_RUN_DOCKER_TESTS=1 for the real-Docker regression",
)
def test_real_docker_snapshot_owned_supervisor_term_kill_and_census() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker CLI is unavailable")
    if subprocess.run(
        ["docker", "info"],
        capture_output=True,
        check=False,
    ).returncode:
        pytest.skip("docker daemon is unavailable")
    image = os.environ.get(
        "NANO_DOCKER_REGRESSION_IMAGE",
        "alexgshaw/fix-git:20260403",
    )
    if subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True,
        check=False,
    ).returncode:
        pytest.skip(f"cached regression image is unavailable: {image}")
    tokens = ["a" * 64, "b" * 64, "c" * 64]
    selected_tokens = iter(tokens)
    container_id = ""
    sentinel_pid = ""
    try:
        container_id = subprocess.run(
            ["docker", "run", "--detach", "--rm", image, "sleep", "infinity"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        environment = DockerExecRemote(container_id)
        actor = RemoteTerminalActor(
            environment,
            snapshot_token_factory=lambda: next(selected_tokens),
        )
        asyncio.run(actor.setup())

        def stage(label: str) -> str:
            created = asyncio.run(
                environment.exec(
                    f"mktemp -d /tmp/nano-workspace-snapshot-v1.docker-{label}.XXXXXX",
                    timeout_sec=5,
                )
            )
            assert created.return_code == 0
            return created.stdout.strip()

        success_stage = stage("success")
        result = asyncio.run(
            actor.exec_snapshot_owned(
                "printf 'snapshot-ok\\n'",
                stage=success_stage,
                timeout_sec=2,
            )
        )
        assert result.stdout == "snapshot-ok\n"
        assert result.termination_verified is True
        assert result.census_verified is True
        assert result.survivor_count == 0

        sentinel = asyncio.run(
            environment.exec(
                "setsid /bin/bash -c 'trap \"\" TERM; sleep 60' "
                "</dev/null >/dev/null 2>&1 & printf '%s\\n' \"$!\"",
                timeout_sec=5,
            )
        )
        assert sentinel.return_code == 0
        sentinel_pid = sentinel.stdout.strip()
        assert sentinel_pid.isdigit()

        for index, (label, command, kill_expected) in enumerate(
            (
                (
                    "term",
                    "trap 'exit 0' TERM; while :; do sleep 0.05; done",
                    False,
                ),
                (
                    "kill",
                    "trap '' TERM; while :; do sleep 0.05; done",
                    True,
                ),
            ),
            start=1,
        ):
            timeout_stage = stage(label)
            with pytest.raises(SnapshotTransportTimeout) as caught:
                asyncio.run(
                    actor.exec_snapshot_owned(
                        command,
                        stage=timeout_stage,
                        timeout_sec=0.2,
                    )
                )
            assert caught.value.evidence.termination_verified is True
            control_dir = f"{timeout_stage}/.nano-snapshot-execution-{tokens[index]}"
            terminal_result = asyncio.run(
                environment.exec(
                    f"cat -- {shlex.quote(control_dir + '/terminal.json')}",
                    timeout_sec=5,
                )
            )
            assert terminal_result.return_code == 0
            terminal = json.loads(terminal_result.stdout)
            assert terminal["status"] == "timed_out"
            assert terminal["term_sent"] is True
            assert terminal["kill_sent"] is kill_expected
            assert terminal["termination_verified"] is True
            assert terminal["census_verified"] is True
            assert terminal["survivor_count"] == 0
            sentinel_alive = asyncio.run(
                environment.exec(
                    f"kill -0 {sentinel_pid}",
                    timeout_sec=5,
                )
            )
            assert sentinel_alive.return_code == 0
        assert asyncio.run(actor.cleanup_active()) is True
    finally:
        if container_id:
            if sentinel_pid.isdigit():
                subprocess.run(
                    [
                        "docker",
                        "exec",
                        container_id,
                        "/bin/bash",
                        "-c",
                        f"kill -KILL -- -{sentinel_pid} 2>/dev/null || true",
                    ],
                    capture_output=True,
                    check=False,
                )
            subprocess.run(
                ["docker", "rm", "--force", container_id],
                capture_output=True,
                check=False,
            )


@pytest.mark.skipif(
    os.environ.get("NANO_RUN_DOCKER_TESTS") != "1",
    reason="set NANO_RUN_DOCKER_TESTS=1 for the real-Docker regression",
)
def test_real_docker_nonstandard_workdir_maps_all_tools_and_fails_on_tamper(
    tmp_path: Path,
) -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker CLI is unavailable")
    if subprocess.run(
        ["docker", "info"],
        capture_output=True,
        check=False,
    ).returncode:
        pytest.skip("docker daemon is unavailable")
    image = os.environ.get(
        "NANO_DOCKER_REGRESSION_IMAGE",
        "alexgshaw/fix-git:20260403",
    )
    if subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True,
        check=False,
    ).returncode:
        pytest.skip(f"cached regression image is unavailable: {image}")
    architecture = subprocess.run(
        [
            "docker",
            "image",
            "inspect",
            image,
            "--format",
            "{{.Architecture}}",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    container_id = ""
    try:
        run_argv = ["docker", "run", "--detach", "--rm"]
        if architecture:
            run_argv.extend(["--platform", f"linux/{architecture}"])
        run_argv.extend([image, "sleep", "infinity"])
        container_id = subprocess.run(
            run_argv,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        environment = DockerExecRemote(container_id)
        actor = RemoteTerminalActor(environment)
        asyncio.run(actor.setup())
        assert actor.diagnostic_metadata()["workspace_mapping"] == {
            "canonical_cwd": "/app/personal-site",
            "default_cwd": "/app/personal-site",
            "logical_cwd": "/workspace",
            "mode": "created_symlink",
            "scratch_root": "/tmp",
        }
        assert actor.diagnostic_metadata()["allowed_roots"] == [
            "/app/personal-site",
            "/tmp",
        ]

        request_index = 0

        def tool_request(
            tool_name: str,
            arguments: dict[str, object],
        ) -> ToolRequest:
            nonlocal request_index
            request_index += 1
            original = request(Path("/workspace"), tool_name, arguments)
            return ToolRequest(
                **{
                    **original.__dict__,
                    "raw_json": json.dumps(
                        {"docker_case": request_index},
                        separators=(",", ":"),
                    ).encode(),
                    "timeout_ms": 10_000,
                    "kill_confirmation_timeout_ms": 1000,
                }
            )

        foreground = asyncio.run(
            actor.execute(
                tool_request(
                    "run_terminal_command",
                    {
                        "command": (
                            "pwd -P; test -f /workspace/index.md; "
                            "printf 'logical-ok\\n'"
                        )
                    },
                )
            )
        )
        assert foreground.return_code == 0
        assert foreground.stdout == b"/app/personal-site\nlogical-ok\n"
        assert foreground.survivor_count == 0

        background = asyncio.run(
            actor.execute(
                tool_request(
                    "run_terminal_command",
                    {
                        "command": ("exec -a nano-cwd-docker-regression sleep 60"),
                        "description": "exercise mapped background cwd",
                        "background": True,
                        "timeout": 0,
                    },
                )
            )
        )
        assert background.process_disposition is ProcessDisposition.BACKGROUND_RETAINED
        assert background.target_task_id is not None
        snapshot = asyncio.run(
            actor.execute(
                tool_request(
                    "get_terminal_command_output",
                    {
                        "task_ids": [background.target_task_id],
                        "timeout_ms": 0,
                    },
                )
            )
        )
        assert b"Status: running" in snapshot.stdout
        killed = asyncio.run(
            actor.execute(
                tool_request(
                    "kill_terminal_command",
                    {"task_id": background.target_task_id},
                )
            )
        )
        assert killed.process_disposition is ProcessDisposition.BACKGROUND_TERMINATED

        read = asyncio.run(
            actor.execute(
                tool_request(
                    "read_file",
                    {"target_file": "/workspace/index.md", "limit": 1},
                )
            )
        )
        assert read.return_code == 0
        assert read.stdout.startswith("1→".encode())
        written = asyncio.run(
            actor.execute(
                tool_request(
                    "write",
                    {
                        "file_path": "/workspace/generated.txt",
                        "content": "before needle\n",
                    },
                )
            )
        )
        assert written.return_code == 0
        replaced = asyncio.run(
            actor.execute(
                tool_request(
                    "search_replace",
                    {
                        "file_path": "/workspace/generated.txt",
                        "old_string": "before",
                        "new_string": "after",
                    },
                )
            )
        )
        assert replaced.return_code == 0
        listed = asyncio.run(
            actor.execute(
                tool_request(
                    "list_dir",
                    {"target_directory": "/workspace"},
                )
            )
        )
        assert b"generated.txt" in listed.stdout
        found = asyncio.run(
            actor.execute(
                tool_request(
                    "grep",
                    {"pattern": "after", "path": "/workspace"},
                )
            )
        )
        assert b"generated.txt:1:after needle" in found.stdout

        scratch_written = asyncio.run(
            actor.execute(
                tool_request(
                    "write",
                    {
                        "file_path": "/tmp/nano-scratch.txt",
                        "content": "scratch needle\n",
                    },
                )
            )
        )
        assert scratch_written.return_code == 0
        scratch_read = asyncio.run(
            actor.execute(
                tool_request(
                    "read_file",
                    {"target_file": "/tmp/nano-scratch.txt", "limit": 1},
                )
            )
        )
        assert scratch_read.stdout == "1→scratch needle\n".encode()
        scratch_found = asyncio.run(
            actor.execute(
                tool_request(
                    "grep",
                    {"pattern": "scratch needle", "path": "/tmp/nano-scratch.txt"},
                )
            )
        )
        assert b"/tmp/nano-scratch.txt:1:scratch needle" in scratch_found.stdout
        scratch_control = asyncio.run(
            actor.execute(
                tool_request(
                    "write",
                    {
                        "file_path": "/tmp/nano-grok-build-terminal-v1/escape",
                        "content": "blocked",
                    },
                )
            )
        )
        assert scratch_control.return_code == 2
        assert scratch_control.stdout == b"path_outside_workspace"

        tamper = asyncio.run(
            actor.execute(
                tool_request(
                    "run_terminal_command",
                    {"command": "unlink /workspace && ln -s /tmp /workspace"},
                )
            )
        )
        assert tamper.return_code == 0
        with pytest.raises(
            BridgeError,
            match="terminal_actor_workspace_mapping_changed",
        ):
            asyncio.run(
                actor.execute(
                    tool_request(
                        "write",
                        {
                            "file_path": "/workspace/nano-cwd-escape",
                            "content": "blocked",
                        },
                    )
                )
            )
        no_escape = asyncio.run(
            environment.exec("test ! -e /tmp/nano-cwd-escape", timeout_sec=5)
        )
        assert no_escape.return_code == 0
        assert asyncio.run(actor.cleanup_active()) is True
        census = asyncio.run(
            environment.exec(
                "for path in /proc/[0-9]*/cmdline; do "
                "value=$(tr '\\0' ' ' < \"$path\" 2>/dev/null || true); "
                'case "$value" in *[n]ano-cwd-docker-regression*) exit 1;; esac; '
                "done",
                timeout_sec=5,
            )
        )
        assert census.return_code == 0
    finally:
        if container_id:
            subprocess.run(
                ["docker", "rm", "--force", container_id],
                capture_output=True,
                check=False,
            )


@pytest.mark.skipif(
    os.environ.get("NANO_RUN_DOCKER_TESTS") != "1",
    reason="set NANO_RUN_DOCKER_TESTS=1 for the real-Docker regression",
)
def test_real_docker_c1_mapping_preflight_load_is_bounded_to_23_calls() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker CLI is unavailable")
    if subprocess.run(
        ["docker", "info"],
        capture_output=True,
        check=False,
    ).returncode:
        pytest.skip("docker daemon is unavailable")
    image = os.environ.get(
        "NANO_DOCKER_REGRESSION_IMAGE",
        "alexgshaw/fix-git:20260403",
    )
    if subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True,
        check=False,
    ).returncode:
        pytest.skip(f"cached regression image is unavailable: {image}")
    architecture = subprocess.run(
        [
            "docker",
            "image",
            "inspect",
            image,
            "--format",
            "{{.Architecture}}",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    container_id = ""
    load_pgid = ""
    try:
        run_argv = ["docker", "run", "--detach", "--rm", "--cpus=1"]
        if architecture:
            run_argv.extend(["--platform", f"linux/{architecture}"])
        run_argv.extend([image, "sleep", "infinity"])
        container_id = subprocess.run(
            run_argv,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        environment = DockerExecRemote(container_id)
        actor = C1DockerMappingActor(environment)
        asyncio.run(actor.setup())

        request_index = 0

        def tool_request() -> ToolRequest:
            nonlocal request_index
            request_index += 1
            original = request(
                Path("/workspace"),
                "list_dir",
                {"target_directory": "/workspace"},
            )
            return ToolRequest(
                **{
                    **original.__dict__,
                    "raw_json": json.dumps(
                        {"c1_mapping_call": request_index},
                        separators=(",", ":"),
                    ).encode(),
                    "call_id": f"c1-mapping-{request_index}",
                    "timeout_ms": 10_000,
                }
            )

        def preflight_calls() -> int:
            return sum(
                "actual=$(realpath -e -- /workspace)" in command
                for command, *_ in environment.exec_calls
            )

        no_load_before = preflight_calls()
        no_load = asyncio.run(actor.execute(tool_request()))
        assert no_load.return_code == 0
        assert preflight_calls() - no_load_before == 1
        assert len(actor.user_effects) == 1

        load = asyncio.run(
            environment.exec(
                "\n".join(
                    [
                        "set -eu",
                        "setsid /bin/bash -c '",
                        '  trap "exit 0" TERM',
                        "  for index in $(seq 1 14); do",
                        '    /bin/bash -c "while :; do :; done" '
                        "</dev/null >/dev/null 2>&1 &",
                        "  done",
                        "  wait",
                        "' </dev/null >/dev/null 2>&1 &",
                        'printf "%s\\n" "$!"',
                    ]
                ),
                timeout_sec=5,
            )
        )
        assert load.return_code == 0
        load_pgid = load.stdout.strip()
        assert load_pgid.isdigit()

        worker_count = 0
        worker_deadline = time.monotonic() + 5
        while time.monotonic() < worker_deadline:
            top = subprocess.run(
                ["docker", "top", container_id, "-eo", "pid,args"],
                check=True,
                capture_output=True,
                text=True,
            )
            worker_count = top.stdout.count("while :; do :; done")
            if worker_count >= 14:
                break
            time.sleep(0.05)
        assert worker_count >= 14

        load_attempts: list[int] = []
        load_successes = 0
        for _ in range(10):
            calls_before = preflight_calls()
            effects_before = len(actor.user_effects)
            try:
                result = asyncio.run(actor.execute(tool_request()))
            except ToolFatalError as error:
                assert error.failure == ToolFailure(
                    code="terminal_actor_workspace_mapping_check_timeout",
                    execution_may_have_started=False,
                    cleanup_verified=None,
                    census_verified=None,
                )
                assert len(actor.user_effects) == effects_before
            else:
                assert result.return_code == 0
                assert len(actor.user_effects) == effects_before + 1
                load_successes += 1
            attempts = preflight_calls() - calls_before
            assert attempts in {1, 2}
            load_attempts.append(attempts)

        stopped = asyncio.run(
            environment.exec(
                f"kill -TERM -- -{load_pgid}",
                timeout_sec=15,
            )
        )
        assert stopped.return_code == 0
        marker_deadline = time.monotonic() + 5
        while time.monotonic() < marker_deadline:
            top = subprocess.run(
                ["docker", "top", container_id, "-eo", "pid,args"],
                check=True,
                capture_output=True,
                text=True,
            )
            if "while :; do :; done" not in top.stdout:
                break
            time.sleep(0.05)
        assert "while :; do :; done" not in top.stdout

        recovery_before = preflight_calls()
        effects_before = len(actor.user_effects)
        recovery = asyncio.run(actor.execute(tool_request()))
        assert recovery.return_code == 0
        assert preflight_calls() - recovery_before == 1
        assert len(actor.user_effects) == effects_before + 1

        tamper = asyncio.run(
            environment.exec(
                "unlink /workspace && ln -s /tmp /workspace",
                timeout_sec=5,
            )
        )
        assert tamper.return_code == 0
        mismatch_before = preflight_calls()
        effects_before = len(actor.user_effects)
        with pytest.raises(
            BridgeError,
            match="^terminal_actor_workspace_mapping_changed$",
        ):
            asyncio.run(actor.execute(tool_request()))
        assert preflight_calls() - mismatch_before == 1
        assert len(actor.user_effects) == effects_before

        assert len(actor.user_effects) == load_successes + 2
        assert sum(load_attempts) + 3 <= 23
        assert preflight_calls() <= 23
        assert asyncio.run(actor.cleanup_active()) is True
    finally:
        if container_id:
            subprocess.run(
                ["docker", "rm", "--force", container_id],
                capture_output=True,
                check=False,
            )


@pytest.mark.skipif(
    os.environ.get("NANO_RUN_DOCKER_TESTS") != "1",
    reason="set NANO_RUN_DOCKER_TESTS=1 for the real-Docker regression",
)
@pytest.mark.parametrize("residual_kind", ["same_pgid", "exact_owner_new_pgid"])
def test_foreground_residual_real_docker_is_cleaned_without_touching_unrelated(
    residual_kind: str,
) -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker CLI is unavailable")
    if subprocess.run(
        ["docker", "info"],
        capture_output=True,
        check=False,
    ).returncode:
        pytest.skip("docker daemon is unavailable")
    image = os.environ.get(
        "NANO_DOCKER_REGRESSION_IMAGE",
        "alexgshaw/fix-git:20260403",
    )
    if subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True,
        check=False,
    ).returncode:
        pytest.skip(f"cached regression image is unavailable: {image}")
    container_id = ""
    sentinel_pid = ""
    try:
        container_id = subprocess.run(
            ["docker", "run", "--detach", "--rm", image, "sleep", "infinity"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        environment = DockerExecRemote(container_id)
        actor = RemoteTerminalActor(environment)
        asyncio.run(actor.setup())
        sentinel = asyncio.run(
            environment.exec(
                "setsid sleep 60 >/dev/null 2>&1 & echo $!",
                timeout_sec=5,
            )
        )
        assert sentinel.return_code == 0
        sentinel_pid = sentinel.stdout.strip()
        assert sentinel_pid.isdigit()
        command = (
            "sleep 60 >/dev/null 2>&1 & printf 'leader-done\\n'"
            if residual_kind == "same_pgid"
            else (
                "setsid /bin/bash -c 'trap \"\" TERM; exec sleep 60' "
                ">/dev/null 2>&1 & printf 'leader-done\\n'"
            )
        )
        original = request(
            Path("/workspace"),
            "run_terminal_command",
            {
                "command": command,
                "description": f"synthetic {residual_kind} containment",
            },
        )
        tool_request = ToolRequest(
            **{
                **original.__dict__,
                "raw_json": json.dumps(
                    {"case": f"foreground-residual-{residual_kind}"},
                    separators=(",", ":"),
                ).encode(),
                "timeout_ms": 2_000,
                "term_grace_ms": 100,
                "kill_confirmation_timeout_ms": 1_000,
            }
        )

        result = asyncio.run(actor.execute(tool_request))

        assert result.return_code == 0
        assert result.timed_out is False
        assert result.stdout == b"leader-done\n"
        assert result.cleanup_attempted is True
        assert result.term_sent or result.kill_sent
        assert result.cleanup_verified is True
        assert result.census_verified is True
        assert result.survivor_count == 0
        assert result.process_disposition is ProcessDisposition.FOREGROUND_CLEANED
        sentinel_alive = asyncio.run(
            environment.exec(
                f"kill -0 {sentinel_pid}",
                timeout_sec=5,
            )
        )
        assert sentinel_alive.return_code == 0
        assert asyncio.run(actor.cleanup_active()) is True
    finally:
        if container_id:
            if sentinel_pid.isdigit():
                subprocess.run(
                    [
                        "docker",
                        "exec",
                        container_id,
                        "/bin/bash",
                        "-c",
                        f"kill -KILL {sentinel_pid} 2>/dev/null || true",
                    ],
                    capture_output=True,
                    check=False,
                )
            subprocess.run(
                ["docker", "rm", "--force", container_id],
                capture_output=True,
                check=False,
            )


@pytest.mark.skipif(
    os.environ.get("NANO_RUN_DOCKER_TESTS") != "1",
    reason="set NANO_RUN_DOCKER_TESTS=1 for the real-Docker regression",
)
def test_real_docker_detached_fifo_writer_is_censused_and_drain_is_bounded(
    tmp_path: Path,
) -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker CLI is unavailable")
    if subprocess.run(
        ["docker", "info"],
        capture_output=True,
        check=False,
    ).returncode:
        pytest.skip("docker daemon is unavailable")
    image = os.environ.get(
        "NANO_DOCKER_REGRESSION_IMAGE",
        "alexgshaw/fix-git:20260403",
    )
    if subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True,
        check=False,
    ).returncode:
        pytest.skip(f"cached regression image is unavailable: {image}")
    container_id = ""
    try:
        container_id = subprocess.run(
            ["docker", "run", "--detach", "--rm", image, "sleep", "infinity"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        environment = DockerExecRemote(container_id)
        actor = RemoteTerminalActor(environment)
        asyncio.run(actor.setup())
        original = request(
            Path("/workspace"),
            "run_terminal_command",
            {
                "command": (
                    "setsid /bin/bash -c '"
                    'trap "" TERM; '
                    "echo $$ > /workspace/nano-detached.pid; "
                    "sleep 60"
                    "' & "
                    "while ! test -s /workspace/nano-detached.pid; "
                    "do sleep 0.01; done; "
                    "printf 'parent-done\\n'"
                )
            },
        )
        tool_request = ToolRequest(
            **{
                **original.__dict__,
                "raw_json": b'{"case":"detached-fifo"}',
                "timeout_ms": 500,
                "term_grace_ms": 50,
                "kill_confirmation_timeout_ms": 500,
            }
        )
        started = time.monotonic()
        result = asyncio.run(actor.execute(tool_request))
        elapsed = time.monotonic() - started

        assert result.return_code == 0
        assert result.stdout == b"parent-done\n"
        assert result.cleanup_verified is True
        assert result.census_verified is True
        assert result.survivor_count == 0
        assert elapsed < 6
        census = asyncio.run(
            environment.exec(
                "pid=$(cat /workspace/nano-detached.pid); "
                'if test -r "/proc/$pid/stat"; then '
                'raw=$(cat "/proc/$pid/stat"); fields=${raw##*) }; '
                'set -- $fields; test "$1" = Z -o "$1" = X; '
                "fi",
                timeout_sec=5,
            )
        )
        assert census.return_code == 0
        for exit_code, expected_status in ((0, "completed"), (1, "failed")):
            quick = request(
                Path("/workspace"),
                "run_terminal_command",
                {
                    "command": f"printf 'quick-{exit_code}\\n'; exit {exit_code}",
                    "description": "quick background exit",
                    "background": True,
                },
            )
            quick = ToolRequest(
                **{
                    **quick.__dict__,
                    "raw_json": json.dumps(
                        {"case": f"quick-exit-{exit_code}"},
                        separators=(",", ":"),
                    ).encode(),
                    "timeout_ms": 2_000,
                    "term_grace_ms": 50,
                    "kill_confirmation_timeout_ms": 500,
                }
            )
            quick_result = asyncio.run(actor.execute(quick))
            assert quick_result.process_disposition is ProcessDisposition.NO_PROCESS
            assert f"<status>{expected_status}</status>".encode() in quick_result.stdout
            assert f"<exit-code>{exit_code}</exit-code>".encode() in quick_result.stdout
            assert f"quick-{exit_code}".encode() in quick_result.stdout
    finally:
        if container_id:
            subprocess.run(
                ["docker", "rm", "--force", container_id],
                capture_output=True,
                check=False,
            )


@pytest.mark.skipif(
    os.environ.get("NANO_RUN_DOCKER_TESTS") != "1",
    reason="set NANO_RUN_DOCKER_TESTS=1 for the real-Docker regression",
)
def test_real_docker_background_launch_ack_survives_initial_status_loss(
    tmp_path: Path,
) -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker CLI is unavailable")
    if subprocess.run(
        ["docker", "info"],
        capture_output=True,
        check=False,
    ).returncode:
        pytest.skip("docker daemon is unavailable")
    image = os.environ.get(
        "NANO_DOCKER_REGRESSION_IMAGE",
        "alexgshaw/fix-git:20260403",
    )
    if subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True,
        check=False,
    ).returncode:
        pytest.skip(f"cached regression image is unavailable: {image}")
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    container_id = ""
    try:
        container_id = subprocess.run(
            ["docker", "run", "--detach", "--rm", image, "sleep", "infinity"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        environment = InitialStatusLossDockerRemote(container_id)
        actor = RemoteTerminalActor(environment, id_factory=lambda: task_id)
        asyncio.run(actor.setup())
        original = request(
            Path("/workspace"),
            "run_terminal_command",
            {
                "command": "sleep 60",
                "description": "retain exact launch identity after status loss",
                "background": True,
            },
        )
        start_request = ToolRequest(
            **{
                **original.__dict__,
                "raw_json": b'{"case":"background-launch-ack-status-loss"}',
                "timeout_ms": 5_000,
                "term_grace_ms": 100,
                "kill_confirmation_timeout_ms": 500,
            }
        )

        retained = asyncio.run(actor.execute(start_request))

        assert retained.process_disposition is ProcessDisposition.BACKGROUND_RETAINED
        assert retained.target_task_id == task_id
        assert retained.survivor_count == 1
        assert b"<status>running</status>" in retained.stdout
        assert b"<status-fresh>false</status-fresh>" in retained.stdout
        assert environment.remaining_status_losses == 0
        assert task_id in actor._background

        observed = asyncio.run(
            actor.execute(
                request(
                    Path("/workspace"),
                    "get_terminal_command_output",
                    {"task_ids": [task_id], "timeout_ms": 0},
                )
            )
        )
        assert b"Status: running" in observed.stdout
        assert b"status_unavailable" not in observed.stdout
        assert asyncio.run(actor.cleanup_active()) is True
        assert actor._background == {}
    finally:
        if container_id:
            subprocess.run(
                ["docker", "rm", "--force", container_id],
                capture_output=True,
                check=False,
            )


@pytest.mark.skipif(
    os.environ.get("NANO_RUN_DOCKER_TESTS") != "1",
    reason="set NANO_RUN_DOCKER_TESTS=1 for the real-Docker regression",
)
@pytest.mark.parametrize("retained_before_exit", [False, True])
def test_real_docker_background_setsid_survivor_settles_without_orphan(
    tmp_path: Path,
    retained_before_exit: bool,
) -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker CLI is unavailable")
    if subprocess.run(
        ["docker", "info"],
        capture_output=True,
        check=False,
    ).returncode:
        pytest.skip("docker daemon is unavailable")
    image = os.environ.get(
        "NANO_DOCKER_REGRESSION_IMAGE",
        "alexgshaw/fix-git:20260403",
    )
    if subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True,
        check=False,
    ).returncode:
        pytest.skip(f"cached regression image is unavailable: {image}")
    task_id = (
        "018f22d6-9f04-7cc0-8000-000000000002"
        if retained_before_exit
        else "018f22d6-9f04-7cc0-8000-000000000001"
    )
    container_id = ""
    try:
        container_id = subprocess.run(
            ["docker", "run", "--detach", "--rm", image, "sleep", "infinity"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        environment = DockerExecRemote(container_id)
        actor = RemoteTerminalActor(environment, id_factory=lambda: task_id)
        asyncio.run(actor.setup())
        delay = "sleep 1; " if retained_before_exit else ""
        original = request(
            Path("/workspace"),
            "run_terminal_command",
            {
                "command": (
                    f"{delay}setsid /bin/bash -c "
                    "'trap \"\" TERM; exec sleep 30' "
                    ">/dev/null 2>&1 & exit 0"
                ),
                "description": "shell exits while its setsid child remains alive",
                "background": True,
            },
        )
        tool_request = ToolRequest(
            **{
                **original.__dict__,
                "raw_json": json.dumps(
                    {
                        "case": "background-setsid-survivor",
                        "retained_before_exit": retained_before_exit,
                    },
                    separators=(",", ":"),
                ).encode(),
                "timeout_ms": 2_000,
                "term_grace_ms": 100,
                "kill_confirmation_timeout_ms": 500,
            }
        )

        started = asyncio.run(actor.execute(tool_request))
        request_dir = f"{_BACKGROUND_ROOT}/{task_id}"
        if started.process_disposition is ProcessDisposition.BACKGROUND_RETAINED:
            assert started.target_task_id == task_id
            assert started.survivor_count == 1
            assert started.background_start_observation is None
            task = actor._background[task_id]
            if retained_before_exit:
                owner_environment = shlex.quote(f"NANO_NGB_OWNER={task.owner_token}")
                ownership = asyncio.run(
                    environment.exec(
                        " && ".join(
                            [
                                f"tr '\\0' '\\n' < /proc/{task.pgid}/environ "
                                f"| grep -Fqx -- {owner_environment}",
                                f"tr '\\0' '\\n' < /proc/{task.monitor_pgid}/environ "
                                f"| grep -Fqx -- {owner_environment}",
                            ]
                        ),
                        timeout_sec=5,
                    )
                )
                assert ownership.return_code == 0
                manifest = asyncio.run(actor.background_manifest())
                process_lease = actor.seal_process_lease_v1(manifest)
                liveness = asyncio.run(
                    actor.observe_process_lease_v1(
                        process_lease,
                        hard_deadline_monotonic_ns=(
                            actor._monotonic_ns() + 5_000_000_000
                        ),
                    )
                )
                assert liveness[0]["task_id"] == task_id
                assert liveness[0]["leader_pid"] == task.pgid
                assert liveness[0]["leader_starttime"] == task.leader_starttime
                assert liveness[0]["monitor_pid"] == task.monitor_pgid
                assert liveness[0]["monitor_starttime"] == task.monitor_starttime
                assert liveness[0]["process_alive"] is True
            time.sleep(1.2)
            kill_request = request(
                Path("/workspace"),
                "kill_terminal_command",
                {"task_id": task_id},
            )
            kill_request = ToolRequest(
                **{
                    **kill_request.__dict__,
                    "raw_json": b'{"case":"kill-terminal-setsid-survivor"}',
                    "timeout_ms": 2_000,
                    "term_grace_ms": 100,
                    "kill_confirmation_timeout_ms": 500,
                }
            )
            killed = asyncio.run(actor.execute(kill_request))
            assert (
                killed.process_disposition is ProcessDisposition.BACKGROUND_TERMINATED
            )
            assert killed.target_task_id == task_id
            assert killed.cleanup_attempted is True
            assert killed.term_sent or killed.kill_sent
            assert actor._background[task_id].state == "cancelled"
        else:
            assert retained_before_exit is False
            assert started.process_disposition is ProcessDisposition.NO_PROCESS
            assert started.return_code == 0
            assert started.cleanup_attempted is True
            assert started.term_sent is False
            assert started.kill_sent is False
            assert started.cleanup_verified is True
            assert started.census_verified is True
            assert started.survivor_count == 0
            assert started.target_task_id is None
            assert started.background_start_observation == BackgroundStartObservation(
                proof_version=BACKGROUND_START_PROOF_VERSION,
                kind=BackgroundStartKind.QUICK_EXIT,
                task_id_published=False,
                child_exit_code=0,
            )
            assert task_id not in actor._background

        identity = asyncio.run(
            environment.exec(
                " ".join(
                    [
                        "cat",
                        shlex.quote(f"{request_dir}/pgid"),
                        shlex.quote(f"{request_dir}/leader_starttime"),
                        shlex.quote(f"{request_dir}/monitor_pgid"),
                        shlex.quote(f"{request_dir}/monitor_starttime"),
                        shlex.quote(f"{request_dir}/owner_token"),
                    ]
                )
            )
        )
        assert identity.return_code == 0
        (
            pgid,
            leader_starttime,
            monitor_pgid,
            monitor_starttime,
            owner_token,
        ) = identity.stdout.splitlines()
        assert pgid.isdigit() and int(pgid) > 1
        assert leader_starttime.isdigit() and int(leader_starttime) > 0
        assert monitor_pgid.isdigit() and int(monitor_pgid) > 1
        assert monitor_starttime.isdigit() and int(monitor_starttime) > 0
        assert len(owner_token) == 64
        assert all(character in "0123456789abcdef" for character in owner_token)
        census = asyncio.run(
            environment.exec(
                " ".join(
                    [
                        "/bin/bash",
                        shlex.quote(_REMOTE_ACTOR),
                        "cleanup-census",
                        shlex.quote(request_dir),
                        "background",
                        pgid,
                        leader_starttime,
                        monitor_pgid,
                        monitor_starttime,
                        owner_token,
                    ]
                ),
                timeout_sec=5,
            )
        )
        assert census.return_code == 0
        assert json.loads(census.stdout) == {
            "verified": True,
            "survivor_count": 0,
        }
        replacement_token = "b" * 64 if owner_token != "b" * 64 else "c" * 64
        tampered = asyncio.run(
            environment.exec(
                f"printf '%s\\n' {replacement_token} > "
                f"{shlex.quote(request_dir + '/owner_token')}",
                timeout_sec=5,
            )
        )
        assert tampered.return_code == 0
        rejected_tampered_census = asyncio.run(
            environment.exec(
                " ".join(
                    [
                        "/bin/bash",
                        shlex.quote(_REMOTE_ACTOR),
                        "cleanup-census",
                        shlex.quote(request_dir),
                        "background",
                        pgid,
                        leader_starttime,
                        monitor_pgid,
                        monitor_starttime,
                        owner_token,
                    ]
                ),
                timeout_sec=5,
            )
        )
        assert rejected_tampered_census.return_code != 0
        assert asyncio.run(actor.cleanup_active()) is True
    finally:
        if container_id:
            subprocess.run(
                ["docker", "rm", "--force", container_id],
                capture_output=True,
                check=False,
            )


def test_foreground_launch_without_pgid_preserves_original_error(
    tmp_path: Path,
) -> None:
    environment = FailedForegroundRemote(evidence_return_code=1)
    actor = RemoteTerminalActor(environment)
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }
    tool_request = request(
        Path("/workspace"),
        "run_terminal_command",
        {"command": "pwd"},
    )

    with pytest.raises(BridgeError, match="terminal_actor_run_failed"):
        asyncio.run(actor.execute(tool_request))

    assert actor._active == {}
    assert not any(
        "/actor.sh cleanup " in command for command, _ in environment.exec_calls
    )


def test_foreground_launch_with_unknown_pgid_evidence_fails_closed(
    tmp_path: Path,
) -> None:
    environment = FailedForegroundRemote(evidence_return_code=2)
    actor = RemoteTerminalActor(environment)
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }
    tool_request = request(
        Path("/workspace"),
        "run_terminal_command",
        {"command": "pwd"},
    )

    with pytest.raises(
        ToolFatalError,
        match="terminal_actor_cleanup_unverified",
    ) as captured:
        asyncio.run(actor.execute(tool_request))

    assert captured.value.failure == ToolFailure(
        code="terminal_actor_cleanup_unverified",
        execution_may_have_started=True,
        cleanup_verified=False,
        census_verified=False,
    )
    assert actor._active


def test_foreground_launch_with_pgid_and_failed_cleanup_fails_closed() -> None:
    environment = FailedForegroundRemote(evidence_return_code=0)
    actor = RemoteTerminalActor(environment)
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }

    with pytest.raises(
        ToolFatalError,
        match="terminal_actor_cleanup_unverified",
    ):
        asyncio.run(
            actor.execute(
                request(
                    Path("/workspace"),
                    "run_terminal_command",
                    {"command": "pwd"},
                )
            )
        )

    assert actor._active
    assert any("/actor.sh cleanup " in command for command, _ in environment.exec_calls)


def test_foreground_transport_timeout_returns_verified_settled_result() -> None:
    environment = SettledForegroundTimeoutRemote()
    actor = RemoteTerminalActor(environment)
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }
    tool_request = request(
        Path("/workspace"),
        "run_terminal_command",
        {"command": "sleep 60"},
    )

    result = asyncio.run(actor.execute(tool_request))

    assert result.return_code == 124
    assert result.timed_out is True
    assert result.stdout == b"partial output\n"
    assert result.process_disposition is ProcessDisposition.FOREGROUND_CLEANED
    assert result.cleanup_verified is True
    assert result.census_verified is True
    assert result.survivor_count == 0
    assert actor._active == {}
    assert not any(
        "/actor.sh cleanup " in command for command, *_ in environment.exec_calls
    )
    run_call = next(
        call for call in environment.exec_calls if "/actor.sh run " in call[0]
    )
    old_exact_bound = (
        tool_request.timeout_ms
        + tool_request.term_grace_ms
        + tool_request.kill_confirmation_timeout_ms
    ) / 1000 + 5
    assert run_call[2] > old_exact_bound


@pytest.mark.parametrize(
    ("evidence_path", "kill_sent"),
    [("same_pgid_child", False), ("exact_owner_new_pgid_child", True)],
)
def test_foreground_residual_emits_non_timeout_verified_signal_evidence(
    evidence_path: str,
    kill_sent: bool,
) -> None:
    environment = SettledForegroundResidualRemote(kill_sent=kill_sent)
    actor = RemoteTerminalActor(environment)
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }

    result = asyncio.run(
        actor.execute(
            request(
                Path("/workspace"),
                "run_terminal_command",
                {
                    "command": "true",
                    "description": f"synthetic {evidence_path}",
                },
            )
        )
    )

    assert result.return_code == 0
    assert result.timed_out is False
    assert result.cleanup_attempted is True
    assert result.term_sent is True
    assert result.kill_sent is kill_sent
    assert result.cleanup_verified is True
    assert result.census_verified is True
    assert result.survivor_count == 0
    assert result.process_disposition is ProcessDisposition.FOREGROUND_CLEANED
    assert result.target_task_id is None
    assert result.background_start_observation is None
    assert actor._active == {}


def test_foreground_residual_does_not_touch_unrelated_preexisting_process() -> None:
    unrelated = subprocess.Popen(
        ["/bin/sleep", "60"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        environment = SettledForegroundResidualRemote(kill_sent=False)
        actor = RemoteTerminalActor(environment)
        actor._ready = True
        actor._workspace_mapping = {
            "canonical_cwd": "/app/repo",
            "default_cwd": "/app/repo",
            "logical_cwd": "/workspace",
            "mode": "created_symlink",
        }

        result = asyncio.run(
            actor.execute(
                request(
                    Path("/workspace"),
                    "run_terminal_command",
                    {
                        "command": "true",
                        "description": "synthetic exact-owner containment",
                    },
                )
            )
        )

        assert result.term_sent is True
        assert unrelated.poll() is None
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=5)


def test_foreground_residual_timeout_and_unverified_containment_stay_distinct() -> None:
    timeout_actor = RemoteTerminalActor(SettledForegroundTimeoutRemote())
    timeout_actor._ready = True
    timeout_actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }
    timeout_result = asyncio.run(
        timeout_actor.execute(
            request(
                Path("/workspace"),
                "run_terminal_command",
                {"command": "sleep 60", "description": "semantic timeout"},
            )
        )
    )
    assert timeout_result.timed_out is True
    assert timeout_result.term_sent is True

    for cleanup_verified, census_verified in [(False, True), (True, False)]:
        actor = RemoteTerminalActor(
            DirectContainmentForegroundRemote(
                cleanup_verified=cleanup_verified,
                census_verified=census_verified,
                cleanup_return_code=73,
            )
        )
        actor._ready = True
        actor._workspace_mapping = {
            "canonical_cwd": "/app/repo",
            "default_cwd": "/app/repo",
            "logical_cwd": "/workspace",
            "mode": "created_symlink",
        }
        with pytest.raises(ToolFatalError, match="terminal_actor_cleanup_unverified"):
            asyncio.run(
                actor.execute(
                    request(
                        Path("/workspace"),
                        "run_terminal_command",
                        {"command": "true", "description": "unverified containment"},
                    )
                )
            )


def _foreground_v3_request(
    *,
    timeout_ms: int,
    actor_done_monotonic_ns: int,
) -> ToolRequest:
    original = request(
        Path("/workspace"),
        "run_terminal_command",
        {"command": "sleep 120", "description": "typed foreground"},
    )
    tool_settled_monotonic_ns = actor_done_monotonic_ns + 10_000_000_000
    runtime_final_monotonic_ns = tool_settled_monotonic_ns + 30_000_000_000
    cleanup_start_monotonic_ns = runtime_final_monotonic_ns + 15_000_000_000
    hard_deadline_monotonic_ns = cleanup_start_monotonic_ns + 20_000_000_000
    return ToolRequest(
        **{
            **original.__dict__,
            "schema_version": "external-tool-stdio-v3",
            "timeout_ms": timeout_ms,
            "term_grace_ms": 1_000,
            "kill_confirmation_timeout_ms": 3_000,
            "actor_done_monotonic_ns": actor_done_monotonic_ns,
            "tool_settled_monotonic_ns": tool_settled_monotonic_ns,
            "last_send_monotonic_ns": runtime_final_monotonic_ns,
            "runtime_final_monotonic_ns": runtime_final_monotonic_ns,
            "cleanup_start_monotonic_ns": cleanup_start_monotonic_ns,
            "hard_deadline_monotonic_ns": hard_deadline_monotonic_ns,
            "cleanup_reserve_ms": 20_000,
            "terminalization_reserve_ms": 15_000,
            "provider_send_reserve_ms": 30_000,
            "process_settlement_reserve_ms": 10_000,
            "deadline_receipt_sha256": "d" * 64,
        }
    )


def _foreground_actor(environment) -> RemoteTerminalActor:
    actor = RemoteTerminalActor(environment, monotonic=lambda: 100.0)
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }
    return actor


def test_foreground_phase_receipt_is_closed_and_root_bounded() -> None:
    environment = SettledForegroundSemanticTimeoutRemote()
    actor = _foreground_actor(environment)
    tool_request = _foreground_v3_request(
        timeout_ms=120_000,
        actor_done_monotonic_ns=400_000_000_000,
    )

    result = asyncio.run(actor.execute(tool_request))

    receipt = getattr(result, "actor_receipt", None)
    assert receipt is not None
    assert receipt.schema_version == "terminal-actor-receipt-v1"
    assert receipt.phase.value in {
        "mapping_preflight",
        "remote_setup",
        "command_upload",
        "remote_exec",
        "recovery_download",
        "result_download",
        "meta_validate",
        "cleanup",
        "census",
        "actor_done",
    }
    assert receipt.origin.value in {"semantic", "transport", "protocol", "actor"}
    assert receipt.primary_subtype.value == "semantic_execution_timed_out"
    assert receipt.recovery_subtype is None
    assert receipt.execution_may_have_started is True
    assert (
        0
        < receipt.effective_cutoff_monotonic_ns
        <= tool_request.actor_done_monotonic_ns
    )
    assert receipt.cleanup_verified is True
    assert receipt.census_verified is True
    assert len(receipt.diagnostic_digest_sha256) == 64
    assert receipt.diagnostic_digest_sha256 == (
        receipt.diagnostic_digest_sha256.lower()
    )


def test_foreground_rpc_timeout_is_clamped_to_actor_done() -> None:
    environment = SettledForegroundTimeoutRemote()
    actor = _foreground_actor(environment)
    tool_request = _foreground_v3_request(
        timeout_ms=4_000,
        actor_done_monotonic_ns=105_000_000_000,
    )

    asyncio.run(actor.execute(tool_request))

    assert environment.exec_calls
    assert all(
        timeout_sec is not None and 0 < timeout_sec <= 5.0
        for _, _, timeout_sec, _ in environment.exec_calls
    )


def test_foreground_root_expiry_is_not_transport_timeout() -> None:
    environment = SettledForegroundTimeoutRemote()
    monotonic_values = iter((100.0, 106.0))
    actor = RemoteTerminalActor(
        environment,
        monotonic=lambda: next(monotonic_values),
    )
    tool_request = _foreground_v3_request(
        timeout_ms=120_000,
        actor_done_monotonic_ns=105_000_000_000,
    )

    with pytest.raises(
        terminal_actor._ActorDoneDeadlineExceeded,
        match="terminal_actor_deadline_exceeded",
    ):
        asyncio.run(
            actor._foreground_exec_rpc(
                tool_request,
                "/bin/bash /opt/nano/actor.sh run synthetic",
            )
        )


def test_foreground_120s_semantic_timeout_does_not_create_135s_transport_cap() -> None:
    environment = SettledForegroundTimeoutRemote()
    actor = _foreground_actor(environment)
    tool_request = _foreground_v3_request(
        timeout_ms=120_000,
        actor_done_monotonic_ns=400_000_000_000,
    )

    asyncio.run(actor.execute(tool_request))

    run_call = next(
        call for call in environment.exec_calls if "/actor.sh run " in call[0]
    )
    assert run_call[2] == pytest.approx(300.0)
    assert run_call[2] != 135.0


def test_foreground_transport_recovery_preserves_primary_and_recovery() -> None:
    environment = SettledForegroundTimeoutRemote()
    actor = _foreground_actor(environment)
    tool_request = _foreground_v3_request(
        timeout_ms=120_000,
        actor_done_monotonic_ns=400_000_000_000,
    )

    result = asyncio.run(actor.execute(tool_request))

    receipt = getattr(result, "actor_receipt", None)
    assert receipt is not None
    assert receipt.phase.value == "meta_validate"
    assert receipt.origin.value == "transport"
    assert receipt.primary_subtype.value == "run_transport_timeout"
    assert receipt.recovery_subtype.value == "recovered_settled"
    assert receipt.execution_may_have_started is True
    assert receipt.cleanup_verified is True
    assert receipt.census_verified is True


def test_foreground_missing_or_corrupt_meta_preserves_primary_origin() -> None:
    environment = CorruptRecoveryForegroundRemote(
        evidence_return_code=1,
        cleanup_return_code=0,
    )
    actor = _foreground_actor(environment)
    tool_request = _foreground_v3_request(
        timeout_ms=120_000,
        actor_done_monotonic_ns=400_000_000_000,
    )

    with pytest.raises(ToolFatalError) as caught:
        asyncio.run(actor.execute(tool_request))

    receipt = getattr(caught.value.failure, "actor_receipt", None)
    assert receipt is not None
    assert receipt.origin.value == "transport"
    assert receipt.primary_subtype.value == "run_transport_timeout"
    assert receipt.recovery_subtype.value == "meta_invalid"


def test_foreground_cleanup_failure_preserves_primary_receipt() -> None:
    environment = CorruptRecoveryForegroundRemote(
        evidence_return_code=0,
        cleanup_return_code=73,
    )
    actor = _foreground_actor(environment)
    tool_request = _foreground_v3_request(
        timeout_ms=120_000,
        actor_done_monotonic_ns=400_000_000_000,
    )

    with pytest.raises(ToolFatalError) as caught:
        asyncio.run(actor.execute(tool_request))

    failure = caught.value.failure
    receipt = getattr(failure, "actor_receipt", None)
    assert failure.code == "terminal_actor_cleanup_unverified"
    assert receipt is not None
    assert receipt.phase.value == "cleanup"
    assert receipt.origin.value == "transport"
    assert receipt.primary_subtype.value == "run_transport_timeout"
    assert receipt.recovery_subtype.value == "meta_invalid"
    assert receipt.execution_may_have_started is True
    assert receipt.cleanup_verified is False
    assert receipt.census_verified is None


def test_foreground_direct_corrupt_meta_is_protocol_meta_phase() -> None:
    environment = CorruptDirectForegroundRemote(
        evidence_return_code=0,
        cleanup_return_code=0,
    )
    actor = _foreground_actor(environment)
    tool_request = _foreground_v3_request(
        timeout_ms=120_000,
        actor_done_monotonic_ns=400_000_000_000,
    )

    with pytest.raises(ToolFatalError) as caught:
        asyncio.run(actor.execute(tool_request))

    receipt = caught.value.failure.actor_receipt
    assert receipt is not None
    assert receipt.phase.value == "meta_validate"
    assert receipt.origin.value == "protocol"
    assert receipt.primary_subtype.value == "meta_invalid"
    assert receipt.recovery_subtype is None
    assert receipt.execution_may_have_started is True
    assert receipt.cleanup_verified is True
    assert receipt.census_verified is True
    encoded = json.loads(encode_tool_response(tool_request, caught.value.failure))
    assert encoded["failure"]["actor_receipt"]["phase"] == "meta_validate"


@pytest.mark.parametrize(
    (
        "initial_cleanup",
        "initial_census",
        "cleanup_return_code",
        "expected_cleanup",
        "expected_census",
        "expected_phase",
    ),
    [
        (False, False, 0, True, True, "census"),
        (True, False, 73, True, False, "census"),
        (False, True, 73, False, True, "cleanup"),
    ],
)
def test_foreground_later_containment_preserves_independent_facts(
    initial_cleanup: bool,
    initial_census: bool,
    cleanup_return_code: int,
    expected_cleanup: bool,
    expected_census: bool,
    expected_phase: str,
) -> None:
    environment = DirectContainmentForegroundRemote(
        cleanup_verified=initial_cleanup,
        census_verified=initial_census,
        cleanup_return_code=cleanup_return_code,
    )
    actor = _foreground_actor(environment)
    tool_request = _foreground_v3_request(
        timeout_ms=120_000,
        actor_done_monotonic_ns=400_000_000_000,
    )

    with pytest.raises(ToolFatalError) as caught:
        asyncio.run(actor.execute(tool_request))

    failure = caught.value.failure
    receipt = failure.actor_receipt
    assert receipt is not None
    assert receipt.phase.value == expected_phase
    assert receipt.origin.value == "actor"
    assert receipt.primary_subtype.value == "cleanup_unverified"
    assert receipt.cleanup_verified is expected_cleanup
    assert receipt.census_verified is expected_census
    assert failure.cleanup_verified is expected_cleanup
    assert failure.census_verified is expected_census
    encode_tool_response(tool_request, failure)


def test_request_rejects_non_workspace_logical_cwd_before_remote_effect() -> None:
    environment = ScriptedRemote([])
    actor = RemoteTerminalActor(environment)
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }

    with pytest.raises(BridgeError, match="terminal_actor_logical_cwd_invalid"):
        asyncio.run(
            actor.execute(
                request(
                    Path("/"),
                    "read_file",
                    {"target_file": "/etc/passwd"},
                )
            )
        )

    assert environment.exec_calls == []


def test_workspace_alias_tamper_fails_before_file_effect() -> None:
    environment = ScriptedRemote(
        [SimpleNamespace(return_code=1, stdout="", stderr="mapping changed")]
    )
    actor = RemoteTerminalActor(environment)
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }

    with pytest.raises(BridgeError, match="terminal_actor_workspace_mapping_changed"):
        asyncio.run(
            actor.execute(
                request(
                    Path("/workspace"),
                    "write",
                    {
                        "file_path": "/workspace/escape",
                        "content": "must not write",
                    },
                )
            )
        )

    assert len(environment.exec_calls) == 1
    assert environment.exec_calls[0][1] == "/app/repo"
    assert environment.uploads == []


def test_mapping_preflight_exact_harbor_timeout_retries_once_before_effect() -> None:
    original = RuntimeError("Command timed out after 5.0 seconds")
    actor, environment, tool_request = mapping_preflight_fixture(
        original,
        SimpleNamespace(return_code=0, stdout="", stderr=""),
    )

    result = asyncio.run(actor.execute(tool_request))

    assert result.return_code == 0
    assert len(environment.exec_calls) == 2
    assert [call[2] for call in environment.exec_calls] == [5.0, 5.0]
    assert actor.user_effects == [tool_request.call_id]


def test_mapping_preflight_builtin_timeout_retries_once_before_effect() -> None:
    original = TimeoutError("typed transport timeout")
    actor, environment, tool_request = mapping_preflight_fixture(
        original,
        SimpleNamespace(return_code=0, stdout="", stderr=""),
    )

    result = asyncio.run(actor.execute(tool_request))

    assert result.return_code == 0
    assert len(environment.exec_calls) == 2
    assert actor.user_effects == [tool_request.call_id]


def test_c1_mapping_load_timeout_fixture_retries_once_before_effect() -> None:
    original = subprocess.TimeoutExpired(
        cmd=["docker", "exec", "c1-mapping-preflight"],
        timeout=5.0,
    )
    actor, environment, tool_request = mapping_preflight_fixture(
        original,
        SimpleNamespace(return_code=0, stdout="", stderr=""),
    )

    result = asyncio.run(actor.execute(tool_request))

    assert result.return_code == 0
    assert len(environment.exec_calls) == 2
    assert actor.user_effects == [tool_request.call_id]


def test_mapping_preflight_timeout_exhaustion_is_distinct_without_effect() -> None:
    actor, environment, tool_request = mapping_preflight_fixture(
        RuntimeError("Command timed out after 5.0 seconds"),
        RuntimeError("Command timed out after 5.0 seconds"),
    )

    with pytest.raises(
        BridgeError,
        match="^terminal_actor_workspace_mapping_check_timeout$",
    ):
        asyncio.run(actor.execute(tool_request))

    assert len(environment.exec_calls) == 2
    assert actor.user_effects == []


def test_mapping_preflight_retry_requires_a_full_remaining_window() -> None:
    environment = MappingPreflightRemote(
        [
            TimeoutError("first full mapping window elapsed"),
            AssertionError("partial retry must not dispatch"),
        ]
    )
    clock = iter((100.0, 105.0, 105.0))
    actor = MappingPreflightActor(
        environment,
        monotonic=lambda: next(clock),
    )
    original = request(
        Path("/workspace"),
        "list_dir",
        {"target_directory": "/workspace"},
    )
    actor_done = 109_900_000_000
    tool_request = ToolRequest(
        **{
            **original.__dict__,
            "schema_version": "external-tool-stdio-v3",
            "timeout_ms": 300_000,
            "actor_done_monotonic_ns": actor_done,
            "tool_settled_monotonic_ns": actor_done + 10_000_000_000,
            "last_send_monotonic_ns": actor_done + 40_000_000_000,
            "runtime_final_monotonic_ns": actor_done + 40_000_000_000,
            "cleanup_start_monotonic_ns": actor_done + 55_000_000_000,
            "hard_deadline_monotonic_ns": actor_done + 75_000_000_000,
            "cleanup_reserve_ms": 20_000,
            "terminalization_reserve_ms": 15_000,
            "provider_send_reserve_ms": 30_000,
            "process_settlement_reserve_ms": 10_000,
            "deadline_receipt_sha256": "d" * 64,
        }
    )

    with pytest.raises(
        ToolFatalError,
        match="^terminal_actor_workspace_mapping_check_timeout$",
    ):
        asyncio.run(actor.execute(tool_request))

    assert len(environment.exec_calls) == 1
    assert environment.exec_calls[0][2] == 5.0
    assert actor.user_effects == []


def test_mapping_preflight_completed_mismatch_is_immediate_without_effect() -> None:
    actor, environment, tool_request = mapping_preflight_fixture(
        SimpleNamespace(return_code=1, stdout="", stderr="mapping changed"),
    )

    with pytest.raises(
        BridgeError,
        match="^terminal_actor_workspace_mapping_changed$",
    ):
        asyncio.run(actor.execute(tool_request))

    assert len(environment.exec_calls) == 1
    assert actor.user_effects == []


def test_mapping_preflight_runtime_error_near_misses_are_not_retried() -> None:
    cases = (
        ("generic", RuntimeError("generic transport failure")),
        (
            "subclass",
            _RuntimeErrorSubclass("Command timed out after 5.0 seconds"),
        ),
        ("near-miss", RuntimeError("Command timed out after 5 seconds")),
        (
            "malformed",
            RuntimeError("Command timed out after 5.0 seconds", "extra"),
        ),
    )
    for label, original in cases:
        actor, environment, tool_request = mapping_preflight_fixture(original)
        with pytest.raises(
            BridgeError,
            match="^terminal_actor_workspace_mapping_changed$",
        ) as caught:
            asyncio.run(actor.execute(tool_request))
        assert caught.value.__cause__ is original, label
        assert len(environment.exec_calls) == 1, label
        assert actor.user_effects == [], label


@pytest.mark.parametrize(
    ("label", "original", "request_timeout_ms"),
    [
        (
            "subprocess-timeout-low",
            subprocess.TimeoutExpired("c1-mapping", timeout=4.999),
            10_000,
        ),
        (
            "subprocess-timeout-high",
            subprocess.TimeoutExpired("c1-mapping", timeout=5.001),
            10_000,
        ),
        (
            "subprocess-timeout-bool",
            subprocess.TimeoutExpired("c1-mapping", timeout=True),
            10_000,
        ),
        (
            "subprocess-timeout-nan",
            subprocess.TimeoutExpired("c1-mapping", timeout=float("nan")),
            10_000,
        ),
        (
            "subprocess-timeout-infinite",
            subprocess.TimeoutExpired("c1-mapping", timeout=float("inf")),
            10_000,
        ),
        (
            "subprocess-timeout-string",
            subprocess.TimeoutExpired("c1-mapping", timeout="5.0"),
            10_000,
        ),
        (
            "subprocess-timeout-subclass",
            _TimeoutExpiredSubclass("c1-mapping", timeout=5.0),
            10_000,
        ),
        (
            "builtin-timeout-subclass",
            _TimeoutErrorSubclass("typed transport timeout"),
            10_000,
        ),
        (
            "builtin-timeout-short-gate",
            TimeoutError("typed transport timeout"),
            1_000,
        ),
    ],
)
def test_mapping_preflight_typed_timeout_closed_set_negatives_do_not_retry(
    label: str,
    original: BaseException,
    request_timeout_ms: int,
) -> None:
    actor, environment, tool_request = mapping_preflight_fixture(
        original,
        SimpleNamespace(return_code=0, stdout="", stderr=""),
        request_timeout_ms=request_timeout_ms,
    )

    with pytest.raises(
        BridgeError,
        match="^terminal_actor_workspace_mapping_changed$",
    ) as caught:
        asyncio.run(actor.execute(tool_request))

    assert caught.value.__cause__ is original, label
    assert len(environment.exec_calls) == 1, label
    assert [call[2] for call in environment.exec_calls] == [
        min(5.0, request_timeout_ms / 1000)
    ], label
    assert actor.user_effects == [], label


def test_mapping_preflight_cancellation_propagates_without_retry_or_effect() -> None:
    original = asyncio.CancelledError()
    actor, environment, tool_request = mapping_preflight_fixture(original)

    with pytest.raises(asyncio.CancelledError) as caught:
        asyncio.run(actor.execute(tool_request))

    assert caught.value is original
    assert len(environment.exec_calls) == 1
    assert actor.user_effects == []


def test_mapping_preflight_normal_success_calls_once_and_effects_once() -> None:
    actor, environment, tool_request = mapping_preflight_fixture(
        SimpleNamespace(return_code=0, stdout="", stderr=""),
    )

    result = asyncio.run(actor.execute(tool_request))

    assert result.return_code == 0
    assert len(environment.exec_calls) == 1
    assert actor.user_effects == [tool_request.call_id]


class ScriptedBackgroundActor(RemoteTerminalActor):
    def __init__(self, workspace: Path, task_ids: list[str]):
        ids = iter(task_ids)
        super().__init__(
            LocalFiles(),
            id_factory=lambda: next(ids),
            monotonic=lambda: 10.0,
            wall_clock=lambda: 1_736_942_400.0,
        )
        self.workspace = workspace
        self._ready = True
        self.launch_timeouts: list[int | None] = []
        self.outputs: dict[str, bytes] = {}
        self.terminated: list[str] = []
        self.confirmed: list[str] = []

    async def _prepare_request(self, request):
        return str(self.workspace)

    def _canonical_workspace(self):
        return str(self.workspace)

    async def _launch_background_remote(
        self, task, request, runtime_timeout_ms
    ) -> None:
        self.launch_timeouts.append(runtime_timeout_ms)
        task.pgid = 4000 + len(self.launch_timeouts)
        task.leader_starttime = 6000 + len(self.launch_timeouts)
        task.monitor_pgid = 5000 + len(self.launch_timeouts)
        task.monitor_starttime = 7000 + len(self.launch_timeouts)

    async def _refresh_background_remote(self, task) -> None:
        return True

    async def _read_background_output(self, task, max_bytes):
        payload = self.outputs.get(task.task_id, b"")
        if task.state == "running" and len(payload) >= task.spool_cap_bytes:
            task.truncated = True
        return payload

    async def _terminate_background_remote(self, task, term_grace_ms, confirmation_ms):
        self.terminated.append(task.task_id)
        task.total_bytes = len(self.outputs.get(task.task_id, b""))
        task.state = "cancelled"
        task.exit_code = -15
        task.end_wall = 1_736_942_401.0
        task.end_monotonic = 11.0
        task.explicitly_killed = True
        return True, False, True

    async def _confirm_background_stopped_remote(self, task, confirmation_ms):
        self.confirmed.append(task.task_id)
        return True

    async def _signal_cleanup_process(
        self,
        process_kind,
        request_dir,
        signal_name,
        cutoff_monotonic_ns,
        *,
        background_task=None,
    ):
        assert process_kind == "background"
        assert background_task is not None
        task = next(
            task
            for task in self._background.values()
            if task.request_dir == request_dir
        )
        if signal_name == "TERM" and task.state == "running":
            self.terminated.append(task.task_id)
            task.state = "cancelled"
        return True

    async def _census_cleanup_process(
        self,
        process_kind,
        request_dir,
        cutoff_monotonic_ns,
        *,
        background_task=None,
    ):
        assert process_kind == "background"
        assert background_task is not None
        task = next(
            task
            for task in self._background.values()
            if task.request_dir == request_dir
        )
        self.confirmed.append(task.task_id)
        return True


class CompletingWaitActor(ScriptedBackgroundActor):
    def __init__(
        self,
        workspace: Path,
        task_ids: list[str],
        complete_after: dict[str, int],
    ):
        super().__init__(workspace, task_ids)
        self.complete_after = complete_after
        self.refresh_counts: dict[str, int] = {}

    async def _refresh_background_remote(self, task) -> bool:
        count = self.refresh_counts.get(task.task_id, 0) + 1
        self.refresh_counts[task.task_id] = count
        if count >= self.complete_after.get(task.task_id, 1_000_000):
            task.state = "completed"
            task.exit_code = 0
            task.leader_exited = True
            task.end_wall = task.start_wall + count / 10
            task.end_monotonic = task.start_monotonic + count / 10
            task.census_verified = True
        return True


class QuickExitBackgroundActor(ScriptedBackgroundActor):
    def __init__(self, workspace: Path, task_ids: list[str], exit_code: int):
        super().__init__(workspace, task_ids)
        self.exit_code = exit_code
        self.launch_count = 0

    async def _launch_background_remote(
        self, task, request, runtime_timeout_ms
    ) -> None:
        self.launch_count += 1
        task.pgid = 4001
        task.leader_starttime = 6001
        task.monitor_pgid = 5001
        task.monitor_starttime = 7001
        task.state = "completed" if self.exit_code == 0 else "failed"
        task.exit_code = self.exit_code
        task.end_wall = task.start_wall + 0.01
        task.end_monotonic = task.start_monotonic + 0.01
        task.total_bytes = len(self.outputs.get(task.task_id, b""))


class LeaderExitedBackgroundActor(ScriptedBackgroundActor):
    def __init__(self, workspace: Path, task_ids: list[str]):
        super().__init__(workspace, task_ids)
        self.expose_survivor = False

    async def _refresh_background_remote(self, task) -> bool:
        if self.expose_survivor:
            task.leader_exited = True
        return True

    async def _background_process_alive_remote(self, task, request=None):
        return True

    async def _confirm_background_stopped_remote(self, task, confirmation_ms):
        self.confirmed.append(task.task_id)
        return False


class AmbiguousStartBackgroundActor(ScriptedBackgroundActor):
    def __init__(self, workspace: Path, task_ids: list[str], *, clean: bool):
        super().__init__(workspace, task_ids)
        self.clean = clean
        self.launch_count = 0

    async def _launch_background_remote(
        self, task, request, runtime_timeout_ms
    ) -> None:
        self.launch_count += 1
        raise BridgeError("terminal_actor_background_start_failed")

    async def _cleanup_failed_background_launch(self, task, request) -> str:
        return "transport_unknown_cleaned" if self.clean else "cleanup_unknown"


class RejectedStartBackgroundActor(ScriptedBackgroundActor):
    def __init__(self, workspace: Path, task_ids: list[str]):
        super().__init__(workspace, task_ids)
        self.launch_count = 0

    async def _launch_background_remote(
        self, task, request, runtime_timeout_ms
    ) -> None:
        self.launch_count += 1
        raise _BackgroundStartFailure(
            "terminal_actor_background_setup_failed",
            start_dispatched=False,
            not_started_verified=True,
        )


class BackgroundPreStartRemote:
    def __init__(
        self,
        *,
        setup_outcome: object,
        upload_error: BaseException | None = None,
    ) -> None:
        self.setup_outcome = setup_outcome
        self.upload_error = upload_error
        self.exec_calls: list[tuple[str, str | None, float | None, object]] = []
        self.upload_calls: list[tuple[Path, str]] = []

    async def exec(self, command, cwd=None, timeout_sec=None, user=None):
        self.exec_calls.append((command, cwd, timeout_sec, user))
        if isinstance(self.setup_outcome, BaseException):
            raise self.setup_outcome
        return self.setup_outcome

    async def upload_file(self, source_path, target_path):
        self.upload_calls.append((Path(source_path), target_path))
        if self.upload_error is not None:
            raise self.upload_error

    async def download_file(self, source_path, target_path):
        raise AssertionError("unexpected download")


class ProductionBackgroundStartActor(RemoteTerminalActor):
    def __init__(
        self,
        workspace: Path,
        environment: BackgroundPreStartRemote,
        task_id: str,
    ) -> None:
        super().__init__(environment, id_factory=lambda: task_id)
        self.workspace = workspace
        self._ready = True

    async def _prepare_request(self, request):
        return str(self.workspace)

    def _canonical_workspace(self):
        return str(self.workspace)


class StatusLossAfterLaunchBackgroundActor(ScriptedBackgroundActor):
    def __init__(self, workspace: Path, task_ids: list[str]):
        super().__init__(workspace, task_ids)
        self.refresh_count = 0

    async def _refresh_background_remote(self, task) -> bool:
        self.refresh_count += 1
        return False


class DispatchedStartLossCompletedBackgroundActor(ScriptedBackgroundActor):
    def __init__(self, workspace: Path, task_ids: list[str]):
        super().__init__(workspace, task_ids)
        self.launch_count = 0

    async def _launch_background_remote(
        self, task, request, runtime_timeout_ms
    ) -> None:
        self.launch_count += 1
        raise _BackgroundStartFailure(
            "terminal_actor_background_start_failed",
            start_dispatched=True,
        )

    async def _cleanup_failed_background_launch(self, task, request) -> str:
        task.state = "completed"
        task.exit_code = 0
        task.end_wall = task.start_wall + 0.01
        task.end_monotonic = task.start_monotonic + 0.01
        return "completed_before_handoff"


class InvalidQuickExitBackgroundActor(ScriptedBackgroundActor):
    def __init__(
        self,
        workspace: Path,
        task_ids: list[str],
        *,
        state: str,
        exit_code: int | None,
        timed_out: bool = False,
        explicitly_killed: bool = False,
    ):
        super().__init__(workspace, task_ids)
        self.invalid_state = state
        self.invalid_exit_code = exit_code
        self.invalid_timed_out = timed_out
        self.invalid_explicitly_killed = explicitly_killed

    async def _launch_background_remote(
        self, task, request, runtime_timeout_ms
    ) -> None:
        task.pgid = 4001
        task.leader_starttime = 6001
        task.monitor_pgid = 5001
        task.monitor_starttime = 7001
        task.state = self.invalid_state
        task.exit_code = self.invalid_exit_code
        task.timed_out = self.invalid_timed_out
        task.explicitly_killed = self.invalid_explicitly_killed
        task.end_wall = task.start_wall + 0.01
        task.end_monotonic = task.start_monotonic + 0.01


class StatusRemote:
    def __init__(self, outcomes):
        self.outcomes = iter(outcomes)
        self.exec_calls = []

    async def exec(self, command, cwd=None, timeout_sec=None, user=None):
        self.exec_calls.append((command, cwd, timeout_sec, user))
        outcome = next(self.outcomes)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    async def upload_file(self, source_path, target_path):
        raise AssertionError("unexpected upload")

    async def download_file(self, source_path, target_path):
        raise AssertionError("unexpected download")


class StatusActor(RemoteTerminalActor):
    def __init__(self, workspace: Path, environment: StatusRemote, task_id: str):
        super().__init__(environment, monotonic=lambda: 10.0)
        self.workspace = workspace
        self._ready = True
        self._background[task_id] = BackgroundTask(
            task_id=task_id,
            request_dir=self._background_dir(task_id),
            command="serve",
            logical_cwd=str(workspace),
            output_path=f"{workspace}/.terminals/{task_id}.log",
            start_wall=1_736_942_400.0,
            start_monotonic=10.0,
            runtime_timeout_ms=None,
            spool_cap_bytes=1024,
            term_grace_ms=100,
            kill_confirmation_timeout_ms=100,
            pgid=4001,
            leader_starttime=6001,
            monitor_pgid=5001,
            monitor_starttime=7001,
        )

    async def _prepare_request(self, request):
        return str(self.workspace)

    def _canonical_workspace(self):
        return str(self.workspace)

    async def _read_background_output(self, task, max_bytes):
        return b"last known output\n"


def running_status(*, leader_exited: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        return_code=0,
        stdout=json.dumps(
            {
                "state": "running",
                "exit_code": None,
                "timed_out": False,
                "total_bytes": 0,
                "truncated": False,
                "leader_exited": leader_exited,
                "started_epoch": 1_736_942_400.0,
                "ended_epoch": None,
            },
            separators=(",", ":"),
        ),
    )


@pytest.mark.parametrize(
    ("exit_code", "expected_status"),
    [(0, "completed"), (1, "failed")],
)
def test_background_quick_exit_is_model_visible_without_replay(
    tmp_path: Path,
    exit_code: int,
    expected_status: str,
) -> None:
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    actor = QuickExitBackgroundActor(tmp_path, [task_id], exit_code)
    actor.outputs[task_id] = b"quick output\n"

    result = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "run_terminal_command",
                {
                    "command": f"printf quick; exit {exit_code}",
                    "description": "quick command",
                    "background": True,
                },
            )
        )
    )

    assert actor.launch_count == 1
    assert result.return_code == (0 if exit_code == 0 else 2)
    assert result.process_disposition is ProcessDisposition.NO_PROCESS
    assert result.cleanup_attempted is True
    assert result.survivor_count == 0
    assert result.target_task_id is None
    assert result.background_start_observation == BackgroundStartObservation(
        proof_version=BACKGROUND_START_PROOF_VERSION,
        kind=BackgroundStartKind.QUICK_EXIT,
        task_id_published=False,
        child_exit_code=exit_code,
    )
    assert task_id not in actor._background
    assert task_id.encode() not in result.stdout
    assert b"<observation>background_start_quick_exit</observation>" in result.stdout
    assert f"<status>{expected_status}</status>".encode() in result.stdout
    assert f"<exit-code>{exit_code}</exit-code>".encode() in result.stdout
    assert b"<diagnostic>" in result.stdout
    assert b"<next-step>" in result.stdout
    assert b"quick output" in result.stdout


def test_background_truncated_quick_exit_never_leaks_unusable_task_identity(
    tmp_path: Path,
) -> None:
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    actor = QuickExitBackgroundActor(tmp_path, [task_id], 0)
    actor.outputs[task_id] = b"x" * 40_001

    result = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "run_terminal_command",
                {
                    "command": "python -c 'print(\"x\" * 40001)'",
                    "description": "quick truncated output",
                    "background": True,
                },
            )
        )
    )

    assert result.return_code == 0
    assert task_id.encode() not in result.stdout
    assert str(tmp_path).encode() not in result.stdout
    assert b"Output truncated" in result.stdout
    assert b"no retained background handle" in result.stdout


@pytest.mark.parametrize("observer", ["status-poll", "manifest"])
def test_background_leader_exit_preserves_live_owned_group(
    tmp_path: Path,
    observer: str,
) -> None:
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    actor = LeaderExitedBackgroundActor(tmp_path, [task_id])
    retained = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "run_terminal_command",
                {
                    "command": "serve",
                    "description": "retained before leader exit",
                    "background": True,
                },
            )
        )
    )
    assert retained.process_disposition is ProcessDisposition.BACKGROUND_RETAINED
    actor.expose_survivor = True

    if observer == "status-poll":
        observed = asyncio.run(
            actor.execute(
                request(
                    tmp_path,
                    "get_terminal_command_output",
                    {"task_ids": [task_id]},
                )
            )
        )
        assert observed.return_code == 0
        assert b"Status: running" in observed.stdout
    else:
        assert asyncio.run(actor.background_manifest()) == [
            {
                "task_id": task_id,
                "pgid": 4001,
                "monitor_pgid": 5001,
                "output_path": f"{tmp_path}/.terminals/{task_id}.log",
                "state": "running",
            }
        ]

    assert actor.confirmed == []
    assert actor.terminated == []
    assert actor._background[task_id].leader_exited is True


def test_background_rejected_before_start_is_recoverable_without_replay(
    tmp_path: Path,
) -> None:
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    actor = RejectedStartBackgroundActor(tmp_path, [task_id])

    result = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "run_terminal_command",
                {
                    "command": "serve",
                    "description": "ambiguous start",
                    "background": True,
                },
            )
        )
    )

    assert actor.launch_count == 1
    assert result.return_code == 2
    assert result.process_disposition is ProcessDisposition.NO_PROCESS
    assert result.cleanup_attempted is False
    assert result.target_task_id is None
    assert result.background_start_observation == BackgroundStartObservation(
        proof_version=BACKGROUND_START_PROOF_VERSION,
        kind=BackgroundStartKind.NOT_STARTED,
        task_id_published=False,
        child_exit_code=None,
    )
    assert b"<observation>background_start_not_running</observation>" in result.stdout
    assert b"<status>not_started</status>" in result.stdout
    assert b"<diagnostic>" in result.stdout
    assert b"<next-step>" in result.stdout
    assert task_id not in actor._background


@pytest.mark.parametrize(
    ("stage", "setup_outcome", "upload_error", "expected_code", "upload_count"),
    [
        (
            "setup-rpc-timeout",
            TimeoutError("setup transport timeout"),
            None,
            "terminal_actor_background_setup_failed",
            0,
        ),
        (
            "upload-transport",
            SimpleNamespace(return_code=0, stdout="", stderr=""),
            ConnectionError("upload transport lost"),
            "terminal_actor_background_start_failed",
            1,
        ),
    ],
)
def test_background_pre_start_transport_is_fatal_without_proof_or_replay(
    tmp_path: Path,
    stage: str,
    setup_outcome: object,
    upload_error: BaseException | None,
    expected_code: str,
    upload_count: int,
) -> None:
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    environment = BackgroundPreStartRemote(
        setup_outcome=setup_outcome,
        upload_error=upload_error,
    )
    actor = ProductionBackgroundStartActor(tmp_path, environment, task_id)

    with pytest.raises(ToolFatalError) as caught:
        asyncio.run(
            actor.execute(
                request(
                    tmp_path,
                    "run_terminal_command",
                    {
                        "command": "serve",
                        "description": stage,
                        "background": True,
                    },
                )
            )
        )

    assert caught.value.failure == ToolFailure(
        code=expected_code,
        execution_may_have_started=False,
        cleanup_verified=None,
        census_verified=None,
    )
    assert len(environment.exec_calls) == 1
    assert len(environment.upload_calls) == upload_count
    assert task_id not in actor._background


def test_background_settled_nonzero_setup_is_recoverable_not_started(
    tmp_path: Path,
) -> None:
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    environment = BackgroundPreStartRemote(
        setup_outcome=SimpleNamespace(return_code=73, stdout="", stderr="rejected"),
    )
    actor = ProductionBackgroundStartActor(tmp_path, environment, task_id)

    result = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "run_terminal_command",
                {
                    "command": "serve",
                    "description": "settled setup rejection",
                    "background": True,
                },
            )
        )
    )

    assert result.background_start_observation == BackgroundStartObservation(
        proof_version=BACKGROUND_START_PROOF_VERSION,
        kind=BackgroundStartKind.NOT_STARTED,
        task_id_published=False,
        child_exit_code=None,
    )
    assert len(environment.exec_calls) == 1
    assert environment.upload_calls == []
    assert task_id not in actor._background


@pytest.mark.parametrize("return_code", [None, "transport-garbage", True])
def test_background_malformed_setup_response_is_fatal_without_proof(
    tmp_path: Path,
    return_code: object,
) -> None:
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    environment = BackgroundPreStartRemote(
        setup_outcome=SimpleNamespace(
            return_code=return_code,
            stdout="",
            stderr="",
        ),
    )
    actor = ProductionBackgroundStartActor(tmp_path, environment, task_id)

    with pytest.raises(ToolFatalError) as caught:
        asyncio.run(
            actor.execute(
                request(
                    tmp_path,
                    "run_terminal_command",
                    {
                        "command": "serve",
                        "description": "malformed setup response",
                        "background": True,
                    },
                )
            )
        )

    assert caught.value.failure == ToolFailure(
        code="terminal_actor_background_setup_failed",
        execution_may_have_started=False,
        cleanup_verified=None,
        census_verified=None,
    )
    assert len(environment.exec_calls) == 1
    assert environment.upload_calls == []
    assert task_id not in actor._background


def test_background_status_loss_after_launch_retains_acknowledged_handle(
    tmp_path: Path,
) -> None:
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    actor = StatusLossAfterLaunchBackgroundActor(tmp_path, [task_id])

    retained = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "run_terminal_command",
                {
                    "command": "serve",
                    "description": "status transport loss",
                    "background": True,
                },
            )
        )
    )

    assert retained.process_disposition is ProcessDisposition.BACKGROUND_RETAINED
    assert retained.target_task_id == task_id
    assert retained.survivor_count == 1
    assert b"<status>running</status>" in retained.stdout
    assert b"<status-fresh>false</status-fresh>" in retained.stdout
    assert b"last known status" in retained.stdout
    assert actor.refresh_count == 1
    assert actor.terminated == []
    assert task_id in actor._background

    observed = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "get_terminal_command_output",
                {"task_ids": [task_id], "timeout_ms": 0},
            )
        )
    )
    assert b"Status: status_unavailable" in observed.stdout
    assert b"Last Known Status: running" in observed.stdout
    assert actor.refresh_count == 2

    assert asyncio.run(actor.cleanup_active()) is True
    assert actor.terminated == [task_id]
    assert task_id not in actor._background


def test_background_start_rpc_loss_cannot_be_recovered_as_quick_exit(
    tmp_path: Path,
) -> None:
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    actor = DispatchedStartLossCompletedBackgroundActor(tmp_path, [task_id])

    with pytest.raises(ToolFatalError) as caught:
        asyncio.run(
            actor.execute(
                request(
                    tmp_path,
                    "run_terminal_command",
                    {
                        "command": "true",
                        "description": "start RPC transport loss",
                        "background": True,
                    },
                )
            )
        )

    assert caught.value.failure == ToolFailure(
        code="terminal_actor_transport_unknown",
        execution_may_have_started=True,
        cleanup_verified=True,
        census_verified=True,
    )
    assert actor.launch_count == 1
    assert task_id not in actor._background


@pytest.mark.parametrize(
    ("state", "exit_code", "timed_out", "explicitly_killed"),
    [
        ("failed", 124, True, False),
        ("cancelled", -15, False, True),
        ("failed", None, False, False),
        ("completed", 7, False, False),
        ("failed", 0, False, False),
    ],
    ids=[
        "timed-out",
        "cancelled",
        "null-exit",
        "completed-nonzero",
        "failed-zero",
    ],
)
def test_background_invalid_terminal_state_is_fatal_not_quick_exit(
    tmp_path: Path,
    state: str,
    exit_code: int | None,
    timed_out: bool,
    explicitly_killed: bool,
) -> None:
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    actor = InvalidQuickExitBackgroundActor(
        tmp_path,
        [task_id],
        state=state,
        exit_code=exit_code,
        timed_out=timed_out,
        explicitly_killed=explicitly_killed,
    )

    with pytest.raises(ToolFatalError) as caught:
        asyncio.run(
            actor.execute(
                request(
                    tmp_path,
                    "run_terminal_command",
                    {
                        "command": "sleep 60",
                        "description": "times out before handoff",
                        "timeout": 1,
                        "background": True,
                    },
                )
            )
        )

    assert caught.value.failure == ToolFailure(
        code="terminal_actor_background_status_invalid",
        execution_may_have_started=True,
        cleanup_verified=True,
        census_verified=True,
    )
    assert task_id not in actor._background


def test_background_transport_loss_is_fatal_even_after_verified_cleanup(
    tmp_path: Path,
) -> None:
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    actor = AmbiguousStartBackgroundActor(tmp_path, [task_id], clean=True)

    with pytest.raises(ToolFatalError) as caught:
        asyncio.run(
            actor.execute(
                request(
                    tmp_path,
                    "run_terminal_command",
                    {
                        "command": "serve",
                        "description": "ambiguous start",
                        "background": True,
                    },
                )
            )
        )

    assert caught.value.failure == ToolFailure(
        code="terminal_actor_transport_unknown",
        execution_may_have_started=True,
        cleanup_verified=True,
        census_verified=True,
    )
    assert actor.launch_count == 1
    assert task_id not in actor._background


def test_background_ambiguous_start_with_unknown_cleanup_is_fatal(
    tmp_path: Path,
) -> None:
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    actor = AmbiguousStartBackgroundActor(tmp_path, [task_id], clean=False)

    with pytest.raises(
        ToolFatalError,
        match="terminal_actor_cleanup_unverified",
    ):
        asyncio.run(
            actor.execute(
                request(
                    tmp_path,
                    "run_terminal_command",
                    {
                        "command": "serve",
                        "description": "ambiguous start",
                        "background": True,
                    },
                )
            )
        )

    assert actor.launch_count == 1


def test_background_status_retries_one_transient_then_uses_fresh_result(
    tmp_path: Path,
) -> None:
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    environment = StatusRemote([TimeoutError("transient"), running_status()])
    actor = StatusActor(tmp_path, environment, task_id)

    result = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "get_terminal_command_output",
                {"task_ids": [task_id], "timeout_ms": 0},
            )
        )
    )

    assert len(environment.exec_calls) == 2
    assert result.return_code == 0
    assert b"Status: running" in result.stdout
    assert b"status_unavailable" not in result.stdout
    assert b"managed status and output above are authoritative" in result.stdout
    assert b"separate shell or process progress probes" in result.stdout


def test_background_status_keeps_exact_owned_group_after_leader_exit(
    tmp_path: Path,
) -> None:
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    environment = StatusRemote(
        [
            running_status(leader_exited=True),
            SimpleNamespace(
                return_code=0,
                stdout='{"process_alive":true}',
            ),
        ]
    )
    actor = StatusActor(tmp_path, environment, task_id)

    result = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "get_terminal_command_output",
                {"task_ids": [task_id], "timeout_ms": 0},
            )
        )
    )

    assert len(environment.exec_calls) == 2
    assert "background-liveness" in environment.exec_calls[1][0]
    assert result.return_code == 0
    assert b"Status: running" in result.stdout
    assert actor._background[task_id].leader_exited is True
    assert actor._background[task_id].census_verified is False


def test_background_terminal_status_becomes_cancelled_when_census_needs_kill() -> None:
    actor = RemoteTerminalActor(object())
    task = BackgroundTask(
        task_id="018f22d6-9f04-7cc0-8000-000000000001",
        request_dir="/tmp/background-terminal-residual",
        command="setsid sleep 30 & exit 0",
        logical_cwd="/workspace",
        output_path="/workspace/.terminals/residual.log",
        start_wall=1_736_942_400.0,
        start_monotonic=10.0,
        runtime_timeout_ms=None,
        spool_cap_bytes=1024,
        term_grace_ms=100,
        kill_confirmation_timeout_ms=500,
        state="completed",
        exit_code=0,
        leader_exited=True,
    )
    calls: list[str] = []

    async def confirm_residual(
        observed: BackgroundTask,
        confirmation_ms: int,
    ) -> bool:
        assert observed is task
        assert confirmation_ms == 500
        calls.append("confirm")
        return False

    async def kill_residual(
        observed: BackgroundTask,
        term_grace_ms: int,
        confirmation_ms: int,
    ) -> tuple[bool, bool, bool]:
        assert observed is task
        assert (term_grace_ms, confirmation_ms) == (100, 500)
        calls.append("kill")
        return True, True, True

    actor._confirm_background_stopped_remote = confirm_residual  # type: ignore[method-assign]
    actor._terminate_background_remote = kill_residual  # type: ignore[method-assign]

    asyncio.run(actor._verify_background_terminal_census(task, 100, 500))

    assert calls == ["confirm", "kill"]
    assert task.census_verified is True
    assert task.state == "cancelled"
    assert task.explicitly_killed is True
    assert task.exit_code == -15


def test_background_last_known_running_then_unavailable_is_truthful(
    tmp_path: Path,
) -> None:
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    environment = StatusRemote(
        [TimeoutError("transient one"), TimeoutError("transient two")]
    )
    actor = StatusActor(tmp_path, environment, task_id)

    result = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "get_terminal_command_output",
                {"task_ids": [task_id], "timeout_ms": 0},
            )
        )
    )

    assert len(environment.exec_calls) == 2
    assert result.return_code == 0
    assert b"Status: status_unavailable" in result.stdout
    assert b"Last Known Status: running" in result.stdout
    assert b"last known output" in result.stdout


def test_background_status_invalid_identity_is_fatal_without_retry(
    tmp_path: Path,
) -> None:
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    environment = StatusRemote(
        [SimpleNamespace(return_code=0, stdout='{"state":"running"}')]
    )
    actor = StatusActor(tmp_path, environment, task_id)

    with pytest.raises(
        BridgeError,
        match="terminal_actor_background_status_invalid",
    ):
        asyncio.run(
            actor.execute(
                request(
                    tmp_path,
                    "get_terminal_command_output",
                    {"task_ids": [task_id], "timeout_ms": 0},
                )
            )
        )

    assert len(environment.exec_calls) == 1


def test_background_launch_uses_uuid_renderer_and_pinned_timeout_semantics(
    tmp_path: Path,
) -> None:
    task_ids = [
        "018f22d6-9f04-7cc0-8000-000000000001",
        "018f22d6-9f04-7cc0-8000-000000000002",
        "018f22d6-9f04-7cc0-8000-000000000003",
    ]
    actor = ScriptedBackgroundActor(tmp_path, task_ids)
    for timeout in (None, 0, 1234):
        arguments: dict[str, object] = {
            "command": "printf ready; sleep 60",
            "description": "serve",
            "background": True,
        }
        if timeout is not None:
            arguments["timeout"] = timeout
        result = asyncio.run(
            actor.execute(request(tmp_path, "run_terminal_command", arguments))
        )
        task_id = task_ids[len(actor.launch_timeouts) - 1]
        output_file = f"{tmp_path}/.terminals/{task_id}.log"
        assert result.process_disposition is ProcessDisposition.BACKGROUND_RETAINED
        assert result.target_task_id == task_id
        assert result.cleanup_attempted is False
        assert result.survivor_count == 1
        assert result.stdout.decode() == (
            f"<task-id>{task_id}</task-id>\n"
            "<task-type>bash</task-type>\n"
            f"<output-file>{output_file}</output-file>\n"
            "<status>running</status>\n"
            f"<summary>Background task {task_id} started</summary>\n"
            "No unsolicited completion message is injected. Use "
            "get_terminal_command_output with "
            f'task_ids=["{task_id}"], timeout_ms=30000, wait_for="any" '
            "as the authoritative status and output channel. While it reports "
            "running, keep waiting through that managed handle instead of "
            "issuing separate shell or process progress probes. Use "
            f'kill_terminal_command with task_id="{task_id}" '
            "to cancel it through the managed owner."
        )
    assert actor.launch_timeouts == [None, None, 1234]


def test_shared_background_fixture_drives_renderer_and_terminal_states(
    tmp_path: Path,
) -> None:
    task_id = _BACKGROUND_FIXTURE["fixed_task_ids"][0]
    actor = ScriptedBackgroundActor(tmp_path, [task_id])
    launch = background_case("launch")
    launched = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                str(launch["tool_name"]),
                dict(launch["arguments"]),
            )
        )
    )
    assert f"<status>{launch['expected_status']}</status>".encode() in launched.stdout
    assert launched.process_disposition.value == launch["expected_process_disposition"]

    task = actor._background[task_id]
    task.state = "completed"
    task.exit_code = 0
    task.end_wall = 1_736_942_401.0
    task.end_monotonic = 11.0
    actor.outputs[task_id] = b"ready"
    completed = background_case("completed_snapshot")
    snapshot = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                str(completed["tool_name"]),
                dict(completed["arguments"]),
            )
        )
    )
    assert f"Status: {completed['expected_status']}".encode() in snapshot.stdout
    assert f"Exit Code: {completed['expected_exit_code']}".encode() in snapshot.stdout

    repeated_case = background_case("kill_repeated")
    repeated = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                str(repeated_case["tool_name"]),
                dict(repeated_case["arguments"]),
            )
        )
    )
    assert repeated.stdout.startswith(str(repeated_case["expected_status"]).encode())
    assert (
        repeated.process_disposition.value
        == repeated_case["expected_process_disposition"]
    )

    unknown_case = background_case("kill_unknown")
    unknown = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                str(unknown_case["tool_name"]),
                dict(unknown_case["arguments"]),
            )
        )
    )
    assert (
        str(unknown_case["expected_status"]).replace("_", " ").encode()
        in unknown.stdout
    )
    assert (
        unknown.process_disposition.value
        == unknown_case["expected_process_disposition"]
    )


def test_background_output_preserves_first_seen_order_and_operation_census(
    tmp_path: Path,
) -> None:
    first = "018f22d6-9f04-7cc0-8000-000000000001"
    second = "018f22d6-9f04-7cc0-8000-000000000002"
    unknown = "018f22d6-9f04-7cc0-8000-000000000099"
    actor = ScriptedBackgroundActor(tmp_path, [first, second])
    for task_id in (first, second):
        asyncio.run(
            actor.execute(
                request(
                    tmp_path,
                    "run_terminal_command",
                    {
                        "command": f"printf {task_id[-1]}; sleep 60",
                        "description": "serve",
                        "background": True,
                    },
                )
            )
        )
        actor.outputs[task_id] = task_id[-1].encode()
    result = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "get_terminal_command_output",
                {
                    "task_ids": [
                        f" {second} ",
                        "",
                        second,
                        unknown,
                        first,
                    ],
                    "timeout_ms": 0,
                },
            )
        )
    )
    rendered = result.stdout.decode()
    assert rendered.index(f"--- Task {second} [running] ---") < rendered.index(
        f"--- Task {unknown} [not_found] ---"
    )
    assert rendered.index(f"--- Task {unknown} [not_found] ---") < rendered.index(
        f"--- Task {first} [running] ---"
    )
    assert rendered.count(f"--- Task {second} [running] ---") == 1
    assert "0/3 tasks completed (poll)" in rendered
    assert result.process_disposition is ProcessDisposition.NO_PROCESS
    assert result.survivor_count == 0


def test_background_wait_any_returns_first_terminal_completion_facts(
    tmp_path: Path,
) -> None:
    first = "018f22d6-9f04-7cc0-8000-000000000001"
    second = "018f22d6-9f04-7cc0-8000-000000000002"
    actor = CompletingWaitActor(tmp_path, [first, second], {})
    for task_id in (first, second):
        asyncio.run(
            actor.execute(
                request(
                    tmp_path,
                    "run_terminal_command",
                    {
                        "command": "sleep 60",
                        "description": "parallel build",
                        "background": True,
                    },
                )
            )
        )
    actor.complete_after = {first: 1, second: 3}
    actor.refresh_counts.clear()

    result = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "get_terminal_command_output",
                {
                    "task_ids": [first, second],
                    "timeout_ms": 1_000,
                    "wait_for": "any",
                },
            )
        )
    )

    rendered = result.stdout.decode()
    assert "<wait-mode>wait_any</wait-mode>" in rendered
    assert "<wait-condition-met>true</wait-condition-met>" in rendered
    assert f"<terminal-task-ids>{first}</terminal-task-ids>" in rendered
    assert f"<running-task-ids>{second}</running-task-ids>" in rendered
    assert "managed status and output above are authoritative" in rendered
    assert "separate shell or process progress probes" in rendered
    assert actor.refresh_counts == {first: 1, second: 1}


def test_background_wait_all_preserves_legacy_multi_wait_semantics(
    tmp_path: Path,
) -> None:
    first = "018f22d6-9f04-7cc0-8000-000000000001"
    second = "018f22d6-9f04-7cc0-8000-000000000002"
    actor = CompletingWaitActor(tmp_path, [first, second], {})
    for task_id in (first, second):
        asyncio.run(
            actor.execute(
                request(
                    tmp_path,
                    "run_terminal_command",
                    {
                        "command": "sleep 60",
                        "description": "parallel build",
                        "background": True,
                    },
                )
            )
        )
    actor.complete_after = {first: 1, second: 2}
    actor.refresh_counts.clear()

    result = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "get_terminal_command_output",
                {
                    "task_ids": [first, second],
                    "timeout_ms": 1_000,
                    "wait_for": "all",
                },
            )
        )
    )

    rendered = result.stdout.decode()
    assert "<wait-mode>wait_all</wait-mode>" in rendered
    assert "<wait-condition-met>true</wait-condition-met>" in rendered
    assert f"<terminal-task-ids>{first},{second}</terminal-task-ids>" in rendered
    assert "<running-task-ids></running-task-ids>" in rendered
    assert actor.refresh_counts == {first: 1, second: 2}


def test_background_wait_mode_is_typed_and_rejects_unknown_values(
    tmp_path: Path,
) -> None:
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    actor = ScriptedBackgroundActor(tmp_path, [task_id])
    asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "run_terminal_command",
                {
                    "command": "sleep 60",
                    "description": "parallel build",
                    "background": True,
                },
            )
        )
    )

    with pytest.raises(BridgeError, match="terminal_actor_arguments_invalid"):
        asyncio.run(
            actor.execute(
                request(
                    tmp_path,
                    "get_terminal_command_output",
                    {
                        "task_ids": [task_id],
                        "timeout_ms": 1_000,
                        "wait_for": "first",
                    },
                )
            )
        )


def test_background_wait_any_timeout_returns_unmet_completion_facts(
    tmp_path: Path,
) -> None:
    first = "018f22d6-9f04-7cc0-8000-000000000001"
    second = "018f22d6-9f04-7cc0-8000-000000000002"
    actor = ScriptedBackgroundActor(tmp_path, [first, second])
    for task_id in (first, second):
        asyncio.run(
            actor.execute(
                request(
                    tmp_path,
                    "run_terminal_command",
                    {
                        "command": "sleep 60",
                        "description": "parallel build",
                        "background": True,
                    },
                )
            )
        )
    actor._monotonic = time.monotonic

    result = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "get_terminal_command_output",
                {
                    "task_ids": [first, second],
                    "timeout_ms": 5,
                    "wait_for": "any",
                },
            )
        )
    )

    rendered = result.stdout.decode()
    assert "<wait-mode>wait_any</wait-mode>" in rendered
    assert "<wait-condition-met>false</wait-condition-met>" in rendered
    assert "<terminal-task-ids></terminal-task-ids>" in rendered
    assert f"<running-task-ids>{first},{second}</running-task-ids>" in rendered


def test_background_kill_repeat_unknown_and_cleanup_are_stable(
    tmp_path: Path,
) -> None:
    first = "018f22d6-9f04-7cc0-8000-000000000001"
    second = "018f22d6-9f04-7cc0-8000-000000000002"
    unknown = "018f22d6-9f04-7cc0-8000-000000000099"
    actor = ScriptedBackgroundActor(tmp_path, [first, second])
    for task_id in (first, second):
        asyncio.run(
            actor.execute(
                request(
                    tmp_path,
                    "run_terminal_command",
                    {
                        "command": "sleep 60",
                        "description": "serve",
                        "background": True,
                    },
                )
            )
        )
    killed = asyncio.run(
        actor.execute(request(tmp_path, "kill_terminal_command", {"task_id": first}))
    )
    repeated = asyncio.run(
        actor.execute(request(tmp_path, "kill_terminal_command", {"task_id": first}))
    )
    missing = asyncio.run(
        actor.execute(request(tmp_path, "kill_terminal_command", {"task_id": unknown}))
    )
    assert killed.stdout == b"killed: Task was terminated successfully"
    assert killed.process_disposition is ProcessDisposition.BACKGROUND_TERMINATED
    assert repeated.stdout == b"already_exited: Task had already completed"
    assert repeated.process_disposition is ProcessDisposition.BACKGROUND_TERMINATED
    assert missing.process_disposition is ProcessDisposition.NO_PROCESS
    assert unknown.encode() in missing.stdout
    actor._background[first].end_monotonic = -1000
    actor._prune_background()
    assert first in actor._background, "5-minute live retention is not tombstone TTL"
    assert asyncio.run(actor.cleanup_active()) is True
    assert actor.terminated == [first, second]
    assert actor.confirmed == [second]
    assert actor._background == {}


def test_running_snapshot_at_spool_cap_includes_truncation_hint(
    tmp_path: Path,
) -> None:
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    actor = ScriptedBackgroundActor(tmp_path, [task_id])
    asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "run_terminal_command",
                {
                    "command": "yes",
                    "description": "fill spool",
                    "background": True,
                },
            )
        )
    )
    actor._background[task_id].spool_cap_bytes = 4
    actor.outputs[task_id] = b"xxxx"
    snapshot = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "get_terminal_command_output",
                {"task_ids": [task_id], "timeout_ms": 0},
            )
        )
    )
    assert b"Output truncated. Full output:" in snapshot.stdout


def test_sequential_backgrounds_reclaim_unused_reservation_and_enforce_run_cap(
    tmp_path: Path,
) -> None:
    task_ids = [f"018f22d6-9f04-7cc0-8000-{index:012d}" for index in range(1, 13)]
    actor = ScriptedBackgroundActor(tmp_path, task_ids)

    def bounded_request(
        tool_name: str,
        arguments: dict[str, object],
        *,
        per_process: int,
        per_run: int,
    ) -> ToolRequest:
        original = request(tmp_path, tool_name, arguments)
        return ToolRequest(
            **{
                **original.__dict__,
                "process_spool_bytes_per_process": per_process,
                "process_spool_bytes_per_run": per_run,
            }
        )

    for task_id in task_ids[:9]:
        launched = asyncio.run(
            actor.execute(
                bounded_request(
                    "run_terminal_command",
                    {
                        "command": "printf x",
                        "description": "tiny",
                        "background": True,
                    },
                    per_process=16,
                    per_run=160,
                )
            )
        )
        assert launched.return_code == 0
        actor.outputs[task_id] = b"x"
        asyncio.run(
            actor.execute(
                bounded_request(
                    "kill_terminal_command",
                    {"task_id": task_id},
                    per_process=16,
                    per_run=160,
                )
            )
        )

    cap_actor = ScriptedBackgroundActor(tmp_path, task_ids[9:12])
    for task_id in task_ids[9:11]:
        launched = asyncio.run(
            cap_actor.execute(
                bounded_request(
                    "run_terminal_command",
                    {
                        "command": "printf x",
                        "description": "tiny",
                        "background": True,
                    },
                    per_process=8,
                    per_run=9,
                )
            )
        )
        assert launched.return_code == 0
        cap_actor.outputs[task_id] = b"x"
        asyncio.run(
            cap_actor.execute(
                bounded_request(
                    "kill_terminal_command",
                    {"task_id": task_id},
                    per_process=8,
                    per_run=9,
                )
            )
        )
    rejected = asyncio.run(
        cap_actor.execute(
            bounded_request(
                "run_terminal_command",
                {
                    "command": "printf x",
                    "description": "tiny",
                    "background": True,
                },
                per_process=8,
                per_run=9,
            )
        )
    )
    assert rejected.return_code == 2
    assert b"<observation>background_start_not_running</observation>" in rejected.stdout
    assert b"output-spool limit is exhausted" in rejected.stdout


def test_read_text_offset_limit_crlf_and_empty_range(tmp_path: Path) -> None:
    actor = LocalFileActor(tmp_path)
    (tmp_path / "notes.txt").write_bytes("one\r\ntwo🙂\r\nthree\r\n".encode())
    result = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "read_file",
                {"target_file": "notes.txt", "offset": 2, "limit": 2},
            )
        )
    )
    assert result.return_code == 0
    assert result.stdout.decode() == "2→two🙂\n3→three\n"
    past = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "read_file",
                {"target_file": "notes.txt", "offset": 99},
            )
        )
    )
    assert past.stdout == b""


def test_read_rejects_binary_media_and_oversize(tmp_path: Path) -> None:
    actor = LocalFileActor(tmp_path)
    (tmp_path / "binary.dat").write_bytes(b"a\x00b")
    (tmp_path / "image.png").write_bytes(b"png")
    (tmp_path / "large.txt").write_text("abcdef", encoding="utf-8")
    for name, expected, cap in [
        ("binary.dat", "binary_file_unsupported", 1024),
        ("image.png", "read_file_media_not_enabled", 1024),
        ("large.txt", "read_file_too_large", 3),
    ]:
        result = asyncio.run(
            actor.execute(
                request(
                    tmp_path,
                    "read_file",
                    {"target_file": name},
                    read_cap=cap,
                )
            )
        )
        assert result.return_code == 2
        assert result.stdout.decode() == expected


@pytest.mark.parametrize(
    ("source_format", "suffix", "expected_mime"),
    [
        ("PNG", ".jpg", "image/png"),
        ("JPEG", ".png", "image/jpeg"),
    ],
)
def test_read_media_uses_magic_and_preserves_the_bounded_source_bytes(
    tmp_path: Path,
    source_format: str,
    suffix: str,
    expected_mime: str,
) -> None:
    target = tmp_path / f"fixture{suffix}"
    sentinel = b"NANO_MEDIA_METADATA_SENTINEL"
    target.write_bytes(
        _png_bytes(3, 2, metadata=sentinel)
        if source_format == "PNG"
        else _jpeg_bytes(3, 2, metadata=sentinel)
    )
    source = target.read_bytes()

    result = asyncio.run(
        LocalMediaActor(tmp_path).execute(
            request(
                tmp_path,
                "read_file",
                {"target_file": target.name},
                read_cap=4 * 1024 * 1024,
                media_enabled=True,
            )
        )
    )

    assert result.return_code == 0
    assert result.media is not None
    assert result.media.logical_path == target.name
    assert result.media.mime_type == expected_mime
    assert result.media.width == 3
    assert result.media.height == 2
    assert result.media.source_byte_length == len(source)
    assert result.media.source_sha256 == hashlib.sha256(source).hexdigest()
    assert result.media.canonical_byte_length == len(result.media.content)
    assert (
        result.media.canonical_sha256
        == hashlib.sha256(result.media.content).hexdigest()
    )
    assert result.media.content == source
    assert result.media.canonical_sha256 == result.media.source_sha256
    assert sentinel in result.media.content
    assert result.stdout.decode() == (
        f"read_file returned an attached image: {expected_mime}, 3x2, "
        f"sha256={result.media.canonical_sha256}"
    )


@pytest.mark.parametrize(
    ("name", "payload", "expected"),
    [
        ("bad.png", b"not an image", "read_file_media_invalid"),
        (
            "truncated.bin",
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
            "read_file_media_invalid",
        ),
        (
            "unsupported.webp",
            b"RIFF\x08\x00\x00\x00WEBPVP8 ",
            "read_file_media_unsupported",
        ),
        (
            "animated.png",
            _png_bytes(1, 1, animation=True),
            "read_file_media_animation_unsupported",
        ),
        (
            "bad-marker.jpeg",
            b"\xff\xd8\xff\xe1\x00",
            "read_file_media_invalid",
        ),
    ],
)
def test_read_media_rejects_bad_magic_decode_and_unsupported_types(
    tmp_path: Path,
    name: str,
    payload: bytes,
    expected: str,
) -> None:
    (tmp_path / name).write_bytes(payload)
    result = asyncio.run(
        LocalMediaActor(tmp_path).execute(
            request(
                tmp_path,
                "read_file",
                {"target_file": name},
                media_enabled=True,
            )
        )
    )
    assert result.return_code == 2
    assert result.stdout.decode() == expected
    assert result.media is None


@pytest.mark.parametrize(
    ("name", "size", "expected"),
    [
        ("wide.png", (8193, 1), "read_file_media_dimension_limit_exceeded"),
        ("pixels.png", (5001, 5000), "read_file_media_pixel_limit_exceeded"),
    ],
)
def test_read_media_rejects_dimension_and_pixel_caps(
    tmp_path: Path,
    name: str,
    size: tuple[int, int],
    expected: str,
) -> None:
    (tmp_path / name).write_bytes(_png_bytes(size[0], size[1], pixel_data=False))
    result = asyncio.run(
        LocalMediaActor(tmp_path).execute(
            request(
                tmp_path,
                "read_file",
                {"target_file": name},
                media_enabled=True,
                read_cap=4 * 1024 * 1024,
            )
        )
    )
    assert result.return_code == 2
    assert result.stdout.decode() == expected


def test_read_media_rejects_source_byte_cap_before_decode(tmp_path: Path) -> None:
    target = tmp_path / "huge.png"
    target.write_bytes(b"\x89PNG\r\n\x1a\n" + b"x" * (4 * 1024 * 1024))
    result = asyncio.run(
        LocalMediaActor(tmp_path).execute(
            request(
                tmp_path,
                "read_file",
                {"target_file": target.name},
                media_enabled=True,
                read_cap=5 * 1024 * 1024,
            )
        )
    )
    assert result.return_code == 2
    assert result.stdout == b"read_file_media_source_too_large"


@pytest.mark.parametrize(
    "relative",
    [
        ".env.png",
        ".git/screenshot.png",
        ".terminals/screenshot.png",
        ".ssh/screenshot.png",
        ".aws/screenshot.png",
        "artifacts/screenshot.png",
        "credentials.png",
        "private-key.pem",
    ],
)
def test_read_media_rejects_sensitive_paths(tmp_path: Path, relative: str) -> None:
    target = tmp_path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(_png_bytes(1, 1))
    result = asyncio.run(
        LocalMediaActor(tmp_path).execute(
            request(
                tmp_path,
                "read_file",
                {"target_file": relative},
                media_enabled=True,
            )
        )
    )
    assert result.return_code == 2
    assert result.stdout == b"read_file_sensitive_path"


def test_read_media_rejects_symlinks_and_source_changes(tmp_path: Path) -> None:
    source = tmp_path / "source.png"
    source.write_bytes(_png_bytes(1, 1))
    (tmp_path / "linked.png").symlink_to(source)
    linked = asyncio.run(
        LocalMediaActor(tmp_path).execute(
            request(
                tmp_path,
                "read_file",
                {"target_file": "linked.png"},
                media_enabled=True,
            )
        )
    )
    assert linked.return_code == 2
    assert linked.stdout == b"read_file_media_symlink_rejected"

    changed = asyncio.run(
        LocalMediaActor(tmp_path, mutate_after_download=True).execute(
            request(
                tmp_path,
                "read_file",
                {"target_file": "source.png"},
                media_enabled=True,
            )
        )
    )
    assert changed.return_code == 2
    assert changed.stdout == b"read_file_media_source_changed"


def test_write_create_overwrite_empty_and_preserve_mode(tmp_path: Path) -> None:
    actor = LocalFileActor(tmp_path)
    created = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "write",
                {"file_path": "nested/new.txt", "content": "hello"},
            )
        )
    )
    target = tmp_path / "nested" / "new.txt"
    assert created.stdout.decode() == f"The file {target} has been " + "created."
    target.chmod(0o640)
    overwritten = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "write",
                {"file_path": "nested/new.txt", "content": ""},
            )
        )
    )
    assert overwritten.stdout.decode() == f"Wrote file successfully to {target}."
    assert target.read_bytes() == b""
    assert stat.S_IMODE(target.stat().st_mode) == 0o640


def test_write_rejects_relative_and_symlink_escape_without_mutation(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "sentinel").write_text("safe", encoding="utf-8")
    (workspace / "escape").symlink_to(outside, target_is_directory=True)
    actor = LocalFileActor(workspace)
    for target in ("../outside/sentinel", "escape/sentinel"):
        result = asyncio.run(
            actor.execute(
                request(
                    workspace,
                    "write",
                    {"file_path": target, "content": "changed"},
                )
            )
        )
        assert result.return_code == 2
        assert result.stdout == b"path_outside_workspace"
    assert (outside / "sentinel").read_text(encoding="utf-8") == "safe"


def test_search_replace_one_zero_multiple_and_replace_all(tmp_path: Path) -> None:
    actor = LocalFileActor(tmp_path)
    target = tmp_path / "notes.txt"
    target.write_text("alpha beta alpha\n", encoding="utf-8")
    original = target.read_bytes()
    multiple = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "search_replace",
                {
                    "file_path": "notes.txt",
                    "old_string": "alpha",
                    "new_string": "omega",
                },
            )
        )
    )
    assert multiple.return_code == 2
    assert b"found multiple times" in multiple.stdout
    assert target.read_bytes() == original
    missing = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "search_replace",
                {
                    "file_path": "notes.txt",
                    "old_string": "missing",
                    "new_string": "omega",
                },
            )
        )
    )
    assert missing.return_code == 2
    assert b"read_file" in missing.stdout
    assert target.read_bytes() == original
    replaced = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "search_replace",
                {
                    "file_path": "notes.txt",
                    "old_string": "alpha",
                    "new_string": "omega",
                    "replace_all": True,
                },
            )
        )
    )
    assert replaced.return_code == 0
    assert target.read_text(encoding="utf-8") == "omega beta omega\n"
    assert (
        replaced.stdout.decode() == "The file notes.txt has been updated. "
        "All occurrences were successfully replaced."
    )


def test_search_replace_empty_old_crlf_and_mode_preservation(
    tmp_path: Path,
) -> None:
    actor = LocalFileActor(tmp_path)
    created = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "search_replace",
                {
                    "file_path": "new.txt",
                    "old_string": "",
                    "new_string": "whole file\n",
                },
            )
        )
    )
    assert created.return_code == 0
    assert (tmp_path / "new.txt").read_text(encoding="utf-8") == "whole file\n"

    target = tmp_path / "crlf.txt"
    target.write_bytes(b"one\r\ntwo\r\n")
    target.chmod(0o640)
    result = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "search_replace",
                {
                    "file_path": "crlf.txt",
                    "old_string": "two\n",
                    "new_string": "three\r\n",
                },
            )
        )
    )
    assert result.return_code == 0
    assert target.read_bytes() == b"one\r\nthree\r\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o640


def test_search_replace_caps_binary_same_and_escape_do_not_mutate(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "notes.txt"
    target.write_text("a a\n", encoding="utf-8")
    binary = workspace / "binary"
    binary.write_bytes(b"a\x00a")
    outside = tmp_path / "outside.txt"
    outside.write_text("a", encoding="utf-8")
    actor = LocalFileActor(workspace)
    cases = [
        (
            {
                "file_path": "notes.txt",
                "old_string": "a",
                "new_string": "b",
                "replace_all": True,
            },
            1024,
            1,
        ),
        (
            {
                "file_path": "binary",
                "old_string": "a",
                "new_string": "b",
            },
            1024,
            100,
        ),
        (
            {
                "file_path": "notes.txt",
                "old_string": "a",
                "new_string": "a",
            },
            1024,
            100,
        ),
        (
            {
                "file_path": "../outside.txt",
                "old_string": "a",
                "new_string": "b",
            },
            1024,
            100,
        ),
    ]
    original = target.read_bytes()
    outside_original = outside.read_bytes()
    for arguments, cap, replacement_cap in cases:
        result = asyncio.run(
            actor.execute(
                request(
                    workspace,
                    "search_replace",
                    arguments,
                    read_cap=cap,
                    replacement_cap=replacement_cap,
                )
            )
        )
        assert result.return_code == 2
        assert target.read_bytes() == original
        assert outside.read_bytes() == outside_original


def test_list_dir_sorted_hidden_gitignored_empty_and_caps(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "b.py").write_text("", encoding="utf-8")
    (tmp_path / "src" / "A.py").write_text("", encoding="utf-8")
    (tmp_path / ".hidden").write_text("", encoding="utf-8")
    (tmp_path / "ignored").mkdir()
    (tmp_path / "ignored" / "x.txt").write_text("", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("ignored/\n", encoding="utf-8")
    actor = LocalFileActor(tmp_path)
    result = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "list_dir",
                {"target_directory": "."},
            )
        )
    )
    assert result.return_code == 0
    assert result.stdout.decode() == (
        f"- {tmp_path}/\n  - src/\n    - A.py\n    - b.py\n"
    )

    empty = tmp_path / "empty"
    empty.mkdir()
    empty_result = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "list_dir",
                {"target_directory": "empty"},
            )
        )
    )
    assert empty_result.stdout.decode() == f"- {empty}/\n"

    capped_request = request(
        tmp_path,
        "list_dir",
        {"target_directory": "."},
        output_cap=180,
    )
    capped_request = ToolRequest(
        **{
            **capped_request.__dict__,
            "max_directory_entries": 2,
        }
    )
    capped = asyncio.run(actor.execute(capped_request))
    assert b"output truncated" in capped.stdout


def test_list_dir_rejects_file_and_symlink_escape(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    file_path = workspace / "file.txt"
    file_path.write_text("", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (workspace / "escape").symlink_to(outside, target_is_directory=True)
    actor = LocalFileActor(workspace)
    for target in ("file.txt", "missing", "escape"):
        result = asyncio.run(
            actor.execute(
                request(
                    workspace,
                    "list_dir",
                    {"target_directory": target},
                )
            )
        )
        assert result.return_code == 2


def test_grep_hit_context_no_hit_error_and_truncation(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("needle\n", encoding="utf-8")
    actor = ScriptedSearchActor(
        tmp_path,
        backend="rg",
        code=0,
        lines=["src/a.py:1:needle", "src/a.py-2-context", "third"],
    )
    result = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "grep",
                {
                    "pattern": "needle",
                    "path": "src",
                    "glob": "*.py",
                    "type": "py",
                    "-A": 1,
                    "-i": True,
                    "head_limit": 2,
                },
            )
        )
    )
    assert result.return_code == 0
    assert result.stdout.decode().startswith("src/a.py:1:needle\nsrc/a.py-2-context\n")
    assert result.stdout.decode().endswith("\n... output truncated ...\n")
    assert "--glob" in actor.argv and "--type" in actor.argv and "-i" in actor.argv

    no_hit = ScriptedSearchActor(tmp_path, backend="rg", code=1, lines=[])
    no_hit_result = asyncio.run(
        no_hit.execute(request(tmp_path, "grep", {"pattern": "absent"}))
    )
    assert no_hit_result.return_code == 0
    assert no_hit_result.stdout == b""

    invalid = ScriptedSearchActor(
        tmp_path,
        backend="rg",
        code=2,
        lines=["regex parse error"],
    )
    invalid_result = asyncio.run(
        invalid.execute(request(tmp_path, "grep", {"pattern": "["}))
    )
    assert invalid_result.return_code == 2
    assert invalid_result.stdout == b"regex parse error\n"


def test_grep_fallback_is_explicit_about_missing_features(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("needle\n", encoding="utf-8")
    actor = ScriptedSearchActor(
        tmp_path,
        backend="grep",
        code=0,
        lines=["a.py:1:needle"],
    )
    supported = asyncio.run(
        actor.execute(
            request(
                tmp_path,
                "grep",
                {"pattern": "needle", "type": "py"},
            )
        )
    )
    assert supported.return_code == 0
    assert "--include=*.py" in actor.argv
    for arguments, expected in [
        (
            {"pattern": "needle", "multiline": True},
            b"grep_multiline_unsupported_without_rg",
        ),
        (
            {"pattern": "needle", "glob": "*.{py,rs}"},
            b"grep_glob_unsupported_without_rg",
        ),
        (
            {"pattern": "needle", "type": "unknown"},
            b"grep_type_unsupported_without_rg",
        ),
    ]:
        result = asyncio.run(actor.execute(request(tmp_path, "grep", arguments)))
        assert result.return_code == 2
        assert result.stdout == expected


def test_snapshot_outer_result_discriminants_are_closed_and_distinct() -> None:
    expected = {
        "outer_return_code_type_invalid",
        "outer_return_code_nonzero",
        "outer_stdout_type_invalid",
        "outer_stderr_type_invalid",
        "outer_stderr_nonempty",
    }

    assert {
        reason.value
        for reason in terminal_actor.SnapshotFailureReasonV1
        if reason.value.startswith("outer_")
    } == expected
    assert len(expected) == len(set(expected))
    for case in _TERMINAL_PHASE_FIXTURE["outer_cases"]:
        return_code = {
            "bool": True,
            "nonzero_int": 7,
            "zero_int": 0,
        }[case["return_code_shape"]]
        stdout = object() if case["stdout_shape"] == "wrong_type" else "bounded stdout"
        stderr = {
            "wrong_type": object(),
            "empty_text": "",
            "bounded_text": "bounded stderr",
        }[case["stderr_shape"]]
        with pytest.raises(SnapshotOperationFailure) as caught:
            terminal_actor._validate_snapshot_outer_result(
                SimpleNamespace(
                    return_code=return_code,
                    stdout=stdout,
                    stderr=stderr,
                ),
                boundary_subtype=SnapshotFailureSubtypeV1.WAIT_RESPONSE_INVALID,
            )
        evidence = caught.value.evidence
        assert evidence.reason.value == case["expected_reason"], case["id"]
        assert (evidence.observed_byte_length is not None) is case["bounded_text"], (
            case["id"]
        )
        assert (evidence.observed_sha256 is not None) is case["bounded_text"], case[
            "id"
        ]

    with pytest.raises(SnapshotOperationFailure) as caught:
        terminal_actor._validate_snapshot_outer_result(
            SimpleNamespace(return_code=0, stdout="", stderr="\ud800"),
            boundary_subtype=SnapshotFailureSubtypeV1.WAIT_RESPONSE_INVALID,
        )
    assert (
        caught.value.evidence.reason
        is terminal_actor.SnapshotFailureReasonV1.OUTER_STDERR_NONEMPTY
    )
    assert caught.value.evidence.observed_byte_length is None
    assert caught.value.evidence.observed_sha256 is None


def test_snapshot_terminal_record_discriminants_are_closed_and_distinct() -> None:
    expected = {
        "terminal_json_invalid",
        "terminal_keyset_invalid",
        "terminal_field_type_invalid",
        "terminal_status_invalid",
        "terminal_identity_mismatch",
        "termination_proof_invalid",
        "terminal_cancelled",
    }

    assert {
        reason.value
        for reason in terminal_actor.SnapshotFailureReasonV1
        if reason.value.startswith("terminal_")
        or reason.value == "termination_proof_invalid"
    } == expected
    assert len(expected) == len(set(expected))
    token = "a" * 64
    remote = OwnedSnapshotRemote()
    lease_raw = json.dumps(remote._ready(token), separators=(",", ":")) + "\n"
    lease = terminal_actor._snapshot_lease(
        lease_raw,
        control_dir="/tmp/nano-workspace-snapshot-v1.fixture/control",
        owner_token=token,
    )
    bound_terminal = terminal_actor._snapshot_terminal(
        json.dumps(remote._terminal(token), separators=(",", ":")) + "\n",
        lease,
    )
    assert bound_terminal.execution_binding_verified is True
    for case in _TERMINAL_PHASE_FIXTURE["terminal_cases"]:
        mutation = case["mutation_oracle"]
        if mutation == "cancelled_terminal":
            actor = _owned_snapshot_actor(OwnedSnapshotRemote(status="cancelled"))
            with pytest.raises(SnapshotOperationFailure) as caught:
                asyncio.run(
                    actor.exec_snapshot_owned(
                        "printf cancelled",
                        stage="/tmp/nano-workspace-snapshot-v1.fixture",
                        timeout_sec=120,
                    )
                )
            evidence = caught.value.evidence
        else:
            terminal = remote._terminal(token)
            if mutation == "invalid_json":
                raw = "{"
            else:
                if mutation == "extra_key":
                    terminal["extra"] = 1
                elif mutation == "boolean_return_code":
                    terminal["return_code"] = True
                elif mutation == "completed_nonzero":
                    terminal["return_code"] = 7
                elif mutation == "owner_token_mismatch":
                    terminal["owner_token"] = "b" * 64
                elif mutation == "nonzero_survivor_count":
                    terminal["survivor_count"] = 1
                raw = json.dumps(terminal, separators=(",", ":")) + "\n"
            with pytest.raises(SnapshotTerminationUnverified) as caught:
                terminal_actor._snapshot_terminal(raw, lease)
            evidence = caught.value.evidence
        assert evidence.reason.value == case["expected_reason"], case["id"]
        assert evidence.observed_byte_length is not None, case["id"]
        assert evidence.observed_sha256 is not None, case["id"]
        assert evidence.execution_binding_verified is (
            mutation == "cancelled_terminal"
        ), case["id"]


def test_process_lease_requires_exact_two_task_identity_set(
    tmp_path: Path,
) -> None:
    task_ids = [
        "018f22d6-9f04-7cc0-8000-000000000001",
        "018f22d6-9f04-7cc0-8000-000000000002",
    ]
    actor = ScriptedBackgroundActor(tmp_path, task_ids)
    for task_id in task_ids:
        retained = asyncio.run(
            actor.execute(
                request(
                    tmp_path,
                    "run_terminal_command",
                    {
                        "command": "sleep 60",
                        "description": task_id,
                        "background": True,
                    },
                )
            )
        )
        assert retained.process_disposition is ProcessDisposition.BACKGROUND_RETAINED

    manifest = asyncio.run(actor.background_manifest())
    assert [row["task_id"] for row in manifest] == task_ids
    with pytest.raises(BridgeError, match="process_lease"):
        actor.seal_process_lease_v1(manifest[:1])

    process_lease = actor.seal_process_lease_v1(manifest)
    assert process_lease.process_count == 2
    extra_task_id = "018f22d6-9f04-7cc0-8000-000000000003"
    actor._background[extra_task_id] = BackgroundTask(
        task_id=extra_task_id,
        request_dir=actor._background_dir(extra_task_id),
        command="sleep 60",
        logical_cwd=str(tmp_path),
        output_path=f"{tmp_path}/.terminals/{extra_task_id}.log",
        start_wall=1_736_942_400.0,
        start_monotonic=10.0,
        runtime_timeout_ms=None,
        spool_cap_bytes=1024,
        term_grace_ms=100,
        kill_confirmation_timeout_ms=100,
        pgid=4003,
        monitor_pgid=5003,
        monitor_starttime=7003,
    )
    with pytest.raises(BridgeError, match="process_lease_observation_invalid"):
        asyncio.run(
            actor.observe_process_lease_v1(
                process_lease,
                hard_deadline_monotonic_ns=20_000_000_000,
            )
        )
    del actor._background[extra_task_id]
    actor._background[task_ids[0]].leader_starttime += 1
    with pytest.raises(BridgeError, match="process_lease"):
        actor.seal_process_lease_v1(manifest)


def test_background_manifest_rejects_running_task_without_complete_identity() -> None:
    actor = RemoteTerminalActor(object())
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    actor._background[task_id] = BackgroundTask(
        task_id=task_id,
        request_dir=actor._background_dir(task_id),
        command="serve",
        logical_cwd="/workspace",
        output_path=f"/workspace/.terminals/{task_id}.log",
        start_wall=1_736_942_400.0,
        start_monotonic=10.0,
        runtime_timeout_ms=None,
        spool_cap_bytes=1024,
        term_grace_ms=100,
        kill_confirmation_timeout_ms=100,
    )

    async def preserve_incomplete_start() -> None:
        return None

    actor._refresh_all_background = preserve_incomplete_start  # type: ignore[method-assign]

    with pytest.raises(
        BridgeError,
        match="^terminal_actor_background_status_unavailable$",
    ):
        asyncio.run(actor.background_manifest())


def test_background_start_captures_exact_leader_and_monitor_starttimes(
    tmp_path: Path,
) -> None:
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    owner_token = "a" * 64
    remote = ScriptedRemote(
        [
            SimpleNamespace(return_code=0, stdout="", stderr=""),
            SimpleNamespace(
                return_code=0,
                stdout=json.dumps(
                    {
                        "pgid": 4001,
                        "leader_starttime": 6001,
                        "monitor_pgid": 5001,
                        "monitor_starttime": 7001,
                        "owner_token": owner_token,
                    },
                    separators=(",", ":"),
                )
                + "\n",
                stderr="",
            ),
        ]
    )
    actor = ProductionBackgroundStartActor(tmp_path, remote, task_id)
    task = BackgroundTask(
        task_id=task_id,
        request_dir=actor._background_dir(task_id),
        command="serve",
        logical_cwd="/workspace",
        output_path=f"/workspace/.terminals/{task_id}.log",
        start_wall=1_736_942_400.0,
        start_monotonic=10.0,
        runtime_timeout_ms=None,
        spool_cap_bytes=1024,
        term_grace_ms=100,
        kill_confirmation_timeout_ms=100,
        owner_token=owner_token,
    )

    asyncio.run(
        actor._launch_background_remote(
            task,
            request(
                tmp_path,
                "run_terminal_command",
                {
                    "command": "serve",
                    "description": "capture identities",
                    "background": True,
                },
            ),
            None,
        )
    )

    assert (task.pgid, task.leader_starttime) == (4001, 6001)
    assert (task.monitor_pgid, task.monitor_starttime) == (5001, 7001)


def test_background_cleanup_shell_revalidates_starttime_before_group_signal() -> None:
    cleanup = _ACTOR.split('if [ "$mode" = "cleanup-signal" ]; then', 1)[1].split(
        'if [ "$mode" = "cleanup-census" ]; then',
        1,
    )[0]
    assert "expected_leader_starttime" in cleanup
    assert "expected_monitor_starttime" in cleanup
    assert "background_signal_identity" in cleanup
    background_cleanup = cleanup.split(
        'elif [ "$process_kind" = "background" ]; then',
        1,
    )[1]
    assert 'kill "-$signal_name" -- "-$pgid"' not in background_cleanup


class BackgroundHandoffRemote:
    def __init__(self, *, process_alive: bool) -> None:
        self.process_alive = process_alive
        self.exec_calls: list[str] = []

    async def exec(self, command, cwd=None, timeout_sec=None, user=None):
        del cwd, timeout_sec, user
        self.exec_calls.append(command)
        if " background-liveness " in command:
            return SimpleNamespace(
                return_code=0,
                stdout=json.dumps(
                    {"process_alive": self.process_alive},
                    separators=(",", ":"),
                )
                + "\n",
                stderr="",
            )
        if " cleanup-signal " in command:
            return SimpleNamespace(return_code=0, stdout="signal-ok\n", stderr="")
        if " cleanup-census " in command:
            return SimpleNamespace(
                return_code=0,
                stdout='{"verified":true,"survivor_count":0}\n',
                stderr="",
            )
        raise AssertionError(f"unexpected command: {command}")

    async def upload_file(self, source_path, target_path):
        raise AssertionError((source_path, target_path))

    async def download_file(self, source_path, target_path):
        raise AssertionError((source_path, target_path))


def test_background_liveness_false_is_evidence_not_gate_and_cleanup_is_bound() -> None:
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    remote = BackgroundHandoffRemote(process_alive=False)
    actor = RemoteTerminalActor(remote, monotonic=lambda: 10.0)
    task = BackgroundTask(
        task_id=task_id,
        request_dir=actor._background_dir(task_id),
        command="serve",
        logical_cwd="/workspace",
        output_path=f"/workspace/.terminals/{task_id}.log",
        start_wall=1_736_942_400.0,
        start_monotonic=10.0,
        runtime_timeout_ms=None,
        spool_cap_bytes=1024,
        term_grace_ms=1,
        kill_confirmation_timeout_ms=100,
        owner_token="a" * 64,
        pgid=4001,
        leader_starttime=6001,
        monitor_pgid=5001,
        monitor_starttime=7001,
    )
    actor._background[task_id] = task
    manifest = [
        {
            "task_id": task_id,
            "pgid": 4001,
            "monitor_pgid": 5001,
            "output_path": task.output_path,
            "state": "running",
        }
    ]
    process_lease = actor.seal_process_lease_v1(manifest)
    assert process_lease.process_count == 1

    rows = asyncio.run(
        actor.observe_process_lease_v1(
            process_lease,
            hard_deadline_monotonic_ns=20_000_000_000,
        )
    )
    assert rows == [
        {
            "task_id": task_id,
            "leader_pid": 4001,
            "leader_starttime": 6001,
            "leader_pgid": 4001,
            "monitor_pid": 5001,
            "monitor_starttime": 7001,
            "monitor_pgid": 5001,
            "owner_token_sha256": hashlib.sha256(b"a" * 64).hexdigest(),
            "process_alive": False,
        }
    ]
    assert (
        asyncio.run(
            actor.close_process_lease_until(
                process_lease,
                20_000_000_000,
            )
        )
        is True
    )
    assert any(" background-liveness " in call for call in remote.exec_calls)
    signal_calls = [call for call in remote.exec_calls if " cleanup-signal " in call]
    assert len(signal_calls) == 2
    assert all(" 4001 6001 5001 7001 " in call for call in signal_calls)
    assert (
        asyncio.run(
            actor.close_process_lease_until(
                process_lease,
                20_000_000_000,
            )
        )
        is True
    )
    assert len([call for call in remote.exec_calls if " cleanup-signal " in call]) == 2


def _v10_absolute_terminal_request(
    original: ToolRequest,
    *,
    actor_done_monotonic_ns: int,
    process_settlement_reserve_ms: int = 10_000,
) -> ToolRequest:
    tool_settled = actor_done_monotonic_ns + process_settlement_reserve_ms * 1_000_000
    runtime_final = tool_settled + 30_000_000_000
    cleanup_start = runtime_final + 15_000_000_000
    hard_deadline = cleanup_start + 20_000_000_000
    return ToolRequest(
        **{
            **original.__dict__,
            "schema_version": "external-tool-stdio-v3",
            "actor_done_monotonic_ns": actor_done_monotonic_ns,
            "tool_settled_monotonic_ns": tool_settled,
            "last_send_monotonic_ns": runtime_final,
            "runtime_final_monotonic_ns": runtime_final,
            "cleanup_start_monotonic_ns": cleanup_start,
            "hard_deadline_monotonic_ns": hard_deadline,
            "cleanup_reserve_ms": 20_000,
            "terminalization_reserve_ms": 15_000,
            "provider_send_reserve_ms": 30_000,
            "process_settlement_reserve_ms": process_settlement_reserve_ms,
            "deadline_receipt_sha256": "e" * 64,
        }
    )


class _V10AdmissionRemote:
    def __init__(
        self,
        clock: list[float],
        *,
        mapping_now: float | None = None,
        setup_now: float | None = None,
    ) -> None:
        self.clock = clock
        self.mapping_now = mapping_now
        self.setup_now = setup_now
        self.exec_calls: list[tuple[str, float | None]] = []
        self.uploads: list[str] = []

    async def exec(self, command, cwd=None, timeout_sec=None, user=None):
        del cwd, user
        self.exec_calls.append((command, timeout_sec))
        if "actual=$(realpath -e -- /workspace)" in command:
            if self.mapping_now is not None:
                self.clock[0] = self.mapping_now
            return SimpleNamespace(return_code=0, stdout="", stderr="")
        if command.startswith("mkdir -p "):
            if self.setup_now is not None:
                self.clock[0] = self.setup_now
            return SimpleNamespace(return_code=0, stdout="", stderr="")
        if "/actor.sh run " in command:
            return SimpleNamespace(return_code=0, stdout="", stderr="")
        if "rmdir --" in command:
            return SimpleNamespace(return_code=0, stdout="", stderr="")
        if command.startswith("if test -f "):
            return SimpleNamespace(return_code=1, stdout="", stderr="")
        raise AssertionError(f"unexpected admission command: {command}")

    async def upload_file(self, source_path, target_path):
        del source_path
        self.uploads.append(target_path)

    async def download_file(self, source_path, target_path):
        payload = {
            "meta.json": json.dumps(
                {
                    "return_code": 0,
                    "timed_out": False,
                    "stdout_truncated": False,
                    "stderr_truncated": False,
                    "cleanup_attempted": True,
                    "term_sent": False,
                    "kill_sent": False,
                    "cleanup_verified": True,
                    "census_verified": True,
                    "survivor_count": 0,
                },
                separators=(",", ":"),
            ).encode(),
            "stdout.bin": b"admitted\n",
            "stderr.bin": b"",
        }[Path(source_path).name]
        Path(target_path).write_bytes(payload)


class _V10PostUploadExpiryRemote(_V10AdmissionRemote):
    def __init__(self, clock: list[float]) -> None:
        super().__init__(clock)
        self.request_dir: str | None = None
        self.residue: set[str] = set()

    async def exec(self, command, cwd=None, timeout_sec=None, user=None):
        if "rmdir --" in command:
            self.exec_calls.append((command, timeout_sec))
            assert self.request_dir is not None
            assert f"{self.request_dir}/pgid" in command
            assert f"{self.request_dir}/owner_token" in command
            assert f"{self.request_dir}/meta.json" in command
            self.residue.discard(f"{self.request_dir}/command.sh")
            self.residue.discard(self.request_dir)
            return SimpleNamespace(return_code=0, stdout="", stderr="")
        result = await super().exec(
            command,
            cwd=cwd,
            timeout_sec=timeout_sec,
            user=user,
        )
        if command.startswith("mkdir -p "):
            self.request_dir = shlex.split(command)[2]
            self.residue.add(self.request_dir)
        return result

    async def upload_file(self, source_path, target_path):
        await super().upload_file(source_path, target_path)
        self.residue.add(target_path)
        self.clock[0] = 103.1


class _V10SetupExpiryRemote(_V10PostUploadExpiryRemote):
    async def exec(self, command, cwd=None, timeout_sec=None, user=None):
        result = await super().exec(
            command,
            cwd=cwd,
            timeout_sec=timeout_sec,
            user=user,
        )
        if command.startswith("mkdir -p "):
            self.clock[0] = 103.1
        return result


class _V10DispatchGapClock:
    def __init__(self) -> None:
        self.value = 100.0

    def __call__(self) -> float:
        return self.value


class _V10DispatchGapRemote(_V10AdmissionRemote):
    def __init__(self, clock: _V10DispatchGapClock) -> None:
        super().__init__([clock.value])
        self.dispatch_clock = clock
        self.wait_for_active = False
        self.run_invoked_inside_timed_task: bool | None = None

    def exec(self, command, cwd=None, timeout_sec=None, user=None):
        if "/actor.sh run " in command:
            self.run_invoked_inside_timed_task = self.wait_for_active
            self.dispatch_clock.value = 100.8
        return super().exec(
            command,
            cwd=cwd,
            timeout_sec=timeout_sec,
            user=user,
        )

    async def upload_file(self, source_path, target_path):
        await super().upload_file(source_path, target_path)
        self.dispatch_clock.value = 100.4


def _v10_run_timeout_ms(environment: _V10AdmissionRemote) -> int:
    command = next(
        command for command, _ in environment.exec_calls if "/actor.sh run " in command
    )
    parts = shlex.split(command)
    return int(parts[parts.index("run") + 3])


def test_v10_foreground_declared_timeout_is_clamped_and_dispatched() -> None:
    clock = [100.0]
    environment = _V10AdmissionRemote(clock)
    actor = RemoteTerminalActor(environment, monotonic=lambda: clock[0])
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }
    original = request(
        Path("/workspace"),
        "run_terminal_command",
        {"command": "sleep 120", "description": "must fit before dispatch"},
    )
    tool_request = _v10_absolute_terminal_request(
        ToolRequest(**{**original.__dict__, "timeout_ms": 120_000}),
        actor_done_monotonic_ns=105_000_000_000,
    )

    result = asyncio.run(actor.execute(tool_request))

    assert result.return_code == 0
    assert result.stdout == b"admitted\n"
    assert _v10_run_timeout_ms(environment) == 5_000
    assert len(environment.uploads) == 1
    assert actor._active == {}


def test_v10_foreground_clamps_exact_timeout_after_setup_budget_erosion() -> None:
    clock = [100.0]
    environment = _V10AdmissionRemote(clock, setup_now=101.125)
    actor = RemoteTerminalActor(environment, monotonic=lambda: clock[0])
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }
    original = request(
        Path("/workspace"),
        "run_terminal_command",
        {"command": "sleep 2", "description": "recheck signed action window"},
    )
    tool_request = _v10_absolute_terminal_request(
        ToolRequest(**{**original.__dict__, "timeout_ms": 2_000}),
        actor_done_monotonic_ns=103_000_000_000,
    )

    result = asyncio.run(actor._execute_foreground_v3(tool_request, "sleep 2"))

    assert result.return_code == 0
    assert _v10_run_timeout_ms(environment) == 1_875
    assert len(environment.uploads) == 1
    assert actor._active == {}


def test_v10_foreground_first_entry_erosion_over_250ms_still_dispatches() -> None:
    clock = [100.0]
    environment = _V10AdmissionRemote(clock, mapping_now=100.5)
    actor = RemoteTerminalActor(environment, monotonic=lambda: clock[0])
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }
    original = request(
        Path("/workspace"),
        "run_terminal_command",
        {"command": "sleep 3", "description": "eroded before actor entry"},
    )
    tool_request = _v10_absolute_terminal_request(
        ToolRequest(**{**original.__dict__, "timeout_ms": 3_000}),
        actor_done_monotonic_ns=103_000_000_000,
    )

    result = asyncio.run(actor.execute(tool_request))

    assert result.return_code == 0
    assert _v10_run_timeout_ms(environment) == 2_500
    assert len(environment.uploads) == 1
    assert actor._active == {}


def test_v10_foreground_sub_millisecond_window_never_dispatches_run() -> None:
    clock = [100.0]
    environment = _V10AdmissionRemote(clock)
    actor = RemoteTerminalActor(environment, monotonic=lambda: clock[0])
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }
    original = request(
        Path("/workspace"),
        "run_terminal_command",
        {"command": "true", "description": "sub-millisecond action window"},
    )
    tool_request = _v10_absolute_terminal_request(
        ToolRequest(**{**original.__dict__, "timeout_ms": 1_000}),
        actor_done_monotonic_ns=100_000_999_999,
    )

    with pytest.raises(ToolFatalError) as caught:
        asyncio.run(actor._execute_foreground_v3(tool_request, "true"))

    failure = caught.value.failure
    assert failure.code == "terminal_actor_action_admission_rejected"
    assert failure.execution_may_have_started is False
    assert failure.cleanup_verified is None
    assert failure.census_verified is None
    assert failure.actor_receipt is not None
    assert failure.actor_receipt.phase.value == "remote_exec"
    assert failure.actor_receipt.primary_subtype.value == "actor_deadline_exceeded"
    assert len(environment.uploads) == 1
    assert not any("/actor.sh run " in command for command, _ in environment.exec_calls)
    assert actor._active == {}


@pytest.mark.parametrize("now", [100.0, 100.001], ids=["zero", "negative"])
def test_v10_foreground_expired_entry_rejects_without_remote_effect(now: float) -> None:
    clock = [now]
    environment = _V10AdmissionRemote(clock)
    actor = RemoteTerminalActor(environment, monotonic=lambda: clock[0])
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }
    original = request(
        Path("/workspace"),
        "run_terminal_command",
        {"command": "true", "description": "expired before request setup"},
    )
    tool_request = _v10_absolute_terminal_request(
        ToolRequest(**{**original.__dict__, "timeout_ms": 3_000}),
        actor_done_monotonic_ns=100_000_000_000,
    )

    with pytest.raises(ToolFatalError) as caught:
        asyncio.run(actor._execute_foreground_v3(tool_request, "true"))

    failure = caught.value.failure
    assert failure.code == "terminal_actor_action_admission_rejected"
    assert failure.execution_may_have_started is False
    assert failure.cleanup_verified is None
    assert failure.census_verified is None
    assert failure.actor_receipt is not None
    assert failure.actor_receipt.phase.value == "remote_setup"
    assert environment.exec_calls == []
    assert environment.uploads == []
    assert actor._active == {}


def test_v10_foreground_setup_expiry_cleans_only_created_residue_in_settlement() -> (
    None
):
    clock = [100.0]
    environment = _V10SetupExpiryRemote(clock)
    actor = RemoteTerminalActor(environment, monotonic=lambda: clock[0])
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }
    original = request(
        Path("/workspace"),
        "run_terminal_command",
        {"command": "true", "description": "expire during request setup"},
    )
    tool_request = _v10_absolute_terminal_request(
        ToolRequest(**{**original.__dict__, "timeout_ms": 3_000}),
        actor_done_monotonic_ns=103_000_000_000,
    )

    with pytest.raises(ToolFatalError) as caught:
        asyncio.run(actor._execute_foreground_v3(tool_request, "true"))

    failure = caught.value.failure
    assert failure.code == "terminal_actor_action_admission_rejected"
    assert failure.execution_may_have_started is False
    assert failure.cleanup_verified is None
    assert failure.census_verified is None
    assert failure.actor_receipt is not None
    assert failure.actor_receipt.phase.value == "command_upload"
    assert environment.uploads == []
    residue_cleanup = next(
        (command, timeout)
        for command, timeout in environment.exec_calls
        if "rmdir --" in command
    )
    stages = tool_request.settlement_stages
    assert stages is not None
    assert residue_cleanup[1] == pytest.approx(
        (stages.probe_monotonic_ns - actor._monotonic_ns()) / 1_000_000_000
    )
    assert environment.residue == set()
    assert actor._active == {}


def test_v10_foreground_post_upload_expiry_preserves_no_start_admission() -> None:
    clock = [100.0]
    environment = _V10PostUploadExpiryRemote(clock)
    actor = RemoteTerminalActor(environment, monotonic=lambda: clock[0])
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }
    original = request(
        Path("/workspace"),
        "run_terminal_command",
        {"command": "true", "description": "expire after command upload"},
    )
    tool_request = _v10_absolute_terminal_request(
        ToolRequest(**{**original.__dict__, "timeout_ms": 3_000}),
        actor_done_monotonic_ns=103_000_000_000,
    )

    with pytest.raises(ToolFatalError) as caught:
        asyncio.run(actor._execute_foreground_v3(tool_request, "true"))

    failure = caught.value.failure
    assert failure.code == "terminal_actor_action_admission_rejected"
    assert failure.execution_may_have_started is False
    assert failure.cleanup_verified is None
    assert failure.census_verified is None
    assert failure.actor_receipt is not None
    assert failure.actor_receipt.cleanup_verified is None
    assert failure.actor_receipt.census_verified is None
    assert not any("/actor.sh run " in command for command, _ in environment.exec_calls)
    residue_cleanup = next(
        (command, timeout)
        for command, timeout in environment.exec_calls
        if "rmdir --" in command
    )
    stages = tool_request.settlement_stages
    assert stages is not None
    assert residue_cleanup[1] == pytest.approx(
        (stages.probe_monotonic_ns - actor._monotonic_ns()) / 1_000_000_000
    )
    assert environment.residue == set()
    assert actor._active == {}


def test_v10_foreground_dispatch_uses_one_signed_budget_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _V10DispatchGapClock()
    environment = _V10DispatchGapRemote(clock)
    actor = RemoteTerminalActor(environment, monotonic=clock)
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }
    original = request(
        Path("/workspace"),
        "run_terminal_command",
        {"command": "sleep 3", "description": "dispatch clock gap"},
    )
    tool_request = _v10_absolute_terminal_request(
        ToolRequest(**{**original.__dict__, "timeout_ms": 3_000}),
        actor_done_monotonic_ns=103_000_000_000,
    )

    original_wait_for = asyncio.wait_for

    async def observed_wait_for(awaitable, *, timeout):
        environment.wait_for_active = True
        try:
            return await original_wait_for(awaitable, timeout=timeout)
        finally:
            environment.wait_for_active = False

    monkeypatch.setattr(terminal_actor.asyncio, "wait_for", observed_wait_for)
    result = asyncio.run(actor._execute_foreground_v3(tool_request, "sleep 3"))

    assert result.return_code == 0
    action_timeout_ms = _v10_run_timeout_ms(environment)
    rpc_timeout_sec = next(
        timeout
        for command, timeout in environment.exec_calls
        if "/actor.sh run " in command
    )
    assert rpc_timeout_sec is not None
    assert action_timeout_ms == 2_600
    assert rpc_timeout_sec == pytest.approx(2.6)
    assert action_timeout_ms <= int(rpc_timeout_sec * 1_000)
    assert (
        rpc_timeout_sec
        <= (tool_request.actor_done_monotonic_ns - 100_400_000_000) / 1_000_000_000
    )
    assert environment.run_invoked_inside_timed_task is True
    assert actor._active == {}


def test_v10_background_start_requires_full_action_control_window() -> None:
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    actor = ScriptedBackgroundActor(Path("/workspace"), [task_id])
    original = request(
        Path("/workspace"),
        "run_terminal_command",
        {
            "command": "sleep 60",
            "description": "late background start",
            "background": True,
        },
    )
    tool_request = _v10_absolute_terminal_request(
        original,
        actor_done_monotonic_ns=29_000_000_000,
    )

    result = asyncio.run(actor.execute(tool_request))

    assert result.return_code == 2
    assert result.process_disposition is ProcessDisposition.NO_PROCESS
    assert result.background_start_observation == BackgroundStartObservation(
        proof_version=BACKGROUND_START_PROOF_VERSION,
        kind=BackgroundStartKind.NOT_STARTED,
        task_id_published=False,
        child_exit_code=None,
    )
    assert b"containment window" in result.stdout
    assert actor.launch_timeouts == []
    assert actor._background == {}


class _V10CrossingForegroundRemote:
    def __init__(self, clock: list[float]) -> None:
        self.clock = clock
        self.exec_calls: list[tuple[str, float | None]] = []
        self.uploads: list[str] = []

    async def exec(self, command, cwd=None, timeout_sec=None, user=None):
        del cwd, user
        self.exec_calls.append((command, timeout_sec))
        if command.startswith("mkdir -p "):
            return SimpleNamespace(return_code=0, stdout="", stderr="")
        if "/actor.sh run " in command:
            self.clock[0] = 103.1
            raise TimeoutError("foreground crossed actor_done")
        if " cleanup-signal " in command:
            return SimpleNamespace(return_code=0, stdout="signal-ok\n", stderr="")
        if " cleanup-census " in command:
            return SimpleNamespace(
                return_code=0,
                stdout='{"verified":true,"survivor_count":0}\n',
                stderr="",
            )
        raise AssertionError(f"unexpected command: {command}")

    async def upload_file(self, source_path, target_path):
        del source_path
        self.uploads.append(target_path)

    async def download_file(self, source_path, target_path):
        raise OSError((source_path, target_path))


def test_v10_foreground_crossing_actor_done_uses_signed_settlement_containment() -> (
    None
):
    clock = [100.0]
    environment = _V10CrossingForegroundRemote(clock)
    actor = RemoteTerminalActor(environment, monotonic=lambda: clock[0])
    actor._ready = True
    actor._workspace_mapping = {
        "canonical_cwd": "/app/repo",
        "default_cwd": "/app/repo",
        "logical_cwd": "/workspace",
        "mode": "created_symlink",
    }
    original = request(
        Path("/workspace"),
        "run_terminal_command",
        {"command": "sleep 2", "description": "cross actor cutoff"},
    )
    tool_request = _v10_absolute_terminal_request(
        ToolRequest(
            **{
                **original.__dict__,
                "timeout_ms": 2_000,
                "term_grace_ms": 1,
                "kill_confirmation_timeout_ms": 1,
            }
        ),
        actor_done_monotonic_ns=103_000_000_000,
    )

    with pytest.raises(ToolFatalError) as caught:
        asyncio.run(actor._execute_foreground_v3(tool_request, "sleep 2"))

    failure = caught.value.failure
    assert failure.execution_may_have_started is True
    assert failure.cleanup_verified is True
    assert failure.census_verified is True
    assert failure.actor_receipt is not None
    assert failure.actor_receipt.execution_may_have_started is True
    calls = [command for command, _ in environment.exec_calls]
    assert (
        sum(" cleanup-signal " in command and " TERM" in command for command in calls)
        == 1
    )
    assert (
        sum(" cleanup-signal " in command and " KILL" in command for command in calls)
        == 1
    )
    assert sum(" cleanup-census " in command for command in calls) == 1
    cleanup_timeouts = [
        timeout for command, timeout in environment.exec_calls if " cleanup-" in command
    ]
    assert cleanup_timeouts
    assert all(timeout is not None and timeout > 0 for timeout in cleanup_timeouts)
    assert actor._active == {}


class _V10HangingContainmentRemote:
    async def exec(self, command, cwd=None, timeout_sec=None, user=None):
        del command, cwd, timeout_sec, user
        await asyncio.Event().wait()


def test_v10_containment_rpcs_cannot_borrow_past_signed_stage() -> None:
    actor = RemoteTerminalActor(_V10HangingContainmentRemote())

    async def exercise() -> tuple[bool, bool]:
        term = await actor._signal_cleanup_process(
            "foreground",
            "/opt/nano/requests/test",
            "TERM",
            actor._monotonic_ns() + 10_000_000,
        )
        census = await actor._census_cleanup_process(
            "foreground",
            "/opt/nano/requests/test",
            actor._monotonic_ns() + 10_000_000,
        )
        return term, census

    assert asyncio.run(asyncio.wait_for(exercise(), timeout=0.2)) == (False, False)


class _V10DispatchedStartLossRemote:
    def __init__(
        self,
        *,
        status: str = "running",
        status_loss: bool = False,
        containment_verified: bool = True,
    ) -> None:
        self.status = status
        self.status_loss = status_loss
        self.containment_verified = containment_verified
        self.exec_calls: list[str] = []
        self.uploads: list[str] = []
        self.owner_token: str | None = None

    async def exec(self, command, cwd=None, timeout_sec=None, user=None):
        del cwd, timeout_sec, user
        self.exec_calls.append(command)
        if command.startswith("/bin/bash -c ") and "owner_token=" in command:
            return SimpleNamespace(return_code=0, stdout="", stderr="")
        if "/actor.sh start " in command:
            self.owner_token = shlex.split(command)[-1]
            raise TimeoutError("post-dispatch/pre-ack loss")
        if " background-inspect " in command:
            assert self.owner_token is not None
            return SimpleNamespace(
                return_code=0,
                stdout=json.dumps(
                    {
                        "pgid": 4101,
                        "leader_starttime": 6101,
                        "monitor_pgid": 5101,
                        "monitor_starttime": 7101,
                        "owner_token": self.owner_token,
                    },
                    separators=(",", ":"),
                )
                + "\n",
                stderr="",
            )
        if "/actor.sh status " in command:
            if self.status_loss:
                raise TimeoutError("status loss")
            terminal = self.status != "running"
            return SimpleNamespace(
                return_code=0,
                stdout=json.dumps(
                    {
                        "state": self.status,
                        "exit_code": (
                            137 if self.status == "failed" else 0 if terminal else None
                        ),
                        "timed_out": False,
                        "total_bytes": 0,
                        "truncated": False,
                        "leader_exited": terminal,
                        "started_epoch": 1_736_942_400.0,
                        "ended_epoch": 1_736_942_401.0 if terminal else None,
                    },
                    separators=(",", ":"),
                ),
                stderr="",
            )
        if " confirm-background " in command:
            return SimpleNamespace(
                return_code=0 if self.containment_verified else 73,
                stdout=json.dumps({"verified": self.containment_verified}),
                stderr="",
            )
        if " kill-background " in command:
            return SimpleNamespace(
                return_code=0 if self.containment_verified else 73,
                stdout=json.dumps(
                    {
                        "term_sent": True,
                        "kill_sent": True,
                        "verified": self.containment_verified,
                    }
                ),
                stderr="",
            )
        raise AssertionError(f"unexpected command: {command}")

    async def upload_file(self, source_path, target_path):
        del source_path
        self.uploads.append(target_path)

    async def download_file(self, source_path, target_path):
        raise AssertionError((source_path, target_path))


@pytest.mark.parametrize(
    ("status", "status_loss"),
    [("running", False), ("running", True), ("completed", False), ("failed", False)],
    ids=["running", "status-loss", "quick-exit", "oom-137"],
)
def test_v10_dispatched_background_loss_reconciles_durable_exact_identity(
    tmp_path: Path,
    status: str,
    status_loss: bool,
) -> None:
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    remote = _V10DispatchedStartLossRemote(status=status, status_loss=status_loss)
    actor = ProductionBackgroundStartActor(tmp_path, remote, task_id)

    with pytest.raises(ToolFatalError) as caught:
        asyncio.run(
            actor.execute(
                request(
                    tmp_path,
                    "run_terminal_command",
                    {
                        "command": "serve",
                        "description": "durable start reconciliation",
                        "background": True,
                    },
                )
            )
        )

    assert caught.value.failure == ToolFailure(
        code="terminal_actor_transport_unknown",
        execution_may_have_started=True,
        cleanup_verified=True,
        census_verified=True,
    )
    inspect = next(call for call in remote.exec_calls if " background-inspect " in call)
    containment = next(
        call
        for call in remote.exec_calls
        if " kill-background " in call or " confirm-background " in call
    )
    assert remote.owner_token is not None and remote.owner_token in inspect
    assert " 4101 6101 5101 7101 " in containment
    assert remote.owner_token in containment
    assert task_id not in actor._background


def test_v10_dispatched_background_census_failure_remains_fatal_and_owned(
    tmp_path: Path,
) -> None:
    task_id = "018f22d6-9f04-7cc0-8000-000000000001"
    remote = _V10DispatchedStartLossRemote(containment_verified=False)
    actor = ProductionBackgroundStartActor(tmp_path, remote, task_id)

    with pytest.raises(ToolFatalError) as caught:
        asyncio.run(
            actor.execute(
                request(
                    tmp_path,
                    "run_terminal_command",
                    {
                        "command": "serve",
                        "description": "unknown containment proof",
                        "background": True,
                    },
                )
            )
        )

    assert caught.value.failure.code == "terminal_actor_cleanup_unverified"
    assert caught.value.failure.execution_may_have_started is True
    assert caught.value.failure.cleanup_verified is False
    assert caught.value.failure.census_verified is False
    assert task_id in actor._background
