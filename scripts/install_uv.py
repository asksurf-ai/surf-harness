#!/usr/bin/env python3
"""Install uv from an immutable, checksum-verified official release asset."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
OFFICIAL_RELEASE_ROOT = "https://github.com/astral-sh/uv/releases/download"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PLATFORMS = {
    ("linux", "x86_64"): "linux-x86_64",
    ("darwin", "arm64"): "macos-aarch64",
    ("darwin", "aarch64"): "macos-aarch64",
    ("darwin", "x86_64"): "macos-x86_64",
    ("darwin", "amd64"): "macos-x86_64",
}


class IntegrityError(RuntimeError):
    """The downloaded bytes do not match the immutable release declaration."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sidecar_hash(sidecar: Path, asset_name: str) -> str:
    lines = [
        line.strip()
        for line in sidecar.read_text(encoding="ascii").splitlines()
        if line.strip()
    ]
    if len(lines) != 1:
        raise IntegrityError(f"{sidecar.name}: expected one checksum line")
    fields = lines[0].split()
    if len(fields) != 2 or fields[1].removeprefix("*") != asset_name:
        raise IntegrityError(f"{sidecar.name}: checksum filename mismatch")
    digest = fields[0].lower()
    if not SHA256.fullmatch(digest):
        raise IntegrityError(f"{sidecar.name}: invalid SHA-256")
    return digest


def verify_download(archive: Path, sidecar: Path, expected_sha256: str) -> None:
    """Match a release archive against both its pin and official sidecar."""
    expected = expected_sha256.lower()
    if not SHA256.fullmatch(expected):
        raise IntegrityError("pinned uv SHA-256 is invalid")
    official = _sidecar_hash(sidecar, archive.name)
    if official != expected:
        raise IntegrityError(
            f"{archive.name}: official sidecar does not match the pinned SHA-256"
        )
    actual = _sha256(archive)
    if actual != expected:
        raise IntegrityError(f"{archive.name}: archive SHA-256 mismatch")


def _download(url: str, destination: Path) -> None:
    if urlparse(url).scheme != "https":
        raise IntegrityError(f"refusing non-HTTPS download: {url}")
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "nano-grok-build-bootstrap"},
    )
    partial = destination.with_name(destination.name + ".partial")
    with urllib.request.urlopen(request, timeout=120) as response:
        if urlparse(response.geturl()).scheme != "https":
            raise IntegrityError("uv download redirected away from HTTPS")
        with partial.open("wb") as output:
            shutil.copyfileobj(response, output)
    partial.replace(destination)


def _platform_key() -> str:
    key = (platform.system().lower(), platform.machine().lower())
    try:
        return PLATFORMS[key]
    except KeyError as error:
        raise IntegrityError(
            f"unsupported uv bootstrap platform: {key[0]}/{key[1]}"
        ) from error


def _load_uv_config(platform_key: str) -> tuple[str, str, str]:
    versions: dict[str, Any] = json.loads(
        (ROOT / "tools/tool-versions.json").read_text(encoding="utf-8")
    )
    uv = versions["uv"]
    version = str(uv["version"])
    release_url = str(uv["release_url"]).rstrip("/")
    expected_release_url = f"{OFFICIAL_RELEASE_ROOT}/{version}"
    if release_url != expected_release_url:
        raise IntegrityError("uv release URL is not the immutable official URL")
    try:
        asset = uv["assets"][platform_key]
    except KeyError as error:
        raise IntegrityError(f"undeclared uv platform: {platform_key}") from error
    name = str(asset["name"])
    if Path(name).name != name or not name.endswith(".tar.gz"):
        raise IntegrityError(f"unsafe uv asset name: {name}")
    return version, f"{release_url}/{name}", str(asset["sha256"]).lower()


def _stage_binaries(archive_path: Path, stage: Path) -> None:
    prefix = archive_path.name.removesuffix(".tar.gz")
    required = {f"{prefix}/uv", f"{prefix}/uvx"}
    with tarfile.open(archive_path, mode="r:gz") as archive:
        files = {member.name: member for member in archive if member.isfile()}
        unexpected = [
            member.name
            for member in archive.getmembers()
            if not (member.isdir() and member.name.rstrip("/") == prefix)
            and member.name not in required
        ]
        if unexpected or set(files) != required:
            raise IntegrityError(f"{archive_path.name}: unexpected archive structure")
        for binary in ("uv", "uvx"):
            source = archive.extractfile(files[f"{prefix}/{binary}"])
            if source is None:
                raise IntegrityError(f"{archive_path.name}: missing {binary}")
            destination = stage / binary
            with destination.open("wb") as output:
                shutil.copyfileobj(source, output)
            destination.chmod(0o755)


def _install_binaries(stage: Path, install_dir: Path) -> Path:
    install_dir.mkdir(parents=True, exist_ok=True)
    for binary in ("uv", "uvx"):
        source = stage / binary
        temporary = install_dir / f".{binary}.{os.getpid()}.tmp"
        shutil.copyfile(source, temporary)
        temporary.chmod(0o755)
        temporary.replace(install_dir / binary)
    return install_dir / "uv"


def install(
    install_dir: Path,
    platform_key: str,
    expected_argument: str | None = None,
) -> Path:
    version, asset_url, pinned_sha256 = _load_uv_config(platform_key)
    if expected_argument is not None and expected_argument.lower() != pinned_sha256:
        raise IntegrityError("command-line uv SHA-256 does not match the manifest")
    asset_name = asset_url.rsplit("/", 1)[1]
    with tempfile.TemporaryDirectory(prefix="nano-uv-bootstrap.") as tmp:
        temporary_root = Path(tmp)
        archive = temporary_root / asset_name
        sidecar = temporary_root / f"{asset_name}.sha256"
        _download(asset_url, archive)
        _download(f"{asset_url}.sha256", sidecar)
        verify_download(archive, sidecar, pinned_sha256)
        stage = temporary_root / "stage"
        stage.mkdir()
        _stage_binaries(archive, stage)
        uv_path = _install_binaries(stage, install_dir.resolve())

    result = subprocess.run(
        [str(uv_path), "--version"],
        check=True,
        capture_output=True,
        text=True,
    )
    fields = result.stdout.split()
    if len(fields) < 2 or fields[:2] != ["uv", version]:
        raise IntegrityError(f"installed uv version mismatch: {result.stdout.strip()}")
    return uv_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--install-dir", type=Path, required=True)
    parser.add_argument("--platform", choices=sorted(set(PLATFORMS.values())))
    parser.add_argument("--expected-sha256")
    args = parser.parse_args()
    try:
        uv_path = install(
            args.install_dir,
            args.platform or _platform_key(),
            args.expected_sha256,
        )
    except (
        IntegrityError,
        OSError,
        subprocess.CalledProcessError,
        tarfile.TarError,
        urllib.error.URLError,
    ) as error:
        print(f"uv bootstrap: {error}", file=sys.stderr)
        return 1
    print(uv_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
