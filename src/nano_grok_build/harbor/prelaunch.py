"""Provider-free runtime and host admission for a frozen TB2.1 launch."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tomllib
import uuid
from collections.abc import Mapping, Sequence
from importlib import metadata
from pathlib import Path
from typing import Literal

ADMISSION_SCHEMA = "nano-tb21-prelaunch-admission-v1"
CONTRACT_ADMISSION_SCHEMA = "runtime-profile-v1"
MINIMUM_FREE_BYTES = 30 * 1024**3
STORAGE_HEADROOM_BYTES = 10 * 1024**3
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HEX_GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_DOCKER_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_DOCKER_CONTAINER_ID = re.compile(r"^[0-9a-f]{12,64}$")
_SCREEN_SESSION = re.compile(r"^[0-9]+\.[^\s]+$")
_PROBE_LABEL_KEY = "ai.asksurf.surfharness.prelaunch-storage-probe"
_LAUNCHD_LABEL_PREFIX = "ai.asksurf.surfharness.tb21"
_CONTRACT_KEYS = {"schema_version"}
_RUNTIME_IMPORTS = (
    "harbor",
    "harbor.job",
    "harbor.models.job.config",
    "harbor.models.trial.config",
)


class PrelaunchError(RuntimeError):
    """A stable, credential-safe prelaunch failure."""


def _sha256_file(path: Path, error_code: str) -> str:
    try:
        metadata_row = path.lstat()
        if not stat.S_ISREG(metadata_row.st_mode):
            raise OSError
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as error:
        raise PrelaunchError(error_code) from error


def _strict_object(raw: bytes, error_code: str) -> dict[str, object]:
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
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("invalid constant")
            ),
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
    ) as error:
        raise PrelaunchError(error_code) from error
    if not isinstance(value, dict):
        raise PrelaunchError(error_code)
    return value


def admit_contract(
    *,
    binary_path: Path,
    contract_dir: Path,
) -> dict[str, object]:
    """Ask the binary to validate one safety profile without a provider."""

    if (
        not binary_path.is_absolute()
        or binary_path.is_symlink()
        or not binary_path.is_file()
        or not binary_path.stat().st_mode & 0o111
    ):
        raise PrelaunchError("runtime_binary_unavailable")
    if (
        not contract_dir.is_absolute()
        or contract_dir.is_symlink()
        or not contract_dir.is_dir()
    ):
        raise PrelaunchError("contract_directory_invalid")
    try:
        result = subprocess.run(
            [
                str(binary_path),
                "validate-contract",
                "--contract-dir",
                str(contract_dir),
            ],
            check=False,
            capture_output=True,
            env={},
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PrelaunchError("contract_admission_unavailable") from error
    if result.returncode != 0:
        raise PrelaunchError("contract_admission_rejected")
    if result.stderr or len(result.stdout) > 4096:
        raise PrelaunchError("contract_admission_invalid")
    observed = _strict_object(result.stdout, "contract_admission_invalid")
    if (
        set(observed) != _CONTRACT_KEYS
        or observed.get("schema_version") != CONTRACT_ADMISSION_SCHEMA
    ):
        raise PrelaunchError("contract_admission_invalid")
    return observed


def _harbor_project_version(checkout: Path) -> str:
    path = checkout / "pyproject.toml"
    try:
        metadata_row = path.lstat()
        if not stat.S_ISREG(metadata_row.st_mode):
            raise OSError
        project = tomllib.loads(path.read_text(encoding="utf-8")).get("project")
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise PrelaunchError("harbor_project_invalid") from error
    if not isinstance(project, dict):
        raise PrelaunchError("harbor_project_invalid")
    name = project.get("name")
    version = project.get("version")
    if name != "harbor" or not isinstance(version, str) or not version:
        raise PrelaunchError("harbor_project_invalid")
    return version


def _lock_binds_harbor(lock_path: Path, version: str) -> bool:
    try:
        value = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return False
    packages = value.get("package")
    if not isinstance(packages, list):
        return False
    matches = [
        row for row in packages if isinstance(row, dict) and row.get("name") == "harbor"
    ]
    return bool(
        len(matches) == 1
        and matches[0].get("version") == version
        and matches[0].get("source") == {"editable": "."}
    )


def _admit_harbor_checkout(checkout: Path, expected_commit: str) -> str:
    if _HEX_GIT_COMMIT.fullmatch(expected_commit) is None:
        raise PrelaunchError("harbor_checkout_commit_invalid")
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=checkout,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=checkout,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise PrelaunchError("harbor_checkout_invalid") from error
    if head != expected_commit:
        raise PrelaunchError("harbor_checkout_commit_mismatch")
    if status:
        raise PrelaunchError("harbor_checkout_dirty")
    return head


def admit_runtime(
    *,
    harbor_checkout: Path,
    runtime_python: Path,
    runtime_python_sha256: str,
    harbor_lock_sha256: str,
    expected_harbor_commit: str,
) -> dict[str, object]:
    """Bind this process to one locked Harbor interpreter and source checkout."""

    if (
        not harbor_checkout.is_absolute()
        or harbor_checkout.is_symlink()
        or not harbor_checkout.is_dir()
        or harbor_checkout.absolute() != harbor_checkout.resolve()
    ):
        raise PrelaunchError("harbor_checkout_invalid")
    harbor_commit = _admit_harbor_checkout(harbor_checkout, expected_harbor_commit)
    if (
        not runtime_python.is_absolute()
        or not runtime_python.is_file()
        or _HEX_SHA256.fullmatch(runtime_python_sha256) is None
        or _HEX_SHA256.fullmatch(harbor_lock_sha256) is None
    ):
        raise PrelaunchError("runtime_python_invalid")
    try:
        selected_invocation = runtime_python.absolute()
        running_invocation = Path(sys.executable).absolute()
        selected_python = runtime_python.resolve(strict=True)
        running_python = Path(sys.executable).resolve(strict=True)
    except OSError as error:
        raise PrelaunchError("runtime_python_invalid") from error
    if selected_invocation != running_invocation or selected_python != running_python:
        raise PrelaunchError("runtime_python_mismatch")
    observed_python_sha256 = _sha256_file(selected_python, "runtime_python_unavailable")
    if observed_python_sha256 != runtime_python_sha256:
        raise PrelaunchError("runtime_python_hash_mismatch")
    lock_path = harbor_checkout / "uv.lock"
    observed_lock_sha256 = _sha256_file(lock_path, "harbor_lock_unavailable")
    if observed_lock_sha256 != harbor_lock_sha256:
        raise PrelaunchError("harbor_lock_hash_mismatch")
    project_version = _harbor_project_version(harbor_checkout)
    if not _lock_binds_harbor(lock_path, project_version):
        raise PrelaunchError("harbor_lock_binding_invalid")
    try:
        distribution_version = metadata.version("harbor")
    except metadata.PackageNotFoundError as error:
        raise PrelaunchError("harbor_distribution_unavailable") from error
    except Exception as error:
        raise PrelaunchError("harbor_distribution_invalid") from error
    if distribution_version != project_version:
        raise PrelaunchError("harbor_distribution_version_mismatch")
    imported: dict[str, object] = {}
    try:
        for name in _RUNTIME_IMPORTS:
            imported[name] = importlib.import_module(name)
    except Exception as error:
        raise PrelaunchError("harbor_runtime_import_failed") from error
    try:
        source_root = (harbor_checkout / "src" / "harbor").resolve(strict=True)
    except OSError as error:
        raise PrelaunchError("harbor_runtime_source_mismatch") from error
    module_paths: dict[str, str] = {}
    for name, module in imported.items():
        module_file = getattr(module, "__file__", None)
        if not isinstance(module_file, str):
            raise PrelaunchError("harbor_runtime_source_mismatch")
        try:
            module_path = Path(module_file).resolve(strict=True)
        except OSError as error:
            raise PrelaunchError("harbor_runtime_source_mismatch") from error
        if not module_path.is_relative_to(source_root):
            raise PrelaunchError("harbor_runtime_source_mismatch")
        module_paths[name] = str(module_path)
    return {
        "runtime_python": str(runtime_python),
        "runtime_python_resolved": str(selected_python),
        "runtime_python_sha256": observed_python_sha256,
        "harbor_checkout": str(harbor_checkout),
        "harbor_commit": harbor_commit,
        "harbor_lock_sha256": observed_lock_sha256,
        "harbor_version": distribution_version,
        "harbor_module": module_paths["harbor"],
        "runtime_modules": module_paths,
        "runtime_imports": list(_RUNTIME_IMPORTS),
    }


def _listed_screen_sessions(screen: str, error_code: str) -> set[str]:
    try:
        result = subprocess.run(
            [screen, "-ls"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PrelaunchError(error_code) from error
    if result.returncode not in (0, 1):
        raise PrelaunchError(error_code)
    return {
        token
        for line in result.stdout.splitlines()
        if line.strip()
        for token in line.strip().split()[:1]
        if _SCREEN_SESSION.fullmatch(token) is not None
    }


def _admit_carrier(carrier: Literal["foreground", "screen"]) -> str:
    if carrier == "foreground":
        try:
            if (
                not sys.stdin.isatty()
                or os.tcgetpgrp(sys.stdin.fileno()) != os.getpgrp()
            ):
                raise PrelaunchError("carrier_unavailable")
        except (OSError, ValueError) as error:
            raise PrelaunchError("carrier_unavailable") from error
        return carrier
    if carrier != "screen":
        raise PrelaunchError("carrier_invalid")
    sty = os.environ.get("STY")
    term = os.environ.get("TERM")
    screen = shutil.which("screen")
    if not sty or not term or not term.startswith("screen") or screen is None:
        raise PrelaunchError("carrier_unavailable")
    if sty not in _listed_screen_sessions(screen, "carrier_unavailable"):
        raise PrelaunchError("carrier_unavailable")
    return carrier


def _host_command(
    executable: str,
    arguments: Sequence[str],
    *,
    error_code: str,
) -> str:
    try:
        result = subprocess.run(
            [executable, *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PrelaunchError(error_code) from error
    if result.returncode != 0 or len(result.stdout) > 16 * 1024 * 1024:
        raise PrelaunchError(error_code)
    return result.stdout


def _controller_class(command: str) -> str | None:
    try:
        arguments = shlex.split(command)
    except ValueError as error:
        if any(
            fragment in command
            for fragment in (
                "run_tb21.py",
                "nano-cli",
                "exec_tb21_with_key.py",
                "launch-controller",
                "nano_grok_build.harbor.tb21",
            )
        ):
            raise PrelaunchError("process_census_failed") from error
        return None
    basenames = tuple(Path(argument).name for argument in arguments)
    if "run_tb21.py" in basenames:
        return "runner"
    if "nano-cli" in basenames:
        return "runtime"
    if "exec_tb21_with_key.py" in basenames:
        return "credential_controller"
    if any(
        name.startswith("launch-controller")
        and (name.endswith(".sh") or name.endswith(".zsh"))
        for name in basenames
    ):
        return "launch_controller"
    if any(
        argument == "-m"
        and index + 1 < len(arguments)
        and arguments[index + 1] == "nano_grok_build.harbor.tb21"
        for index, argument in enumerate(arguments)
    ):
        return "runner"
    return None


def _admit_process_state(
    carrier: Literal["foreground", "screen"],
) -> dict[str, object]:
    ps = shutil.which("ps")
    if ps is None:
        raise PrelaunchError("process_census_failed")
    stdout = _host_command(
        ps,
        ("-axo", "pid=,ppid=,command="),
        error_code="process_census_failed",
    )
    rows: dict[int, tuple[int, str]] = {}
    for line in stdout.splitlines():
        match = re.fullmatch(r"\s*([0-9]+)\s+([0-9]+)\s+(.+)", line)
        if match is None:
            raise PrelaunchError("process_census_failed")
        pid = int(match.group(1))
        ppid = int(match.group(2))
        if pid <= 0 or ppid < 0 or pid in rows:
            raise PrelaunchError("process_census_failed")
        rows[pid] = (ppid, match.group(3))
    current_pid = os.getpid()
    if current_pid not in rows:
        raise PrelaunchError("process_census_failed")
    allowed_pids: set[int] = set()
    cursor = current_pid
    while cursor:
        if cursor in allowed_pids or cursor not in rows:
            raise PrelaunchError("process_census_failed")
        allowed_pids.add(cursor)
        cursor = rows[cursor][0]
    controller_rows = [
        (pid, controller_class)
        for pid, (_ppid, command) in rows.items()
        if (controller_class := _controller_class(command)) is not None
    ]
    if any(pid not in allowed_pids for pid, _controller_class_name in controller_rows):
        raise PrelaunchError("controller_process_collision")

    launchd_collision_count = 0
    if sys.platform == "darwin":
        launchctl = shutil.which("launchctl")
        if launchctl is None:
            raise PrelaunchError("process_census_failed")
        launchd = _host_command(
            launchctl,
            ("list",),
            error_code="process_census_failed",
        )
        labels = [
            fields[-1]
            for line in launchd.splitlines()
            if (fields := line.split()) and fields[-1] != "Label"
        ]
        launchd_collision_count = sum(
            label.startswith(_LAUNCHD_LABEL_PREFIX) for label in labels
        )
        if launchd_collision_count:
            raise PrelaunchError("launchd_collision")

    screen_collision_count = 0
    screen = shutil.which("screen")
    if screen is not None:
        sessions = _listed_screen_sessions(screen, "process_census_failed")
        current_session = os.environ.get("STY") if carrier == "screen" else None
        if carrier == "screen" and current_session not in sessions:
            raise PrelaunchError("carrier_unavailable")
        collisions = {
            session
            for session in sessions
            if "tb21" in session.split(".", 1)[1].lower() and session != current_session
        }
        screen_collision_count = len(collisions)
        if collisions:
            raise PrelaunchError("screen_session_collision")
    return {
        "process_count": len(rows),
        "allowed_controller_process_count": len(controller_rows),
        "launchd_collision_count": launchd_collision_count,
        "screen_collision_count": screen_collision_count,
    }


def _docker_command(
    docker: str,
    arguments: Sequence[str],
    *,
    error_code: str,
) -> str:
    try:
        result = subprocess.run(
            [docker, *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PrelaunchError(error_code) from error
    if result.returncode != 0:
        raise PrelaunchError(error_code)
    return result.stdout


def _container_ids(raw: str, error_code: str) -> tuple[str, ...]:
    values = tuple(line.strip() for line in raw.splitlines() if line.strip())
    if any(_DOCKER_CONTAINER_ID.fullmatch(value) is None for value in values):
        raise PrelaunchError(error_code)
    return values


def _task_container_ids(docker: str) -> tuple[str, ...]:
    return _container_ids(
        _docker_command(
            docker,
            (
                "ps",
                "-aq",
                "--filter",
                "label=com.docker.compose.service=task",
            ),
            error_code="docker_process_census_failed",
        ),
        "docker_process_census_failed",
    )


def _inspect_image_bindings(
    docker: str,
    image_refs: Sequence[str],
    *,
    error_code: str,
) -> list[dict[str, str]]:
    image_ids = _docker_command(
        docker,
        (
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            *image_refs,
        ),
        error_code=error_code,
    ).splitlines()
    if len(image_ids) != len(image_refs):
        raise PrelaunchError(error_code)
    bindings: list[dict[str, str]] = []
    for image_ref, raw_image_id in zip(image_refs, image_ids, strict=True):
        image_id = raw_image_id.strip()
        if _DOCKER_IMAGE_ID.fullmatch(image_id) is None:
            raise PrelaunchError(error_code)
        bindings.append({"image_ref": image_ref, "image_id": image_id})
    return bindings


def _closed_image_bindings(bindings: object) -> list[tuple[str, str]]:
    if (
        not isinstance(bindings, Sequence)
        or isinstance(bindings, str | bytes)
        or not bindings
    ):
        raise PrelaunchError("docker_image_binding_invalid")
    closed: list[tuple[str, str]] = []
    for row in bindings:
        if not isinstance(row, Mapping) or set(row) != {"image_ref", "image_id"}:
            raise PrelaunchError("docker_image_binding_invalid")
        image_ref = row.get("image_ref")
        image_id = row.get("image_id")
        if (
            not isinstance(image_ref, str)
            or not image_ref
            or "\x00" in image_ref
            or not isinstance(image_id, str)
            or _DOCKER_IMAGE_ID.fullmatch(image_id) is None
        ):
            raise PrelaunchError("docker_image_binding_invalid")
        closed.append((image_ref, image_id))
    if len({image_ref for image_ref, _image_id in closed}) != len(closed):
        raise PrelaunchError("docker_image_binding_invalid")
    return closed


def verify_docker_image_bindings(bindings: object) -> None:
    """Fail if an admitted image reference now resolves to a different image ID."""

    closed = _closed_image_bindings(bindings)
    docker = shutil.which("docker")
    if docker is None:
        raise PrelaunchError("docker_unavailable")
    observed = _inspect_image_bindings(
        docker,
        tuple(image_ref for image_ref, _image_id in closed),
        error_code="docker_image_binding_unavailable",
    )
    observed_pairs = [(row["image_ref"], row["image_id"]) for row in observed]
    if observed_pairs != closed:
        raise PrelaunchError("docker_image_binding_drift")


def _probe_label_container_ids(docker: str, label: str) -> tuple[str, ...]:
    return _container_ids(
        _docker_command(
            docker,
            ("ps", "-aq", "--filter", f"label={label}"),
            error_code="docker_storage_probe_cleanup_unverified",
        ),
        "docker_storage_probe_cleanup_unverified",
    )


def _parse_df_available_bytes(raw: str) -> int:
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(lines) < 2:
        raise PrelaunchError("docker_storage_probe_invalid")
    fields = lines[-1].split()
    if len(fields) < 6 or not fields[3].isdigit():
        raise PrelaunchError("docker_storage_probe_invalid")
    available_kib = int(fields[3])
    if available_kib <= 0:
        raise PrelaunchError("docker_storage_probe_invalid")
    return available_kib * 1024


def _probe_docker_storage(docker: str, image_ref: str) -> int:
    token = uuid.uuid4().hex
    label = f"{_PROBE_LABEL_KEY}={token}"
    name = f"nano-prelaunch-storage-{token}"
    if _probe_label_container_ids(docker, label):
        raise PrelaunchError("docker_storage_probe_collision")
    try:
        return _parse_df_available_bytes(
            _docker_command(
                docker,
                (
                    "run",
                    "--rm",
                    "--pull",
                    "never",
                    "--network",
                    "none",
                    "--read-only",
                    "--name",
                    name,
                    "--label",
                    label,
                    "--entrypoint",
                    "/bin/df",
                    image_ref,
                    "-Pk",
                    "/",
                ),
                error_code="docker_storage_probe_failed",
            )
        )
    finally:
        owned = _probe_label_container_ids(docker, label)
        if owned:
            _docker_command(
                docker,
                ("rm", "-f", *owned),
                error_code="docker_storage_probe_cleanup_unverified",
            )
            if _probe_label_container_ids(docker, label):
                raise PrelaunchError("docker_storage_probe_cleanup_unverified")


def _storage_required_bytes(
    selected_storage_mb: Sequence[int | None],
    concurrency: int,
) -> int:
    if (
        isinstance(concurrency, bool)
        or not isinstance(concurrency, int)
        or concurrency <= 0
        or any(
            value is not None
            and (isinstance(value, bool) or not isinstance(value, int) or value <= 0)
            for value in selected_storage_mb
        )
    ):
        raise PrelaunchError("storage_requirement_invalid")
    largest = sorted((value or 0 for value in selected_storage_mb), reverse=True)[
        :concurrency
    ]
    planned = sum(largest) * 1024**2 + STORAGE_HEADROOM_BYTES
    return max(MINIMUM_FREE_BYTES, planned)


def admit_operations(
    *,
    output_dir: Path,
    pid_file: Path,
    carrier: Literal["foreground", "screen"],
    docker_images: Sequence[str],
    selected_storage_mb: Sequence[int | None],
    concurrency: int,
) -> dict[str, object]:
    """Provider-free carrier, collision, storage, daemon, and image admission."""

    if (
        not output_dir.is_absolute()
        or output_dir.exists()
        or output_dir.is_symlink()
        or not output_dir.parent.is_dir()
        or output_dir.parent.is_symlink()
    ):
        raise PrelaunchError("fresh_output_required")
    if (
        not pid_file.is_absolute()
        or pid_file.exists()
        or pid_file.is_symlink()
        or not pid_file.parent.is_dir()
        or pid_file.parent.is_symlink()
        or pid_file == output_dir
    ):
        raise PrelaunchError("stale_controller_pid_file")
    admitted_carrier = _admit_carrier(carrier)
    process_state = _admit_process_state(carrier)
    required_bytes = _storage_required_bytes(selected_storage_mb, concurrency)
    try:
        host_available_bytes = shutil.disk_usage(output_dir.parent).free
    except OSError as error:
        raise PrelaunchError("storage_capacity_unavailable") from error
    if host_available_bytes < required_bytes:
        raise PrelaunchError("storage_capacity_insufficient")
    if not docker_images or any(
        not isinstance(image, str) or not image or "\x00" in image
        for image in docker_images
    ):
        raise PrelaunchError("docker_image_inventory_invalid")
    unique_images = tuple(dict.fromkeys(docker_images))
    docker = shutil.which("docker")
    if docker is None:
        raise PrelaunchError("docker_unavailable")
    server_version = _docker_command(
        docker,
        ("info", "--format", "{{.ServerVersion}}"),
        error_code="docker_unavailable",
    ).strip()
    if not server_version:
        raise PrelaunchError("docker_unavailable")
    if _task_container_ids(docker):
        raise PrelaunchError("task_container_residue")
    image_bindings = _inspect_image_bindings(
        docker,
        unique_images,
        error_code="docker_image_inventory_incomplete",
    )
    probe_error: PrelaunchError | None = None
    docker_available_bytes = 0
    try:
        docker_available_bytes = _probe_docker_storage(docker, unique_images[0])
    except PrelaunchError as error:
        probe_error = error
    post_probe_task_ids = _task_container_ids(docker)
    if post_probe_task_ids:
        raise PrelaunchError("task_container_residue") from probe_error
    if probe_error is not None:
        raise probe_error
    if docker_available_bytes < required_bytes:
        raise PrelaunchError("docker_storage_capacity_insufficient")
    return {
        "carrier": admitted_carrier,
        "pid_file": str(pid_file),
        "output_dir": str(output_dir),
        "docker_server_version": server_version,
        "selected_image_count": len(docker_images),
        "cached_image_count": len(image_bindings),
        "unique_image_count": len(unique_images),
        "image_bindings": image_bindings,
        "task_container_count": 0,
        "docker_calls": 7,
        "storage_required_bytes": required_bytes,
        "storage_available_bytes": min(
            host_available_bytes,
            docker_available_bytes,
        ),
        "host_storage_available_bytes": host_available_bytes,
        "docker_storage_available_bytes": docker_available_bytes,
        "process_state": process_state,
    }


def admit_prelaunch(
    *,
    harbor_checkout: Path,
    runtime_python: Path,
    runtime_python_sha256: str,
    harbor_lock_sha256: str,
    expected_harbor_commit: str,
    binary_path: Path,
    contract_dir: Path,
    output_dir: Path,
    pid_file: Path,
    carrier: Literal["foreground", "screen"],
    docker_images: Sequence[str],
    selected_storage_mb: Sequence[int | None],
    concurrency: int,
) -> dict[str, object]:
    """Run every hard admission check and return one secret-free receipt."""

    runtime = admit_runtime(
        harbor_checkout=harbor_checkout,
        runtime_python=runtime_python,
        runtime_python_sha256=runtime_python_sha256,
        harbor_lock_sha256=harbor_lock_sha256,
        expected_harbor_commit=expected_harbor_commit,
    )
    contract = admit_contract(
        binary_path=binary_path,
        contract_dir=contract_dir,
    )
    operations = admit_operations(
        output_dir=output_dir,
        pid_file=pid_file,
        carrier=carrier,
        docker_images=docker_images,
        selected_storage_mb=selected_storage_mb,
        concurrency=concurrency,
    )
    return {
        "schema_version": ADMISSION_SCHEMA,
        "status": "passed",
        "runtime": runtime,
        "contract": contract,
        "operations": operations,
        "network_calls": 0,
        "provider_calls": 0,
        "docker_calls": operations["docker_calls"],
        "output_created": False,
        "cost_gate": "advisory",
        "timing_gate": "advisory",
    }
