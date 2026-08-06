from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from nano_grok_build.harbor import prelaunch


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _runtime_checkout(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    checkout = tmp_path / "harbor"
    package = checkout / "src" / "harbor"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "job").mkdir()
    (package / "job" / "__init__.py").write_text("", encoding="utf-8")
    (package / "models" / "job").mkdir(parents=True)
    (package / "models" / "job" / "config.py").write_text("", encoding="utf-8")
    (package / "models" / "trial").mkdir(parents=True)
    (package / "models" / "trial" / "config.py").write_text("", encoding="utf-8")
    (checkout / "pyproject.toml").write_text(
        '[project]\nname = "harbor"\nversion = "0.20.0"\n',
        encoding="utf-8",
    )
    lock = checkout / "uv.lock"
    lock.write_text(
        'version = 1\n[[package]]\nname = "harbor"\n'
        'version = "0.20.0"\nsource = { editable = "." }\n',
        encoding="utf-8",
    )
    python = tmp_path / "runtime-python"
    python.write_bytes(b"pinned-python")
    python.chmod(0o700)
    subprocess.run(["git", "init", "-q"], cwd=checkout, check=True)
    subprocess.run(["git", "add", "."], cwd=checkout, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=prelaunch-test",
            "-c",
            "user.email=prelaunch@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        cwd=checkout,
        check=True,
    )
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=checkout,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return checkout, lock, python, head


def _contract(tmp_path: Path) -> Path:
    contract_dir = tmp_path / "runtime" / "profile"
    contract_dir.mkdir(parents=True)
    return contract_dir


def test_runtime_profile_admission_is_provider_free_and_has_no_governance_flags(
    tmp_path: Path,
) -> None:
    contract_dir = _contract(tmp_path)
    binary = tmp_path / "nano-cli"
    argv_path = tmp_path / "argv.json"
    env_path = tmp_path / "env.json"
    binary.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$@\" > {argv_path!s}\n"
        f"env | sort > {env_path!s}\n"
        "printf '%s\\n' "
        '\'{"schema_version":"runtime-profile-v1"}\'\n',
        encoding="utf-8",
    )
    binary.chmod(0o700)

    observed = prelaunch.admit_contract(
        binary_path=binary.resolve(),
        contract_dir=contract_dir.resolve(),
    )

    assert observed == {"schema_version": "runtime-profile-v1"}
    assert argv_path.read_text().splitlines() == [
        "validate-contract",
        "--contract-dir",
        str(contract_dir.resolve()),
    ]
    assert "XAI_API_KEY" not in env_path.read_text()


@pytest.mark.parametrize(
    ("payload", "error"),
    [
        (
            {
                "schema_version": "runtime-profile-v1",
                "extra": True,
            },
            "contract_admission_invalid",
        ),
    ],
)
def test_contract_admission_rejects_wrong_or_open_output(
    tmp_path: Path,
    payload: dict[str, object],
    error: str,
) -> None:
    contract_dir = _contract(tmp_path)
    binary = tmp_path / "nano-cli"
    binary.write_text(
        "#!/bin/sh\nprintf '%s\\n' "
        + repr(json.dumps(payload, separators=(",", ":")))
        + "\n",
        encoding="utf-8",
    )
    binary.chmod(0o700)

    with pytest.raises(prelaunch.PrelaunchError, match=f"^{error}$"):
        prelaunch.admit_contract(
            binary_path=binary.resolve(),
            contract_dir=contract_dir.resolve(),
        )


def test_runtime_admission_binds_interpreter_lock_metadata_and_imports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout, lock, python, head = _runtime_checkout(tmp_path)
    imports: list[str] = []

    monkeypatch.setattr(prelaunch.sys, "executable", str(python))
    monkeypatch.setattr(prelaunch.metadata, "version", lambda name: "0.20.0")

    def import_module(name: str) -> object:
        imports.append(name)
        module_path = checkout / "src" / Path(*name.split("."))
        return SimpleNamespace(
            __file__=str(
                module_path / "__init__.py"
                if name in {"harbor", "harbor.job"}
                else module_path.with_suffix(".py")
            )
        )

    monkeypatch.setattr(prelaunch.importlib, "import_module", import_module)

    receipt = prelaunch.admit_runtime(
        harbor_checkout=checkout.resolve(),
        runtime_python=python.resolve(),
        runtime_python_sha256=_sha256(python),
        harbor_lock_sha256=_sha256(lock),
        expected_harbor_commit=head,
    )

    assert receipt["harbor_version"] == "0.20.0"
    assert receipt["runtime_python_sha256"] == _sha256(python)
    assert receipt["harbor_lock_sha256"] == _sha256(lock)
    assert receipt["runtime_modules"] == {
        "harbor": str(checkout / "src/harbor/__init__.py"),
        "harbor.job": str(checkout / "src/harbor/job/__init__.py"),
        "harbor.models.job.config": str(checkout / "src/harbor/models/job/config.py"),
        "harbor.models.trial.config": str(
            checkout / "src/harbor/models/trial/config.py"
        ),
    }
    assert imports == [
        "harbor",
        "harbor.job",
        "harbor.models.job.config",
        "harbor.models.trial.config",
    ]


@pytest.mark.parametrize(
    ("field", "error"),
    [
        ("runtime_python_sha256", "runtime_python_hash_mismatch"),
        ("harbor_lock_sha256", "harbor_lock_hash_mismatch"),
    ],
)
def test_runtime_admission_fails_closed_on_hash_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    error: str,
) -> None:
    checkout, lock, python, head = _runtime_checkout(tmp_path)
    monkeypatch.setattr(prelaunch.sys, "executable", str(python))
    kwargs = {
        "harbor_checkout": checkout.resolve(),
        "runtime_python": python.resolve(),
        "runtime_python_sha256": _sha256(python),
        "harbor_lock_sha256": _sha256(lock),
        "expected_harbor_commit": head,
    }
    kwargs[field] = "0" * 64

    with pytest.raises(prelaunch.PrelaunchError, match=f"^{error}$"):
        prelaunch.admit_runtime(**kwargs)


def test_runtime_admission_requires_distribution_metadata_before_imports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout, lock, python, head = _runtime_checkout(tmp_path)
    monkeypatch.setattr(prelaunch.sys, "executable", str(python))

    def missing(_name: str) -> str:
        raise prelaunch.metadata.PackageNotFoundError("harbor")

    monkeypatch.setattr(prelaunch.metadata, "version", missing)
    monkeypatch.setattr(
        prelaunch.importlib,
        "import_module",
        lambda _name: (_ for _ in ()).throw(AssertionError("import reached")),
    )

    with pytest.raises(
        prelaunch.PrelaunchError, match="^harbor_distribution_unavailable$"
    ):
        prelaunch.admit_runtime(
            harbor_checkout=checkout.resolve(),
            runtime_python=python.resolve(),
            runtime_python_sha256=_sha256(python),
            harbor_lock_sha256=_sha256(lock),
            expected_harbor_commit=head,
        )


def test_runtime_admission_rejects_harbor_module_from_another_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout, lock, python, head = _runtime_checkout(tmp_path)
    monkeypatch.setattr(prelaunch.sys, "executable", str(python))
    monkeypatch.setattr(prelaunch.metadata, "version", lambda _name: "0.20.0")
    monkeypatch.setattr(
        prelaunch.importlib,
        "import_module",
        lambda _name: SimpleNamespace(__file__=str(tmp_path / "other/harbor.py")),
    )

    with pytest.raises(
        prelaunch.PrelaunchError, match="^harbor_runtime_source_mismatch$"
    ):
        prelaunch.admit_runtime(
            harbor_checkout=checkout.resolve(),
            runtime_python=python.resolve(),
            runtime_python_sha256=_sha256(python),
            harbor_lock_sha256=_sha256(lock),
            expected_harbor_commit=head,
        )


def test_runtime_admission_rejects_one_submodule_from_another_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout, lock, python, head = _runtime_checkout(tmp_path)
    monkeypatch.setattr(prelaunch.sys, "executable", str(python))
    monkeypatch.setattr(prelaunch.metadata, "version", lambda _name: "0.20.0")

    def import_module(name: str) -> object:
        if name == "harbor.models.trial.config":
            return SimpleNamespace(__file__=str(tmp_path / "other/config.py"))
        return SimpleNamespace(__file__=str(checkout / "src" / f"{name}.py"))

    monkeypatch.setattr(prelaunch.importlib, "import_module", import_module)

    with pytest.raises(
        prelaunch.PrelaunchError, match="^harbor_runtime_source_mismatch$"
    ):
        prelaunch.admit_runtime(
            harbor_checkout=checkout.resolve(),
            runtime_python=python.resolve(),
            runtime_python_sha256=_sha256(python),
            harbor_lock_sha256=_sha256(lock),
            expected_harbor_commit=head,
        )


def test_runtime_admission_rejects_dirty_or_wrong_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout, lock, python, head = _runtime_checkout(tmp_path)
    monkeypatch.setattr(prelaunch.sys, "executable", str(python))
    (checkout / "untracked").write_text("drift", encoding="utf-8")

    with pytest.raises(prelaunch.PrelaunchError, match="^harbor_checkout_dirty$"):
        prelaunch.admit_runtime(
            harbor_checkout=checkout.resolve(),
            runtime_python=python.resolve(),
            runtime_python_sha256=_sha256(python),
            harbor_lock_sha256=_sha256(lock),
            expected_harbor_commit=head,
        )

    (checkout / "untracked").unlink()
    with pytest.raises(
        prelaunch.PrelaunchError, match="^harbor_checkout_commit_mismatch$"
    ):
        prelaunch.admit_runtime(
            harbor_checkout=checkout.resolve(),
            runtime_python=python.resolve(),
            runtime_python_sha256=_sha256(python),
            harbor_lock_sha256=_sha256(lock),
            expected_harbor_commit="0" * 40,
        )


def test_operational_admission_checks_carrier_process_storage_and_all_images(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "results" / "fresh"
    output.parent.mkdir()
    pid_file = tmp_path / "controller.pid"
    images = ("image-a:pin", "image-b:pin")
    commands: list[tuple[str, ...]] = []
    monkeypatch.setattr(prelaunch, "_admit_carrier", lambda _carrier: "foreground")
    monkeypatch.setattr(
        prelaunch,
        "_admit_process_state",
        lambda _carrier: {
            "process_count": 3,
            "allowed_controller_process_count": 2,
            "launchd_collision_count": 0,
            "screen_collision_count": 0,
        },
    )
    monkeypatch.setattr(
        prelaunch.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=80 * 1024**3),
    )
    monkeypatch.setattr(prelaunch.shutil, "which", lambda name: f"/usr/bin/{name}")

    def run(
        command: list[str],
        **_kwargs: object,
    ) -> SimpleNamespace:
        commands.append(tuple(command))
        if command[1] == "info":
            return SimpleNamespace(returncode=0, stdout="ok\n", stderr="")
        if command[1] == "ps":
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if command[1:3] == ["image", "inspect"]:
            return SimpleNamespace(
                returncode=0,
                stdout=f"sha256:{'1' * 64}\nsha256:{'2' * 64}\n",
                stderr="",
            )
        if command[1] == "run":
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                    "/dev/vda 100000000 1000 83886080 1% /\n"
                ),
                stderr="",
            )
        raise AssertionError(command)

    monkeypatch.setattr(prelaunch.subprocess, "run", run)

    receipt = prelaunch.admit_operations(
        output_dir=output.resolve(),
        pid_file=pid_file.resolve(),
        carrier="foreground",
        docker_images=images,
        selected_storage_mb=(10240, 10240),
        concurrency=2,
    )

    assert receipt["carrier"] == "foreground"
    assert receipt["cached_image_count"] == 2
    assert receipt["selected_image_count"] == 2
    assert receipt["storage_required_bytes"] == 30 * 1024**3
    assert receipt["host_storage_available_bytes"] == 80 * 1024**3
    assert receipt["docker_storage_available_bytes"] == 80 * 1024**3
    assert receipt["image_bindings"] == [
        {"image_ref": "image-a:pin", "image_id": f"sha256:{'1' * 64}"},
        {"image_ref": "image-b:pin", "image_id": f"sha256:{'2' * 64}"},
    ]
    assert not output.exists()
    assert not pid_file.exists()
    assert any(
        command[1:3] == ("image", "inspect") and command[-2:] == images
        for command in commands
    )
    assert any(
        command[1] == "run"
        and "--pull" in command
        and "never" in command
        and "--network" in command
        and "none" in command
        and "--read-only" in command
        for command in commands
    )


@pytest.mark.parametrize(
    ("state", "error"),
    [
        ("output", "fresh_output_required"),
        ("pid", "stale_controller_pid_file"),
        ("storage", "storage_capacity_insufficient"),
        ("container", "task_container_residue"),
        ("image", "docker_image_inventory_incomplete"),
        ("docker_storage", "docker_storage_capacity_insufficient"),
    ],
)
def test_operational_admission_fails_closed_without_mutating_host(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: str,
    error: str,
) -> None:
    output = tmp_path / "results" / "fresh"
    output.parent.mkdir()
    pid_file = tmp_path / "controller.pid"
    if state == "output":
        output.mkdir()
    if state == "pid":
        pid_file.write_text("123\n", encoding="utf-8")
    monkeypatch.setattr(prelaunch, "_admit_carrier", lambda _carrier: "foreground")
    monkeypatch.setattr(
        prelaunch,
        "_admit_process_state",
        lambda _carrier: {
            "process_count": 1,
            "allowed_controller_process_count": 1,
            "launchd_collision_count": 0,
            "screen_collision_count": 0,
        },
    )
    monkeypatch.setattr(
        prelaunch.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(
            free=(20 if state == "storage" else 80) * 1024**3
        ),
    )
    monkeypatch.setattr(prelaunch.shutil, "which", lambda name: f"/usr/bin/{name}")

    def run(command: list[str], **_kwargs: object) -> SimpleNamespace:
        if command[1] == "info":
            return SimpleNamespace(returncode=0, stdout="ok\n", stderr="")
        if command[1] == "ps":
            return SimpleNamespace(
                returncode=0,
                stdout="abc123def456\n" if state == "container" else "",
                stderr="",
            )
        if command[1:3] == ["image", "inspect"]:
            return SimpleNamespace(
                returncode=1 if state == "image" else 0,
                stdout="" if state == "image" else f"sha256:{'1' * 64}\n",
                stderr="missing",
            )
        if command[1] == "run":
            available_kib = 20 * 1024**2 if state == "docker_storage" else 80 * 1024**2
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                    f"/dev/vda 100000000 1000 {available_kib} 1% /\n"
                ),
                stderr="",
            )
        raise AssertionError(command)

    monkeypatch.setattr(prelaunch.subprocess, "run", run)

    with pytest.raises(prelaunch.PrelaunchError, match=f"^{error}$"):
        prelaunch.admit_operations(
            output_dir=output.resolve(),
            pid_file=pid_file.resolve(),
            carrier="foreground",
            docker_images=("image-a:pin",),
            selected_storage_mb=(10240,),
            concurrency=2,
        )

    assert not pid_file.exists() or state == "pid"


def test_process_state_allows_current_controller_chain_and_rejects_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = os.getpid()
    rows = (
        f"1 0 /sbin/launchd\n"
        f"40 1 /bin/zsh /tmp/launch-controller-screen-v2.zsh\n"
        f"{current} 40 /runtime/python /repo/tests/harbor/run_tb21.py --all\n"
    )
    monkeypatch.setattr(prelaunch.sys, "platform", "linux")
    monkeypatch.delenv("STY", raising=False)
    monkeypatch.setattr(
        prelaunch.shutil,
        "which",
        lambda name: None if name == "screen" else f"/usr/bin/{name}",
    )
    monkeypatch.setattr(
        prelaunch.subprocess,
        "run",
        lambda command, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=rows if command[0].endswith("/ps") else "",
            stderr="",
        ),
    )

    receipt = prelaunch._admit_process_state("foreground")
    assert receipt["allowed_controller_process_count"] == 2

    collision = rows + "900 1 /runtime/nano-cli run --contract-dir /tmp/c\n"
    monkeypatch.setattr(
        prelaunch.subprocess,
        "run",
        lambda command, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=collision if command[0].endswith("/ps") else "",
            stderr="",
        ),
    )
    with pytest.raises(
        prelaunch.PrelaunchError, match="^controller_process_collision$"
    ):
        prelaunch._admit_process_state("foreground")


def test_process_state_rejects_launchd_and_screen_collisions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = os.getpid()
    ps_rows = f"1 0 /sbin/launchd\n{current} 1 /runtime/python worker.py\n"
    monkeypatch.setattr(prelaunch.sys, "platform", "darwin")
    monkeypatch.setattr(
        prelaunch.shutil,
        "which",
        lambda name: f"/usr/bin/{name}",
    )

    def launchd_run(command: list[str], **_kwargs: object) -> SimpleNamespace:
        stdout = ps_rows
        if command[0].endswith("/launchctl"):
            stdout = "-\t0\tai.asksurf.surfharness.tb21.full\n"
        elif command[0].endswith("/screen"):
            stdout = "No Sockets found.\n"
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr(prelaunch.subprocess, "run", launchd_run)
    with pytest.raises(prelaunch.PrelaunchError, match="^launchd_collision$"):
        prelaunch._admit_process_state("foreground")

    def screen_run(command: list[str], **_kwargs: object) -> SimpleNamespace:
        stdout = ps_rows
        if command[0].endswith("/launchctl"):
            stdout = "PID\tStatus\tLabel\n"
        elif command[0].endswith("/screen"):
            stdout = "\t8765.tb21-stale\t(Detached)\n"
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr(prelaunch.subprocess, "run", screen_run)
    with pytest.raises(prelaunch.PrelaunchError, match="^screen_session_collision$"):
        prelaunch._admit_process_state("foreground")


def test_docker_probe_cleans_exact_owned_container_after_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []
    label_census = 0

    def run(command: list[str], **_kwargs: object) -> SimpleNamespace:
        nonlocal label_census
        calls.append(tuple(command))
        if command[1] == "ps":
            label_census += 1
            return SimpleNamespace(
                returncode=0,
                stdout="abc123def456\n" if label_census == 2 else "",
                stderr="",
            )
        if command[1] == "run":
            return SimpleNamespace(returncode=1, stdout="", stderr="probe failed")
        if command[1:3] == ["rm", "-f"]:
            return SimpleNamespace(returncode=0, stdout="abc123def456\n", stderr="")
        raise AssertionError(command)

    monkeypatch.setattr(prelaunch.subprocess, "run", run)
    with pytest.raises(prelaunch.PrelaunchError, match="^docker_storage_probe_failed$"):
        prelaunch._probe_docker_storage(
            "/usr/bin/docker",
            "image-a:pin",
        )
    assert any(command[1:3] == ("rm", "-f") for command in calls)
    assert label_census == 3


def test_docker_image_bindings_are_closed_and_reverified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bindings = [
        {"image_ref": "image-a:pin", "image_id": f"sha256:{'1' * 64}"},
        {"image_ref": "image-b:pin", "image_id": f"sha256:{'2' * 64}"},
    ]
    monkeypatch.setattr(prelaunch.shutil, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(
        prelaunch.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=f"sha256:{'1' * 64}\nsha256:{'2' * 64}\n",
            stderr="",
        ),
    )
    prelaunch.verify_docker_image_bindings(bindings)

    monkeypatch.setattr(
        prelaunch.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=f"sha256:{'1' * 64}\nsha256:{'3' * 64}\n",
            stderr="",
        ),
    )
    with pytest.raises(prelaunch.PrelaunchError, match="^docker_image_binding_drift$"):
        prelaunch.verify_docker_image_bindings(bindings)


def test_screen_carrier_requires_current_listed_screen_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STY", "12345.tb21")
    monkeypatch.setenv("TERM", "screen")
    monkeypatch.setattr(prelaunch.shutil, "which", lambda _name: "/usr/bin/screen")
    monkeypatch.setattr(
        prelaunch.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout="There is a screen on:\n\t12345.tb21\t(Detached)\n",
            stderr="",
        ),
    )

    assert prelaunch._admit_carrier("screen") == "screen"

    monkeypatch.setattr(
        prelaunch.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout="No Sockets found.\n",
            stderr="",
        ),
    )
    with pytest.raises(prelaunch.PrelaunchError, match="^carrier_unavailable$"):
        prelaunch._admit_carrier("screen")


def test_foreground_carrier_requires_the_tty_foreground_process_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdin = SimpleNamespace(isatty=lambda: True, fileno=lambda: 7)
    monkeypatch.setattr(prelaunch.sys, "stdin", stdin)
    monkeypatch.setattr(prelaunch.os, "tcgetpgrp", lambda _fd: 91)
    monkeypatch.setattr(prelaunch.os, "getpgrp", lambda: 91)
    assert prelaunch._admit_carrier("foreground") == "foreground"

    monkeypatch.setattr(prelaunch.os, "getpgrp", lambda: 92)
    with pytest.raises(prelaunch.PrelaunchError, match="^carrier_unavailable$"):
        prelaunch._admit_carrier("foreground")
