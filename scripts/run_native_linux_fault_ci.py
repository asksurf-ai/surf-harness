#!/usr/bin/env python3
"""Run the provider-free native-Linux Docker fault matrix and bind evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

SOURCE_ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = SOURCE_ROOT / "src"
if str(SOURCE_PATH) not in sys.path:
    sys.path.insert(0, str(SOURCE_PATH))
SCHEMA_VERSION = "surf-harness-native-linux-fault-evidence-v1"
REGRESSION_IMAGE = (
    "alexgshaw/fix-git@"
    "sha256:389b9c8247610c2c5be080b1ac00429007c2c69bf57f7f26c79f0f75ba2d5c74"
)
TEST_FUNCTIONS = (
    "test_real_docker_snapshot_owned_supervisor_term_kill_and_census",
    "test_real_docker_nonstandard_workdir_maps_all_tools_and_fails_on_tamper",
    "test_real_docker_c1_mapping_preflight_load_is_bounded_to_23_calls",
    "test_foreground_residual_real_docker_is_cleaned_without_touching_unrelated",
    "test_real_docker_detached_fifo_writer_is_censused_and_drain_is_bounded",
    "test_real_docker_background_launch_ack_survives_initial_status_loss",
    "test_real_docker_background_setsid_survivor_settles_without_orphan",
)
TEST_SELECTORS = tuple(
    f"tests/test_terminal_actor.py::{function}" for function in TEST_FUNCTIONS
)
EXPECTED_NODE_IDS = (
    TEST_SELECTORS[0],
    TEST_SELECTORS[1],
    TEST_SELECTORS[2],
    f"{TEST_SELECTORS[3]}[same_pgid]",
    f"{TEST_SELECTORS[3]}[exact_owner_new_pgid]",
    TEST_SELECTORS[4],
    TEST_SELECTORS[5],
    f"{TEST_SELECTORS[6]}[False]",
    f"{TEST_SELECTORS[6]}[True]",
)
PROVIDER_CREDENTIAL_NAMES = ("XAI_API_KEY",)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


class EvidenceError(RuntimeError):
    """Raised when the native fault evidence cannot be trusted."""


def _run(*command: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=SOURCE_ROOT,
        check=check,
        capture_output=True,
        text=True,
    )


def _output(*command: str) -> str:
    return _run(*command).stdout.strip()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode()


def _testcase_node_id(testcase: ET.Element) -> str:
    classname = testcase.attrib.get("classname", "")
    name = testcase.attrib.get("name", "")
    if classname != "tests.test_terminal_actor" or not name:
        raise EvidenceError("junit_test_identity_invalid")
    return f"tests/test_terminal_actor.py::{name}"


def validate_junit(path: Path) -> dict[str, object]:
    """Require the exact matrix, with every case passed and none skipped."""

    try:
        root = ET.fromstring(path.read_bytes())
    except (OSError, ET.ParseError) as error:
        raise EvidenceError("junit_unavailable_or_invalid") from error
    testcases = list(root.iter("testcase"))
    observed = tuple(_testcase_node_id(case) for case in testcases)
    failures = sum(case.find("failure") is not None for case in testcases)
    errors = sum(case.find("error") is not None for case in testcases)
    skipped = sum(case.find("skipped") is not None for case in testcases)
    if set(observed) != set(EXPECTED_NODE_IDS) or len(observed) != len(
        EXPECTED_NODE_IDS
    ):
        raise EvidenceError("junit_exact_matrix_mismatch")
    if failures or errors or skipped:
        raise EvidenceError("junit_matrix_not_all_passed")
    return {
        "selected_functions": list(TEST_FUNCTIONS),
        "expected_case_count": len(EXPECTED_NODE_IDS),
        "observed_case_count": len(observed),
        "passed": len(observed),
        "failed": failures,
        "errors": errors,
        "skipped": skipped,
        "node_ids": sorted(observed),
        "junit_sha256": _sha256(path),
    }


def _tool_versions() -> dict[str, Any]:
    return json.loads((SOURCE_ROOT / "tools/tool-versions.json").read_bytes())


def _git_identity() -> dict[str, object]:
    head = _output("git", "rev-parse", "HEAD")
    tree = _output("git", "rev-parse", "HEAD^{tree}")
    github_sha = os.environ.get("GITHUB_SHA", "")
    if not all(GIT_SHA.fullmatch(value) for value in (head, tree, github_sha)):
        raise EvidenceError("git_identity_invalid")
    if head != github_sha:
        raise EvidenceError("github_sha_head_mismatch")
    if _output("git", "status", "--porcelain", "--untracked-files=no"):
        raise EvidenceError("tracked_worktree_not_clean")
    return {"commit": head, "tree": tree, "github_sha": github_sha}


def _runner_identity() -> dict[str, object]:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise EvidenceError("github_actions_runner_required")
    machine = platform.machine()
    if (
        os.environ.get("RUNNER_OS") != "Linux"
        or os.environ.get("RUNNER_ARCH") != "X64"
        or platform.system() != "Linux"
        or machine != "x86_64"
    ):
        raise EvidenceError("native_linux_runner_required")
    return {
        "github_actions": True,
        "runner_os": "Linux",
        "platform_system": platform.system(),
        "platform_release": platform.release(),
        "runner_arch": "X64",
        "machine": machine,
        "docker_on_darwin": False,
        "execution_isolation_claimed": False,
    }


def _python_and_rust_versions(versions: dict[str, Any]) -> dict[str, object]:
    expected_python = str(versions["python"]["version"])
    expected_rust = str(versions["rust"]["version"])
    python_version = platform.python_version()
    rust_verbose = _output("rustc", "--version", "--verbose")
    rust_version = rust_verbose.splitlines()[0]
    if python_version != expected_python:
        raise EvidenceError("python_version_mismatch")
    if not rust_version.startswith(f"rustc {expected_rust} "):
        raise EvidenceError("rust_version_mismatch")
    return {
        "python": {
            "version": python_version,
            "implementation": platform.python_implementation(),
        },
        "rust": {"version": expected_rust, "rustc_verbose": rust_verbose},
    }


def _docker_identity() -> dict[str, object]:
    if os.environ.get("NANO_DOCKER_REGRESSION_IMAGE") != REGRESSION_IMAGE:
        raise EvidenceError("docker_image_not_digest_pinned")
    try:
        version = json.loads(_output("docker", "version", "--format", "{{json .}}"))
        image = json.loads(
            _output(
                "docker", "image", "inspect", REGRESSION_IMAGE, "--format", "{{json .}}"
            )
        )
    except json.JSONDecodeError as error:
        raise EvidenceError("docker_identity_invalid") from error
    client = version.get("Client", {})
    server = version.get("Server", {})
    identity_fields = (
        client.get("Version"),
        server.get("Version"),
        server.get("Arch"),
        image.get("Id"),
        image.get("Architecture"),
    )
    if not all(isinstance(value, str) and value for value in identity_fields):
        raise EvidenceError("docker_identity_incomplete")
    if (
        server.get("Os") != "linux"
        or server.get("Arch") != "amd64"
        or image.get("Os") != "linux"
        or image.get("Architecture") != "amd64"
    ):
        raise EvidenceError("linux_docker_daemon_required")
    image_id = str(image["Id"])
    if not image_id.startswith("sha256:") or not SHA256.fullmatch(image_id[7:]):
        raise EvidenceError("docker_image_id_invalid")
    repo_digests = image.get("RepoDigests", [])
    if REGRESSION_IMAGE not in repo_digests:
        raise EvidenceError("docker_image_digest_mismatch")
    return {
        "client_version": client.get("Version"),
        "server_version": server.get("Version"),
        "server_os": server.get("Os"),
        "server_arch": server.get("Arch"),
        "image": REGRESSION_IMAGE,
        "image_id": image.get("Id"),
        "image_os": image.get("Os"),
        "image_arch": image.get("Architecture"),
    }


def _image_container_census() -> list[str]:
    output = _output(
        "docker", "ps", "--quiet", "--filter", f"ancestor={REGRESSION_IMAGE}"
    )
    return sorted(line for line in output.splitlines() if line)


def _harbor_identity() -> dict[str, object]:
    from nano_grok_build.harbor.compat_v020 import HARBOR_VERSION

    if HARBOR_VERSION != "0.20.0":
        raise EvidenceError("harbor_compatibility_version_mismatch")
    return {
        "compatibility_target_version": HARBOR_VERSION,
        "runtime_executed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    output_dir = args.output_dir.resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise EvidenceError("evidence_output_not_empty")
    output_dir.mkdir(parents=True, exist_ok=True)
    junit_path = output_dir / "pytest-junit.xml"
    log_path = output_dir / "pytest.log"
    evidence_path = output_dir / "evidence.json"

    evidence: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "status": "failed",
        "execution_isolation_claimed": False,
        "provider": {
            "provider_calls": 0,
            "benchmark_runs": 0,
            "credentials_forwarded": False,
        },
    }
    error_code: str | None = None
    phase = "provider_preflight"
    pytest_result: subprocess.CompletedProcess[str] | None = None
    try:
        if any(name in os.environ for name in PROVIDER_CREDENTIAL_NAMES):
            raise EvidenceError("provider_credential_present")
        if os.environ.get("NANO_RUN_DOCKER_TESTS") != "1":
            raise EvidenceError("docker_fault_tests_not_enabled")
        phase = "tool_versions"
        versions = _tool_versions()
        phase = "git_identity"
        evidence["git"] = _git_identity()
        phase = "runner_identity"
        evidence["runner"] = _runner_identity()
        phase = "toolchain_identity"
        evidence["toolchains"] = _python_and_rust_versions(versions)
        phase = "harbor_identity"
        evidence["harbor"] = _harbor_identity()
        phase = "docker_identity"
        evidence["docker"] = _docker_identity()
        phase = "container_census_before"
        before = _image_container_census()
        if before:
            raise EvidenceError("fault_image_container_present_before_matrix")

        phase = "pytest_matrix"
        pytest_result = _run(
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "--tb=short",
            f"--junitxml={junit_path}",
            *TEST_SELECTORS,
            check=False,
        )
        log_path.write_text(
            f"stdout:\n{pytest_result.stdout}\nstderr:\n{pytest_result.stderr}",
            encoding="utf-8",
        )
        phase = "junit_validation"
        evidence["tests"] = validate_junit(junit_path)
        evidence["tests"]["pytest_return_code"] = pytest_result.returncode  # type: ignore[index]
        if pytest_result.returncode != 0:
            raise EvidenceError("pytest_matrix_failed")
        phase = "container_census_after"
        after = _image_container_census()
        evidence["docker"]["containers_before"] = before  # type: ignore[index]
        evidence["docker"]["containers_after"] = after  # type: ignore[index]
        if after:
            raise EvidenceError("fault_image_container_survived_matrix")
        evidence["status"] = "passed"
    except Exception as error:
        if isinstance(error, EvidenceError):
            error_code = str(error)
        elif isinstance(error, ImportError):
            error_code = "bootstrap_import_failed"
        elif isinstance(error, subprocess.SubprocessError):
            error_code = "subprocess_failed"
        elif isinstance(error, OSError):
            error_code = "os_operation_failed"
        else:
            error_code = "native_fault_runner_unexpected_failure"
        evidence["failure"] = {
            "code": error_code,
            "error_type": type(error).__name__,
            "phase": phase,
        }
    finally:
        evidence_path.write_bytes(_canonical_json(evidence))
        if pytest_result is not None:
            sys.stdout.write(pytest_result.stdout)
            sys.stderr.write(pytest_result.stderr)
        print(json.dumps(evidence, sort_keys=True))
    return 1 if error_code is not None else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceError, OSError) as error:
        print(f"native Linux fault evidence failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
