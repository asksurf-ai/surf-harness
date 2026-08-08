from __future__ import annotations

import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from scripts import run_native_linux_fault_ci as runner
from scripts.run_native_linux_fault_ci import (
    EXPECTED_NODE_IDS,
    EvidenceError,
    validate_junit,
)

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_native_linux_fault_ci.py"


def _write_junit(
    path: Path,
    node_ids: tuple[str, ...] = EXPECTED_NODE_IDS,
    *,
    skipped: bool = False,
) -> None:
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite")
    for index, node_id in enumerate(node_ids):
        testcase = ET.SubElement(
            suite,
            "testcase",
            classname="tests.test_terminal_actor",
            name=node_id.split("::", 1)[1],
        )
        if skipped and index == 0:
            ET.SubElement(testcase, "skipped")
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


def test_junit_requires_the_exact_all_passed_native_matrix(tmp_path: Path) -> None:
    junit = tmp_path / "junit.xml"
    _write_junit(junit)

    summary = validate_junit(junit)

    assert summary["expected_case_count"] == 9
    assert summary["observed_case_count"] == 9
    assert summary["passed"] == 9
    assert summary["failed"] == 0
    assert summary["errors"] == 0
    assert summary["skipped"] == 0


@pytest.mark.parametrize("mode", ["missing", "skipped"])
def test_junit_fails_closed_on_missing_or_skipped_case(
    tmp_path: Path,
    mode: str,
) -> None:
    junit = tmp_path / "junit.xml"
    node_ids = EXPECTED_NODE_IDS[:-1] if mode == "missing" else EXPECTED_NODE_IDS
    _write_junit(junit, node_ids, skipped=mode == "skipped")

    with pytest.raises(EvidenceError):
        validate_junit(junit)


def test_runner_self_bootstraps_src_in_isolated_uninstalled_process(
    tmp_path: Path,
) -> None:
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            (
                "import importlib.util,json,runpy,sys;"
                "assert importlib.util.find_spec('nano_grok_build') is None;"
                "scope=runpy.run_path(sys.argv[1]);"
                "print(json.dumps(scope['_harbor_identity'](),sort_keys=True))"
            ),
            str(RUNNER),
        ],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "compatibility_target_version": "0.20.0",
        "runtime_executed": False,
    }


def test_unexpected_import_failure_writes_structured_provider_free_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "evidence"
    monkeypatch.delenv("XAI_API_KEY", raising=False)
    monkeypatch.setenv("NANO_RUN_DOCKER_TESTS", "1")
    monkeypatch.setattr(runner, "_tool_versions", lambda: {})
    monkeypatch.setattr(runner, "_git_identity", lambda: {"commit": "a" * 40})
    monkeypatch.setattr(runner, "_runner_identity", lambda: {"runner_os": "Linux"})
    monkeypatch.setattr(runner, "_python_and_rust_versions", lambda _versions: {})

    def fail_import() -> dict[str, object]:
        raise ModuleNotFoundError("synthetic uninstalled project")

    monkeypatch.setattr(runner, "_harbor_identity", fail_import)
    monkeypatch.setattr(
        sys,
        "argv",
        ["run_native_linux_fault_ci.py", "--output-dir", str(output)],
    )

    assert runner.main() == 1
    evidence = json.loads((output / "evidence.json").read_bytes())
    assert evidence["status"] == "failed"
    assert evidence["failure"] == {
        "code": "bootstrap_import_failed",
        "error_type": "ModuleNotFoundError",
        "phase": "harbor_identity",
    }
    assert evidence["provider"] == {
        "provider_calls": 0,
        "benchmark_runs": 0,
        "credentials_forwarded": False,
    }
    assert "tests" not in evidence
    assert not (output / "pytest-junit.xml").exists()
