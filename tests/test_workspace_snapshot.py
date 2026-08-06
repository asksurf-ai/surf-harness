from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import os
import shlex
import shutil
import stat
import subprocess
import tarfile
import traceback
from pathlib import Path
from types import SimpleNamespace

import pytest

from nano_grok_build.adapter import workspace_snapshot
from nano_grok_build.adapter.terminal_actor import (
    SnapshotFailureEvidenceV1,
    SnapshotFailureReasonV1,
    SnapshotFailureSubtypeV1,
    SnapshotOperationFailure,
    SnapshotTimeoutOriginV1,
    SnapshotTransportTimeout,
)


class LocalSnapshotActor:
    """C0 fixture boundary; C1 maps this behavior to the remote actor transport."""

    def __init__(self, workspace: Path, artifacts: Path) -> None:
        self.workspace = workspace
        self.artifacts = artifacts
        self.capture_phases: list[str] = []
        self.fail_phase: str | None = None


class RemoteSnapshotActor:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir()
        self.stage_count = 0
        self.capture_count = 0
        self.stages: dict[str, Path] = {}
        self.cleanup_calls: list[str] = []
        self.snapshot_phases: list[str] = []
        self.preflight_timeouts: list[float] = []
        self.capture_timeouts: list[float] = []
        self.capture_deadlines: list[int | None] = []
        self.capture_hard_deadlines: list[int | None] = []
        self.block_capture = False
        self.capture_started = asyncio.Event()

    def snapshot_workspace_root(self) -> str:
        return "/workspace"

    async def exec_snapshot(
        self,
        command: str,
        *,
        timeout_sec: float,
    ) -> SimpleNamespace:
        assert timeout_sec > 0
        if command.startswith("rm -rf -- "):
            self.snapshot_phases.append("cleanup")
            self.cleanup_calls.append(command)
            remote = shlex.split(command)[3]
            stage = self.stages.pop(remote)
            shutil.rmtree(stage)
            return SimpleNamespace(return_code=0, stdout="", stderr="")
        if "mktemp -d " in command and "inventory=" not in command:
            self.snapshot_phases.append("preflight")
            self.preflight_timeouts.append(timeout_sec)
            self.stage_count += 1
            stage_name = f"/tmp/nano-workspace-snapshot-v1.fixture{self.stage_count}"
            stage = self.root / f"stage-{self.stage_count}"
            stage.mkdir()
            self.stages[stage_name] = stage
            return SimpleNamespace(
                return_code=0,
                stdout=f"{stage_name}\n",
                stderr="",
            )
        self.snapshot_phases.append("capture")
        self.capture_timeouts.append(timeout_sec)
        if self.block_capture:
            self.capture_started.set()
            await asyncio.Future()
        self.capture_count += 1
        assert len(self.stages) == 1
        stage_name, stage = next(iter(self.stages.items()))
        before = self.capture_count == 1
        answer = b"before\n" if before else b"after\n"
        rows = [
            (
                "answer.txt",
                "file",
                "0644",
                len(answer),
                __import__("hashlib").sha256(answer).hexdigest(),
                "",
            )
        ]
        if not before:
            secret = b"do-not-export"
            rows.append(
                (
                    "vulnerable-secret.txt",
                    "file",
                    "0600",
                    len(secret),
                    __import__("hashlib").sha256(secret).hexdigest(),
                    "sensitive_path",
                )
            )
        inventory = b"".join(
            (
                "E\t"
                + base64.b64encode(path.encode()).decode()
                + f"\t{kind}\t{mode}\t{size}\t{detail}\t{reason}\n"
            ).encode()
            for path, kind, mode, size, detail, reason in rows
        )
        (stage / "inventory.tsv").write_bytes(inventory)
        with tarfile.open(stage / "safe.tar", "w:") as archive:
            information = tarfile.TarInfo("answer.txt")
            information.size = len(answer)
            information.mode = 0o644
            archive.addfile(information, io.BytesIO(answer))
        return SimpleNamespace(return_code=0, stdout="", stderr="")

    async def exec_snapshot_owned(
        self,
        command: str,
        *,
        stage: str,
        timeout_sec: float,
        capture_deadline_monotonic_ns: int | None = None,
        hard_deadline_monotonic_ns: int | None = None,
    ) -> SimpleNamespace:
        assert stage in self.stages
        self.capture_deadlines.append(capture_deadline_monotonic_ns)
        self.capture_hard_deadlines.append(hard_deadline_monotonic_ns)
        try:
            result = await self.exec_snapshot(command, timeout_sec=timeout_sec)
        except BaseException as error:
            error.subtype = SnapshotFailureSubtypeV1.WAIT_TRANSPORT_FAILED
            error.timeout_origin = (
                SnapshotTimeoutOriginV1.SEMANTIC_EXECUTION_TIMED_OUT
                if isinstance(error, TimeoutError)
                else SnapshotTimeoutOriginV1.NOT_A_TIMEOUT
            )
            error.stage_validated = True
            error.termination_verified = True
            error.census_verified = True
            error.zero_census_verified = True
            error.survivor_count = 0
            raise
        return SimpleNamespace(
            return_code=getattr(result, "return_code", None),
            stdout=getattr(result, "stdout", None),
            stderr=getattr(result, "stderr", None),
            termination_verified=True,
            census_verified=True,
            zero_census_verified=True,
            survivor_count=0,
        )

    async def download_snapshot(
        self,
        source_path: str,
        target_path: Path | str,
    ) -> None:
        for remote, local in self.stages.items():
            if source_path.startswith(f"{remote}/"):
                shutil.copyfile(local / source_path.rsplit("/", 1)[1], target_path)
                return
        raise AssertionError("unknown remote snapshot path")


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_bytes())


def _failure_core(receipt: dict[str, object]) -> dict[str, object]:
    failure = receipt["failure"]
    assert isinstance(failure, dict)
    assert set(failure) == {
        "stage",
        "category",
        "subtype",
        "timeout_origin",
        "errno",
        "return_code",
        "attempt",
        "stage_validated",
        "termination_verified",
        "cleanup_verified",
        "zero_census_verified",
        "execution_binding_verified",
        "reason",
        "observed_byte_length",
        "observed_sha256",
    }
    return {
        key: failure[key]
        for key in ("stage", "category", "errno", "return_code", "attempt")
    }


def _run_remote_sensitive_detector(path: Path) -> bool:
    script = workspace_snapshot._remote_script(
        "/workspace",
        workspace_snapshot.SnapshotPolicy(),
        "/tmp/nano-workspace-snapshot-v1.fixture",
    )
    assert shlex.quote(workspace_snapshot._REMOTE_SENSITIVE_ERE) in script
    sample = path.read_bytes()[: workspace_snapshot._SENSITIVE_SAMPLE_BYTES].replace(
        b"\n", b" "
    )
    completed = subprocess.run(
        [
            "grep",
            "-aEiq",
            "--",
            workspace_snapshot._REMOTE_SENSITIVE_ERE,
        ],
        check=False,
        input=sample,
        capture_output=True,
        timeout=5,
    )
    assert completed.returncode in {0, 1}, completed.stderr.decode(errors="replace")
    return completed.returncode == 0


def test_v3_failure_receipt_requires_closed_subtype_and_proofs(
    tmp_path: Path,
) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    target = workspace_snapshot.SnapshotTarget(actor=object(), artifact_dir=artifacts)
    failure = workspace_snapshot.WorkspaceSnapshotError(
        "workspace_before_capture_failed",
        stage="remote-exec",
        category="internal",
        subtype=SnapshotFailureSubtypeV1.UNKNOWN_INTERNAL,
        timeout_origin=SnapshotTimeoutOriginV1.NOT_A_TIMEOUT,
        attempt=2,
        stage_validated=True,
        termination_verified=True,
        cleanup_verified=True,
        zero_census_verified=True,
        execution_binding_verified=True,
    )

    workspace_snapshot._failure_receipt(
        target,
        workspace_snapshot.SnapshotPolicy(),
        failure.code,
        failure,
    )

    payload = (artifacts / "workspace-receipt.json").read_bytes()
    receipt = json.loads(payload)
    assert receipt["schema_version"] == "nano-workspace-receipt-v5"
    assert set(receipt) == {
        "schema_version",
        "status",
        "code",
        "policy",
        "truncated",
        "omitted_count",
        "artifacts",
        "failure",
        "baseline_state",
    }
    assert set(receipt["failure"]) == {
        "stage",
        "category",
        "subtype",
        "timeout_origin",
        "errno",
        "return_code",
        "attempt",
        "stage_validated",
        "termination_verified",
        "cleanup_verified",
        "zero_census_verified",
        "execution_binding_verified",
        "reason",
        "observed_byte_length",
        "observed_sha256",
    }
    assert receipt["failure"] == {
        "stage": "remote-exec",
        "category": "internal",
        "subtype": "unknown_internal",
        "timeout_origin": "not_a_timeout",
        "errno": None,
        "return_code": None,
        "attempt": 2,
        "stage_validated": True,
        "termination_verified": True,
        "cleanup_verified": True,
        "zero_census_verified": True,
        "execution_binding_verified": True,
        "reason": "not_applicable",
        "observed_byte_length": None,
        "observed_sha256": None,
    }
    assert {subtype.value for subtype in SnapshotFailureSubtypeV1} == {
        "owned_stage_setup_failed",
        "command_upload_failed",
        "launch_failed",
        "lease_parse_failed",
        "lease_release_failed",
        "wait_transport_failed",
        "wait_response_invalid",
        "terminal_record_invalid",
        "output_download_failed",
        "host_evidence_parse_failed",
        "host_evidence_materialization_failed",
        "recovery_unverified",
        "stage_cleanup_failed",
        "unknown_internal",
    }
    assert b"HOST_OS_ERROR" not in payload

    for missing_proof in (
        "stage_validated",
        "termination_verified",
        "cleanup_verified",
        "zero_census_verified",
    ):
        proofs = {
            "stage_validated": True,
            "termination_verified": True,
            "cleanup_verified": True,
            "zero_census_verified": True,
        }
        proofs[missing_proof] = False
        assert (
            workspace_snapshot.workspace_failure_disposition(
                "workspace_before_capture_failed",
                "remote-exec",
                "timeout",
                subtype=SnapshotFailureSubtypeV1.WAIT_TRANSPORT_FAILED,
                timeout_origin=SnapshotTimeoutOriginV1.SEMANTIC_EXECUTION_TIMED_OUT,
                **proofs,
            )
            == "trial_fatal"
        )

    invalid_timeout_origin = workspace_snapshot.WorkspaceSnapshotError(
        "workspace_after_capture_failed",
        stage="host-evidence",
        category="evidence",
        subtype=SnapshotFailureSubtypeV1.HOST_EVIDENCE_MATERIALIZATION_FAILED,
        timeout_origin="future_timeout_origin",
        stage_validated=True,
        termination_verified=True,
        cleanup_verified=True,
        zero_census_verified=True,
    )
    assert (
        workspace_snapshot.workspace_failure_disposition(
            invalid_timeout_origin.code,
            invalid_timeout_origin.failure.stage,
            invalid_timeout_origin.failure.category,
            subtype=invalid_timeout_origin.failure.subtype,
            timeout_origin=invalid_timeout_origin.failure.timeout_origin,
            stage_validated=invalid_timeout_origin.failure.stage_validated,
            termination_verified=(invalid_timeout_origin.failure.termination_verified),
            cleanup_verified=invalid_timeout_origin.failure.cleanup_verified,
            zero_census_verified=(invalid_timeout_origin.failure.zero_census_verified),
        )
        == "trial_fatal"
    )


@pytest.mark.parametrize(
    ("code", "stage", "category", "subtype", "timeout_origin"),
    [
        (
            "workspace_before_capture_failed",
            "remote-exec",
            "timeout",
            SnapshotFailureSubtypeV1.WAIT_TRANSPORT_FAILED,
            SnapshotTimeoutOriginV1.SEMANTIC_EXECUTION_TIMED_OUT,
        ),
        (
            "workspace_after_capture_failed",
            "remote-exec",
            "timeout",
            SnapshotFailureSubtypeV1.WAIT_TRANSPORT_FAILED,
            SnapshotTimeoutOriginV1.WAIT_TRANSPORT_TIMED_OUT_RECOVERED,
        ),
        (
            "workspace_after_capture_failed",
            "host-evidence",
            "evidence",
            SnapshotFailureSubtypeV1.HOST_EVIDENCE_MATERIALIZATION_FAILED,
            SnapshotTimeoutOriginV1.NOT_A_TIMEOUT,
        ),
    ],
)
def test_workspace_failure_disposition_has_exact_proven_allowlist(
    code: str,
    stage: str,
    category: str,
    subtype: SnapshotFailureSubtypeV1,
    timeout_origin: SnapshotTimeoutOriginV1,
) -> None:
    assert (
        workspace_snapshot.workspace_failure_disposition(
            code,
            stage,
            category,
            subtype=subtype,
            timeout_origin=timeout_origin,
            stage_validated=True,
            termination_verified=True,
            cleanup_verified=True,
            zero_census_verified=True,
        )
        == "diagnostic_failed_continue"
    )


@pytest.mark.parametrize(
    ("code", "stage", "category"),
    [
        ("workspace_before_capture_failed", "target", "transport"),
        ("workspace_before_capture_failed", "stage-parse", "parse"),
        ("workspace_before_capture_failed", "inventory-parse", "parse"),
        ("workspace_before_capture_failed", "archive-parse", "parse"),
        ("workspace_before_capture_failed", "publish", "publish"),
        ("workspace_before_capture_failed", "remote-exec", "timeout"),
        ("workspace_before_capture_failed", "remote-exec", "connection"),
        ("workspace_before_capture_failed", "remote-exec", "os_error"),
        ("workspace_before_capture_failed", "remote-exec", "transport"),
        ("workspace_before_capture_failed", "remote-exec", "policy"),
        ("workspace_before_capture_failed", "remote-command", "transport"),
        ("workspace_before_capture_failed", "remote-command", "command"),
        ("workspace_before_capture_failed", "inventory-download", "connection"),
        ("workspace_before_capture_failed", "archive-download", "transport"),
        ("workspace_before_capture_failed", "cleanup", "timeout"),
        ("workspace_before_capture_failed", "cleanup", "connection"),
        ("workspace_before_capture_failed", "cleanup", "os_error"),
        ("workspace_before_capture_failed", "cleanup", "transport"),
        ("workspace_before_capture_failed", "cleanup", "command"),
        ("workspace_before_capture_failed", "cleanup", "internal"),
        ("workspace_before_capture_cancelled", "target", "cancelled"),
        ("workspace_after_capture_cancelled", "publish", "cancelled"),
        ("workspace_snapshot_existing_mismatch", "publish", "publish"),
        ("workspace_snapshot_transport_unavailable", "target", "transport"),
        ("unknown_future_workspace_code", "remote-exec", "transport"),
        ("workspace_before_capture_failed", "unknown-stage", "transport"),
        ("workspace_before_capture_failed", "remote-exec", "unknown-category"),
    ],
)
def test_workspace_failure_disposition_defaults_security_failures_to_fatal(
    code: str,
    stage: str,
    category: str,
) -> None:
    assert (
        workspace_snapshot.workspace_failure_disposition(code, stage, category)
        == "trial_fatal"
    )


@pytest.mark.parametrize(
    ("stage_validated", "cleanup_verified"),
    [(True, False), (False, True)],
)
@pytest.mark.parametrize(
    "category",
    ["timeout", "connection", "os_error", "transport"],
)
def test_remote_exec_disposition_requires_both_ownership_proofs(
    category: str,
    stage_validated: bool,
    cleanup_verified: bool,
) -> None:
    assert (
        workspace_snapshot.workspace_failure_disposition(
            "workspace_before_capture_failed",
            "remote-exec",
            category,
            stage_validated=stage_validated,
            cleanup_verified=cleanup_verified,
        )
        == "trial_fatal"
    )


def test_remote_exec_disposition_requires_execution_termination_proof() -> None:
    assert (
        workspace_snapshot.workspace_failure_disposition(
            "workspace_before_capture_failed",
            "remote-exec",
            "timeout",
            subtype=SnapshotFailureSubtypeV1.WAIT_TRANSPORT_FAILED,
            timeout_origin=SnapshotTimeoutOriginV1.SEMANTIC_EXECUTION_TIMED_OUT,
            stage_validated=True,
            termination_verified=False,
            cleanup_verified=True,
            zero_census_verified=True,
        )
        == "trial_fatal"
    )
    assert (
        workspace_snapshot.workspace_failure_disposition(
            "workspace_before_capture_failed",
            "remote-exec",
            "timeout",
            subtype=SnapshotFailureSubtypeV1.WAIT_TRANSPORT_FAILED,
            timeout_origin=SnapshotTimeoutOriginV1.SEMANTIC_EXECUTION_TIMED_OUT,
            stage_validated=True,
            termination_verified=True,
            cleanup_verified=True,
            zero_census_verified=True,
        )
        == "diagnostic_failed_continue"
    )


@pytest.mark.parametrize(
    "code",
    ["workspace_before_capture_failed", "workspace_after_capture_failed"],
)
def test_wait_response_invalid_requires_exact_execution_binding_proof(
    code: str,
) -> None:
    proofs = {
        "stage_validated": True,
        "termination_verified": True,
        "cleanup_verified": True,
        "zero_census_verified": True,
        "execution_binding_verified": True,
    }
    disposition = {
        "subtype": SnapshotFailureSubtypeV1.WAIT_RESPONSE_INVALID,
        "timeout_origin": SnapshotTimeoutOriginV1.NOT_A_TIMEOUT,
        "reason": SnapshotFailureReasonV1.OUTER_RETURN_CODE_NONZERO,
    }
    assert (
        workspace_snapshot.workspace_failure_disposition(
            code,
            "remote-exec",
            "internal",
            **disposition,
            **proofs,
        )
        == "diagnostic_failed_continue"
    )

    for missing_proof in proofs:
        partial = dict(proofs)
        partial[missing_proof] = False
        assert (
            workspace_snapshot.workspace_failure_disposition(
                code,
                "remote-exec",
                "internal",
                **disposition,
                **partial,
            )
            == "trial_fatal"
        )

    for mutation in (
        {"stage": "cleanup"},
        {"category": "command"},
        {"timeout_origin": SnapshotTimeoutOriginV1.SEMANTIC_EXECUTION_TIMED_OUT},
        {"reason": SnapshotFailureReasonV1.UNKNOWN},
    ):
        assert (
            workspace_snapshot.workspace_failure_disposition(
                code,
                mutation.get("stage", "remote-exec"),
                mutation.get("category", "internal"),
                subtype=SnapshotFailureSubtypeV1.WAIT_RESPONSE_INVALID,
                timeout_origin=mutation.get(
                    "timeout_origin",
                    SnapshotTimeoutOriginV1.NOT_A_TIMEOUT,
                ),
                reason=mutation.get(
                    "reason",
                    SnapshotFailureReasonV1.OUTER_RETURN_CODE_NONZERO,
                ),
                **proofs,
            )
            == "trial_fatal"
        )


def test_policy_is_versioned_bounded_and_rejects_invalid_caps() -> None:
    policy = workspace_snapshot.SnapshotPolicy(
        max_files=7,
        max_total_bytes=19,
        max_file_bytes=11,
        max_patch_bytes=13,
    )

    assert policy.version == "nano-workspace-snapshot-policy-v1"
    assert policy.max_files == 7
    assert policy.max_total_bytes == 19
    assert policy.max_file_bytes == 11
    assert policy.max_patch_bytes == 13

    for kwargs in (
        {"max_files": 0},
        {"max_total_bytes": 0},
        {"max_file_bytes": 0},
        {"max_patch_bytes": 0},
        {"max_file_bytes": 2, "max_total_bytes": 1},
        {"version": "unreviewed"},
    ):
        with pytest.raises(ValueError):
            workspace_snapshot.SnapshotPolicy(**kwargs)


@pytest.mark.parametrize(
    ("limit", "over_budget"),
    [(7, True), (8, False), (9, False)],
)
def test_content_cap_boundary_uses_bounded_secret_sample_without_full_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit: int,
    over_budget: bool,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    candidate = workspace / "payload.bin"
    candidate.write_bytes(b"12345678")
    reads: list[str] = []
    original = workspace_snapshot._read_exact_regular

    def observed(path: Path, metadata: os.stat_result) -> bytes:
        reads.append(path.name)
        return original(path, metadata)

    monkeypatch.setattr(workspace_snapshot, "_read_exact_regular", observed)
    policy = workspace_snapshot.SnapshotPolicy(
        max_files=10,
        max_total_bytes=limit,
        max_file_bytes=limit,
        max_patch_bytes=100,
    )

    inventory = workspace_snapshot._inventory(workspace, policy)
    if over_budget:
        assert inventory.safe_contents == {}
        assert reads == []
        assert "sha256" not in inventory.entries["payload.bin"]
        assert inventory.content_omissions["payload.bin"] == {
            "path": "payload.bin",
            "reason": "per_file_byte_cap",
        }
    else:
        assert inventory.safe_contents == {"payload.bin": b"12345678"}
        assert reads == ["payload.bin"]


def test_excluded_and_sensitive_paths_are_pruned_before_content_read_or_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "safe.txt").write_text("safe")
    (workspace / "owner-token.txt").write_text("must not read")
    excluded = workspace / ".git"
    excluded.mkdir()
    (excluded / "object").write_text("must not read")
    sensitive = workspace / "credentials"
    sensitive.mkdir()
    (sensitive / "nested.txt").write_text("must not read")
    reads: list[str] = []
    original = workspace_snapshot._read_exact_regular

    def observed(path: Path, metadata: os.stat_result) -> bytes:
        relative = path.relative_to(workspace).as_posix()
        reads.append(relative)
        return original(path, metadata)

    monkeypatch.setattr(workspace_snapshot, "_read_exact_regular", observed)
    inventory = workspace_snapshot._inventory(
        workspace,
        workspace_snapshot.SnapshotPolicy(),
    )

    assert reads == ["safe.txt"]
    assert set(inventory.entries) == {"safe.txt"}
    assert inventory.content_omissions == {
        "credentials": {
            "path": "credentials",
            "reason": "sensitive_path",
        },
        "owner-token.txt": {
            "path": "owner-token.txt",
            "reason": "sensitive_path",
        },
    }
    assert all("token" not in repr(value) for value in inventory.manifest.values())


def test_over_budget_after_publishes_partial_valid_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    artifacts = tmp_path / "artifacts"
    workspace.mkdir()
    artifacts.mkdir()
    policy = workspace_snapshot.SnapshotPolicy(
        max_files=10,
        max_total_bytes=7,
        max_file_bytes=7,
        max_patch_bytes=100,
    )
    actor = LocalSnapshotActor(workspace, artifacts)
    before = asyncio.run(workspace_snapshot.capture_before(actor, policy))
    (workspace / "payload.bin").write_bytes(b"12345678")

    def unexpected(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("over-budget plan reached content/archive work")

    monkeypatch.setattr(workspace_snapshot, "_read_exact_regular", unexpected)
    receipt = asyncio.run(workspace_snapshot.capture_after(actor, before))

    assert receipt.schema_version == workspace_snapshot.RECEIPT_SCHEMA
    assert receipt.status == "complete"
    assert receipt.code == "completed"
    assert receipt.truncated is True
    assert receipt.omitted_count == 1
    delta = _load(artifacts / "workspace-delta.json")
    assert delta["omitted"] == [
        {
            "path": "payload.bin",
            "reason": "per_file_byte_cap",
        }
    ]
    with tarfile.open(artifacts / "workspace-changed.tar", "r:") as archive:
        assert archive.getnames() == []
    persisted = workspace_snapshot.load_workspace_receipt(
        artifacts / "workspace-receipt.json"
    )
    assert persisted == receipt


def test_in_budget_metadata_plan_retains_exact_manifest_bytes(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    candidate = workspace / "answer.txt"
    candidate.write_bytes(b"answer\n")
    candidate.chmod(0o644)

    inventory = workspace_snapshot._inventory(
        workspace,
        workspace_snapshot.SnapshotPolicy(
            max_files=1,
            max_total_bytes=7,
            max_file_bytes=7,
            max_patch_bytes=100,
        ),
    )

    assert workspace_snapshot.canonical_json(inventory.manifest) == (
        b'{"entries":[{"kind":"file","mode":"0644","path":"answer.txt",'
        b'"sha256":"6959b4fff6c9960b2ebbc289573e00e9c7097597e84b3c45759f36fe'
        b'f9778736","size":7}],"entry_count":1,"policy_version":'
        b'"nano-workspace-snapshot-policy-v1","scan_complete":true,'
        b'"schema_version":"nano-workspace-manifest-v1"}\n'
    )


def test_remote_script_caps_content_without_exact_plan_failure() -> None:
    script = workspace_snapshot._remote_script(
        "/workspace",
        workspace_snapshot.SnapshotPolicy(),
        "/tmp/nano-workspace-snapshot-v1.fixture",
    )
    assert "exact-plan.tsv" not in script
    assert "per_file_byte_cap" in script
    assert "total_byte_cap" in script
    assert "C\\tfile_count_cap\\t%s\\tlower_bound" in script
    assert f"head -z -n {workspace_snapshot.SnapshotPolicy().max_files + 1}" in script
    assert "sort -z" not in script
    assert script.index('if [ "$size" -gt') < script.rindex("sha256sum")
    assert script.rindex("sha256sum") < script.index('tar -C "$root"')
    assert (
        f"timeout -k 1s {workspace_snapshot._REMOTE_SCAN_PHASE_TIMEOUT_SEC}s" in script
    )
    assert (
        f"content_cutoff=$(( $(date +%s) + "
        f"{workspace_snapshot._REMOTE_CONTENT_PHASE_TIMEOUT_SEC} ))" in script
    )
    assert "C\\tinventory_scan_wall_budget" in script
    assert "C\\tcontent_scan_wall_budget" in script
    assert "C\\tarchive_wall_budget" in script


def test_generated_remote_script_round_trips_capped_inventory_deterministically(
    tmp_path: Path,
) -> None:
    if shutil.which("timeout") is None:
        pytest.skip("GNU timeout unavailable")
    head_probe = subprocess.run(
        ["head", "-z", "-n", "1"],
        input=b"probe\0",
        capture_output=True,
        check=False,
    )
    if head_probe.returncode != 0:
        pytest.skip("GNU head -z unavailable")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    payloads = {f"fixture-{index}.txt": f"{index}\n".encode() for index in range(6)}
    for name, payload in payloads.items():
        (workspace / name).write_bytes(payload)
    policy = workspace_snapshot.SnapshotPolicy(
        max_files=5,
        max_total_bytes=100,
        max_file_bytes=100,
        max_patch_bytes=100,
    )

    captures = []
    for capture_index in range(2):
        stage = tmp_path / f"stage-{capture_index}"
        stage.mkdir()
        completed = subprocess.run(
            ["bash"],
            input=workspace_snapshot._remote_script(
                str(workspace),
                policy,
                str(stage),
            ).encode(),
            capture_output=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
        parsed = workspace_snapshot._parse_remote_inventory(
            stage / "inventory.tsv",
            stage / "safe.tar",
            policy,
        )
        captures.append(
            (
                parsed,
                (stage / "inventory.tsv").read_bytes(),
                (stage / "safe.tar").read_bytes(),
            )
        )

    first, second = captures
    retained = set(first[0].entries)
    assert len(retained) == policy.max_files
    assert set(first[0].safe_contents) == retained
    assert first[0].safe_contents == {name: payloads[name] for name in retained}
    assert {name: first[0].entries[name]["sha256"] for name in retained} == {
        name: hashlib.sha256(payloads[name]).hexdigest() for name in retained
    }
    assert first[0].manifest["scan_complete"] is False
    assert first[0].content_omissions == {
        "": {
            "path": "",
            "reason": "file_count_cap",
            "count": 1,
            "count_is_lower_bound": True,
        }
    }
    assert workspace_snapshot.canonical_json(first[0].manifest) == (
        workspace_snapshot.canonical_json(second[0].manifest)
    )
    assert first[0].safe_contents == second[0].safe_contents
    assert first[0].content_omissions == second[0].content_omissions
    assert first[1:] == second[1:]


def test_git_snapshot_records_tracked_staged_binary_and_nul_safe_untracked(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    artifacts = tmp_path / "artifacts"
    workspace.mkdir()
    artifacts.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
    subprocess.run(
        ["git", "config", "user.email", "fixture@example.invalid"],
        cwd=workspace,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "fixture"],
        cwd=workspace,
        check=True,
    )
    (workspace / "tracked.txt").write_text("before\n")
    (workspace / "binary.bin").write_bytes(b"\x00before")
    subprocess.run(
        ["git", "add", "tracked.txt", "binary.bin"], cwd=workspace, check=True
    )
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=workspace, check=True)
    actor = LocalSnapshotActor(workspace, artifacts)
    before = asyncio.run(
        workspace_snapshot.capture_before(actor, workspace_snapshot.SnapshotPolicy())
    )

    (workspace / "tracked.txt").write_text("after\n")
    (workspace / "binary.bin").write_bytes(b"\x00after")
    subprocess.run(["git", "add", "binary.bin"], cwd=workspace, check=True)
    newline_name = "untracked\nname.txt"
    (workspace / newline_name).write_text("new\n")
    receipt = asyncio.run(workspace_snapshot.capture_after(actor, before))

    delta = _load(artifacts / "workspace-delta.json")
    patch = (artifacts / "workspace-diff.patch").read_bytes()
    assert delta["git"]["head"]
    assert delta["git"]["index_tree_before"] != delta["git"]["index_tree_after"]
    assert delta["git"]["status_porcelain_v2_z_sha256"]
    assert newline_name in {row["path"] for row in delta["created"]}
    assert b"tracked.txt" in patch
    assert b"binary.bin" not in patch
    assert receipt.status == "complete"


def test_non_git_manifest_tracks_mode_symlink_size_hash_and_deletion(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    artifacts = tmp_path / "artifacts"
    workspace.mkdir()
    artifacts.mkdir()
    original = workspace / "original.txt"
    original.write_text("before")
    original.chmod(0o640)
    symlink = workspace / "link"
    symlink.symlink_to("original.txt")
    actor = LocalSnapshotActor(workspace, artifacts)
    before = asyncio.run(
        workspace_snapshot.capture_before(actor, workspace_snapshot.SnapshotPolicy())
    )

    original.unlink()
    created = workspace / "created.txt"
    created.write_text("after")
    created.chmod(0o750)
    symlink.unlink()
    symlink.symlink_to("created.txt")
    asyncio.run(workspace_snapshot.capture_after(actor, before))

    after = _load(artifacts / "workspace-after.json")
    rows = {row["path"]: row for row in after["entries"]}
    assert rows["created.txt"] == {
        "kind": "file",
        "mode": "0750",
        "path": "created.txt",
        "sha256": __import__("hashlib").sha256(b"after").hexdigest(),
        "size": 5,
    }
    assert rows["link"] == {
        "kind": "symlink",
        "mode": f"{stat.S_IMODE(os.lstat(symlink).st_mode):04o}",
        "path": "link",
        "size": len("created.txt"),
        "target": "created.txt",
    }
    delta = _load(artifacts / "workspace-delta.json")
    assert [row["path"] for row in delta["deleted"]] == ["original.txt"]
    assert [row["path"] for row in delta["modified"]] == ["link"]


def test_local_escape_symlink_is_omitted_without_invalidating_snapshot(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    artifacts = tmp_path / "artifacts"
    workspace.mkdir()
    artifacts.mkdir()
    actor = LocalSnapshotActor(workspace, artifacts)
    before = asyncio.run(
        workspace_snapshot.capture_before(actor, workspace_snapshot.SnapshotPolicy())
    )
    (workspace / "outside-link").symlink_to("/etc/passwd")

    receipt = asyncio.run(workspace_snapshot.capture_after(actor, before))

    delta = _load(artifacts / "workspace-delta.json")
    assert delta["omitted"] == [
        {
            "path": "outside-link",
            "reason": "symlink_escape",
        }
    ]
    with tarfile.open(artifacts / "workspace-changed.tar", "r:") as archive:
        assert archive.getnames() == []
    assert receipt.status == "complete"
    assert receipt.truncated is False


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unavailable")
def test_special_files_and_excluded_trees_are_never_archived(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    artifacts = tmp_path / "artifacts"
    workspace.mkdir()
    artifacts.mkdir()
    actor = LocalSnapshotActor(workspace, artifacts)
    before = asyncio.run(
        workspace_snapshot.capture_before(actor, workspace_snapshot.SnapshotPolicy())
    )
    fifo = workspace / "pipe"
    os.mkfifo(fifo)
    for excluded in (".git", ".terminals", ".cache", "cache", "dataset", "datasets"):
        directory = workspace / excluded
        directory.mkdir()
        (directory / "payload.txt").write_text("do not archive")

    asyncio.run(workspace_snapshot.capture_after(actor, before))

    delta = _load(artifacts / "workspace-delta.json")
    omissions = {row["path"]: row["reason"] for row in delta["omitted"]}
    assert omissions["pipe"] == "special_file"
    with tarfile.open(artifacts / "workspace-changed.tar", "r:") as archive:
        names = archive.getnames()
    assert "pipe" not in names
    assert not any(
        name.startswith((".git/", ".terminals/", ".cache/")) for name in names
    )
    assert not any(
        name.startswith(("cache/", "dataset/", "datasets/")) for name in names
    )


@pytest.mark.parametrize(
    "path,content",
    [
        ("vulnerable-secret.txt", b"harmless"),
        (".env", b"PUBLIC=harmless\n"),
        ("config.json", b'{"api_key":"sk-secret-value"}\n'),
        (
            "id_rsa",
            b"-----BEGIN " + b"PRIVATE " + b"KEY-----\nsecret\n",
        ),
    ],
)
def test_sensitive_path_is_pruned_and_sensitive_content_is_quarantined(
    tmp_path: Path,
    path: str,
    content: bytes,
) -> None:
    workspace = tmp_path / "workspace"
    artifacts = tmp_path / "artifacts"
    workspace.mkdir()
    artifacts.mkdir()
    actor = LocalSnapshotActor(workspace, artifacts)
    before = asyncio.run(
        workspace_snapshot.capture_before(actor, workspace_snapshot.SnapshotPolicy())
    )
    (workspace / path).write_bytes(content)

    asyncio.run(workspace_snapshot.capture_after(actor, before))

    delta_raw = (artifacts / "workspace-delta.json").read_bytes()
    delta = json.loads(delta_raw)
    if workspace_snapshot._sensitive_path(path):
        assert path not in {row["path"] for row in delta["created"]}
        omission = next(row for row in delta["omitted"] if row["path"] == path)
        assert omission == {"path": path, "reason": "sensitive_path"}
        assert hashlib.sha256(content).hexdigest().encode() not in delta_raw
    else:
        omission = next(row for row in delta["omitted"] if row["path"] == path)
        assert omission["reason"] == "sensitive_content"
        assert omission["sha256"]
    assert content not in delta_raw
    with tarfile.open(artifacts / "workspace-changed.tar", "r:") as archive:
        assert path not in archive.getnames()


@pytest.mark.parametrize(
    ("payload", "expected_sensitive"),
    [
        (b"case MODFTOKEN:\n      automaton((char *)0);\n", True),
        (b"password:\n    fixture-value\n", True),
        (b"password=abc\x00def\n", True),
        (b"case MODFITEM:\n      automaton((char *)0);\n", False),
    ],
)
def test_remote_sensitive_detector_matches_host_across_record_boundaries(
    tmp_path: Path,
    payload: bytes,
    expected_sensitive: bool,
) -> None:
    candidate = tmp_path / "candidate.bin"
    candidate.write_bytes(payload)

    assert workspace_snapshot._sensitive_content(payload) is expected_sensitive
    assert _run_remote_sensitive_detector(candidate) is expected_sensitive


@pytest.mark.parametrize(
    "payload",
    [
        b"case MODFTOKEN:\n      automaton((char *)0);\n",
        b"password=abc\x00def\n",
    ],
)
def test_remote_archive_keeps_host_sensitive_payload_fail_closed(
    tmp_path: Path,
    payload: bytes,
) -> None:
    archive_path = tmp_path / "safe.tar"
    with tarfile.open(archive_path, "w:") as archive:
        information = tarfile.TarInfo("candidate.bin")
        information.size = len(payload)
        archive.addfile(information, io.BytesIO(payload))
    entries = {
        "candidate.bin": {
            "kind": "file",
            "mode": "0644",
            "path": "candidate.bin",
            "sha256": __import__("hashlib").sha256(payload).hexdigest(),
            "size": len(payload),
        }
    }

    with pytest.raises(
        workspace_snapshot.WorkspaceSnapshotError,
        match="^workspace_snapshot_remote_archive_invalid$",
    ):
        workspace_snapshot._parse_remote_archive(
            archive_path,
            entries=entries,
            omissions={},
            policy=workspace_snapshot.SnapshotPolicy(),
        )


def test_remote_escape_symlink_is_omitted_without_invalidating_snapshot(
    tmp_path: Path,
) -> None:
    inventory_path = tmp_path / "inventory.tsv"
    archive_path = tmp_path / "safe.tar"
    relative = "outside-link"
    target = "/etc/passwd"
    inventory_path.write_text(
        "E\t"
        + base64.b64encode(relative.encode()).decode()
        + "\tsymlink\t0777\t"
        + str(len(target))
        + "\t"
        + base64.b64encode(target.encode()).decode()
        + "\tsymlink_escape\n"
    )
    with tarfile.open(archive_path, "w:"):
        pass

    inventory = workspace_snapshot._parse_remote_inventory(
        inventory_path,
        archive_path,
        workspace_snapshot.SnapshotPolicy(),
    )

    assert inventory.entries[relative]["target"] == target
    assert inventory.safe_contents == {}
    assert inventory.content_omissions[relative] == {
        "path": relative,
        "reason": "symlink_escape",
    }


def test_remote_inventory_archive_membership_mismatch_remains_fatal(
    tmp_path: Path,
) -> None:
    inventory_path = tmp_path / "inventory.tsv"
    archive_path = tmp_path / "safe.tar"
    relative = "inside-link"
    target = "answer.txt"
    inventory_path.write_text(
        "E\t"
        + base64.b64encode(relative.encode()).decode()
        + "\tsymlink\t0777\t"
        + str(len(target))
        + "\t"
        + base64.b64encode(target.encode()).decode()
        + "\t\n"
    )
    with tarfile.open(archive_path, "w:"):
        pass

    with pytest.raises(
        workspace_snapshot.WorkspaceSnapshotError,
        match="^workspace_snapshot_remote_archive_invalid$",
    ):
        workspace_snapshot._parse_remote_inventory(
            inventory_path,
            archive_path,
            workspace_snapshot.SnapshotPolicy(),
        )


def test_remote_caps_preserve_hashed_manifest_and_omission_count(
    tmp_path: Path,
) -> None:
    inventory_path = tmp_path / "inventory.tsv"
    archive_path = tmp_path / "safe.tar"
    relative = "large.bin"
    digest = hashlib.sha256(b"oversized").hexdigest()
    inventory_path.write_text(
        "E\t"
        + base64.b64encode(relative.encode()).decode()
        + f"\tfile\t0644\t9\t{digest}\tper_file_byte_cap\n"
        + "C\tfile_count_cap\t3\n"
    )
    with tarfile.open(archive_path, "w:"):
        pass

    inventory = workspace_snapshot._parse_remote_inventory(
        inventory_path,
        archive_path,
        workspace_snapshot.SnapshotPolicy(),
    )

    assert inventory.manifest["scan_complete"] is False
    assert inventory.entries[relative]["sha256"] == digest
    assert inventory.content_omissions[relative]["reason"] == "per_file_byte_cap"
    assert inventory.content_omissions[""] == {
        "path": "",
        "reason": "file_count_cap",
        "count": 3,
    }


def test_remote_phase_budget_can_publish_metadata_only_partial_inventory(
    tmp_path: Path,
) -> None:
    inventory_path = tmp_path / "inventory.tsv"
    archive_path = tmp_path / "safe.tar"
    relative = "answer.txt"
    digest = hashlib.sha256(b"answer\n").hexdigest()
    inventory_path.write_text(
        "E\t"
        + base64.b64encode(relative.encode()).decode()
        + f"\tfile\t0644\t7\t{digest}\t\n"
        + "C\tgit_metadata_unavailable\n"
        + "C\tinventory_scan_wall_budget\n"
        + "C\tarchive_wall_budget\n"
    )
    with tarfile.open(archive_path, "w:"):
        pass

    inventory = workspace_snapshot._parse_remote_inventory(
        inventory_path,
        archive_path,
        workspace_snapshot.SnapshotPolicy(),
    )

    assert inventory.manifest["scan_complete"] is False
    assert inventory.entries[relative]["sha256"] == digest
    assert inventory.safe_contents == {}
    assert {row["reason"] for row in inventory.content_omissions.values()} == {
        "archive_wall_budget",
        "git_metadata_unavailable",
        "inventory_scan_wall_budget",
    }


def test_local_inventory_stops_at_entry_cap_and_marks_count_lower_bound(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    for index in range(100):
        (workspace / f"{index:03d}.txt").write_text(str(index))
    policy = workspace_snapshot.SnapshotPolicy(
        max_files=5,
        max_total_bytes=100,
        max_file_bytes=100,
        max_patch_bytes=100,
    )

    inventory = workspace_snapshot._inventory(workspace, policy)

    assert len(inventory.entries) == policy.max_files
    assert inventory.manifest["scan_complete"] is False
    assert inventory.content_omissions[""] == {
        "path": "",
        "reason": "file_count_cap",
        "count": 1,
        "count_is_lower_bound": True,
    }


def test_binary_is_archived_but_patch_omits_it(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    artifacts = tmp_path / "artifacts"
    workspace.mkdir()
    artifacts.mkdir()
    actor = LocalSnapshotActor(workspace, artifacts)
    before = asyncio.run(
        workspace_snapshot.capture_before(actor, workspace_snapshot.SnapshotPolicy())
    )
    payload = b"\x00\x01\x02binary"
    (workspace / "result.bin").write_bytes(payload)

    asyncio.run(workspace_snapshot.capture_after(actor, before))

    assert b"result.bin" not in (artifacts / "workspace-diff.patch").read_bytes()
    with tarfile.open(artifacts / "workspace-changed.tar", "r:") as archive:
        member = archive.getmember("result.bin")
        extracted = archive.extractfile(member)
        assert extracted is not None
        assert extracted.read() == payload


@pytest.mark.parametrize(
    ("policy", "files", "reason"),
    [
        (
            workspace_snapshot.SnapshotPolicy(
                max_files=1,
                max_total_bytes=20,
                max_file_bytes=10,
                max_patch_bytes=100,
            ),
            {"a.txt": b"aaaa", "b.txt": b"bbbb"},
            "file_count_cap",
        ),
        (
            workspace_snapshot.SnapshotPolicy(
                max_files=10,
                max_total_bytes=20,
                max_file_bytes=5,
                max_patch_bytes=100,
            ),
            {"large.txt": b"cccccc"},
            "per_file_byte_cap",
        ),
        (
            workspace_snapshot.SnapshotPolicy(
                max_files=10,
                max_total_bytes=7,
                max_file_bytes=7,
                max_patch_bytes=100,
            ),
            {"a.txt": b"aaaa", "b.txt": b"bbbb"},
            "total_byte_cap",
        ),
        (
            workspace_snapshot.SnapshotPolicy(
                max_files=10,
                max_total_bytes=20,
                max_file_bytes=10,
                max_patch_bytes=4,
            ),
            {"a.txt": b"aaaa"},
            "patch_byte_cap",
        ),
    ],
)
def test_file_per_file_total_and_patch_caps_produce_explicit_omissions(
    tmp_path: Path,
    policy: workspace_snapshot.SnapshotPolicy,
    files: dict[str, bytes],
    reason: str,
) -> None:
    workspace = tmp_path / "workspace"
    artifacts = tmp_path / "artifacts"
    workspace.mkdir()
    artifacts.mkdir()
    actor = LocalSnapshotActor(workspace, artifacts)
    before = asyncio.run(workspace_snapshot.capture_before(actor, policy))
    for name, payload in files.items():
        (workspace / name).write_bytes(payload)

    receipt = asyncio.run(workspace_snapshot.capture_after(actor, before))

    delta = _load(artifacts / "workspace-delta.json")
    reasons = {row["reason"] for row in delta["omitted"]}
    assert reason in reasons
    assert receipt.schema_version == workspace_snapshot.RECEIPT_SCHEMA
    assert receipt.status == "complete"
    assert receipt.code == "completed"
    assert receipt.truncated is True
    assert receipt.omitted_count >= 1
    assert (artifacts / "workspace-changed.tar").exists()
    assert (artifacts / "workspace-diff.patch").stat().st_size <= (
        policy.max_patch_bytes
    )


def test_capture_failure_and_cancel_still_publish_canonical_receipt(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    artifacts = tmp_path / "artifacts"
    workspace.mkdir()
    artifacts.mkdir()
    actor = LocalSnapshotActor(workspace, artifacts)
    actor.fail_phase = "after"
    before = asyncio.run(
        workspace_snapshot.capture_before(actor, workspace_snapshot.SnapshotPolicy())
    )

    receipt = asyncio.run(workspace_snapshot.capture_after(actor, before))

    assert receipt.status == "failed"
    assert receipt.code == "workspace_after_capture_failed"
    receipt_raw = (artifacts / "workspace-receipt.json").read_bytes()
    assert receipt_raw.endswith(b"\n")
    assert receipt_raw == workspace_snapshot.canonical_json(json.loads(receipt_raw))
    assert b"Traceback" not in receipt_raw


def test_after_host_evidence_failure_without_remote_closure_is_fatal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    artifacts = tmp_path / "artifacts"
    workspace.mkdir()
    artifacts.mkdir()
    actor = LocalSnapshotActor(workspace, artifacts)
    before = asyncio.run(
        workspace_snapshot.capture_before(actor, workspace_snapshot.SnapshotPolicy())
    )
    (workspace / "answer.txt").write_text("answer\n")
    original_open = workspace_snapshot.os.open

    def fail_new_after_publish(path: object, *args: object, **kwargs: object) -> int:
        if Path(path) == artifacts / ".workspace-after.json.tmp":
            raise PermissionError(13, "HOST_OS_ERROR", "/host/private")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(workspace_snapshot.os, "open", fail_new_after_publish)

    receipt = asyncio.run(workspace_snapshot.capture_after(actor, before))

    assert receipt.status == "failed"
    assert receipt.code == "workspace_after_capture_failed"
    assert receipt.failure is not None
    assert receipt.failure.stage == "publish"
    assert receipt.failure.category == "os_error"
    assert receipt.failure.subtype is SnapshotFailureSubtypeV1.UNKNOWN_INTERNAL
    assert receipt.continuable is False
    assert not (artifacts / "workspace-after.json").exists()
    assert not (artifacts / "workspace-delta.json").exists()
    assert not (artifacts / "workspace-diff.patch").exists()
    assert not (artifacts / "workspace-changed.tar").exists()


def test_after_host_evidence_failure_with_remote_closure_continues(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = RemoteSnapshotActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)
    before = asyncio.run(
        workspace_snapshot.capture_before(target, workspace_snapshot.SnapshotPolicy())
    )
    original_open = workspace_snapshot.os.open

    def fail_new_after_publish(path: object, *args: object, **kwargs: object) -> int:
        if Path(path) == artifacts / ".workspace-after.json.tmp":
            raise PermissionError(13, "HOST_OS_ERROR", "/host/private")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(workspace_snapshot.os, "open", fail_new_after_publish)

    receipt = asyncio.run(workspace_snapshot.capture_after(target, before))

    assert receipt.status == "failed"
    assert receipt.failure is not None
    assert receipt.failure.stage == "host-evidence"
    assert receipt.failure.category == "evidence"
    assert (
        receipt.failure.subtype
        is SnapshotFailureSubtypeV1.HOST_EVIDENCE_MATERIALIZATION_FAILED
    )
    assert receipt.failure.stage_validated is True
    assert receipt.failure.termination_verified is True
    assert receipt.failure.cleanup_verified is True
    assert receipt.failure.zero_census_verified is True
    assert receipt.continuable is True
    raw = (artifacts / "workspace-receipt.json").read_bytes()
    assert b"HOST_OS_ERROR" not in raw
    assert b"/host/private" not in raw


def test_after_capture_clamps_every_attempt_to_one_absolute_cutoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = RemoteSnapshotActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)
    before = asyncio.run(
        workspace_snapshot.capture_before(target, workspace_snapshot.SnapshotPolicy())
    )
    monkeypatch.setattr(
        workspace_snapshot,
        "host_monotonic_ns",
        lambda: 100_000_000_000,
    )

    asyncio.run(
        workspace_snapshot.capture_after(
            target,
            before,
            hard_deadline_monotonic_ns=130_000_000_000,
        )
    )

    assert actor.preflight_timeouts[-1] == 5.0
    assert workspace_snapshot.POST_AGENT_SNAPSHOT_CLEANUP_RESERVE_SEC == (
        workspace_snapshot.SNAPSHOT_CANCEL_TERMINAL_RESERVE_SEC
        + workspace_snapshot.SNAPSHOT_REAP_RESERVE_SEC
        + workspace_snapshot.SNAPSHOT_STAGE_CLEANUP_RESERVE_SEC
        + workspace_snapshot.SNAPSHOT_RECEIPT_SCHEDULE_RESERVE_SEC
    )
    assert workspace_snapshot.POST_AGENT_SNAPSHOT_CLEANUP_RESERVE_SEC == 22.0
    assert actor.capture_timeouts[-1] == 8.0
    assert actor.capture_deadlines[-1] == 108_000_000_000
    assert actor.capture_hard_deadlines[-1] == 123_000_000_000
    deadline = workspace_snapshot._SnapshotCaptureDeadlineV1(130_000_000_000)
    assert deadline.recovery_monotonic_ns == 123_000_000_000
    assert deadline.cleanup_monotonic_ns == 128_000_000_000


def test_after_capture_recovery_preserves_cleanup_and_receipt_subcutoffs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [100_000_000_000]

    class ReserveActor(RemoteSnapshotActor):
        def __init__(self, root: Path) -> None:
            super().__init__(root)
            self.fail_after = False
            self.cleanup_timeouts: list[float] = []

        async def exec_snapshot(
            self,
            command: str,
            *,
            timeout_sec: float,
        ) -> SimpleNamespace:
            if self.fail_after and command.startswith("rm -rf -- "):
                self.cleanup_timeouts.append(timeout_sec)
                clock[0] = 128_000_000_000
            return await super().exec_snapshot(command, timeout_sec=timeout_sec)

        async def exec_snapshot_owned(
            self,
            command: str,
            *,
            stage: str,
            timeout_sec: float,
            capture_deadline_monotonic_ns: int | None = None,
            hard_deadline_monotonic_ns: int | None = None,
        ) -> SimpleNamespace:
            if self.fail_after:
                assert capture_deadline_monotonic_ns == 108_000_000_000
                assert hard_deadline_monotonic_ns == 123_000_000_000
                clock[0] = hard_deadline_monotonic_ns
                raise SnapshotTransportTimeout(
                    termination_verified=True,
                    census_verified=True,
                    survivor_count=0,
                    stage_validated=True,
                    timeout_origin=(
                        SnapshotTimeoutOriginV1.WAIT_TRANSPORT_TIMED_OUT_UNRECOVERED
                    ),
                )
            return await super().exec_snapshot_owned(
                command,
                stage=stage,
                timeout_sec=timeout_sec,
                capture_deadline_monotonic_ns=capture_deadline_monotonic_ns,
                hard_deadline_monotonic_ns=hard_deadline_monotonic_ns,
            )

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = ReserveActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)
    before = asyncio.run(
        workspace_snapshot.capture_before(target, workspace_snapshot.SnapshotPolicy())
    )
    actor.fail_after = True
    monkeypatch.setattr(
        workspace_snapshot,
        "host_monotonic_ns",
        lambda: clock[0],
    )

    receipt = asyncio.run(
        workspace_snapshot.capture_after(
            target,
            before,
            hard_deadline_monotonic_ns=130_000_000_000,
        )
    )

    assert receipt.status == "failed"
    assert actor.cleanup_timeouts == [5.0]
    assert clock[0] == 128_000_000_000
    assert 130_000_000_000 - clock[0] == 2_000_000_000
    assert (artifacts / "workspace-receipt.json").is_file()


def test_semantic_execution_timeout_is_continuable_but_never_retried(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [100_000_000_000]

    class OneFailureActor(RemoteSnapshotActor):
        def __init__(self, root: Path) -> None:
            super().__init__(root)
            self.fail_after = False

        async def exec_snapshot_owned(
            self,
            command: str,
            *,
            stage: str,
            timeout_sec: float,
        ) -> SimpleNamespace:
            if self.fail_after:
                clock[0] = 106_000_000_000
                raise SnapshotTransportTimeout(
                    termination_verified=True,
                    census_verified=True,
                    survivor_count=0,
                    stage_validated=True,
                    timeout_origin=(
                        SnapshotTimeoutOriginV1.SEMANTIC_EXECUTION_TIMED_OUT
                    ),
                )
            return await super().exec_snapshot_owned(
                command,
                stage=stage,
                timeout_sec=timeout_sec,
            )

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = OneFailureActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)
    before = asyncio.run(
        workspace_snapshot.capture_before(target, workspace_snapshot.SnapshotPolicy())
    )
    actor.fail_after = True
    monkeypatch.setattr(
        workspace_snapshot,
        "host_monotonic_ns",
        lambda: clock[0],
    )

    receipt = asyncio.run(
        workspace_snapshot.capture_after(
            target,
            before,
            hard_deadline_monotonic_ns=160_000_000_000,
        )
    )

    assert receipt.status == "failed"
    assert receipt.continuable is True
    persisted = _load(artifacts / "workspace-receipt.json")
    assert persisted["failure"]["attempt"] == 1
    assert actor.stage_count == 2


@pytest.mark.parametrize("phase", ["before", "after"])
def test_bound_wait_response_failure_survives_cleanup_as_v5_receipt(
    tmp_path: Path,
    phase: str,
) -> None:
    class BoundWaitResponseActor(RemoteSnapshotActor):
        fail_owned = False

        async def exec_snapshot_owned(
            self,
            command: str,
            *,
            stage: str,
            timeout_sec: float,
        ) -> SimpleNamespace:
            if self.fail_owned:
                raise SnapshotOperationFailure(
                    SnapshotFailureEvidenceV1(
                        subtype=SnapshotFailureSubtypeV1.WAIT_RESPONSE_INVALID,
                        timeout_origin=SnapshotTimeoutOriginV1.NOT_A_TIMEOUT,
                        stage_validated=True,
                        termination_verified=True,
                        zero_census_verified=True,
                        execution_binding_verified=True,
                        reason=SnapshotFailureReasonV1.OUTER_RETURN_CODE_NONZERO,
                    ),
                    return_code=92,
                )
            return await super().exec_snapshot_owned(
                command,
                stage=stage,
                timeout_sec=timeout_sec,
            )

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = BoundWaitResponseActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)
    if phase == "before":
        actor.fail_owned = True
        captured = asyncio.run(
            workspace_snapshot.capture_before(
                target,
                workspace_snapshot.SnapshotPolicy(),
            )
        )
        assert (
            captured.baseline_state
            is workspace_snapshot.WorkspaceBaselineStateV1.UNAVAILABLE
        )
    else:
        before = asyncio.run(
            workspace_snapshot.capture_before(
                target,
                workspace_snapshot.SnapshotPolicy(),
            )
        )
        actor.fail_owned = True
        captured = asyncio.run(workspace_snapshot.capture_after(target, before))
        assert (
            captured.baseline_state
            is workspace_snapshot.WorkspaceBaselineStateV1.AVAILABLE
        )

    assert captured.status == "failed"
    assert captured.continuable is True
    assert captured.failure is not None
    assert captured.failure.execution_binding_verified is True
    assert captured.failure.cleanup_verified is True
    assert captured.failure.return_code == 92
    persisted = workspace_snapshot.load_workspace_receipt(
        artifacts / "workspace-receipt.json"
    )
    assert persisted.schema_version == workspace_snapshot.FAILURE_RECEIPT_SCHEMA_V5
    assert persisted.failure == captured.failure
    assert len(actor.cleanup_calls) == 1 + (phase == "after")


def test_recovered_wait_transport_timeout_is_not_retried_as_transport_noise(
    tmp_path: Path,
) -> None:
    class RecoveredWaitTimeoutActor(RemoteSnapshotActor):
        def __init__(self, root: Path) -> None:
            super().__init__(root)
            self.failed = False

        async def exec_snapshot_owned(
            self,
            command: str,
            *,
            stage: str,
            timeout_sec: float,
            hard_deadline_monotonic_ns: int | None = None,
        ) -> SimpleNamespace:
            if not self.failed:
                self.failed = True
                raise SnapshotTransportTimeout(
                    termination_verified=True,
                    census_verified=True,
                    survivor_count=0,
                    stage_validated=True,
                    timeout_origin=(
                        SnapshotTimeoutOriginV1.WAIT_TRANSPORT_TIMED_OUT_RECOVERED
                    ),
                )
            return await super().exec_snapshot_owned(
                command,
                stage=stage,
                timeout_sec=timeout_sec,
                hard_deadline_monotonic_ns=hard_deadline_monotonic_ns,
            )

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = RecoveredWaitTimeoutActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)

    before = asyncio.run(
        workspace_snapshot.capture_before(target, workspace_snapshot.SnapshotPolicy())
    )

    assert before.status == "failed"
    assert before.continuable is True
    assert actor.capture_count == 0
    assert actor.stage_count == 1
    assert len(actor.cleanup_calls) == 1


def test_existing_receipt_mismatch_remains_immutable_and_fatal(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    artifacts = tmp_path / "artifacts"
    workspace.mkdir()
    artifacts.mkdir()
    actor = LocalSnapshotActor(workspace, artifacts)
    before = asyncio.run(
        workspace_snapshot.capture_before(actor, workspace_snapshot.SnapshotPolicy())
    )
    receipt_path = artifacts / "workspace-receipt.json"
    original = b"existing-immutable-evidence\n"
    receipt_path.write_bytes(original)
    actor.fail_phase = "after"

    with pytest.raises(
        workspace_snapshot.WorkspaceSnapshotError,
        match="^workspace_snapshot_existing_mismatch$",
    ):
        asyncio.run(workspace_snapshot.capture_after(actor, before))

    assert receipt_path.read_bytes() == original


def test_capture_is_pre_verifier_and_unchanged_inputs_are_byte_deterministic(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "answer.txt").write_text("answer\n")
    (workspace / "answer.txt").chmod(0o644)

    outputs: list[dict[str, bytes]] = []
    for index in range(2):
        artifacts = tmp_path / f"artifacts-{index}"
        artifacts.mkdir()
        actor = LocalSnapshotActor(workspace, artifacts)
        before = asyncio.run(
            workspace_snapshot.capture_before(
                actor, workspace_snapshot.SnapshotPolicy()
            )
        )
        (workspace / "answer.txt").write_text("agent answer\n")
        asyncio.run(workspace_snapshot.capture_after(actor, before))
        actor.capture_phases.append("verifier")
        assert actor.capture_phases == ["before", "after", "verifier"]
        outputs.append(
            {
                path.name: path.read_bytes()
                for path in sorted(artifacts.iterdir(), key=lambda row: row.name)
            }
        )
        (workspace / "answer.txt").write_text("answer\n")

    assert outputs[0] == outputs[1]
    assert {
        name: (len(payload), hashlib.sha256(payload).hexdigest())
        for name, payload in outputs[0].items()
    } == {
        "workspace-after.json": (
            286,
            "86b118e39a1aa8aafc8862d30288c18dfe50c5eb25d21847e6709967f0922d86",
        ),
        "workspace-before.json": (
            285,
            "1cc7f1bbcc147204a57eba768f06275d1f108ff8203ccd6784cede7ac915aed2",
        ),
        "workspace-changed.tar": (
            10_240,
            "ed2a5e3c7d92afe7c61803395a3401fc1222279261c3d756e90c6e6a83b41bc4",
        ),
        "workspace-delta.json": (
            172,
            "eaa73a6e5bde10d1fdf1df2a78e0cf6e0a1d94ca7b99787c6af7426fc99bcba5",
        ),
        "workspace-diff.patch": (
            68,
            "b887c1b525d37657147ce7c158a1e9e4032fd6650b9584271e5ccb556f8443c7",
        ),
        "workspace-receipt.json": (
            1_108,
            "b7a93c07983a04ce840d91126cb421f87a4b6f4a0d8bc2eb475d88a515d3ad2e",
        ),
    }
    with tarfile.open(
        fileobj=io.BytesIO(outputs[0]["workspace-changed.tar"]), mode="r:"
    ) as archive:
        member = archive.getmember("answer.txt")
        assert member.uid == member.gid == 0
        assert member.mtime == 0


def test_remote_transport_is_bounded_parsed_and_secret_aware(
    tmp_path: Path,
) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = RemoteSnapshotActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)

    before = asyncio.run(
        workspace_snapshot.capture_before(target, workspace_snapshot.SnapshotPolicy())
    )
    receipt = asyncio.run(workspace_snapshot.capture_after(target, before))

    assert receipt.status == "complete"
    assert actor.stage_count == 2
    assert actor.capture_count == 2
    assert len(actor.cleanup_calls) == 2
    assert actor.snapshot_phases == [
        "preflight",
        "capture",
        "cleanup",
        "preflight",
        "capture",
        "cleanup",
    ]
    assert actor.preflight_timeouts == [5.0, 5.0]
    assert actor.capture_timeouts == [120.0, 120.0]
    assert actor.stages == {}
    assert list(actor.root.iterdir()) == []
    delta = _load(artifacts / "workspace-delta.json")
    assert delta["modified"] == [{"path": "answer.txt"}]
    assert delta["created"] == [{"path": "vulnerable-secret.txt"}]
    assert delta["omitted"] == [
        {
            "path": "vulnerable-secret.txt",
            "reason": "sensitive_path",
            "sha256": __import__("hashlib").sha256(b"do-not-export").hexdigest(),
        }
    ]
    with tarfile.open(artifacts / "workspace-changed.tar", "r:") as archive:
        assert archive.getnames() == ["answer.txt"]


def test_cancelled_after_capture_still_publishes_failure_receipt(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        artifacts = tmp_path / "artifacts"
        artifacts.mkdir()
        actor = RemoteSnapshotActor(tmp_path / "remote")
        target = workspace_snapshot.SnapshotTarget(
            actor=actor,
            artifact_dir=artifacts,
        )
        before = await workspace_snapshot.capture_before(
            target,
            workspace_snapshot.SnapshotPolicy(),
        )
        actor.block_capture = True
        capture = asyncio.create_task(workspace_snapshot.capture_after(target, before))
        await actor.capture_started.wait()
        capture.cancel()
        with pytest.raises(asyncio.CancelledError):
            await capture
        receipt = _load(artifacts / "workspace-receipt.json")
        assert receipt["status"] == "failed"
        assert receipt["code"] == "workspace_after_capture_cancelled"
        assert receipt["failure"]["stage"] == "remote-exec"
        assert receipt["failure"]["category"] == "cancelled"
        assert receipt["failure"]["subtype"] == "wait_transport_failed"
        assert receipt["failure"]["timeout_origin"] == "not_a_timeout"
        assert receipt["failure"]["stage_validated"] is True
        assert receipt["failure"]["termination_verified"] is True
        assert receipt["failure"]["cleanup_verified"] is True
        assert receipt["failure"]["zero_census_verified"] is True
        assert actor.snapshot_phases[-3:] == [
            "preflight",
            "capture",
            "cleanup",
        ]
        assert actor.stages == {}
        assert list(actor.root.iterdir()) == []

    asyncio.run(scenario())


def test_host_materialization_checks_capture_cutoff_between_bounded_steps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = RemoteSnapshotActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)
    before = asyncio.run(
        workspace_snapshot.capture_before(target, workspace_snapshot.SnapshotPolicy())
    )
    clock = [100_000_000_000]
    original_tar = workspace_snapshot._tar

    def tar_then_expire(**kwargs: object) -> bytes:
        payload = original_tar(**kwargs)
        clock[0] = 111_000_000_000
        return payload

    monkeypatch.setattr(workspace_snapshot, "host_monotonic_ns", lambda: clock[0])
    monkeypatch.setattr(workspace_snapshot, "_tar", tar_then_expire)

    receipt = asyncio.run(
        workspace_snapshot.capture_after(
            target,
            before,
            hard_deadline_monotonic_ns=130_000_000_000,
        )
    )

    assert receipt.status == "failed"
    assert receipt.failure is not None
    assert (
        receipt.failure.subtype
        is SnapshotFailureSubtypeV1.HOST_EVIDENCE_MATERIALIZATION_FAILED
    )
    assert receipt.failure.stage == "host-evidence"
    assert receipt.continuable is True
    assert not (artifacts / "workspace-after.json").exists()


@pytest.mark.parametrize(
    "cleanup_failure",
    ["nonzero", "timeout", "exception"],
)
def test_cancelled_capture_cleanup_failure_dominates_and_remains_fatal(
    tmp_path: Path,
    cleanup_failure: str,
) -> None:
    class CancellationCleanupFailureActor(RemoteSnapshotActor):
        async def exec_snapshot(
            self,
            command: str,
            *,
            timeout_sec: float,
        ) -> SimpleNamespace:
            if command.startswith("rm -rf -- "):
                self.snapshot_phases.append("cleanup")
                self.cleanup_calls.append(command)
                if cleanup_failure == "nonzero":
                    return SimpleNamespace(
                        return_code=75,
                        stdout="",
                        stderr="secret cleanup detail",
                    )
                if cleanup_failure == "timeout":
                    raise TimeoutError("secret cleanup detail")
                raise RuntimeError("secret cleanup detail")
            return await super().exec_snapshot(command, timeout_sec=timeout_sec)

    async def scenario() -> None:
        artifacts = tmp_path / "artifacts"
        artifacts.mkdir()
        actor = CancellationCleanupFailureActor(tmp_path / "remote")
        actor.block_capture = True
        target = workspace_snapshot.SnapshotTarget(
            actor=actor,
            artifact_dir=artifacts,
        )
        capture = asyncio.create_task(
            workspace_snapshot.capture_before(
                target,
                workspace_snapshot.SnapshotPolicy(),
            )
        )
        await actor.capture_started.wait()
        capture.cancel()
        with pytest.raises(
            workspace_snapshot.WorkspaceSnapshotError,
            match="^workspace_before_capture_failed$",
        ) as raised:
            await capture
        assert isinstance(raised.value.__cause__, asyncio.CancelledError)
        assert raised.value.failure.stage == "cleanup"
        assert raised.value.failure.category == "internal"
        assert raised.value.failure.stage_validated is True
        assert raised.value.failure.cleanup_verified is False
        receipt = _load(artifacts / "workspace-receipt.json")
        assert receipt["status"] == "failed"
        assert receipt["code"] == "workspace_before_capture_failed"
        assert _failure_core(receipt) == {
            "stage": "cleanup",
            "category": "internal",
            "errno": None,
            "return_code": None,
            "attempt": 1,
        }
        assert actor.snapshot_phases == ["preflight", "capture", "cleanup"]
        assert len(actor.cleanup_calls) == 1
        assert len(actor.stages) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("cleanup_failure", ["nonzero", "timeout"])
def test_cancelled_after_capture_cleanup_failure_raises_fatal_with_cause(
    tmp_path: Path,
    cleanup_failure: str,
) -> None:
    class AfterCancellationCleanupFailureActor(RemoteSnapshotActor):
        def __init__(self, root: Path) -> None:
            super().__init__(root)
            self.fail_cleanup = False

        async def exec_snapshot(
            self,
            command: str,
            *,
            timeout_sec: float,
        ) -> SimpleNamespace:
            if command.startswith("rm -rf -- ") and self.fail_cleanup:
                self.snapshot_phases.append("cleanup")
                self.cleanup_calls.append(command)
                if cleanup_failure == "nonzero":
                    return SimpleNamespace(
                        return_code=75,
                        stdout="",
                        stderr="secret cleanup detail",
                    )
                raise TimeoutError("secret cleanup detail")
            return await super().exec_snapshot(command, timeout_sec=timeout_sec)

    async def scenario() -> None:
        artifacts = tmp_path / "artifacts"
        artifacts.mkdir()
        actor = AfterCancellationCleanupFailureActor(tmp_path / "remote")
        target = workspace_snapshot.SnapshotTarget(
            actor=actor,
            artifact_dir=artifacts,
        )
        before = await workspace_snapshot.capture_before(
            target,
            workspace_snapshot.SnapshotPolicy(),
        )
        actor.fail_cleanup = True
        actor.block_capture = True
        capture = asyncio.create_task(workspace_snapshot.capture_after(target, before))
        await actor.capture_started.wait()
        capture.cancel()
        try:
            await capture
        except workspace_snapshot.WorkspaceSnapshotError as error:
            raised = error
        else:
            returned = capture.result()
            pytest.fail(
                "returned_failed_receipt="
                f"{returned.status}/{returned.code};"
                f"stage_remaining={bool(actor.stages)}"
            )
        assert isinstance(raised.__cause__, asyncio.CancelledError)
        assert raised.code == "workspace_after_capture_failed"
        assert raised.failure.stage == "cleanup"
        assert raised.failure.category == "internal"
        assert raised.failure.stage_validated is True
        assert raised.failure.cleanup_verified is False
        receipt = _load(artifacts / "workspace-receipt.json")
        assert receipt["status"] == "failed"
        assert receipt["code"] == "workspace_after_capture_failed"
        assert _failure_core(receipt) == {
            "stage": "cleanup",
            "category": "internal",
            "errno": None,
            "return_code": None,
            "attempt": 1,
        }
        assert actor.snapshot_phases[-3:] == [
            "preflight",
            "capture",
            "cleanup",
        ]
        assert len(actor.cleanup_calls) == 2
        assert len(actor.stages) == 1
        assert sorted(path.name for path in artifacts.iterdir()) == [
            "workspace-before.json",
            "workspace-receipt.json",
        ]

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("stage", "category"),
    [
        ("target", "policy"),
        ("remote-exec", "timeout"),
        ("remote-command", "command"),
        ("stage-parse", "parse"),
        ("inventory-download", "connection"),
        ("archive-download", "os_error"),
        ("inventory-parse", "parse"),
        ("archive-parse", "parse"),
        ("cleanup", "transport"),
        ("publish", "publish"),
    ],
)
def test_before_failure_is_typed_and_sanitized_by_disposition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    category: str,
) -> None:
    workspace = tmp_path / "workspace"
    artifacts = tmp_path / "artifacts"
    workspace.mkdir()
    artifacts.mkdir()
    actor = LocalSnapshotActor(workspace, artifacts)
    secret = "xai-secret /tmp/private stderr=provider-command ENV_SECRET"

    async def fail_capture(
        _target: workspace_snapshot.SnapshotTarget,
        _policy: workspace_snapshot.SnapshotPolicy,
    ) -> object:
        raise workspace_snapshot.WorkspaceSnapshotError(
            secret,
            stage=stage,
            category=category,
            errno=110,
            attempt=2,
        )

    monkeypatch.setattr(workspace_snapshot, "_capture_inventory", fail_capture)

    continuable = (
        workspace_snapshot.workspace_failure_disposition(
            "workspace_before_capture_failed",
            stage,
            category,
        )
        == "diagnostic_failed_continue"
    )
    if continuable:
        before = asyncio.run(
            workspace_snapshot.capture_before(
                actor,
                workspace_snapshot.SnapshotPolicy(),
            )
        )
        assert before.status == "failed"
        assert before.failure is not None
        assert before.failure.stage == stage
        assert before.failure.category == category
    else:
        with pytest.raises(
            workspace_snapshot.WorkspaceSnapshotError,
            match="^workspace_before_capture_failed$",
        ) as caught:
            asyncio.run(
                workspace_snapshot.capture_before(
                    actor,
                    workspace_snapshot.SnapshotPolicy(),
                )
            )
        assert caught.value.failure.stage == stage
        formatted = "".join(
            traceback.format_exception(caught.type, caught.value, caught.tb)
        )
        assert str(caught.value) == "workspace_before_capture_failed"
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        for marker in (
            secret,
            "provider-command",
            "secret",
            "/tmp/private",
            "ENV_SECRET",
            "stderr=",
        ):
            assert marker not in formatted
    receipt_raw = (artifacts / "workspace-receipt.json").read_bytes()
    receipt = json.loads(receipt_raw)
    assert receipt["schema_version"] == "nano-workspace-receipt-v5"
    assert set(receipt) == {
        "schema_version",
        "status",
        "code",
        "policy",
        "truncated",
        "omitted_count",
        "artifacts",
        "failure",
        "baseline_state",
    }
    assert _failure_core(receipt) == {
        "stage": stage,
        "category": category,
        "errno": 110,
        "return_code": None,
        "attempt": 2,
    }
    assert secret.encode() not in receipt_raw
    assert b"/tmp/private" not in receipt_raw
    assert b"ENV_SECRET" not in receipt_raw
    assert not (artifacts / "workspace-before.json").exists()


@pytest.mark.parametrize("failure_mode", ["existing-read", "new-write"])
def test_failure_receipt_publish_traceback_suppresses_host_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_mode: str,
) -> None:
    workspace = tmp_path / "workspace"
    artifacts = tmp_path / "artifacts"
    workspace.mkdir()
    artifacts.mkdir()
    actor = LocalSnapshotActor(workspace, artifacts)
    receipt_path = artifacts / "workspace-receipt.json"
    host_path = "/host/private/artifacts/ENV_HOST_SECRET"
    capture_marker = "RAW_CAPTURE_COMMAND stderr=secret /workspace/private"

    async def fail_capture(
        _target: workspace_snapshot.SnapshotTarget,
        _policy: workspace_snapshot.SnapshotPolicy,
    ) -> object:
        raise RuntimeError(capture_marker)

    monkeypatch.setattr(workspace_snapshot, "_capture_inventory", fail_capture)
    if failure_mode == "existing-read":
        receipt_path.write_bytes(b"existing")
        original_read_bytes = Path.read_bytes

        def fail_receipt_read(path: Path) -> bytes:
            if path == receipt_path:
                raise PermissionError(13, "HOST_OS_ERROR", host_path)
            return original_read_bytes(path)

        monkeypatch.setattr(Path, "read_bytes", fail_receipt_read)
    else:
        original_open = workspace_snapshot.os.open

        def fail_receipt_open(path: object, *args: object) -> int:
            if Path(path) == artifacts / ".workspace-receipt.json.tmp":
                raise PermissionError(13, "HOST_OS_ERROR", host_path)
            return original_open(path, *args)

        monkeypatch.setattr(workspace_snapshot.os, "open", fail_receipt_open)

    with pytest.raises(
        workspace_snapshot.WorkspaceSnapshotError,
        match="^workspace_snapshot_publish_failed$",
    ) as caught:
        asyncio.run(
            workspace_snapshot.capture_before(
                actor,
                workspace_snapshot.SnapshotPolicy(),
            )
        )

    formatted = "".join(
        traceback.format_exception(caught.type, caught.value, caught.tb)
    )
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__
    for marker in (
        capture_marker,
        "RAW_CAPTURE_COMMAND",
        "stderr=secret",
        "/workspace/private",
        "HOST_OS_ERROR",
        host_path,
        "ENV_HOST_SECRET",
    ):
        assert marker not in formatted


def test_remote_semantic_exec_timeout_does_not_retry(tmp_path: Path) -> None:
    class TransientExecActor(RemoteSnapshotActor):
        def __init__(self, root: Path) -> None:
            super().__init__(root)
            self.primary_calls = 0

        async def exec_snapshot(
            self,
            command: str,
            *,
            timeout_sec: float,
        ) -> SimpleNamespace:
            if "inventory=" in command:
                self.primary_calls += 1
                if self.primary_calls == 1:
                    self.snapshot_phases.append("capture")
                    self.capture_timeouts.append(timeout_sec)
                    raise TimeoutError("secret transport detail")
            return await super().exec_snapshot(command, timeout_sec=timeout_sec)

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = TransientExecActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)

    before = asyncio.run(
        workspace_snapshot.capture_before(target, workspace_snapshot.SnapshotPolicy())
    )

    assert before.status == "failed"
    assert before.continuable is True
    assert actor.stage_count == 1
    assert actor.primary_calls == 1
    assert actor.capture_count == 0
    assert len(actor.cleanup_calls) == 1
    assert actor.snapshot_phases == [
        "preflight",
        "capture",
        "cleanup",
    ]


def test_remote_preflight_without_stage_proof_is_fatal(tmp_path: Path) -> None:
    class PreflightFailureActor(RemoteSnapshotActor):
        def __init__(self, root: Path) -> None:
            super().__init__(root)
            self.preflight_calls = 0

        async def exec_snapshot(
            self,
            command: str,
            *,
            timeout_sec: float,
        ) -> SimpleNamespace:
            if command.startswith("rm -rf -- "):
                raise AssertionError("no validated stage exists to clean")
            if "mktemp -d " in command and "inventory=" not in command:
                self.preflight_calls += 1
                raise TimeoutError("secret transport detail")
            raise AssertionError("capture must not run without validated stage")

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = PreflightFailureActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)

    with pytest.raises(
        workspace_snapshot.WorkspaceSnapshotError,
        match="^workspace_before_capture_failed$",
    ):
        asyncio.run(
            workspace_snapshot.capture_before(
                target,
                workspace_snapshot.SnapshotPolicy(),
            )
        )

    assert actor.preflight_calls == 1
    assert actor.capture_count == 0
    assert actor.cleanup_calls == []
    receipt = _load(artifacts / "workspace-receipt.json")
    assert receipt["failure"]["stage"] == "remote-exec"
    assert receipt["failure"]["category"] == "timeout"
    assert receipt["failure"]["attempt"] == 1


def test_remote_preflight_nonzero_does_not_authorize_stage_cleanup(
    tmp_path: Path,
) -> None:
    class NonzeroPreflightActor(RemoteSnapshotActor):
        def __init__(self, root: Path) -> None:
            super().__init__(root)
            self.preflight_calls = 0

        async def exec_snapshot(
            self,
            command: str,
            *,
            timeout_sec: float,
        ) -> SimpleNamespace:
            if command.startswith("rm -rf -- "):
                raise AssertionError("nonzero preflight did not establish ownership")
            if "mktemp -d " in command and "inventory=" not in command:
                self.preflight_calls += 1
                return SimpleNamespace(
                    return_code=71,
                    stdout=(
                        "/tmp/nano-workspace-snapshot-v1.untrusted\n"
                        "xai-preflight-stdout-secret\n"
                    ),
                    stderr="xai-preflight-stderr-secret",
                )
            raise AssertionError("capture must not run after nonzero preflight")

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = NonzeroPreflightActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)

    with pytest.raises(
        workspace_snapshot.WorkspaceSnapshotError,
        match="^workspace_before_capture_failed$",
    ) as raised:
        asyncio.run(
            workspace_snapshot.capture_before(
                target,
                workspace_snapshot.SnapshotPolicy(),
            )
        )

    assert actor.preflight_calls == 1
    assert actor.capture_count == 0
    assert actor.cleanup_calls == []
    receipt = _load(artifacts / "workspace-receipt.json")
    assert _failure_core(receipt) == {
        "stage": "remote-exec",
        "category": "command",
        "errno": None,
        "return_code": 71,
        "attempt": 1,
    }
    assert raised.value.failure.stage_validated is False
    assert raised.value.failure.cleanup_verified is False
    receipt_raw = (artifacts / "workspace-receipt.json").read_bytes()
    assert b"preflight" not in receipt_raw
    assert b"untrusted" not in receipt_raw


@pytest.mark.parametrize("stdout", ["", "/tmp/not-a-snapshot-stage\n"])
def test_remote_preflight_invalid_stage_is_fatal_without_cleanup(
    tmp_path: Path,
    stdout: str,
) -> None:
    class InvalidStageActor(RemoteSnapshotActor):
        def __init__(self, root: Path) -> None:
            super().__init__(root)
            self.preflight_calls = 0

        async def exec_snapshot(
            self,
            command: str,
            *,
            timeout_sec: float,
        ) -> SimpleNamespace:
            if command.startswith("rm -rf -- "):
                raise AssertionError("invalid stage is not cleanup authority")
            if "mktemp -d " in command and "inventory=" not in command:
                self.preflight_calls += 1
                return SimpleNamespace(
                    return_code=0,
                    stdout=stdout,
                    stderr="secret",
                )
            raise AssertionError("capture must not run after invalid stage")

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = InvalidStageActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)

    with pytest.raises(
        workspace_snapshot.WorkspaceSnapshotError,
        match="^workspace_before_capture_failed$",
    ):
        asyncio.run(
            workspace_snapshot.capture_before(
                target,
                workspace_snapshot.SnapshotPolicy(),
            )
        )

    assert actor.preflight_calls == 1
    assert actor.capture_count == 0
    assert actor.cleanup_calls == []
    receipt = _load(artifacts / "workspace-receipt.json")
    assert _failure_core(receipt) == {
        "stage": "stage-parse",
        "category": "parse",
        "errno": None,
        "return_code": None,
        "attempt": 1,
    }


def test_stage_cleanup_without_execution_proof_is_fatal_without_retry_or_delete(
    tmp_path: Path,
) -> None:
    class MainExecFailureActor(RemoteSnapshotActor):
        exec_snapshot_owned = None

        def __init__(self, root: Path) -> None:
            super().__init__(root)
            self.primary_calls = 0

        async def exec_snapshot(
            self,
            command: str,
            *,
            timeout_sec: float,
        ) -> SimpleNamespace:
            if "inventory=" in command:
                self.snapshot_phases.append("capture")
                self.capture_timeouts.append(timeout_sec)
                self.primary_calls += 1
                raise TimeoutError("secret transport detail")
            return await super().exec_snapshot(command, timeout_sec=timeout_sec)

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = MainExecFailureActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)

    with pytest.raises(
        workspace_snapshot.WorkspaceSnapshotError,
        match="^workspace_before_capture_failed$",
    ) as raised:
        asyncio.run(
            workspace_snapshot.capture_before(
                target,
                workspace_snapshot.SnapshotPolicy(),
            )
        )

    assert raised.value.failure.stage == "remote-exec"
    assert raised.value.failure.category == "internal"
    assert raised.value.failure.stage_validated is True
    assert raised.value.failure.termination_verified is False
    assert raised.value.failure.cleanup_verified is False
    assert actor.stage_count == 1
    assert actor.primary_calls == 1
    assert actor.cleanup_calls == []
    assert actor.snapshot_phases == ["preflight", "capture"]
    assert len(actor.stages) == 1
    assert len(list(actor.root.iterdir())) == 1
    receipt = _load(artifacts / "workspace-receipt.json")
    assert _failure_core(receipt) == {
        "stage": "remote-exec",
        "category": "internal",
        "errno": None,
        "return_code": None,
        "attempt": 1,
    }
    assert sorted(path.name for path in artifacts.iterdir()) == [
        "workspace-receipt.json"
    ]


@pytest.mark.parametrize("failure_mode", ["exception", "malformed"])
def test_validated_stage_unknown_remote_exec_failure_is_fatal(
    tmp_path: Path,
    failure_mode: str,
) -> None:
    class UnknownMainFailureActor(RemoteSnapshotActor):
        def __init__(self, root: Path) -> None:
            super().__init__(root)
            self.primary_calls = 0

        async def exec_snapshot(
            self,
            command: str,
            *,
            timeout_sec: float,
        ) -> SimpleNamespace:
            if "inventory=" in command:
                self.snapshot_phases.append("capture")
                self.capture_timeouts.append(timeout_sec)
                self.primary_calls += 1
                if failure_mode == "exception":
                    raise RuntimeError("xai-unknown-exception-secret")
                return SimpleNamespace(
                    stdout="xai-malformed-stdout-secret",
                    stderr="xai-malformed-stderr-secret",
                )
            return await super().exec_snapshot(command, timeout_sec=timeout_sec)

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = UnknownMainFailureActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)

    with pytest.raises(
        workspace_snapshot.WorkspaceSnapshotError,
        match="^workspace_before_capture_failed$",
    ) as raised:
        asyncio.run(
            workspace_snapshot.capture_before(
                target,
                workspace_snapshot.SnapshotPolicy(),
            )
        )

    assert raised.value.failure.stage == "remote-exec"
    assert raised.value.failure.category == "internal"
    assert raised.value.failure.stage_validated is True
    assert raised.value.failure.cleanup_verified is True
    assert actor.stage_count == 1
    assert actor.primary_calls == 1
    assert len(actor.cleanup_calls) == 1
    assert actor.snapshot_phases == ["preflight", "capture", "cleanup"]
    assert actor.stages == {}
    assert list(actor.root.iterdir()) == []
    receipt_raw = (artifacts / "workspace-receipt.json").read_bytes()
    receipt = json.loads(receipt_raw)
    assert _failure_core(receipt) == {
        "stage": "remote-exec",
        "category": "internal",
        "errno": None,
        "return_code": None,
        "attempt": 1,
    }
    assert b"xai-" not in receipt_raw
    assert sorted(path.name for path in artifacts.iterdir()) == [
        "workspace-receipt.json"
    ]


def test_validated_stage_remote_exec_cleanup_failure_dominates_primary(
    tmp_path: Path,
) -> None:
    class MainAndCleanupFailureActor(RemoteSnapshotActor):
        async def exec_snapshot(
            self,
            command: str,
            *,
            timeout_sec: float,
        ) -> SimpleNamespace:
            if command.startswith("rm -rf -- "):
                self.snapshot_phases.append("cleanup")
                self.cleanup_calls.append(command)
                return SimpleNamespace(return_code=75, stdout="", stderr="secret")
            if "inventory=" in command:
                self.snapshot_phases.append("capture")
                self.capture_timeouts.append(timeout_sec)
                raise TimeoutError("secret transport detail")
            return await super().exec_snapshot(command, timeout_sec=timeout_sec)

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = MainAndCleanupFailureActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)

    with pytest.raises(
        workspace_snapshot.WorkspaceSnapshotError,
        match="^workspace_before_capture_failed$",
    ):
        asyncio.run(
            workspace_snapshot.capture_before(
                target,
                workspace_snapshot.SnapshotPolicy(),
            )
        )

    receipt = _load(artifacts / "workspace-receipt.json")
    assert _failure_core(receipt) == {
        "stage": "cleanup",
        "category": "internal",
        "errno": None,
        "return_code": None,
        "attempt": 1,
    }
    assert actor.stage_count == 1
    assert len(actor.cleanup_calls) == 1
    assert actor.snapshot_phases == ["preflight", "capture", "cleanup"]


@pytest.mark.parametrize("cleanup_error", [TimeoutError, RuntimeError])
def test_validated_stage_remote_exec_cleanup_exception_is_fatal(
    tmp_path: Path,
    cleanup_error: type[Exception],
) -> None:
    class MainAndCleanupExceptionActor(RemoteSnapshotActor):
        async def exec_snapshot(
            self,
            command: str,
            *,
            timeout_sec: float,
        ) -> SimpleNamespace:
            if command.startswith("rm -rf -- "):
                self.snapshot_phases.append("cleanup")
                self.cleanup_calls.append(command)
                raise cleanup_error("secret cleanup detail")
            if "inventory=" in command:
                self.snapshot_phases.append("capture")
                self.capture_timeouts.append(timeout_sec)
                raise TimeoutError("secret transport detail")
            return await super().exec_snapshot(command, timeout_sec=timeout_sec)

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = MainAndCleanupExceptionActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)

    with pytest.raises(
        workspace_snapshot.WorkspaceSnapshotError,
        match="^workspace_before_capture_failed$",
    ):
        asyncio.run(
            workspace_snapshot.capture_before(
                target,
                workspace_snapshot.SnapshotPolicy(),
            )
        )

    receipt = _load(artifacts / "workspace-receipt.json")
    assert _failure_core(receipt) == {
        "stage": "cleanup",
        "category": "internal",
        "errno": None,
        "return_code": None,
        "attempt": 1,
    }
    assert actor.stage_count == 1
    assert len(actor.cleanup_calls) == 1
    assert actor.snapshot_phases == ["preflight", "capture", "cleanup"]


def test_remote_snapshot_exec_uses_wave_a_120_second_budget(tmp_path: Path) -> None:
    class BudgetActor(RemoteSnapshotActor):
        def __init__(self, root: Path) -> None:
            super().__init__(root)
            self.observed_preflight_timeouts: list[float] = []
            self.observed_capture_timeouts: list[float] = []

        async def exec_snapshot(
            self,
            command: str,
            *,
            timeout_sec: float,
        ) -> SimpleNamespace:
            if "mktemp -d " in command and "inventory=" not in command:
                self.observed_preflight_timeouts.append(timeout_sec)
            elif "inventory=" in command:
                self.observed_capture_timeouts.append(timeout_sec)
            return await super().exec_snapshot(command, timeout_sec=timeout_sec)

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = BudgetActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)

    asyncio.run(
        workspace_snapshot.capture_before(
            target,
            workspace_snapshot.SnapshotPolicy(),
        )
    )

    assert actor.observed_preflight_timeouts == [5.0]
    assert actor.observed_capture_timeouts == [120.0]


@pytest.mark.parametrize(
    ("failed_name", "expected_downloads"),
    [
        ("inventory.tsv", {"inventory.tsv": 2, "safe.tar": 1}),
        ("safe.tar", {"inventory.tsv": 2, "safe.tar": 2}),
    ],
)
def test_remote_transient_download_retries_capture_exactly_once(
    tmp_path: Path,
    failed_name: str,
    expected_downloads: dict[str, int],
) -> None:
    class TransientDownloadActor(RemoteSnapshotActor):
        def __init__(self, root: Path) -> None:
            super().__init__(root)
            self.downloads = {"inventory.tsv": 0, "safe.tar": 0}

        async def download_snapshot(
            self,
            source_path: str,
            target_path: Path | str,
        ) -> None:
            name = source_path.rsplit("/", 1)[1]
            self.downloads[name] += 1
            if name == failed_name and self.downloads[name] == 1:
                raise ConnectionError("secret download transport text")
            await super().download_snapshot(source_path, target_path)

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = TransientDownloadActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)

    before = asyncio.run(
        workspace_snapshot.capture_before(target, workspace_snapshot.SnapshotPolicy())
    )

    assert before.status == "complete"
    assert actor.capture_count == 2
    assert len(actor.cleanup_calls) == 2
    assert actor.downloads == expected_downloads


def test_remote_transient_owned_wait_failure_retries_exactly_once(
    tmp_path: Path,
) -> None:
    class TransientOwnedWaitActor(RemoteSnapshotActor):
        def __init__(self, root: Path) -> None:
            super().__init__(root)
            self.failed = False

        async def exec_snapshot_owned(
            self,
            command: str,
            *,
            stage: str,
            timeout_sec: float,
            hard_deadline_monotonic_ns: int | None = None,
        ) -> SimpleNamespace:
            if not self.failed:
                self.failed = True
                failure = SnapshotOperationFailure(
                    SnapshotFailureEvidenceV1(
                        subtype=SnapshotFailureSubtypeV1.WAIT_TRANSPORT_FAILED,
                        timeout_origin=SnapshotTimeoutOriginV1.NOT_A_TIMEOUT,
                        stage_validated=True,
                        termination_verified=True,
                        cleanup_verified=False,
                        zero_census_verified=True,
                    )
                )
                raise failure from ConnectionError("secret wait transport")
            return await super().exec_snapshot_owned(
                command,
                stage=stage,
                timeout_sec=timeout_sec,
                hard_deadline_monotonic_ns=hard_deadline_monotonic_ns,
            )

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = TransientOwnedWaitActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)

    before = asyncio.run(
        workspace_snapshot.capture_before(target, workspace_snapshot.SnapshotPolicy())
    )

    assert before.status == "complete"
    assert actor.capture_count == 1
    assert actor.stage_count == 2
    assert len(actor.cleanup_calls) == 2


def test_remote_retry_rejects_mismatched_stage_and_subtype(
    tmp_path: Path,
) -> None:
    class MismatchedOwnedFailureActor(RemoteSnapshotActor):
        async def exec_snapshot_owned(
            self,
            command: str,
            *,
            stage: str,
            timeout_sec: float,
            hard_deadline_monotonic_ns: int | None = None,
        ) -> SimpleNamespace:
            failure = SnapshotOperationFailure(
                SnapshotFailureEvidenceV1(
                    subtype=SnapshotFailureSubtypeV1.OUTPUT_DOWNLOAD_FAILED,
                    timeout_origin=SnapshotTimeoutOriginV1.NOT_A_TIMEOUT,
                    stage_validated=True,
                    termination_verified=True,
                    cleanup_verified=False,
                    zero_census_verified=True,
                )
            )
            raise failure from ConnectionError("secret mismatched transport")

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = MismatchedOwnedFailureActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)

    with pytest.raises(workspace_snapshot.WorkspaceSnapshotError):
        asyncio.run(
            workspace_snapshot.capture_before(
                target,
                workspace_snapshot.SnapshotPolicy(),
            )
        )

    receipt = _load(artifacts / "workspace-receipt.json")
    assert receipt["failure"]["attempt"] == 1
    assert receipt["failure"]["stage"] == "remote-exec"
    assert receipt["failure"]["subtype"] == "output_download_failed"
    assert actor.stage_count == 1
    assert len(actor.cleanup_calls) == 1


def test_remote_inventory_download_failure_is_fatal_before(
    tmp_path: Path,
) -> None:
    class FailedInventoryDownloadActor(RemoteSnapshotActor):
        async def download_snapshot(
            self,
            source_path: str,
            target_path: Path | str,
        ) -> None:
            if source_path.endswith("/inventory.tsv"):
                raise ConnectionError("secret download transport text")
            await super().download_snapshot(source_path, target_path)

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = FailedInventoryDownloadActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)

    with pytest.raises(
        workspace_snapshot.WorkspaceSnapshotError,
        match="^workspace_before_capture_failed$",
    ):
        asyncio.run(
            workspace_snapshot.capture_before(
                target,
                workspace_snapshot.SnapshotPolicy(),
            )
        )

    assert actor.capture_count == 2
    assert len(actor.cleanup_calls) == 2
    receipt = _load(artifacts / "workspace-receipt.json")
    assert receipt["failure"]["stage"] == "inventory-download"
    assert receipt["failure"]["category"] == "connection"
    assert receipt["failure"]["subtype"] == "output_download_failed"
    assert receipt["failure"]["attempt"] == 2
    assert sorted(path.name for path in artifacts.iterdir()) == [
        "workspace-receipt.json"
    ]


def test_remote_after_download_failure_remains_fatal(
    tmp_path: Path,
) -> None:
    class FailedAfterDownloadActor(RemoteSnapshotActor):
        async def download_snapshot(
            self,
            source_path: str,
            target_path: Path | str,
        ) -> None:
            if self.capture_count > 1 and source_path.endswith("/inventory.tsv"):
                raise ConnectionError("secret download transport text")
            await super().download_snapshot(source_path, target_path)

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = FailedAfterDownloadActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)
    before = asyncio.run(
        workspace_snapshot.capture_before(target, workspace_snapshot.SnapshotPolicy())
    )

    receipt = asyncio.run(workspace_snapshot.capture_after(target, before))

    assert receipt.status == "failed"
    assert receipt.code == "workspace_after_capture_failed"
    assert receipt.failure is not None
    assert receipt.failure.stage == "inventory-download"
    assert receipt.failure.category == "connection"
    assert receipt.failure.stage_validated is True
    assert receipt.failure.cleanup_verified is True
    assert receipt.failure.subtype is SnapshotFailureSubtypeV1.OUTPUT_DOWNLOAD_FAILED
    assert receipt.failure.zero_census_verified is True
    assert receipt.continuable is False
    assert actor.capture_count == 3
    assert len(actor.cleanup_calls) == 3
    assert sorted(path.name for path in artifacts.iterdir()) == [
        "workspace-before.json",
        "workspace-receipt.json",
    ]


def test_remote_inventory_parse_failure_remains_fatal_and_publishes_no_snapshot(
    tmp_path: Path,
) -> None:
    class InvalidInventoryActor(RemoteSnapshotActor):
        async def download_snapshot(
            self,
            source_path: str,
            target_path: Path | str,
        ) -> None:
            await super().download_snapshot(source_path, target_path)
            if source_path.endswith("/inventory.tsv"):
                Path(target_path).write_bytes(b"not-an-inventory\n")

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = InvalidInventoryActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)

    with pytest.raises(
        workspace_snapshot.WorkspaceSnapshotError,
        match="^workspace_before_capture_failed$",
    ):
        asyncio.run(
            workspace_snapshot.capture_before(
                target,
                workspace_snapshot.SnapshotPolicy(),
            )
        )

    receipt = _load(artifacts / "workspace-receipt.json")
    assert receipt["failure"]["stage"] == "inventory-parse"
    assert receipt["failure"]["category"] == "parse"
    assert actor.capture_count == 1
    assert len(actor.cleanup_calls) == 1
    assert sorted(path.name for path in artifacts.iterdir()) == [
        "workspace-receipt.json"
    ]


def test_after_inventory_parse_failure_is_diagnostic_and_verifier_safe(
    tmp_path: Path,
) -> None:
    class InvalidAfterInventoryActor(RemoteSnapshotActor):
        corrupt_after = False

        async def download_snapshot(
            self,
            source_path: str,
            target_path: Path | str,
        ) -> None:
            await super().download_snapshot(source_path, target_path)
            if self.corrupt_after and source_path.endswith("/inventory.tsv"):
                Path(target_path).write_bytes(b"not-an-inventory\n")

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = InvalidAfterInventoryActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)
    before = asyncio.run(
        workspace_snapshot.capture_before(
            target,
            workspace_snapshot.SnapshotPolicy(),
        )
    )
    actor.corrupt_after = True

    receipt = asyncio.run(workspace_snapshot.capture_after(target, before))

    assert receipt.status == "failed"
    assert receipt.code == "workspace_after_capture_failed"
    assert receipt.failure is not None
    assert receipt.failure.stage == "inventory-parse"
    assert receipt.failure.category == "parse"
    assert (
        receipt.failure.subtype is SnapshotFailureSubtypeV1.HOST_EVIDENCE_PARSE_FAILED
    )
    assert receipt.failure.termination_verified is True
    assert receipt.failure.cleanup_verified is True
    assert receipt.failure.zero_census_verified is True
    assert receipt.continuable is True
    assert actor.capture_count == 2
    assert len(actor.cleanup_calls) == 2


def test_remote_size_policy_failure_is_not_retried(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = RemoteSnapshotActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)
    policy = workspace_snapshot.SnapshotPolicy(
        max_file_bytes=1,
        max_total_bytes=1,
    )

    with pytest.raises(workspace_snapshot.WorkspaceSnapshotError):
        asyncio.run(workspace_snapshot.capture_before(target, policy))

    assert actor.capture_count == 1
    assert len(actor.cleanup_calls) == 1
    receipt = _load(artifacts / "workspace-receipt.json")
    assert receipt["failure"]["stage"] == "archive-parse"
    assert receipt["failure"]["attempt"] == 1
    assert actor.stages == {}
    assert list(actor.root.iterdir()) == []
    assert sorted(path.name for path in artifacts.iterdir()) == [
        "workspace-receipt.json"
    ]


def test_remote_primary_plus_cleanup_failure_is_cleanup_unverified_fatal(
    tmp_path: Path,
) -> None:
    class PrimaryAndCleanupFailureActor(RemoteSnapshotActor):
        async def exec_snapshot(
            self,
            command: str,
            *,
            timeout_sec: float,
        ) -> SimpleNamespace:
            if command.startswith("rm -rf -- "):
                self.cleanup_calls.append(command)
                return SimpleNamespace(return_code=75, stdout="", stderr="secret")
            if "mktemp -d " in command and "inventory=" not in command:
                return await super().exec_snapshot(
                    command,
                    timeout_sec=timeout_sec,
                )
            result = await super().exec_snapshot(command, timeout_sec=timeout_sec)
            return SimpleNamespace(
                return_code=74,
                stdout=result.stdout,
                stderr="secret primary stderr",
            )

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = PrimaryAndCleanupFailureActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)

    with pytest.raises(workspace_snapshot.WorkspaceSnapshotError):
        asyncio.run(
            workspace_snapshot.capture_before(
                target,
                workspace_snapshot.SnapshotPolicy(),
            )
        )

    receipt_raw = (artifacts / "workspace-receipt.json").read_bytes()
    receipt = json.loads(receipt_raw)
    assert _failure_core(receipt) == {
        "stage": "cleanup",
        "category": "internal",
        "errno": None,
        "return_code": None,
        "attempt": 1,
    }
    assert b"stderr" not in receipt_raw
    assert actor.capture_count == 1
    assert len(actor.cleanup_calls) == 1


@pytest.mark.parametrize("cleanup_phase", ["before", "after"])
def test_remote_snapshot_cleanup_uncertainty_retains_partial_evidence(
    tmp_path: Path,
    cleanup_phase: str,
) -> None:
    class CleanupFailureActor(RemoteSnapshotActor):
        fail_cleanup = False

        async def exec_snapshot(
            self,
            command: str,
            *,
            timeout_sec: float,
        ) -> SimpleNamespace:
            if command.startswith("rm -rf -- ") and self.fail_cleanup:
                completed = await super().exec_snapshot(
                    command,
                    timeout_sec=timeout_sec,
                )
                assert completed.return_code == 0
                return SimpleNamespace(return_code=75, stdout="", stderr="secret")
            return await super().exec_snapshot(command, timeout_sec=timeout_sec)

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = CleanupFailureActor(tmp_path / "remote")
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)
    actor.fail_cleanup = cleanup_phase == "before"
    before = asyncio.run(
        workspace_snapshot.capture_before(
            target,
            workspace_snapshot.SnapshotPolicy(),
        )
    )
    actor.fail_cleanup = cleanup_phase == "after"

    receipt = asyncio.run(workspace_snapshot.capture_after(target, before))

    delta = _load(artifacts / "workspace-delta.json")
    assert "stage_cleanup_unverified" in {row["reason"] for row in delta["omitted"]}
    assert receipt.status == "complete"
    assert receipt.truncated is True
    assert receipt.omitted_count == len(delta["omitted"])
    assert actor.capture_count == 2
    assert len(actor.cleanup_calls) == 2


def test_fresh_before_publish_io_failure_is_fatal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    artifacts = tmp_path / "artifacts"
    workspace.mkdir()
    artifacts.mkdir()
    actor = LocalSnapshotActor(workspace, artifacts)
    original_open = workspace_snapshot.os.open

    def fail_new_before_publish(path: object, *args: object) -> int:
        if Path(path) == artifacts / ".workspace-before.json.tmp":
            raise PermissionError(13, "HOST_OS_ERROR", "/host/private")
        return original_open(path, *args)

    monkeypatch.setattr(workspace_snapshot.os, "open", fail_new_before_publish)

    with pytest.raises(
        workspace_snapshot.WorkspaceSnapshotError,
        match="^workspace_before_capture_failed$",
    ):
        asyncio.run(
            workspace_snapshot.capture_before(
                actor,
                workspace_snapshot.SnapshotPolicy(),
            )
        )

    assert not (artifacts / "workspace-before.json").exists()
    receipt = _load(artifacts / "workspace-receipt.json")
    assert receipt["failure"]["stage"] == "publish"
    assert receipt["failure"]["category"] == "os_error"
    assert receipt["failure"]["subtype"] == "unknown_internal"


def test_receipt_v5_round_trip_is_canonical_and_duplicate_key_closed(
    tmp_path: Path,
) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    target = workspace_snapshot.SnapshotTarget(actor=object(), artifact_dir=artifacts)
    failure = workspace_snapshot.WorkspaceSnapshotError(
        "workspace_before_capture_failed",
        stage="remote-exec",
        category="internal",
        return_code=7,
        subtype=SnapshotFailureSubtypeV1.WAIT_RESPONSE_INVALID,
        timeout_origin=SnapshotTimeoutOriginV1.NOT_A_TIMEOUT,
        stage_validated=True,
        termination_verified=True,
        cleanup_verified=True,
        zero_census_verified=True,
        execution_binding_verified=True,
        reason=SnapshotFailureReasonV1.OUTER_RETURN_CODE_NONZERO,
        observed_byte_length=4,
        observed_sha256="a" * 64,
    )

    persisted = workspace_snapshot._failure_receipt(
        target,
        workspace_snapshot.SnapshotPolicy(),
        failure.code,
        failure,
    )
    payload = (artifacts / "workspace-receipt.json").read_bytes()

    assert payload == workspace_snapshot.canonical_json(json.loads(payload))
    assert workspace_snapshot.parse_workspace_receipt_bytes(payload) == persisted
    assert persisted.schema_version == workspace_snapshot.FAILURE_RECEIPT_SCHEMA_V5
    assert persisted.failure is not None
    assert persisted.failure.execution_binding_verified is True
    assert persisted.continuable is True
    assert (
        persisted.baseline_state
        is workspace_snapshot.WorkspaceBaselineStateV1.UNAVAILABLE
    )
    duplicate = payload.replace(
        b'{"artifacts":',
        b'{"artifacts":{},"artifacts":',
        1,
    )
    with pytest.raises(
        workspace_snapshot.WorkspaceSnapshotError,
        match="^workspace_receipt_invalid$",
    ):
        workspace_snapshot.parse_workspace_receipt_bytes(duplicate)

    oversized = json.loads(payload)
    oversized["failure"]["observed_byte_length"] = (
        workspace_snapshot.SNAPSHOT_OUTPUT_CAP_BYTES + 1
    )
    with pytest.raises(
        workspace_snapshot.WorkspaceSnapshotError,
        match="^workspace_receipt_invalid$",
    ):
        workspace_snapshot.parse_workspace_receipt_bytes(
            workspace_snapshot.canonical_json(oversized)
        )

    sanitized = workspace_snapshot.WorkspaceSnapshotError(
        "workspace_before_capture_failed",
        observed_byte_length=workspace_snapshot.SNAPSHOT_OUTPUT_CAP_BYTES + 1,
        observed_sha256="b" * 64,
    )
    assert sanitized.failure.observed_byte_length is None
    assert sanitized.failure.observed_sha256 is None


def test_v5_binding_proof_is_closed_and_v4_semantics_are_legacy_compatible() -> None:
    proven = workspace_snapshot.WorkspaceSnapshotError(
        "workspace_after_capture_failed",
        stage="remote-exec",
        category="internal",
        return_code=92,
        subtype=SnapshotFailureSubtypeV1.WAIT_RESPONSE_INVALID,
        timeout_origin=SnapshotTimeoutOriginV1.NOT_A_TIMEOUT,
        stage_validated=True,
        termination_verified=True,
        cleanup_verified=True,
        zero_census_verified=True,
        execution_binding_verified=True,
        reason=SnapshotFailureReasonV1.OUTER_RETURN_CODE_NONZERO,
    )
    value = workspace_snapshot._failure_receipt_value(
        workspace_snapshot.SnapshotPolicy(),
        proven.code,
        proven.failure,
    )
    parsed = workspace_snapshot.parse_workspace_receipt_bytes(
        workspace_snapshot.canonical_json(value)
    )
    assert parsed.failure is not None
    assert parsed.failure.execution_binding_verified is True
    assert parsed.continuable is True

    unbound = json.loads(json.dumps(value))
    unbound["failure"]["execution_binding_verified"] = False
    parsed_unbound = workspace_snapshot.parse_workspace_receipt_bytes(
        workspace_snapshot.canonical_json(unbound)
    )
    assert parsed_unbound.failure is not None
    assert parsed_unbound.failure.execution_binding_verified is False
    assert parsed_unbound.continuable is False

    cleanup_partial = json.loads(json.dumps(value))
    cleanup_partial["failure"]["cleanup_verified"] = False
    parsed_cleanup_partial = workspace_snapshot.parse_workspace_receipt_bytes(
        workspace_snapshot.canonical_json(cleanup_partial)
    )
    assert parsed_cleanup_partial.continuable is False

    for forged_binding in (None, 1, "true"):
        forged = json.loads(json.dumps(value))
        forged["failure"]["execution_binding_verified"] = forged_binding
        with pytest.raises(
            workspace_snapshot.WorkspaceSnapshotError,
            match="^workspace_receipt_invalid$",
        ):
            workspace_snapshot.parse_workspace_receipt_bytes(
                workspace_snapshot.canonical_json(forged)
            )

    missing = json.loads(json.dumps(value))
    del missing["failure"]["execution_binding_verified"]
    extra = json.loads(json.dumps(value))
    extra["failure"]["future_binding_proof"] = True
    contradictions = []
    for proof in (
        "stage_validated",
        "termination_verified",
        "zero_census_verified",
    ):
        contradiction = json.loads(json.dumps(value))
        contradiction["failure"][proof] = False
        contradictions.append(contradiction)
    for invalid in (missing, extra, *contradictions):
        with pytest.raises(
            workspace_snapshot.WorkspaceSnapshotError,
            match="^workspace_receipt_invalid$",
        ):
            workspace_snapshot.parse_workspace_receipt_bytes(
                workspace_snapshot.canonical_json(invalid)
            )

    legacy_wait_response = json.loads(json.dumps(value))
    legacy_wait_response["schema_version"] = (
        workspace_snapshot.FAILURE_RECEIPT_SCHEMA_V4
    )
    del legacy_wait_response["failure"]["execution_binding_verified"]
    parsed_legacy_wait_response = workspace_snapshot.parse_workspace_receipt_bytes(
        workspace_snapshot.canonical_json(legacy_wait_response)
    )
    assert parsed_legacy_wait_response.failure is not None
    assert parsed_legacy_wait_response.failure.execution_binding_verified is False
    assert parsed_legacy_wait_response.continuable is False

    legacy_transport_failure = workspace_snapshot.WorkspaceSnapshotError(
        "workspace_before_capture_failed",
        stage="remote-exec",
        category="timeout",
        subtype=SnapshotFailureSubtypeV1.WAIT_TRANSPORT_FAILED,
        timeout_origin=SnapshotTimeoutOriginV1.SEMANTIC_EXECUTION_TIMED_OUT,
        stage_validated=True,
        termination_verified=True,
        cleanup_verified=True,
        zero_census_verified=True,
    )
    legacy_transport = workspace_snapshot._failure_receipt_value(
        workspace_snapshot.SnapshotPolicy(),
        legacy_transport_failure.code,
        legacy_transport_failure.failure,
    )
    legacy_transport["schema_version"] = workspace_snapshot.FAILURE_RECEIPT_SCHEMA_V4
    del legacy_transport["failure"]["execution_binding_verified"]
    parsed_legacy_transport = workspace_snapshot.parse_workspace_receipt_bytes(
        workspace_snapshot.canonical_json(legacy_transport)
    )
    assert parsed_legacy_transport.continuable is True


def test_workspace_receipt_parser_fails_closed_on_recursion_and_unknown_reason() -> (
    None
):
    recursive = b"[" * 2_000 + b"0" + b"]" * 2_000
    with pytest.raises(
        workspace_snapshot.WorkspaceSnapshotError,
        match="^workspace_receipt_invalid$",
    ):
        workspace_snapshot.parse_workspace_receipt_bytes(recursive)

    failure = workspace_snapshot.WorkspaceSnapshotError(
        "workspace_before_capture_failed",
        stage="remote-exec",
        category="timeout",
        subtype=SnapshotFailureSubtypeV1.WAIT_TRANSPORT_FAILED,
        timeout_origin=SnapshotTimeoutOriginV1.SEMANTIC_EXECUTION_TIMED_OUT,
        stage_validated=True,
        termination_verified=True,
        cleanup_verified=True,
        zero_census_verified=True,
        reason=SnapshotFailureReasonV1.UNKNOWN,
    )
    payload = workspace_snapshot.canonical_json(
        workspace_snapshot._failure_receipt_value(
            workspace_snapshot.SnapshotPolicy(),
            failure.code,
            failure.failure,
        )
    )
    parsed = workspace_snapshot.parse_workspace_receipt_bytes(payload)
    assert parsed.failure is not None
    assert parsed.failure.reason is SnapshotFailureReasonV1.UNKNOWN
    assert parsed.continuable is False


def test_workspace_receipt_loader_rejects_symlink_and_oversize(tmp_path: Path) -> None:
    target = tmp_path / "receipt-target.json"
    target.write_bytes(b"{}\n")
    symlink = tmp_path / "workspace-receipt.json"
    symlink.symlink_to(target)

    with pytest.raises(
        workspace_snapshot.WorkspaceSnapshotError,
        match="^workspace_receipt_invalid$",
    ):
        workspace_snapshot.load_workspace_receipt(symlink)

    oversized = tmp_path / "oversized-receipt.json"
    oversized.write_bytes(b"x" * (workspace_snapshot._WORKSPACE_RECEIPT_MAX_BYTES + 1))
    with pytest.raises(
        workspace_snapshot.WorkspaceSnapshotError,
        match="^workspace_receipt_invalid$",
    ):
        workspace_snapshot.load_workspace_receipt(oversized)


def test_producer_rejects_valid_receipt_replacement_between_write_and_reread(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    target = workspace_snapshot.SnapshotTarget(actor=object(), artifact_dir=artifacts)
    policy = workspace_snapshot.SnapshotPolicy()
    intended = workspace_snapshot.WorkspaceSnapshotError(
        "workspace_before_capture_failed",
        stage="remote-exec",
        category="timeout",
        subtype=SnapshotFailureSubtypeV1.WAIT_TRANSPORT_FAILED,
        timeout_origin=SnapshotTimeoutOriginV1.SEMANTIC_EXECUTION_TIMED_OUT,
    )
    replacement = workspace_snapshot.WorkspaceSnapshotError(
        "workspace_before_capture_failed",
        stage="target",
        category="internal",
        subtype=SnapshotFailureSubtypeV1.UNKNOWN_INTERNAL,
        reason=SnapshotFailureReasonV1.UNKNOWN,
    )
    replacement_payload = workspace_snapshot.canonical_json(
        workspace_snapshot._failure_receipt_value(
            policy,
            replacement.code,
            replacement.failure,
        )
    )
    real_write = workspace_snapshot._write

    def replace_after_write(path: Path, payload: bytes) -> None:
        real_write(path, payload)
        if path.name == "workspace-receipt.json":
            path.write_bytes(replacement_payload)

    monkeypatch.setattr(workspace_snapshot, "_write", replace_after_write)

    with pytest.raises(
        workspace_snapshot.WorkspaceSnapshotError,
        match="^workspace_receipt_persisted_mismatch$",
    ):
        workspace_snapshot._failure_receipt(
            target,
            policy,
            intended.code,
            intended,
        )


def test_remote_unverified_failure_preserves_numeric_return_code(
    tmp_path: Path,
) -> None:
    stage = "/tmp/nano-workspace-snapshot-v1.fixture"

    async def execute(command: str, *, timeout_sec: float) -> SimpleNamespace:
        assert timeout_sec > 0
        assert command == workspace_snapshot._remote_stage_script()
        return SimpleNamespace(return_code=0, stdout=f"{stage}\n", stderr="")

    async def execute_owned(
        command: str,
        *,
        stage: str,
        timeout_sec: float,
    ) -> None:
        assert command
        assert stage == "/tmp/nano-workspace-snapshot-v1.fixture"
        assert timeout_sec > 0
        raise SnapshotOperationFailure(
            SnapshotFailureEvidenceV1(
                subtype=SnapshotFailureSubtypeV1.LAUNCH_FAILED,
                reason=SnapshotFailureReasonV1.OUTER_RETURN_CODE_NONZERO,
                observed_byte_length=2,
                observed_sha256=hashlib.sha256(b"23").hexdigest(),
            ),
            return_code=23,
        )

    async def download(source: str, target: Path) -> None:
        raise AssertionError(f"unexpected download: {source} -> {target}")

    with pytest.raises(workspace_snapshot.WorkspaceSnapshotError) as caught:
        asyncio.run(
            workspace_snapshot._remote_inventory_attempt(
                object(),
                workspace_snapshot.SnapshotPolicy(),
                root="/workspace",
                execute=execute,
                execute_owned=execute_owned,
                download=download,
                attempt=1,
                deadline=None,
            )
        )

    error = caught.value
    assert error.code == "workspace_snapshot_remote_termination_unverified"
    assert error.failure.return_code == 23
    assert error.failure.reason is SnapshotFailureReasonV1.OUTER_RETURN_CODE_NONZERO

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    persisted = workspace_snapshot._failure_receipt(
        workspace_snapshot.SnapshotTarget(
            actor=object(),
            artifact_dir=artifacts,
        ),
        workspace_snapshot.SnapshotPolicy(),
        "workspace_before_capture_failed",
        error,
    )
    assert persisted.failure is not None
    assert persisted.failure.return_code == 23
    assert persisted.failure.reason is SnapshotFailureReasonV1.OUTER_RETURN_CODE_NONZERO


def test_capture_returns_exactly_persisted_receipt_projection(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    artifacts = tmp_path / "artifacts"
    workspace.mkdir()
    artifacts.mkdir()
    actor = LocalSnapshotActor(workspace, artifacts)

    before = asyncio.run(
        workspace_snapshot.capture_before(actor, workspace_snapshot.SnapshotPolicy())
    )
    (workspace / "answer.txt").write_text("answer\n", encoding="utf-8")
    captured = asyncio.run(workspace_snapshot.capture_after(actor, before))

    assert captured == workspace_snapshot.load_workspace_receipt(
        artifacts / "workspace-receipt.json"
    )


def test_snapshot_target_separates_private_capture_from_publication_root(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    private = tmp_path / ".nano-control-v2"
    public = tmp_path / "agent"
    workspace.mkdir()
    private.mkdir(mode=0o700)
    public.mkdir()
    (workspace / "sentinel.txt").write_text("private snapshot")
    actor = LocalSnapshotActor(workspace, private)
    target = workspace_snapshot.SnapshotTarget(
        actor=actor,
        artifact_dir=private,
        publication_dir=public,
    )

    before = asyncio.run(
        workspace_snapshot.capture_before(
            target,
            workspace_snapshot.SnapshotPolicy(),
        )
    )

    assert before.target.publication_dir == public.resolve()
    assert (private / "workspace-before.json").is_file()
    assert list(public.iterdir()) == []


def test_workspace_archive_publication_limit_has_safe_ustar_headroom() -> None:
    from nano_grok_build.adapter.artifact_limits import (
        DEFAULT_PUBLICATION_FILE_MAX_BYTES,
        PUBLICATION_TOTAL_MAX_BYTES,
        WORKSPACE_CHANGED_TAR_MAX_BYTES,
        publication_file_max_bytes,
    )

    worst_case = 64 * 1024 * 1024 + 10_000 * (512 + 511) + 10_240
    assert worst_case == 77_349_104
    assert DEFAULT_PUBLICATION_FILE_MAX_BYTES == 64 * 1024 * 1024
    assert WORKSPACE_CHANGED_TAR_MAX_BYTES == 80 * 1024 * 1024
    assert PUBLICATION_TOTAL_MAX_BYTES == 256 * 1024 * 1024
    assert worst_case < WORKSPACE_CHANGED_TAR_MAX_BYTES
    assert (
        publication_file_max_bytes("workspace-changed.tar")
        == WORKSPACE_CHANGED_TAR_MAX_BYTES
    )
    assert (
        publication_file_max_bytes("Workspace-changed.tar")
        == DEFAULT_PUBLICATION_FILE_MAX_BYTES
    )
    assert (
        publication_file_max_bytes("nested/workspace-changed.tar")
        == DEFAULT_PUBLICATION_FILE_MAX_BYTES
    )


def test_capture_after_fails_closed_before_writing_an_oversize_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    actor = SimpleNamespace(artifacts=artifacts)
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)
    policy = workspace_snapshot.SnapshotPolicy(
        max_files=1,
        max_total_bytes=8,
        max_file_bytes=8,
        max_patch_bytes=8,
    )
    before = workspace_snapshot.BeforeSnapshot(
        target=target,
        policy=policy,
        manifest={
            "schema_version": workspace_snapshot.MANIFEST_SCHEMA,
            "policy_version": policy.version,
            "entries": [],
            "entry_count": 0,
            "scan_complete": True,
        },
        safe_contents={},
    )
    payload = b"changed\n"
    entry = {
        "path": "answer.txt",
        "kind": "file",
        "mode": "0644",
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    after = workspace_snapshot._Inventory(
        manifest={
            "schema_version": workspace_snapshot.MANIFEST_SCHEMA,
            "policy_version": policy.version,
            "entries": [entry],
            "entry_count": 1,
            "scan_complete": True,
        },
        entries={"answer.txt": entry},
        safe_contents={"answer.txt": payload},
        content_omissions={},
        stage_validated=True,
        termination_verified=True,
        cleanup_verified=True,
        zero_census_verified=True,
    )

    async def captured(*_args, **_kwargs):
        return after

    monkeypatch.setattr(workspace_snapshot, "_capture_inventory", captured)
    monkeypatch.setattr(workspace_snapshot, "_tar", lambda **_kwargs: b"xx")
    monkeypatch.setattr(
        workspace_snapshot,
        "WORKSPACE_CHANGED_TAR_MAX_BYTES",
        1,
        raising=False,
    )

    receipt = asyncio.run(workspace_snapshot.capture_after(actor, before))

    assert receipt.status == "failed"
    assert receipt.code == "workspace_after_capture_failed"
    assert receipt.failure is not None
    assert receipt.failure.stage == "host-evidence"
    assert receipt.failure.category == "evidence"
    assert (
        receipt.failure.subtype
        is SnapshotFailureSubtypeV1.HOST_EVIDENCE_MATERIALIZATION_FAILED
    )
    assert set(artifacts.iterdir()) == {artifacts / "workspace-receipt.json"}


def test_failed_before_uses_explicit_no_baseline_sentinel(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    artifacts = tmp_path / "artifacts"
    workspace.mkdir()
    artifacts.mkdir()
    actor = LocalSnapshotActor(workspace, artifacts)
    target = workspace_snapshot.SnapshotTarget(actor=actor, artifact_dir=artifacts)
    failure = workspace_snapshot.WorkspaceSnapshotError(
        "workspace_before_capture_failed",
        stage="remote-exec",
        category="timeout",
        subtype=SnapshotFailureSubtypeV1.WAIT_TRANSPORT_FAILED,
        timeout_origin=SnapshotTimeoutOriginV1.SEMANTIC_EXECUTION_TIMED_OUT,
        stage_validated=True,
        termination_verified=True,
        cleanup_verified=True,
        zero_census_verified=True,
    )
    persisted = workspace_snapshot._failure_receipt(
        target,
        workspace_snapshot.SnapshotPolicy(),
        failure.code,
        failure,
    )
    before = workspace_snapshot.BeforeSnapshot(
        target=target,
        policy=workspace_snapshot.SnapshotPolicy(),
        baseline_state=workspace_snapshot.WorkspaceBaselineStateV1.UNAVAILABLE,
        manifest=None,
        safe_contents={},
        status="failed",
        code=persisted.code,
        failure=persisted.failure,
        receipt_sha256=persisted.canonical_sha256,
    )

    captured = asyncio.run(workspace_snapshot.capture_after(target, before))

    assert captured == persisted
    assert (
        captured.baseline_state
        is workspace_snapshot.WorkspaceBaselineStateV1.UNAVAILABLE
    )
    assert not (artifacts / "workspace-after.json").exists()
    assert actor.capture_phases == []
