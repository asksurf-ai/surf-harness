"""Provider-free all-89 Harbor setup smoke for one exact controller image."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import threading
from collections.abc import Mapping, MutableMapping, Sequence
from pathlib import Path
from typing import Any
from uuid import uuid4

REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY / "src"))

from nano_grok_build.adapter.artifactizer import rust_run_spec_sha256  # noqa: E402
from nano_grok_build.adapter.control_plane import control_root_for  # noqa: E402
from nano_grok_build.harbor.git_history_capability import (  # noqa: E402
    GIT_HISTORY_ACCESS_REQUIRED,
)
from nano_grok_build.harbor.git_history_receipt import (  # noqa: E402
    HISTORY_BASELINE_RECEIPT,
    load_git_history_baseline_receipt,
)
from nano_grok_build.harbor.tb21 import (  # noqa: E402
    HARBOR_COMMIT,
    LEADERBOARD_AGENT,
    LEADERBOARD_MODEL,
    TB21_DATASET,
    TB21_DATASET_REF,
    TB21_SOURCE_COMMIT,
    TB21_TASK_COUNT,
    capture_capability_manifest,
    create_bound_job,
    load_inventory,
    load_official_task_checksums,
    prepare_run,
)

SCHEMA_VERSION = "tb21-all89-setup-smoke-v1"
HISTORY_AUTHORITY_SCHEMA = "tb21-git-history-capability-authority-v2"
HISTORY_AUTHORITY_PATH = Path("policy/tb21-git-history-capability-v2.json")
HISTORY_AUTHORITY_SHA256 = (
    "c2c6f4327c05d97142b89b7daeb88a097f3265ae7eccc9a3057a2a9d896eb9e8"
)
HISTORY_CAPABILITIES_SHA256 = (
    "9ba72cb460c7ddd5138d9ba2375794783d455a921d62ab30f773917519e20499"
)
OFFICIAL_TASK_CHECKSUMS_SHA256 = (
    "e2c68e04fd0270254c9e657211a66ea98932101a5feb62a0e89941c6a29d5ee7"
)
_DIGEST_IMAGE = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
_INVENTORY_IMAGE = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}|@sha256:[0-9a-f]{64})$"
)
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_COUNTER_NAMES = frozenset(
    {
        "credential_reads",
        "provider_constructions",
        "provider_launches",
        "provider_sends",
        "agent_runs",
        "verifier_starts",
        "scoring_or_collection_starts",
    }
)
_SECRET_NAME = re.compile(
    r"(?:^|_)(?:XAI)(?:_|$).*(?:KEY|SECRET|TOKEN)|(?:KEY|SECRET|TOKEN).*(?:^|_)XAI(?:_|$)"
)


class SetupSmokeError(RuntimeError):
    """A stable, non-waivable setup-smoke failure."""


def canonical(value: object) -> bytes:
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


def require_image_identity(candidate: str, intended: str, executing: str) -> str:
    if _DIGEST_IMAGE.fullmatch(candidate) is None:
        raise SetupSmokeError("candidate_image_invalid")
    if candidate != intended or candidate != executing:
        raise SetupSmokeError("candidate_image_mismatch")
    return candidate


def require_inventory_image_refs(image_refs: Sequence[str]) -> tuple[str, ...]:
    refs = tuple(image_refs)
    if not refs or any(_INVENTORY_IMAGE.fullmatch(ref) is None for ref in refs):
        raise SetupSmokeError("inventory_identity_invalid")
    return refs


def admit_inventory_image_bindings(
    image_refs: Sequence[str], bindings: object
) -> dict[str, str]:
    """Bind strict source refs to immutable IDs resolved by prelaunch's local daemon."""

    refs = tuple(dict.fromkeys(require_inventory_image_refs(image_refs)))
    if (
        not isinstance(bindings, Sequence)
        or isinstance(bindings, str | bytes)
        or len(bindings) != len(refs)
    ):
        raise SetupSmokeError("inventory_image_binding_invalid")
    resolved: dict[str, str] = {}
    for expected_ref, row in zip(refs, bindings, strict=True):
        if not isinstance(row, Mapping) or set(row) != {"image_ref", "image_id"}:
            raise SetupSmokeError("inventory_image_binding_invalid")
        image_ref = row.get("image_ref")
        image_id = row.get("image_id")
        if (
            image_ref != expected_ref
            or image_ref in resolved
            or not isinstance(image_id, str)
            or _IMAGE_ID.fullmatch(image_id) is None
        ):
            raise SetupSmokeError("inventory_image_binding_invalid")
        resolved[image_ref] = image_id
    return resolved


def assert_no_paid_secret(environment: Mapping[str, str]) -> None:
    if any(
        value and _SECRET_NAME.search(name.upper())
        for name, value in environment.items()
    ):
        raise SetupSmokeError("provider_credential_present")


def load_frozen_history_authority(repository: Path) -> dict[str, object]:
    path = repository / HISTORY_AUTHORITY_PATH
    try:
        metadata = path.lstat()
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise SetupSmokeError("history_authority_invalid") from error
    rows = value.get("tasks") if isinstance(value, dict) else None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size > 64 * 1024
        or hashlib.sha256(raw).hexdigest() != HISTORY_AUTHORITY_SHA256
        or not isinstance(value, dict)
        or set(value)
        != {
            "dataset_ref",
            "git_history_capabilities_sha256",
            "official_task_checksums_sha256",
            "schema_version",
            "task_count",
            "tasks",
            "terminal_bench_commit",
        }
        or canonical(value) != raw
        or value.get("schema_version") != HISTORY_AUTHORITY_SCHEMA
        or value.get("dataset_ref") != TB21_DATASET_REF
        or value.get("git_history_capabilities_sha256") != HISTORY_CAPABILITIES_SHA256
        or value.get("official_task_checksums_sha256") != OFFICIAL_TASK_CHECKSUMS_SHA256
        or value.get("terminal_bench_commit") != TB21_SOURCE_COMMIT
        or value.get("task_count") != TB21_TASK_COUNT
        or not isinstance(rows, list)
        or len(rows) != TB21_TASK_COUNT
    ):
        raise SetupSmokeError("history_authority_invalid")
    observed: list[str] = []
    required: list[str] = []
    for row in rows:
        if (
            not isinstance(row, dict)
            or set(row)
            != {
                "canonical_instruction_sha256",
                "git_history_access",
                "supporting_span_sha256",
                "task_id",
                "trusted_manifest_sha256",
            }
            or row.get("git_history_access") not in {"not_required", "required"}
            or not isinstance(row.get("task_id"), str)
            or not row["task_id"].startswith("terminal-bench/")
            or not isinstance(row.get("canonical_instruction_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", row["canonical_instruction_sha256"])
            is None
            or not isinstance(row.get("trusted_manifest_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", row["trusted_manifest_sha256"]) is None
            or row["git_history_access"] == "not_required"
            and row.get("supporting_span_sha256") is not None
            or row["git_history_access"] == "required"
            and (
                not isinstance(row.get("supporting_span_sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", row["supporting_span_sha256"]) is None
            )
        ):
            raise SetupSmokeError("history_authority_invalid")
        observed.append(row["task_id"])
        if row["git_history_access"] == "required":
            required.append(row["task_id"])
    if (
        observed != sorted(observed)
        or len(set(observed)) != TB21_TASK_COUNT
        or required != ["terminal-bench/git-leak-recovery"]
        or hashlib.sha256(canonical(rows)[:-1]).hexdigest()
        != HISTORY_CAPABILITIES_SHA256
    ):
        raise SetupSmokeError("history_authority_invalid")
    return value


def admit_frozen_history_authority(
    authority: Mapping[str, object],
    inventory_ids: Sequence[str],
    run_specs: Sequence[Mapping[str, object]],
) -> str:
    rows = authority.get("tasks")
    if not isinstance(rows, list):
        raise SetupSmokeError("history_authority_mismatch")
    expected = {
        str(row["task_id"]): dict(row) for row in rows if isinstance(row, Mapping)
    }
    if (
        len(expected) != TB21_TASK_COUNT
        or len(inventory_ids) != TB21_TASK_COUNT
        or len(set(inventory_ids)) != TB21_TASK_COUNT
        or set(inventory_ids) != set(expected)
        or len(run_specs) != TB21_TASK_COUNT
    ):
        raise SetupSmokeError("history_authority_mismatch")
    observed: dict[str, dict[str, object]] = {}
    for spec in run_specs:
        task = spec.get("task") if isinstance(spec, Mapping) else None
        capability = (
            task.get("git_history_capability") if isinstance(task, Mapping) else None
        )
        task_id = task.get("id") if isinstance(task, Mapping) else None
        if (
            not isinstance(task_id, str)
            or task_id in observed
            or not isinstance(capability, Mapping)
        ):
            raise SetupSmokeError("history_authority_mismatch")
        observed[task_id] = {
            "canonical_instruction_sha256": capability.get(
                "canonical_instruction_sha256"
            ),
            "git_history_access": capability.get("git_history_access"),
            "supporting_span_sha256": capability.get("supporting_span_sha256"),
            "task_id": task_id,
            "trusted_manifest_sha256": capability.get("trusted_manifest_sha256"),
        }
    if observed != expected:
        raise SetupSmokeError("history_authority_mismatch")
    return HISTORY_AUTHORITY_SHA256


class ProviderTripwire:
    """Fail on first forbidden boundary touch and leave a durable marker."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.counts = {name: 0 for name in sorted(_COUNTER_NAMES)}
        self._lock = threading.Lock()

    def hit(self, name: str) -> None:
        if name not in _COUNTER_NAMES:
            raise SetupSmokeError("provider_tripwire_invalid")
        with self._lock:
            self.counts[name] += 1
            path = self.root / f"TRIPWIRE-{name}"
            try:
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(f"{self.counts[name]}\n".encode())
                    handle.flush()
                    os.fsync(handle.fileno())
        raise SetupSmokeError("provider_tripwire_touched")


def cohort_status(
    *, rows: int, cleanup: int, residual: int, counters: Mapping[str, int]
) -> str:
    return (
        "PASS"
        if rows == TB21_TASK_COUNT
        and cleanup == TB21_TASK_COUNT
        and residual == 0
        and set(counters) == _COUNTER_NAMES
        and all(value == 0 for value in counters.values())
        else "FAIL"
    )


def history_cohort_admitted(rows: Sequence[Mapping[str, object]]) -> bool:
    """Require the one frozen history exception and 88 isolated tasks exactly."""

    if len(rows) != TB21_TASK_COUNT:
        return False
    task_ids = [row.get("task_id") for row in rows]
    if (
        any(not isinstance(task_id, str) for task_id in task_ids)
        or len(set(task_ids)) != TB21_TASK_COUNT
    ):
        return False
    required = []
    not_required = []
    for row in rows:
        capability = row.get("capability")
        if not isinstance(capability, Mapping):
            return False
        access = capability.get("git_history_access")
        if access == GIT_HISTORY_ACCESS_REQUIRED:
            required.append(row)
        elif access == "not_required":
            not_required.append(row)
        else:
            return False
    return (
        len(required) == 1
        and required[0].get("task_id") == "terminal-bench/git-leak-recovery"
        and required[0].get("history_status") == "preserved"
        and required[0].get("history_topology") == "nested"
        and len(not_required) == TB21_TASK_COUNT - 1
        and all(
            row.get("history_status") in {"created", "isolated"} for row in not_required
        )
    )


def _run(command: Sequence[str]) -> str:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise SetupSmokeError("host_identity_check_failed") from error
    if result.returncode != 0 or len(result.stdout) > 16 * 1024 * 1024:
        raise SetupSmokeError("host_identity_check_failed")
    return result.stdout.strip()


def _git_head(path: Path) -> str:
    return _run(("git", "-C", str(path), "rev-parse", "HEAD"))


def _verify_executing_image(candidate: str) -> dict[str, object]:
    container = os.environ.get("HOSTNAME", "")
    if not container:
        raise SetupSmokeError("executing_image_unavailable")
    container_image_id = _run(
        ("docker", "inspect", container, "--format", "{{.Image}}")
    )
    candidate_image_id = _run(
        ("docker", "image", "inspect", candidate, "--format", "{{.Id}}")
    )
    try:
        repo_digests = json.loads(
            _run(
                (
                    "docker",
                    "image",
                    "inspect",
                    candidate,
                    "--format",
                    "{{json .RepoDigests}}",
                )
            )
        )
    except json.JSONDecodeError as error:
        raise SetupSmokeError("executing_image_unavailable") from error
    if (
        container_image_id != candidate_image_id
        or not isinstance(repo_digests, list)
        or candidate not in repo_digests
    ):
        raise SetupSmokeError("executing_image_mismatch")
    return {"image_id": candidate_image_id, "repo_digests": sorted(repo_digests)}


def _residual_containers(session_id: str) -> list[str]:
    output = _run(
        (
            "docker",
            "ps",
            "-aq",
            "--filter",
            f"label=com.docker.compose.project={session_id}",
        )
    )
    return sorted(line for line in output.splitlines() if line)


def _network_none(containers: Sequence[str]) -> bool:
    return bool(containers) and all(
        _run(("docker", "inspect", item, "--format", "{{.HostConfig.NetworkMode}}"))
        == "none"
        for item in containers
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


async def _bound_job(prepared: Any) -> Any:
    from harbor.models.job.config import DatasetConfig, JobConfig, RetryConfig
    from harbor.models.trial.config import AgentConfig, EnvironmentConfig

    config = JobConfig(
        job_name="nano-tb21-setup-smoke",
        jobs_dir=prepared.output_dir / "jobs",
        n_attempts=1,
        n_concurrent_trials=2,
        quiet=True,
        retry=RetryConfig(max_retries=0),
        environment=EnvironmentConfig(type="docker", delete=True),
        agents=[
            AgentConfig(
                name=LEADERBOARD_AGENT,
                import_path="nano_grok_build.adapter.harbor:NanoGrokBuildAgent",
                model_name=LEADERBOARD_MODEL,
                kwargs={"reasoning_effort": prepared.inputs.reasoning_effort},
            )
        ],
        datasets=[
            DatasetConfig(
                name=TB21_DATASET,
                ref=TB21_DATASET_REF,
                task_names=[task.task_id for task in prepared.selected],
            )
        ],
        tasks=[],
    )
    return await create_bound_job(config, prepared.inputs)


def _install_tripwires(tripwire: ProviderTripwire) -> None:
    from harbor.job import Job
    from harbor.metrics.mean import Mean
    from harbor.trial.single_step import SingleStepTrial
    from harbor.trial.trial import Trial
    from harbor.verifier.factory import VerifierFactory

    import nano_grok_build.adapter.harbor as harbor_adapter
    import nano_grok_build.adapter.stdio_bridge as stdio_bridge
    import nano_grok_build.harbor.provider as provider_runtime
    import nano_grok_build.harbor.tb21 as tb21_runner

    def credential_read(*_args: object, **_kwargs: object) -> None:
        tripwire.hit("credential_reads")

    def provider_construction(*_args: object, **_kwargs: object) -> None:
        tripwire.hit("provider_constructions")

    async def provider_launch(*_args: object, **_kwargs: object) -> None:
        tripwire.hit("provider_launches")

    def provider_send(*_args: object, **_kwargs: object) -> None:
        tripwire.hit("provider_sends")

    async def agent_run(*_args: object, **_kwargs: object) -> None:
        tripwire.hit("agent_runs")

    def verifier_start(*_args: object, **_kwargs: object) -> None:
        tripwire.hit("verifier_starts")

    async def verifier_start_async(*_args: object, **_kwargs: object) -> None:
        tripwire.hit("verifier_starts")

    def scoring_or_collection_start(*_args: object, **_kwargs: object) -> None:
        tripwire.hit("scoring_or_collection_starts")

    async def scoring_or_collection_start_async(
        *_args: object, **_kwargs: object
    ) -> None:
        tripwire.hit("scoring_or_collection_starts")

    tb21_runner.load_xai_key = credential_read
    provider_runtime.runtime_command = provider_construction
    harbor_adapter.runtime_command = provider_construction
    harbor_adapter.run_stdio_bridge = provider_launch
    stdio_bridge.run_stdio_bridge = provider_launch
    stdio_bridge._write_response_before_drain_cutoff = provider_send
    harbor_adapter.NanoGrokBuildAgent.run = agent_run
    harbor_adapter.NanoGrokBuildAgent.run_with_deadline = agent_run
    harbor_adapter.NanoGrokBuildAgent.populate_context_post_run = (
        scoring_or_collection_start
    )
    Job.run = agent_run
    Job._refresh_metrics_for_eval = scoring_or_collection_start
    VerifierFactory.create_verifier_from_config = classmethod(verifier_start)
    VerifierFactory.create_verifier_from_import_path = classmethod(verifier_start)
    Mean.compute = scoring_or_collection_start
    SingleStepTrial._run_verifier = verifier_start_async
    Trial._run_shared_verifier = verifier_start_async
    Trial._run_separate_verifier = verifier_start_async
    SingleStepTrial._collect_artifacts = scoring_or_collection_start_async
    Trial._run_collect_hooks = scoring_or_collection_start_async
    Trial._collect_artifacts_phased = scoring_or_collection_start_async
    tb21_runner.collect_job = scoring_or_collection_start


async def _run_setup_cohort(
    *, prepared: Any, bound: Any, image_bindings: Mapping[str, str]
) -> list[dict[str, object]]:
    from harbor.agents.factory import AgentFactory
    from harbor.environments.docker.docker import DockerEnvironment
    from harbor.models.task.config import EnvironmentConfig as TaskEnvironmentConfig
    from harbor.models.trial.paths import TrialPaths

    import nano_grok_build.adapter.harbor as harbor_adapter

    selected = {task.task_id: task for task in prepared.selected}
    trial_configs = bound.job._trial_configs  # noqa: SLF001 - pinned smoke seam
    if len(trial_configs) != TB21_TASK_COUNT or len(bound.run_specs) != TB21_TASK_COUNT:
        raise SetupSmokeError("bound_trial_count_mismatch")
    no_network = (
        prepared.harbor_checkout
        / "src/harbor/environments/docker/docker-compose-no-network.yaml"
    )
    semaphore = asyncio.Semaphore(2)

    async def lane(
        index: int, trial_config: Any, spec: dict[str, Any]
    ) -> dict[str, object]:
        task_id = str(spec["task"]["id"])
        source = selected.get(task_id)
        if source is None:
            return {"task_id": task_id, "status": "FAIL", "error": "unexpected_task"}
        session_id = f"nano-tb21-setup-{index:02d}-{uuid4().hex[:8]}"
        trial_root = Path(spec["artifact_dir"]).parents[1]
        paths = TrialPaths(trial_root)
        environment: Any | None = None
        cleanup = False
        row: dict[str, object] = {
            "task_id": task_id,
            "task_image": source.docker_image,
            "task_image_source_ref": source.docker_image,
            "task_image_resolved_identity": image_bindings[source.docker_image],
            "session_id": session_id,
            "status": "FAIL",
        }
        async with semaphore:
            try:
                paths.mkdir()
                environment = DockerEnvironment(
                    environment_dir=source.path / "environment",
                    environment_name=f"nano-tb21-setup-{index:02d}",
                    session_id=session_id,
                    trial_paths=paths,
                    task_env_config=TaskEnvironmentConfig(
                        docker_image=source.docker_image,
                        cpus=source.cpus,
                        memory_mb=source.memory_mb,
                        storage_mb=source.storage_mb,
                        gpus=source.gpus,
                    ),
                    extra_docker_compose=[no_network],
                )
                await environment.start(force_build=False)
                active = _residual_containers(session_id)
                if not _network_none(active):
                    raise SetupSmokeError("task_network_not_none")
                logs_dir = trial_root / "agent"
                logs_dir.mkdir(exist_ok=True)
                agent = AgentFactory.create_agent_from_config(
                    trial_config.agent,
                    logs_dir,
                )
                if type(agent) is not harbor_adapter.NanoGrokBuildAgent:
                    raise SetupSmokeError("production_agent_constructor_bypassed")
                agent.session_id = session_id
                agent.context_id = uuid4()
                await agent.setup(environment)
                control_root = control_root_for(logs_dir)
                receipt = load_git_history_baseline_receipt(
                    control_root / HISTORY_BASELINE_RECEIPT,
                    capability=spec["task"]["git_history_capability"],
                    run_spec_sha256=rust_run_spec_sha256(spec),
                )
                required = (
                    spec["task"]["git_history_capability"]["git_history_access"]
                    == GIT_HISTORY_ACCESS_REQUIRED
                )
                if (
                    required
                    and receipt["status"] != "preserved"
                    or not required
                    and receipt["status"] not in {"created", "isolated"}
                ):
                    raise SetupSmokeError("history_capability_contradiction")
                before_path = control_root / "workspace-before.json"
                if not before_path.is_file() or before_path.is_symlink():
                    raise SetupSmokeError("workspace_capture_unavailable")
                actor_metadata = agent._actor.diagnostic_metadata()  # noqa: SLF001
                mapping = actor_metadata.get("workspace_mapping")
                if (
                    not isinstance(mapping, MutableMapping)
                    or mapping.get("logical_cwd") != "/workspace"
                ):
                    raise SetupSmokeError("workspace_mapping_invalid")
                row.update(
                    {
                        "status": "PASS",
                        "run_spec_sha256": rust_run_spec_sha256(spec),
                        "capability": spec["task"]["git_history_capability"],
                        "history_status": receipt["status"],
                        "history_topology": receipt["topology_after"],
                        "admitted_repo_relative_path": receipt[
                            "admitted_repo_relative_path"
                        ],
                        "history_receipt_sha256": _sha256(
                            control_root / HISTORY_BASELINE_RECEIPT
                        ),
                        "capture_before_sha256": _sha256(before_path),
                        "workspace_mapping": dict(mapping),
                    }
                )
            except Exception as error:
                row["error"] = (
                    str(error)
                    if isinstance(error, SetupSmokeError)
                    else type(error).__name__
                )
            finally:
                if environment is not None:
                    try:
                        await environment.stop(delete=True)
                    except Exception:
                        row["cleanup_error"] = "environment_stop_failed"
                cleanup = not _residual_containers(session_id)
                row["cleanup_verified"] = cleanup
                if not cleanup:
                    row["status"] = "FAIL"
        return row

    rows = await asyncio.gather(
        *(
            lane(index, trial_config, spec)
            for index, (trial_config, spec) in enumerate(
                zip(trial_configs, bound.run_specs, strict=True), start=1
            )
        )
    )
    return sorted(rows, key=lambda row: str(row["task_id"]))


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--harbor-checkout", type=Path, required=True)
    parser.add_argument("--tb21-checkout", type=Path, required=True)
    parser.add_argument("--contract-dir", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--capability-probe", type=Path, required=True)
    parser.add_argument("--runtime-python", type=Path, required=True)
    parser.add_argument("--runtime-python-sha256", required=True)
    parser.add_argument("--harbor-lock-sha256", required=True)
    parser.add_argument("--controller-pid-file", type=Path, required=True)
    parser.add_argument("--carrier", choices=("foreground", "screen"), required=True)
    parser.add_argument("--candidate-image", required=True)
    parser.add_argument("--intended-production-image", required=True)
    parser.add_argument("--executing-image", required=True)
    parser.add_argument("--cargo", default="cargo")
    return parser.parse_args(arguments)


async def run(args: argparse.Namespace) -> dict[str, object]:
    assert_no_paid_secret(os.environ)
    history_authority = load_frozen_history_authority(REPOSITORY)
    candidate = require_image_identity(
        args.candidate_image,
        args.intended_production_image,
        args.executing_image,
    )
    executing = _verify_executing_image(candidate)
    repository = REPOSITORY.resolve()
    harbor_checkout = args.harbor_checkout.resolve()
    source_checkout = args.tb21_checkout.resolve()
    output = args.output_dir.resolve()
    if _git_head(harbor_checkout) != HARBOR_COMMIT:
        raise SetupSmokeError("harbor_checkout_invalid")
    if _git_head(source_checkout) != TB21_SOURCE_COMMIT:
        raise SetupSmokeError("tb21_checkout_invalid")
    inventory = load_inventory(source_checkout / "tasks")
    if len(inventory) != TB21_TASK_COUNT:
        raise SetupSmokeError("inventory_identity_invalid")
    source_image_refs = require_inventory_image_refs(
        tuple(task.docker_image for task in inventory)
    )
    official = load_official_task_checksums(repository, inventory)
    if set(official) != {task.task_id for task in inventory}:
        raise SetupSmokeError("inventory_identity_invalid")
    capability_manifest = capture_capability_manifest(args.capability_probe.resolve())
    prepared = prepare_run(
        repository=repository,
        harbor_checkout=harbor_checkout,
        source_checkout=source_checkout,
        output_dir=output,
        contract_dir=args.contract_dir.resolve(),
        inventory=inventory,
        selected=inventory,
        concurrency=2,
        binary_path=args.binary.resolve(),
        cargo=args.cargo,
        capability_manifest=capability_manifest,
    )
    from nano_grok_build.harbor.prelaunch import (
        PrelaunchError,
        admit_prelaunch,
        verify_docker_image_bindings,
    )

    admission = admit_prelaunch(
        harbor_checkout=harbor_checkout,
        runtime_python=args.runtime_python.resolve(),
        runtime_python_sha256=args.runtime_python_sha256,
        harbor_lock_sha256=args.harbor_lock_sha256,
        expected_harbor_commit=HARBOR_COMMIT,
        binary_path=prepared.inputs.binary_path,
        contract_dir=prepared.inputs.contract_dir,
        output_dir=output,
        pid_file=args.controller_pid_file.resolve(),
        carrier=args.carrier,
        docker_images=tuple(task.docker_image for task in inventory),
        selected_storage_mb=tuple(task.storage_mb for task in inventory),
        concurrency=2,
    )
    if (
        admission.get("status") != "passed"
        or admission.get("provider_calls") != 0
        or admission.get("network_calls") != 0
        or admission.get("operations", {}).get("task_container_count") != 0
    ):
        raise SetupSmokeError("prelaunch_admission_failed")
    operations = admission.get("operations")
    image_bindings = (
        operations.get("image_bindings") if isinstance(operations, Mapping) else None
    )
    resolved_images = admit_inventory_image_bindings(source_image_refs, image_bindings)
    output.mkdir(parents=True, exist_ok=False)
    tripwire = ProviderTripwire(output)
    _install_tripwires(tripwire)
    bound = await _bound_job(prepared)
    history_authority_sha256 = admit_frozen_history_authority(
        history_authority,
        tuple(task.task_id for task in inventory),
        bound.run_specs,
    )
    try:
        verify_docker_image_bindings(image_bindings)
    except PrelaunchError as error:
        raise SetupSmokeError(str(error)) from error
    rows = await _run_setup_cohort(
        prepared=prepared,
        bound=bound,
        image_bindings=resolved_images,
    )
    residual = sum(len(_residual_containers(str(row["session_id"]))) for row in rows)
    passed = sum(row.get("status") == "PASS" for row in rows)
    cleanup = sum(row.get("cleanup_verified") is True for row in rows)
    task_ids = [str(row["task_id"]) for row in rows]
    if (
        len(task_ids) != len(set(task_ids))
        or set(task_ids) != set(official)
        or not history_cohort_admitted(rows)
    ):
        passed = -1
    status = cohort_status(
        rows=passed,
        cleanup=cleanup,
        residual=residual,
        counters=tripwire.counts,
    )
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "candidate_image": candidate,
        "executing_image": executing,
        "git_history_capability_authority_sha256": history_authority_sha256,
        "inventory": {
            "expected": TB21_TASK_COUNT,
            "observed": len(rows),
            "passed": passed,
            "unique": len(set(task_ids)),
        },
        "prelaunch": admission,
        "cleanup_verified": cleanup,
        "residual_containers": residual,
        "tripwire_counts": dict(tripwire.counts),
        "attempts": 1,
        "retry_max": 0,
        "concurrency": 2,
        "rows": rows,
    }
    target = output / f"{SCHEMA_VERSION}.json"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(canonical(receipt))
        handle.flush()
        os.fsync(handle.fileno())
    return receipt


def main(arguments: Sequence[str] | None = None) -> int:
    receipt = asyncio.run(run(parse_args(arguments)))
    sys.stdout.buffer.write(canonical(receipt))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
