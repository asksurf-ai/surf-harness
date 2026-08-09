# ruff: noqa: E501
import base64
import hashlib
import importlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

COMMIT = "d0c4c8c3d268ec4551e82021222b31e9a36e3245"
TREE = "142b3d10164772195568bec50fa126c73f068dc3"
BLOBS = {"crates/nano-types/src/event.rs": "96d9b28e9c1b6e1656a00d51507326510125e476548e485aafb133b4cbd28f78", "crates/nano-provider-xai/src/sse.rs": "19a9a339c4c6151a1cfff63048b28d0aebd626e73b41b2c653bf98c9ecd08775", "src/nano_grok_build/adapter/artifactizer.py": "7158e37a38a67133936a89058a439cef822333504175f5ac13f8cdc0fef79693", "src/nano_grok_build/adapter/deadline.py": "a82d2a8d2aad8502a38500963af8ccaa261ce9497c5436b7e44bbaa3dc4816a2"}
EXPECTED_FILES = ("agent-run.json", "runtime-usage-receipt.json", "runtime/deadline.json", "runtime/events.jsonl", "runtime/run.json", "trajectory.json")
RECIPE_FILES = ("exporter.rs", "input.json", "reconstruct.py")
INPUT_ID = ("nano-tb21-historical-v2-deadline-synthetic-input-v1", "synthetic_historical_v2_deadline_wire_only")
GOLDEN_ID = ("nano-tb21-historical-v2-deadline-synthetic-golden-v1", "synthetic_historical_v2_deadline_wire_only;no_benchmark_bytes_scores_or_metrics")
HERE = Path(__file__).resolve().parent
GOLDEN = HERE / "golden.json"
PRODUCER = {"commit": COMMIT, "tree": TREE, "blobs": BLOBS}


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _json(path: Path) -> object:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        if len(dict(items)) != len(items):
            raise ValueError("duplicate JSON field")
        return dict(items)

    raw = path.read_bytes()
    value = json.loads(raw, object_pairs_hook=pairs)
    if raw != _canonical(value):
        raise ValueError("non-canonical JSON")
    return value


def _run(*args: object, cwd: Path | None = None) -> bytes:
    return subprocess.run(list(map(str, args)), cwd=cwd, check=True, capture_output=True).stdout


def _git(repo: Path, *args: str) -> str:
    return _run("git", "-C", repo, *args).decode().strip()


def _source(path: Path) -> Path:
    path = path.resolve(strict=True)
    if _git(path, "rev-parse", "HEAD") != COMMIT or _git(path, "rev-parse", "HEAD^{tree}") != TREE or _git(path, "status", "--porcelain", "--untracked-files=all") or any(hashlib.sha256((path / name).read_bytes()).hexdigest() != digest for name, digest in BLOBS.items()):
        raise ValueError("historical source pin mismatch")
    return path


def _empty(path: Path) -> Path:
    if path.is_symlink() or (path.exists() and (not path.is_dir() or any(path.iterdir()))):
        raise ValueError("destination must be absent or empty")
    path.mkdir(parents=True, exist_ok=True)
    return path.resolve()


def _files(root: Path) -> dict[str, bytes]:
    entries = tuple(root.rglob("*"))
    names = tuple(sorted(path.relative_to(root).as_posix() for path in entries if path.is_file()))
    if names != EXPECTED_FILES:
        raise ValueError("fixture file envelope mismatch")
    return {name: (root / name).read_bytes() for name in names}


def generate(source: Path, destination: Path) -> dict[str, bytes]:
    source, destination = _source(source), _empty(destination)
    value = _json(HERE / "input.json")
    if not isinstance(value, dict) or (value.get("schema_version"), value.get("scope")) != INPUT_ID:
        raise ValueError("synthetic input identity mismatch")

    sys.path.insert(0, str(source / "src"))
    try:
        deadline = importlib.import_module("nano_grok_build.adapter.deadline")
        artifactizer = importlib.import_module("nano_grok_build.adapter.artifactizer")
    finally:
        sys.path.pop(0)
    if any(not Path(module.__file__).resolve().is_relative_to(source) for module in (deadline, artifactizer)):
        raise ValueError("historical Python module pin mismatch")

    deadline_value, spec = value["deadline"], value["run_spec"]
    reserves = deadline.DeadlineReservesV1(**deadline_value["reserves"])
    cutoff = deadline.RunDeadlineV1.mint_harbor_agent_phase(agent_timeout_ms=deadline_value["agent_timeout_ms"], now_monotonic_ns=deadline_value["now_monotonic_ns"], reserves=reserves)
    spec_sha = artifactizer.rust_run_spec_sha256(spec)
    receipt = deadline.RunDeadlineReceiptV1.bind(deadline=cutoff, run_id=spec["run_id"], trial_id=spec["trial_id"], attempt_id=spec["attempt_id"], run_spec_sha256=spec_sha, reserves=reserves)
    runtime = destination / "runtime"
    runtime.mkdir()
    (runtime / "deadline.json").write_bytes(receipt.to_bytes())

    example = source / "crates/nano-types/examples/pr2_historical_v2_deadline_exporter.rs"
    if example.exists():
        raise ValueError("temporary exporter exists")
    try:
        shutil.copyfile(HERE / "exporter.rs", example)
        command = (
            "cargo", "run", "--quiet", "--locked", "-p", "nano-types", "--example", example.stem, "--", HERE / "input.json", spec_sha, receipt.sha256(), destination,
        )
        _run(*command, cwd=source)
    finally:
        example.unlink(missing_ok=True)
    if _git(source, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("historical source changed")
    artifactizer.publish_artifacts(logs_dir=destination, run_spec=spec, instruction=spec["task"]["instruction"], agent_name="nano-grok-build-synthetic-historical-compat", agent_version=COMMIT[:12], model_name=spec["provider"]["model"], require_harbor_validator=False)
    return _files(destination)


def _hex(value: object, size: int) -> bool:
    return isinstance(value, str) and len(value) == size and all(char in "0123456789abcdef" for char in value)


def _envelope(recipe: tuple[str, dict[str, str]], files: dict[str, bytes]) -> dict[str, object]:
    commit, digests = recipe
    return {
        "schema_version": GOLDEN_ID[0], "scope": GOLDEN_ID[1],
        "producer": PRODUCER, "recipe_commit": commit, "recipe_sha256": digests,
        "files": [
            {"path": name, "byte_length": len(files[name]), "sha256": hashlib.sha256(files[name]).hexdigest(),
             "base64": base64.b64encode(files[name]).decode()}
            for name in EXPECTED_FILES
        ],
    }


def _decode(value: object) -> tuple[tuple[str, dict[str, str]], dict[str, bytes]]:
    try:
        if (
            not isinstance(value, dict)
            or set(value) != {"schema_version", "scope", "producer", "recipe_commit", "recipe_sha256", "files"}
            or (value["schema_version"], value["scope"]) != GOLDEN_ID
            or value["producer"] != PRODUCER
        ):
            raise ValueError
        rows, commit, digests = value["files"], value["recipe_commit"], value["recipe_sha256"]
        if (
            not isinstance(rows, list) or not _hex(commit, 40) or not isinstance(digests, dict)
            or tuple(digests) != RECIPE_FILES or any(not _hex(digest, 64) for digest in digests.values())
            or any(not isinstance(row, dict) or set(row) != {"path", "byte_length", "sha256", "base64"} for row in rows)
        ):
            raise ValueError
        if [row["path"] for row in rows] != list(EXPECTED_FILES):
            raise ValueError
        files = {}
        for row in rows:
            encoded, length, digest = row["base64"], row["byte_length"], row["sha256"]
            raw = base64.b64decode(encoded, validate=True)
            if (
                not isinstance(encoded, str) or type(length) is not int or not _hex(digest, 64)
                or base64.b64encode(raw).decode() != encoded or len(raw) != length
                or hashlib.sha256(raw).hexdigest() != digest
            ):
                raise ValueError
            files[row["path"]] = raw
        return (commit, digests), files
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("golden envelope mismatch") from exc


def _recipe(recipe: tuple[str, dict[str, str]], *, prove: bool = False) -> None:
    commit, digests = recipe
    raw = {name: (HERE / name).read_bytes() for name in RECIPE_FILES}
    if {name: hashlib.sha256(data).hexdigest() for name, data in raw.items()} != digests:
        raise ValueError("recipe content mismatch")
    prefix = "tests/fixtures/tb21/historical-v2-deadline-synthetic-v1"
    if prove and any(_run("git", "-C", HERE, "show", f"{commit}:{prefix}/{name}") != raw[name] for name in RECIPE_FILES):
        raise ValueError("recipe differs from committed producer")


def materialize(destination: Path) -> None:
    recipe, files = _decode(_json(GOLDEN))
    _recipe(recipe)
    destination = _empty(destination)
    for name, raw in files.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)


def _twice(source: Path) -> dict[str, bytes]:
    with tempfile.TemporaryDirectory() as left, tempfile.TemporaryDirectory() as right:
        first, second = generate(source, Path(left)), generate(source, Path(right))
    if first != second:
        raise ValueError("historical regeneration is not deterministic")
    return first


def reconstruct(source: Path, *, write: bool) -> None:
    if write:
        if GOLDEN.exists() or _git(HERE, "status", "--porcelain", "--untracked-files=all"):
            raise ValueError("build requires clean Commit A without golden.json")
        recipe = (
            _git(HERE, "rev-parse", "HEAD"),
            {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in RECIPE_FILES},
        )
        GOLDEN.write_bytes(_canonical(_envelope(recipe, _twice(source))))
    else:
        value = _json(GOLDEN)
        recipe, _ = _decode(value)
        _recipe(recipe, prove=True)
        if _canonical(_envelope(recipe, _twice(source))) != _canonical(value):
            raise ValueError("historical regeneration differs from exact golden envelope")


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in {"build", "verify"}:
        raise SystemExit("usage: reconstruct.py {build|verify} HISTORICAL_SOURCE_TREE")
    reconstruct(Path(sys.argv[2]), write=sys.argv[1] == "build")
