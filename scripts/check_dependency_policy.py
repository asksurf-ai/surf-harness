#!/usr/bin/env python3
"""Fail closed on dependencies outside the public bootstrap policy."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import unquote, urlsplit

CRATES_IO = {
    "registry+https://github.com/rust-lang/crates.io-index",
    "registry+sparse+https://index.crates.io/",
}
PYPI = {"https://pypi.org/simple"}
PYPI_ARTIFACT_HOST = "files.pythonhosted.org"
PYTHON_LOCAL_SOURCES = {"directory", "editable", "virtual"}
BUILD_BACKEND = "hatchling.build"
BUILD_REQUIREMENT = "hatchling==1.27.0"
BUILD_PACKAGE = "hatchling"
BUILD_VERSION = "1.27.0"
HATCHLING_DEPENDENCIES = {
    "packaging",
    "pathspec",
    "pluggy",
    "trove-classifiers",
}
EXPECTED_CARGO_MEMBERS = {
    "nano-cli": "crates/nano-cli",
    "nano-provider-xai": "crates/nano-provider-xai",
    "nano-runtime": "crates/nano-runtime",
    "nano-types": "crates/nano-types",
}
PYTHON_ARTIFACT_FIELDS = {"url", "hash", "size", "upload-time"}
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
CARGO_CHECKSUM = re.compile(r"^[0-9a-f]{64}$")
PYTHON_VERSION = re.compile(
    r"^[0-9]+(?:[._-]?[0-9A-Za-z]+)*(?:\+[0-9A-Za-z]+(?:[._-][0-9A-Za-z]+)*)?$"
)
FORBIDDEN_RUNTIME_PACKAGES = {
    "async-openai",
    "grok-build",
    "openai",
    "openai-api-rs",
    "openai-dive",
    "xai-sdk",
}
DEPENDENCY_TABLES = {"dependencies", "dev-dependencies", "build-dependencies"}
FORBIDDEN_PATH_SEGMENTS = {"grok-build", "our-forks"}
FORBIDDEN_SOURCE = re.compile(
    r"(?:^|[/@])(?:grok-build|our-forks|xai-[a-z0-9_.-]+)(?:$|[/?.#])"
)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _canonical_package(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _forbidden_package(name: str) -> bool:
    canonical = _canonical_package(name)
    return canonical.startswith("xai-") or canonical in FORBIDDEN_RUNTIME_PACKAGES


def _forbidden_source(source: str) -> bool:
    return FORBIDDEN_SOURCE.search(source.lower().replace("\\", "/")) is not None


def _forbidden_path(path: Path, workspace_root: Path) -> bool:
    resolved = path.resolve()
    try:
        parts = resolved.relative_to(workspace_root.resolve()).parts
    except ValueError:
        parts = resolved.parts
    for part in parts:
        canonical = _canonical_package(part)
        if canonical in FORBIDDEN_PATH_SEGMENTS or canonical.startswith("xai-"):
            return True
    return False


def check_metadata(metadata: dict[str, Any], workspace_root: Path) -> list[str]:
    """Validate resolved Cargo metadata."""
    errors: list[str] = []
    root = workspace_root.resolve()
    for package in metadata.get("packages", []):
        name = str(package.get("name", ""))
        source = package.get("source")
        manifest = Path(str(package.get("manifest_path", "")))

        if _forbidden_package(name):
            errors.append(f"forbidden package: {name}")
        if source is None:
            if not _inside(manifest, root):
                errors.append(f"path dependency outside workspace: {manifest}")
            elif _forbidden_path(manifest.parent, root):
                errors.append(f"forbidden dependency path: {manifest.parent}")
            continue

        source_text = str(source)
        if source_text.startswith("git+"):
            errors.append(f"git dependency forbidden: {name}")
        elif source_text.startswith("registry+") and source_text not in CRATES_IO:
            errors.append(f"unknown registry forbidden for {name}: {source_text}")
        elif not source_text.startswith("registry+"):
            errors.append(f"unknown dependency source for {name}: {source_text}")

        if _forbidden_source(source_text):
            errors.append(f"forbidden upstream source for {name}: {source_text}")
    return errors


def _walk_dependency_tables(
    value: Any,
    manifest_dir: Path,
    workspace_root: Path,
    workspace_paths: dict[Path, str],
    location: str,
) -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        if "git" in value:
            errors.append(f"git dependency forbidden at {location}")
            if _forbidden_source(str(value["git"])):
                errors.append(f"forbidden upstream source at {location}")
        if "registry" in value:
            errors.append(f"alternate registry forbidden at {location}")
        if "path" in value:
            path = (manifest_dir / str(value["path"])).resolve()
            if not _inside(path, workspace_root):
                errors.append(
                    f"path dependency outside workspace at {location}: {path}"
                )
            elif _forbidden_path(path, workspace_root):
                errors.append(f"forbidden dependency path at {location}: {path}")
            elif path not in workspace_paths:
                errors.append(
                    f"undeclared workspace path dependency at {location}: {path}"
                )
            else:
                declared_name = str(value.get("package", location.rsplit(".", 1)[-1]))
                if _canonical_package(declared_name) != workspace_paths[path]:
                    errors.append(
                        f"path dependency name mismatch at {location}: {declared_name}"
                    )
        for key, child in value.items():
            errors.extend(
                _walk_dependency_tables(
                    child,
                    manifest_dir,
                    workspace_root,
                    workspace_paths,
                    f"{location}.{key}",
                )
            )
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(
                _walk_dependency_tables(
                    child,
                    manifest_dir,
                    workspace_root,
                    workspace_paths,
                    f"{location}[{index}]",
                )
            )
    return errors


def _check_declared_dependency_names(value: Any, location: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, dict):
        return errors
    for key, child in value.items():
        if key in DEPENDENCY_TABLES and isinstance(child, dict):
            for alias, specification in child.items():
                package = alias
                if isinstance(specification, dict) and "package" in specification:
                    package = str(specification["package"])
                if _forbidden_package(str(package)):
                    errors.append(
                        f"forbidden declared package at {location}.{key}: {package}"
                    )
        errors.extend(_check_declared_dependency_names(child, f"{location}.{key}"))
    return errors


def _cargo_workspace_projects(
    workspace_root: Path,
) -> tuple[dict[Path, str], set[str], list[str]]:
    root = workspace_root.resolve()
    root_manifest = root / "Cargo.toml"
    try:
        data = tomllib.loads(root_manifest.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        return (
            {},
            set(),
            [f"cannot parse Cargo workspace manifest {root_manifest}: {error}"],
        )

    workspace = data.get("workspace")
    if not isinstance(workspace, dict):
        return {}, set(), [f"missing [workspace] in {root_manifest}"]
    members = workspace.get("members")
    expected_paths = set(EXPECTED_CARGO_MEMBERS.values())
    if (
        not isinstance(members, list)
        or not all(isinstance(member, str) for member in members)
        or set(members) != expected_paths
        or len(members) != len(expected_paths)
    ):
        errors = [
            "Cargo workspace members must exactly match the reviewed runtime skeleton"
        ]
    else:
        errors = []

    paths: dict[Path, str] = {}
    names: set[str] = set()
    for expected_name, relative in EXPECTED_CARGO_MEMBERS.items():
        member = (root / relative).resolve()
        if not _inside(member, root):
            errors.append(f"Cargo workspace member outside workspace: {relative}")
            continue
        manifest = member / "Cargo.toml"
        try:
            member_data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as error:
            errors.append(f"cannot parse Cargo workspace member {manifest}: {error}")
            continue
        package = member_data.get("package")
        actual_name = package.get("name") if isinstance(package, dict) else None
        if _canonical_package(str(actual_name or "")) != expected_name:
            errors.append(
                f"Cargo workspace member name mismatch: {manifest}: {actual_name}"
            )
            continue
        paths[member] = expected_name
        names.add(expected_name)
    return paths, names, errors


def check_repository_cargo_configs(workspace_root: Path) -> list[str]:
    """Reject Cargo configuration files inside the repository boundary."""
    root = workspace_root.resolve()
    errors: list[str] = []
    for cargo_directory in sorted(root.rglob(".cargo")):
        for filename in ("config", "config.toml"):
            config = cargo_directory / filename
            if config.exists() or config.is_symlink():
                errors.append(f"repository-local Cargo config forbidden: {config}")
    return errors


def check_manifests(workspace_root: Path) -> list[str]:
    """Reject Cargo source replacement and unsafe manifest dependency forms."""
    root = workspace_root.resolve()
    workspace_paths, _, workspace_errors = _cargo_workspace_projects(root)
    errors = [*check_repository_cargo_configs(root), *workspace_errors]
    for manifest in sorted(root.rglob("Cargo.toml")):
        if any(part in {"target", ".venv"} for part in manifest.parts):
            continue
        try:
            relative = manifest.resolve().relative_to(root)
        except ValueError:
            relative = manifest
        if relative.parts[:2] == ("tools", "upstream-export"):
            errors.append(f"exporter Cargo manifest forbidden: {manifest}")
            continue
        try:
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as error:
            errors.append(f"cannot parse {manifest}: {error}")
            continue
        if "patch" in data:
            errors.append(f"[patch] forbidden in {manifest}")
        if "replace" in data:
            errors.append(f"[replace] forbidden in {manifest}")
        errors.extend(
            _walk_dependency_tables(
                data, manifest.parent, root, workspace_paths, str(manifest)
            )
        )
        errors.extend(_check_declared_dependency_names(data, str(manifest)))

    return errors


def check_cargo_lock(lock_path: Path) -> list[str]:
    """Statically validate Cargo.lock without invoking Cargo or build scripts."""
    if not lock_path.exists():
        return [f"missing Cargo lock: {lock_path}"]
    try:
        lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"cannot parse Cargo lock: {error}"]

    _, workspace_names, workspace_errors = _cargo_workspace_projects(
        lock_path.resolve().parent
    )
    errors = list(workspace_errors)
    packages = lock.get("package")
    if not isinstance(packages, list):
        return [*errors, "Cargo lock package table must be an array"]
    for package in packages:
        if not isinstance(package, dict):
            errors.append("unknown Cargo lock package entry")
            continue
        name = str(package.get("name", ""))
        source = package.get("source")
        if _forbidden_package(name):
            errors.append(f"forbidden Cargo lock package: {name}")
        if source is None:
            if _canonical_package(name) not in workspace_names:
                errors.append(f"unknown local Cargo lock package: {name}")
            if "checksum" in package:
                errors.append(f"local Cargo lock package has checksum: {name}")
            continue
        source_text = str(source)
        if source_text not in CRATES_IO:
            errors.append(f"unknown Cargo lock source for {name}: {source_text}")
        checksum = package.get("checksum")
        if not isinstance(checksum, str) or not CARGO_CHECKSUM.fullmatch(checksum):
            errors.append(f"invalid Cargo lock checksum for {name}")
    return errors


def _python_project_name(data: dict[str, Any]) -> str | None:
    project = data.get("project")
    if not isinstance(project, dict):
        return None
    name = project.get("name")
    if not isinstance(name, str) or not name.strip():
        return None
    return _canonical_package(name)


def _python_workspace_projects(
    workspace_root: Path,
) -> tuple[dict[str, Path], list[str]]:
    """Return manifest-declared Python workspace package paths."""
    root = workspace_root.resolve()
    root_manifest = root / "pyproject.toml"
    if not root_manifest.exists():
        return {}, []

    errors: list[str] = []
    try:
        root_data = tomllib.loads(root_manifest.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        return {}, [f"cannot parse Python workspace manifest {root_manifest}: {error}"]

    projects: dict[str, Path] = {}
    ambiguous: set[str] = set()

    def register(name: str, path: Path) -> None:
        previous = projects.get(name)
        if previous is not None and previous != path:
            errors.append(f"duplicate Python workspace package name: {name}")
            ambiguous.add(name)
            return
        projects[name] = path

    root_name = _python_project_name(root_data)
    if root_name is not None:
        register(root_name, root)

    tool = root_data.get("tool", {})
    uv = tool.get("uv", {}) if isinstance(tool, dict) else {}
    workspace = uv.get("workspace", {}) if isinstance(uv, dict) else {}
    members = workspace.get("members", []) if isinstance(workspace, dict) else []
    if not isinstance(members, list) or not all(
        isinstance(member, str) and member for member in members
    ):
        errors.append("Python workspace members must be a list of non-empty paths")
        members = []
    exclusions = workspace.get("exclude", []) if isinstance(workspace, dict) else []
    if not isinstance(exclusions, list) or not all(
        isinstance(exclusion, str) and exclusion for exclusion in exclusions
    ):
        errors.append("Python workspace exclusions must be a list of non-empty paths")
        exclusions = []

    excluded_paths: set[Path] = set()
    for pattern in exclusions:
        if Path(pattern).is_absolute() or PureWindowsPath(pattern).is_absolute():
            errors.append(f"absolute Python workspace exclusion forbidden: {pattern}")
            continue
        try:
            candidates = root.glob(pattern)
            excluded_paths.update(
                candidate.resolve()
                for candidate in candidates
                if candidate.is_dir() and _inside(candidate, root)
            )
        except (NotImplementedError, OSError, ValueError) as error:
            errors.append(
                f"invalid Python workspace exclusion pattern {pattern}: {error}"
            )

    for pattern in members:
        if Path(pattern).is_absolute() or PureWindowsPath(pattern).is_absolute():
            errors.append(f"absolute Python workspace member forbidden: {pattern}")
            continue
        try:
            candidates = sorted(root.glob(pattern))
        except (NotImplementedError, OSError, ValueError) as error:
            errors.append(f"invalid Python workspace member pattern {pattern}: {error}")
            continue
        for candidate in candidates:
            resolved = candidate.resolve()
            if not candidate.is_dir():
                continue
            if resolved in excluded_paths:
                continue
            if not _inside(resolved, root):
                errors.append(f"Python workspace member outside workspace: {candidate}")
                continue
            member_manifest = resolved / "pyproject.toml"
            try:
                member_data = tomllib.loads(member_manifest.read_text(encoding="utf-8"))
            except (OSError, tomllib.TOMLDecodeError) as error:
                errors.append(
                    f"cannot parse Python workspace member {member_manifest}: {error}"
                )
                continue
            member_name = _python_project_name(member_data)
            if member_name is None:
                errors.append(
                    f"Python workspace member has no project name: {member_manifest}"
                )
                continue
            register(member_name, resolved)

    for name in ambiguous:
        projects.pop(name, None)
    return projects, errors


def _python_source_path(value: Any, workspace_root: Path) -> Path | None:
    if not isinstance(value, str) or not value or "\x00" in value:
        return None
    path = Path(value)
    if path.is_absolute() or PureWindowsPath(value).is_absolute():
        return None
    return (workspace_root / path).resolve()


def check_python_project(workspace_root: Path) -> list[str]:
    """Require one exact, lock-visible PEP 517 build backend declaration."""
    manifest = workspace_root.resolve() / "pyproject.toml"
    try:
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"cannot parse Python project manifest {manifest}: {error}"]

    errors: list[str] = []
    build_system = data.get("build-system")
    if not isinstance(build_system, dict):
        return ["Python build-system must be a table"]
    if build_system.get("build-backend") != BUILD_BACKEND:
        errors.append(f"Python build-backend must be exactly {BUILD_BACKEND}")
    if build_system.get("requires") != [BUILD_REQUIREMENT]:
        errors.append(
            f"Python build-system.requires must be exactly [{BUILD_REQUIREMENT}]"
        )
    unknown_build_keys = set(build_system) - {"build-backend", "requires"}
    if unknown_build_keys:
        errors.append(
            "unknown Python build-system fields: "
            + ", ".join(sorted(unknown_build_keys))
        )

    groups = data.get("dependency-groups")
    build_group = groups.get("build") if isinstance(groups, dict) else None
    if build_group != [BUILD_REQUIREMENT]:
        errors.append(
            f"Python dependency-groups.build must be exactly [{BUILD_REQUIREMENT}]"
        )
    return errors


def _valid_artifact_url(value: Any) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or any(character.isspace() or ord(character) < 32 for character in value)
    ):
        return False
    try:
        parsed = urlsplit(value)
        decoded_path = unquote(parsed.path)
        port = parsed.port
    except ValueError:
        return False
    if (
        parsed.scheme != "https"
        or parsed.netloc != PYPI_ARTIFACT_HOST
        or parsed.hostname != PYPI_ARTIFACT_HOST
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
        or not decoded_path.startswith("/packages/")
        or decoded_path.endswith("/")
        or "\\" in decoded_path
        or "//" in decoded_path
    ):
        return False
    parts = PurePosixPath(decoded_path).parts
    return ".." not in parts and "." not in parts and len(parts) >= 4


def _check_python_artifact(artifact: Any, location: str) -> list[str]:
    if not isinstance(artifact, dict):
        return [f"malformed Python artifact at {location}"]
    errors: list[str] = []
    fields = set(artifact)
    if fields != PYTHON_ARTIFACT_FIELDS:
        errors.append(
            f"Python artifact fields at {location} must be exactly "
            + ", ".join(sorted(PYTHON_ARTIFACT_FIELDS))
        )
    if not _valid_artifact_url(artifact.get("url")):
        errors.append(f"unsafe Python artifact URL at {location}")
    artifact_hash = artifact.get("hash")
    if not isinstance(artifact_hash, str) or not SHA256.fullmatch(artifact_hash):
        errors.append(f"invalid Python artifact SHA-256 at {location}")
    size = artifact.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        errors.append(f"invalid Python artifact size at {location}")
    upload_time = artifact.get("upload-time")
    if not isinstance(upload_time, str):
        errors.append(f"invalid Python artifact upload time at {location}")
    else:
        try:
            dt.datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
        except ValueError:
            errors.append(f"invalid Python artifact upload time at {location}")
    return errors


def _check_registry_artifacts(package: dict[str, Any], name: str) -> list[str]:
    errors: list[str] = []
    artifact_count = 0
    if "sdist" in package:
        artifact_count += 1
        errors.extend(_check_python_artifact(package["sdist"], f"{name}.sdist"))
    if "wheels" in package:
        wheels = package["wheels"]
        if not isinstance(wheels, list) or not wheels:
            errors.append(f"malformed Python wheels for {name}")
        else:
            artifact_count += len(wheels)
            for index, wheel in enumerate(wheels):
                errors.extend(_check_python_artifact(wheel, f"{name}.wheels[{index}]"))
    if artifact_count == 0:
        errors.append(f"registry package has no verified artifacts: {name}")
    return errors


def _build_policy_is_exact(workspace_root: Path) -> bool:
    return check_python_project(workspace_root) == []


def _check_locked_build_graph(
    packages: list[dict[str, Any]], workspace_root: Path
) -> list[str]:
    if not _build_policy_is_exact(workspace_root):
        return []
    errors: list[str] = []
    project_data = tomllib.loads(
        (workspace_root / "pyproject.toml").read_text(encoding="utf-8")
    )
    root_name = _python_project_name(project_data)
    root_packages = [
        package
        for package in packages
        if _canonical_package(str(package.get("name", ""))) == root_name
        and package.get("source") == {"editable": "."}
    ]
    if len(root_packages) != 1:
        return ["Python lock must contain exactly one editable root project"]
    root_package = root_packages[0]
    dev_dependencies = root_package.get("dev-dependencies")
    locked_build = (
        dev_dependencies.get("build") if isinstance(dev_dependencies, dict) else None
    )
    if locked_build != [{"name": BUILD_PACKAGE}]:
        errors.append("Python lock root build dependency edge is not exact")
    metadata = root_package.get("metadata")
    requires_dev = metadata.get("requires-dev") if isinstance(metadata, dict) else None
    metadata_build = (
        requires_dev.get("build") if isinstance(requires_dev, dict) else None
    )
    if metadata_build != [{"name": BUILD_PACKAGE, "specifier": f"=={BUILD_VERSION}"}]:
        errors.append("Python lock root build requirement metadata is not exact")

    hatchling_packages = [
        package
        for package in packages
        if _canonical_package(str(package.get("name", ""))) == BUILD_PACKAGE
        and str(package.get("version", "")) == BUILD_VERSION
        and package.get("source") == {"registry": "https://pypi.org/simple"}
    ]
    if len(hatchling_packages) != 1:
        errors.append(f"Python lock must contain exact {BUILD_REQUIREMENT}")
        return errors
    dependencies = hatchling_packages[0].get("dependencies")
    dependency_names = (
        {
            _canonical_package(str(dependency.get("name", "")))
            for dependency in dependencies
            if isinstance(dependency, dict)
        }
        if isinstance(dependencies, list)
        else set()
    )
    if dependency_names != HATCHLING_DEPENDENCIES:
        errors.append("locked hatchling transitive dependency set is not exact")
    package_names = {
        _canonical_package(str(package.get("name", ""))) for package in packages
    }
    missing = sorted(HATCHLING_DEPENDENCIES - package_names)
    if missing:
        errors.append("missing locked hatchling transitives: " + ", ".join(missing))
    return errors


def check_python_lock(lock_path: Path) -> list[str]:
    """Validate uv's resolved sources without importing third-party code."""
    if not lock_path.exists():
        return [f"missing Python lock: {lock_path}"]
    try:
        lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        return [f"cannot parse Python lock: {error}"]

    workspace_root = lock_path.resolve().parent
    workspace_projects, workspace_errors = _python_workspace_projects(workspace_root)
    errors: list[str] = list(workspace_errors)
    packages = lock.get("package", [])
    if not isinstance(packages, list):
        return [*errors, "Python lock package table must be an array"]

    typed_packages: list[dict[str, Any]] = []
    for package in packages:
        if not isinstance(package, dict):
            errors.append("unknown Python package entry")
            continue
        typed_packages.append(package)
        name = str(package.get("name", ""))
        source = package.get("source")
        if _forbidden_package(name):
            errors.append(f"forbidden Python package: {name}")
        if not isinstance(source, dict):
            errors.append(f"unknown Python source for {name}")
            continue

        if len(source) != 1:
            errors.append(f"unknown Python source for {name}")
            continue
        kind, value = next(iter(source.items()))

        if kind == "registry":
            if value not in PYPI:
                errors.append(f"unknown Python registry for {name}: {value}")
            else:
                version = package.get("version")
                if not isinstance(version, str) or not PYTHON_VERSION.fullmatch(
                    version
                ):
                    errors.append(f"invalid Python registry version for {name}")
                errors.extend(_check_registry_artifacts(package, name))
        elif kind in PYTHON_LOCAL_SOURCES:
            resolved = _python_source_path(value, workspace_root)
            expected = workspace_projects.get(_canonical_package(name))
            if resolved is None or expected is None or resolved != expected:
                errors.append(
                    f"Python {kind} source forbidden for {name}: "
                    "not an allowlisted workspace member"
                )
        elif kind == "git":
            errors.append(f"Python git source forbidden: {name}")
            if _forbidden_source(str(value)):
                errors.append(f"forbidden Python upstream source: {name}")
        elif kind == "url":
            errors.append(f"Python direct URL source forbidden: {name}")
            if _forbidden_source(str(value)):
                errors.append(f"forbidden Python upstream source: {name}")
        elif kind == "path":
            errors.append(f"Python path source forbidden: {name}")
        else:
            errors.append(f"unknown Python source for {name}: {kind}")
    errors.extend(_check_locked_build_graph(typed_packages, workspace_root))
    return errors


def resolved_metadata(root: Path) -> dict[str, Any]:
    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args()
    root = args.root.resolve()
    static_errors = [
        *check_manifests(root),
        *check_cargo_lock(root / "Cargo.lock"),
        *check_python_project(root),
        *check_python_lock(root / "uv.lock"),
    ]
    if static_errors:
        for error in static_errors:
            print(f"dependency policy: {error}", file=sys.stderr)
        return 1
    try:
        metadata = resolved_metadata(root)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        print(f"dependency policy: cargo metadata failed: {error}", file=sys.stderr)
        return 1

    errors = check_metadata(metadata, root)
    for error in errors:
        print(f"dependency policy: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
