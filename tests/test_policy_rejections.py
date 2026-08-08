from __future__ import annotations

import http.server
import shutil
import tempfile
import threading
import unittest
from pathlib import Path

from scripts import check_dependency_policy as policy
from scripts.check_dependency_policy import (
    check_manifests,
    check_metadata,
    check_python_lock,
)

ROOT = Path(__file__).resolve().parents[1]
VALID_HASH = "sha256:" + ("a" * 64)
VALID_SDIST = (
    'sdist = { url = "https://files.pythonhosted.org/packages/aa/bb/'
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc/"
    'ordinary-1.0.0.tar.gz", '
    f'hash = "{VALID_HASH}", size = 123, '
    'upload-time = "2025-01-01T00:00:00Z" }'
)
VALID_WHEEL = (
    'wheels = [{ url = "https://files.pythonhosted.org/packages/aa/bb/'
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd/"
    'ordinary-1.0.0-py3-none-any.whl", '
    f'hash = "{VALID_HASH}", size = 456, '
    'upload-time = "2025-01-01T00:00:00Z" }]'
)


def write_build_project(
    root: Path,
    *,
    requires: str | None = '["hatchling==1.27.0"]',
    backend: str | None = '"hatchling.build"',
    build_group: str | None = '["hatchling==1.27.0"]',
) -> None:
    lines = ["[build-system]"]
    if requires is not None:
        lines.append(f"requires = {requires}")
    if backend is not None:
        lines.append(f"build-backend = {backend}")
    lines.extend(
        [
            "",
            "[project]",
            'name = "nano-grok-build"',
            'version = "0.0.0"',
            "",
            "[dependency-groups]",
            'dev = ["pytest==8.4.1"]',
        ]
    )
    if build_group is not None:
        lines.append(f"build = {build_group}")
    (root / "pyproject.toml").write_text("\n".join(lines) + "\n")


def registry_package(
    *,
    name: str = "ordinary",
    version: str = "1.0.0",
    source: str = '{ registry = "https://pypi.org/simple" }',
    artifacts: str = VALID_SDIST,
    dependencies: str = "",
) -> str:
    dependency_text = f"dependencies = {dependencies}\n" if dependencies else ""
    artifact_text = f"{artifacts}\n" if artifacts else ""
    return (
        "[[package]]\n"
        f'name = "{name}"\n'
        f'version = "{version}"\n'
        f"source = {source}\n"
        f"{dependency_text}"
        f"{artifact_text}"
    )


def locked_build_graph() -> str:
    transitive_names = ("packaging", "pathspec", "pluggy", "trove-classifiers")
    packages = [
        'version = 1\nrevision = 2\nrequires-python = "==3.12.*"\n',
        "[[package]]\n"
        'name = "nano-grok-build"\n'
        'version = "0.0.0"\n'
        'source = { editable = "." }\n'
        "[package.dev-dependencies]\n"
        'build = [{ name = "hatchling" }]\n'
        "[package.metadata]\n"
        "[package.metadata.requires-dev]\n"
        'build = [{ name = "hatchling", specifier = "==1.27.0" }]\n',
        registry_package(
            name="hatchling",
            version="1.27.0",
            dependencies=(
                "["
                + ", ".join(f'{{ name = "{name}" }}' for name in transitive_names)
                + "]"
            ),
        ),
    ]
    packages.extend(registry_package(name=name) for name in transitive_names)
    return "\n".join(packages)


class CountingHandler(http.server.BaseHTTPRequestHandler):
    requests = 0

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        type(self).requests += 1
        self.send_response(500)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        del format, args


def metadata(root: Path, extra: dict[str, object] | None = None) -> dict[str, object]:
    packages: list[dict[str, object]] = [
        {
            "name": "nano-types",
            "source": None,
            "manifest_path": str(root / "crates/nano-types/Cargo.toml"),
        }
    ]
    if extra:
        packages.append(extra)
    return {
        "workspace_root": str(root),
        "workspace_members": ["nano-types 0.0.0"],
        "packages": packages,
    }


def copy_cargo_workspace(destination: Path) -> None:
    shutil.copy2(ROOT / "Cargo.toml", destination / "Cargo.toml")
    shutil.copytree(ROOT / "crates", destination / "crates")


class DependencyPolicyRejectionTests(unittest.TestCase):
    def test_build_backend_must_be_exact_hatchling(self) -> None:
        cases = {
            "missing": None,
            "setuptools": '"setuptools.build_meta"',
            "hatchling-prefix": '"hatchling.build:build_wheel"',
            "trailing-space": '"hatchling.build "',
            "non-string": "27",
        }
        for label, backend in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                write_build_project(root, backend=backend)
                errors = policy.check_python_project(root)
                self.assertTrue(any("build-backend" in error for error in errors))

    def test_build_system_requires_rejects_every_nonexact_form(self) -> None:
        cases = {
            "missing": None,
            "empty": "[]",
            "multiple": '["hatchling==1.27.0", "packaging==24.2"]',
            "unpinned": '["hatchling"]',
            "range": '["hatchling>=1.27.0"]',
            "direct-http": '["hatchling @ http://127.0.0.1/pkg.whl"]',
            "git": '["hatchling @ git+https://example.invalid/repo"]',
            "path": '["hatchling @ file:///tmp/hatchling.whl"]',
            "marker": "[\"hatchling==1.27.0; python_version >= '3.12'\"]",
            "extra": '["hatchling[foo]==1.27.0"]',
            "unknown": '["setuptools==75.0.0"]',
        }
        for label, requires in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                write_build_project(root, requires=requires)
                errors = policy.check_python_project(root)
                self.assertTrue(
                    any("build-system.requires" in error for error in errors)
                )

    def test_build_dependency_group_rejects_every_nonexact_form(self) -> None:
        cases = {
            "missing": None,
            "empty": "[]",
            "multiple": '["hatchling==1.27.0", "packaging==24.2"]',
            "unpinned": '["hatchling"]',
            "wrong-version": '["hatchling==1.26.3"]',
            "direct-url": '["hatchling @ https://example.invalid/pkg.whl"]',
            "unknown": '["setuptools==75.0.0"]',
        }
        for label, build_group in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                write_build_project(root, build_group=build_group)
                errors = policy.check_python_project(root)
                self.assertTrue(
                    any("dependency-groups.build" in error for error in errors)
                )

    def test_exact_build_manifest_and_locked_graph_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_build_project(root)
            (root / "uv.lock").write_text(locked_build_graph())
            self.assertEqual(policy.check_python_project(root), [])
            self.assertEqual(check_python_lock(root / "uv.lock"), [])

    def test_lock_must_bind_exact_build_group_and_hatchling_graph(self) -> None:
        mutations = {
            "missing-root-edge": (
                '[package.dev-dependencies]\nbuild = [{ name = "hatchling" }]\n',
                "",
            ),
            "wrong-build-version": ('specifier = "==1.27.0"', 'specifier = "==1.26.3"'),
            "missing-hatchling": ('name = "hatchling"', 'name = "not-hatchling"'),
            "wrong-hatchling-version": ('version = "1.27.0"', 'version = "1.26.3"'),
            "missing-transitive-edge": (
                '{ name = "trove-classifiers" }',
                '{ name = "not-a-transitive" }',
            ),
        }
        for label, (before, after) in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                write_build_project(root)
                lock = root / "uv.lock"
                lock.write_text(locked_build_graph().replace(before, after, 1))
                self.assertTrue(check_python_lock(lock))

    def test_direct_build_url_fails_policy_without_request(self) -> None:
        CountingHandler.requests = 0
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CountingHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                url = f"http://127.0.0.1:{server.server_port}/hatchling.whl"
                write_build_project(root, requires=f'["hatchling @ {url}"]')
                errors = policy.check_python_project(root)
                self.assertTrue(
                    any("build-system.requires" in error for error in errors)
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        self.assertEqual(CountingHandler.requests, 0)

    def test_clean_workspace_metadata_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(check_metadata(metadata(Path(tmp)), Path(tmp)), [])

    def test_private_git_dependency_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            errors = check_metadata(
                metadata(
                    root,
                    {
                        "name": "remote",
                        "source": "git+ssh://git@private.example.invalid/repo?rev=abc",
                        "manifest_path": str(root / "registry/remote/Cargo.toml"),
                    },
                ),
                root,
            )
            self.assertTrue(any("git dependency" in error for error in errors))

    def test_non_crates_registry_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            errors = check_metadata(
                metadata(
                    root,
                    {
                        "name": "remote",
                        "source": "registry+https://packages.example.invalid/index",
                        "manifest_path": str(root / "registry/remote/Cargo.toml"),
                    },
                ),
                root,
            )
            self.assertTrue(any("registry" in error for error in errors))

    def test_external_path_dependency_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            external = Path(tmp) / "external/Cargo.toml"
            errors = check_metadata(
                metadata(
                    root,
                    {
                        "name": "external",
                        "source": None,
                        "manifest_path": str(external),
                    },
                ),
                root,
            )
            self.assertTrue(any("outside workspace" in error for error in errors))

    def test_forbidden_grok_xai_or_sdk_package_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("grok-build", "xai-private", "async-openai"):
                errors = check_metadata(
                    metadata(
                        root,
                        {
                            "name": name,
                            "source": "registry+https://github.com/rust-lang/crates.io-index",
                            "manifest_path": str(root / f"registry/{name}/Cargo.toml"),
                        },
                    ),
                    root,
                )
                self.assertTrue(any("forbidden package" in error for error in errors))

    def test_public_crates_io_package_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            errors = check_metadata(
                metadata(
                    root,
                    {
                        "name": "ordinary-public-crate",
                        "source": "registry+https://github.com/rust-lang/crates.io-index",
                        "manifest_path": str(
                            root / "registry/ordinary-public-crate/Cargo.toml"
                        ),
                    },
                ),
                root,
            )
            self.assertEqual(errors, [])

    def test_github_xai_upstream_git_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            errors = check_metadata(
                metadata(
                    root,
                    {
                        "name": "upstream",
                        "source": (
                            "git+https://github.com/xai-org/grok-build"
                            "?rev=a5727c5960452e7527a154b25cb5bf00cda0545e"
                        ),
                        "manifest_path": str(root / "registry/upstream/Cargo.toml"),
                    },
                ),
                root,
            )
            self.assertTrue(any("git dependency" in error for error in errors))
            self.assertTrue(any("upstream source" in error for error in errors))

    def test_patch_and_replace_with_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                "[workspace]\nmembers=[]\n[patch.crates-io]\nfoo={path='foo'}\n"
            )
            (root / ".cargo").mkdir()
            (root / ".cargo/config.toml").write_text(
                "[source.crates-io]\nreplace-with='mirror'\n"
            )
            errors = check_manifests(root)
            self.assertTrue(any("[patch]" in error for error in errors))
            self.assertTrue(
                any(
                    "repository-local Cargo config forbidden" in error
                    for error in errors
                )
            )

    def test_every_repository_cargo_config_form_fails(self) -> None:
        cases = {
            "legacy-config": (
                ".cargo/config",
                "[build]\nincremental = false\n",
            ),
            "modern-config": (
                ".cargo/config.toml",
                "[net]\noffline = true\n",
            ),
            "paths": (
                ".cargo/config.toml",
                'paths = ["vendor/override"]\n',
            ),
            "rustc-wrapper": (
                ".cargo/config.toml",
                '[build]\nrustc-wrapper = "tools/wrapper"\n',
            ),
            "target-linker": (
                ".cargo/config.toml",
                '[target.aarch64-apple-darwin]\nlinker = "tools/linker"\n',
            ),
            "source-replacement": (
                ".cargo/config.toml",
                "[source.crates-io]\n"
                'replace-with = "mirror"\n'
                "[source.mirror]\n"
                'registry = "https://example.invalid/index"\n',
            ),
            "nested-member": (
                "crates/nano-types/.cargo/config.toml",
                '[build]\nrustc-wrapper = "member-wrapper"\n',
            ),
        }
        for label, (relative, content) in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                copy_cargo_workspace(root)
                config = root / relative
                config.parent.mkdir(parents=True, exist_ok=True)
                config.write_text(content)
                errors = check_manifests(root)
                self.assertTrue(
                    any(
                        "repository-local Cargo config forbidden" in error
                        and str(config) in error
                        for error in errors
                    )
                )

    def test_empty_repository_cargo_directory_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            copy_cargo_workspace(root)
            (root / ".cargo").mkdir()
            self.assertEqual(check_manifests(root), [])

    def test_cargo_config_outside_repository_is_not_inspected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temporary = Path(tmp)
            root = temporary / "repository"
            root.mkdir()
            copy_cargo_workspace(root)
            outside = temporary / ".cargo"
            outside.mkdir()
            (outside / "config.toml").write_text(
                '[build]\nrustc-wrapper = "user-controlled-wrapper"\n'
            )
            self.assertEqual(check_manifests(root), [])

    def test_upstream_and_fork_paths_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                "[workspace]\nmembers=[]\n"
                "[workspace.dependencies]\n"
                "upstream={path='vendor/grok-build'}\n"
                "fork={path='vendor/our-forks/fork'}\n"
            )
            errors = check_manifests(root)
            self.assertTrue(
                any("forbidden dependency path" in error for error in errors)
            )

    def test_python_grok_and_xai_packages_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "uv.lock"
            lock.write_text(
                "version = 1\n"
                '[[package]]\nname = "grok-build"\n'
                'source = { registry = "https://pypi.org/simple" }\n'
                '[[package]]\nname = "xai-private"\n'
                'source = { registry = "https://pypi.org/simple" }\n'
            )
            errors = check_python_lock(lock)
            self.assertEqual(
                sum("forbidden Python package" in error for error in errors),
                2,
            )

    def test_python_git_source_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "uv.lock"
            lock.write_text(
                'version = 1\n[[package]]\nname = "bad"\n'
                'source = { git = "https://example.invalid/repo" }\n'
            )
            self.assertTrue(
                any("git source" in error for error in check_python_lock(lock))
            )

    def test_python_registry_requires_exact_pypi_index(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "uv.lock"
            lock.write_text(
                'version = 1\n[[package]]\nname = "ordinary-public-package"\n'
                'source = { registry = "https://pypi.org/simple/" }\n'
            )
            self.assertTrue(
                any("registry" in error for error in check_python_lock(lock))
            )

    def test_python_ordinary_public_package_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "uv.lock"
            lock.write_text(
                'version = 1\n[[package]]\nname = "ordinary-public-package"\n'
                'version = "1.0.0"\n'
                'source = { registry = "https://pypi.org/simple" }\n'
                f"{VALID_SDIST}\n"
            )
            self.assertEqual(check_python_lock(lock), [])

    def test_registry_artifacts_reject_unsafe_or_malformed_forms(self) -> None:
        cases = {
            "non-https": VALID_SDIST.replace("https://", "http://"),
            "wrong-host": VALID_SDIST.replace(
                "files.pythonhosted.org", "packages.example.invalid"
            ),
            "host-suffix": VALID_SDIST.replace(
                "files.pythonhosted.org", "files.pythonhosted.org.example.invalid"
            ),
            "missing-path": VALID_SDIST.replace(
                "/packages/aa/bb/"
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc/"
                "ordinary-1.0.0.tar.gz",
                "/",
            ),
            "query": VALID_SDIST.replace(".tar.gz", ".tar.gz?download=1"),
            "missing-hash": VALID_SDIST.replace(f', hash = "{VALID_HASH}"', ""),
            "wrong-hash-kind": VALID_SDIST.replace("sha256:", "md5:"),
            "short-hash": VALID_SDIST.replace("a" * 64, "a" * 63),
            "unknown-field": VALID_SDIST.replace(
                ", size = 123", ', signature = "untrusted", size = 123'
            ),
            "malformed-sdist": 'sdist = "not-a-table"',
            "malformed-wheels": 'wheels = { url = "not-a-list" }',
            "no-artifacts": "",
        }
        for label, artifacts in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                lock = Path(tmp) / "uv.lock"
                lock.write_text(
                    "version = 1\n"
                    + registry_package(
                        name="ordinary-public-package", artifacts=artifacts
                    )
                )
                self.assertTrue(check_python_lock(lock))

    def test_registry_version_must_be_structured(self) -> None:
        for version in ("", "latest", "1.0 @ https://example.invalid", "1.0/evil"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as tmp:
                lock = Path(tmp) / "uv.lock"
                lock.write_text(
                    "version = 1\n"
                    + registry_package(name="ordinary-public-package", version=version)
                )
                self.assertTrue(
                    any(
                        "registry version" in error for error in check_python_lock(lock)
                    )
                )

    def test_malicious_artifact_host_fails_without_request(self) -> None:
        CountingHandler.requests = 0
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CountingHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                lock = Path(tmp) / "uv.lock"
                url = f"http://127.0.0.1:{server.server_port}/ordinary-1.0.0.tar.gz"
                artifact = (
                    f'sdist = {{ url = "{url}", hash = "{VALID_HASH}", '
                    'size = 123, upload-time = "2025-01-01T00:00:00Z" }'
                )
                lock.write_text(
                    "version = 1\n"
                    + registry_package(
                        name="ordinary-public-package", artifacts=artifact
                    )
                )
                self.assertTrue(check_python_lock(lock))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        self.assertEqual(CountingHandler.requests, 0)

    def test_registry_package_accepts_sdist_wheel_or_both(self) -> None:
        for artifacts in (VALID_SDIST, VALID_WHEEL, f"{VALID_SDIST}\n{VALID_WHEEL}"):
            with (
                self.subTest(artifacts=artifacts),
                tempfile.TemporaryDirectory() as tmp,
            ):
                lock = Path(tmp) / "uv.lock"
                lock.write_text(
                    "version = 1\n"
                    + registry_package(
                        name="ordinary-public-package", artifacts=artifacts
                    )
                )
                self.assertEqual(check_python_lock(lock), [])

    def test_python_absolute_directory_source_outside_workspace_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "workspace"
            root.mkdir()
            lock = root / "uv.lock"
            lock.write_text(
                'version = 1\n[[package]]\nname = "bad"\n'
                f'source = {{ directory = "{Path(tmp).as_posix()}/external" }}\n'
            )
            self.assertTrue(
                any("directory source" in error for error in check_python_lock(lock))
            )

    def test_python_relative_directory_source_outside_workspace_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "workspace"
            root.mkdir()
            lock = root / "uv.lock"
            lock.write_text(
                'version = 1\n[[package]]\nname = "bad"\n'
                'source = { directory = "../external" }\n'
            )
            self.assertTrue(
                any("directory source" in error for error in check_python_lock(lock))
            )

    def test_python_editable_source_outside_workspace_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "workspace"
            root.mkdir()
            lock = root / "uv.lock"
            lock.write_text(
                'version = 1\n[[package]]\nname = "bad"\n'
                'source = { editable = "../external" }\n'
            )
            self.assertTrue(
                any("editable source" in error for error in check_python_lock(lock))
            )

    def test_python_virtual_source_outside_workspace_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "workspace"
            root.mkdir()
            lock = root / "uv.lock"
            lock.write_text(
                'version = 1\n[[package]]\nname = "bad"\n'
                'source = { virtual = "../external" }\n'
            )
            self.assertTrue(
                any("virtual source" in error for error in check_python_lock(lock))
            )

    def test_python_path_source_outside_workspace_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "workspace"
            root.mkdir()
            lock = root / "uv.lock"
            lock.write_text(
                'version = 1\n[[package]]\nname = "bad"\n'
                'source = { path = "../external/bad.whl" }\n'
            )
            self.assertTrue(
                any("path source" in error for error in check_python_lock(lock))
            )

    def test_python_absolute_path_source_outside_workspace_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "workspace"
            root.mkdir()
            lock = root / "uv.lock"
            lock.write_text(
                'version = 1\n[[package]]\nname = "bad"\n'
                f'source = {{ path = "{Path(tmp).as_posix()}/external/bad.whl" }}\n'
            )
            self.assertTrue(
                any("path source" in error for error in check_python_lock(lock))
            )

    def test_python_file_url_outside_workspace_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "workspace"
            root.mkdir()
            lock = root / "uv.lock"
            external = (Path(tmp) / "external/bad.whl").as_uri()
            lock.write_text(
                'version = 1\n[[package]]\nname = "bad"\n'
                f'source = {{ url = "{external}" }}\n'
            )
            self.assertTrue(
                any("URL source" in error for error in check_python_lock(lock))
            )

    def test_python_unknown_source_field_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "uv.lock"
            lock.write_text(
                'version = 1\n[[package]]\nname = "bad"\n'
                'source = { mirror = "https://example.invalid/simple" }\n'
            )
            self.assertTrue(
                any(
                    "unknown Python source" in error
                    for error in check_python_lock(lock)
                )
            )

    def test_python_missing_source_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "uv.lock"
            lock.write_text('version = 1\n[[package]]\nname = "bad"\n')
            self.assertTrue(
                any(
                    "unknown Python source" in error
                    for error in check_python_lock(lock)
                )
            )

    def test_python_unlisted_workspace_editable_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text(
                '[project]\nname = "root-project"\nversion = "0.0.0"\n'
            )
            lock = root / "uv.lock"
            lock.write_text(
                'version = 1\n[[package]]\nname = "unlisted"\n'
                'source = { editable = "packages/unlisted" }\n'
            )
            self.assertTrue(
                any("editable source" in error for error in check_python_lock(lock))
            )

    def test_python_root_project_is_explicitly_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text(
                '[project]\nname = "root-project"\nversion = "0.0.0"\n'
            )
            lock = root / "uv.lock"
            lock.write_text(
                'version = 1\n[[package]]\nname = "root-project"\n'
                'source = { editable = "." }\n'
            )
            self.assertEqual(check_python_lock(lock), [])

    def test_python_virtual_root_project_is_explicitly_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text(
                '[project]\nname = "root-project"\nversion = "0.0.0"\n'
            )
            lock = root / "uv.lock"
            lock.write_text(
                'version = 1\n[[package]]\nname = "root-project"\n'
                'source = { virtual = "." }\n'
            )
            self.assertEqual(check_python_lock(lock), [])

    def test_python_root_editable_name_must_match_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text(
                '[project]\nname = "root-project"\nversion = "0.0.0"\n'
            )
            lock = root / "uv.lock"
            lock.write_text(
                'version = 1\n[[package]]\nname = "ordinary-public-package"\n'
                'source = { editable = "." }\n'
            )
            self.assertTrue(
                any("editable source" in error for error in check_python_lock(lock))
            )

    def test_python_explicit_workspace_member_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            member = root / "packages/member"
            member.mkdir(parents=True)
            (root / "pyproject.toml").write_text(
                '[project]\nname = "root-project"\nversion = "0.0.0"\n'
                '[tool.uv.workspace]\nmembers = ["packages/member"]\n'
            )
            (member / "pyproject.toml").write_text(
                '[project]\nname = "workspace-member"\nversion = "0.0.0"\n'
            )
            lock = root / "uv.lock"
            lock.write_text(
                'version = 1\n[[package]]\nname = "workspace-member"\n'
                'source = { editable = "packages/member" }\n'
            )
            self.assertEqual(check_python_lock(lock), [])

    def test_python_explicit_virtual_workspace_member_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            member = root / "packages/member"
            member.mkdir(parents=True)
            (root / "pyproject.toml").write_text(
                '[project]\nname = "root-project"\nversion = "0.0.0"\n'
                '[tool.uv.workspace]\nmembers = ["packages/member"]\n'
            )
            (member / "pyproject.toml").write_text(
                '[project]\nname = "workspace-member"\nversion = "0.0.0"\n'
            )
            lock = root / "uv.lock"
            lock.write_text(
                'version = 1\n[manifest]\nmembers = ["workspace-member"]\n'
                '[[package]]\nname = "workspace-member"\n'
                'source = { virtual = "packages/member" }\n'
            )
            self.assertEqual(check_python_lock(lock), [])

    def test_python_workspace_member_name_must_match_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            member = root / "packages/member"
            member.mkdir(parents=True)
            (root / "pyproject.toml").write_text(
                '[project]\nname = "root-project"\nversion = "0.0.0"\n'
                '[tool.uv.workspace]\nmembers = ["packages/member"]\n'
            )
            (member / "pyproject.toml").write_text(
                '[project]\nname = "workspace-member"\nversion = "0.0.0"\n'
            )
            lock = root / "uv.lock"
            lock.write_text(
                'version = 1\n[[package]]\nname = "spoofed-member"\n'
                'source = { editable = "packages/member" }\n'
            )
            self.assertTrue(
                any("editable source" in error for error in check_python_lock(lock))
            )

    def test_python_excluded_workspace_member_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            member = root / "packages/excluded"
            member.mkdir(parents=True)
            (root / "pyproject.toml").write_text(
                '[project]\nname = "root-project"\nversion = "0.0.0"\n'
                "[tool.uv.workspace]\n"
                'members = ["packages/*"]\n'
                'exclude = ["packages/excluded"]\n'
            )
            (member / "pyproject.toml").write_text(
                '[project]\nname = "excluded-member"\nversion = "0.0.0"\n'
            )
            lock = root / "uv.lock"
            lock.write_text(
                'version = 1\n[[package]]\nname = "excluded-member"\n'
                'source = { virtual = "packages/excluded" }\n'
            )
            self.assertTrue(
                any("virtual source" in error for error in check_python_lock(lock))
            )

    def test_python_source_cannot_mix_registry_and_editable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text(
                '[project]\nname = "root-project"\nversion = "0.0.0"\n'
            )
            lock = root / "uv.lock"
            lock.write_text(
                'version = 1\n[[package]]\nname = "root-project"\n'
                'source = { registry = "https://pypi.org/simple", editable = "." }\n'
            )
            self.assertTrue(
                any(
                    "unknown Python source" in error
                    for error in check_python_lock(lock)
                )
            )


if __name__ == "__main__":
    unittest.main()
