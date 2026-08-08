#!/usr/bin/env python3
"""Enforce one-way imports between core, integration, and evaluation code."""

from __future__ import annotations

import argparse
import ast
import sys
from collections.abc import Iterator
from pathlib import Path

# These modules are runtime primitives even though the package has not yet been
# split physically.  Keeping the list explicit makes this first guard
# behavior-neutral; later extraction can replace it with a directory boundary.
CORE_PYTHON_FILES = (
    "src/nano_grok_build/adapter/deadline.py",
    "src/nano_grok_build/adapter/stdio_bridge.py",
    "src/nano_grok_build/adapter/terminal_actor.py",
)
CORE_PYTHON_DIRECTORIES = ("src/nano_grok_build/runtime",)

# Core may not know which benchmark or collector consumes it.  This is an
# import boundary, not a vocabulary or score-policy scan.
INTEGRATION_MODULE_PREFIXES = (
    "harbor",
    "nano_grok_build.adapter.artifactizer",
    "nano_grok_build.adapter.atif",
    "nano_grok_build.adapter.harbor",
    "nano_grok_build.adapter.workspace_snapshot",
    "nano_grok_build.evals",
    "nano_grok_build.harbor",
    "nano_grok_build.integrations",
)


def _is_integration_module(module: str) -> bool:
    return any(
        module == prefix or module.startswith(f"{prefix}.")
        for prefix in INTEGRATION_MODULE_PREFIXES
    )


def _module_name(root: Path, path: Path) -> tuple[str, bool]:
    relative = path.relative_to(root / "src").with_suffix("")
    parts = list(relative.parts)
    is_package = parts[-1] == "__init__"
    if is_package:
        parts.pop()
    return ".".join(parts), is_package


def _resolve_from_import(
    root: Path,
    path: Path,
    node: ast.ImportFrom,
) -> tuple[str, ...]:
    if node.level == 0:
        return (node.module,) if node.module else ()

    current_module, is_package = _module_name(root, path)
    package_parts = current_module.split(".")
    if not is_package:
        package_parts.pop()
    ascent = node.level - 1
    if ascent > len(package_parts):
        return ()
    if ascent:
        package_parts = package_parts[:-ascent]
    if node.module:
        return (".".join([*package_parts, *node.module.split(".")]),)
    return tuple(
        ".".join([*package_parts, alias.name])
        for alias in node.names
        if alias.name != "*"
    )


def _literal_dynamic_import(node: ast.Call) -> str | None:
    if not node.args or not isinstance(node.args[0], ast.Constant):
        return None
    value = node.args[0].value
    if not isinstance(value, str):
        return None
    if isinstance(node.func, ast.Name) and node.func.id == "__import__":
        return value
    if (
        isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "importlib"
        and node.func.attr == "import_module"
    ):
        return value
    return None


def _imports(root: Path, path: Path, tree: ast.AST) -> Iterator[tuple[int, str]]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, alias.name
        elif isinstance(node, ast.ImportFrom):
            for module in _resolve_from_import(root, path, node):
                yield node.lineno, module
        elif isinstance(node, ast.Call):
            module = _literal_dynamic_import(node)
            if module is not None:
                yield node.lineno, module


def _core_python_sources(root: Path) -> list[Path]:
    sources = {
        path for relative in CORE_PYTHON_FILES if (path := root / relative).is_file()
    }
    for relative in CORE_PYTHON_DIRECTORIES:
        directory = root / relative
        if directory.is_dir():
            sources.update(path for path in directory.rglob("*.py") if path.is_file())
    return sorted(sources)


def check_architecture_boundaries(root: Path) -> list[str]:
    """Return core-to-integration import violations without importing code."""

    resolved = root.resolve()
    errors: list[str] = []
    for path in _core_python_sources(resolved):
        relative = path.relative_to(resolved)
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(relative))
        except (OSError, UnicodeDecodeError, SyntaxError) as error:
            errors.append(f"{relative}: cannot inspect Python imports: {error}")
            continue
        for lineno, module in _imports(resolved, path, tree):
            if _is_integration_module(module):
                errors.append(
                    f"{relative}:{lineno}: core imports integration/eval module "
                    f"{module!r}"
                )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args()
    errors = check_architecture_boundaries(args.root)
    for error in errors:
        print(f"architecture boundary: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
