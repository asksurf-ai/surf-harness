from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.check_architecture_boundaries import check_architecture_boundaries

ROOT = Path(__file__).resolve().parents[1]


class ArchitectureBoundaryTests(unittest.TestCase):
    def write_core(self, root: Path, source: str) -> Path:
        path = root / "src/nano_grok_build/runtime/worker.py"
        path.parent.mkdir(parents=True)
        path.write_text(source, encoding="utf-8")
        return path

    def test_repository_boundaries_pass(self) -> None:
        self.assertEqual(check_architecture_boundaries(ROOT), [])

    def test_core_cannot_import_internal_harbor_integration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_core(root, "from nano_grok_build.harbor import tb21\n")
            errors = check_architecture_boundaries(root)
            self.assertTrue(any("nano_grok_build.harbor" in error for error in errors))

    def test_core_cannot_import_external_harbor_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_core(root, "from harbor.models import Trial\n")
            errors = check_architecture_boundaries(root)
            self.assertTrue(any("'harbor.models'" in error for error in errors))

    def test_relative_integration_import_is_resolved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_core(root, "from ..harbor import dispatch\n")
            errors = check_architecture_boundaries(root)
            self.assertTrue(any("nano_grok_build.harbor" in error for error in errors))

    def test_integration_may_import_core(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_core(root, "from pathlib import Path\n")
            integration = root / "src/nano_grok_build/harbor/dispatch.py"
            integration.parent.mkdir(parents=True)
            integration.write_text(
                "from nano_grok_build.runtime.worker import Path\n",
                encoding="utf-8",
            )
            self.assertEqual(check_architecture_boundaries(root), [])

    def test_core_syntax_failure_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_core(root, "from (\n")
            errors = check_architecture_boundaries(root)
            self.assertTrue(
                any("cannot inspect Python imports" in error for error in errors)
            )


if __name__ == "__main__":
    unittest.main()
