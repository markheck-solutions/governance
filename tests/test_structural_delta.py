from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from governance_eval.structural import scan_structural_metrics, structural_delta


class StructuralDeltaTests(unittest.TestCase):
    def test_delta_splits_existing_introduced_removed_and_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            head = root / "head"
            _write(base / "src/pkg/a.py", "from pkg._private import _old\n\n\ndef stable():\n    return _old()\n")
            _write(base / "src/pkg/_private.py", "def _old():\n    return 1\n")
            _write(head / "src/pkg/a.py", "from pkg._private import _old\nfrom pkg._private import _new\n\n\ndef stable():\n    return _old()\n")
            _write(head / "src/pkg/_private.py", "def _old():\n    return 1\n\n\ndef _new():\n    return 2\n")

            delta = structural_delta(scan_structural_metrics(base), scan_structural_metrics(head))

        private = delta["cross_module_private_references"]
        self.assertEqual(private["status"], "MEASURED")
        self.assertTrue(private["existing"])
        self.assertTrue(private["introduced"])

    def test_package_qualified_three_node_cycle_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "src/demo/a.py", "import demo.b\n")
            _write(root / "src/demo/b.py", "import demo.c\n")
            _write(root / "src/demo/c.py", "import demo.a\n")

            metrics = scan_structural_metrics(root)

        self.assertIn("demo.a->demo.b->demo.c->demo.a", metrics["import_cycles"])

    def test_relative_import_cycle_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "src/demo/__init__.py", "")
            _write(root / "src/demo/a.py", "from . import b\n")
            _write(root / "src/demo/b.py", "from . import a\n")

            metrics = scan_structural_metrics(root)

        self.assertIn("demo.a->demo.b->demo.a", metrics["import_cycles"])

    def test_target_pack_roots_and_private_test_attribute_access(self) -> None:
        pack = _pack()
        pack["production_roots"] = ["app"]
        pack["test_roots"] = ["spec"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "app/pkg/api.py", "def _helper():\n    return 1\n")
            _write(root / "spec/test_api.py", "import pkg.api\n\n\ndef test_api():\n    assert pkg.api._helper() == 1\n")

            metrics = scan_structural_metrics(root, pack=pack)

        self.assertTrue(metrics["tests_private_production_internals"])

    def test_production_private_attribute_access_after_module_import_is_detected(self) -> None:
        pack = _pack()
        pack["structural_detectors"].append("cross_module_private_references")
        pack["detector_policies"]["cross_module_private_references"] = {
            "required": True,
            "blocking": True,
            "fail_on_unknown": True,
            "thresholds": {},
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            head = root / "head"
            _write(base / "src/pkg/api.py", "def call():\n    return 1\n")
            _write(base / "src/pkg/util.py", "def _helper():\n    return 1\n")
            _write(head / "src/pkg/api.py", "import pkg.util\n\n\ndef call():\n    return pkg.util._helper()\n")
            _write(head / "src/pkg/util.py", "def _helper():\n    return 1\n")

            delta = structural_delta(scan_structural_metrics(base, pack=pack), scan_structural_metrics(head, pack=pack), pack)

        self.assertTrue(delta["cross_module_private_references"]["introduced"])

    def test_gate_scope_narrowing_is_detected_without_headline_threshold_change(self) -> None:
        pack = _pack()
        base_text = """
[tool.ruff.lint]
select = ["E", "F", "I", "N", "W", "C901"]

[tool.ruff.lint.mccabe]
max-complexity = 9

[tool.pytest.ini_options]
testpaths = ["tests", "integration"]
addopts = "--cov=src"

[tool.mypy]
files = ["src", "scripts", "tests"]
"""
        head_text = """
[tool.ruff]
extend-exclude = ["src/pkg/**"]

[tool.ruff.lint]
select = ["E", "F", "I", "N", "W"]

[tool.ruff.lint.mccabe]
max-complexity = 9

[tool.pytest.ini_options]
testpaths = ["tests"]

[tool.mypy]
files = ["src", "tests"]
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            head = root / "head"
            _write(base / "pyproject.toml", base_text)
            _write(head / "pyproject.toml", head_text)
            _write(base / ".github/workflows/validation.yml", "jobs:\n  test:\n    steps:\n      - name: MyPy type check\n        run: python -m mypy src scripts tests\n")
            _write(head / ".github/workflows/validation.yml", "jobs:\n  test:\n    steps:\n      - name: MyPy type check\n        run: python -m mypy src tests\n")

            delta = structural_delta(scan_structural_metrics(base, pack=pack), scan_structural_metrics(head, pack=pack), pack)

        introduced = delta["gate_scope_or_threshold_weakening"]["introduced"]
        self.assertTrue(any("ruff.select_removed:C901" in item for item in introduced))
        self.assertTrue(any("ruff.exclude_added:src/pkg/**" in item for item in introduced))
        self.assertTrue(any("pytest.testpaths_removed:integration" in item for item in introduced))
        self.assertTrue(any("mypy.files_removed:scripts" in item for item in introduced))

    def test_required_command_comment_does_not_satisfy_gate_contract(self) -> None:
        pack = _pack()
        pack["gate_contract"]["required_commands"] = ["python -m mypy src scripts tests"]
        pack["gate_contract"]["governed_roots"] = []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            head = root / "head"
            _write(
                base / ".github/workflows/validation.yml",
                "jobs:\n  test:\n    steps:\n      - name: MyPy type check\n        run: python -m mypy src scripts tests\n",
            )
            _write(
                head / ".github/workflows/validation.yml",
                "jobs:\n  test:\n    steps:\n      - name: MyPy type check\n        # run: python -m mypy src scripts tests\n        run: echo skipped\n",
            )

            delta = structural_delta(scan_structural_metrics(base, pack=pack), scan_structural_metrics(head, pack=pack), pack)

        introduced = delta["gate_scope_or_threshold_weakening"]["introduced"]
        self.assertIn("required_command_missing:python -m mypy src scripts tests", introduced)

    def test_required_command_disabled_step_does_not_satisfy_gate_contract(self) -> None:
        pack = _pack()
        pack["gate_contract"]["required_commands"] = ["python -m mypy src scripts tests"]
        pack["gate_contract"]["governed_roots"] = []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            head = root / "head"
            _write(
                base / ".github/workflows/validation.yml",
                "jobs:\n  test:\n    steps:\n      - name: MyPy type check\n        run: python -m mypy src scripts tests\n",
            )
            _write(
                head / ".github/workflows/validation.yml",
                "jobs:\n  test:\n    steps:\n      - name: MyPy type check\n        if: ${{ false }}\n        run: python -m mypy src scripts tests\n",
            )

            delta = structural_delta(scan_structural_metrics(base, pack=pack), scan_structural_metrics(head, pack=pack), pack)

        introduced = delta["gate_scope_or_threshold_weakening"]["introduced"]
        self.assertIn("required_command_missing:python -m mypy src scripts tests", introduced)

    def test_required_command_step_if_after_run_does_not_satisfy_gate_contract(self) -> None:
        pack = _pack()
        pack["gate_contract"]["required_commands"] = ["python -m mypy src scripts tests"]
        pack["gate_contract"]["governed_roots"] = []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            head = root / "head"
            _write(
                base / ".github/workflows/validation.yml",
                "jobs:\n  test:\n    steps:\n      - name: MyPy type check\n        run: python -m mypy src scripts tests\n",
            )
            _write(
                head / ".github/workflows/validation.yml",
                "jobs:\n  test:\n    steps:\n      - name: MyPy type check\n        run: python -m mypy src scripts tests\n        if: false\n",
            )

            delta = structural_delta(scan_structural_metrics(base, pack=pack), scan_structural_metrics(head, pack=pack), pack)

        introduced = delta["gate_scope_or_threshold_weakening"]["introduced"]
        self.assertIn("required_command_missing:python -m mypy src scripts tests", introduced)

    def test_required_command_disabled_job_does_not_satisfy_gate_contract(self) -> None:
        pack = _pack()
        pack["gate_contract"]["required_commands"] = ["python -m mypy src scripts tests"]
        pack["gate_contract"]["governed_roots"] = []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            head = root / "head"
            _write(
                base / ".github/workflows/validation.yml",
                "jobs:\n  test:\n    steps:\n      - name: MyPy type check\n        run: python -m mypy src scripts tests\n",
            )
            _write(
                head / ".github/workflows/validation.yml",
                "jobs:\n  test:\n    if: false\n    steps:\n      - name: MyPy type check\n        run: python -m mypy src scripts tests\n",
            )

            delta = structural_delta(scan_structural_metrics(base, pack=pack), scan_structural_metrics(head, pack=pack), pack)

        introduced = delta["gate_scope_or_threshold_weakening"]["introduced"]
        self.assertIn("required_command_missing:python -m mypy src scripts tests", introduced)

    def test_required_command_commented_in_multiline_run_does_not_satisfy_gate_contract(self) -> None:
        pack = _pack()
        pack["gate_contract"]["required_commands"] = ["python -m mypy src scripts tests"]
        pack["gate_contract"]["governed_roots"] = []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            head = root / "head"
            _write(
                base / ".github/workflows/validation.yml",
                "jobs:\n  test:\n    steps:\n      - name: MyPy type check\n        run: python -m mypy src scripts tests\n",
            )
            _write(
                head / ".github/workflows/validation.yml",
                "jobs:\n  test:\n    steps:\n      - name: MyPy type check\n        run: |\n          # python -m mypy src scripts tests\n          echo skipped\n",
            )

            delta = structural_delta(scan_structural_metrics(base, pack=pack), scan_structural_metrics(head, pack=pack), pack)

        introduced = delta["gate_scope_or_threshold_weakening"]["introduced"]
        self.assertIn("required_command_missing:python -m mypy src scripts tests", introduced)

    def test_required_command_active_step_satisfies_gate_contract(self) -> None:
        pack = _pack()
        pack["gate_contract"]["required_commands"] = ["python -m mypy src scripts tests"]
        pack["gate_contract"]["governed_roots"] = []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            head = root / "head"
            workflow = "jobs:\n  test:\n    steps:\n      - name: MyPy type check\n        run: python -m mypy src scripts tests\n"
            _write(base / ".github/workflows/validation.yml", workflow)
            _write(head / ".github/workflows/validation.yml", workflow)

            delta = structural_delta(scan_structural_metrics(base, pack=pack), scan_structural_metrics(head, pack=pack), pack)

        introduced = delta["gate_scope_or_threshold_weakening"]["introduced"]
        self.assertNotIn("required_command_missing:python -m mypy src scripts tests", introduced)

    def test_ruff_include_and_workflow_path_narrowing_are_detected(self) -> None:
        pack = _pack()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            head = root / "head"
            _write(base / "pyproject.toml", "[tool.ruff.lint]\nselect = [\"E\", \"F\"]\n")
            _write(head / "pyproject.toml", "[tool.ruff]\ninclude = [\"src/pkg/*.py\"]\n\n[tool.ruff.lint]\nselect = [\"E\", \"F\"]\n")
            _write(
                base / ".github/workflows/validation.yml",
                "on:\n  pull_request:\n    paths:\n      - 'src/**'\n      - 'tests/**'\njobs:\n  test:\n    steps:\n      - name: Tests\n",
            )
            _write(
                head / ".github/workflows/validation.yml",
                "on:\n  pull_request:\n    paths:\n      - 'docs/**'\njobs:\n  test:\n    steps:\n      - name: Tests\n",
            )

            delta = structural_delta(scan_structural_metrics(base, pack=pack), scan_structural_metrics(head, pack=pack), pack)

        introduced = delta["gate_scope_or_threshold_weakening"]["introduced"]
        self.assertTrue(any("ruff.include_narrowed:src/pkg/*.py" in item for item in introduced))
        self.assertTrue(any("workflow.paths_removed:validation.yml:src/**" in item for item in introduced))
        self.assertTrue(any("workflow.paths_removed:validation.yml:tests/**" in item for item in introduced))

    def test_commented_workflow_paths_do_not_hide_path_narrowing(self) -> None:
        pack = _pack()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            head = root / "head"
            _write(
                base / ".github/workflows/validation.yml",
                "on:\n  pull_request:\n    paths:\n      - 'src/**'\n      - 'tests/**'\njobs:\n  test:\n    steps:\n      - name: Tests\n",
            )
            _write(
                head / ".github/workflows/validation.yml",
                "on:\n  pull_request:\n    # paths: ['src/**', 'tests/**']\n    paths: ['docs/**']\njobs:\n  test:\n    steps:\n      - name: Tests\n",
            )

            delta = structural_delta(scan_structural_metrics(base, pack=pack), scan_structural_metrics(head, pack=pack), pack)

        introduced = delta["gate_scope_or_threshold_weakening"]["introduced"]
        self.assertTrue(any("workflow.paths_removed:validation.yml:src/**" in item for item in introduced))
        self.assertTrue(any("workflow.paths_removed:validation.yml:tests/**" in item for item in introduced))

    def test_publicized_private_helper_rename_is_measured(self) -> None:
        pack = _pack()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            head = root / "head"
            _write(base / "src/demo/api.py", "def _helper(value):\n    return value + 1\n")
            _write(head / "src/demo/api.py", "def helper(value):\n    return value + 1\n")

            delta = structural_delta(scan_structural_metrics(base, pack=pack), scan_structural_metrics(head, pack=pack), pack)

        metric = delta["publicized_private_helper_renames"]
        self.assertEqual(metric["status"], "MEASURED")
        self.assertEqual(metric["introduced"], ["src/demo/api.py:_helper->helper"])

    def test_large_typed_module_uses_large_typed_threshold_policy(self) -> None:
        pack = _pack()
        pack["structural_detectors"].append("large_typed_god_modules")
        pack["detector_policies"]["large_typed_god_modules"] = {
            "required": True,
            "blocking": True,
            "fail_on_unknown": True,
            "thresholds": {"max_lines": 5, "max_functions": 1},
        }
        pack["detector_policies"]["production_module_size_function_count"] = {
            "required": True,
            "blocking": True,
            "fail_on_unknown": True,
            "thresholds": {"max_lines": 1000, "max_functions": 1000},
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "src/demo/typed.py",
                "from typing import TypedDict\n\nclass Row(TypedDict):\n    value: int\n\n"
                "def one():\n    return 1\n\n"
                "def two():\n    return 2\n",
            )

            metrics = scan_structural_metrics(root, pack=pack)

        self.assertEqual(metrics["large_typed_god_modules"], ["src/demo/typed.py"])

    def test_clean_equivalent_gate_change_is_not_blocked(self) -> None:
        pack = _pack()
        text = """
[tool.ruff.lint]
select = ["E", "F", "I", "N", "W"]

[tool.pytest.ini_options]
testpaths = ["tests"]

[tool.mypy]
files = ["src", "scripts", "tests"]
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            head = root / "head"
            _write(base / "pyproject.toml", text)
            _write(head / "pyproject.toml", text + "\n[tool.ruff]\nline-length = 100\n")

            delta = structural_delta(scan_structural_metrics(base, pack=pack), scan_structural_metrics(head, pack=pack), pack)

        self.assertEqual(delta["gate_scope_or_threshold_weakening"]["introduced"], [])

    def test_growth_in_existing_over_threshold_modules_is_introduced_debt(self) -> None:
        pack = _pack()
        pack["structural_detectors"].extend(["module_dependency_fanout", "production_module_size_function_count"])
        pack["detector_policies"]["module_dependency_fanout"] = {
            "required": True,
            "blocking": True,
            "fail_on_unknown": True,
            "thresholds": {"max_imports": 1},
        }
        pack["detector_policies"]["production_module_size_function_count"] = {
            "required": True,
            "blocking": True,
            "fail_on_unknown": True,
            "thresholds": {"max_lines": 5, "max_functions": 1},
        }
        base = {
            "module_dependency_fanout": {
                "threshold": 1,
                "over_threshold": ["demo.api"],
                "by_module": {"demo.api": 2},
            },
            "production_module_size_function_count": {
                "threshold": {"max_lines": 5, "max_functions": 1},
                "over_threshold": ["src/demo/api.py"],
                "by_module": {"src/demo/api.py": {"lines": 8, "function_count": 2, "has_typing": False}},
            },
        }
        head = copy.deepcopy(base)
        head["module_dependency_fanout"]["by_module"]["demo.api"] = 3
        head["production_module_size_function_count"]["by_module"]["src/demo/api.py"]["lines"] = 12
        head["production_module_size_function_count"]["by_module"]["src/demo/api.py"]["function_count"] = 3

        delta = structural_delta(base, head, pack)

        self.assertIn("demo.api:3", delta["module_dependency_fanout"]["introduced"])
        self.assertIn(
            "src/demo/api.py:function_count=3,lines=12",
            delta["production_module_size_function_count"]["introduced"],
        )


def _pack() -> dict:
    return {
        "production_roots": ["src"],
        "test_roots": ["tests"],
        "source_globs": ["**/*.py"],
        "ignore_globs": [],
        "structural_detectors": [
            "tests_private_production_internals",
            "import_cycles",
            "gate_scope_or_threshold_weakening",
            "publicized_private_helper_renames",
        ],
        "detector_policies": {
            "tests_private_production_internals": {"required": True, "blocking": True, "fail_on_unknown": True, "thresholds": {}},
            "import_cycles": {"required": True, "blocking": True, "fail_on_unknown": True, "thresholds": {}},
            "gate_scope_or_threshold_weakening": {"required": True, "blocking": True, "fail_on_unknown": True, "thresholds": {}},
            "publicized_private_helper_renames": {"required": True, "blocking": True, "fail_on_unknown": True, "thresholds": {}},
        },
        "gate_contract": {
            "required_files": ["pyproject.toml", ".github/workflows"],
            "required_commands": [],
            "governed_roots": ["src", "scripts", "tests"],
            "allowed_exceptions": [],
        },
    }


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
