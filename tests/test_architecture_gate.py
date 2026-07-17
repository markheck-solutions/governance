from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from governance_eval.architecture_policy import architecture_policy_weakening_errors
from governance_eval.architecture_gate import (
    EXIT_BLOCKED,
    EXIT_CONFIG,
    EXIT_OK,
    _fingerprint,
    run_architecture_gate,
)
from governance_eval.hashing import sha256_file
from governance_eval.paths import repo_root
from governance_eval.supportability import load_supportability_config


class ArchitectureGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def test_architecture_policy_comparison_rejects_limit_increase(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), self.root, mode="block_all")
            config = load_supportability_config(
                repo / ".github/governance/supportability.yml"
            )
        base = {"architecture_policy": config["architecture_policy"]}
        head = json.loads(json.dumps(base))
        head["architecture_policy"]["modules"]["src"]["limits"]["max_file_lines"] += 1

        errors = architecture_policy_weakening_errors(base, head)

        self.assertTrue(any("max_file_lines increased" in error for error in errors))

    def test_codex_connector_test_classes_respect_architecture_limits(self) -> None:
        result, code = run_architecture_gate(
            self.root / ".github/governance/supportability.yml",
            self.root,
            "a" * 40,
            "b" * 40,
            changed_files=["tests/test_codex_connector_evidence.py"],
        )

        self.assertEqual(code, EXIT_OK, result["violations"])
        self.assertFalse(
            any(
                violation["rule_id"] == "python_class_lines"
                and violation["path"] == "tests/test_codex_connector_evidence.py"
                for violation in result["violations"]
            )
        )

    def test_request_receipt_slice_has_architecture_coverage(self) -> None:
        changed_files = [
            ".github/workflows/supportability-gate.yml",
            "fixtures/supportability-enforcement-receipt-activated.yml",
            "governance_eval/ai_review_gate.py",
            "governance_eval/codex_connector_evidence.py",
            "governance_eval/codex_review_gate.py",
            "governance_eval/schemas.py",
            "governance_eval/supportability.py",
            "schemas/v4/codex_connector_evidence_result.schema.json",
            "tests/test_ai_review_gate.py",
            "tests/test_architecture_gate.py",
            "tests/test_codex_connector_evidence.py",
            "tests/test_codex_review_gate.py",
            "tests/test_self_update_policy.py",
            "tests/test_supportability.py",
            "tests/test_workflows.py",
        ]

        result, code = run_architecture_gate(
            self.root / ".github/governance/supportability.yml",
            self.root,
            "a" * 40,
            "b" * 40,
            changed_files=changed_files,
        )

        self.assertEqual(code, EXIT_OK, result["violations"])
        self.assertEqual(result["changed_files"], sorted(changed_files))
        self.assertEqual(
            result["rule_results"]["changed_file_architecture_coverage"],
            "PASS",
        )

    def test_registered_python_module_passes_and_writes_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), self.root, mode="block_all")

            result, code = run_architecture_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
                output_dir=repo / "artifacts/supportability",
                changed_files=["src/app.py"],
            )

            self.assertEqual(code, EXIT_OK)
            self.assertEqual(result["owner_status"], "GREEN")
            self.assertTrue(
                (
                    repo / "artifacts/supportability/architecture-gate-result.json"
                ).exists()
            )
            self.assertTrue(
                (repo / "artifacts/supportability/architecture-gate-result.md").exists()
            )

    def test_fail_closed_checkpoint_files_have_architecture_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), self.root, mode="block_all")
            runtime = repo / "governance_eval"
            runtime.mkdir()
            config_binding_slice_paths = {
                ".github/workflows/supportability-gate.yml",
                "governance_eval/codex_review_gate.py",
                "governance_eval/supportability.py",
                "tests/test_architecture_gate.py",
                "tests/test_codex_review_gate.py",
                "tests/test_self_update_policy.py",
                "tests/test_supportability.py",
                "tests/test_workflows.py",
            }
            changed_files = sorted(
                config_binding_slice_paths
                | {
                    "governance_eval/ai_review_gate.py",
                    "governance_eval/codex_connector_evidence.py",
                    "schemas/v1/supportability_config.schema.json",
                    "tests/test_ai_review_gate.py",
                    "tests/test_codex_connector_collector.py",
                    "tests/test_codex_connector_evidence.py",
                }
            )
            for path in changed_files:
                target = repo / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("value = 1\n", encoding="utf-8")
            config_path = repo / ".github/governance/supportability.yml"
            config = load_supportability_config(config_path)
            config["architecture_policy"]["governed_roots"].append(
                {
                    "path": "governance_eval",
                    "kind": "production_python",
                    "owner": "governance",
                    "purpose": "evaluator runtime",
                }
            )
            config["architecture_policy"]["governed_roots"].append(
                {
                    "path": "schemas",
                    "kind": "schema_artifact",
                    "owner": "governance",
                    "purpose": "machine-readable contracts",
                }
            )
            config["architecture_policy"]["governed_roots"].append(
                {
                    "path": ".github/workflows",
                    "kind": "ci_config",
                    "owner": "governance",
                    "purpose": "GitHub enforcement workflows",
                }
            )
            config["architecture_policy"]["runtime_relevance"][
                "non_runtime_globs"
            ].append(".github/workflows/**")
            config["architecture_policy"]["modules"]["governance_eval"] = {
                "path": "governance_eval",
                "owner": "governance",
                "purpose": "evaluator runtime",
                "classification": "application",
                "domain": "governance-evaluation",
                "allowed_dependencies": [],
                "forbidden_dependencies": ["tests"],
                "test_strategy": "unittest coverage through tests/",
                "limits": {
                    "max_file_lines": 50,
                    "max_function_lines": 10,
                    "max_class_lines": 5,
                    "max_functions_per_file": 5,
                    "max_classes_per_file": 2,
                },
            }
            config["architecture_policy"]["modules"]["schemas"] = {
                "path": "schemas",
                "owner": "governance",
                "purpose": "machine-readable contracts",
                "classification": "schema",
                "domain": "governance-evaluation",
                "allowed_dependencies": [],
                "forbidden_dependencies": ["tests"],
                "test_strategy": "schema validation through tests/",
                "limits": {
                    "max_file_lines": 500,
                    "max_function_lines": 10,
                    "max_class_lines": 5,
                    "max_functions_per_file": 5,
                    "max_classes_per_file": 2,
                },
            }
            config["architecture_policy"]["modules"]["workflows"] = {
                "path": ".github/workflows",
                "owner": "governance",
                "purpose": "GitHub enforcement workflows",
                "classification": "ci",
                "domain": "github-enforcement",
                "allowed_dependencies": ["governance_eval"],
                "forbidden_dependencies": ["artifacts"],
                "test_strategy": "workflow assertions through tests/",
                "limits": {
                    "max_file_lines": 500,
                    "max_function_lines": 0,
                    "max_class_lines": 0,
                    "max_functions_per_file": 0,
                    "max_classes_per_file": 0,
                },
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")

            result, code = run_architecture_gate(
                config_path,
                repo,
                "a" * 40,
                "b" * 40,
                changed_files=changed_files,
            )

            self.assertEqual(code, EXIT_OK, result["errors"])
            self.assertEqual(result["owner_status"], "GREEN")
            self.assertEqual(
                result["rule_results"]["changed_file_architecture_coverage"],
                "PASS",
            )

    def test_block_new_mode_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), self.root, mode="block_new")

            result, code = run_architecture_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
            )

            self.assertEqual(code, EXIT_CONFIG)
            self.assertTrue(
                any(
                    "enforcement_mode must be block_all" in error
                    for error in result["errors"]
                )
            )

    def test_report_only_mode_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), self.root, mode="report_only")

            result, code = run_architecture_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
            )

            self.assertEqual(code, EXIT_CONFIG)
            self.assertTrue(
                any(
                    "enforcement_mode must be block_all" in error
                    for error in result["errors"]
                )
            )

    def test_missing_policy_is_gate_implementation_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), self.root, mode="block_all")
            config_path = repo / ".github/governance/supportability.yml"
            config = load_supportability_config(config_path)
            config.pop("architecture_policy")
            config_path.write_text(json.dumps(config), encoding="utf-8")

            result, code = run_architecture_gate(config_path, repo, "a" * 40, "b" * 40)

            self.assertEqual(code, EXIT_CONFIG)
            self.assertEqual(result["gate_implementation"], "FAIL")
            self.assertTrue(
                any("architecture_policy" in error for error in result["errors"])
            )

    def test_non_object_policy_is_gate_implementation_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), self.root, mode="block_all")
            config_path = repo / ".github/governance/supportability.yml"
            config = load_supportability_config(config_path)
            config["architecture_policy"] = []
            config_path.write_text(json.dumps(config), encoding="utf-8")

            result, code = run_architecture_gate(config_path, repo, "a" * 40, "b" * 40)

            self.assertEqual(code, EXIT_CONFIG)
            self.assertEqual(result["gate_implementation"], "FAIL")
            self.assertTrue(
                any("architecture_policy" in error for error in result["errors"])
            )

    def test_root_tool_caches_skip_but_nested_exact_names_and_lookalikes_are_scanned(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), self.root, mode="block_all")
            subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            for cache in (".mypy_cache", ".ruff_cache"):
                (repo / cache).mkdir()
                (repo / cache / "cache.py").write_text("x = 1\n", encoding="utf-8")
            scanned_files = {
                ".mypy_cache/evil.py",
                ".ruff_cache/evil.py",
                "src/.mypy_cache_like.py",
                "src/.mypy_cache/evil.py",
                "src/.ruff_cache/evil.py",
                "src/build/evil.py",
                "src/coverage/evil.py",
                "src/dist/evil.py",
            }
            for relative_path in scanned_files:
                source = repo / relative_path
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(
                    "\n".join(f"value_{index} = {index}" for index in range(51)),
                    encoding="utf-8",
                )
            subprocess.run(
                ["git", "add", "--force", "--", *sorted(scanned_files)],
                cwd=repo,
                check=True,
            )

            result, code = run_architecture_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
                changed_files=sorted(scanned_files),
            )

            self.assertEqual(code, EXIT_BLOCKED)
            violation_paths = {item["path"] for item in result["violations"]}
            self.assertNotIn(".mypy_cache/cache.py", violation_paths)
            self.assertNotIn(".ruff_cache/cache.py", violation_paths)
            self.assertTrue(scanned_files <= violation_paths)

    def test_structured_known_debt_records_debt_but_remains_red(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), self.root, mode="block_all")
            (repo / "src/shared").mkdir()
            (repo / "src/shared/model.py").write_text("x = 1\n", encoding="utf-8")
            _add_known_debt(
                repo,
                {
                    "rule_id": "vague_folder_name",
                    "path": "src/shared/model.py",
                    "source_module": "",
                    "target_module": "",
                    "symbol_name": "shared",
                    "detail": "forbidden vague folder name: shared",
                },
            )

            result, code = run_architecture_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
                changed_files=["src/shared/model.py"],
            )

            self.assertEqual(code, EXIT_BLOCKED)
            self.assertEqual(result["owner_status"], "RED")
            self.assertEqual(len(result["known_debt_applied"]), 1)
            self.assertTrue(result["violations"])

    def test_path_only_known_debt_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), self.root, mode="block_all")
            config_path = repo / ".github/governance/supportability.yml"
            config = load_supportability_config(config_path)
            config["architecture_policy"]["known_debt"].append(
                {
                    "rule": "vague_folder_name",
                    "path": "src/shared",
                    "owner": "test",
                    "reason": "too broad",
                    "expires_on": "2099-12-31",
                }
            )
            config_path.write_text(json.dumps(config), encoding="utf-8")

            result, code = run_architecture_gate(config_path, repo, "a" * 40, "b" * 40)

            self.assertEqual(code, EXIT_CONFIG)
            self.assertTrue(any("fingerprint" in error for error in result["errors"]))

    def test_expired_known_debt_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), self.root, mode="block_all")
            (repo / "src/shared").mkdir()
            (repo / "src/shared/model.py").write_text("x = 1\n", encoding="utf-8")
            _add_known_debt(
                repo,
                {
                    "rule_id": "vague_folder_name",
                    "path": "src/shared/model.py",
                    "source_module": "",
                    "target_module": "",
                    "symbol_name": "shared",
                    "detail": "forbidden vague folder name: shared",
                },
                expires_on="2020-01-01",
            )

            result, code = run_architecture_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
                changed_files=["src/shared/model.py"],
            )

            self.assertEqual(code, EXIT_BLOCKED)
            self.assertTrue(result["expired_known_debt"])

    def test_unregistered_top_level_and_runtime_file_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), self.root, mode="block_all")
            (repo / "feature").mkdir()
            (repo / "feature/app.py").write_text("x = 1\n", encoding="utf-8")

            result, code = run_architecture_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
                changed_files=["feature/app.py"],
            )

            self.assertEqual(code, EXIT_BLOCKED)
            rules = {item["rule_id"] for item in result["violations"]}
            self.assertIn("unregistered_top_level", rules)
            self.assertIn("unknown_runtime_file", rules)
            self.assertIn("changed_file_architecture_coverage", rules)

    def test_required_gates_architecture_echo_cannot_bypass_checker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), self.root, mode="block_all")
            config_path = repo / ".github/governance/supportability.yml"
            config = load_supportability_config(config_path)
            config["required_gates"]["architecture"] = ["echo ok"]
            config_path.write_text(json.dumps(config), encoding="utf-8")
            (repo / "src/utils").mkdir()
            (repo / "src/utils/bad.py").write_text("x = 1\n", encoding="utf-8")

            result, code = run_architecture_gate(
                config_path,
                repo,
                "a" * 40,
                "b" * 40,
                changed_files=["src/utils/bad.py"],
            )

            self.assertEqual(code, EXIT_BLOCKED)
            self.assertTrue(
                any(
                    item["rule_id"] == "vague_folder_name"
                    for item in result["violations"]
                )
            )

    def test_python_parse_failure_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), self.root, mode="block_all")
            (repo / "src/bad_parse.py").write_text(
                "def broken(:\n    pass\n", encoding="utf-8"
            )

            result, code = run_architecture_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
                changed_files=["src/bad_parse.py"],
            )

            self.assertEqual(code, EXIT_BLOCKED)
            self.assertTrue(
                any(
                    item["rule_id"] == "python_parse_failure"
                    for item in result["violations"]
                )
            )

    def test_python_dependency_direction_cycle_dynamic_parse_and_size_rules(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), self.root, mode="block_all")
            (repo / "tests/leak.py").write_text("import src.app\n", encoding="utf-8")
            (repo / "src/app.py").write_text(
                "import tests.leak\nimport importlib\nimportlib.import_module('src.runtime')\nclass Oversized:\n"
                + "    x = 1\n" * 10,
                encoding="utf-8",
            )

            result, code = run_architecture_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
                changed_files=["src/app.py"],
            )

            self.assertEqual(code, EXIT_BLOCKED)
            rules = {item["rule_id"] for item in result["violations"]}
            self.assertIn("python_dependency_direction", rules)
            self.assertIn("python_import_cycle", rules)
            self.assertIn("python_dynamic_import", rules)
            self.assertIn("python_class_lines", rules)

    def test_cli_outputs_expected_status_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), self.root, mode="block_all")
            from governance_eval.architecture_gate import main

            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                code = main(
                    [
                        "architecture-gate",
                        "--config",
                        str(repo / ".github/governance/supportability.yml"),
                        "--target-repo",
                        str(repo),
                        "--base-sha",
                        "a" * 40,
                        "--head-sha",
                        "b" * 40,
                    ]
                )

            self.assertEqual(code, EXIT_OK)
            output = stream.getvalue()
            self.assertIn("Architecture Fitness Gate", output)
            self.assertIn("Gate implementation: PASS", output)
            self.assertIn("Repo architecture supportability: PASS", output)

    def test_behavior_fixtures_must_run_for_green(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), self.root, mode="block_all")

            result, code = run_architecture_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
                changed_files=["src/app.py"],
            )

            self.assertEqual(code, EXIT_OK)
            self.assertEqual(result["architecture_behavior_proof"], "PASS")
            self.assertTrue(result["behavior_fixtures"])
            self.assertTrue(
                all(item["status"] == "PASS" for item in result["behavior_fixtures"])
            )

    def test_behavior_fixture_failure_keeps_gate_red(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), self.root, mode="block_all")

            with mock.patch(
                "governance_eval.architecture_gate._architecture_behavior_fixtures",
                return_value={
                    "status": "FAIL",
                    "fixtures": [{"name": "theater", "status": "FAIL"}],
                    "errors": ["fixture failed"],
                },
            ):
                result, code = run_architecture_gate(
                    repo / ".github/governance/supportability.yml",
                    repo,
                    "a" * 40,
                    "b" * 40,
                    changed_files=["src/app.py"],
                )

            self.assertEqual(code, EXIT_BLOCKED)
            self.assertEqual(result["owner_status"], "RED")
            self.assertEqual(result["architecture_behavior_proof"], "FAIL")

    def test_behavior_fixtures_catch_checker_that_turns_violations_green(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), self.root, mode="block_all")

            def fake_scan(policy: dict, files: list, changed_files: list) -> dict:
                return {
                    "violations": [],
                    "rules_checked": set(),
                    "python_file_count": len(files),
                }

            with mock.patch(
                "governance_eval.architecture_gate._scan_files", side_effect=fake_scan
            ):
                result, code = run_architecture_gate(
                    repo / ".github/governance/supportability.yml",
                    repo,
                    "a" * 40,
                    "b" * 40,
                    changed_files=["src/app.py"],
                )

            self.assertEqual(code, EXIT_BLOCKED)
            self.assertEqual(result["architecture_behavior_proof"], "FAIL")
            self.assertTrue(
                any("negative_vague_folder" in error for error in result["errors"])
            )


def _repo(path: Path, root: Path, *, mode: str) -> Path:
    (path / ".github/governance").mkdir(parents=True)
    (path / "docs/reference").mkdir(parents=True)
    (path / "src").mkdir()
    (path / "tests").mkdir()
    standard = root / "docs/reference/supportability-standard.md"
    target_standard = path / "docs/reference/supportability-standard.md"
    target_standard.write_text(standard.read_text(encoding="utf-8"), encoding="utf-8")
    (path / "src/app.py").write_text("def app():\n    return 1\n", encoding="utf-8")
    (path / "tests/test_app.py").write_text(
        "from src.app import app\n", encoding="utf-8"
    )
    (path / ".github/governance/supportability.yml").write_text(
        _config_yaml(sha256_file(target_standard), mode),
        encoding="utf-8",
    )
    return path


def _add_known_debt(
    repo: Path, violation: dict, *, expires_on: str = "2099-12-31"
) -> None:
    config_path = repo / ".github/governance/supportability.yml"
    config = load_supportability_config(config_path)
    fingerprint = _fingerprint(violation)
    config["architecture_policy"]["known_debt"].append(
        {
            "rule": violation["rule_id"],
            "path": violation["path"],
            "source_module": violation["source_module"],
            "target_module": violation["target_module"],
            "symbol_name": violation["symbol_name"],
            "detail": violation["detail"],
            "fingerprint": fingerprint,
            "owner": "test",
            "reason": "test known_debt with explicit owner and expiry",
            "expires_on": expires_on,
        }
    )
    config_path.write_text(json.dumps(config), encoding="utf-8")


def _config_yaml(standard_hash: str, mode: str) -> str:
    return f"""standard:
  name: supportability-standard
  source: docs/reference/supportability-standard.md
  hash: "{standard_hash}"
required_gates:
  lint:
    - python -c pass
  format_check:
    - python -c pass
  typecheck:
    - python -c pass
  complexity:
    - python -c pass
  architecture:
    - python -c pass
  tests:
    - python -c pass
  compile_or_build:
    - python -c pass
  package_audit: []
  sql_supportability: auto
coverage:
  changed_files: required
  high_risk_files: required
  forbid_gate_scope_narrowing: true
  forbid_threshold_weakening: true
ai_review:
  provider: codex_connector
  adapter: codex_connector_pr_signal_v2
  review_window_seconds: 300
  unavailable_after_cutoff: non_blocking
  unresolved_p0_p1_p2_blocks: true
receipt:
  artifact_name: supportability-delivery-receipt
  retention_days: 90
architecture_policy:
  version: 1
  enforcement_mode: {mode}
  governed_roots:
    - path: src
      kind: production_python
      owner: test
      purpose: production package
    - path: tests
      kind: test_python
      owner: test
      purpose: tests
    - path: docs
      kind: docs
      owner: test
      purpose: docs
    - path: .github/governance
      kind: ci_config
      owner: test
      purpose: governance config
  runtime_relevance:
    production_globs:
      - "**/*.py"
    non_runtime_globs:
      - "docs/**"
      - "**/*.md"
  vague_names:
    forbidden:
      - utils
      - helpers
      - common
      - misc
      - stuff
      - shared
  modules:
    src:
      path: src
      owner: test
      purpose: app module
      classification: application
      domain: demo
      allowed_dependencies: []
      forbidden_dependencies:
        - tests
      test_strategy: unittest
      limits:
        max_file_lines: 50
        max_function_lines: 10
        max_class_lines: 5
        max_functions_per_file: 5
        max_classes_per_file: 2
    tests:
      path: tests
      owner: test
      purpose: tests
      classification: test
      domain: demo
      allowed_dependencies:
        - src
      forbidden_dependencies: []
      test_strategy: unittest
      limits:
        max_file_lines: 100
        max_function_lines: 20
        max_class_lines: 20
        max_functions_per_file: 10
        max_classes_per_file: 5
  known_debt: []
"""


if __name__ == "__main__":
    unittest.main()
