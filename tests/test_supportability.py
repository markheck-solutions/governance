from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import governance_eval.supportability as supportability_module
from governance_eval.codex_review_gate import run_codex_review_gate
from governance_eval.hashing import sha256_file
from governance_eval.paths import repo_root
from governance_eval.supportability import (
    STATUS_GREEN,
    STATUS_RED,
    SupportabilityError,
    generate_delivery_receipt,
    load_supportability_config,
    parse_supportability_config_bytes,
    run_supportability_gate,
    validate_supportability_config,
    verify_delivery_receipt,
)
from governance_eval.schemas import validate_named
from governance_eval.schema_validator import SchemaValidationError


LEGACY_POLICY_DEBT_FIELD = "ex" + "ceptions"
LEGACY_APPLIED_DEBT_FIELD = "ex" + "ceptions_applied"
LEGACY_EXPIRED_DEBT_FIELD = "expired_ex" + "ceptions"


class SupportabilityConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def test_config_validation_rejects_missing_gate_empty_command_and_bad_hash(
        self,
    ) -> None:
        config = _valid_config(self.root)
        config["standard"]["hash"] = "not-a-hash"
        config["required_gates"].pop("tests")
        config["required_gates"]["lint"] = []

        errors = validate_supportability_config(config)

        self.assertTrue(any("standard.hash" in error for error in errors))
        self.assertTrue(any("required_gates.tests" in error for error in errors))
        self.assertTrue(any("required_gates.lint" in error for error in errors))

    def test_config_accepts_typed_codex_policy_and_rejects_legacy_copilot(self) -> None:
        config = _valid_config(self.root)
        legacy = {
            "copilot_required": True,
            "latest_head_required": True,
            "unresolved_p0_p1_p2_blocks": True,
            "reviewer_login_patterns": ["*copilot*"],
        }
        config["ai_review"] = {
            "provider": "codex_connector",
            "adapter": "codex_connector_pr_signal_v2",
            "review_window_seconds": 300,
            "unavailable_after_cutoff": "non_blocking",
            "unresolved_p0_p1_p2_blocks": True,
        }

        self.assertEqual(validate_supportability_config(config), [])

        config["ai_review"] = legacy
        errors = validate_supportability_config(config)
        self.assertTrue(any("legacy Copilot" in error for error in errors), errors)

    def test_config_accepts_only_nonblocking_unavailability_policy(self) -> None:
        config = _valid_config(self.root)
        config["ai_review"]["unavailable_after_cutoff"] = "non_blocking"
        self.assertEqual(validate_supportability_config(config), [])

        for policy in (
            "blocking",
            "ignore",
            "Blocking",
            " blocking",
            "",
            None,
            True,
            1,
            [],
            {},
        ):
            with self.subTest(invalid_policy=policy):
                config = _valid_config(self.root)
                config["ai_review"]["unavailable_after_cutoff"] = policy
                errors = validate_supportability_config(config)
                self.assertTrue(
                    any(
                        "ai_review.unavailable_after_cutoff" in error
                        for error in errors
                    ),
                    errors,
                )

        missing = _valid_config(self.root)
        missing["ai_review"].pop("unavailable_after_cutoff")
        self.assertTrue(
            any(
                "ai_review.unavailable_after_cutoff" in error
                for error in validate_supportability_config(missing)
            )
        )

        unknown = _valid_config(self.root)
        unknown["ai_review"]["fallback"] = "non_blocking"
        self.assertTrue(
            any(
                "ai_review.fallback" in error
                for error in validate_supportability_config(unknown)
            )
        )

    def test_config_validation_rejects_soft_architecture_modes(self) -> None:
        for mode in ("report_only", "block_new"):
            with self.subTest(mode=mode):
                config = _valid_config(self.root)
                config["architecture_policy"]["enforcement_mode"] = mode

                errors = validate_supportability_config(config)

                self.assertTrue(
                    any(
                        "architecture_policy.enforcement_mode" in error
                        for error in errors
                    )
                )

    def test_config_validation_rejects_deleted_architecture_policy(self) -> None:
        config = _valid_config(self.root)
        config.pop("architecture_policy")

        errors = validate_supportability_config(config)

        self.assertTrue(any("architecture_policy" in error for error in errors))

    def test_config_schema_rejects_legacy_debt_field(self) -> None:
        config = _valid_config(self.root)
        config["architecture_policy"][LEGACY_POLICY_DEBT_FIELD] = []

        errors = validate_supportability_config(config)

        self.assertTrue(
            any("legacy architecture debt field" in error for error in errors)
        )
        with self.assertRaises(SchemaValidationError):
            validate_named("supportability_config", config, self.root)

    def test_config_schema_validation_is_independent_of_current_working_directory(
        self,
    ) -> None:
        config = _valid_config(self.root)

        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.chdir(tmp):
                errors = validate_supportability_config(config)

        self.assertEqual(errors, [])

    def test_yaml_config_contract_loads_without_third_party_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            config_path = repo / ".github/governance/supportability.yml"

            config = load_supportability_config(config_path)

            self.assertEqual(validate_supportability_config(config), [])
            self.assertEqual(config["receipt"]["retention_days"], 90)

    def test_config_bytes_parser_uses_exact_utf8_buffer_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            config_path = repo / ".github/governance/supportability.yml"
            raw = config_path.read_bytes()

            config = parse_supportability_config_bytes(raw, suffix=".yml")

            self.assertEqual(validate_supportability_config(config), [])
            with self.assertRaisesRegex(SupportabilityError, "must be UTF-8"):
                parse_supportability_config_bytes(b"\xff", suffix=".yml")

    def test_yaml_parser_fails_closed_on_missing_nested_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "supportability.yml"
            config_path.write_text("standard:\n  name:\n", encoding="utf-8")

            with self.assertRaises(SupportabilityError):
                load_supportability_config(config_path)

    def test_yaml_parser_fails_closed_on_unsupported_flow_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "supportability.yml"
            config_path.write_text(
                "standard: {name: supportability-standard}\n", encoding="utf-8"
            )

            with self.assertRaises(SupportabilityError):
                load_supportability_config(config_path)

    def test_yaml_parser_fails_closed_on_unsupported_flow_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "supportability.yml"
            config_path.write_text("required_gates: [lint, tests]\n", encoding="utf-8")

            with self.assertRaises(SupportabilityError):
                load_supportability_config(config_path)

    def test_json_config_parse_error_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "supportability.json"
            config_path.write_text(
                "{name: supportability-standard}\n", encoding="utf-8"
            )

            with self.assertRaisesRegex(SupportabilityError, "JSON invalid"):
                load_supportability_config(config_path)

    def test_sql_supportability_error_names_accepted_shapes(self) -> None:
        config = _valid_config(self.root)
        config["required_gates"]["sql_supportability"] = 123

        errors = validate_supportability_config(config)

        self.assertTrue(
            any(
                "auto, a non-empty command string, or a non-empty command list" in error
                for error in errors
            )
        )


class SupportabilityGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def test_missing_automatic_request_receipt_fails_before_gate_execution(
        self,
    ) -> None:
        collector = mock.Mock()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(
                ValueError, "automatic workflow request receipt is required"
            ):
                run_codex_review_gate(
                    config_path=root / "missing.yml",
                    config_source_path=".github/governance/supportability.yml",
                    config_binding_digest="sha256:" + "0" * 64,
                    repository="owner/repo",
                    pull_request_number=1,
                    base_sha="a" * 40,
                    head_sha="b" * 40,
                    governance_sha="c" * 40,
                    review_window_started_at="2026-07-13T00:00:00Z",
                    output_dir=root / "artifacts",
                    collector=collector,
                )

        collector.assert_not_called()

    def test_synthetic_repo_with_passing_config_returns_green(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)

            result = run_supportability_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
                changed_files=["src/app.py"],
                command_runner=_passing_runner,
            )

            self.assertEqual(result["owner_status"], STATUS_GREEN, result["errors"])
            self.assertEqual(result["errors"], [])
            self.assertIn("lint", result["coverage"]["changed_files"]["src/app.py"])

    def test_gate_fails_on_scope_narrowing_excluding_changed_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            _rewrite_gate_command(repo, "lint", ["ruff check src/other"])

            result = run_supportability_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
                changed_files=["src/app.py"],
                command_runner=_passing_runner,
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any("command scope excludes" in error for error in result["errors"])
            )

    def test_gate_fails_on_threshold_weakening(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            _rewrite_gate_command(
                repo, "complexity", ["ruff check --max-complexity=12 ."]
            )

            result = run_supportability_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
                changed_files=["src/app.py"],
                command_runner=_passing_runner,
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any("threshold weakening" in error for error in result["errors"])
            )

    def test_gate_fails_on_non_blocking_required_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            _rewrite_gate_command(repo, "tests", ["pytest || true"])

            result = run_supportability_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
                changed_files=["src/app.py"],
                command_runner=_passing_runner,
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any("non-blocking command" in error for error in result["errors"])
            )

    def test_gate_rejects_string_command_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            _rewrite_gate_command(repo, "lint", "python -c pass")
            seen: list[str] = []

            def runner(command: str, cwd: Path) -> subprocess.CompletedProcess[str]:
                seen.append(command)
                return _passing_runner(command, cwd)

            result = run_supportability_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
                changed_files=["src/app.py"],
                command_runner=runner,
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any("required_gates.lint" in error for error in result["errors"])
            )
            self.assertEqual(seen, [])
            self.assertTrue(
                all(command["status"] == "SKIPPED" for command in result["commands"])
            )

    def test_invalid_sha_returns_red_without_git_diff_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            seen: list[str] = []

            def runner(command: str, cwd: Path) -> subprocess.CompletedProcess[str]:
                seen.append(command)
                return _passing_runner(command, cwd)

            result = run_supportability_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "not-a-sha",
                "b" * 40,
                command_runner=runner,
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(any("base_sha" in error for error in result["errors"]))
            self.assertEqual(result["base_sha"], "0" * 40)
            self.assertEqual(seen, [])
            self.assertTrue(
                all(command["status"] == "SKIPPED" for command in result["commands"])
            )

    def test_changed_file_discovery_failure_returns_structured_red(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            seen: list[str] = []

            def runner(command: str, cwd: Path) -> subprocess.CompletedProcess[str]:
                seen.append(command)
                return _passing_runner(command, cwd)

            result = run_supportability_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
                command_runner=runner,
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any(
                    "git diff changed-file discovery failed" in error
                    for error in result["errors"]
                )
            )
            self.assertEqual(seen, [])
            self.assertTrue(
                all(command["status"] == "SKIPPED" for command in result["commands"])
            )

    def test_changed_file_discovery_timeout_raises_supportability_error(self) -> None:
        def fake_run(
            *args: object, **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            cmd = args[0] if args else "git diff"
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=60)

        with mock.patch(
            "governance_eval.supportability.subprocess.run", side_effect=fake_run
        ):
            with self.assertRaises(SupportabilityError):
                supportability_module._git_changed_files(Path("."), "a" * 40, "b" * 40)

    def test_changed_file_discovery_ignores_unrelated_hash_config_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            _git(repo, "init")
            _git(repo, "config", "user.email", "test@example.com")
            _git(repo, "config", "user.name", "Test User")
            _git(repo, "add", ".")
            _git(repo, "commit", "-m", "base")
            base = _git(repo, "rev-parse", "HEAD").strip()
            (repo / "src/app.py").write_text(
                "def app():\n    return 2\n", encoding="utf-8"
            )
            _git(repo, "add", "src/app.py")
            _git(repo, "commit", "-m", "change app")
            head = _git(repo, "rev-parse", "HEAD").strip()

            config_path = repo / ".github/governance/supportability.yml"
            config = load_supportability_config(config_path)
            config["standard"]["hash"] = "not-a-hash"
            config_path.write_text(json.dumps(config), encoding="utf-8")

            result = run_supportability_gate(
                config_path,
                repo,
                base,
                head,
                command_runner=_passing_runner,
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertIn("src/app.py", result["changed_files"])
            self.assertTrue(any("standard.hash" in error for error in result["errors"]))

    def test_gate_fails_when_supportability_config_is_changed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)

            result = run_supportability_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
                changed_files=[".github/governance/supportability.yml", "src/app.py"],
                command_runner=_passing_runner,
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any(
                    "config change must be isolated" in error
                    for error in result["errors"]
                )
            )
            self.assertTrue(
                all(command["status"] == "SKIPPED" for command in result["commands"])
            )

    def test_gate_blocks_initial_architecture_policy_adoption_mixed_with_config_change(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            config = load_supportability_config(
                repo / ".github/governance/supportability.yml"
            )
            base_config = dict(config)
            base_config.pop("architecture_policy")

            with mock.patch(
                "governance_eval.supportability._base_supportability_config",
                return_value=(base_config, []),
            ):
                result = run_supportability_gate(
                    repo / ".github/governance/supportability.yml",
                    repo,
                    "a" * 40,
                    "b" * 40,
                    changed_files=[".github/governance/supportability.yml"],
                    command_runner=_passing_runner,
                )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any(
                    "unclassified supportability config key added" in error
                    for error in result["errors"]
                )
            )

    def test_gate_blocks_architecture_size_limit_increase(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            base_config = load_supportability_config(
                repo / ".github/governance/supportability.yml"
            )
            head_config = json.loads(json.dumps(base_config))
            head_config["architecture_policy"]["modules"]["src"]["limits"][
                "max_file_lines"
            ] += 1
            (repo / ".github/governance/supportability.yml").write_text(
                json.dumps(head_config), encoding="utf-8"
            )

            result = _run_config_change_with_base(repo, base_config)

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any("max_file_lines increased" in error for error in result["errors"])
            )

    def test_gate_blocks_removed_governed_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            base_config = load_supportability_config(
                repo / ".github/governance/supportability.yml"
            )
            head_config = json.loads(json.dumps(base_config))
            head_config["architecture_policy"]["governed_roots"] = [
                root
                for root in head_config["architecture_policy"]["governed_roots"]
                if root["path"] != "docs"
            ]
            (repo / ".github/governance/supportability.yml").write_text(
                json.dumps(head_config), encoding="utf-8"
            )

            result = _run_config_change_with_base(repo, base_config)

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any("governed_roots removed" in error for error in result["errors"])
            )

    def test_gate_blocks_broadened_non_runtime_globs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            base_config = load_supportability_config(
                repo / ".github/governance/supportability.yml"
            )
            head_config = json.loads(json.dumps(base_config))
            head_config["architecture_policy"]["runtime_relevance"][
                "non_runtime_globs"
            ].append("src/**")
            (repo / ".github/governance/supportability.yml").write_text(
                json.dumps(head_config), encoding="utf-8"
            )

            result = _run_config_change_with_base(repo, base_config)

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any(
                    "non_runtime_globs broadened" in error for error in result["errors"]
                )
            )

    def test_gate_blocks_dependency_policy_weakening(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            base_config = load_supportability_config(
                repo / ".github/governance/supportability.yml"
            )
            head_config = json.loads(json.dumps(base_config))
            head_config["architecture_policy"]["modules"]["src"][
                "allowed_dependencies"
            ].append("tests")
            head_config["architecture_policy"]["modules"]["src"][
                "forbidden_dependencies"
            ] = []
            (repo / ".github/governance/supportability.yml").write_text(
                json.dumps(head_config), encoding="utf-8"
            )

            result = _run_config_change_with_base(repo, base_config)

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any(
                    "allowed_dependencies broadened" in error
                    for error in result["errors"]
                )
            )
            self.assertTrue(
                any(
                    "forbidden_dependencies narrowed" in error
                    for error in result["errors"]
                )
            )

    def test_gate_blocks_added_architecture_known_debt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            base_config = load_supportability_config(
                repo / ".github/governance/supportability.yml"
            )
            head_config = json.loads(json.dumps(base_config))
            head_config["architecture_policy"]["known_debt"].append(
                {
                    "rule": "vague_folder_name",
                    "path": "src/utils/file.py",
                    "source_module": "",
                    "target_module": "",
                    "symbol_name": "utils",
                    "detail": "forbidden vague folder name: utils",
                    "fingerprint": "a" * 64,
                    "owner": "test",
                    "reason": "hide utils",
                    "expires_on": "2099-12-31",
                }
            )
            (repo / ".github/governance/supportability.yml").write_text(
                json.dumps(head_config), encoding="utf-8"
            )

            result = _run_config_change_with_base(repo, base_config)

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any("known_debt added" in error for error in result["errors"])
            )

    def test_gate_blocks_architecture_checker_file_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)

            result = run_supportability_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
                changed_files=["governance_eval/architecture_gate.py"],
                command_runner=_passing_runner,
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any("protected checker change" in error for error in result["errors"])
            )
            self.assertTrue(
                all(command["status"] == "SKIPPED" for command in result["commands"])
            )

    def test_gate_protects_active_codex_result_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            active_schema = "schemas/v3/codex_connector_evidence_result.schema.json"

            result = run_supportability_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
                changed_files=[active_schema],
                command_runner=_passing_runner,
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any(active_schema in error for error in result["errors"]),
                result["errors"],
            )
            self.assertTrue(
                all(command["status"] == "SKIPPED" for command in result["commands"])
            )

    def test_gate_accepts_review_checker_change_with_independent_regressions(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            workflow_dir = repo / ".github/workflows"
            workflow_dir.mkdir(parents=True)
            enforcement = self.root / ".github/workflows/supportability-enforcement.yml"
            (workflow_dir / "supportability-enforcement.yml").write_text(
                enforcement.read_text(encoding="utf-8"), encoding="utf-8"
            )
            changed_files = [
                ".github/workflows/supportability-gate.yml",
                "governance_eval/ai_review_gate.py",
                "governance_eval/codex_connector_evidence.py",
                "governance_eval/codex_review_gate.py",
                "schemas/v3/codex_connector_evidence_result.schema.json",
                "tests/test_ai_review_gate.py",
                "tests/test_architecture_gate.py",
                "tests/test_codex_connector_collector.py",
                "tests/test_codex_connector_evidence.py",
                "tests/test_codex_review_gate.py",
                "tests/test_supportability.py",
                "tests/test_workflows.py",
            ]

            for required_test in (
                "tests/test_architecture_gate.py",
                "tests/test_supportability.py",
            ):
                with self.subTest(missing_independent_regression=required_test):
                    blocked = run_supportability_gate(
                        repo / ".github/governance/supportability.yml",
                        repo,
                        "a" * 40,
                        "b" * 40,
                        changed_files=[
                            path for path in changed_files if path != required_test
                        ],
                        command_runner=_passing_runner,
                    )
                    self.assertEqual(blocked["owner_status"], STATUS_RED)
                    self.assertTrue(
                        any(required_test in error for error in blocked["errors"])
                    )

            result = run_supportability_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
                changed_files=changed_files,
                command_runner=_passing_runner,
            )

            self.assertEqual(result["owner_status"], STATUS_GREEN, result["errors"])
            self.assertFalse(
                any("protected checker change" in error for error in result["errors"])
            )
            statuses = {
                command["gate"]: command["status"] for command in result["commands"]
            }
            for gate in (
                "lint",
                "format_check",
                "typecheck",
                "complexity",
                "architecture",
                "tests",
                "compile_or_build",
            ):
                self.assertEqual(statuses[gate], "PASS")

    def test_protected_delivery_chain_accepts_current_remote_pinned_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            workflow_dir = repo / ".github/workflows"
            workflow_dir.mkdir(parents=True)
            source = self.root / ".github/workflows/supportability-enforcement.yml"
            target = workflow_dir / "supportability-enforcement.yml"
            target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

            errors = supportability_module._protected_delivery_chain_errors(repo)

            self.assertEqual(errors, [])

    def test_protected_delivery_chain_rejects_floating_candidate_pin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            workflow_dir = repo / ".github/workflows"
            workflow_dir.mkdir(parents=True)
            source = self.root / ".github/workflows/supportability-enforcement.yml"
            text = source.read_text(encoding="utf-8")
            candidate_pins = list(
                re.finditer(
                    r"uses: markheck-solutions/governance/\.github/workflows/"
                    r"supportability-gate\.yml@([0-9a-f]{40})",
                    text,
                )
            )
            self.assertEqual(len(candidate_pins), 2)
            pin = candidate_pins[1]
            text = text[: pin.start(1)] + "main" + text[pin.end(1) :]
            (workflow_dir / "supportability-enforcement.yml").write_text(
                text, encoding="utf-8"
            )

            errors = supportability_module._protected_delivery_chain_errors(repo)

            self.assertIn(
                "protected candidate-supportability workflow must use exact "
                "supportability-gate.yml at a full immutable SHA",
                errors,
            )

    def test_protected_pin_rotation_requires_matching_governance_refs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            workflow_dir = repo / ".github/workflows"
            workflow_dir.mkdir(parents=True)
            source = self.root / ".github/workflows/supportability-enforcement.yml"
            current = source.read_text(encoding="utf-8")
            current_pins = re.findall(
                r"(?:@|governance-ref:\s+)([0-9a-f]{40})", current
            )
            self.assertEqual(len(current_pins), 6)
            self.assertEqual(len(set(current_pins)), 1)
            head = current.replace(current_pins[0], "2" * 40)
            self.assertEqual(head.count("2" * 40), 6)
            (workflow_dir / "supportability-enforcement.yml").write_text(
                head.replace(
                    "governance-ref: " + "2" * 40, "governance-ref: " + "3" * 40, 1
                ),
                encoding="utf-8",
            )

            with mock.patch(
                "governance_eval.supportability._git_show_text",
                return_value=current,
            ):
                errors = supportability_module._protected_enforcement_change_errors(
                    repo,
                    "2" * 40,
                    ".github/workflows/supportability-enforcement.yml",
                )

            self.assertIn(
                "protected enforcement workflow pins must equal trusted base SHA",
                errors,
            )

    def test_gate_blocks_existing_copilot_review_evidence_checker_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)

            with mock.patch(
                "governance_eval.supportability._git_show_text",
                return_value="base parser",
            ):
                result = run_supportability_gate(
                    repo / ".github/governance/supportability.yml",
                    repo,
                    "a" * 40,
                    "b" * 40,
                    changed_files=["governance_eval/copilot_review_evidence.py"],
                    command_runner=_passing_runner,
                )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any("copilot_review_evidence.py" in error for error in result["errors"])
            )


class SupportabilityAiReviewPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def test_fixed_nonblocking_ai_policy_runs_trusted_base_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            base_config = _valid_config(repo)
            _set_semantic_gate_commands(base_config)
            head_config = json.loads(json.dumps(base_config))
            (repo / ".github/governance/supportability.yml").write_text(
                json.dumps(head_config), encoding="utf-8"
            )
            seen: list[str] = []

            def runner(command: str, cwd: Path) -> subprocess.CompletedProcess[str]:
                del cwd
                seen.append(command)
                return subprocess.CompletedProcess(
                    args=command, returncode=0, stdout="", stderr=""
                )

            with mock.patch(
                "governance_eval.supportability._base_supportability_config",
                return_value=(base_config, []),
            ):
                result = run_supportability_gate(
                    repo / ".github/governance/supportability.yml",
                    repo,
                    "a" * 40,
                    "b" * 40,
                    changed_files=[".github/governance/supportability.yml"],
                    command_runner=runner,
                )

            self.assertEqual(result["owner_status"], STATUS_GREEN, result["errors"])
            self.assertTrue(seen)
            self.assertIn("python -m ruff check .", seen)

    def test_config_change_rejects_blocking_trusted_base_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            base_config = _valid_config(repo)
            _set_semantic_gate_commands(base_config)
            base_config["ai_review"]["unavailable_after_cutoff"] = "blocking"
            head_config = json.loads(json.dumps(base_config))
            head_config["ai_review"]["unavailable_after_cutoff"] = "non_blocking"
            (repo / ".github/governance/supportability.yml").write_text(
                json.dumps(head_config), encoding="utf-8"
            )

            result = _run_config_change_with_base(repo, base_config)

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any(
                    "trusted base ai_review.unavailable_after_cutoff must be "
                    "'non_blocking'" in error
                    for error in result["errors"]
                ),
                result["errors"],
            )
            self.assertTrue(
                all(command["status"] == "SKIPPED" for command in result["commands"])
            )

    def test_config_change_rejects_invalid_trusted_base_ai_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            base_config = _valid_config(repo)
            _set_semantic_gate_commands(base_config)
            base_config["ai_review"]["unavailable_after_cutoff"] = "ignore"
            head_config = json.loads(json.dumps(base_config))
            head_config["ai_review"]["unavailable_after_cutoff"] = "non_blocking"
            (repo / ".github/governance/supportability.yml").write_text(
                json.dumps(head_config), encoding="utf-8"
            )

            result = _run_config_change_with_base(repo, base_config)

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any(
                    "trusted base ai_review.unavailable_after_cutoff" in error
                    for error in result["errors"]
                ),
                result["errors"],
            )
            self.assertTrue(
                all(command["status"] == "SKIPPED" for command in result["commands"])
            )

    def test_config_change_rejects_malformed_trusted_base_ai_types(self) -> None:
        cases = (
            ("review_window_seconds", 300.0, 300),
            ("unresolved_p0_p1_p2_blocks", 1, True),
        )
        for field, malformed, valid in cases:
            with self.subTest(field=field, malformed=malformed):
                with tempfile.TemporaryDirectory() as tmp:
                    repo = _synthetic_repo(Path(tmp), self.root)
                    base_config = _valid_config(repo)
                    _set_semantic_gate_commands(base_config)
                    base_config["ai_review"][field] = malformed
                    head_config = json.loads(json.dumps(base_config))
                    head_config["ai_review"][field] = valid
                    (repo / ".github/governance/supportability.yml").write_text(
                        json.dumps(head_config), encoding="utf-8"
                    )

                    result = _run_config_change_with_base(repo, base_config)

                    self.assertEqual(result["owner_status"], STATUS_RED)
                    self.assertTrue(
                        any(
                            f"trusted base ai_review.{field}" in error
                            for error in result["errors"]
                        ),
                        result["errors"],
                    )
                    self.assertTrue(
                        all(
                            command["status"] == "SKIPPED"
                            for command in result["commands"]
                        )
                    )


class SupportabilityGateWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def test_config_change_rejects_unclassified_key_and_unapproved_reviewer(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            base_config = _valid_config(repo)
            head_config = json.loads(json.dumps(base_config))
            head_config["execution"] = {"shell_escape": True}
            head_config["ai_review"] = {
                "copilot_required": True,
                "latest_head_required": True,
                "unresolved_p0_p1_p2_blocks": True,
                "reviewer_login_patterns": ["evil-copilot-attacker[bot]"],
            }
            (repo / ".github/governance/supportability.yml").write_text(
                json.dumps(head_config), encoding="utf-8"
            )

            result = _run_config_change_with_base(repo, base_config)

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any(
                    "unclassified supportability config key" in error
                    for error in result["errors"]
                )
            )
            self.assertTrue(
                any("legacy Copilot" in error for error in result["errors"]),
                result["errors"],
            )
            self.assertTrue(
                all(command["status"] == "SKIPPED" for command in result["commands"])
            )

    def test_gate_blocks_architecture_workflow_command_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            workflow_path = repo / ".github/workflows/supportability-gate.yml"
            workflow_path.parent.mkdir(parents=True, exist_ok=True)
            workflow_path.write_text("run: echo ok\n", encoding="utf-8")
            base_workflow = "run: python -m governance_eval architecture-gate \\\n"

            with mock.patch(
                "governance_eval.supportability._git_show_text",
                return_value=base_workflow,
            ):
                result = run_supportability_gate(
                    repo / ".github/governance/supportability.yml",
                    repo,
                    "a" * 40,
                    "b" * 40,
                    changed_files=[".github/workflows/supportability-gate.yml"],
                    command_runner=_passing_runner,
                )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any(
                    "architecture gate workflow command changed" in error
                    for error in result["errors"]
                )
            )

    def test_dot_slash_scope_is_repo_wide(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            _rewrite_gate_command(repo, "lint", ["go test ./..."])

            result = run_supportability_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
                changed_files=["src/app.py"],
                command_runner=_passing_runner,
            )

            self.assertFalse(
                any("command scope excludes" in error for error in result["errors"])
            )

    def test_sql_like_repo_without_explicit_sql_gate_returns_red(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            (repo / "sql").mkdir()
            (repo / "sql/report.sql").write_text("select 1;\n", encoding="utf-8")

            result = run_supportability_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
                changed_files=["sql/report.sql"],
                command_runner=_passing_runner,
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any(
                    "SQL files require explicit SQL gate" in error
                    for error in result["errors"]
                )
            )
            self.assertTrue(
                any(
                    "explicit SQL gate command missing" in error
                    for error in result["errors"]
                )
            )
            self.assertNotIn(
                "sql_supportability",
                result["coverage"]["changed_files"]["sql/report.sql"],
            )

    def test_repo_file_discovery_prunes_skipped_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            (repo / "node_modules/pkg").mkdir(parents=True)
            (repo / "node_modules/pkg/ignored.py").write_text(
                "x = 1\n", encoding="utf-8"
            )
            (repo / "node_modules/pkg/ignored.sql").write_text(
                "select 1;\n", encoding="utf-8"
            )

            files = supportability_module._production_files(repo)

            self.assertIn("src/app.py", files)
            self.assertNotIn("node_modules/pkg/ignored.py", files)
            self.assertFalse(supportability_module._repo_has_sql(repo))

            (repo / "sql").mkdir()
            (repo / "sql/report.sql").write_text("select 1;\n", encoding="utf-8")

            self.assertTrue(supportability_module._repo_has_sql(repo))


class DeliveryReceiptTests(unittest.TestCase):
    def test_known_debt_does_not_make_green(self) -> None:
        architecture = _architecture_result()
        architecture["known_debt_applied"] = [
            {
                "rule": "python_import_cycle",
                "path": "src/app.py",
                "fingerprint": "a" * 64,
                "owner": "test",
                "reason": "known debt remains blocking",
                "expires_on": "2099-12-31",
            }
        ]

        receipt = generate_delivery_receipt(
            _gate_result(),
            _copilot_result(),
            architecture_result=architecture,
            artifact_name="supportability-delivery-receipt",
            artifact_id="456",
            artifact_digest=f"sha256:{'a' * 64}",
        )

        self.assertEqual(receipt["owner_status"], STATUS_RED)
        self.assertTrue(any("known_debt" in error for error in receipt["errors"]))

    def test_legacy_debt_result_fields_do_not_make_green(self) -> None:
        architecture = _architecture_result()
        architecture[LEGACY_APPLIED_DEBT_FIELD] = [{"rule": "python_import_cycle"}]
        architecture[LEGACY_EXPIRED_DEBT_FIELD] = [{"rule": "python_import_cycle"}]

        receipt = generate_delivery_receipt(
            _gate_result(),
            _copilot_result(),
            architecture_result=architecture,
            artifact_name="supportability-delivery-receipt",
            artifact_id="456",
            artifact_digest=f"sha256:{'a' * 64}",
        )

        self.assertEqual(receipt["owner_status"], STATUS_RED)
        self.assertTrue(
            any(LEGACY_APPLIED_DEBT_FIELD in error for error in receipt["errors"])
        )
        self.assertTrue(
            any(LEGACY_EXPIRED_DEBT_FIELD in error for error in receipt["errors"])
        )

    def test_approval_and_allowance_metadata_do_not_make_green(self) -> None:
        for field in (
            "human_approval",
            "codeowner_approval",
            "CODEOWNER_approval",
            "protected_baseline_debt_file",
            "baseline_debt_file",
            "waiver",
            "allowlist",
            "approval",
        ):
            with self.subTest(field=field):
                architecture = _architecture_result()
                architecture[field] = {"by": "owner"}

                receipt = generate_delivery_receipt(
                    _gate_result(),
                    _copilot_result(),
                    architecture_result=architecture,
                    artifact_name="supportability-delivery-receipt",
                    artifact_id="456",
                    artifact_digest=f"sha256:{'a' * 64}",
                )

                self.assertEqual(receipt["owner_status"], STATUS_RED)
                self.assertTrue(any(field in error for error in receipt["errors"]))

    def test_missing_required_judge_proof_does_not_make_green(self) -> None:
        gate = _gate_result()
        gate["required_judges"]["candidate_receipt_produced"] = False

        receipt = generate_delivery_receipt(
            gate,
            _copilot_result(),
            architecture_result=_architecture_result(),
            artifact_name="supportability-delivery-receipt",
            artifact_id="456",
            artifact_digest=f"sha256:{'a' * 64}",
        )

        self.assertEqual(receipt["owner_status"], STATUS_RED)
        self.assertTrue(
            any("candidate_receipt_produced" in error for error in receipt["errors"])
        )

    def test_bootstrap_receipt_remains_red(self) -> None:
        receipt = supportability_module.generate_bootstrap_receipt(
            repository_url="https://github.com/example/repo.git",
            pr_url="https://github.com/example/repo/pull/7",
            base_sha="1" * 40,
            head_sha="2" * 40,
        )

        self.assertEqual(receipt["owner_status"], STATUS_RED)
        self.assertEqual(receipt["bootstrap"]["gate_result"], STATUS_RED)
        self.assertEqual(
            receipt["bootstrap"]["reason"],
            "baseline protected workflow missing on main",
        )
        self.assertEqual(receipt["bootstrap"]["human_decision_required"], "YES")
        self.assertFalse(receipt["bootstrap"]["governance_pass"])

    def test_receipt_rejects_architecture_status_mismatch(self) -> None:
        architecture = _architecture_result()
        architecture["repo_architecture_supportability"] = "FAIL"

        receipt = generate_delivery_receipt(
            _gate_result(),
            _copilot_result(),
            architecture_result=architecture,
            repository_url="https://github.com/example/repo.git",
            pr_url="https://github.com/example/repo/pull/7",
            run_id="123",
            workflow_run_url="https://github.com/example/repo/actions/runs/123",
            artifact_name="supportability-delivery-receipt",
            artifact_id="456",
            artifact_digest=f"sha256:{'a' * 64}",
        )

        self.assertEqual(receipt["owner_status"], STATUS_RED)
        self.assertTrue(
            any(
                "repo_architecture_supportability" in error
                for error in receipt["errors"]
            )
        )

    def test_receipt_rejects_architecture_violations_even_if_owner_green(self) -> None:
        architecture = _architecture_result()
        architecture["violations"] = [{"rule_id": "vague_folder_name"}]

        receipt = generate_delivery_receipt(
            _gate_result(),
            _copilot_result(),
            architecture_result=architecture,
            repository_url="https://github.com/example/repo.git",
            pr_url="https://github.com/example/repo/pull/7",
            run_id="123",
            workflow_run_url="https://github.com/example/repo/actions/runs/123",
            artifact_name="supportability-delivery-receipt",
            artifact_id="456",
            artifact_digest=f"sha256:{'a' * 64}",
        )

        self.assertEqual(receipt["owner_status"], STATUS_RED)
        self.assertTrue(
            any(
                "architecture violations must be empty" in error
                for error in receipt["errors"]
            )
        )

    def test_receipt_verifier_rejects_open_pr_claimed_merged_and_bad_artifact(
        self,
    ) -> None:
        gate = _gate_result()
        copilot = _copilot_result()
        receipt = generate_delivery_receipt(
            gate,
            copilot,
            architecture_result=_architecture_result(),
            repository_url="https://github.com/example/repo.git",
            pr_url="https://github.com/example/repo/pull/7",
            run_id="123",
            workflow_run_url="https://github.com/example/repo/actions/runs/123",
            artifact_name="supportability-delivery-receipt",
            artifact_id="456",
            artifact_digest=f"sha256:{'a' * 64}",
            merged_sha="3" * 40,
        )
        observations = {
            "ls_remote_main_sha": "0" * 40,
            "fresh_clone_head_log": ["0000000 (HEAD -> main) stale"],
            "fresh_clone_contains_merged_sha": False,
            "pr": {
                "state": "OPEN",
                "baseRefOid": gate["base_sha"],
                "headRefOid": gate["head_sha"],
                "mergeCommit": None,
            },
            "run": {
                "status": "completed",
                "conclusion": "success",
                "headSha": gate["head_sha"],
            },
            "artifact": {
                "id": 456,
                "name": "supportability-delivery-receipt",
                "digest": f"sha256:{'b' * 64}",
                "expired": True,
            },
        }

        result = verify_delivery_receipt(receipt, live_observations=observations)

        self.assertEqual(result["owner_status"], STATUS_RED)
        self.assertTrue(any("not MERGED" in error for error in result["errors"]))
        self.assertTrue(any("expired" in error for error in result["errors"]))
        self.assertTrue(any("digest" in error for error in result["errors"]))

    def test_receipt_verifier_allows_main_to_advance_after_merge(self) -> None:
        gate = _gate_result()
        copilot = _copilot_result()
        merged_sha = "3" * 40
        digest = f"sha256:{'a' * 64}"
        receipt = generate_delivery_receipt(
            gate,
            copilot,
            architecture_result=_architecture_result(),
            repository_url="https://github.com/example/repo.git",
            pr_url="https://github.com/example/repo/pull/7",
            run_id="123",
            workflow_run_url="https://github.com/example/repo/actions/runs/123",
            artifact_name="supportability-delivery-receipt",
            artifact_id="456",
            artifact_digest=digest,
            merged_sha=merged_sha,
        )
        observations = {
            "ls_remote_main_sha": "9" * 40,
            "fresh_clone_head_log": ["9999999 (HEAD -> main) later commit"],
            "fresh_clone_contains_merged_sha": True,
            "pr": {
                "state": "MERGED",
                "baseRefOid": gate["base_sha"],
                "headRefOid": gate["head_sha"],
                "mergeCommit": {"oid": merged_sha},
            },
            "run": {
                "status": "completed",
                "conclusion": "success",
                "headSha": gate["head_sha"],
            },
            "artifact": {
                "id": 456,
                "name": "supportability-delivery-receipt",
                "digest": digest,
                "expired": False,
            },
        }

        result = verify_delivery_receipt(receipt, live_observations=observations)

        self.assertEqual(result["owner_status"], STATUS_GREEN)

    def test_receipt_verifier_allows_current_run_pending_conclusion(self) -> None:
        gate = _gate_result()
        digest = f"sha256:{'a' * 64}"
        receipt = generate_delivery_receipt(
            gate,
            _copilot_result(),
            architecture_result=_architecture_result(),
            repository_url="https://github.com/example/repo.git",
            pr_url="https://github.com/example/repo/pull/7",
            run_id="123",
            workflow_run_url="https://github.com/example/repo/actions/runs/123",
            artifact_name="supportability-delivery-receipt",
            artifact_id="456",
            artifact_digest=digest,
        )
        observations = {
            "ls_remote_main_sha": "9" * 40,
            "fresh_clone_head_log": ["9999999 (HEAD -> main) later commit"],
            "fresh_clone_contains_merged_sha": None,
            "pr": {
                "state": "OPEN",
                "baseRefOid": gate["base_sha"],
                "headRefOid": gate["head_sha"],
                "mergeCommit": None,
            },
            "run": {
                "status": "in_progress",
                "conclusion": "",
                "headSha": gate["head_sha"],
            },
            "artifact": {
                "id": 456,
                "name": "supportability-delivery-receipt",
                "digest": digest,
                "expired": False,
            },
        }

        with mock.patch.dict(os.environ, {"GITHUB_RUN_ID": "123"}):
            result = verify_delivery_receipt(
                receipt,
                live_observations=observations,
                allow_current_run_pending=True,
            )

        self.assertEqual(result["owner_status"], STATUS_GREEN)

    def test_receipt_uses_live_observation_ls_remote_key(self) -> None:
        receipt = generate_delivery_receipt(
            _gate_result(),
            _copilot_result(),
            artifact_name="supportability-delivery-receipt",
        )

        self.assertIn("ls_remote_main_sha", receipt["remote_audit"])
        self.assertNotIn("git_ls_remote_main_sha", receipt["remote_audit"])

    def test_receipt_verifier_rejects_missing_ls_remote_proof(self) -> None:
        gate = _gate_result()
        copilot = _copilot_result()
        digest = f"sha256:{'a' * 64}"
        receipt = generate_delivery_receipt(
            gate,
            copilot,
            repository_url="https://github.com/example/repo.git",
            pr_url="https://github.com/example/repo/pull/7",
            run_id="123",
            workflow_run_url="https://github.com/example/repo/actions/runs/123",
            artifact_name="supportability-delivery-receipt",
            artifact_id="456",
            artifact_digest=digest,
        )
        observations = {
            "ls_remote_main_sha": "",
            "fresh_clone_head_log": ["9999999 (HEAD -> main) later commit"],
            "fresh_clone_contains_merged_sha": None,
            "pr": {
                "state": "OPEN",
                "baseRefOid": gate["base_sha"],
                "headRefOid": gate["head_sha"],
                "mergeCommit": None,
            },
            "run": {
                "status": "completed",
                "conclusion": "success",
                "headSha": gate["head_sha"],
            },
            "artifact": {
                "id": 456,
                "name": "supportability-delivery-receipt",
                "digest": digest,
                "expired": False,
            },
        }

        result = verify_delivery_receipt(receipt, live_observations=observations)

        self.assertEqual(result["owner_status"], STATUS_RED)
        self.assertTrue(any("ls-remote" in error for error in result["errors"]))

    def test_receipt_verifier_rejects_invalid_merged_sha_shape(self) -> None:
        receipt = generate_delivery_receipt(
            _gate_result(),
            _copilot_result(),
            artifact_name="supportability-delivery-receipt",
        )
        receipt["merged_sha"] = "not-a-sha"

        result = verify_delivery_receipt(receipt)

        self.assertEqual(result["owner_status"], STATUS_RED)
        self.assertTrue(any("merged_sha" in error for error in result["errors"]))

    def test_receipt_generation_rejects_invalid_merged_sha_without_schema_crash(
        self,
    ) -> None:
        receipt = generate_delivery_receipt(
            _gate_result(),
            _copilot_result(),
            artifact_name="supportability-gate-evidence",
            artifact_id="456",
            artifact_digest=f"sha256:{'a' * 64}",
            merged_sha="not-a-sha",
        )

        self.assertEqual(receipt["owner_status"], STATUS_RED)
        self.assertEqual(receipt["merged_sha"], "")
        self.assertTrue(
            any("merged_sha must be empty" in error for error in receipt["errors"])
        )

    def test_receipt_generation_rejects_bad_gate_shas_without_schema_crash(
        self,
    ) -> None:
        gate = _gate_result()
        gate["base_sha"] = "bad-base"
        gate["head_sha"] = "bad-head"

        receipt = generate_delivery_receipt(
            gate,
            _copilot_result(),
            artifact_name="supportability-gate-evidence",
            artifact_id="456",
            artifact_digest=f"sha256:{'a' * 64}",
        )

        self.assertEqual(receipt["owner_status"], STATUS_RED)
        self.assertEqual(receipt["base_sha"], "0" * 40)
        self.assertEqual(receipt["head_sha"], "0" * 40)
        self.assertTrue(any("base_sha must be" in error for error in receipt["errors"]))
        self.assertTrue(any("head_sha must be" in error for error in receipt["errors"]))

    def test_receipt_schema_validation_is_independent_of_current_working_directory(
        self,
    ) -> None:
        receipt = generate_delivery_receipt(
            _gate_result(),
            _copilot_result(),
            architecture_result=_architecture_result(),
            artifact_name="supportability-gate-evidence",
            artifact_id="456",
            artifact_digest=f"sha256:{'a' * 64}",
        )

        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.chdir(tmp):
                result = verify_delivery_receipt(receipt)

        self.assertEqual(result["owner_status"], STATUS_GREEN)

    def test_receipt_verifier_rejects_fabricated_nested_green(self) -> None:
        receipt = generate_delivery_receipt(
            _gate_result(),
            _copilot_result(),
            architecture_result=_architecture_result(),
            artifact_name="supportability-gate-evidence",
            artifact_id="456",
            artifact_digest=f"sha256:{'a' * 64}",
        )
        receipt["supportability_gate"] = {}
        receipt["ai_review"] = {}
        receipt["architecture"] = {}
        receipt["required_judges"] = {}

        result = verify_delivery_receipt(receipt)

        self.assertEqual(result["owner_status"], STATUS_RED)
        self.assertTrue(
            any(
                "delivery receipt schema invalid" in error for error in result["errors"]
            )
        )

    def test_receipt_verifier_rejects_legacy_architecture_fields(self) -> None:
        receipt = generate_delivery_receipt(
            _gate_result(),
            _copilot_result(),
            architecture_result=_architecture_result(),
            artifact_name="supportability-gate-evidence",
            artifact_id="456",
            artifact_digest=f"sha256:{'a' * 64}",
        )
        receipt["architecture"][LEGACY_APPLIED_DEBT_FIELD] = [{"rule": "old"}]
        receipt["architecture"][LEGACY_EXPIRED_DEBT_FIELD] = [{"rule": "old"}]

        result = verify_delivery_receipt(receipt)

        self.assertEqual(result["owner_status"], STATUS_RED)
        self.assertTrue(
            any(LEGACY_APPLIED_DEBT_FIELD in error for error in result["errors"])
        )
        self.assertTrue(
            any(LEGACY_EXPIRED_DEBT_FIELD in error for error in result["errors"])
        )

    def test_receipt_verifier_rejects_merged_sha_missing_from_main_history(
        self,
    ) -> None:
        gate = _gate_result()
        copilot = _copilot_result()
        merged_sha = "3" * 40
        digest = f"sha256:{'a' * 64}"
        receipt = generate_delivery_receipt(
            gate,
            copilot,
            repository_url="https://github.com/example/repo.git",
            pr_url="https://github.com/example/repo/pull/7",
            run_id="123",
            workflow_run_url="https://github.com/example/repo/actions/runs/123",
            artifact_name="supportability-delivery-receipt",
            artifact_id="456",
            artifact_digest=digest,
            merged_sha=merged_sha,
        )
        observations = {
            "ls_remote_main_sha": "9" * 40,
            "fresh_clone_head_log": ["9999999 (HEAD -> main) later commit"],
            "fresh_clone_contains_merged_sha": False,
            "pr": {
                "state": "MERGED",
                "baseRefOid": gate["base_sha"],
                "headRefOid": gate["head_sha"],
                "mergeCommit": {"oid": merged_sha},
            },
            "run": {
                "status": "completed",
                "conclusion": "success",
                "headSha": gate["head_sha"],
            },
            "artifact": {
                "id": 456,
                "name": "supportability-delivery-receipt",
                "digest": digest,
                "expired": False,
            },
        }

        result = verify_delivery_receipt(receipt, live_observations=observations)

        self.assertEqual(result["owner_status"], STATUS_RED)
        self.assertTrue(any("main history" in error for error in result["errors"]))

    def test_live_artifact_populates_missing_digest_from_zip_archive(self) -> None:
        archive = b"supportability evidence archive"
        expected_digest = f"sha256:{hashlib.sha256(archive).hexdigest()}"

        with mock.patch("governance_eval.supportability._gh_api_json") as api_json:
            with mock.patch(
                "governance_eval.supportability._gh_api_bytes", return_value=archive
            ) as api_bytes:
                api_json.return_value = {
                    "id": 456,
                    "name": "supportability-gate-evidence",
                    "expired": False,
                }

                artifact = supportability_module._live_artifact("example/repo", "456")

        self.assertEqual(artifact["digest"], expected_digest)
        api_bytes.assert_called_once_with(
            "repos/example/repo/actions/artifacts/456/zip"
        )

    def test_gh_json_uses_network_timeout(self) -> None:
        calls: list[dict[str, object]] = []

        def fake_run(
            args: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            calls.append(kwargs)
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout="{}", stderr=""
            )

        with mock.patch(
            "governance_eval.supportability.subprocess.run", side_effect=fake_run
        ):
            self.assertEqual(
                supportability_module._gh_json(["api", "repos/example/repo"]), {}
            )

        self.assertEqual(
            calls[0]["timeout"], supportability_module.GIT_NETWORK_TIMEOUT_SECONDS
        )

    def test_fresh_clone_log_uses_full_history_fetch(self) -> None:
        calls: list[list[str]] = []
        timeouts: list[object] = []

        def fake_run(
            args: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            calls.append(args)
            timeouts.append(kwargs.get("timeout"))
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout="abc1234 (HEAD -> main) ok\n", stderr=""
            )

        with mock.patch(
            "governance_eval.supportability.subprocess.run", side_effect=fake_run
        ):
            log = supportability_module._fresh_clone_log(
                "https://github.com/example/repo.git"
            )

        self.assertEqual(log, ["abc1234 (HEAD -> main) ok"])
        self.assertNotIn("--depth", calls[0])
        self.assertIn("--filter=blob:none", calls[0])
        self.assertIn("origin/main", calls[1])
        self.assertEqual(
            timeouts, [supportability_module.GIT_NETWORK_TIMEOUT_SECONDS] * 2
        )

    def test_fresh_clone_contains_commit_raises_on_git_error(self) -> None:
        calls: list[list[str]] = []

        def fake_run(
            args: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            calls.append(args)
            if "merge-base" in args:
                return subprocess.CompletedProcess(
                    args=args, returncode=128, stdout="", stderr="bad object"
                )
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout="", stderr=""
            )

        with mock.patch(
            "governance_eval.supportability.subprocess.run", side_effect=fake_run
        ):
            with self.assertRaises(SupportabilityError):
                supportability_module._fresh_clone_contains_commit(
                    "https://github.com/example/repo.git", "3" * 40
                )

        self.assertIn("merge-base", calls[1])

    def test_receipt_verifier_rejects_schema_invalid_receipt(self) -> None:
        receipt = generate_delivery_receipt(
            _gate_result(),
            _copilot_result(),
            artifact_name="supportability-delivery-receipt",
        )
        receipt.pop("artifact")

        result = verify_delivery_receipt(receipt)

        self.assertEqual(result["owner_status"], STATUS_RED)
        self.assertTrue(
            any(
                "delivery receipt schema invalid" in error for error in result["errors"]
            )
        )

    def test_receipt_verifier_rejects_red_receipt(self) -> None:
        gate = _gate_result()
        gate["owner_status"] = STATUS_RED
        receipt = generate_delivery_receipt(
            gate, _copilot_result(), artifact_name="supportability-delivery-receipt"
        )

        result = verify_delivery_receipt(receipt)

        self.assertEqual(result["owner_status"], STATUS_RED)
        self.assertTrue(
            any(
                "receipt owner_status must be GREEN" in error
                for error in result["errors"]
            )
        )

    def test_receipt_generation_requires_artifact_metadata_for_green(self) -> None:
        receipt = generate_delivery_receipt(
            _gate_result(),
            _copilot_result(),
            artifact_name="supportability-delivery-receipt",
        )

        self.assertEqual(receipt["owner_status"], STATUS_RED)
        self.assertTrue(
            any("artifact ID is missing" in error for error in receipt["errors"])
        )
        self.assertTrue(
            any("artifact digest is missing" in error for error in receipt["errors"])
        )

    def test_receipt_generation_requires_repository_and_pr_urls_for_green(self) -> None:
        gate = _gate_result()
        gate["repository_url"] = ""
        gate["pull_request_url"] = ""

        receipt = generate_delivery_receipt(
            gate,
            _copilot_result(),
            artifact_name="supportability-delivery-receipt",
            artifact_id="456",
            artifact_digest=f"sha256:{'a' * 64}",
        )

        self.assertEqual(receipt["owner_status"], STATUS_RED)
        self.assertTrue(
            any("repository_url is required" in error for error in receipt["errors"])
        )
        self.assertTrue(
            any("pull_request_url is required" in error for error in receipt["errors"])
        )

    def test_receipt_verifier_rejects_missing_artifact_identity(self) -> None:
        receipt = generate_delivery_receipt(
            _gate_result(),
            _copilot_result(),
            artifact_name="supportability-gate-evidence",
            artifact_id="456",
            artifact_digest=f"sha256:{'a' * 64}",
        )
        receipt["artifact"]["id"] = ""
        receipt["artifact"]["digest"] = ""

        result = verify_delivery_receipt(receipt)

        self.assertEqual(result["owner_status"], STATUS_RED)
        self.assertTrue(
            any("artifact.id is required" in error for error in result["errors"])
        )
        self.assertTrue(
            any("artifact.digest is required" in error for error in result["errors"])
        )

    def test_delivery_receipt_cli_defaults_to_supportability_evidence_artifact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gate_path = root / "gate.json"
            ai_review_path = root / "ai-review.json"
            architecture_path = root / "architecture.json"
            out = root / "out"
            gate_path.write_text(json.dumps(_gate_result()), encoding="utf-8")
            ai_review_path.write_text(json.dumps(_copilot_result()), encoding="utf-8")
            architecture_path.write_text(
                json.dumps(_architecture_result()), encoding="utf-8"
            )

            with contextlib.redirect_stdout(io.StringIO()):
                rc = supportability_module.main(
                    [
                        "delivery-receipt",
                        "--gate-result",
                        str(gate_path),
                        "--ai-review-result",
                        str(ai_review_path),
                        "--architecture-result",
                        str(architecture_path),
                        "--output-dir",
                        str(out),
                        "--artifact-id",
                        "456",
                        "--artifact-digest",
                        f"sha256:{'a' * 64}",
                        "--protected-baseline-judge-ran",
                        "--candidate-judge-ran",
                        "--baseline-receipt-produced",
                        "--candidate-receipt-produced",
                    ]
                )

            receipt = json.loads(
                (out / "supportability-delivery-receipt.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(rc, 0)
            self.assertEqual(
                receipt["artifact"]["name"], "supportability-gate-evidence"
            )


def _synthetic_repo(path: Path, root: Path) -> Path:
    (path / ".github/governance").mkdir(parents=True)
    (path / "docs/reference").mkdir(parents=True)
    (path / "src").mkdir()
    standard = root / "docs/reference/supportability-standard.md"
    target_standard = path / "docs/reference/supportability-standard.md"
    target_standard.write_text(standard.read_text(encoding="utf-8"), encoding="utf-8")
    (path / "src/app.py").write_text("def app():\n    return 1\n", encoding="utf-8")
    (path / "src/risk.py").write_text("x = 1\n" * 20, encoding="utf-8")
    (path / ".github/governance/supportability.yml").write_text(
        _config_yaml(sha256_file(target_standard)),
        encoding="utf-8",
    )
    return path


def _valid_config(root: Path) -> dict:
    standard = root / "docs/reference/supportability-standard.md"
    return {
        "standard": {
            "name": "supportability-standard",
            "source": "docs/reference/supportability-standard.md",
            "hash": sha256_file(standard),
        },
        "required_gates": {
            "lint": ["python -c pass"],
            "format_check": ["python -c pass"],
            "typecheck": ["python -c pass"],
            "complexity": ["python -c pass"],
            "architecture": ["python -c pass"],
            "tests": ["python -c pass"],
            "compile_or_build": ["python -c pass"],
            "package_audit": [],
            "sql_supportability": "auto",
        },
        "coverage": {
            "changed_files": "required",
            "high_risk_files": "required",
            "forbid_gate_scope_narrowing": True,
            "forbid_threshold_weakening": True,
        },
        "ai_review": {
            "provider": "codex_connector",
            "adapter": "codex_connector_pr_signal_v2",
            "review_window_seconds": 300,
            "unavailable_after_cutoff": "non_blocking",
            "unresolved_p0_p1_p2_blocks": True,
        },
        "receipt": {
            "artifact_name": "supportability-delivery-receipt",
            "retention_days": 90,
        },
        "architecture_policy": _architecture_policy(),
    }


def _config_yaml(standard_hash: str) -> str:
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
  enforcement_mode: block_all
  governed_roots:
    - path: src
      kind: production_python
      owner: test
      purpose: production source
    - path: tests
      kind: test_python
      owner: test
      purpose: tests
    - path: docs
      kind: docs
      owner: test
      purpose: docs
  runtime_relevance:
    production_globs:
      - "**/*.py"
      - "**/*.sql"
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
      purpose: production source
      classification: application
      domain: synthetic
      allowed_dependencies: []
      forbidden_dependencies:
        - tests
      test_strategy: unittest
      limits:
        max_file_lines: 500
        max_function_lines: 100
        max_class_lines: 200
        max_functions_per_file: 50
        max_classes_per_file: 20
    tests:
      path: tests
      owner: test
      purpose: tests
      classification: test
      domain: synthetic
      allowed_dependencies:
        - src
      forbidden_dependencies: []
      test_strategy: unittest
      limits:
        max_file_lines: 500
        max_function_lines: 100
        max_class_lines: 200
        max_functions_per_file: 50
        max_classes_per_file: 20
  known_debt: []
"""


def _architecture_policy() -> dict:
    return {
        "version": 1,
        "enforcement_mode": "block_all",
        "governed_roots": [
            {
                "path": "src",
                "kind": "production_python",
                "owner": "test",
                "purpose": "production source",
            },
            {
                "path": "tests",
                "kind": "test_python",
                "owner": "test",
                "purpose": "tests",
            },
            {"path": "docs", "kind": "docs", "owner": "test", "purpose": "docs"},
        ],
        "runtime_relevance": {
            "production_globs": ["**/*.py", "**/*.sql"],
            "non_runtime_globs": ["docs/**", "**/*.md"],
        },
        "vague_names": {
            "forbidden": ["utils", "helpers", "common", "misc", "stuff", "shared"]
        },
        "modules": {
            "src": {
                "path": "src",
                "owner": "test",
                "purpose": "production source",
                "classification": "application",
                "domain": "synthetic",
                "allowed_dependencies": [],
                "forbidden_dependencies": ["tests"],
                "test_strategy": "unittest",
                "limits": {
                    "max_file_lines": 500,
                    "max_function_lines": 100,
                    "max_class_lines": 200,
                    "max_functions_per_file": 50,
                    "max_classes_per_file": 20,
                },
            },
            "tests": {
                "path": "tests",
                "owner": "test",
                "purpose": "tests",
                "classification": "test",
                "domain": "synthetic",
                "allowed_dependencies": ["src"],
                "forbidden_dependencies": [],
                "test_strategy": "unittest",
                "limits": {
                    "max_file_lines": 500,
                    "max_function_lines": 100,
                    "max_class_lines": 200,
                    "max_functions_per_file": 50,
                    "max_classes_per_file": 20,
                },
            },
        },
        "known_debt": [],
    }


def _rewrite_gate_command(repo: Path, gate: str, commands: object) -> None:
    config = load_supportability_config(repo / ".github/governance/supportability.yml")
    config["required_gates"][gate] = commands
    (repo / ".github/governance/supportability.yml").write_text(
        json.dumps(config), encoding="utf-8"
    )


def _run_config_change_with_base(repo: Path, base_config: dict) -> dict:
    with mock.patch(
        "governance_eval.supportability._base_supportability_config",
        return_value=(base_config, []),
    ):
        return run_supportability_gate(
            repo / ".github/governance/supportability.yml",
            repo,
            "a" * 40,
            "b" * 40,
            changed_files=[".github/governance/supportability.yml"],
            command_runner=_passing_runner,
        )


def _set_semantic_gate_commands(config: dict) -> None:
    config["required_gates"].update(
        {
            "lint": ["python -m ruff check ."],
            "format_check": ["python -m ruff format --check ."],
            "typecheck": ["python -m mypy ."],
            "complexity": ["python -m ruff check --select C901 ."],
            "architecture": [
                "python -m governance_eval architecture-gate --config .github/governance/supportability.yml --target-repo . --base-sha $BASE_SHA --head-sha $HEAD_SHA"
            ],
            "tests": ["python -m pytest tests -q"],
            "compile_or_build": ["python -m build"],
            "package_audit": ["python -m pip check"],
        }
    )


def _passing_runner(command: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )
    return completed.stdout


def _gate_result() -> dict:
    return {
        "owner_status": STATUS_GREEN,
        "repository_url": "https://github.com/example/repo.git",
        "pull_request_url": "https://github.com/example/repo/pull/7",
        "base_sha": "1" * 40,
        "head_sha": "2" * 40,
        "changed_files": ["src/app.py"],
        "high_risk_files": ["src/risk.py"],
        "coverage": {"changed_files": {"src/app.py": ["lint"]}},
        "required_judges": {
            "protected_baseline_judge_ran": True,
            "candidate_judge_ran": True,
            "baseline_receipt_produced": True,
            "candidate_receipt_produced": True,
            "governance_weakening_detected": False,
        },
        "errors": [],
    }


def _copilot_result() -> dict:
    return {
        "owner_status": STATUS_GREEN,
        "evidence_status": "CLEAN",
        "approval_provided": False,
        "observations": [],
    }


def _architecture_result() -> dict:
    return {
        "owner_status": STATUS_GREEN,
        "gate_implementation": "PASS",
        "repo_architecture_supportability": "PASS",
        "architecture_behavior_proof": "PASS",
        "enforcement_mode": "block_all",
        "violations": [],
        "new_violations": [],
        "existing_violations": [],
        "known_debt_applied": [],
        "expired_known_debt": [],
        "errors": [],
    }


if __name__ == "__main__":
    unittest.main()
