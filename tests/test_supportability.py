from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import governance_eval.supportability as supportability_module
from governance_eval.hashing import sha256_file
from governance_eval.paths import repo_root
from governance_eval.supportability import (
    STATUS_GREEN,
    STATUS_RED,
    SupportabilityError,
    evaluate_copilot_review_gate,
    generate_delivery_receipt,
    load_supportability_config,
    run_supportability_gate,
    validate_supportability_config,
    verify_delivery_receipt,
)


class SupportabilityConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def test_config_validation_rejects_missing_gate_empty_command_and_bad_hash(self) -> None:
        config = _valid_config(self.root)
        config["standard"]["hash"] = "not-a-hash"
        config["required_gates"].pop("tests")
        config["required_gates"]["lint"] = []

        errors = validate_supportability_config(config)

        self.assertTrue(any("standard.hash" in error for error in errors))
        self.assertTrue(any("required_gates.tests" in error for error in errors))
        self.assertTrue(any("required_gates.lint" in error for error in errors))

    def test_yaml_config_contract_loads_without_third_party_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            config_path = repo / ".github/governance/supportability.yml"

            config = load_supportability_config(config_path)

            self.assertEqual(validate_supportability_config(config), [])
            self.assertEqual(config["receipt"]["retention_days"], 90)

    def test_yaml_parser_fails_closed_on_missing_nested_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "supportability.yml"
            config_path.write_text("standard:\n  name:\n", encoding="utf-8")

            with self.assertRaises(SupportabilityError):
                load_supportability_config(config_path)

    def test_yaml_parser_fails_closed_on_unsupported_flow_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "supportability.yml"
            config_path.write_text("standard: {name: supportability-standard}\n", encoding="utf-8")

            with self.assertRaises(SupportabilityError):
                load_supportability_config(config_path)

    def test_json_config_parse_error_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "supportability.json"
            config_path.write_text("{name: supportability-standard}\n", encoding="utf-8")

            with self.assertRaisesRegex(SupportabilityError, "JSON invalid"):
                load_supportability_config(config_path)

    def test_sql_supportability_error_names_accepted_shapes(self) -> None:
        config = _valid_config(self.root)
        config["required_gates"]["sql_supportability"] = 123

        errors = validate_supportability_config(config)

        self.assertTrue(any("auto, a non-empty command string, or a non-empty command list" in error for error in errors))


class SupportabilityGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

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

            self.assertEqual(result["owner_status"], STATUS_GREEN)
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
            self.assertTrue(any("command scope excludes" in error for error in result["errors"]))

    def test_gate_fails_on_threshold_weakening(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            _rewrite_gate_command(repo, "complexity", ["ruff check --max-complexity=12 ."])

            result = run_supportability_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
                changed_files=["src/app.py"],
                command_runner=_passing_runner,
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(any("threshold weakening" in error for error in result["errors"]))

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
            self.assertTrue(any("non-blocking command" in error for error in result["errors"]))

    def test_gate_normalizes_string_command_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            _rewrite_gate_command(repo, "lint", "python -c pass")
            seen: list[str] = []
            env_seen: list[tuple[str | None, str | None]] = []

            def runner(command: str, cwd: Path) -> subprocess.CompletedProcess[str]:
                seen.append(command)
                env_seen.append((os.environ.get("TARGET_BASE_SHA"), os.environ.get("TARGET_HEAD_SHA")))
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
            self.assertTrue(any("required_gates.lint" in error for error in result["errors"]))
            self.assertEqual(result["commands"][0]["command"], "python -c pass")
            self.assertEqual(seen[0], "python -c pass")
            self.assertIn(("a" * 40, "b" * 40), env_seen)

    def test_invalid_sha_returns_red_without_git_diff_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)

            result = run_supportability_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "not-a-sha",
                "b" * 40,
                command_runner=_passing_runner,
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(any("base_sha" in error for error in result["errors"]))

    def test_changed_file_discovery_failure_returns_structured_red(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)

            result = run_supportability_gate(
                repo / ".github/governance/supportability.yml",
                repo,
                "a" * 40,
                "b" * 40,
                command_runner=_passing_runner,
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(any("git diff changed-file discovery failed" in error for error in result["errors"]))

    def test_changed_file_discovery_timeout_raises_supportability_error(self) -> None:
        def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
            cmd = args[0] if args else "git diff"
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=60)

        with mock.patch("governance_eval.supportability.subprocess.run", side_effect=fake_run):
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
            (repo / "src/app.py").write_text("def app():\n    return 2\n", encoding="utf-8")
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
            self.assertTrue(any("supportability config changed" in error for error in result["errors"]))
            self.assertTrue(all(command["status"] == "SKIPPED" for command in result["commands"]))

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

            self.assertFalse(any("command scope excludes" in error for error in result["errors"]))

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
            self.assertTrue(any("SQL files require explicit SQL gate" in error for error in result["errors"]))
            self.assertTrue(any("explicit SQL gate command missing" in error for error in result["errors"]))
            self.assertNotIn("sql_supportability", result["coverage"]["changed_files"]["sql/report.sql"])

    def test_repo_file_discovery_prunes_skipped_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            (repo / "node_modules/pkg").mkdir(parents=True)
            (repo / "node_modules/pkg/ignored.py").write_text("x = 1\n", encoding="utf-8")
            (repo / "node_modules/pkg/ignored.sql").write_text("select 1;\n", encoding="utf-8")

            files = supportability_module._production_files(repo)

            self.assertIn("src/app.py", files)
            self.assertNotIn("node_modules/pkg/ignored.py", files)
            self.assertFalse(supportability_module._repo_has_sql(repo))

            (repo / "sql").mkdir()
            (repo / "sql/report.sql").write_text("select 1;\n", encoding="utf-8")

            self.assertTrue(supportability_module._repo_has_sql(repo))


class CopilotReviewGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def test_copilot_review_gate_accepts_latest_clean_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            head = "c" * 40

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[_review(head)]),
            )

            self.assertEqual(result["owner_status"], STATUS_GREEN)
            self.assertTrue(result["review_status"]["latest_head_reviewed"])

    def test_copilot_review_gate_rejects_missing_or_stale_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            head = "d" * 40

            missing = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[]),
            )
            stale = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[_review("e" * 40)]),
            )

            self.assertEqual(missing["owner_status"], STATUS_RED)
            self.assertEqual(stale["owner_status"], STATUS_RED)
            self.assertTrue(any("missing or stale" in error for error in stale["errors"]))

    def test_copilot_review_gate_rejects_unresolved_p0_p2_thread(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _synthetic_repo(Path(tmp), self.root)
            head = "f" * 40
            payload = _copilot_payload(
                head,
                reviews=[_review(head)],
                review_threads=[
                    {
                        "isResolved": False,
                        "path": "src/app.py",
                        "body": "P1: gate can be bypassed",
                        "authors": ["github-copilot[bot]"],
                    }
                ],
            )

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=payload,
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertEqual(result["review_status"]["blocking_thread_count"], 1)


class DeliveryReceiptTests(unittest.TestCase):
    def test_receipt_verifier_rejects_open_pr_claimed_merged_and_bad_artifact(self) -> None:
        gate = _gate_result()
        copilot = _copilot_result()
        receipt = generate_delivery_receipt(
            gate,
            copilot,
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
            "run": {"status": "completed", "conclusion": "success", "headSha": gate["head_sha"]},
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
            "run": {"status": "completed", "conclusion": "success", "headSha": gate["head_sha"]},
            "artifact": {"id": 456, "name": "supportability-delivery-receipt", "digest": digest, "expired": False},
        }

        result = verify_delivery_receipt(receipt, live_observations=observations)

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
            "run": {"status": "completed", "conclusion": "success", "headSha": gate["head_sha"]},
            "artifact": {"id": 456, "name": "supportability-delivery-receipt", "digest": digest, "expired": False},
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

    def test_receipt_verifier_rejects_merged_sha_missing_from_main_history(self) -> None:
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
            "run": {"status": "completed", "conclusion": "success", "headSha": gate["head_sha"]},
            "artifact": {"id": 456, "name": "supportability-delivery-receipt", "digest": digest, "expired": False},
        }

        result = verify_delivery_receipt(receipt, live_observations=observations)

        self.assertEqual(result["owner_status"], STATUS_RED)
        self.assertTrue(any("main history" in error for error in result["errors"]))

    def test_fresh_clone_log_uses_full_history_fetch(self) -> None:
        calls: list[list[str]] = []
        timeouts: list[object] = []

        def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(args)
            timeouts.append(kwargs.get("timeout"))
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="abc1234 (HEAD -> main) ok\n", stderr="")

        with mock.patch("governance_eval.supportability.subprocess.run", side_effect=fake_run):
            log = supportability_module._fresh_clone_log("https://github.com/example/repo.git")

        self.assertEqual(log, ["abc1234 (HEAD -> main) ok"])
        self.assertNotIn("--depth", calls[0])
        self.assertIn("--filter=blob:none", calls[0])
        self.assertIn("origin/main", calls[1])
        self.assertEqual(timeouts, [supportability_module.GIT_NETWORK_TIMEOUT_SECONDS] * 2)

    def test_fresh_clone_contains_commit_raises_on_git_error(self) -> None:
        calls: list[list[str]] = []

        def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(args)
            if "merge-base" in args:
                return subprocess.CompletedProcess(args=args, returncode=128, stdout="", stderr="bad object")
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

        with mock.patch("governance_eval.supportability.subprocess.run", side_effect=fake_run):
            with self.assertRaises(SupportabilityError):
                supportability_module._fresh_clone_contains_commit("https://github.com/example/repo.git", "3" * 40)

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
        self.assertTrue(any("delivery receipt schema invalid" in error for error in result["errors"]))

    def test_receipt_verifier_rejects_red_receipt(self) -> None:
        gate = _gate_result()
        gate["owner_status"] = STATUS_RED
        receipt = generate_delivery_receipt(gate, _copilot_result(), artifact_name="supportability-delivery-receipt")

        result = verify_delivery_receipt(receipt)

        self.assertEqual(result["owner_status"], STATUS_RED)
        self.assertTrue(any("receipt owner_status must be GREEN" in error for error in result["errors"]))

    def test_receipt_generation_requires_artifact_metadata_for_green(self) -> None:
        receipt = generate_delivery_receipt(
            _gate_result(),
            _copilot_result(),
            artifact_name="supportability-delivery-receipt",
        )

        self.assertEqual(receipt["owner_status"], STATUS_RED)
        self.assertTrue(any("artifact ID is missing" in error for error in receipt["errors"]))
        self.assertTrue(any("artifact digest is missing" in error for error in receipt["errors"]))

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
        self.assertTrue(any("repository_url is required" in error for error in receipt["errors"]))
        self.assertTrue(any("pull_request_url is required" in error for error in receipt["errors"]))


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
            "copilot_required": True,
            "latest_head_required": True,
            "unresolved_p0_p1_p2_blocks": True,
            "reviewer_login_patterns": ["*copilot*", "chatgpt-codex-connector*"],
        },
        "receipt": {"artifact_name": "supportability-delivery-receipt", "retention_days": 90},
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
  copilot_required: true
  latest_head_required: true
  unresolved_p0_p1_p2_blocks: true
  reviewer_login_patterns:
    - "*copilot*"
    - "chatgpt-codex-connector*"
receipt:
  artifact_name: supportability-delivery-receipt
  retention_days: 90
"""


def _rewrite_gate_command(repo: Path, gate: str, commands: object) -> None:
    config = load_supportability_config(repo / ".github/governance/supportability.yml")
    config["required_gates"][gate] = commands
    (repo / ".github/governance/supportability.yml").write_text(json.dumps(config), encoding="utf-8")


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


def _copilot_payload(head_sha: str, *, reviews: list[dict], review_threads: list[dict] | None = None) -> dict:
    return {
        "headRefOid": head_sha,
        "reviews": reviews,
        "comments": [],
        "reviewThreads": review_threads if review_threads is not None else [],
    }


def _review(head_sha: str) -> dict:
    return {
        "state": "COMMENTED",
        "submittedAt": "2026-06-25T10:05:00Z",
        "commitOid": head_sha,
        "author": "github-copilot[bot]",
        "body": f"Reviewed commit {head_sha[:10]}. Clean.",
    }


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
        "errors": [],
    }


def _copilot_result() -> dict:
    return {
        "owner_status": STATUS_GREEN,
        "review_status": {"latest_head_reviewed": True},
        "errors": [],
    }


if __name__ == "__main__":
    unittest.main()
