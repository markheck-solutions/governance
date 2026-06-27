from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

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

            self.assertEqual(result["commands"][0]["command"], "python -c pass")
            self.assertEqual(seen[0], "python -c pass")
            self.assertIn(("a" * 40, "b" * 40), env_seen)

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
