from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from governance_eval.hashing import sha256_file, sha256_json
from governance_eval.paths import repo_root
from governance_eval.supportability import load_supportability_config
from governance_eval.trusted_workflow import create_trusted_plan, finalize_trusted_plan


class TrustedWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def test_successful_ephemeral_matrix_produces_bound_green_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, config_path, base_sha, head_sha = _target_repo(Path(tmp), self.root)
            plan = create_trusted_plan(
                config_path,
                repo,
                base_sha,
                head_sha,
                workflow_repository="markheck-solutions/governance",
                workflow_sha="c" * 40,
                repository_url="https://github.com/example/target.git",
                pull_request_url="https://github.com/example/target/pull/1",
            )
            result = finalize_trusted_plan(
                plan,
                "success",
                workflow_repository="markheck-solutions/governance",
                workflow_sha="c" * 40,
            )

        self.assertEqual(result["owner_status"], "GREEN")
        self.assertEqual(result["execution_identity"]["mode"], "GITHUB_EPHEMERAL_JOB_MATRIX")
        self.assertEqual(result["execution_identity"]["target_tree_sha"], plan["target_identity"]["head_tree_sha"])

    def test_failed_matrix_or_tampered_plan_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, config_path, base_sha, head_sha = _target_repo(Path(tmp), self.root)
            plan = create_trusted_plan(
                config_path,
                repo,
                base_sha,
                head_sha,
                workflow_repository="markheck-solutions/governance",
                workflow_sha="c" * 40,
                repository_url="https://github.com/example/target.git",
                pull_request_url="https://github.com/example/target/pull/1",
            )
            plan["target_identity"]["head_sha"] = "d" * 40
            result = finalize_trusted_plan(
                plan,
                "failure",
                workflow_repository="markheck-solutions/governance",
                workflow_sha="c" * 40,
            )

        self.assertEqual(result["owner_status"], "RED")
        self.assertTrue(any("plan hash mismatch" in error for error in result["errors"]))
        self.assertTrue(any("execution matrix result" in error for error in result["errors"]))

    def test_rehashed_plan_cannot_substitute_evaluator_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, config_path, base_sha, head_sha = _target_repo(Path(tmp), self.root)
            plan = create_trusted_plan(
                config_path,
                repo,
                base_sha,
                head_sha,
                workflow_repository="markheck-solutions/governance",
                workflow_sha="c" * 40,
                repository_url="https://github.com/example/target.git",
                pull_request_url="https://github.com/example/target/pull/1",
            )
            plan["workflow_identity"]["evaluator_tree_hash"] = "d" * 64
            plan["plan_hash"] = sha256_json({**plan, "plan_hash": ""})
            result = finalize_trusted_plan(
                plan, "success", workflow_repository="markheck-solutions/governance", workflow_sha="c" * 40
            )
        self.assertEqual(result["owner_status"], "RED")
        self.assertTrue(any("evaluator tree hash mismatch" in error for error in result["errors"]))


def _target_repo(path: Path, root: Path) -> tuple[Path, Path, str, str]:
    repo = path / "target"
    (repo / ".github/governance").mkdir(parents=True)
    (repo / "docs/reference").mkdir(parents=True)
    (repo / "src").mkdir()
    standard = repo / "docs/reference/supportability-standard.md"
    standard.write_text(
        (root / "docs/reference/supportability-standard.md").read_text(encoding="utf-8"), encoding="utf-8"
    )
    config = load_supportability_config(root / ".github/governance/supportability.yml")
    config["standard"]["hash"] = sha256_file(standard)
    config["architecture_policy"]["governed_roots"] = [
        {"path": "src", "kind": "production_python", "owner": "test", "purpose": "target source"}
    ]
    config["architecture_policy"]["modules"] = {
        "src": {
            "path": "src",
            "owner": "test",
            "purpose": "target source",
            "classification": "application",
            "domain": "test",
            "allowed_dependencies": [],
            "forbidden_dependencies": [],
            "test_strategy": "command gates",
            "limits": {
                "max_file_lines": 200,
                "max_function_lines": 40,
                "max_class_lines": 100,
                "max_functions_per_file": 20,
                "max_classes_per_file": 10,
            },
        }
    }
    config_path = repo / ".github/governance/supportability.json"
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    (repo / "src/app.py").write_text("def app() -> int:\n    return 1\n", encoding="utf-8")
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base_sha = _git(repo, "rev-parse", "HEAD")
    (repo / "src/app.py").write_text("def app() -> int:\n    return 2\n", encoding="utf-8")
    _git(repo, "add", "src/app.py")
    _git(repo, "commit", "-m", "candidate")
    return repo, config_path, base_sha, _git(repo, "rev-parse", "HEAD")


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)
    return completed.stdout.strip()
