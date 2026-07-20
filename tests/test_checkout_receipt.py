from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
import base64
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

from governance_eval.checkout_receipt import (
    CheckoutReceiptError,
    HttpJsonEvidence,
    bind_checkout,
    validate_checkout_receipt_v1,
)
from governance_eval.docker_toolchain import (
    CERTIFIED_TOOLCHAIN_BUNDLE_ID,
    PYTHON_IMAGE,
)
from governance_eval.hashing import sha256_file, sha256_json
from governance_eval.schema_validator import SchemaValidationError
from governance_eval.schemas import validate_packaged_named
from governance_eval.supportability_config_v2 import TYPED_CAPABILITIES
import governance_eval.checkout_receipt as checkout_receipt


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip()


def _commit(root: Path, message: str) -> str:
    _git(root, "add", ".")
    _git(root, "commit", "-qm", message)
    return _git(root, "rev-parse", "HEAD")


class CheckoutReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.git = Path(shutil.which("git") or "missing-git").resolve()
        self.evaluator = self.root / "evaluator"
        self.target = self.root / "target"
        self._create_evaluator()
        self._create_target()
        self._create_api_evidence()
        self._create_contexts()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _create_evaluator(self) -> None:
        self.evaluator.mkdir()
        self._init_repository(
            self.evaluator,
            "https://github.com/markheck-solutions/governance.git",
        )
        workflow = self.evaluator / ".github/workflows/supportability-gate.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("name: Supportability Gate\n", encoding="utf-8")
        self.evaluator_sha = _commit(self.evaluator, "evaluator")
        self.evaluator_tree = _git(
            self.evaluator, "rev-parse", f"{self.evaluator_sha}^{{tree}}"
        )

    def _create_target(self) -> None:
        self.target.mkdir()
        self._init_repository(self.target, "https://github.com/example/target.git")
        standard = b"# Supportability Standard\n"
        standard_path = self.target / "docs/reference/supportability-standard.md"
        standard_path.parent.mkdir(parents=True)
        standard_path.write_bytes(standard)
        config = self.target / ".github/governance/supportability.yml"
        config.parent.mkdir(parents=True)
        config.write_text(
            json.dumps(
                {
                    "schema_version": "2.0",
                    "standard": {
                        "name": "supportability-standard",
                        "source": "docs/reference/supportability-standard.md",
                        "hash": sha256(standard).hexdigest(),
                    },
                    "capabilities": TYPED_CAPABILITIES,
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
                    "architecture_policy": {
                        "version": 1,
                        "enforcement_mode": "block_all",
                        "governed_roots": [
                            {
                                "path": "target.py",
                                "kind": "production_python",
                                "owner": "test",
                                "purpose": "checkout receipt test target",
                            }
                        ],
                        "runtime_relevance": {
                            "production_globs": ["**/*.py"],
                            "non_runtime_globs": ["**/*.md"],
                        },
                        "vague_names": {"forbidden": ["utils"]},
                        "modules": {
                            "target": {
                                "path": "target.py",
                                "owner": "test",
                                "purpose": "checkout receipt test target",
                                "classification": "application",
                                "domain": "test",
                                "allowed_dependencies": [],
                                "forbidden_dependencies": [],
                                "test_strategy": "receipt binding",
                                "limits": {
                                    "max_file_lines": 100,
                                    "max_function_lines": 25,
                                    "max_class_lines": 50,
                                    "max_functions_per_file": 10,
                                    "max_classes_per_file": 5,
                                },
                            }
                        },
                        "known_debt": [],
                    },
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        caller = self.target / ".github/workflows/supportability-enforcement.yml"
        caller.parent.mkdir(parents=True, exist_ok=True)
        caller.write_text(self._caller_workflow(), encoding="utf-8")
        (self.target / "target.py").write_text("BASE = True\n", encoding="utf-8")
        self.base_sha = _commit(self.target, "base")
        self.base_tree = _git(self.target, "rev-parse", f"{self.base_sha}^{{tree}}")
        (self.target / "target.py").write_text("HEAD = True\n", encoding="utf-8")
        self.head_sha = _commit(self.target, "head")
        self.head_tree = _git(self.target, "rev-parse", f"{self.head_sha}^{{tree}}")

    def _caller_workflow(self) -> str:
        gate = "markheck-solutions/governance/.github/workflows/supportability-gate.yml"
        return (
            "name: Supportability Enforcement\n"
            "jobs:\n"
            "  baseline-supportability:\n"
            f"    uses: {gate}@{self.evaluator_sha}\n"
            "    with:\n"
            f"      governance-ref: {self.evaluator_sha}\n"
            "      artifact-name: baseline-supportability-gate-evidence\n"
            "\n"
            "  candidate-supportability:\n"
            f"    uses: {gate}@{self.evaluator_sha}\n"
            "    with:\n"
            f"      governance-ref: {self.evaluator_sha}\n"
            "      artifact-name: candidate-supportability-gate-evidence\n"
            "\n"
            "  delivery-receipt:\n"
            "    name: Delivery Receipt\n"
        )

    @staticmethod
    def _init_repository(root: Path, remote: str) -> None:
        _git(root, "init", "-q")
        _git(root, "config", "user.email", "governance@example.invalid")
        _git(root, "config", "user.name", "Governance Test")
        _git(root, "remote", "add", "origin", remote)

    def _create_api_evidence(self) -> None:
        self.repository = {
            "id": 101,
            "full_name": "example/target",
            "default_branch": "main",
            "url": "https://api.github.com/repos/example/target",
            "html_url": "https://github.com/example/target",
        }
        self.evaluator_repository = {
            "id": 202,
            "full_name": "markheck-solutions/governance",
            "default_branch": "main",
            "url": "https://api.github.com/repos/markheck-solutions/governance",
            "html_url": "https://github.com/markheck-solutions/governance",
        }
        self.pull_request = {
            "number": 84,
            "url": "https://api.github.com/repos/example/target/pulls/84",
            "html_url": "https://github.com/example/target/pull/84",
            "base": {
                "ref": "main",
                "sha": self.base_sha,
                "repo": {"id": 101, "full_name": "example/target"},
            },
            "head": {
                "ref": "feature",
                "sha": self.head_sha,
                "repo": {"id": 101, "full_name": "example/target"},
            },
        }
        self.run = {
            "id": 999,
            "run_attempt": 1,
            "event": "pull_request_target",
            "path": ".github/workflows/supportability-enforcement.yml",
            "head_sha": self.base_sha,
            "repository": {"id": 101, "full_name": "example/target"},
            "referenced_workflows": [
                {
                    "path": (
                        "markheck-solutions/governance/"
                        ".github/workflows/supportability-gate.yml@"
                        f"{self.evaluator_sha}"
                    ),
                    "sha": self.evaluator_sha,
                }
            ],
        }
        self.resource_bodies: dict[str, object] = {
            "target_repository": self.repository,
            "evaluator_repository": self.evaluator_repository,
            "pull_request": self.pull_request,
            "base_commit": self._commit_body(
                "example/target", self.base_sha, self.base_tree
            ),
            "head_commit": self._commit_body(
                "example/target", self.head_sha, self.head_tree
            ),
            "evaluator_commit": self._commit_body(
                "markheck-solutions/governance",
                self.evaluator_sha,
                self.evaluator_tree,
            ),
            "workflow_run": self.run,
            "effective_base_rules": [],
        }
        self.resources = {
            name: self._resource(name, body)
            for name, body in self.resource_bodies.items()
        }

    @staticmethod
    def _commit_body(repository: str, commit: str, tree: str) -> dict[str, object]:
        return {
            "url": f"https://api.github.com/repos/{repository}/commits/{commit}",
            "sha": commit,
            "commit": {"tree": {"sha": tree}},
        }

    def _resource(self, name: str, body: object) -> HttpJsonEvidence:
        urls = {
            "target_repository": self.repository["url"],
            "evaluator_repository": self.evaluator_repository["url"],
            "pull_request": self.pull_request["url"],
            "base_commit": self.resource_bodies["base_commit"]["url"],
            "head_commit": self.resource_bodies["head_commit"]["url"],
            "evaluator_commit": self.resource_bodies["evaluator_commit"]["url"],
            "workflow_run": (
                "https://api.github.com/repos/example/target/actions/runs/999"
            ),
            "effective_base_rules": (
                "https://api.github.com/repos/example/target/rules/branches/main"
            ),
        }
        return HttpJsonEvidence(
            url=str(urls[name]),
            status=200,
            headers={
                "Date": "Sun, 19 Jul 2026 17:00:00 GMT",
                "ETag": f'"{name}"',
            },
            body=(
                json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("utf-8"),
        )

    def _create_contexts(self) -> None:
        self.event = {
            "action": "synchronize",
            "repository": self.repository,
            "pull_request": self.pull_request,
        }
        self.github = {
            "repository": "example/target",
            "repository_id": 101,
            "workflow_ref": (
                "example/target/.github/workflows/"
                "supportability-enforcement.yml@refs/heads/main"
            ),
            "workflow_sha": self.base_sha,
            "event_name": "pull_request_target",
            "run_id": 999,
            "run_attempt": 1,
        }
        self.job = {
            "workflow_repository": "markheck-solutions/governance",
            "workflow_file_path": ".github/workflows/supportability-gate.yml",
            "workflow_ref": (
                "markheck-solutions/governance/.github/workflows/"
                f"supportability-gate.yml@{self.evaluator_sha}"
            ),
            "workflow_sha": self.evaluator_sha,
            "artifact_name": "baseline-supportability-gate-evidence",
        }
        executable_digest = sha256_file(self.git)
        self.runtime = {
            "git": {
                "path": str(self.git),
                "sha256": executable_digest,
                "version": "git version 2.39.5",
            },
            "python": {
                "path": str(self.git),
                "sha256": executable_digest,
                "implementation": "CPython",
                "version": "3.12.13",
                "cache_tag": "cpython-312",
            },
            "docker": {
                "path": str(self.git),
                "sha256": executable_digest,
                "host": "npipe:////./pipe/docker_engine",
                "client_version": "29.5.2",
                "server_version": "29.5.2",
                "server_api_version": "1.54",
                "os": "linux",
                "architecture": "amd64",
            },
            "container_image": {
                "reference": PYTHON_IMAGE,
                "image_id": "sha256:" + "a" * 64,
            },
            "toolchain": {
                "bundle_id": CERTIFIED_TOOLCHAIN_BUNDLE_ID,
                "manifest_sha256": "b" * 64,
                "lock_sha256": "c" * 64,
            },
        }

    def _bind(self, role: str = "BASELINE", **overrides: object):
        job = deepcopy(self.job)
        if role == "CANDIDATE":
            job["artifact_name"] = "candidate-supportability-gate-evidence"
        arguments: dict[str, object] = {
            "evaluation_role": role,
            "target_root": self.target,
            "evaluator_root": self.evaluator,
            "event_payload": self.event,
            "github_context": self.github,
            "job_context": job,
            "github_resources": self.resources,
            "runtime": self.runtime,
        }
        arguments.update(overrides)
        return bind_checkout(**arguments)

    def test_binds_strict_baseline_and_candidate_policy_sources(self) -> None:
        baseline = self._bind()
        candidate = self._bind("CANDIDATE")

        self.assertEqual(baseline.policy["source"], "BASE")
        self.assertEqual(baseline.policy["commit_sha"], self.base_sha)
        self.assertEqual(candidate.policy["source"], "HEAD")
        self.assertEqual(candidate.policy["commit_sha"], self.head_sha)
        self.assertNotEqual(baseline.receipt_id, candidate.receipt_id)
        self.assertEqual(
            validate_checkout_receipt_v1(baseline)["receipt_id"],
            baseline.receipt_id,
        )

    def test_legacy_schema_remains_validation_only_and_byte_stable(self) -> None:
        legacy = {
            "schema_version": "1.0",
            "receipt_id": "a" * 64,
            "repository": {"id": 1, "full_name": "example/target"},
            "pull_request": {
                "number": 1,
                "url": "https://github.com/example/target/pull/1",
                "base_sha": "b" * 40,
                "head_sha": "c" * 40,
                "base_tree_sha": "d" * 40,
                "head_tree_sha": "e" * 40,
            },
            "evaluator": {
                "repository_id": 2,
                "repository_full_name": "markheck-solutions/governance",
                "commit_sha": "f" * 40,
                "tree_sha": "0" * 40,
            },
            "workflow": {
                "workflow_ref": "legacy",
                "run_id": 1,
                "run_attempt": 1,
                "server_url": "https://github.com",
                "api_url": "https://api.github.com",
                "observed_at": "2026-07-19T17:00:00Z",
            },
            "git_path": "git",
            "git_sha256": "1" * 64,
            "docker": {
                "path": "docker",
                "sha256": "2" * 64,
                "host": "npipe:////./pipe/docker_engine",
            },
            "config_sha256": "3" * 64,
            "standard_sha256": "4" * 64,
        }
        validate_packaged_named("checkout_receipt_legacy_v1", legacy)
        with self.assertRaises(SchemaValidationError):
            validate_packaged_named("checkout_receipt", legacy)

    def test_optional_etags_and_fork_head_are_supported(self) -> None:
        resources = deepcopy(self.resources)
        for name, evidence in resources.items():
            resources[name] = HttpJsonEvidence(
                evidence.url,
                evidence.status,
                {"Date": "Sun, 19 Jul 2026 17:00:00 GMT"},
                evidence.body,
            )
        receipt = self._bind(github_resources=resources)
        self.assertIsNone(receipt.github_resources["head_commit"]["etag"])

        fork_pr = deepcopy(self.pull_request)
        fork_pr["head"]["repo"] = {"id": 303, "full_name": "fork/target"}
        event = deepcopy(self.event)
        event["pull_request"] = fork_pr
        bodies = deepcopy(self.resource_bodies)
        bodies["pull_request"] = fork_pr
        bodies["head_commit"] = self._commit_body(
            "fork/target", self.head_sha, self.head_tree
        )
        self.resource_bodies = bodies
        resources = {name: self._resource(name, body) for name, body in bodies.items()}
        fork = self._bind(event_payload=event, github_resources=resources)
        self.assertEqual(
            fork.pull_request["head"]["repository_full_name"], "fork/target"
        )

    def test_identity_role_and_tree_mismatches_block(self) -> None:
        cases: list[tuple[str, dict[str, object]]] = []
        event = deepcopy(self.event)
        event["repository"]["id"] = 999
        cases.append(("event repository", {"event_payload": event}))
        job = deepcopy(self.job)
        job["artifact_name"] = "candidate-supportability-gate-evidence"
        cases.append(("evaluation role", {"job_context": job}))
        run_bodies = deepcopy(self.resource_bodies)
        run_bodies["workflow_run"]["referenced_workflows"] = []
        cases.append(
            ("reusable evaluator", {"github_resources": self._resources(run_bodies)})
        )
        tree_bodies = deepcopy(self.resource_bodies)
        tree_bodies["head_commit"]["commit"]["tree"]["sha"] = "f" * 40
        cases.append(
            ("target head tree", {"github_resources": self._resources(tree_bodies)})
        )

        for expected, overrides in cases:
            with (
                self.subTest(expected=expected),
                self.assertRaisesRegex(CheckoutReceiptError, expected),
            ):
                self._bind(**overrides)

    def test_hostile_or_incomplete_http_evidence_blocks(self) -> None:
        missing = dict(self.resources)
        missing.pop("effective_base_rules")
        with self.assertRaisesRegex(CheckoutReceiptError, "set is incomplete"):
            self._bind(github_resources=missing)

        duplicate = dict(self.resources)
        original = duplicate["pull_request"]
        duplicate["pull_request"] = HttpJsonEvidence(
            original.url,
            200,
            original.headers,
            b'{"number":84,"number":85}',
        )
        with self.assertRaisesRegex(CheckoutReceiptError, "duplicate keys"):
            self._bind(github_resources=duplicate)

        invalid_rules = deepcopy(self.resource_bodies)
        invalid_rules["effective_base_rules"] = {}
        with self.assertRaisesRegex(CheckoutReceiptError, "must be an array"):
            self._bind(github_resources=self._resources(invalid_rules))

        wrong_url = dict(self.resources)
        original = wrong_url["workflow_run"]
        wrong_url["workflow_run"] = HttpJsonEvidence(
            "https://api.github.com/repos/example/target/actions/runs/998",
            200,
            original.headers,
            original.body,
        )
        with self.assertRaisesRegex(CheckoutReceiptError, "workflow_run resource URL"):
            self._bind(github_resources=wrong_url)

    def test_validator_blocks_rehashed_cross_field_mutation_and_returns_copy(
        self,
    ) -> None:
        receipt = self._bind()
        payload = receipt.to_json()
        validated = validate_checkout_receipt_v1(payload)
        validated["repository"]["full_name"] = "changed/value"
        self.assertEqual(receipt.repository["full_name"], "example/target")

        hostile = receipt.to_json()
        hostile["evaluation_target"]["tree_sha"] = "f" * 40
        unsigned = deepcopy(hostile)
        unsigned.pop("receipt_id")
        hostile["receipt_id"] = sha256_json(unsigned)
        with self.assertRaisesRegex(CheckoutReceiptError, "evaluation target"):
            validate_checkout_receipt_v1(hostile)

    def test_dirty_checkout_and_runtime_mutation_block(self) -> None:
        (self.target / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaisesRegex(CheckoutReceiptError, "target checkout is dirty"):
            self._bind()
        (self.target / "untracked.txt").unlink()

        runtime = deepcopy(self.runtime)
        runtime["toolchain"]["bundle_id"] = "f" * 64
        with self.assertRaisesRegex(CheckoutReceiptError, "not certified"):
            self._bind(runtime=runtime)

    def test_caller_comments_cannot_spoof_role_binding(self) -> None:
        expected = self.evaluator_sha
        hostile = (
            "name: Supportability Enforcement\n"
            "jobs:\n"
            "  baseline-supportability:\n"
            "    uses: attacker/repository/.github/workflows/gate.yml@main\n"
            "    with:\n"
            "      governance-ref: main\n"
            "      artifact-name: attacker-evidence\n"
            f"    # uses: markheck-solutions/governance/.github/workflows/supportability-gate.yml@{expected}\n"
            f"    # governance-ref: {expected}\n"
            "    # artifact-name: baseline-supportability-gate-evidence\n"
        ).encode()
        with self.assertRaisesRegex(CheckoutReceiptError, "role binding"):
            checkout_receipt._validate_role_binding(
                "BASELINE", hostile, self.job, self.evaluator_sha
            )

    def test_serialized_receipt_revalidates_embedded_api_bodies(self) -> None:
        hostile = self._bind().to_json()
        replacement = json.dumps({"id": 999}).encode()
        resource = hostile["github_resources"]["target_repository"]
        resource["body_base64"] = base64.b64encode(replacement).decode("ascii")
        resource["body_sha256"] = sha256(replacement).hexdigest()
        unsigned = deepcopy(hostile)
        unsigned.pop("receipt_id")
        hostile["receipt_id"] = sha256_json(unsigned)

        with self.assertRaisesRegex(CheckoutReceiptError, "repository"):
            validate_checkout_receipt_v1(hostile)

    def test_serialized_validation_is_pure_but_semantically_strict(self) -> None:
        payload = self._bind().to_json()
        payload["runtime"]["git"]["path"] = str(self.root / "missing-git.exe")
        unsigned = deepcopy(payload)
        unsigned.pop("receipt_id")
        payload["receipt_id"] = sha256_json(unsigned)
        self.assertEqual(
            validate_checkout_receipt_v1(payload)["receipt_id"], payload["receipt_id"]
        )

        payload["workflows"]["run"]["observed_at"] = "2026-99-99T99:99:99Z"
        for resource in payload["github_resources"].values():
            resource["observed_at"] = "2026-99-99T99:99:99Z"
        unsigned = deepcopy(payload)
        unsigned.pop("receipt_id")
        payload["receipt_id"] = sha256_json(unsigned)
        with self.assertRaisesRegex(CheckoutReceiptError, "timestamp"):
            validate_checkout_receipt_v1(payload)

    def test_malformed_deep_and_large_integer_json_fails_closed(self) -> None:
        original = self.resources["effective_base_rules"]
        for raw in (
            (b"[" * 5000) + (b"]" * 5000),
            b"[" + (b"9" * 5000) + b"]",
        ):
            with self.subTest(size=len(raw)):
                resources = dict(self.resources)
                resources["effective_base_rules"] = HttpJsonEvidence(
                    original.url,
                    original.status,
                    original.headers,
                    raw,
                )
                with self.assertRaisesRegex(CheckoutReceiptError, "malformed"):
                    self._bind(github_resources=resources)

    def _resources(self, bodies: dict[str, object]) -> dict[str, HttpJsonEvidence]:
        original = self.resource_bodies
        try:
            self.resource_bodies = bodies
            return {name: self._resource(name, body) for name, body in bodies.items()}
        finally:
            self.resource_bodies = original


if __name__ == "__main__":
    unittest.main()
