from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from governance_eval.paths import repo_root
from governance_eval.schema_validator import SchemaValidationError
from governance_eval.schemas import validate_named
from governance_eval.target_eval import (
    NON_BLOCKING,
    SHADOW_ASK_BUSINESS,
    SHADOW_BLOCK_TECHNICAL,
    SHADOW_MERGE,
    evaluate_target,
    _parse_github_repository,
)
from governance_eval.target_pack import load_target_pack, validate_target_request


class TargetPackAndShadowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def test_target_packs_are_schema_valid_and_policy_driven(self) -> None:
        for relative in [
            "target_packs/spaghetti/v1/pack.json",
            "target_packs/synthetic_clean/v1/pack.json",
            "target_packs/synthetic_evasion/v1/pack.json",
        ]:
            pack = load_target_pack(self.root / relative)
            self.assertIn("behavior_cases", pack)
            self.assertEqual(
                set(pack["structural_detectors"]) - set(pack["detector_policies"]),
                set(),
            )
            self.assertIn("CANDIDATE_DYNAMIC", pack["revision_modes"])

    def test_schema_rejects_fixture_only_required_behavior_pack(self) -> None:
        pack = _mutable_pack(self.root / "target_packs/spaghetti/v1/pack.json")
        pack["behavior_cases"][0]["provenance_classification"] = "FIXTURE_ONLY"
        validate_named("target_pack", pack, self.root)
        with tempfile.TemporaryDirectory() as tmp:
            target = _make_synthetic_repo(Path(tmp), evasion=False)
            _retarget_pack(pack, target)
            case = pack["behavior_cases"][0]
            case["pull_request"] = None
            case["expected_source_hashes"] = {}
            case["reproducer"] = "target_packs/synthetic_clean/v1/reproducer.py"
            case["source_files"] = ["src/demo/api.py"]
            case["source_symbols"] = [{"path": "src/demo/api.py", "symbol": "classify"}]
            case["expected_base_result"] = {"value": "ok"}
            case["comparison_policies"] = {
                "HISTORICAL_FIXED": "PINNED_EXPECTED",
                "SAFE_FIXED": "PINNED_EXPECTED",
                "CANDIDATE_DYNAMIC": "PRESERVE_BASE_BEHAVIOR",
            }
            pack_path = Path(tmp) / "pack.json"
            pack_path.write_text(json.dumps(pack), encoding="utf-8")
            result = evaluate_target(pack_path, target["base"], target["head"])
        self.assertEqual(result["real_target_shadow_decision"], SHADOW_BLOCK_TECHNICAL)
        self.assertTrue(
            any("FIXTURE_ONLY" in error for error in result["acceptance_errors"])
        )

    def test_pull_request_pack_requires_expected_source_hashes(self) -> None:
        pack = _mutable_pack(self.root / "target_packs/spaghetti/v1/pack.json")
        del pack["behavior_cases"][0]["expected_source_hashes"]
        with tempfile.TemporaryDirectory() as tmp:
            pack_path = Path(tmp) / "pack.json"
            pack_path.write_text(json.dumps(pack), encoding="utf-8")
            with self.assertRaises(SchemaValidationError):
                load_target_pack(pack_path)

    def test_pull_request_pack_rejects_empty_expected_source_hash_sets(self) -> None:
        pack = _mutable_pack(self.root / "target_packs/spaghetti/v1/pack.json")
        base_sha = pack["immutable_revisions"]["base_sha"]
        head_sha = pack["immutable_revisions"]["head_sha"]
        pack["behavior_cases"][0]["expected_source_hashes"] = {
            base_sha: {"files": {}, "symbols": {}},
            head_sha: {"files": {}, "symbols": {}},
        }
        with tempfile.TemporaryDirectory() as tmp:
            pack_path = Path(tmp) / "pack.json"
            pack_path.write_text(json.dumps(pack), encoding="utf-8")
            with self.assertRaises(SchemaValidationError):
                load_target_pack(pack_path)

    def test_partial_comparison_policy_defaults_still_require_pinned_expected_result(
        self,
    ) -> None:
        pack = _mutable_pack(self.root / "target_packs/synthetic_clean/v1/pack.json")
        del pack["behavior_cases"][0]["expected_base_result"]
        pack["behavior_cases"][0]["comparison_policies"] = {
            "CANDIDATE_DYNAMIC": "PRESERVE_BASE_BEHAVIOR"
        }
        with tempfile.TemporaryDirectory() as tmp:
            pack_path = Path(tmp) / "pack.json"
            pack_path.write_text(json.dumps(pack), encoding="utf-8")
            with self.assertRaises(SchemaValidationError):
                load_target_pack(pack_path)

    def test_synthetic_clean_target_shadow_merges(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = _make_synthetic_repo(Path(tmp), evasion=False)
            pack_path = _pack_copy(
                self.root / "target_packs/synthetic_clean/v1/pack.json",
                Path(tmp) / "pack.json",
                target,
            )
            result = evaluate_target(
                pack_path, target["base"], target["head"], Path(tmp) / "artifacts"
            )
            repeated = evaluate_target(pack_path, target["base"], target["head"])
        self.assertEqual(result["real_target_shadow_decision"], SHADOW_MERGE)
        self.assertEqual(result["enforcement_mode"], NON_BLOCKING)
        self.assertEqual(result["case_counts"]["behavior_cases_passed"], 1)
        self.assertEqual(result["applicable_behavior_case_count"], 1)
        self.assertEqual(result["case_counts"]["required_behavior_case_count"], 1)
        self.assertEqual(
            result["behavior_results"][0]["provenance_classification"],
            "EXECUTES_PINNED_TARGET_CODE",
        )
        self.assertEqual(result["revision_mode"], "HISTORICAL_FIXED")
        self.assertEqual(result["review_gate"], "NOT_APPLICABLE")
        self.assertEqual(result["github_review_state"], "NOT_APPLICABLE")
        self.assertRegex(result["artifact_content_hash"], r"^[0-9a-f]{64}$")
        self.assertRegex(result["deterministic_evidence_hash"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            result["deterministic_evidence_hash"],
            repeated["deterministic_evidence_hash"],
        )

    def test_candidate_dynamic_with_all_behavior_cases_filtered_out_blocks(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = _make_synthetic_repo(Path(tmp), evasion=False)
            pack_path = _pack_copy(
                self.root / "target_packs/synthetic_clean/v1/pack.json",
                Path(tmp) / "pack.json",
                target,
            )
            data = _mutable_pack(pack_path)
            data["behavior_cases"][0]["revision_modes"] = ["HISTORICAL_FIXED"]
            pack_path.write_text(json.dumps(data), encoding="utf-8")
            result = evaluate_target(
                pack_path,
                target["base"],
                target["head"],
                revision_mode="CANDIDATE_DYNAMIC",
            )

        self.assertEqual(result["real_target_shadow_decision"], SHADOW_BLOCK_TECHNICAL)
        self.assertEqual(result["applicable_behavior_case_count"], 0)
        self.assertTrue(
            any(
                "no applicable behavior cases for revision mode CANDIDATE_DYNAMIC"
                in error
                for error in result["acceptance_errors"]
            )
        )

    def test_historical_fixed_with_all_behavior_cases_filtered_out_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = _make_synthetic_repo(Path(tmp), evasion=False)
            pack_path = _pack_copy(
                self.root / "target_packs/synthetic_clean/v1/pack.json",
                Path(tmp) / "pack.json",
                target,
            )
            data = _mutable_pack(pack_path)
            data["behavior_cases"][0]["revision_modes"] = ["CANDIDATE_DYNAMIC"]
            pack_path.write_text(json.dumps(data), encoding="utf-8")
            result = evaluate_target(
                pack_path,
                target["base"],
                target["head"],
                revision_mode="HISTORICAL_FIXED",
            )

        self.assertEqual(result["real_target_shadow_decision"], SHADOW_BLOCK_TECHNICAL)
        self.assertEqual(result["applicable_behavior_case_count"], 0)
        self.assertTrue(
            any(
                "no applicable behavior cases for revision mode HISTORICAL_FIXED"
                in error
                for error in result["acceptance_errors"]
            )
        )

    def test_advisory_behavior_cases_do_not_satisfy_required_behavior_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = _make_synthetic_repo(Path(tmp), evasion=False)
            pack_path = _pack_copy(
                self.root / "target_packs/synthetic_clean/v1/pack.json",
                Path(tmp) / "pack.json",
                target,
            )
            data = _mutable_pack(pack_path)
            data["behavior_cases"][0]["required_behavior_evidence"] = False
            pack_path.write_text(json.dumps(data), encoding="utf-8")
            result = evaluate_target(
                pack_path,
                target["base"],
                target["head"],
                revision_mode="CANDIDATE_DYNAMIC",
            )

        self.assertEqual(result["real_target_shadow_decision"], SHADOW_BLOCK_TECHNICAL)
        self.assertEqual(result["applicable_behavior_case_count"], 0)
        self.assertEqual(result["case_counts"]["advisory_behavior_case_count"], 1)
        self.assertTrue(
            any(
                "no applicable behavior cases" in error
                for error in result["acceptance_errors"]
            )
        )

    def test_required_unknown_structural_detector_blocks_and_advisory_unknown_does_not(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = _make_synthetic_repo(Path(tmp), evasion=False)
            required_pack = _pack_copy(
                self.root / "target_packs/synthetic_clean/v1/pack.json",
                Path(tmp) / "required.json",
                target,
            )
            data = _mutable_pack(required_pack)
            data["structural_detectors"].append("missing_required_detector")
            data["detector_policies"]["missing_required_detector"] = {
                "required": True,
                "blocking": True,
                "fail_on_unknown": True,
                "thresholds": {},
            }
            required_pack.write_text(json.dumps(data), encoding="utf-8")
            required_result = evaluate_target(
                required_pack, target["base"], target["head"]
            )

            advisory_pack = Path(tmp) / "advisory.json"
            data["structural_detectors"][-1] = "missing_advisory_detector"
            data["detector_policies"].pop("missing_required_detector")
            data["detector_policies"]["missing_advisory_detector"] = {
                "required": False,
                "blocking": False,
                "fail_on_unknown": False,
                "thresholds": {},
            }
            advisory_pack.write_text(json.dumps(data), encoding="utf-8")
            advisory_result = evaluate_target(
                advisory_pack, target["base"], target["head"]
            )

        self.assertEqual(
            required_result["real_target_shadow_decision"], SHADOW_BLOCK_TECHNICAL
        )
        self.assertEqual(
            required_result["structural_measurements"]["unknown_required_count"], 1
        )
        self.assertEqual(advisory_result["real_target_shadow_decision"], SHADOW_MERGE)
        self.assertEqual(
            advisory_result["structural_measurements"]["unknown_advisory_count"], 1
        )

    def test_missing_source_symbol_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = _make_synthetic_repo(Path(tmp), evasion=False)
            data = _mutable_pack(
                self.root / "target_packs/synthetic_clean/v1/pack.json"
            )
            _retarget_pack(data, target)
            data["behavior_cases"][0]["source_symbols"] = [
                {"path": "src/demo/api.py", "symbol": "missing_symbol"}
            ]
            pack_path = Path(tmp) / "pack.json"
            pack_path.write_text(json.dumps(data), encoding="utf-8")
            result = evaluate_target(pack_path, target["base"], target["head"])
        self.assertEqual(result["real_target_shadow_decision"], SHADOW_BLOCK_TECHNICAL)
        self.assertTrue(
            any(
                "source hash validation failed" in error
                for error in result["acceptance_errors"]
            )
        )

    def test_repository_override_rejected_and_candidate_mode_accepts_unlisted_valid_shas(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = _make_synthetic_repo(Path(tmp), evasion=False)
            pack_path = _pack_copy(
                self.root / "target_packs/synthetic_clean/v1/pack.json",
                Path(tmp) / "pack.json",
                target,
            )
            with self.assertRaises(ValueError):
                evaluate_target(
                    pack_path,
                    target["base"],
                    target["head"],
                    repository_url="https://example.invalid/other.git",
                )

            dynamic = _make_synthetic_repo(Path(tmp) / "dynamic", evasion=True)
            data = _mutable_pack(pack_path)
            _retarget_pack(data, dynamic)
            data["immutable_revisions"] = {
                "base_sha": "0" * 40,
                "head_sha": "0" * 40,
                "safe_base_sha": "0" * 40,
                "safe_head_sha": "0" * 40,
            }
            dynamic_pack = Path(tmp) / "dynamic-pack.json"
            dynamic_pack.write_text(json.dumps(data), encoding="utf-8")
            result = evaluate_target(
                dynamic_pack,
                dynamic["base"],
                dynamic["head"],
                revision_mode="CANDIDATE_DYNAMIC",
            )
        self.assertEqual(result["revision_mode"], "CANDIDATE_DYNAMIC")

    def test_github_candidate_pr_number_must_match_base_and_head(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = _make_synthetic_repo(Path(tmp), evasion=False)
            pack_path = _pack_copy(
                self.root / "target_packs/synthetic_clean/v1/pack.json",
                Path(tmp) / "pack.json",
                target,
            )
            data = _mutable_pack(pack_path)
            data["repository_url"] = "https://github.com/example/synthetic-clean.git"
            data["repository_identity"]["canonical_url"] = data["repository_url"]
            pack_path.write_text(json.dumps(data), encoding="utf-8")
            with (
                mock.patch(
                    "governance_eval.target_eval._checkout",
                    side_effect=[Path(tmp) / "base", Path(tmp) / "head"],
                ),
                mock.patch(
                    "governance_eval.target_eval._commit_exists", return_value=True
                ),
                mock.patch(
                    "governance_eval.target_eval._candidate_pull_request_validation",
                    return_value={
                        "status": "FAIL",
                        "reason": "target PR base/head does not match supplied revisions",
                    },
                ),
                mock.patch(
                    "governance_eval.target_eval._run_setup_commands", return_value=[]
                ),
                mock.patch(
                    "governance_eval.target_eval._changed_files", return_value=set()
                ),
                mock.patch(
                    "governance_eval.target_eval._run_behavior_case",
                    return_value={
                        "case_id": "mock",
                        "status": "PASS",
                        "required_behavior_evidence": True,
                        "behavior_comparison_policy": "PRESERVE_BASE_BEHAVIOR",
                        "provenance_classification": "EXECUTES_PINNED_TARGET_CODE",
                        "classification_reason": "",
                        "target_repository_url": data["repository_url"],
                        "pull_request": None,
                        "base_sha": target["base"],
                        "head_sha": target["head"],
                        "merge_sha": None,
                        "base_execution": _mock_execution(target["base"]),
                        "head_execution": _mock_execution(target["head"]),
                        "expected_result": {},
                        "observed_result": {},
                        "source_files": {"base": [], "head": []},
                        "source_symbols": {"base": [], "head": []},
                        "source_hash_validation": "PASS",
                        "reproducer_files": [],
                        "commands": [],
                    },
                ),
                mock.patch(
                    "governance_eval.target_eval.scan_structural_metrics",
                    return_value={"cross_module_private_references": []},
                ),
                mock.patch(
                    "governance_eval.target_eval.structural_delta",
                    return_value={
                        "cross_module_private_references": {
                            "status": "MEASURED",
                            "introduced": [],
                            "policy": data["detector_policies"][
                                "cross_module_private_references"
                            ],
                            "base_count": 0,
                            "head_count": 0,
                            "existing": [],
                            "removed": [],
                            "threshold": {},
                            "evidence": {},
                            "reason": "",
                        }
                    },
                ),
            ):
                result = evaluate_target(
                    pack_path,
                    target["base"],
                    target["head"],
                    revision_mode="CANDIDATE_DYNAMIC",
                    target_pr_number=999,
                )

        self.assertEqual(result["real_target_shadow_decision"], SHADOW_BLOCK_TECHNICAL)
        self.assertTrue(
            any(
                "candidate pull request validation failed" in error
                for error in result["acceptance_errors"]
            )
        )

    def test_github_repository_parser_accepts_dotted_repository_names(self) -> None:
        self.assertEqual(
            _parse_github_repository("https://github.com/example/repo.name.git"),
            ("example", "repo.name"),
        )

    def test_historical_pair_requires_merge_sha(self) -> None:
        pack_path = self.root / "target_packs/spaghetti/v1/pack.json"
        pack = load_target_pack(pack_path)
        with self.assertRaises(ValueError):
            evaluate_target(
                pack_path,
                pack["immutable_revisions"]["base_sha"],
                pack["immutable_revisions"]["head_sha"],
                revision_mode="HISTORICAL_FIXED",
            )

    def test_target_pack_path_traversal_and_symlink_escape_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            outside = Path(tmp) / "outside.json"
            outside.write_text("{}", encoding="utf-8")
            with self.assertRaises(SchemaValidationError):
                validate_target_request(
                    Path("../outside.json"),
                    "https://example.invalid/repo.git",
                    "0" * 40,
                    "0" * 40,
                    None,
                    "CANDIDATE_DYNAMIC",
                    self.root,
                )
            if hasattr(os, "symlink"):
                symlink = (
                    self.root
                    / "target_packs"
                    / "synthetic_clean"
                    / "v1"
                    / f"pack-link-test-{uuid.uuid4().hex}.json"
                )
                try:
                    try:
                        os.symlink(outside, symlink)
                    except OSError as exc:
                        self.skipTest(f"symlink creation unavailable: {exc}")
                    with self.assertRaises(SchemaValidationError):
                        load_target_pack(
                            symlink, root=self.root, require_governance_owned=True
                        )
                finally:
                    try:
                        if symlink.exists() or symlink.is_symlink():
                            symlink.unlink()
                    except FileNotFoundError:
                        pass

    def test_business_review_policy_produces_ask_business(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = _make_synthetic_repo(
                Path(tmp), evasion=False, behavior_change=True
            )
            pack_path = _pack_copy(
                self.root / "target_packs/synthetic_clean/v1/pack.json",
                Path(tmp) / "pack.json",
                target,
            )
            data = _mutable_pack(pack_path)
            data["behavior_cases"][0]["comparison_policies"]["CANDIDATE_DYNAMIC"] = (
                "BUSINESS_REVIEW_ON_CHANGE"
            )
            pack_path.write_text(json.dumps(data), encoding="utf-8")
            result = evaluate_target(
                pack_path,
                target["base"],
                target["head"],
                revision_mode="CANDIDATE_DYNAMIC",
            )
        self.assertEqual(result["real_target_shadow_decision"], SHADOW_ASK_BUSINESS)
        self.assertEqual(result["case_counts"]["behavior_cases_business_ambiguous"], 1)

    def test_result_schema_rejects_malformed_nested_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = _make_synthetic_repo(Path(tmp), evasion=False)
            pack_path = _pack_copy(
                self.root / "target_packs/synthetic_clean/v1/pack.json",
                Path(tmp) / "pack.json",
                target,
            )
            result = evaluate_target(pack_path, target["base"], target["head"])
        result["behavior_results"][0]["base_execution"]["source_files"] = [{}]
        with self.assertRaises(SchemaValidationError):
            validate_named("target_evaluation_result", result, self.root)

    def test_result_schema_rejects_empty_revision_and_structural_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = _make_synthetic_repo(Path(tmp), evasion=False)
            pack_path = _pack_copy(
                self.root / "target_packs/synthetic_clean/v1/pack.json",
                Path(tmp) / "pack.json",
                target,
            )
            result = evaluate_target(pack_path, target["base"], target["head"])
            result["revision_validation"] = {}
            with self.assertRaises(SchemaValidationError):
                validate_named("target_evaluation_result", result, self.root)
            result = evaluate_target(pack_path, target["base"], target["head"])
            result["structural_delta"] = {}
            with self.assertRaises(SchemaValidationError):
                validate_named("target_evaluation_result", result, self.root)
            result = evaluate_target(pack_path, target["base"], target["head"])
            result["structural_measurements"] = {}
            with self.assertRaises(SchemaValidationError):
                validate_named("target_evaluation_result", result, self.root)

    def test_synthetic_evasion_target_shadow_blocks_structural_delta(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = _make_synthetic_repo(Path(tmp), evasion=True)
            pack_path = _pack_copy(
                self.root / "target_packs/synthetic_evasion/v1/pack.json",
                Path(tmp) / "pack.json",
                target,
            )
            result = evaluate_target(pack_path, target["base"], target["head"])
        self.assertEqual(result["real_target_shadow_decision"], SHADOW_BLOCK_TECHNICAL)
        delta = result["structural_delta"]
        self.assertGreater(
            delta["weak_public_contracts"]["head_count"],
            delta["weak_public_contracts"]["base_count"],
        )
        self.assertIn("demo.api", delta["module_dependency_fanout"]["introduced"])
        self.assertTrue(delta["large_typed_god_modules"]["introduced"])
        self.assertEqual(
            delta["publicized_private_helper_renames"]["status"], "MEASURED"
        )
        self.assertTrue(delta["publicized_private_helper_renames"]["introduced"])


def _mutable_pack(source: Path) -> dict:
    return json.loads(source.read_text(encoding="utf-8"))


def _retarget_pack(data: dict, target: dict[str, str]) -> None:
    data["repository_url"] = target["url"]
    data["repository_identity"]["canonical_url"] = target["url"]
    data["immutable_revisions"] = {
        "base_sha": target["base"],
        "head_sha": target["head"],
        "safe_base_sha": target["base"],
        "safe_head_sha": target["base"],
    }


def _pack_copy(source: Path, dest: Path, target: dict[str, str]) -> Path:
    data = _mutable_pack(source)
    _retarget_pack(data, target)
    dest.write_text(json.dumps(data), encoding="utf-8")
    return dest


def _make_synthetic_repo(
    root: Path, evasion: bool, behavior_change: bool = False
) -> dict[str, str]:
    repo = root / "target-repo"
    (repo / "src/demo").mkdir(parents=True)
    _write(
        repo / "src/demo/api.py",
        "def _helper(value):\n    return 'ok'\n\n\ndef classify(value):\n    return _helper(value)\n",
    )
    _git(repo, "init")
    _git(repo, "config", "user.email", "governance@example.invalid")
    _git(repo, "config", "user.name", "Governance Test")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD").strip()
    if evasion or behavior_change:
        if evasion:
            for index in range(13):
                _write(repo / f"src/demo/m{index}.py", f"VALUE = {index}\n")
            fanout_imports = "\n".join(f"import demo.m{index}" for index in range(13))
            _write(
                repo / "src/demo/api.py",
                fanout_imports
                + "\nfrom typing import Any, TypedDict\n\n"
                + "class Payload(TypedDict):\n    data: Any\n\n"
                + "def helper(value):\n    return 'ok'\n\n"
                + "def classify(value):\n    return helper(value)\n\n"
                + "def leaky(data: dict[str, Any]) -> dict[str, Any]:\n    return data\n",
            )
            functions = "\n".join(
                f"def function_{index}(value: int) -> int:\n    return value + {index}\n"
                for index in range(21)
            )
            padding = "\n".join(f"# line {index}" for index in range(410))
            _write(
                repo / "src/demo/god.py",
                "from typing import TypedDict\n\nclass Row(TypedDict):\n    value: int\n\n"
                + functions
                + padding,
            )
        else:
            _write(
                repo / "src/demo/api.py", "def classify(value):\n    return 'changed'\n"
            )
        _git(repo, "add", ".")
        _git(repo, "commit", "-m", "head")
        head = _git(repo, "rev-parse", "HEAD").strip()
    else:
        head = base
    return {"url": repo.as_uri(), "base": base, "head": head}


def _mock_execution(sha: str) -> dict:
    return {
        "exact_revision_executed": sha,
        "command": "mock",
        "exit_code": 0,
        "timed_out": False,
        "stdout_hash": "0" * 64,
        "stderr_hash": "0" * 64,
        "observed_result": {},
        "source_files": [],
        "source_symbols": [],
        "source_hash_validation": "PASS",
    }


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", *args], cwd=repo, text=True, stderr=subprocess.STDOUT
    )


if __name__ == "__main__":
    unittest.main()
