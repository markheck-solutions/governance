from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from governance_eval.paths import repo_root
from governance_eval.schema_validator import SchemaValidationError
from governance_eval.schemas import validate_named
from governance_eval.target_eval import NON_BLOCKING, SHADOW_BLOCK_TECHNICAL, SHADOW_MERGE, evaluate_target
from governance_eval.target_pack import load_target_pack


class TargetPackAndShadowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def test_target_packs_are_schema_valid_and_isolated(self) -> None:
        for relative in [
            "target_packs/spaghetti/v1/pack.json",
            "target_packs/synthetic_clean/v1/pack.json",
            "target_packs/synthetic_evasion/v1/pack.json",
        ]:
            pack = load_target_pack(self.root / relative)
            self.assertIn("behavior_cases", pack)
            self.assertNotEqual(pack["id"], "")

    def test_schema_rejects_fixture_only_required_behavior_pack(self) -> None:
        pack = load_target_pack(self.root / "target_packs/spaghetti/v1/pack.json")
        pack["behavior_cases"][0]["provenance_classification"] = "FIXTURE_ONLY"
        validate_named("target_pack", pack, self.root)
        with tempfile.TemporaryDirectory() as tmp:
            target = _make_synthetic_repo(Path(tmp), evasion=False)
            pack["repository_url"] = target["url"]
            pack["immutable_revisions"] = {"base_sha": target["base"], "head_sha": target["head"]}
            pack["behavior_cases"][0]["pull_request"] = None
            pack["behavior_cases"][0]["expected_source_hashes"] = {}
            pack["behavior_cases"][0]["reproducer"] = "target_packs/synthetic_clean/v1/reproducer.py"
            pack["behavior_cases"][0]["source_files"] = ["src/demo/api.py"]
            pack["behavior_cases"][0]["source_symbols"] = [{"path": "src/demo/api.py", "symbol": "classify"}]
            pack["behavior_cases"][0]["expected_base_result"] = {"value": "ok"}
            pack_path = Path(tmp) / "pack.json"
            pack_path.write_text(json.dumps(pack), encoding="utf-8")
            result = evaluate_target(pack_path, target["base"], target["head"])
        self.assertEqual(result["real_target_shadow_decision"], SHADOW_BLOCK_TECHNICAL)
        self.assertTrue(any("FIXTURE_ONLY" in error for error in result["acceptance_errors"]))

    def test_pull_request_pack_requires_expected_source_hashes(self) -> None:
        pack = load_target_pack(self.root / "target_packs/spaghetti/v1/pack.json")
        del pack["behavior_cases"][0]["expected_source_hashes"]
        with tempfile.TemporaryDirectory() as tmp:
            pack_path = Path(tmp) / "pack.json"
            pack_path.write_text(json.dumps(pack), encoding="utf-8")
            with self.assertRaises(SchemaValidationError):
                load_target_pack(pack_path)

    def test_pull_request_pack_rejects_empty_expected_source_hash_sets(self) -> None:
        pack = load_target_pack(self.root / "target_packs/spaghetti/v1/pack.json")
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

    def test_synthetic_clean_target_shadow_merges(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = _make_synthetic_repo(Path(tmp), evasion=False)
            pack_path = _pack_copy(
                self.root / "target_packs/synthetic_clean/v1/pack.json",
                Path(tmp) / "pack.json",
                target,
            )
            result = evaluate_target(pack_path, target["base"], target["head"], Path(tmp) / "artifacts")
            repeated = evaluate_target(pack_path, target["base"], target["head"])
        self.assertEqual(result["real_target_shadow_decision"], SHADOW_MERGE)
        self.assertEqual(result["enforcement_mode"], NON_BLOCKING)
        self.assertEqual(result["case_counts"]["behavior_cases_passed"], 1)
        self.assertEqual(result["behavior_results"][0]["provenance_classification"], "EXECUTES_PINNED_TARGET_CODE")
        self.assertRegex(result["artifact_content_hash"], r"^[0-9a-f]{64}$")
        self.assertRegex(result["deterministic_evidence_hash"], r"^[0-9a-f]{64}$")
        self.assertEqual(result["deterministic_evidence_hash"], repeated["deterministic_evidence_hash"])

    def test_missing_source_symbol_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = _make_synthetic_repo(Path(tmp), evasion=False)
            data = json.loads((self.root / "target_packs/synthetic_clean/v1/pack.json").read_text(encoding="utf-8"))
            data["repository_url"] = target["url"]
            data["immutable_revisions"] = {"base_sha": target["base"], "head_sha": target["head"]}
            data["behavior_cases"][0]["source_symbols"] = [{"path": "src/demo/api.py", "symbol": "missing_symbol"}]
            pack_path = Path(tmp) / "pack.json"
            pack_path.write_text(json.dumps(data), encoding="utf-8")
            result = evaluate_target(pack_path, target["base"], target["head"])
        self.assertEqual(result["real_target_shadow_decision"], SHADOW_BLOCK_TECHNICAL)
        self.assertTrue(any("source hash validation failed" in error for error in result["acceptance_errors"]))

    def test_target_pack_rejects_repository_override_and_unlisted_shas(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = _make_synthetic_repo(Path(tmp), evasion=False)
            pack_path = _pack_copy(
                self.root / "target_packs/synthetic_clean/v1/pack.json",
                Path(tmp) / "pack.json",
                target,
            )
            with self.assertRaises(ValueError):
                evaluate_target(pack_path, target["base"], target["head"], repository_url="https://example.invalid/other.git")
            with self.assertRaises(ValueError):
                evaluate_target(pack_path, "f" * 40, target["head"])

    def test_historical_pair_requires_merge_sha(self) -> None:
        pack_path = self.root / "target_packs/spaghetti/v1/pack.json"
        pack = load_target_pack(pack_path)
        with self.assertRaises(ValueError):
            evaluate_target(
                pack_path,
                pack["immutable_revisions"]["base_sha"],
                pack["immutable_revisions"]["head_sha"],
            )

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
        self.assertGreater(delta["weak_public_contracts"]["head_count"], delta["weak_public_contracts"]["base_count"])
        self.assertIn("demo.api", delta["module_dependency_fanout"]["introduced"])
        self.assertTrue(delta["large_typed_god_modules"]["introduced"])
        self.assertEqual(delta["publicized_private_helper_renames"]["status"], "UNKNOWN")


def _pack_copy(source: Path, dest: Path, target: dict[str, str]) -> Path:
    data = json.loads(source.read_text(encoding="utf-8"))
    data["repository_url"] = target["url"]
    data["immutable_revisions"] = {"base_sha": target["base"], "head_sha": target["head"]}
    dest.write_text(json.dumps(data), encoding="utf-8")
    return dest


def _make_synthetic_repo(root: Path, evasion: bool) -> dict[str, str]:
    repo = root / "target-repo"
    (repo / "src/demo").mkdir(parents=True)
    _write(repo / "src/demo/api.py", "def _helper(value):\n    return 'ok'\n\n\ndef classify(value):\n    return _helper(value)\n")
    _git(repo, "init")
    _git(repo, "config", "user.email", "governance@example.invalid")
    _git(repo, "config", "user.name", "Governance Test")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD").strip()
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
        functions = "\n".join(f"def function_{index}(value: int) -> int:\n    return value + {index}\n" for index in range(21))
        padding = "\n".join(f"# line {index}" for index in range(410))
        _write(repo / "src/demo/god.py", "from typing import TypedDict\n\nclass Row(TypedDict):\n    value: int\n\n" + functions + padding)
    if evasion:
        _git(repo, "add", ".")
        _git(repo, "commit", "-m", "head")
        head = _git(repo, "rev-parse", "HEAD").strip()
    else:
        head = base
    return {"url": repo.as_uri(), "base": base, "head": head}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True, stderr=subprocess.STDOUT)


if __name__ == "__main__":
    unittest.main()
