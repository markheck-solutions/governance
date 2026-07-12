from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from governance_eval.target_eval import SHADOW_MERGE, evaluate_target
from governance_eval.target_workflow import _raw_result_errors, create_target_plan


ROOT = Path(__file__).resolve().parents[1]


class TargetWorkflowTests(unittest.TestCase):
    def test_candidate_plan_requires_pr_identity(self) -> None:
        pack_path = ROOT / "target_packs" / "synthetic_clean" / "v1" / "pack.json"
        with tempfile.TemporaryDirectory() as tmp, self.assertRaisesRegex(ValueError, "requires target_pr_number"):
            create_target_plan(
                pack_path,
                "https://example.invalid/synthetic-clean.git",
                "a" * 40,
                "b" * 40,
                None,
                "CANDIDATE_DYNAMIC",
                "SHADOW",
                "markheck-solutions/governance",
                "c" * 40,
                None,
                Path(tmp) / "plan.json",
            )

    def test_command_only_adapter_runs_through_public_target_interface(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=target, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=target, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=target, check=True)
            (target / "governance.json").write_text('{"status":"ok"}', encoding="utf-8")
            subprocess.run(["git", "add", "governance.json"], cwd=target, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "control"], cwd=target, check=True)
            sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
            pack = json.loads((ROOT / "target_packs/command_only/v1/pack.json").read_text(encoding="utf-8"))
            pack["repository_url"] = str(target)
            pack["repository_identity"] = {"canonical_url": str(target)}
            pack["immutable_revisions"] = {"base_sha": sha, "head_sha": sha, "safe_base_sha": sha, "safe_head_sha": sha}
            pack_path = root / "pack.json"
            pack_path.write_text(json.dumps(pack), encoding="utf-8")
            result = evaluate_target(pack_path, sha, sha)
            self.assertEqual(result["real_target_shadow_decision"], SHADOW_MERGE)
            self.assertEqual(result["target_pack_id"], "command-only-v1")

    def test_raw_result_identity_and_setup_are_bound_to_trusted_plan(self) -> None:
        item = {
            "id": "case-1-base",
            "case_id": "case-1",
            "side": "base",
            "sha": "a" * 40,
            "exit_code": 0,
            "timed_out": False,
            "observed_result": {},
            "setup_results": [{"command": "python -m pip check"}],
        }
        self.assertEqual(_raw_result_errors(item, "case-1", "base", "a" * 40, ["python -m pip check"]), [])
        tampered = {**item, "sha": "b" * 40, "setup_results": []}
        errors = _raw_result_errors(tampered, "case-1", "base", "a" * 40, ["python -m pip check"])
        self.assertTrue(any("invalid sha" in error for error in errors))
        self.assertTrue(any("setup commands" in error for error in errors))

    def test_plan_is_hash_bound_and_contains_only_blind_execution_fields(self) -> None:
        pack_path = ROOT / "target_packs" / "synthetic_clean" / "v1" / "pack.json"
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "plan.json"
            plan = create_target_plan(
                pack_path,
                "https://example.invalid/synthetic-clean.git",
                "0" * 40,
                "0" * 40,
                None,
                "SAFE_FIXED",
                "SHADOW",
                "markheck-solutions/governance",
                "a" * 40,
                None,
                output,
            )
            encoded = json.dumps(plan, sort_keys=True)
            self.assertTrue(output.is_file())
            self.assertEqual(len(plan["matrix"]), 2)
            self.assertNotIn("expected_base_result", encoded)
            self.assertNotIn("expected_decision", encoded)
            self.assertNotIn('"decision"', encoded)
            self.assertEqual(len(plan["plan_hash"]), 64)


if __name__ == "__main__":
    unittest.main()
