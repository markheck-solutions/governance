from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from governance_eval.benchmark import run_benchmark
from governance_eval.benchmark import validate_benchmark_result
from governance_eval.benchmark import _metrics
from governance_eval.paths import repo_root
from governance_eval.schema_validator import SchemaValidationError
from governance_eval.schemas import validate_named


class BenchmarkCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def test_benchmark_meets_phase1_acceptance_metrics(self) -> None:
        result = run_benchmark(self.root, repeat=3)
        self.assertEqual(result["phase1_decision"], "BENCHMARK_PASS")
        self.assertEqual(result["acceptance_errors"], [])
        self.assertEqual(result["metrics"]["critical_defect_recall"], 1.0)
        self.assertEqual(result["metrics"]["critical_defects_blocked"], result["metrics"]["critical_defect_count"])
        self.assertEqual(result["metrics"]["negative_control_recall"], 1.0)
        self.assertEqual(result["metrics"]["negative_controls_blocked"], result["metrics"]["negative_control_count"])
        self.assertEqual(result["metrics"]["false_block_rate"], 0.0)
        self.assertEqual(result["metrics"]["false_blocks"], 0)
        self.assertEqual(result["metrics"]["repeated_run_decision_stability"], 1.0)
        self.assertEqual(result["metrics"]["deterministic_flake_rate"], 0.0)
        validate_named("benchmark_run_result", result, self.root)
        validate_benchmark_result(result, self.root)

    def test_benchmark_writes_schema_valid_json_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = run_benchmark(self.root, repeat=2, artifacts_dir=Path(tmp))
            latest = Path(tmp) / "governance-benchmark-latest.json"
            self.assertTrue(latest.exists())
            data = json.loads(latest.read_text(encoding="utf-8"))
            validate_named("benchmark_run_result", data, self.root)
            self.assertEqual(result["phase1_decision"], "BENCHMARK_PASS")

    def test_nested_benchmark_result_validation_rejects_tampering(self) -> None:
        result = run_benchmark(self.root, repeat=1)
        result["cases"][0]["decision"]["decision"] = "NOT_A_DECISION"
        with self.assertRaises(SchemaValidationError):
            validate_benchmark_result(result, self.root)

    def test_nested_benchmark_result_validation_rejects_bad_lock_sha(self) -> None:
        result = run_benchmark(self.root, repeat=1)
        result["target_lock"]["base_sha"] = "not-a-sha"
        with self.assertRaises(SchemaValidationError):
            validate_benchmark_result(result, self.root)

    def test_flake_metric_tracks_evidence_changes_not_only_decisions(self) -> None:
        base_case = {"critical": True, "label": "REPRODUCED_BAD", "category": "historical_behavior"}
        repetitions = [
            [
                {
                    "case": base_case,
                    "decision": {"decision": "BLOCK_TECHNICAL"},
                    "evidence": [{"status": "FAIL", "detector_id": "route_interleaving"}],
                }
            ],
            [
                {
                    "case": base_case,
                    "decision": {"decision": "BLOCK_TECHNICAL"},
                    "evidence": [{"status": "PASS", "detector_id": "route_interleaving"}],
                }
            ],
        ]
        metrics = _metrics(repetitions)
        self.assertEqual(metrics["repeated_run_decision_stability"], 1.0)
        self.assertEqual(metrics["deterministic_flake_rate"], 1.0)

    def test_cli_case_command_uses_real_detector(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "governance_eval",
                "run-case",
                "SPAGHETTI-PR-141-PARTIAL-METADATA-INTERLEAVING-DEFECT",
            ],
            cwd=self.root,
            text=True,
            capture_output=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        data = json.loads(completed.stdout)
        self.assertEqual(data["decision"]["decision"], "BLOCK_TECHNICAL")
        route_evidence = next(item for item in data["evidence"] if item["detector_id"] == "route_interleaving")
        self.assertEqual(route_evidence["observed"]["actual_sequence"], ["A1", "A3", "B1", "B3"])


if __name__ == "__main__":
    unittest.main()
