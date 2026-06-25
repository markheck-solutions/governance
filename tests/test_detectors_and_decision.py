from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from governance_eval.cases import load_cases
from governance_eval.decision import decide
from governance_eval.detectors import run_detectors
from governance_eval.detectors import _covered_by_any_gate
from governance_eval.models import Decision
from governance_eval.paths import repo_root


class DetectorDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())
        self.cases = {case["id"]: case for case in load_cases(self.root)}

    def decision_for(self, case_id: str) -> str:
        case = self.cases[case_id]
        evidence = run_detectors(case, self.root)
        return decide(case, evidence).decision.value

    def test_pr_141_defect_is_executable_and_blocked(self) -> None:
        case = self.cases["SPAGHETTI-PR-141-PARTIAL-METADATA-INTERLEAVING-DEFECT"]
        evidence = run_detectors(case, self.root)
        route_evidence = next(item for item in evidence if item.detector_id == "route_interleaving")
        self.assertEqual(route_evidence.observed["actual_sequence"], ["A1", "A3", "B1", "B3"])
        self.assertEqual(route_evidence.observed["expected_sequence"], ["A1", "B1", "A3", "B3"])
        self.assertEqual(decide(case, evidence).decision, Decision.BLOCK_TECHNICAL)

    def test_pr_141_clean_oracle_passes(self) -> None:
        self.assertEqual(
            self.decision_for("SPAGHETTI-PR-141-PARTIAL-METADATA-INTERLEAVING-CLEAN"),
            "MERGE",
        )

    def test_each_defective_synthetic_control_blocks(self) -> None:
        defective = [
            case_id
            for case_id, case in self.cases.items()
            if case["category"] == "synthetic_structural" and case["label"] == "REPRODUCED_BAD"
        ]
        self.assertEqual(len(defective), 6)
        for case_id in defective:
            with self.subTest(case_id=case_id):
                self.assertEqual(self.decision_for(case_id), "BLOCK_TECHNICAL")

    def test_each_clean_control_passes(self) -> None:
        clean = [
            case_id
            for case_id, case in self.cases.items()
            if case["category"] in {"synthetic_structural", "historical_behavior"}
            and case["label"] == "VERIFIED_SAFE"
        ]
        self.assertEqual(len(clean), 7)
        for case_id in clean:
            with self.subTest(case_id=case_id):
                self.assertEqual(self.decision_for(case_id), "MERGE")

    def test_missing_required_evidence_fails_closed(self) -> None:
        case = self.cases["FAIL-CLOSED-MISSING-EVIDENCE"]
        decision = decide(case, run_detectors(case, self.root))
        self.assertEqual(decision.decision, Decision.BLOCK_TECHNICAL)
        self.assertTrue(decision.fail_closed)

    def test_unknown_detector_fails_closed(self) -> None:
        case = copy.deepcopy(self.cases["SYN-PRIVATE-REEXPORT-CLEAN"])
        case["detectors"] = ["does_not_exist"]
        decision = decide(case, run_detectors(case, self.root))
        self.assertEqual(decision.decision, Decision.BLOCK_TECHNICAL)
        self.assertTrue(decision.fail_closed)

    def test_required_evidence_without_detector_fails_closed(self) -> None:
        case = copy.deepcopy(self.cases["SYN-PRIVATE-REEXPORT-CLEAN"])
        case["detectors"] = []
        case["required_evidence"] = ["must_exist"]
        decision = decide(case, [])
        self.assertEqual(decision.decision, Decision.BLOCK_TECHNICAL)
        self.assertTrue(decision.fail_closed)

    def test_mismatched_required_evidence_label_fails_closed(self) -> None:
        case = copy.deepcopy(self.cases["SYN-PRIVATE-REEXPORT-CLEAN"])
        case["required_evidence"] = ["nonexistent required proof label"]
        decision = decide(case, run_detectors(case, self.root))
        self.assertEqual(decision.decision, Decision.BLOCK_TECHNICAL)
        self.assertTrue(decision.fail_closed)

    def test_wrong_case_evidence_fails_closed(self) -> None:
        defect_case = self.cases["SPAGHETTI-PR-141-PARTIAL-METADATA-INTERLEAVING-DEFECT"]
        clean_case = self.cases["SPAGHETTI-PR-141-PARTIAL-METADATA-INTERLEAVING-CLEAN"]
        clean_evidence = run_detectors(clean_case, self.root)
        decision = decide(defect_case, clean_evidence)
        self.assertEqual(decision.decision, Decision.BLOCK_TECHNICAL)
        self.assertTrue(decision.fail_closed)

    def test_gate_scope_glob_star_does_not_cross_directories(self) -> None:
        gates = [{"name": "ruff", "scope": ["src/*"]}]
        self.assertFalse(_covered_by_any_gate("src/app/public_api.py", gates))
        self.assertTrue(_covered_by_any_gate("src/public_api.py", gates))
        self.assertTrue(_covered_by_any_gate("src/app/public_api.py", [{"name": "ruff", "scope": ["src/**"]}]))

    def test_malformed_fixture_is_evidence_not_crash(self) -> None:
        case = copy.deepcopy(self.cases["SPAGHETTI-PR-141-PARTIAL-METADATA-INTERLEAVING-DEFECT"])
        case["detectors"] = ["route_interleaving"]
        with tempfile.TemporaryDirectory(dir=self.root) as tmp:
            fixture = Path(tmp) / "fixture"
            fixture.mkdir()
            (fixture / "behavior.json").write_text(json.dumps({"rows": []}), encoding="utf-8")
            case["fixture_path"] = str(fixture.relative_to(self.root))
            evidence = run_detectors(case, self.root)
        self.assertEqual(evidence[0].status.value, "MALFORMED")
        decision = decide(case, evidence)
        self.assertEqual(decision.decision, Decision.BLOCK_TECHNICAL)
        self.assertTrue(decision.fail_closed)

    def test_business_ambiguity_returns_ask_business(self) -> None:
        decision = self.decision_for("ASK-BUSINESS-ROUTE-ORDER")
        self.assertEqual(decision, "ASK_BUSINESS")


if __name__ == "__main__":
    unittest.main()
