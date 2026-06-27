from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from governance_eval.cases import load_cases
from governance_eval.lock import read_spaghetti_lock, validate_spaghetti_lock, write_spaghetti_lock
from governance_eval.models import DetectorEvidence, EvidenceStatus, ReviewFinding
from governance_eval.paths import repo_root
from governance_eval.schema_validator import SchemaValidationError, validate
from governance_eval.schemas import validate_named


class SchemaAndLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def test_all_cases_validate_against_schema(self) -> None:
        cases = load_cases(self.root)
        self.assertGreaterEqual(len(cases), 16)
        self.assertEqual(len({case["id"] for case in cases}), len(cases))

    def test_evidence_finding_and_decision_schemas_accept_model_output(self) -> None:
        finding = ReviewFinding(
            id="FINDING-001",
            severity="P2",
            category="behavior_regression",
            message="route order changed",
            evidence_id="CASE::detector",
        )
        evidence = DetectorEvidence(
            evidence_id="CASE::detector",
            case_id="CASE",
            detector_id="detector",
            status=EvidenceStatus.FAIL,
            message="failed",
            observed={"actual": ["A1"]},
            findings=(finding,),
        )
        validate_named("review_finding", finding.to_json(), self.root)
        validate_named("detector_evidence", evidence.to_json(), self.root)

    def test_schema_rejects_missing_required_case_field(self) -> None:
        bad_case = json.loads((self.root / "cases/v1/001_spaghetti_pr_141_defect.json").read_text())
        del bad_case["expected_decision"]
        with self.assertRaises(SchemaValidationError):
            validate_named("evaluation_case", bad_case, self.root)

    def test_schema_validator_reports_invalid_regex_pattern(self) -> None:
        with self.assertRaisesRegex(SchemaValidationError, "invalid pattern"):
            validate("abc", {"type": "string", "pattern": "["}, "$.field")

    def test_schema_validator_pattern_uses_search_semantics(self) -> None:
        validate("prefix-abc-suffix", {"type": "string", "pattern": "abc"}, "$.field")
        with self.assertRaisesRegex(SchemaValidationError, "does not match pattern"):
            validate("prefix-def-suffix", {"type": "string", "pattern": "abc"}, "$.field")

    def test_spaghetti_lock_contains_full_immutable_shas(self) -> None:
        lock_path = self.root / "targets/spaghetti.lock.toml"
        self.assertEqual(validate_spaghetti_lock(lock_path), [])
        lock = read_spaghetti_lock(lock_path)
        for key, value in lock.to_json().items():
            if key.endswith("_sha"):
                self.assertRegex(value, r"^[0-9a-f]{40}$")
        self.assertEqual(lock.pull_request, 141)

    def test_lock_writer_generates_schema_versioned_toml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "spaghetti.lock.toml"
            write_spaghetti_lock(path)
            self.assertTrue(path.exists())
            self.assertEqual(validate_spaghetti_lock(path), [])

    def test_lock_validator_rejects_fabricated_sha_shape_only_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "spaghetti.lock.toml"
            path.write_text(
                "\n".join(
                    [
                        "schema_version = 1",
                        'generated_at = "2026-06-25T00:00:00Z"',
                        'evidence_source = "fabricated"',
                        'repository_url = "https://example.invalid/fake.git"',
                        "",
                        "[pull_request_141]",
                        "number = 141",
                        'historical_case_id = "SPAGHETTI-PR-141-PARTIAL-METADATA-INTERLEAVING"',
                        f'base_sha = "{"a" * 40}"',
                        f'head_sha = "{"b" * 40}"',
                        f'merge_commit_sha = "{"c" * 40}"',
                        f'approved_oracle_sha = "{"a" * 40}"',
                        f'observed_main_sha = "{"d" * 40}"',
                    ]
                ),
                encoding="utf-8",
            )
            self.assertNotEqual(validate_spaghetti_lock(path), [])


if __name__ == "__main__":
    unittest.main()
