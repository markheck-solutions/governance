from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from governance_eval.cases import load_cases
from governance_eval.lock import (
    read_spaghetti_lock,
    validate_spaghetti_lock,
    write_spaghetti_lock,
)
from governance_eval.models import DetectorEvidence, EvidenceStatus, ReviewFinding
from governance_eval.paths import repo_root
from governance_eval.schema_validator import SchemaValidationError, validate
from governance_eval.schemas import validate_named


class SchemaAndLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def test_schema_validator_resolves_local_defs_and_array_bounds(self) -> None:
        schema = {
            "$defs": {"positive": {"type": "integer", "minimum": 1}},
            "type": "array",
            "minItems": 1,
            "maxItems": 2,
            "items": {"$ref": "#/$defs/positive"},
        }
        validate([1, 2], schema)
        for invalid in ([], [0], [1, 2, 3]):
            with (
                self.subTest(invalid=invalid),
                self.assertRaises(SchemaValidationError),
            ):
                validate(invalid, schema)

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
        bad_case = json.loads(
            (self.root / "cases/v1/001_spaghetti_pr_141_defect.json").read_text()
        )
        del bad_case["expected_decision"]
        with self.assertRaises(SchemaValidationError):
            validate_named("evaluation_case", bad_case, self.root)

    def test_schema_validator_reports_invalid_regex_pattern(self) -> None:
        with self.assertRaisesRegex(SchemaValidationError, "invalid pattern"):
            validate("abc", {"type": "string", "pattern": "["}, "$.field")

    def test_schema_validator_pattern_uses_search_semantics(self) -> None:
        validate("prefix-abc-suffix", {"type": "string", "pattern": "abc"}, "$.field")
        with self.assertRaisesRegex(SchemaValidationError, "does not match pattern"):
            validate(
                "prefix-def-suffix", {"type": "string", "pattern": "abc"}, "$.field"
            )

    def test_supportability_result_schemas_reject_malformed_shas(self) -> None:
        gate_result = {
            "schema_version": "1.0",
            "generated_at": "2026-06-27T00:00:00Z",
            "owner_status": "RED",
            "base_sha": "not-a-sha",
            "head_sha": "2" * 40,
            "standard": {},
            "changed_files": [],
            "high_risk_files": [],
            "coverage": {},
            "commands": [],
            "errors": [],
        }
        with self.assertRaisesRegex(SchemaValidationError, "base_sha"):
            validate_named("supportability_gate_result", gate_result, self.root)

        copilot_result = {
            "schema_version": "1.0",
            "generated_at": "2026-06-27T00:00:00Z",
            "owner_status": "RED",
            "head_sha": "not-a-sha",
            "reviewer_login_patterns": ["*copilot*"],
            "review_status": {
                "latest_head_reviewed": False,
                "reviewer": "",
                "submitted_at": "",
                "commit_oid": "",
                "structured_evidence_present": False,
                "structured_evidence_valid": False,
                "reviewed_commit_sha": "",
                "verdict": "",
                "open_finding_count": 0,
                "blocking_thread_count": 0,
                "blocking_comment_count": 0,
            },
            "review_request": {"prompt": ""},
            "errors": [],
        }
        with self.assertRaisesRegex(SchemaValidationError, "head_sha"):
            validate_named("copilot_review_gate_result", copilot_result, self.root)

    def test_copilot_review_gate_schema_accepts_structured_review_fields(self) -> None:
        head = "c" * 40
        result = {
            "schema_version": "1.0",
            "generated_at": "2026-06-27T00:00:00Z",
            "owner_status": "GREEN",
            "repository": "example/repo",
            "pull_request_number": 7,
            "head_sha": head,
            "reviewer_login_patterns": ["*copilot*"],
            "review_status": {
                "latest_head_reviewed": True,
                "reviewer": "github-copilot[bot]",
                "submitted_at": "2026-06-30T14:35:45Z",
                "commit_oid": "",
                "structured_evidence_present": True,
                "structured_evidence_valid": True,
                "reviewed_commit_sha": head,
                "verdict": "clean",
                "open_finding_count": 0,
                "blocking_thread_count": 0,
                "blocking_comment_count": 0,
            },
            "review_request": {"prompt": f"@copilot review commit {head}"},
            "errors": [],
        }

        validate_named("copilot_review_gate_result", result, self.root)

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
