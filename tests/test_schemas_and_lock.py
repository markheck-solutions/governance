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

    def test_schema_constant_and_enum_do_not_confuse_booleans_with_integers(
        self,
    ) -> None:
        for value, schema in (
            (1, {"const": True}),
            (True, {"const": 1}),
            (False, {"enum": [0]}),
            ({"enabled": 1}, {"const": {"enabled": True}}),
        ):
            with self.subTest(value=value, schema=schema):
                with self.assertRaises(SchemaValidationError):
                    validate(value, schema)
        validate(1.0, {"const": 1})

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

    def test_lock_validator_preserves_complete_problem_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "spaghetti.lock.toml"
            path.write_text(
                "\n".join(
                    [
                        "schema_version = 2",
                        'generated_at = "x"',
                        'evidence_source = "x"',
                        'repository_url = "https://example.invalid/fake"',
                        "[pull_request_141]",
                        "number = 999",
                        'historical_case_id = "wrong"',
                        'base_sha = "BASE"',
                        'head_sha = "HEAD"',
                        'merge_commit_sha = "MERGE"',
                        'approved_oracle_sha = "ORACLE"',
                        'observed_main_sha = "MAIN"',
                    ]
                ),
                encoding="utf-8",
            )

            problems = validate_spaghetti_lock(path)

        sha_names = (
            "base_sha",
            "head_sha",
            "merge_commit_sha",
            "approved_oracle_sha",
            "observed_main_sha",
        )
        self.assertEqual(
            problems,
            [
                "schema_version must be 1",
                "repository_url does not match targets/spaghetti.toml",
                "historical_case_id mismatch",
                *[
                    f"{name} is not a full immutable SHA: {value!r}"
                    for name, value in zip(
                        sha_names, ("BASE", "HEAD", "MERGE", "ORACLE", "MAIN")
                    )
                ],
                *[
                    f"{name} does not match resolved PR #141 evidence"
                    for name in sha_names
                ],
                "unexpected pull request: 999",
                "approved oracle SHA must equal PR base SHA for Phase 1 historical oracle",
            ],
        )


if __name__ == "__main__":
    unittest.main()
